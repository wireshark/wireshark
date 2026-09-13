/* dtsdi.c
 *
 * DekTec DTSDI file reader.
 *
 * File-format definitions are in Import/DtSdiFileFmt.h in the DekTec
 * DtPlay source package. SDI sample representations are documented by
 * the DtSdi class in the DekTec DTAPI documentation. Both are distributed
 * from:
 * https://www.dektec.com/downloads/SDK/
 *
 * Supported:
 * - Version 2 files containing uncompressed full SDI frames.
 * - 8-bit, packed 10-bit, and 16-bit sample storage.
 * - External compression handled by Wiretap, such as .dtsdi.gz files.
 * - Full-frame size inference when a writer leaves the V2 frame size at
 *   zero; frame count is also inferred when the logical file size is known.
 *
 * Not supported:
 * - Version 1 files, internal Huffman compression, or files containing
 *   only active video, HANC, or VANC regions.
 * - Writing DTSDI files.
 *
 * The reader exposes one complete stored SDI frame per Wiretap record.
 * Video, audio, and ancillary-data interpretation belongs to the dissector.
 * A zero V2 frame count is treated as unknown when an external compression
 * wrapper prevents reliable file-size validation; sequential reading then
 * stops at checked EOF, and a partial final frame is a short-read error.
 *
 * Copyright (c) 2026, Devin Heitmueller <dheitmueller@ltnglobal.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "wtap_module.h"
#include "file_wrappers.h"

#include <wsutil/buffer.h>
#include <wsutil/pint.h>

#define DTSDI_MAGIC_SIZE       12
#define DTSDI_BASE_HEADER_SIZE 16
#define DTSDI_V2_HEADER_SIZE   24

#define DTSDI_FORMAT_VERSION_2 1

#define DTSDI_FLAG_FULL        0x0001
#define DTSDI_FLAG_ACTVID      0x0002
#define DTSDI_FLAG_HANC        0x0004
#define DTSDI_FLAG_VANC        0x0008
#define DTSDI_FLAG_10B         0x0080
#define DTSDI_FLAG_16B         0x0100
#define DTSDI_FLAG_HUFFMAN     0x0200

typedef struct {
    uint8_t format_version;
    uint8_t data_type;
    uint16_t flags;
    uint32_t frame_size;
    uint32_t num_frames;
    uint32_t frame_rate_num;
    uint32_t frame_rate_den;
    int64_t data_offset;
} dtsdi_t;

static int dtsdi_file_type_subtype = -1;

void register_dtsdi(void);

static bool
dtsdi_frame_rate(uint8_t data_type, uint32_t *num, uint32_t *den)
{
    *den = 1;

    switch (data_type) {
    case 0x01: *num = 25; break;             /* 625i50 */
    case 0x02: *num = 30000; *den = 1001; break; /* 525i59.94 */
    case 0x03: case 0x0b: case 0x16:
        *num = 24000; *den = 1001; break;
    case 0x04: case 0x0c: case 0x17:
        *num = 24; break;
    case 0x05: case 0x0d: case 0x10: case 0x18:
        *num = 25; break;
    case 0x06: case 0x0f: case 0x11: case 0x19:
        *num = 30000; *den = 1001; break;
    case 0x07: case 0x0e: case 0x12: case 0x1a:
        *num = 30; break;
    case 0x08: case 0x13:
        *num = 50; break;
    case 0x09: case 0x14:
        *num = 60000; *den = 1001; break;
    case 0x0a: case 0x15:
        *num = 60; break;
    default:
        return false;
    }

    return true;
}

static bool
dtsdi_full_frame_size(uint8_t data_type, uint16_t flags, uint32_t *frame_size)
{
    uint32_t word_count;
    unsigned storage_bits;

    switch (data_type) {
    case 0x01: /* 625i50 */
        word_count = 1080000;
        break;
    case 0x02: /* 525i59.94 */
        word_count = 900900;
        break;
    case 0x03: case 0x04:                 /* 720p23.98/24 */
    case 0x0b: case 0x0c:                 /* 1080p23.98/24 */
    case 0x16: case 0x17:                 /* 1080psf23.98/24 */
        word_count = 6187500;
        break;
    case 0x05:                            /* 720p25 */
    case 0x0d: case 0x10: case 0x13:     /* 1080p25/i50/p50 */
    case 0x18:                            /* 1080psf25 */
        word_count = 5940000;
        break;
    case 0x06: case 0x07:                 /* 720p29.97/30 */
    case 0x0e: case 0x0f:                 /* 1080p30/29.97 */
    case 0x11: case 0x12:                 /* 1080i59.94/60 */
    case 0x14: case 0x15:                 /* 1080p59.94/60 */
    case 0x19: case 0x1a:                 /* 1080psf29.97/30 */
        word_count = 4950000;
        break;
    case 0x08: /* 720p50 */
        word_count = 2970000;
        break;
    case 0x09: case 0x0a: /* 720p59.94/60 */
        word_count = 2475000;
        break;
    default:
        return false;
    }

    if (flags & DTSDI_FLAG_16B)
        storage_bits = 16;
    else if (flags & DTSDI_FLAG_10B)
        storage_bits = 10;
    else
        storage_bits = 8;

    *frame_size = (uint32_t)(((uint64_t)word_count * storage_bits + 7) / 8);
    return true;
}

static void
dtsdi_set_pseudo_header(wtap_rec *rec, const dtsdi_t *dtsdi)
{
    rec->rec_header.packet_header.pseudo_header.dtsdi.format_version = dtsdi->format_version;
    rec->rec_header.packet_header.pseudo_header.dtsdi.data_type = dtsdi->data_type;
    rec->rec_header.packet_header.pseudo_header.dtsdi.flags = dtsdi->flags;
}

static bool
dtsdi_read_frame(wtap *wth, FILE_T fh, int64_t offset, wtap_rec *rec,
                 int *err, char **err_info)
{
    dtsdi_t *dtsdi = (dtsdi_t *)wth->priv;
    uint64_t frame_number;
    uint64_t timestamp_num;

    if (offset < dtsdi->data_offset)
        return false;

    frame_number = (uint64_t)(offset - dtsdi->data_offset) / dtsdi->frame_size;
    if (dtsdi->num_frames != 0 && frame_number >= dtsdi->num_frames) {
        *err = 0;
        return false;
    }

    if (!wtap_read_bytes_or_eof_buffer(fh, &rec->data, dtsdi->frame_size,
                                       err, err_info))
        return false;

    wtap_setup_packet_rec(rec, wth->file_encap);
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS;

    timestamp_num = frame_number * dtsdi->frame_rate_den;
    rec->ts.secs = (time_t)(timestamp_num / dtsdi->frame_rate_num);
    rec->ts.nsecs = (int)((timestamp_num % dtsdi->frame_rate_num) * 1000000000 /
                          dtsdi->frame_rate_num);

    rec->rec_header.packet_header.caplen = dtsdi->frame_size;
    rec->rec_header.packet_header.len = dtsdi->frame_size;
    dtsdi_set_pseudo_header(rec, dtsdi);

    return true;
}

static bool
dtsdi_read(wtap *wth, wtap_rec *rec, int *err, char **err_info,
           int64_t *data_offset)
{
    *data_offset = file_tell(wth->fh);
    return dtsdi_read_frame(wth, wth->fh, *data_offset, rec, err, err_info);
}

static bool
dtsdi_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec, int *err,
                char **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return false;

    return dtsdi_read_frame(wth, wth->random_fh, seek_off, rec, err, err_info);
}

wtap_open_return_val
dtsdi_open(wtap *wth, int *err, char **err_info)
{
    uint8_t header[DTSDI_V2_HEADER_SIZE];
    dtsdi_t *dtsdi;
    uint8_t format_version;
    uint8_t data_type;
    uint16_t flags;
    uint32_t frame_size;
    uint32_t minimum_frame_size;
    uint32_t num_frames;
    uint32_t frame_rate_num;
    uint32_t frame_rate_den;
    int64_t file_size;
    uint64_t data_size;
    uint64_t expected_size;

    if (!wtap_read_bytes(wth->fh, header, DTSDI_MAGIC_SIZE, err, err_info)) {
        if (*err == WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_NOT_MINE;
        return WTAP_OPEN_ERROR;
    }

    if (pletohu32(header) != 0x546b6544 ||
        pletohu32(header + 4) != 0x642e6365 ||
        pletohu32(header + 8) != 0x69647374)
        return WTAP_OPEN_NOT_MINE;

    if (!wtap_read_bytes(wth->fh, header + DTSDI_MAGIC_SIZE,
                         DTSDI_BASE_HEADER_SIZE - DTSDI_MAGIC_SIZE,
                         err, err_info))
        return WTAP_OPEN_ERROR;

    format_version = header[12];
    data_type = header[13];
    flags = pletohu16(header + 14);

    if (format_version != DTSDI_FORMAT_VERSION_2) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = ws_strdup_printf("dtsdi: format version %u is not yet supported",
                                     format_version + 1);
        return WTAP_OPEN_ERROR;
    }

    if (!wtap_read_bytes(wth->fh, header + DTSDI_BASE_HEADER_SIZE,
                         DTSDI_V2_HEADER_SIZE - DTSDI_BASE_HEADER_SIZE,
                         err, err_info))
        return WTAP_OPEN_ERROR;

    frame_size = pletohu32(header + 16);
    num_frames = pletohu32(header + 20);

    if (flags & DTSDI_FLAG_HUFFMAN) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = g_strdup("dtsdi: Huffman-compressed SDI frames are not yet supported");
        return WTAP_OPEN_ERROR;
    }

    if ((flags & (DTSDI_FLAG_FULL | DTSDI_FLAG_ACTVID |
                  DTSDI_FLAG_HANC | DTSDI_FLAG_VANC)) != DTSDI_FLAG_FULL) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = ws_strdup_printf("dtsdi: only full-frame SDI data is currently supported (flags 0x%04x)",
                                     flags);
        return WTAP_OPEN_ERROR;
    }

    if ((flags & (DTSDI_FLAG_10B | DTSDI_FLAG_16B)) ==
        (DTSDI_FLAG_10B | DTSDI_FLAG_16B)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("dtsdi: 10-bit packed and 16-bit storage flags are both set");
        return WTAP_OPEN_ERROR;
    }

    if (!dtsdi_frame_rate(data_type, &frame_rate_num, &frame_rate_den)) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = ws_strdup_printf("dtsdi: unknown SDI data type 0x%02x", data_type);
        return WTAP_OPEN_ERROR;
    }

    if (!dtsdi_full_frame_size(data_type, flags, &minimum_frame_size)) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = ws_strdup_printf("dtsdi: cannot infer frame size for SDI data type 0x%02x",
                                     data_type);
        return WTAP_OPEN_ERROR;
    }

    /* Some V2 writers leave both frame metadata fields zero. Full-frame
     * rasters have a fixed size for each video standard and storage mode. */
    if (frame_size == 0)
        frame_size = minimum_frame_size;
    else if (frame_size < minimum_frame_size) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("dtsdi: frame size %u is smaller than the minimum %u-byte full frame",
                                     frame_size, minimum_frame_size);
        return WTAP_OPEN_ERROR;
    }

    if (frame_size > WTAP_MAX_PACKET_SIZE_DEKTEC_SDI) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("dtsdi: frame size %u exceeds the supported maximum %u",
                                     frame_size, WTAP_MAX_PACKET_SIZE_DEKTEC_SDI);
        return WTAP_OPEN_ERROR;
    }

    if (!file_iscompressed(wth->fh)) {
        file_size = wtap_file_size(wth, err);
        if (file_size == -1)
            return WTAP_OPEN_ERROR;
        if (file_size < DTSDI_V2_HEADER_SIZE) {
            *err = WTAP_ERR_SHORT_READ;
            *err_info = ws_strdup_printf("dtsdi: file contains only %" G_GINT64_FORMAT
                                         " bytes, shorter than the %u-byte header",
                                         file_size, DTSDI_V2_HEADER_SIZE);
            return WTAP_OPEN_ERROR;
        }

        data_size = (uint64_t)file_size - DTSDI_V2_HEADER_SIZE;
        if (num_frames == 0) {
            if (data_size % frame_size != 0 ||
                data_size / frame_size > UINT32_MAX) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("dtsdi: file contains %" G_GUINT64_FORMAT
                                             " bytes after the header, not a supported number of %u-byte frames",
                                             data_size, frame_size);
                return WTAP_OPEN_ERROR;
            }
            num_frames = (uint32_t)(data_size / frame_size);
        } else {
            expected_size = DTSDI_V2_HEADER_SIZE +
                            (uint64_t)frame_size * num_frames;
            if (expected_size > (uint64_t)file_size) {
                *err = WTAP_ERR_SHORT_READ;
                *err_info = ws_strdup_printf("dtsdi: header describes %" G_GUINT64_FORMAT
                                             " bytes, but file contains %" G_GINT64_FORMAT,
                                             expected_size, file_size);
                return WTAP_OPEN_ERROR;
            }
        }
    }

    dtsdi = g_new0(dtsdi_t, 1);
    dtsdi->format_version = format_version;
    dtsdi->data_type = data_type;
    dtsdi->flags = flags;
    dtsdi->frame_size = frame_size;
    dtsdi->num_frames = num_frames;
    dtsdi->data_offset = DTSDI_V2_HEADER_SIZE;

    dtsdi->frame_rate_num = frame_rate_num;
    dtsdi->frame_rate_den = frame_rate_den;

    if (file_seek(wth->fh, dtsdi->data_offset, SEEK_SET, err) == -1) {
        g_free(dtsdi);
        return WTAP_OPEN_ERROR;
    }

    wth->file_type_subtype = dtsdi_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_DEKTEC_SDI;
    wth->file_tsprec = WTAP_TSPREC_NSEC;
    wth->snapshot_length = frame_size;
    wth->subtype_read = dtsdi_read;
    wth->subtype_seek_read = dtsdi_seek_read;
    wth->priv = dtsdi;

    return WTAP_OPEN_MINE;
}

static const struct supported_block_type dtsdi_blocks_supported[] = {
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info dtsdi_info = {
    "DekTec SDI", "dtsdi", "dtsdi", "dtsdi",
    false, BLOCKS_SUPPORTED(dtsdi_blocks_supported),
    NULL, NULL, NULL
};

void
register_dtsdi(void)
{
    dtsdi_file_type_subtype = wtap_register_file_type_subtype(&dtsdi_info);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
