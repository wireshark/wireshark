/* mp2t.c
 *
 * ISO/IEC 13818-1 MPEG2-TS file format decoder for the Wiretap library.
 * Written by Weston Schmidt <weston_schmidt@alumni.purdue.edu>
 * Copyright 2012 Weston Schmidt
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "mp2t.h"

#include <sys/types.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "wtap-int.h"
#include <wsutil/buffer.h>
#include "file_wrappers.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MP2T_SYNC_BYTE      0x47
#define MP2T_SIZE           188
#define MP2T_QAM64_BITRATE  26970350    /* bits per second */
#define MP2T_PCR_CLOCK      27000000    /* cycles per second - 27MHz */

/* we try to detect trailing data up to 40 bytes after each packet */
#define TRAILER_LEN_MAX 40

/* number of consecutive packets we must read to decide that a file
   is actually an mpeg2 ts */
#define SYNC_STEPS   10


typedef struct {
    uint64_t bitrate;
    uint32_t start_offset;
    /* length of header data (e.g., TP_extra_header in BDAV m2ts files) before
     * each packet) */
    uint8_t header_len;
    /* length of trailing data (e.g. FEC) that's appended after each packet */
    uint8_t trailer_len;
} mp2t_filetype_t;

static int mp2t_file_type_subtype = -1;

void register_mp2t(void);

static bool
mp2t_read_packet(mp2t_filetype_t *mp2t, FILE_T fh, int64_t offset,
                 wtap_rec *rec, Buffer *buf, int *err,
                 char **err_info)
{
    uint64_t tmp;

    /*
     * MP2T_SIZE will always be less than WTAP_MAX_PACKET_SIZE_STANDARD, so
     * we don't have to worry about the packet being too big.
     */
    ws_buffer_assure_space(buf, MP2T_SIZE);
    if (!wtap_read_bytes_or_eof(fh, ws_buffer_start_ptr(buf), MP2T_SIZE, err, err_info))
        return false;

    rec->rec_type = REC_TYPE_PACKET;
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);

    /* XXX - relative, not absolute, time stamps */
    rec->presence_flags = WTAP_HAS_TS;

    /*
     * Every packet in an MPEG2-TS stream is has a fixed size of
     * MP2T_SIZE plus the number of trailer bytes.
     *
     * We assume that the bits in the transport stream are supplied at
     * a constant rate; is that guaranteed by all media that use
     * MPEG2-TS?  If so, the time offset, from the beginning of the
     * stream, of a given packet is the packet offset, in bits, divided
     * by the bitrate.
     *
     * It would be really cool to be able to configure the bitrate, in
     * case our attempt to guess it from the PCRs of one of the programs
     * doesn't get the right answer.
     */
    tmp = ((uint64_t)(offset - mp2t->start_offset) * 8); /* offset, in bits */
    rec->ts.secs = (time_t)(tmp / mp2t->bitrate);
    rec->ts.nsecs = (int)((tmp % mp2t->bitrate) * 1000000000 / mp2t->bitrate);

    rec->rec_header.packet_header.caplen = MP2T_SIZE;
    rec->rec_header.packet_header.len = MP2T_SIZE;

    return true;
}

static bool
mp2t_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
        char **err_info, int64_t *data_offset)
{
    mp2t_filetype_t *mp2t;

    mp2t = (mp2t_filetype_t*) wth->priv;

    /* if there's a header, skip it and go to the start of the packet */
    /* XXX - Eventually we might want to process the header (and trailer?) in
     * packet-mp2t.c, in which case we would read it in mp2t_read_packet and
     * include header_len in the packet_header lengths. We'd probably want
     * pseudo-header information to indicate it to packet-mp2t.c
     */
    if (mp2t->header_len!=0) {
        if (!wtap_read_bytes_or_eof(wth->fh, NULL, mp2t->header_len, err, err_info)) {
            return false;
        }
    }

    *data_offset = file_tell(wth->fh);

    if (!mp2t_read_packet(mp2t, wth->fh, *data_offset, rec, buf, err,
                          err_info)) {
        return false;
    }

    /* if there's a trailer, skip it and go to the start of the next packet */
    if (mp2t->trailer_len!=0) {
        if (!wtap_read_bytes(wth->fh, NULL, mp2t->trailer_len, err, err_info)) {
            return false;
        }
    }

    return true;
}

static bool
mp2t_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
        Buffer *buf, int *err, char **err_info)
{
    mp2t_filetype_t *mp2t;

    if (-1 == file_seek(wth->random_fh, seek_off, SEEK_SET, err)) {
        return false;
    }

    mp2t = (mp2t_filetype_t*) wth->priv;

    if (!mp2t_read_packet(mp2t, wth->random_fh, seek_off, rec, buf,
                          err, err_info)) {
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return false;
    }
    return true;
}

static uint64_t
mp2t_read_pcr(uint8_t *buffer)
{
    uint64_t base;
    uint64_t ext;

    base = pntoh40(buffer);
    base >>= 7;

    ext = pntoh16(&buffer[4]);
    ext &= 0x01ff;

    return (base * 300 + ext);
}

static bool
mp2t_find_next_pcr(wtap *wth, uint8_t trailer_len,
        int *err, char **err_info, uint32_t *idx, uint64_t *pcr, uint16_t *pid)
{
    uint8_t buffer[MP2T_SIZE+TRAILER_LEN_MAX];
    bool found;
    uint8_t afc;
    unsigned timeout = 0;

    found = false;
    while (false == found && timeout++ < SYNC_STEPS * SYNC_STEPS) {
        (*idx)++;
        if (!wtap_read_bytes_or_eof(
                    wth->fh, buffer, MP2T_SIZE+trailer_len, err, err_info)) {
            /* Read error, short read, or EOF */
            return false;
        }

        if (MP2T_SYNC_BYTE != buffer[0]) {
            continue;
        }

        /* Read out the AFC value. */
        afc = 3 & (buffer[3] >> 4);
        if (afc < 2) {
            continue;
        }

        /* Check the length. */
        if (buffer[4] < 7) {
            continue;
        }

        /* Check that there is the PCR flag. */
        if (0x10 != (0x10 & buffer[5])) {
            continue;
        }

        /* We have a PCR value! */
        *pcr = mp2t_read_pcr(&buffer[6]);
        *pid = 0x01ff & pntoh16(&buffer[1]);
        found = true;
    }

    return found;
}

static wtap_open_return_val
mp2t_bits_per_second(wtap *wth, uint32_t first, uint8_t trailer_len,
        uint64_t *bitrate, int *err, char **err_info)
{
    uint32_t pn1, pn2;
    uint64_t pcr1, pcr2;
    uint16_t pid1, pid2;
    uint32_t idx;
    uint64_t pcr_delta, bits_passed;

    /* Find the first PCR + PID.
     * Then find another PCR in that PID.
     * Take the difference and that's our bitrate.
     * All the different PCRs in different PIDs 'should' be the same.
     *
     * XXX - is this assuming that the time stamps in the PCRs correspond
     * to the time scale of the underlying transport stream?
     */
    idx = first;

    if (!mp2t_find_next_pcr(wth, trailer_len, err, err_info, &idx, &pcr1, &pid1)) {
        /* Read error, short read, or EOF */
        if (*err == WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_NOT_MINE;    /* not a full frame */
        if (*err != 0)
            return WTAP_OPEN_ERROR;

        /* We don't have any PCRs, so we can't guess the bit rate.
         * Default to something reasonable.
         */
        *bitrate = MP2T_QAM64_BITRATE;
        return WTAP_OPEN_MINE;
    }

    pn1 = idx;
    pn2 = pn1;

    while (pn1 == pn2) {
        if (!mp2t_find_next_pcr(wth, trailer_len, err, err_info, &idx, &pcr2, &pid2)) {
            /* Read error, short read, or EOF */
            if (*err == WTAP_ERR_SHORT_READ)
                return WTAP_OPEN_NOT_MINE;    /* not a full frame */
            if (*err != 0)
                return WTAP_OPEN_ERROR;

            /* We don't have two PCRs for the same PID, so we can't guess
             * the bit rate.
             * Default to something reasonable.
             */
            *bitrate = MP2T_QAM64_BITRATE;
            return WTAP_OPEN_MINE;
        }

        if (pid1 == pid2) {
            pn2 = idx;
        }
    }

    if (pcr2 <= pcr1) {
        /* The PCRs for that PID didn't go forward; treat that as an
         * indication that this isn't an MPEG-2 TS.
         */
        return WTAP_OPEN_NOT_MINE;
    }
    pcr_delta = pcr2 - pcr1;
    /* cast one of the factors to uint64_t
       otherwise, the multiplication would use uint32_t and could
       overflow before the result is assigned to the uint64_t bits_passed */
    bits_passed = (uint64_t)MP2T_SIZE * (pn2 - pn1) * 8;

    *bitrate = ((MP2T_PCR_CLOCK * bits_passed) / pcr_delta);
    if (*bitrate == 0) {
        /* pcr_delta < MP2T_PCR_CLOCK * bits_passed (pn2 != pn1,
         * as that's the test for the loop above, so bits_passed
         * is non-zero).
         *
         * That will produce a fractional bitrate, which turns
         * into zero, causing a zero divide later.
         *
         * XXX - should we report this as "not ours"?  A bitrate
         * of less than 1 bit per second is not very useful for any
         * form of audio/video, so presumably that's unlikely to
         * be an MP2T file.
         */
        return WTAP_OPEN_ERROR;
    }
    return WTAP_OPEN_MINE;
}

wtap_open_return_val
mp2t_open(wtap *wth, int *err, char **err_info)
{
    uint8_t buffer[MP2T_SIZE+TRAILER_LEN_MAX];
    uint8_t trailer_len = 0;
    uint8_t header_len = 0;
    unsigned sync_steps = 0;
    unsigned i;
    uint32_t first = 0;
    mp2t_filetype_t *mp2t;
    wtap_open_return_val status;
    uint64_t bitrate;


    if (!wtap_read_bytes(wth->fh, buffer, MP2T_SIZE, err, err_info)) {
        if (*err != WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_ERROR;
        return WTAP_OPEN_NOT_MINE;
    }

    for (i = 0; i < MP2T_SIZE; i++) {
        if (MP2T_SYNC_BYTE == buffer[i]) {
            first = i;
            goto found;
        }
    }
    /*
     * No sync bytes found, so not an MPEG-2 Transport Stream file.
     */
    return WTAP_OPEN_NOT_MINE; /* wrong file type - not an mpeg2 ts file */

found:
    if (-1 == file_seek(wth->fh, first, SEEK_SET, err)) {
        return WTAP_OPEN_ERROR;
    }

    /* read some packets and make sure they all start with a sync byte */
    do {
        if (!wtap_read_bytes(wth->fh, buffer, MP2T_SIZE+trailer_len, err, err_info)) {
            if (*err != WTAP_ERR_SHORT_READ)
                return WTAP_OPEN_ERROR;  /* read error */
            if(sync_steps<2) return WTAP_OPEN_NOT_MINE; /* wrong file type - not an mpeg2 ts file */
            break;  /* end of file, that's ok if we're still in sync */
        }
        if (buffer[0] == MP2T_SYNC_BYTE) {
                sync_steps++;
        }
        else {
            /* no sync byte found, check if trailing data is appended
               and we have to increase the packet size */

            /* if we've already detected a trailer field, we must remain in sync
               another mismatch means we have no mpeg2 ts file */
            if (trailer_len>0) {
                /* check for header with spurious sync byte in header */
                if (first < trailer_len) {
                    first += 1;
                    trailer_len -= 1;
                    if (-1 == file_seek(wth->fh, first, SEEK_SET, err)) {
                        return WTAP_OPEN_ERROR;
                    }
                    /* Shouldn't fail, we just read this */
                    if (!wtap_read_bytes(wth->fh, buffer, MP2T_SIZE, err, err_info)) {
                        if (*err != WTAP_ERR_SHORT_READ)
                            return WTAP_OPEN_ERROR;
                        return WTAP_OPEN_NOT_MINE;
                    }
                    for (i = 0; i < MP2T_SIZE; i++) {
                        if (MP2T_SYNC_BYTE == buffer[i]) {
                            first += i;
                            trailer_len -= i;
                            goto found;
                        }
                    }
                }
                return WTAP_OPEN_NOT_MINE;
            }

            /* check if a trailer is appended to the packet */
            for (i=0; i<TRAILER_LEN_MAX; i++) {
                if (buffer[i] == MP2T_SYNC_BYTE) {
                    trailer_len = i;
                    if (-1 == file_seek(wth->fh, first, SEEK_SET, err)) {
                        return WTAP_OPEN_ERROR;
                    }
                    sync_steps = 0;
                    break;
                }
            }
            /* no sync byte found in the vicinity, this is no mpeg2 ts file */
            if (i==TRAILER_LEN_MAX)
                return WTAP_OPEN_NOT_MINE;
        }
    } while (sync_steps < SYNC_STEPS);

    if (-1 == file_seek(wth->fh, first, SEEK_SET, err)) {
        return WTAP_OPEN_ERROR;
    }

    /* Ensure there is a valid bitrate */
    status = mp2t_bits_per_second(wth, first, trailer_len,
            &bitrate, err, err_info);
    if (status != WTAP_OPEN_MINE) {
        return status;
    }

    /* If the packet didn't start on a sync byte, the "trailer" might
     * be a header. At least BDAV M2TS does this with a four byte header. */
    header_len = MIN(first, trailer_len);
    first -= header_len;
    trailer_len -= header_len;

    if (-1 == file_seek(wth->fh, first, SEEK_SET, err)) {
        return WTAP_OPEN_ERROR;
    }

    wth->file_type_subtype = mp2t_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_MPEG_2_TS;
    wth->file_tsprec = WTAP_TSPREC_NSEC;
    wth->subtype_read = mp2t_read;
    wth->subtype_seek_read = mp2t_seek_read;
    wth->snapshot_length = 0;

    mp2t = g_new(mp2t_filetype_t, 1);

    wth->priv = mp2t;
    mp2t->start_offset = first;
    mp2t->trailer_len = trailer_len;
    mp2t->header_len = header_len;
    mp2t->bitrate = bitrate;

    return WTAP_OPEN_MINE;
}

static int mp2t_dump_can_write_encap(int encap)
{
    /* Per-packet encapsulations aren't supported. */
    if (encap == WTAP_ENCAP_PER_PACKET) {
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
    }

    /* This is the only encapsulation type we write. */
    if (encap != WTAP_ENCAP_MPEG_2_TS) {
        return WTAP_ERR_UNWRITABLE_ENCAP;
    }

    return 0;
}

/* Write a record for a packet to a dump file.
   Returns true on success, false on failure. */
static bool mp2t_dump(wtap_dumper *wdh, const wtap_rec *rec,
    const uint8_t *pd, int *err, char **err_info _U_)
{
    /* We can only write packet records. */
    if (rec->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
        return false;
    }

    /*
     * Make sure this packet doesn't have a link-layer type that
     * differs from the one for the file.
     */
    if (wdh->file_encap != rec->rec_header.packet_header.pkt_encap) {
        *err = WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
        return false;
    }

    /* A MPEG-2 Transport Stream is just the packet bytes, with no header.
     * The sync byte is supposed to identify where packets start.
     * Note this drops existing headers and trailers currently, since we
     * don't include them in the record.
     */
    if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err)) {
        return false;
    }

    return true;
}

/* Returns true on success, false on failure; sets "*err" to an error code on
   failure */
static bool mp2t_dump_open(wtap_dumper *wdh, int *err _U_, char **err_info _U_)
{
    /* There is no header, so we just always return true. */
    wdh->subtype_write = mp2t_dump;

    return true;
}

static const struct supported_block_type mp2t_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info mp2t_info = {
    "MPEG2 transport stream", "mp2t", "mp2t", "ts;m2ts;mpg",
    false, BLOCKS_SUPPORTED(mp2t_blocks_supported),
    mp2t_dump_can_write_encap, mp2t_dump_open, NULL
};

void register_mp2t(void)
{
    mp2t_file_type_subtype = wtap_register_file_type_subtype(&mp2t_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("MPEG_2_TS",
                                                   mp2t_file_type_subtype);
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
