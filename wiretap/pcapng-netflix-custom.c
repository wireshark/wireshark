/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "wtap-int.h"
#include "pcapng.h"
#include "pcapng_module.h"

#define NFLX_BLOCK_TYPE_EVENT   1
#define NFLX_BLOCK_TYPE_SKIP    2

typedef struct pcapng_nflx_custom_block_s {
    uint32_t nflx_type;
} pcapng_nflx_custom_block_t;

/*
 * Minimum length of the payload (custom block data plus options) of a
 * Netflix custom bock.
 */
#define MIN_NFLX_CB_SIZE ((uint32_t)sizeof(pcapng_nflx_custom_block_t))

bool
pcapng_read_nflx_custom_block(FILE_T fh, uint32_t block_payload_length,
                              section_info_t *section_info,
                              wtapng_block_t *wblock,
                              int *err, char **err_info)
{
    pcapng_nflx_custom_block_t nflx_cb;
    unsigned opt_cont_buf_len;
    uint32_t type, skipped;

    if (block_payload_length < MIN_NFLX_CB_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: payload length %u of a Netflix CB is too small (< %u)",
                                    block_payload_length, MIN_NFLX_CB_SIZE);
        return false;
    }

    wblock->rec->rec_type = REC_TYPE_CUSTOM_BLOCK;
    wblock->rec->rec_header.custom_block_header.pen = PEN_NFLX;
    /* "NFLX Custom Block" read fixed part */
    if (!wtap_read_bytes(fh, &nflx_cb, sizeof nflx_cb, err, err_info)) {
        ws_debug("Failed to read nflx type");
        return false;
    }
    type = GUINT32_FROM_LE(nflx_cb.nflx_type);
    ws_debug("BBLog type: %u", type);
    switch (type) {
        case NFLX_BLOCK_TYPE_EVENT:
            /*
             * The fixed-length portion is MIN_NFLX_CB_SIZE bytes.
             * We already know we have that much data in the block.
             */
            wblock->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type = BBLOG_TYPE_EVENT_BLOCK;
            opt_cont_buf_len = block_payload_length - MIN_NFLX_CB_SIZE;
            ws_debug("event");
            break;
        case NFLX_BLOCK_TYPE_SKIP:
            /*
             * The fixed-length portion is MIN_NFLX_CB_SIZE bytes plus a
             * 32-bit value.
             *
             * Make sure we have that much data in the block.
             */
            if (block_payload_length < MIN_NFLX_CB_SIZE + (uint32_t)sizeof(uint32_t)) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("pcapng: total block length %u of a Netflix skip CB is too small (< %u)",
                                            block_payload_length,
                                            MIN_NFLX_CB_SIZE + (uint32_t)sizeof(uint32_t));
                return false;
            }
            if (!wtap_read_bytes(fh, &skipped, sizeof(uint32_t), err, err_info)) {
                ws_debug("Failed to read skipped");
                return false;
            }
            wblock->rec->presence_flags = 0;
            wblock->rec->rec_header.custom_block_header.length = 4;
            wblock->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type = BBLOG_TYPE_SKIPPED_BLOCK;
            wblock->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.skipped = GUINT32_FROM_LE(skipped);
            wblock->internal = false;
            opt_cont_buf_len = block_payload_length - MIN_NFLX_CB_SIZE - sizeof(uint32_t);
            ws_debug("skipped: %u", wblock->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.skipped);
            break;
        default:
            ws_debug("Unknown type %u", type);
            return false;
    }

    /*
     * Options.
     *
     * This block type supports only comments and custom options,
     * so it doesn't need a callback.
     */
    if (!pcapng_process_options(fh, wblock, section_info, opt_cont_buf_len,
                                NULL, OPT_LITTLE_ENDIAN, err, err_info))
        return false;

    return true;
}

/*
 * Everything in this is little-endian, regardless of the byte order
 * of the host that wrote the file.
 */
bool
pcapng_process_nflx_custom_option(wtapng_block_t *wblock,
                                  section_info_t *section_info,
                                  const uint8_t *value, uint16_t length)
{
    struct nflx_dumpinfo dumpinfo;
    uint32_t type, version;
    int64_t dumptime, temp;

    if (length < 4) {
        ws_debug("Length = %u too small", length);
        return false;
    }
    memcpy(&type, value, sizeof(uint32_t));
    type = GUINT32_FROM_LE(type);
    value += 4;
    length -= 4;
    ws_debug("Handling type = %u, payload of length = %u", type, length);
    switch (type) {
    case NFLX_OPT_TYPE_VERSION:
        if (length == sizeof(uint32_t)) {
            memcpy(&version, value, sizeof(uint32_t));
            version = GUINT32_FROM_LE(version);
            ws_debug("BBLog version: %u", version);
            section_info->bblog_version = version;
        } else {
            ws_debug("BBLog version parameter has strange length: %u", length);
        }
        break;
    case NFLX_OPT_TYPE_TCPINFO:
        ws_debug("BBLog tcpinfo of length: %u", length);
        if (wblock->type == BLOCK_TYPE_CB_COPY) {
            ws_buffer_assure_space(&wblock->rec->data, length);
            wblock->rec->rec_header.custom_block_header.length = length + 4;
            memcpy(ws_buffer_start_ptr(&wblock->rec->data), value, length);
            memcpy(&temp, value, sizeof(uint64_t));
            temp = GUINT64_FROM_LE(temp);
            wblock->rec->ts.secs = section_info->bblog_offset_tv_sec + temp;
            memcpy(&temp, value + sizeof(uint64_t), sizeof(uint64_t));
            temp = GUINT64_FROM_LE(temp);
            wblock->rec->ts.nsecs = (uint32_t)(section_info->bblog_offset_tv_usec + temp) * 1000;
            if (wblock->rec->ts.nsecs >= 1000000000) {
                wblock->rec->ts.secs += 1;
                wblock->rec->ts.nsecs -= 1000000000;
            }
            wblock->rec->presence_flags = WTAP_HAS_TS;
            wblock->internal = false;
        }
        break;
    case NFLX_OPT_TYPE_DUMPINFO:
        if (length == sizeof(struct nflx_dumpinfo)) {
            memcpy(&dumpinfo, value, sizeof(struct nflx_dumpinfo));
            section_info->bblog_offset_tv_sec = GUINT64_FROM_LE(dumpinfo.tlh_offset_tv_sec);
            section_info->bblog_offset_tv_usec = GUINT64_FROM_LE(dumpinfo.tlh_offset_tv_usec);
            ws_debug("BBLog dumpinfo time offset: %" PRIu64, section_info->bblog_offset_tv_sec);
        } else {
            ws_debug("BBLog dumpinfo parameter has strange length: %u", length);
        }
        break;
    case NFLX_OPT_TYPE_DUMPTIME:
        if (length == sizeof(int64_t)) {
            memcpy(&dumptime, value, sizeof(int64_t));
            dumptime = GINT64_FROM_LE(dumptime);
            ws_debug("BBLog dumpinfo time offset: %" PRIu64, dumptime);
        } else {
            ws_debug("BBLog dumptime parameter has strange length: %u", length);
        }
        break;
    case NFLX_OPT_TYPE_STACKNAME:
        if (length >= 2) {
            ws_debug("BBLog stack name: %.*s(%u)", length - 1, value + 1, *(uint8_t *)value);
        } else {
            ws_debug("BBLog stack name has strange length: %u)", length);
        }
        break;
    default:
        ws_debug("Unknown type: %u, length: %u", type, length);
        break;
    }
    return wtap_block_add_nflx_custom_option(wblock->block, type, value, length) == WTAP_OPTTYPE_SUCCESS;
}

bool
pcapng_write_nflx_custom_block(wtap_dumper *wdh, const wtap_rec *rec, int *err,
                               char **err_info _U_)
{
    pcapng_block_header_t bh;
    uint32_t options_size = 0;
    uint32_t pen, skipped, type;

    /*
     * Compute size of all the options.
     *
     * Only the universal options - comments and custom options -
     * are supported, so we need no option-processing routine.
     */
    options_size = pcapng_compute_options_size(rec->block, NULL);

    /* write block header */
    bh.block_type = BLOCK_TYPE_CB_COPY;
    bh.block_total_length = (uint32_t)(sizeof(bh) + sizeof(uint32_t) + sizeof(uint32_t) + options_size + 4);
    if (rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type == BBLOG_TYPE_SKIPPED_BLOCK) {
        bh.block_total_length += (uint32_t)sizeof(uint32_t);
    }
    ws_debug("writing %u bytes, type %u",
             bh.block_total_length, rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type);
    if (!wtap_dump_file_write(wdh, &bh, sizeof(bh), err)) {
        return false;
    }

    /* write PEN */
    pen = PEN_NFLX;
    if (!wtap_dump_file_write(wdh, &pen, sizeof(uint32_t), err)) {
        return false;
    }
    ws_debug("wrote PEN = %u", pen);

    /* write type */
    type = GUINT32_TO_LE(rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type);
    if (!wtap_dump_file_write(wdh, &type, sizeof(uint32_t), err)) {
        return false;
    }
    ws_debug("wrote type = %u", rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type);

    if (rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type == BBLOG_TYPE_SKIPPED_BLOCK) {
        skipped = GUINT32_TO_LE(rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.skipped);
        if (!wtap_dump_file_write(wdh, &skipped, sizeof(uint32_t), err)) {
            return false;
        }
        ws_debug("wrote skipped = %u", rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.skipped);
    }

    /* Write options, if we have any */
    if (options_size != 0) {
        /*
         * This block type supports only comments and custom options,
         * so it doesn't need a callback.
         */
        if (!pcapng_write_options(wdh, rec->block, NULL, err))
            return false;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err)) {
        return false;
    }

    return true;
}
