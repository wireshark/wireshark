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
#include "wtap_opttypes.h"
#include "pcapng.h"
#include "pcapng_module.h"
#include "pcapng-netflix-custom.h"

/*
 * Per-section information managed and used for Netflix BBLog blocks
 * and options.
 */
typedef struct {
    uint32_t bblog_version;        /**< BBLog: version used */
    uint64_t bblog_offset_tv_sec;  /**< BBLog: UTC offset */
    uint64_t bblog_offset_tv_usec;
} pcapng_nflx_per_section_t;

typedef struct pcapng_nflx_custom_block_s {
    uint32_t nflx_type;
} pcapng_nflx_custom_block_t;

static void *
new_nflx_custom_block_data(void)
{
    return g_new0(pcapng_nflx_per_section_t, 1);
}

static const section_info_funcs_t nflx_custom_block_data_funcs = {
	new_nflx_custom_block_data,
	g_free
};

static pcapng_nflx_per_section_t *
get_nflx_custom_blocK_data(section_info_t *section_info)
{
    return pcapng_get_cb_section_info_data(section_info, PEN_NFLX,
                                           &nflx_custom_block_data_funcs);
}

/*
 * Minimum length of the payload (custom block data plus options) of a
 * Netflix custom bock.
 */
#define MIN_NFLX_CB_SIZE ((uint32_t)sizeof(pcapng_nflx_custom_block_t))

static bool
pcapng_read_nflx_custom_block(FILE_T fh, section_info_t *section_info,
                              wtapng_block_t *wblock,
                              int *err, char **err_info)
{
    pcapng_nflx_custom_block_t nflx_cb;
    unsigned opt_cont_buf_len;
    uint32_t type, skipped;
    wtapng_nflx_custom_mandatory_t *mandatory_data;

    /*
     * Set the record type name for this particular type of custom
     * block.
     */
    wblock->rec->rec_type_name = "Black Box Log Block";
    if (wblock->rec->rec_header.custom_block_header.length < MIN_NFLX_CB_SIZE) {
        *err = WTAP_ERR_REC_MALFORMED;
        *err_info = ws_strdup_printf("pcapng: payload length %u of a Netflix CB is too small (< %u)",
                                     wblock->rec->rec_header.custom_block_header.length,
                                     MIN_NFLX_CB_SIZE);
        return false;
    }

    /* "NFLX Custom Block" read fixed part */
    if (!wtap_read_bytes(fh, &nflx_cb, sizeof nflx_cb, err, err_info)) {
        ws_debug("Failed to read nflx type");
        return false;
    }

    /*
     * Allocate mandatory data.
     */
    wblock->block->mandatory_data = g_new0(wtapng_nflx_custom_mandatory_t, 1);
    mandatory_data = (wtapng_nflx_custom_mandatory_t *)wblock->block->mandatory_data;
    type = GUINT32_FROM_LE(nflx_cb.nflx_type);
    mandatory_data->type = type;
    ws_debug("BBLog type: %u", type);
    switch (type) {
        case NFLX_BLOCK_TYPE_EVENT:
            /*
             * The fixed-length portion is MIN_NFLX_CB_SIZE bytes.
             * We already know we have that much data in the block.
             */
            opt_cont_buf_len = wblock->rec->rec_header.custom_block_header.length - MIN_NFLX_CB_SIZE;
            ws_debug("event");
            break;
        case NFLX_BLOCK_TYPE_SKIP:
            /*
             * The fixed-length portion is MIN_NFLX_CB_SIZE bytes plus a
             * 32-bit value.
             *
             * Make sure we have that much data in the block.
             */
            if (wblock->rec->rec_header.custom_block_header.length < MIN_NFLX_CB_SIZE + (uint32_t)sizeof(uint32_t)) {
                *err = WTAP_ERR_REC_MALFORMED;
                *err_info = ws_strdup_printf("pcapng: payload length %u of a Netflix skip CB is too small (< %u)",
                                             wblock->rec->rec_header.custom_block_header.length,
                                             MIN_NFLX_CB_SIZE + (uint32_t)sizeof(uint32_t));
                return false;
            }
            if (!wtap_read_bytes(fh, &skipped, sizeof(uint32_t), err, err_info)) {
                ws_debug("Failed to read skipped");
                return false;
            }
            wblock->rec->presence_flags = 0;
            wblock->rec->rec_header.custom_block_header.length = 4;
            mandatory_data->skipped = GUINT32_FROM_LE(skipped);
            wblock->internal = false;
            opt_cont_buf_len = wblock->rec->rec_header.custom_block_header.length - MIN_NFLX_CB_SIZE - sizeof(uint32_t);
            ws_debug("skipped: %u", mandatory_data->skipped);
            break;
        default:
            ws_debug("Unknown type %u", type);
            *err = WTAP_ERR_UNSUPPORTED;
            *err_info = g_strdup_printf("pcapng Netflix BBLog block: unknown type %u", type);
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
static bool
pcapng_process_nflx_custom_option(wtapng_block_t *wblock,
                                  section_info_t *section_info,
                                  uint16_t option_code,
                                  const uint8_t *value, uint16_t length)
{
    struct nflx_dumpinfo dumpinfo;
    uint32_t type, version;
    int64_t dumptime, temp;
    pcapng_nflx_per_section_t *nflx_per_section_info;

    if (length < 4) {
        ws_debug("Length = %u too small", length);
        return false;
    }
    if (wtap_block_add_custom_binary_option_from_data(wblock->block, option_code, PEN_NFLX, value, length) != WTAP_OPTTYPE_SUCCESS)
        return false;
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
            nflx_per_section_info = get_nflx_custom_blocK_data(section_info);
            nflx_per_section_info->bblog_version = version;
        } else {
            ws_debug("BBLog version parameter has strange length: %u", length);
        }
        break;
    case NFLX_OPT_TYPE_TCPINFO:
        ws_debug("BBLog tcpinfo of length: %u", length);
        if (wblock->type == BLOCK_TYPE_CB_COPY) {
            /*
             * This is in a BBlog custom block; we append the option's
             * value to the data of the block, and use times from
             * the option to set the time stamp.
             */
            ws_buffer_assure_space(&wblock->rec->data, length);
            wblock->rec->rec_header.custom_block_header.length = length + 4;
            memcpy(ws_buffer_start_ptr(&wblock->rec->data), value, length);
            memcpy(&temp, value, sizeof(uint64_t));
            temp = GUINT64_FROM_LE(temp);
            nflx_per_section_info = get_nflx_custom_blocK_data(section_info);
            wblock->rec->ts.secs = nflx_per_section_info->bblog_offset_tv_sec + temp;
            memcpy(&temp, value + sizeof(uint64_t), sizeof(uint64_t));
            temp = GUINT64_FROM_LE(temp);
            wblock->rec->ts.nsecs = (uint32_t)(nflx_per_section_info->bblog_offset_tv_usec + temp) * 1000;
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
            nflx_per_section_info = get_nflx_custom_blocK_data(section_info);
            nflx_per_section_info->bblog_offset_tv_sec = GUINT64_FROM_LE(dumpinfo.tlh_offset_tv_sec);
            nflx_per_section_info->bblog_offset_tv_usec = GUINT64_FROM_LE(dumpinfo.tlh_offset_tv_usec);
            ws_debug("BBLog dumpinfo time offset: %" PRIu64, nflx_per_section_info->bblog_offset_tv_sec);
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
    return true;
}

static bool
pcapng_write_nflx_custom_block(wtap_dumper *wdh, const wtap_rec *rec, int *err,
                               char **err_info)
{
    pcapng_block_header_t bh;
    uint32_t options_size = 0;
    uint32_t pen, skipped, type;
    wtapng_nflx_custom_mandatory_t *mandatory_data;

    /*
     * Compute size of all the options.
     *
     * Only the universal options - comments and custom options -
     * are supported, so we need no option-processing routine.
     */
    options_size = pcapng_compute_options_size(rec->block, NULL);

    mandatory_data = (wtapng_nflx_custom_mandatory_t *)rec->block->mandatory_data;

    /* write block header */
    bh.block_type = BLOCK_TYPE_CB_COPY;
    bh.block_total_length = (uint32_t)(sizeof(bh) + sizeof(uint32_t) + sizeof(uint32_t) + options_size + 4);
    if (mandatory_data->type == NFLX_BLOCK_TYPE_SKIP) {
        bh.block_total_length += (uint32_t)sizeof(uint32_t);
    }
    ws_debug("writing %u bytes, type %u",
             bh.block_total_length, mandatory_data->type);
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
    type = GUINT32_TO_LE(mandatory_data->type);
    if (!wtap_dump_file_write(wdh, &type, sizeof(uint32_t), err)) {
        return false;
    }
    ws_debug("wrote type = %u", mandatory_data->type);

    if (mandatory_data->type == NFLX_BLOCK_TYPE_SKIP) {
        skipped = GUINT32_TO_LE(mandatory_data->skipped);
        if (!wtap_dump_file_write(wdh, &skipped, sizeof(uint32_t), err)) {
            return false;
        }
        ws_debug("wrote skipped = %u", mandatory_data->skipped);
    }

    /* Write options, if we have any */
    if (options_size != 0) {
        /*
         * This block type supports only comments and custom options,
         * so it doesn't need a callback.
         */
        if (!pcapng_write_options(wdh, OPT_LITTLE_ENDIAN, rec->block, NULL,
                                  err, err_info))
            return false;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err)) {
        return false;
    }

    return true;
}

void register_nflx_custom(void)
{
    static pcapng_custom_block_enterprise_handler_t enterprise_netflix =
    {
        pcapng_read_nflx_custom_block,
        pcapng_process_nflx_custom_option,
        pcapng_write_nflx_custom_block
    };

    register_pcapng_custom_block_enterprise_handler(PEN_NFLX, &enterprise_netflix);
}
