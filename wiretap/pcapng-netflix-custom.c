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

#define NFLX_BLOCK_TYPE_EVENT   1
#define NFLX_BLOCK_TYPE_SKIP    2

typedef struct pcapng_nflx_custom_block_s {
    uint32_t nflx_type;
} pcapng_nflx_custom_block_t;

wtap_opttype_return_val
wtap_block_get_nflx_custom_option(wtap_block_t block, uint32_t nflx_type, char* nflx_custom_data, size_t nflx_custom_data_len)
{
    const wtap_opttype_t* opttype;
    wtap_option_t* opt;
    unsigned i;
    char* real_custom_data;

    if (block == NULL) {
        return WTAP_OPTTYPE_BAD_BLOCK;
    }
    opttype = GET_OPTION_TYPE(block->info->options, OPT_CUSTOM_BIN_COPY);
    if (opttype == NULL) {
        return WTAP_OPTTYPE_NO_SUCH_OPTION;
    }
    if (opttype->data_type != WTAP_OPTTYPE_CUSTOM_BINARY) {
        return WTAP_OPTTYPE_TYPE_MISMATCH;
    }

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        if ((opt->option_id == OPT_CUSTOM_BIN_COPY) &&
            (opt->value.custom_binaryval.pen == PEN_NFLX) &&
            (opt->value.custom_binaryval.data.custom_data_len >= sizeof(uint32_t))) {
            uint32_t type;
            memcpy(&type, opt->value.custom_binaryval.data.custom_data, sizeof(uint32_t));
            type = GUINT32_FROM_LE(type);
            if (type == nflx_type)
                break;
        }
    }
    if (i == block->options->len) {
        return WTAP_OPTTYPE_NOT_FOUND;
    }
    if (nflx_custom_data_len + sizeof(uint32_t) < opt->value.custom_binaryval.data.custom_data_len) {
        return WTAP_OPTTYPE_TYPE_MISMATCH;
    }

    /* Custom data includes the type, so it's already been accounted for */
    real_custom_data = ((char*)opt->value.custom_binaryval.data.custom_data) + sizeof(uint32_t);

    switch (nflx_type) {
    case NFLX_OPT_TYPE_VERSION: {
        uint32_t* src, * dst;

        ws_assert(nflx_custom_data_len == sizeof(uint32_t));
        src = (uint32_t*)real_custom_data;
        dst = (uint32_t*)nflx_custom_data;
        *dst = GUINT32_FROM_LE(*src);
        break;
    }
    case NFLX_OPT_TYPE_TCPINFO: {
        struct nflx_tcpinfo* src, * dst;

        /*
         * Do not use sizeof (struct nflx_tcpinfo); see the comment
         * before the definition of OPT_NFLX_TCPINFO_SIZE in
         * wiretap/pcapng-netflix-custom.h.
         */
        ws_assert(nflx_custom_data_len == OPT_NFLX_TCPINFO_SIZE);
        src = (struct nflx_tcpinfo*)real_custom_data;
        dst = (struct nflx_tcpinfo*)nflx_custom_data;
        dst->tlb_tv_sec = GUINT64_FROM_LE(src->tlb_tv_sec);
        dst->tlb_tv_usec = GUINT64_FROM_LE(src->tlb_tv_usec);
        dst->tlb_ticks = GUINT32_FROM_LE(src->tlb_ticks);
        dst->tlb_sn = GUINT32_FROM_LE(src->tlb_sn);
        dst->tlb_stackid = src->tlb_stackid;
        dst->tlb_eventid = src->tlb_eventid;
        dst->tlb_eventflags = GUINT16_FROM_LE(src->tlb_eventflags);
        dst->tlb_errno = GINT32_FROM_LE(src->tlb_errno);
        dst->tlb_rxbuf_tls_sb_acc = GUINT32_FROM_LE(src->tlb_rxbuf_tls_sb_acc);
        dst->tlb_rxbuf_tls_sb_ccc = GUINT32_FROM_LE(src->tlb_rxbuf_tls_sb_ccc);
        dst->tlb_rxbuf_tls_sb_spare = GUINT32_FROM_LE(src->tlb_rxbuf_tls_sb_spare);
        dst->tlb_txbuf_tls_sb_acc = GUINT32_FROM_LE(src->tlb_txbuf_tls_sb_acc);
        dst->tlb_txbuf_tls_sb_ccc = GUINT32_FROM_LE(src->tlb_txbuf_tls_sb_ccc);
        dst->tlb_txbuf_tls_sb_spare = GUINT32_FROM_LE(src->tlb_txbuf_tls_sb_spare);
        dst->tlb_state = GINT32_FROM_LE(src->tlb_state);
        dst->tlb_starttime = GUINT32_FROM_LE(src->tlb_starttime);
        dst->tlb_iss = GUINT32_FROM_LE(src->tlb_iss);
        dst->tlb_flags = GUINT32_FROM_LE(src->tlb_flags);
        dst->tlb_snd_una = GUINT32_FROM_LE(src->tlb_snd_una);
        dst->tlb_snd_max = GUINT32_FROM_LE(src->tlb_snd_max);
        dst->tlb_snd_cwnd = GUINT32_FROM_LE(src->tlb_snd_cwnd);
        dst->tlb_snd_nxt = GUINT32_FROM_LE(src->tlb_snd_nxt);
        dst->tlb_snd_recover = GUINT32_FROM_LE(src->tlb_snd_recover);
        dst->tlb_snd_wnd = GUINT32_FROM_LE(src->tlb_snd_wnd);
        dst->tlb_snd_ssthresh = GUINT32_FROM_LE(src->tlb_snd_ssthresh);
        dst->tlb_srtt = GUINT32_FROM_LE(src->tlb_srtt);
        dst->tlb_rttvar = GUINT32_FROM_LE(src->tlb_rttvar);
        dst->tlb_rcv_up = GUINT32_FROM_LE(src->tlb_rcv_up);
        dst->tlb_rcv_adv = GUINT32_FROM_LE(src->tlb_rcv_adv);
        dst->tlb_flags2 = GUINT32_FROM_LE(src->tlb_flags2);
        dst->tlb_rcv_nxt = GUINT32_FROM_LE(src->tlb_rcv_nxt);
        dst->tlb_rcv_wnd = GUINT32_FROM_LE(src->tlb_rcv_wnd);
        dst->tlb_dupacks = GUINT32_FROM_LE(src->tlb_dupacks);
        dst->tlb_segqlen = GINT32_FROM_LE(src->tlb_segqlen);
        dst->tlb_snd_numholes = GINT32_FROM_LE(src->tlb_snd_numholes);
        dst->tlb_flex1 = GUINT32_FROM_LE(src->tlb_flex1);
        dst->tlb_flex2 = GUINT32_FROM_LE(src->tlb_flex2);
        dst->tlb_fbyte_in = GUINT32_FROM_LE(src->tlb_fbyte_in);
        dst->tlb_fbyte_out = GUINT32_FROM_LE(src->tlb_fbyte_out);
        dst->tlb_snd_scale = src->tlb_snd_scale;
        dst->tlb_rcv_scale = src->tlb_rcv_scale;
        for (i = 0; i < 3; i++) {
            dst->_pad[i] = src->_pad[i];
        }
        dst->tlb_stackinfo_bbr_cur_del_rate = GUINT64_FROM_LE(src->tlb_stackinfo_bbr_cur_del_rate);
        dst->tlb_stackinfo_bbr_delRate = GUINT64_FROM_LE(src->tlb_stackinfo_bbr_delRate);
        dst->tlb_stackinfo_bbr_rttProp = GUINT64_FROM_LE(src->tlb_stackinfo_bbr_rttProp);
        dst->tlb_stackinfo_bbr_bw_inuse = GUINT64_FROM_LE(src->tlb_stackinfo_bbr_bw_inuse);
        dst->tlb_stackinfo_bbr_inflight = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_inflight);
        dst->tlb_stackinfo_bbr_applimited = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_applimited);
        dst->tlb_stackinfo_bbr_delivered = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_delivered);
        dst->tlb_stackinfo_bbr_timeStamp = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_timeStamp);
        dst->tlb_stackinfo_bbr_epoch = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_epoch);
        dst->tlb_stackinfo_bbr_lt_epoch = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_lt_epoch);
        dst->tlb_stackinfo_bbr_pkts_out = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_pkts_out);
        dst->tlb_stackinfo_bbr_flex1 = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_flex1);
        dst->tlb_stackinfo_bbr_flex2 = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_flex2);
        dst->tlb_stackinfo_bbr_flex3 = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_flex3);
        dst->tlb_stackinfo_bbr_flex4 = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_flex4);
        dst->tlb_stackinfo_bbr_flex5 = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_flex5);
        dst->tlb_stackinfo_bbr_flex6 = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_flex6);
        dst->tlb_stackinfo_bbr_lost = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_lost);
        dst->tlb_stackinfo_bbr_pacing_gain = GUINT16_FROM_LE(src->tlb_stackinfo_bbr_lost);
        dst->tlb_stackinfo_bbr_cwnd_gain = GUINT16_FROM_LE(src->tlb_stackinfo_bbr_lost);
        dst->tlb_stackinfo_bbr_flex7 = GUINT16_FROM_LE(src->tlb_stackinfo_bbr_flex7);
        dst->tlb_stackinfo_bbr_bbr_state = src->tlb_stackinfo_bbr_bbr_state;
        dst->tlb_stackinfo_bbr_bbr_substate = src->tlb_stackinfo_bbr_bbr_substate;
        dst->tlb_stackinfo_bbr_inhpts = src->tlb_stackinfo_bbr_inhpts;
        dst->tlb_stackinfo_bbr_ininput = src->tlb_stackinfo_bbr_ininput;
        dst->tlb_stackinfo_bbr_use_lt_bw = src->tlb_stackinfo_bbr_use_lt_bw;
        dst->tlb_stackinfo_bbr_flex8 = src->tlb_stackinfo_bbr_flex8;
        dst->tlb_stackinfo_bbr_pkt_epoch = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_pkt_epoch);
        dst->tlb_len = GUINT32_FROM_LE(src->tlb_len);
        break;
    }
    case NFLX_OPT_TYPE_DUMPINFO: {
        struct nflx_dumpinfo* src, * dst;

        /*
         * This, however, is safe; see the comment before the
         * declaration of struct nflx_dumpinfo in
         * wiretap/pcapng-netflix-custom.h.
         */
        ws_assert(nflx_custom_data_len == sizeof(struct nflx_dumpinfo));
        src = (struct nflx_dumpinfo*)real_custom_data;
        dst = (struct nflx_dumpinfo*)nflx_custom_data;
        dst->tlh_version = GUINT32_FROM_LE(src->tlh_version);
        dst->tlh_type = GUINT32_FROM_LE(src->tlh_type);
        dst->tlh_length = GUINT64_FROM_LE(src->tlh_length);
        dst->tlh_ie_fport = src->tlh_ie_fport;
        dst->tlh_ie_lport = src->tlh_ie_lport;
        for (i = 0; i < 4; i++) {
            dst->tlh_ie_faddr_addr32[i] = src->tlh_ie_faddr_addr32[i];
            dst->tlh_ie_laddr_addr32[i] = src->tlh_ie_laddr_addr32[i];
        }
        dst->tlh_ie_zoneid = src->tlh_ie_zoneid;
        dst->tlh_offset_tv_sec = GUINT64_FROM_LE(src->tlh_offset_tv_sec);
        dst->tlh_offset_tv_usec = GUINT64_FROM_LE(src->tlh_offset_tv_usec);
        memcpy(dst->tlh_id, src->tlh_id, 64);
        memcpy(dst->tlh_reason, src->tlh_reason, 32);
        memcpy(dst->tlh_tag, src->tlh_tag, 32);
        dst->tlh_af = src->tlh_af;
        memcpy(dst->_pad, src->_pad, 7);
        break;
    }
    case NFLX_OPT_TYPE_DUMPTIME: {
        uint64_t* src, * dst;

        ws_assert(nflx_custom_data_len == sizeof(uint64_t));
        src = (uint64_t*)real_custom_data;
        dst = (uint64_t*)nflx_custom_data;
        *dst = GUINT64_FROM_LE(*src);
        break;
    }
    case NFLX_OPT_TYPE_STACKNAME:
        ws_assert(nflx_custom_data_len >= 2);
        memcpy(nflx_custom_data, real_custom_data, nflx_custom_data_len);
        break;
    default:
        return WTAP_OPTTYPE_NOT_FOUND;
    }
    return WTAP_OPTTYPE_SUCCESS;
}

/*
 * Minimum length of the payload (custom block data plus options) of a
 * Netflix custom bock.
 */
#define MIN_NFLX_CB_SIZE ((uint32_t)sizeof(pcapng_nflx_custom_block_t))

bool
pcapng_read_nflx_custom_block(FILE_T fh, section_info_t *section_info,
                              wtapng_block_t *wblock,
                              int *err, char **err_info)
{
    pcapng_nflx_custom_block_t nflx_cb;
    unsigned opt_cont_buf_len;
    uint32_t type, skipped;

    /*
     * Set the record type name for this particular type of custom
     * block.
     */
    wblock->rec->rec_type_name = "Black Box Log Block";
    if (wblock->rec->rec_header.custom_block_header.length < MIN_NFLX_CB_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
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
    type = GUINT32_FROM_LE(nflx_cb.nflx_type);
    ws_debug("BBLog type: %u", type);
    switch (type) {
        case NFLX_BLOCK_TYPE_EVENT:
            /*
             * The fixed-length portion is MIN_NFLX_CB_SIZE bytes.
             * We already know we have that much data in the block.
             */
            wblock->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type = BBLOG_TYPE_EVENT_BLOCK;
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
                *err = WTAP_ERR_BAD_FILE;
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
            wblock->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type = BBLOG_TYPE_SKIPPED_BLOCK;
            wblock->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.skipped = GUINT32_FROM_LE(skipped);
            wblock->internal = false;
            opt_cont_buf_len = wblock->rec->rec_header.custom_block_header.length - MIN_NFLX_CB_SIZE - sizeof(uint32_t);
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
                               char **err_info)
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
