/* tap_export_pdu.c
 * Routines for exporting PDUs to file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/tap.h>
#include <epan/exported_pdu.h>
#include <epan/epan_dissect.h>
#include <wiretap/wtap.h>
#include <wiretap/wtap_opttypes.h>
#include <wsutil/os_version_info.h>
#include <wsutil/report_message.h>

#include "ui/version_info.h"

#include "tap_export_pdu.h"

/* Main entry point to the tap */
static tap_packet_status
export_pdu_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data, tap_flags_t flags _U_)
{
    const exp_pdu_data_t *exp_pdu_data = (const exp_pdu_data_t *)data;
    exp_pdu_t  *exp_pdu_tap_data = (exp_pdu_t *)tapdata;
    wtap_rec rec;
    int err;
    gchar *err_info;
    int buffer_len;
    guint8 *packet_buf;
    tap_packet_status status = TAP_PACKET_DONT_REDRAW; /* no GUI, nothing to redraw */

    /*
     * Count this packet.
     */
    exp_pdu_tap_data->framenum++;

    memset(&rec, 0, sizeof rec);
    buffer_len = exp_pdu_data->tvb_captured_length + exp_pdu_data->tlv_buffer_len;
    packet_buf = (guint8 *)g_malloc(buffer_len);

    if(exp_pdu_data->tlv_buffer_len > 0){
        memcpy(packet_buf, exp_pdu_data->tlv_buffer, exp_pdu_data->tlv_buffer_len);
    }
    if(exp_pdu_data->tvb_captured_length > 0){
        tvb_memcpy(exp_pdu_data->pdu_tvb, packet_buf+exp_pdu_data->tlv_buffer_len, 0, exp_pdu_data->tvb_captured_length);
    }
    rec.rec_type                           = REC_TYPE_PACKET;
    rec.presence_flags                     = WTAP_HAS_CAP_LEN|WTAP_HAS_INTERFACE_ID|WTAP_HAS_TS;
    rec.ts.secs                            = pinfo->abs_ts.secs;
    rec.ts.nsecs                           = pinfo->abs_ts.nsecs;
    rec.rec_header.packet_header.caplen    = buffer_len;
    rec.rec_header.packet_header.len       = exp_pdu_data->tvb_reported_length + exp_pdu_data->tlv_buffer_len;

    rec.rec_header.packet_header.pkt_encap = exp_pdu_tap_data->pkt_encap;

    /* rec.opt_block is not modified by wtap_dump, but if for some reason the
     * epan_get_modified_block() or pinfo->rec->block are invalidated,
     * copying it here does not hurt. (Can invalidation really happen?) */
    if (pinfo->fd->has_modified_block) {
        rec.block = epan_get_modified_block(edt->session, pinfo->fd);
        rec.block_was_modified = TRUE;
    } else {
        rec.block = pinfo->rec->block;
    }

    /* XXX: should the rec.rec_header.packet_header.pseudo_header be set to the pinfo's pseudo-header? */
    if (!wtap_dump(exp_pdu_tap_data->wdh, &rec, packet_buf, &err, &err_info)) {
        report_cfile_write_failure(NULL, exp_pdu_tap_data->pathname,
                                   err, err_info, exp_pdu_tap_data->framenum,
                                   wtap_dump_file_type_subtype(exp_pdu_tap_data->wdh));
        status = TAP_PACKET_FAILED;
    }

    g_free(packet_buf);

    return status;
}

gboolean
exp_pdu_open(exp_pdu_t *exp_pdu_tap_data, char *pathname,
             int file_type_subtype, int fd, const char *comment,
             int *err, gchar **err_info)
{
    /* pcapng defs */
    wtap_block_t                 shb_hdr;
    wtap_block_t                 int_data;
    wtapng_if_descr_mandatory_t *int_data_mand;
    GString                     *os_info_str;
    gsize                        opt_len;
    gchar                       *opt_str;

    /*
     * If the file format supports a section block, and the section
     * block supports comments, create data for it.
     */
    if (wtap_file_type_subtype_supports_block(file_type_subtype,
                                              WTAP_BLOCK_SECTION) != BLOCK_NOT_SUPPORTED &&
        wtap_file_type_subtype_supports_option(file_type_subtype,
                                               WTAP_BLOCK_SECTION,
                                               OPT_COMMENT) != OPTION_NOT_SUPPORTED) {
        os_info_str = g_string_new("");
        get_os_version_info(os_info_str);

        shb_hdr = wtap_block_create(WTAP_BLOCK_SECTION);

        /* options */
        wtap_block_add_string_option(shb_hdr, OPT_COMMENT, comment, strlen(comment));

        /*
         * UTF-8 string containing the name of the operating system used to
         * create this section.
         */
        opt_len = os_info_str->len;
        opt_str = g_string_free(os_info_str, FALSE);
        if (opt_str) {
            wtap_block_add_string_option(shb_hdr, OPT_SHB_OS, opt_str, opt_len);
            g_free(opt_str);
        }
        /*
         * UTF-8 string containing the name of the application used to create
         * this section.
         */
        wtap_block_add_string_option_format(shb_hdr, OPT_SHB_USERAPPL, "%s",
                                            get_appname_and_version());

        exp_pdu_tap_data->shb_hdrs = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));
        g_array_append_val(exp_pdu_tap_data->shb_hdrs, shb_hdr);
    } else {
        exp_pdu_tap_data->shb_hdrs = NULL;
    }

    /*
     * Create fake interface information for files that support (meaning
     * "require") interface information and per-packet interface IDs.
     */
    if (wtap_file_type_subtype_supports_block(file_type_subtype,
                                              WTAP_BLOCK_IF_ID_AND_INFO) != BLOCK_NOT_SUPPORTED) {
        exp_pdu_tap_data->idb_inf = g_new(wtapng_iface_descriptions_t,1);
        exp_pdu_tap_data->idb_inf->interface_data = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));

        /* create the fake interface data */
        int_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
        int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);
        int_data_mand->wtap_encap      = exp_pdu_tap_data->pkt_encap;
        int_data_mand->time_units_per_second = 1000000000; /* default nanosecond resolution */
        int_data_mand->snap_len        = WTAP_MAX_PACKET_SIZE_STANDARD;

        wtap_block_add_string_option(int_data, OPT_IDB_NAME, "Fake IF, PDU->Export", strlen("Fake IF, PDU->Export"));
        wtap_block_add_uint8_option(int_data, OPT_IDB_TSRESOL, 9);

        g_array_append_val(exp_pdu_tap_data->idb_inf->interface_data, int_data);
    } else {
        exp_pdu_tap_data->idb_inf = NULL;
    }

    const wtap_dump_params params = {
        .encap = exp_pdu_tap_data->pkt_encap,
        .snaplen = WTAP_MAX_PACKET_SIZE_STANDARD,
        .shb_hdrs = exp_pdu_tap_data->shb_hdrs,
        .idb_inf = exp_pdu_tap_data->idb_inf,
    };
    if (fd == 1) {
        exp_pdu_tap_data->wdh = wtap_dump_open_stdout(file_type_subtype,
                WTAP_UNCOMPRESSED, &params, err, err_info);
    } else {
        exp_pdu_tap_data->wdh = wtap_dump_fdopen(fd, file_type_subtype,
                WTAP_UNCOMPRESSED, &params, err, err_info);
    }
    if (exp_pdu_tap_data->wdh == NULL)
        return FALSE;

    exp_pdu_tap_data->pathname = pathname;
    exp_pdu_tap_data->framenum = 0; /* No frames written yet */
    return TRUE;
}

gboolean
exp_pdu_close(exp_pdu_t *exp_pdu_tap_data, int *err, gchar **err_info)
{
    gboolean status;

    status = wtap_dump_close(exp_pdu_tap_data->wdh, NULL, err, err_info);

    wtap_block_array_free(exp_pdu_tap_data->shb_hdrs);
    wtap_free_idb_info(exp_pdu_tap_data->idb_inf);

    remove_tap_listener(exp_pdu_tap_data);
    return status;
}


char *
exp_pdu_pre_open(const char *tap_name, const char *filter, exp_pdu_t *exp_pdu_tap_data)
{
    GString        *error_string;

    /* Register this tap listener now */
    error_string = register_tap_listener(tap_name,             /* The name of the tap we want to listen to */
                                         exp_pdu_tap_data,     /* instance identifier/pointer to a struct holding
                                                                * all state variables */
                                         filter,               /* pointer to a filter string */
                                         TL_REQUIRES_PROTO_TREE,  /* flags for the tap listener */
                                         NULL,
                                         export_pdu_packet,
                                         NULL,
                                         NULL);
    if (error_string != NULL)
        return g_string_free(error_string, FALSE);

    exp_pdu_tap_data->pkt_encap = export_pdu_tap_get_encap(tap_name);

    return NULL;
}
