/* tap_export_pdu.c
 * Routines for exporting PDU:s to file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include "globals.h"
#include "wtap.h"
#include "pcap-encap.h"
#include "wsutil/tempfile.h"
#include "wsutil/os_version_info.h"
#include "wsutil/ws_version_info.h"

#include <epan/tap.h>
#include <epan/exported_pdu.h>

#include "ui/alert_box.h"
#include "ui/simple_dialog.h"
#include "tap_export_pdu.h"

/* Main entry point to the tap */
int
export_pdu_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data)
{
    const exp_pdu_data_t *exp_pdu_data = (const exp_pdu_data_t *)data;
    exp_pdu_t  *exp_pdu_tap_data = (exp_pdu_t *)tapdata;
    struct wtap_pkthdr pkthdr;
    int err;
    int buffer_len;
    guint8 *packet_buf;

    memset(&pkthdr, 0, sizeof(struct wtap_pkthdr));
    buffer_len = exp_pdu_data->tvb_captured_length + exp_pdu_data->tlv_buffer_len;
    packet_buf = (guint8 *)g_malloc(buffer_len);

    if(exp_pdu_data->tlv_buffer_len > 0){
        memcpy(packet_buf, exp_pdu_data->tlv_buffer, exp_pdu_data->tlv_buffer_len);
        g_free(exp_pdu_data->tlv_buffer);
    }
    if(exp_pdu_data->tvb_length > 0){
        tvb_memcpy(exp_pdu_data->pdu_tvb, packet_buf+exp_pdu_data->tlv_buffer_len, 0, exp_pdu_data->tvb_length);
    }
    pkthdr.rec_type  = REC_TYPE_PACKET;
    pkthdr.ts.secs   = pinfo->fd->abs_ts.secs;
    pkthdr.ts.nsecs  = pinfo->fd->abs_ts.nsecs;
    pkthdr.caplen    = buffer_len;
    pkthdr.len       = exp_pdu_data->tvb_reported_length + exp_pdu_data->tlv_buffer_len;

    pkthdr.pkt_encap = exp_pdu_tap_data->pkt_encap;
    pkthdr.opt_comment = g_strdup(pinfo->pkt_comment);
    pkthdr.presence_flags = WTAP_HAS_CAP_LEN|WTAP_HAS_INTERFACE_ID|WTAP_HAS_TS|WTAP_HAS_PACK_FLAGS;

    /* XXX: should the pkthdr.pseudo_header be set to the pinfo's pseudo-header? */

    wtap_dump(exp_pdu_tap_data->wdh, &pkthdr, packet_buf, &err);

    g_free(packet_buf);
    g_free(pkthdr.opt_comment);

    return FALSE; /* Do not redraw */
}

void
exp_pdu_file_open(exp_pdu_t *exp_pdu_tap_data)
{
    int   import_file_fd;
    char *tmpname, *capfile_name;
    int   err;

    /* pcapng defs */
    wtapng_section_t            *shb_hdr;
    wtapng_iface_descriptions_t *idb_inf;
    wtapng_if_descr_t            int_data;
    GString                     *os_info_str;
    char                         appname[100];

    /* Choose a random name for the temporary import buffer */
    import_file_fd = create_tempfile(&tmpname, "Wireshark_PDU_");
    capfile_name = g_strdup(tmpname);

    /* Create data for SHB  */
    os_info_str = g_string_new("");
    get_os_version_info(os_info_str);

    g_snprintf(appname, sizeof(appname), "Wireshark %s", get_ws_vcs_version_info());

    shb_hdr = g_new(wtapng_section_t,1);
    shb_hdr->section_length = -1;
    /* options */
    shb_hdr->opt_comment    = g_strdup_printf("Dump of PDU:s from %s", cfile.filename);
    shb_hdr->shb_hardware   = NULL;                    /* UTF-8 string containing the
                                                       * description of the hardware used to create this section.
                                                       */
    shb_hdr->shb_os         = os_info_str->str;        /* UTF-8 string containing the name
                                                       * of the operating system used to create this section.
                                                       */
    g_string_free(os_info_str, FALSE);                /* The actual string is not freed */
    shb_hdr->shb_user_appl  = appname;                /* UTF-8 string containing the name
                                                       *  of the application used to create this section.
                                                       */


    /* Create fake IDB info */
    idb_inf = g_new(wtapng_iface_descriptions_t,1);
    idb_inf->interface_data = g_array_new(FALSE, FALSE, sizeof(wtapng_if_descr_t));

    /* create the fake interface data */
    int_data.wtap_encap            = WTAP_ENCAP_WIRESHARK_UPPER_PDU;
    int_data.time_units_per_second = 1000000; /* default microsecond resolution */
    int_data.link_type             = wtap_wtap_encap_to_pcap_encap(WTAP_ENCAP_WIRESHARK_UPPER_PDU);
    int_data.snap_len              = WTAP_MAX_PACKET_SIZE;
    int_data.if_name               = g_strdup("Fake IF, PDU->Export");
    int_data.opt_comment           = NULL;
    int_data.if_description        = NULL;
    int_data.if_speed              = 0;
    int_data.if_tsresol            = 6;
    int_data.if_filter_str         = NULL;
    int_data.bpf_filter_len        = 0;
    int_data.if_filter_bpf_bytes   = NULL;
    int_data.if_os                 = NULL;
    int_data.if_fcslen             = -1;
    int_data.num_stat_entries      = 0;          /* Number of ISB:s */
    int_data.interface_statistics  = NULL;

    g_array_append_val(idb_inf->interface_data, int_data);

    exp_pdu_tap_data->wdh = wtap_dump_fdopen_ng(import_file_fd, WTAP_FILE_TYPE_SUBTYPE_PCAPNG, WTAP_ENCAP_WIRESHARK_UPPER_PDU, WTAP_MAX_PACKET_SIZE, FALSE, shb_hdr, idb_inf, &err);
    if (exp_pdu_tap_data->wdh == NULL) {
        open_failure_alert_box(capfile_name, err, TRUE);
        goto end;
    }


    /* Run the tap */
    cf_retap_packets(&cfile);


    if (!wtap_dump_close(exp_pdu_tap_data->wdh, &err)) {
        write_failure_alert_box(capfile_name, err);
    }

    remove_tap_listener(exp_pdu_tap_data);

    /* XXX: should this use the open_routine type in the cfile instead of WTAP_TYPE_AUTO? */
    if (cf_open(&cfile, capfile_name, WTAP_TYPE_AUTO, TRUE /* temporary file */, &err) != CF_OK) {
        open_failure_alert_box(capfile_name, err, FALSE);
        goto end;
    }

    switch (cf_read(&cfile, FALSE)) {
    case CF_READ_OK:
    case CF_READ_ERROR:
    /* Just because we got an error, that doesn't mean we were unable
       to read any of the file; we handle what we could get from the
       file. */
    break;

    case CF_READ_ABORTED:
    /* The user bailed out of re-reading the capture file; the
       capture file has been closed - just free the capture file name
       string and return (without changing the last containing
       directory). */
    break;
    }

end:
    g_free(capfile_name);
}

gboolean
do_export_pdu(const char *filter, gchar *tap_name, gpointer data)
{
    GString        *error_string;
    exp_pdu_t  *exp_pdu_tap_data = (exp_pdu_t *)data;

    /* Register this tap listener now */
    error_string = register_tap_listener(tap_name,             /* The name of the tap we want to listen to */
                                         exp_pdu_tap_data,     /* instance identifier/pointer to a struct holding
                                                                * all state variables */
                                         filter,               /* pointer to a filter string */
                                         TL_REQUIRES_NOTHING,  /* flags for the tap listener */
                                         NULL,
                                         export_pdu_packet,
                                         NULL);
    if (error_string){
        /* Error.  We failed to attach to the tap. Clean up */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
        g_string_free(error_string, TRUE);
        return FALSE;
    }

    exp_pdu_file_open(exp_pdu_tap_data);
    return TRUE;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
