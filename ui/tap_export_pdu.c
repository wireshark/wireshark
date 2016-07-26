/* tap_export_pdu.c
 * Routines for exporting PDUs to file
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


#include "globals.h"
#include "wiretap/pcap-encap.h"
#include "wsutil/os_version_info.h"
#include "ws_version_info.h"

#include <epan/tap.h>
#include <epan/exported_pdu.h>
#include <epan/epan_dissect.h>
#include <wiretap/wtap.h>
#include <wiretap/wtap_opttypes.h>
#include <wiretap/pcapng.h>

#include "tap_export_pdu.h"

/* Main entry point to the tap */
static gboolean
export_pdu_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data)
{
    const exp_pdu_data_t *exp_pdu_data = (const exp_pdu_data_t *)data;
    exp_pdu_t  *exp_pdu_tap_data = (exp_pdu_t *)tapdata;
    struct wtap_pkthdr pkthdr;
    int err;
    gchar *err_info;
    int buffer_len;
    guint8 *packet_buf;

    memset(&pkthdr, 0, sizeof(struct wtap_pkthdr));
    buffer_len = exp_pdu_data->tvb_captured_length + exp_pdu_data->tlv_buffer_len;
    packet_buf = (guint8 *)g_malloc(buffer_len);

    if(exp_pdu_data->tlv_buffer_len > 0){
        memcpy(packet_buf, exp_pdu_data->tlv_buffer, exp_pdu_data->tlv_buffer_len);
        g_free(exp_pdu_data->tlv_buffer);
    }
    if(exp_pdu_data->tvb_captured_length > 0){
        tvb_memcpy(exp_pdu_data->pdu_tvb, packet_buf+exp_pdu_data->tlv_buffer_len, 0, exp_pdu_data->tvb_captured_length);
    }
    pkthdr.rec_type  = REC_TYPE_PACKET;
    pkthdr.ts.secs   = pinfo->abs_ts.secs;
    pkthdr.ts.nsecs  = pinfo->abs_ts.nsecs;
    pkthdr.caplen    = buffer_len;
    pkthdr.len       = exp_pdu_data->tvb_reported_length + exp_pdu_data->tlv_buffer_len;

    pkthdr.pkt_encap = exp_pdu_tap_data->pkt_encap;

    if (pinfo->fd->flags.has_user_comment)
        pkthdr.opt_comment = g_strdup(epan_get_user_comment(edt->session, pinfo->fd));
    else if (pinfo->fd->flags.has_phdr_comment)
        pkthdr.opt_comment = g_strdup(pinfo->phdr->opt_comment);

    pkthdr.presence_flags = WTAP_HAS_CAP_LEN|WTAP_HAS_INTERFACE_ID|WTAP_HAS_TS|WTAP_HAS_PACK_FLAGS;

    /* XXX: should the pkthdr.pseudo_header be set to the pinfo's pseudo-header? */
    /* XXX: report errors! */
    if (!wtap_dump(exp_pdu_tap_data->wdh, &pkthdr, packet_buf, &err, &err_info)) {
        switch (err) {

        case WTAP_ERR_UNWRITABLE_REC_DATA:
            g_free(err_info);
            break;

        default:
            break;
        }
    }

    g_free(packet_buf);
    g_free(pkthdr.opt_comment);

    return FALSE; /* Do not redraw */
}

int
exp_pdu_open(exp_pdu_t *exp_pdu_tap_data, int fd, char *comment)
{

    int   err;

    /* pcapng defs */
    wtap_block_t                 shb_hdr;
    GArray                      *shb_hdrs = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));
    wtapng_iface_descriptions_t *idb_inf;
    wtap_block_t                 int_data;
    wtapng_if_descr_mandatory_t *int_data_mand;
    GString                     *os_info_str;
    gsize                        opt_len;
    gchar                       *opt_str;

    /* Create data for SHB  */
    os_info_str = g_string_new("");
    get_os_version_info(os_info_str);

    shb_hdr = wtap_block_create(WTAP_BLOCK_NG_SECTION);

    /* options */
    wtap_block_add_string_option(shb_hdr, OPT_COMMENT, comment, strlen(comment));
    g_free(comment);

    /*
     * UTF-8 string containing the name of the operating system used to create
     * this section.
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
    wtap_block_add_string_option_format(shb_hdr, OPT_SHB_USERAPPL, "Wireshark %s", get_ws_vcs_version_info());

    /* Create fake IDB info */
    idb_inf = g_new(wtapng_iface_descriptions_t,1);
    idb_inf->interface_data = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));

    /* create the fake interface data */
    int_data = wtap_block_create(WTAP_BLOCK_IF_DESCR);
    int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);
    int_data_mand->wtap_encap      = WTAP_ENCAP_WIRESHARK_UPPER_PDU;
    int_data_mand->time_units_per_second = 1000000000; /* default nanosecond resolution */
    int_data_mand->link_type       = wtap_wtap_encap_to_pcap_encap(WTAP_ENCAP_WIRESHARK_UPPER_PDU);
    int_data_mand->snap_len        = WTAP_MAX_PACKET_SIZE;

    wtap_block_add_string_option(int_data, OPT_IDB_NAME, "Fake IF, PDU->Export", strlen("Fake IF, PDU->Export"));
    wtap_block_add_uint8_option(int_data, OPT_IDB_TSRESOL, 9);

    g_array_append_val(idb_inf->interface_data, int_data);

    g_array_append_val(shb_hdrs, shb_hdr);

    /* Use a random name for the temporary import buffer */
    exp_pdu_tap_data->wdh = wtap_dump_fdopen_ng(fd, WTAP_FILE_TYPE_SUBTYPE_PCAPNG, WTAP_ENCAP_WIRESHARK_UPPER_PDU, WTAP_MAX_PACKET_SIZE, FALSE,
        shb_hdrs, idb_inf, NULL, &err);
    if (exp_pdu_tap_data->wdh == NULL) {
        g_assert(err != 0);
        return err;
    }

    return 0;
}

int
exp_pdu_close(exp_pdu_t *exp_pdu_tap_data)
{
    int err = 0;
    if (!wtap_dump_close(exp_pdu_tap_data->wdh, &err))
        g_assert(err != 0);

    remove_tap_listener(exp_pdu_tap_data);
    return err;
}


char *
exp_pdu_pre_open(const char *tap_name, const char *filter, exp_pdu_t *exp_pdu_tap_data)
{
    GString        *error_string;

    /* XXX: can we always assume WTAP_ENCAP_WIRESHARK_UPPER_PDU? */
    exp_pdu_tap_data->pkt_encap = wtap_wtap_encap_to_pcap_encap(WTAP_ENCAP_WIRESHARK_UPPER_PDU);

    /* Register this tap listener now */
    error_string = register_tap_listener(tap_name,             /* The name of the tap we want to listen to */
                                         exp_pdu_tap_data,     /* instance identifier/pointer to a struct holding
                                                                * all state variables */
                                         filter,               /* pointer to a filter string */
                                         TL_REQUIRES_PROTO_TREE,  /* flags for the tap listener */
                                         NULL,
                                         export_pdu_packet,
                                         NULL);
    if (error_string != NULL)
        return g_string_free(error_string, FALSE);

    return NULL;
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
