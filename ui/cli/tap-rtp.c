/* tap-rtp.c
 * RTP TAP for tshark
 *
 * Copyright 2008, Ericsson AB
 * By Balint Reczey <balint.reczey@ericsson.com>
 *
 * based on ui/gtk/rtp_stream_dlg.c
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
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

/*
 * This TAP provides statistics for RTP streams
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <locale.h>

#include <glib.h>

#include <epan/packet_info.h>
#include <epan/value_string.h>
#include <epan/tap.h>
#include <epan/rtp_pt.h>
#include <epan/stat_tap_ui.h>
#include <epan/addr_resolv.h>

#include "ui/rtp_stream.h"
#include "ui/tap-rtp-common.h"

void register_tap_listener_rtp_streams(void);

/* The one and only global rtpstream_tapinfo_t structure for tshark and wireshark.
 */
static rtpstream_tapinfo_t the_tapinfo_struct =
        {NULL, NULL, NULL, NULL, 0, NULL, 0, TAP_ANALYSE, NULL, NULL, NULL, FALSE};

static void
rtp_streams_stat_draw(void *arg _U_)
{
    GList *list;
    rtp_stream_info_t *strinfo;
    gchar *payload_type;
    guint32 expected;
    gint32 lost;
    double perc;
    char *savelocale;
    char *src_addr, *dst_addr;

    printf("========================= RTP Streams ========================\n");
    printf("%15s %5s %15s %5s %10s %16s %5s %12s %15s %15s %15s %s\n","Src IP addr", "Port",  "Dest IP addr", "Port", "SSRC", "Payload", "Pkts", "Lost", "Max Delta(ms)", "Max Jitter(ms)", "Mean Jitter(ms)", "Problems?");

    /* save the current locale */
    savelocale = g_strdup(setlocale(LC_NUMERIC, NULL));
    /* switch to "C" locale to avoid problems with localized decimal separators
       in g_snprintf("%f") functions */
    setlocale(LC_NUMERIC, "C");

    list = the_tapinfo_struct.strinfo_list;

    list = g_list_first(list);
    while (list)
    {
        strinfo = (rtp_stream_info_t*)(list->data);

        /* payload type */
        if (strinfo->payload_type > 95) {
        if (strinfo->payload_type_name != NULL) {
            payload_type = wmem_strdup(NULL, strinfo->payload_type_name);
        }else{
            payload_type = wmem_strdup_printf(NULL, "Unknown(%u)", strinfo->payload_type);
        }

        }else{
            payload_type = val_to_str_ext_wmem(NULL, strinfo->payload_type, &rtp_payload_type_vals_ext, "Unknown (%u)");
        }

        /* packet count, lost packets */
        expected = (strinfo->rtp_stats.stop_seq_nr + strinfo->rtp_stats.cycles*65536)
            - strinfo->rtp_stats.start_seq_nr + 1;
        lost = expected - strinfo->rtp_stats.total_nr;
        if (expected) {
            perc = (double)(lost*100)/(double)expected;
        } else {
            perc = 0;
        }

        src_addr = address_to_display(NULL, &(strinfo->src_addr));
        dst_addr = address_to_display(NULL, &(strinfo->dest_addr));
        printf("%15s %5u %15s %5u 0x%08X %16s %5u %5d (%.1f%%) %15.2f %15.2f %15.2f %s\n",
            src_addr,
            strinfo->src_port,
            dst_addr,
            strinfo->dest_port,
            strinfo->ssrc,
            payload_type,
            strinfo->packet_count,
            lost, perc,
            strinfo->rtp_stats.max_delta,
            strinfo->rtp_stats.max_jitter,
            strinfo->rtp_stats.mean_jitter,
            (strinfo->problem)?"X":"");

        list = g_list_next(list);

        wmem_free(NULL, src_addr);
        wmem_free(NULL, dst_addr);
        wmem_free(NULL, payload_type);
    }

    printf("==============================================================\n");
    /* restore previous locale setting */
    setlocale(LC_NUMERIC, savelocale);
    g_free(savelocale);
}


static void
rtp_streams_stat_init(const char *opt_arg _U_, void *userdata _U_)
{
    GString             *err_p;

    err_p =
        register_tap_listener("rtp", &the_tapinfo_struct, NULL, 0,
            rtpstream_reset_cb,
            rtpstream_packet,
            rtp_streams_stat_draw);

    if (err_p != NULL)
    {
        g_string_free(err_p, TRUE);

        exit(1);
    }
}

static stat_tap_ui rtp_streams_stat_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "rtp,streams",
    rtp_streams_stat_init,
    0,
    NULL
};

void
register_tap_listener_rtp_streams(void)
{
    register_stat_tap_ui(&rtp_streams_stat_ui, NULL);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
