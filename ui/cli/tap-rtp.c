/* tap-rtp.c
 * RTP TAP for tshark
 *
 * $Id$
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

#include <stdio.h>

#include <string.h>
#include <locale.h>
#include "epan/packet_info.h"
#include "epan/value_string.h"
#include <epan/tap.h>
#include <epan/rtp_pt.h>
#include <epan/stat_cmd_args.h>
#include <epan/addr_resolv.h>
#include "tap-rtp-common.h"

/* The one and only global rtpstream_tapinfo_t structure for tshark and wireshark.
 */
static rtpstream_tapinfo_t the_tapinfo_struct =
        {0, NULL, 0, TAP_ANALYSE, NULL, NULL, NULL, 0, FALSE};

static void
rtp_streams_stat_draw(void *arg _U_)
{


    GList *list;
    rtp_stream_info_t* strinfo;
    gchar *payload_type;
    guint32 expected;
    gint32 lost;
    double perc;
    char *savelocale;

    printf("========================= RTP Streams ========================\n");
    printf("%15s %5s %15s %5s %10s %16s %5s %12s %15s %15s %15s %s\n","Src IP addr", "Port",  "Dest IP addr", "Port", "SSRC", "Payload", "Pkts", "Lost", "Max Delta(ms)", "Max Jitter(ms)", "Mean Jitter(ms)", "Problems?");

    /* save the current locale */
    savelocale = setlocale(LC_NUMERIC, NULL);
    /* switch to "C" locale to avoid problems with localized decimal separators
       in g_snprintf("%f") functions */
    setlocale(LC_NUMERIC, "C");

    list = the_tapinfo_struct.strinfo_list;

    list = g_list_first(list);
    while (list)
    {
        strinfo = (rtp_stream_info_t*)(list->data);

        /* payload type */
        if(strinfo->pt>95){
    	if(strinfo->info_payload_type_str != NULL){
            payload_type = g_strdup(strinfo->info_payload_type_str);
    	}else{
    	    payload_type = g_strdup_printf("Unknown(%u)",strinfo->pt);
    	}

        }else{
    	    payload_type = g_strdup(val_to_str_ext(strinfo->pt, &rtp_payload_type_vals_ext,
	        "Unknown (%u)"));
        }

        /* packet count, lost packets */
	expected = (strinfo->rtp_stats.stop_seq_nr + strinfo->rtp_stats.cycles*65536)
            - strinfo->rtp_stats.start_seq_nr + 1;
        lost = expected - strinfo->rtp_stats.total_nr;
        if (expected){
            perc = (double)(lost*100)/(double)expected;
        } else {
            perc = 0;
        }

        printf("%15s %5u %15s %5u 0x%08X %16s %5u %5d (%.1f%%) %15.2f %15.2f %15.2f %s\n",
            get_addr_name(&(strinfo->src_addr)),
	    strinfo->src_port,
	    get_addr_name(&(strinfo->dest_addr)),
	    strinfo->dest_port,
	    strinfo->ssrc,
	    payload_type,
	    strinfo->npackets,
	    lost, perc,
	    strinfo->rtp_stats.max_delta,
	    strinfo->rtp_stats.max_jitter,
	    strinfo->rtp_stats.mean_jitter,
	    (strinfo->problem)?"X":"");

	list = g_list_next(list);

	g_free(payload_type);

    }

    printf("==============================================================\n");
    /* restore previous locale setting */
    setlocale(LC_NUMERIC, savelocale);
}


static void
rtp_streams_stat_init(const char *optarg _U_, void* userdata _U_)
{
    GString		*err_p;

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


void
register_tap_listener_rtp_streams(void)
{
    register_stat_cmd_arg("rtp,streams", rtp_streams_stat_init,NULL);
}
