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
 * SPDX-License-Identifier: GPL-2.0-or-later
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

void register_tap_listener_rtpstreams(void);
static void rtpstreams_stat_draw_cb(rtpstream_tapinfo_t *tapinfo);

/* The one and only global rtpstream_tapinfo_t structure for tshark and wireshark.
 */
static rtpstream_tapinfo_t the_tapinfo_struct =
        { NULL, rtpstreams_stat_draw_cb, NULL,
          NULL, 0, NULL, NULL, 0, TAP_ANALYSE, NULL, NULL, NULL, false, false
        };

static void
rtpstreams_stat_draw_cb(rtpstream_tapinfo_t *tapinfo _U_)
{
    GList *list;
    rtpstream_info_t *strinfo;
    rtpstream_info_calc_t calc;
    char *savelocale;

    printf("========================= RTP Streams ========================\n");
    printf("%13s %13s %15s %5s %15s %5s %10s %16s %5s %12s %15s %15s %15s %15s %15s %15s %s\n",
            "Start time", "End time", "Src IP addr", "Port",  "Dest IP addr", "Port", "SSRC", "Payload", "Pkts", "Lost",
            "Min Delta(ms)", "Mean Delta(ms)", "Max Delta(ms)", "Min Jitter(ms)", "Mean Jitter(ms)", "Max Jitter(ms)", "Problems?");

    /* save the current locale */
    savelocale = g_strdup(setlocale(LC_NUMERIC, NULL));
    /* switch to "C" locale to avoid problems with localized decimal separators
       in snprintf("%f") functions */
    setlocale(LC_NUMERIC, "C");

    list = the_tapinfo_struct.strinfo_list;

    list = g_list_first(list);
    while (list)
    {
        strinfo = (rtpstream_info_t*)(list->data);
        rtpstream_info_calculate(strinfo, &calc);

        printf("%13.6f %13.6f %15s %5u %15s %5u 0x%08X %16s %5u %5d (%.1f%%) %15.3f %15.3f %15.3f %15.3f %15.3f %15.3f %s\n",
            nstime_to_sec(&(strinfo->start_rel_time)),
            nstime_to_sec(&(strinfo->stop_rel_time)),
            calc.src_addr_str,
            calc.src_port,
            calc.dst_addr_str,
            calc.dst_port,
            calc.ssrc,
            calc.all_payload_type_names,
            calc.packet_count,
            calc.lost_num,
            calc.lost_perc,
            calc.min_delta,
            calc.mean_delta,
            calc.max_delta,
            calc.min_jitter,
            calc.mean_jitter,
            calc.max_jitter,
            (calc.problem)?"X":"");

        rtpstream_info_calc_free(&calc);

        list = g_list_next(list);
    }

    printf("==============================================================\n");
    /* restore previous locale setting */
    setlocale(LC_NUMERIC, savelocale);
    g_free(savelocale);
}


static void
rtpstreams_stat_init(const char *opt_arg _U_, void *userdata _U_)
{
    register_tap_listener_rtpstream(&the_tapinfo_struct, NULL, NULL);
}

static stat_tap_ui rtpstreams_stat_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "rtp,streams",
    rtpstreams_stat_init,
    0,
    NULL
};

void
register_tap_listener_rtpstreams(void)
{
    register_stat_tap_ui(&rtpstreams_stat_ui, NULL);
}
