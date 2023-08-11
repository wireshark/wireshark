/* tap-voip.c
 * voip   2023 Niels Widger
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <glib.h>

#include "epan/packet_info.h"
#include "epan/value_string.h"
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/addr_resolv.h>
#include "ui/voip_calls.h"
#include "ui/rtp_stream.h"
#include "epan/sequence_analysis.h"
#include "tap-voip.h"

/* HACKY HACKY
 *
 * The cf_retap_packets call doesn't seem to be necessary
 * when doing VOIP stuff, so it's OK if it's a NOP, it shouldn't get called.
 *
 * ... I don't think.
 */
#include "file.h"
cf_read_status_t
cf_retap_packets(capture_file *cf)
{
    (void)cf;
    return CF_READ_OK;
}

voip_calls_tapinfo_t tapinfo_;
int voip_conv_sel[VOIP_CONV_NUM];

void voip_stat_init_tapinfo(void)
{
    memset(&tapinfo_, 0, sizeof(tapinfo_));
    tapinfo_.callsinfos = g_queue_new();

    /* fs_option FLOW_ALL shows the same info as the "SIP Flows" Wireshark tool
     * FLOW_ONLY_INVITES shows the same thing as "VoIP Flows" in Wireshark.
     * not totally sure what this really means right now. I believe we want FLOW_ONLY_INVITES?
     * this matches the Wireshark menu options and shows fewer streams.
     */
    tapinfo_.fs_option = FLOW_ONLY_INVITES;

    // add graph analysis
    tapinfo_.graph_analysis = sequence_analysis_info_new();
    tapinfo_.graph_analysis->name = "voip";
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
 *
 */
