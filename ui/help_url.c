/* help_url.c
 *
 * Some content from gtk/help_dlg.c by Laurent Deniel <laurent.deniel@free.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <glib.h>

#include "help_url.h"
#include "urls.h"
#include "wsutil/filesystem.h"
#include <wsutil/ws_assert.h>

// To do:
// - Automatically generate part or all of this, e.g. by parsing
//   the DocBook XML or the chunked HTML.

/*
 * Open the help dialog and show a specific HTML help page.
 */
gchar *
user_guide_url(const gchar *page) {
    GString *url = g_string_new("");

#if defined(_WIN32)
    /*
     * The User's Guide is in a directory named "Wireshark User's Guide" in
     * the program directory.
     */

    GString *ug_dir = g_string_new("");
    g_string_printf(ug_dir, "%s\\Wireshark User's Guide", get_datafile_dir());
    if (g_file_test(ug_dir->str, G_FILE_TEST_IS_DIR)) {
        g_string_printf(url, "file:///%s/%s", ug_dir->str, page);
    }
    g_string_free(ug_dir, TRUE);
#elif defined(DOC_DIR)
    if (g_file_test(DOC_DIR "/guides/wsug_html_chunked", G_FILE_TEST_IS_DIR)) {
        /* try to open the HTML page from wireshark.org instead */
        g_string_printf(url, "file://" DOC_DIR "/guides/wsug_html_chunked/%s", page);
    }
#endif /* _WIN32 / DOC_DIR */


    /* Fall back to wireshark.org. */
    if (url->len == 0) {
        g_string_printf(url, WS_DOCS_URL "wsug_html_chunked/%s", page);
    }
    return g_string_free(url, FALSE);
}

gchar *
topic_action_url(topic_action_e action)
{
    gchar *url;

    switch(action) {
    /* pages online at www.wireshark.org */
    case(ONLINEPAGE_HOME):
        url = g_strdup(WS_HOME_PAGE_URL);
        break;
    case(ONLINEPAGE_WIKI):
        url = g_strdup(WS_WIKI_HOME_URL);
        break;
    case(ONLINEPAGE_DOWNLOAD):
        url = g_strdup(WS_DOWNLOAD_URL);
        break;
    case(ONLINEPAGE_DOCS):
        url = g_strdup(WS_DOCS_URL);
        break;
    case(ONLINEPAGE_USERGUIDE):
        url = g_strdup(WS_DOCS_URL "wsug_html_chunked/");
        break;
    case(ONLINEPAGE_FAQ):
        url = g_strdup(WS_FAQ_URL);
        break;
    case(ONLINEPAGE_ASK):
        url = g_strdup(WS_Q_AND_A_URL);
        break;
    case(ONLINEPAGE_SAMPLE_FILES):
        url = g_strdup(WS_WIKI_URL("SampleCaptures"));
        break;
    case(ONLINEPAGE_CAPTURE_SETUP):
        url = g_strdup(WS_WIKI_URL("CaptureSetup"));
        break;
    case(ONLINEPAGE_NETWORK_MEDIA):
        url = g_strdup(WS_WIKI_URL("CaptureSetup/NetworkMedia"));
        break;
    case(ONLINEPAGE_SAMPLE_CAPTURES):
        url = g_strdup(WS_WIKI_URL("SampleCaptures"));
        break;
    case(ONLINEPAGE_SECURITY):
        url = g_strdup(WS_WIKI_URL("Security"));
        break;
    case(ONLINEPAGE_CHIMNEY):
        url = g_strdup(WS_WIKI_URL("CaptureSetup/Offloading#chimney"));
        break;

    /* local manual pages */
    case(LOCALPAGE_MAN_WIRESHARK):
        url = data_file_url("wireshark.html");
        break;
    case(LOCALPAGE_MAN_WIRESHARK_FILTER):
        url = data_file_url("wireshark-filter.html");
        break;
    case(LOCALPAGE_MAN_CAPINFOS):
        url = data_file_url("capinfos.html");
        break;
    case(LOCALPAGE_MAN_DUMPCAP):
        url = data_file_url("dumpcap.html");
        break;
    case(LOCALPAGE_MAN_EDITCAP):
        url = data_file_url("editcap.html");
        break;
    case(LOCALPAGE_MAN_MERGECAP):
        url = data_file_url("mergecap.html");
        break;
    case(LOCALPAGE_MAN_RAWSHARK):
        url = data_file_url("rawshark.html");
        break;
    case(LOCALPAGE_MAN_REORDERCAP):
        url = data_file_url("reordercap.html");
        break;
    case(LOCALPAGE_MAN_TEXT2PCAP):
        url = data_file_url("text2pcap.html");
        break;
    case(LOCALPAGE_MAN_TSHARK):
        url = data_file_url("tshark.html");
        break;

    /* local help pages (User's Guide) */
    case(HELP_CONTENT):
        url = user_guide_url( "index.html");
        break;
    case(HELP_CAPTURE_OPTIONS):
        url = user_guide_url("ChCapCaptureOptions.html");
        break;
    case(HELP_CAPTURE_FILTERS_DIALOG):
        url = user_guide_url("ChWorkDefineFilterSection.html");
        break;
    case(HELP_DISPLAY_FILTERS_DIALOG):
        url = user_guide_url("ChWorkDefineFilterSection.html");
        break;
    case(HELP_FILTER_EXPRESSION_DIALOG):
        url = user_guide_url("ChWorkFilterAddExpressionSection.html");
        break;
    case(HELP_COLORING_RULES_DIALOG):
        url = user_guide_url("ChCustColorizationSection.html");
        break;
    case(HELP_CONFIG_PROFILES_DIALOG):
        url = user_guide_url("ChCustConfigProfilesSection.html");
        break;
    case(HELP_PRINT_DIALOG):
        url = user_guide_url("ChIOPrintSection.html");
        break;
    case(HELP_FIND_DIALOG):
        url = user_guide_url("ChWorkFindPacketSection.html");
        break;
    case(HELP_FIREWALL_DIALOG):
        url = user_guide_url("ChUseToolsMenuSection.html");
        break;
    case(HELP_GOTO_DIALOG):
        url = user_guide_url("ChWorkGoToPacketSection.html");
        break;
    case(HELP_CAPTURE_OPTIONS_DIALOG):
        url = user_guide_url("ChCapCaptureOptions.html");
        break;
    case(HELP_CAPTURE_INFO_DIALOG):
        url = user_guide_url("ChCapRunningSection.html");
        break;
    case(HELP_CAPTURE_MANAGE_INTERFACES_DIALOG):
        url = user_guide_url("ChCapManageInterfacesSection.html");
        break;
    case(HELP_ENABLED_PROTOCOLS_DIALOG):
        url = user_guide_url("ChCustProtocolDissectionSection.html");
        break;
    case(HELP_ENABLED_HEURISTICS_DIALOG):
        url = user_guide_url("ChCustProtocolDissectionSection.html");
        break;
    case(HELP_DECODE_AS_DIALOG):
        url = user_guide_url("ChCustProtocolDissectionSection.html");
        break;
    case(HELP_DECODE_AS_SHOW_DIALOG):
        url = user_guide_url("ChCustProtocolDissectionSection.html");
        break;
    case(HELP_FOLLOW_STREAM_DIALOG):
        url = user_guide_url("ChAdvFollowStreamSection.html");
        break;
    case(HELP_SHOW_PACKET_BYTES_DIALOG):
        url = user_guide_url("ChAdvShowPacketBytes.html");
        break;
    case(HELP_EXPERT_INFO_DIALOG):
        url = user_guide_url("ChAdvExpert.html");
        break;
    case(HELP_EXTCAP_OPTIONS_DIALOG):
        url = data_file_url("extcap.html");
        break;
    case(HELP_STATS_SUMMARY_DIALOG):
        url = user_guide_url("ChStatSummary.html");
        break;
    case(HELP_STATS_PROTO_HIERARCHY_DIALOG):
        url = user_guide_url("ChStatHierarchy.html");
        break;
    case(HELP_STATS_ENDPOINTS_DIALOG):
        url = user_guide_url("ChStatEndpoints.html");
        break;
    case(HELP_STATS_CONVERSATIONS_DIALOG):
        url = user_guide_url("ChStatConversations.html");
        break;
    case(HELP_STATS_IO_GRAPH_DIALOG):
        url = user_guide_url("ChStatIOGraphs.html");
        break;
    case(HELP_STATS_LTE_MAC_TRAFFIC_DIALOG):
        url = user_guide_url("ChTelLTEMACTraffic.html");
        break;
    case(HELP_STATS_LTE_RLC_TRAFFIC_DIALOG):
        url = user_guide_url("ChTelLTERLCTraffic.html");
        break;
    case(HELP_STATS_TCP_STREAM_GRAPHS_DIALOG):
        url = user_guide_url("ChStatTCPStreamGraphs.html");
        break;
    case(HELP_STATS_WLAN_TRAFFIC_DIALOG):
        url = user_guide_url("ChStatWLANTraffic.html");
        break;
    case(HELP_FILESET_DIALOG):
        url = user_guide_url("ChIOFileSetSection.html");
        break;
    case(HELP_CAPTURE_INTERFACE_OPTIONS_DIALOG):
        url = user_guide_url("ChCustPreferencesSection.html#ChCustInterfaceOptionsSection");
        break;
    case(HELP_PREFERENCES_DIALOG):
        url = user_guide_url("ChCustPreferencesSection.html");
        break;
    case(HELP_EXPORT_FILE_DIALOG):
    case(HELP_EXPORT_FILE_WIN32_DIALOG):
        url = user_guide_url("ChIOExportSection.html");
        break;
    case(HELP_EXPORT_BYTES_DIALOG):
        url = user_guide_url("ChIOExportSection.html#ChIOExportSelectedDialog");
        break;
    case(HELP_EXPORT_OBJECT_LIST):
        url = user_guide_url("ChIOExportSection.html#ChIOExportObjectsDialog");
        break;
    case(HELP_OPEN_DIALOG):
    case(HELP_OPEN_WIN32_DIALOG):
        url = user_guide_url("ChIOOpenSection.html");
        break;
    case(HELP_MERGE_DIALOG):
    case(HELP_MERGE_WIN32_DIALOG):
        url = user_guide_url("ChIOMergeSection.html");
        break;
    case(HELP_IMPORT_DIALOG):
        url = user_guide_url("ChIOImportSection.html");
        break;
    case(HELP_SAVE_DIALOG):
    case(HELP_SAVE_WIN32_DIALOG):
        url = user_guide_url("ChIOSaveSection.html");
        break;
    case(HELP_TIME_SHIFT_DIALOG):
        url = user_guide_url("ChWorkShiftTimePacketSection.html");
        break;
    case(HELP_TELEPHONY_VOIP_CALLS_DIALOG):
        url = user_guide_url("ChTelVoipCalls.html");
        break;
    case(HELP_TELEPHONY_RTP_ANALYSIS_DIALOG):
        url = user_guide_url("ChTelRTPAnalysis.html");
        break;
    case(HELP_TELEPHONY_RTP_STREAMS_DIALOG):
        url = user_guide_url("ChTelRTPStreams.html");
        break;
    case(HELP_NEW_PACKET_DIALOG):
        url = user_guide_url("ChapterWork.html#ChWorkPacketSepView");
        break;
    case(HELP_IAX2_ANALYSIS_DIALOG):
        url = user_guide_url("ChTelIAX2Analysis.html");
        break;
    case(HELP_TELEPHONY_RTP_PLAYER_DIALOG):
        url = user_guide_url("ChTelRtpPlayer.html");
        break;
    case(HELP_STAT_FLOW_GRAPH):
        url = user_guide_url("ChStatFlowGraph.html");
        break;

    case(TOPIC_ACTION_NONE):
    default:
        url = g_strdup(WS_HOME_PAGE_URL);
        ws_assert_not_reached();
    }

    return url;
}
