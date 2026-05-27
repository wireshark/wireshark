/** @file
 *
 * Some content from gtk/help_dlg.h by Laurent Deniel <laurent.deniel@free.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*
 */

#ifndef __HELP_URL_H__
#define __HELP_URL_H__

#include <ws_attributes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file help_url.h
 * "Help" URLs.
 */

/**
 * @brief Identifies a help topic or navigable destination reachable from the UI help system.
 */
typedef enum {
    TOPIC_ACTION_NONE,                              /**< No action; uninitialized or placeholder */

    /* pages online at www.wireshark.org */
    ONLINEPAGE_WIRESHARK_HOME,                      /**< Wireshark project home page */
    ONLINEPAGE_WIRESHARK_WIKI,                      /**< Wireshark community wiki */
    ONLINEPAGE_USERGUIDE,                           /**< Wireshark User's Guide */
    ONLINEPAGE_FAQ,                                 /**< Wireshark Frequently Asked Questions */
    ONLINEPAGE_WIRESHARK_DOWNLOAD,                  /**< Wireshark download page */
    ONLINEPAGE_DOCS,                                /**< Wireshark documentation index */
    ONLINEPAGE_SAMPLE_FILES,                        /**< Sample capture file downloads */
    ONLINEPAGE_CAPTURE_SETUP,                       /**< Guide for setting up packet capture */
    ONLINEPAGE_NETWORK_MEDIA,                       /**< Supported network media types reference */
    ONLINEPAGE_SAMPLE_CAPTURES,                     /**< Online sample captures repository */
    ONLINEPAGE_SECURITY,                            /**< Wireshark security advisories page */
    ONLINEPAGE_ASK,                                 /**< Wireshark Q&A community forum (ask.wireshark.org) */
    ONLINEPAGE_DFILTER_REF,                         /**< Display filter reference documentation */

    /* pages online at stratoshark.org */
    ONLINEPAGE_STRATOSHARK_HOME,                    /**< Stratoshark project home page */
    ONLINEPAGE_STRATOSHARK_WIKI,                    /**< Stratoshark community wiki */
    ONLINEPAGE_STRATOSHARK_DOWNLOAD,                /**< Stratoshark download page */

    /* local manual pages */
    LOCALPAGE_MAN_WIRESHARK         = 100,          /**< Local man page for wireshark(1) */
    LOCALPAGE_MAN_STRATOSHARK,                      /**< Local man page for stratoshark(1) */
    LOCALPAGE_MAN_WIRESHARK_FILTER,                 /**< Local man page for wireshark-filter(4) */
    LOCALPAGE_MAN_CAPINFOS,                         /**< Local man page for capinfos(1) */
    LOCALPAGE_MAN_DUMPCAP,                          /**< Local man page for dumpcap(1) */
    LOCALPAGE_MAN_EDITCAP,                          /**< Local man page for editcap(1) */
    LOCALPAGE_MAN_MERGECAP,                         /**< Local man page for mergecap(1) */
    LOCALPAGE_MAN_RAWSHARK,                         /**< Local man page for rawshark(1) */
    LOCALPAGE_MAN_REORDERCAP,                       /**< Local man page for reordercap(1) */
    LOCALPAGE_MAN_TEXT2PCAP,                        /**< Local man page for text2pcap(1) */
    LOCALPAGE_MAN_TSHARK,                           /**< Local man page for tshark(1) */

    /* Release Notes */
    LOCALPAGE_WIRESHARK_RELEASE_NOTES,              /**< Local Wireshark release notes document */
    LOCALPAGE_STRATOSHARK_RELEASE_NOTES,            /**< Local Stratoshark release notes document */

    /* help pages (textfiles or HTML User's Guide) */
    HELP_CONTENT                    = 200,          /**< Top-level help contents/index page */
    HELP_GETTING_STARTED,                           /**< Getting started overview (currently unused) */
    HELP_CAPTURE_OPTIONS,                           /**< Capture options overview (currently unused) */
    HELP_CAPTURE_FILTERS_DIALOG,                    /**< Help for the Capture Filters dialog */
    HELP_DISPLAY_FILTERS_DIALOG,                    /**< Help for the Display Filters dialog */
    HELP_FILTER_EXPRESSION_DIALOG,                  /**< Help for the Filter Expression dialog */
    HELP_DISPLAY_MACRO_DIALOG,                      /**< Help for the Display Filter Macros dialog */
    HELP_COLORING_RULES_DIALOG,                     /**< Help for the Coloring Rules dialog */
    HELP_CONFIG_PROFILES_DIALOG,                    /**< Help for the Configuration Profiles dialog */
    HELP_PRINT_DIALOG,                              /**< Help for the Print dialog */
    HELP_FIND_DIALOG,                               /**< Help for the Find Packet dialog */
    HELP_FILESET_DIALOG,                            /**< Help for the File Set dialog */
    HELP_FIREWALL_DIALOG,                           /**< Help for the Firewall ACL Rules dialog */
    HELP_GOTO_DIALOG,                               /**< Help for the Go To Packet dialog */
    HELP_CAPTURE_OPTIONS_DIALOG,                    /**< Help for the Capture Options dialog */
    HELP_CAPTURE_MANAGE_INTERFACES_DIALOG,          /**< Help for the Manage Interfaces dialog */
    HELP_ENABLED_PROTOCOLS_DIALOG,                  /**< Help for the Enabled Protocols dialog */
    HELP_ENABLED_HEURISTICS_DIALOG,                 /**< Help for the Enabled Heuristic Dissectors dialog */
    HELP_DECODE_AS_DIALOG,                          /**< Help for the Decode As dialog */
    HELP_DECODE_AS_SHOW_DIALOG,                     /**< Help for the Decode As Show dialog */
    HELP_FOLLOW_STREAM_DIALOG,                      /**< Help for the Follow Stream dialog */
    HELP_SHOW_PACKET_BYTES_DIALOG,                  /**< Help for the Show Packet Bytes dialog */
    HELP_EXPERT_INFO_DIALOG,                        /**< Help for the Expert Information dialog */
    HELP_EXTCAP_OPTIONS_DIALOG,                     /**< Help for the External Capture (extcap) options dialog */
    HELP_STATS_SUMMARY_DIALOG,                      /**< Help for the Capture File Properties/Summary dialog */
    HELP_STATS_PROTO_HIERARCHY_DIALOG,              /**< Help for the Protocol Hierarchy Statistics dialog */
    HELP_STATS_ENDPOINTS_DIALOG,                    /**< Help for the Endpoints statistics dialog */
    HELP_STATS_CONVERSATIONS_DIALOG,                /**< Help for the Conversations statistics dialog */
    HELP_STATS_IO_GRAPH_DIALOG,                     /**< Help for the I/O Graph dialog */
    HELP_STATS_LTE_MAC_TRAFFIC_DIALOG,              /**< Help for the LTE MAC Traffic Statistics dialog */
    HELP_STATS_LTE_RLC_TRAFFIC_DIALOG,              /**< Help for the LTE RLC Traffic Statistics dialog */
    HELP_STATS_TCP_STREAM_GRAPHS_DIALOG,            /**< Help for the TCP Stream Graphs dialog */
    HELP_STATS_WLAN_TRAFFIC_DIALOG,                 /**< Help for the WLAN Traffic Statistics dialog */
    HELP_CAPTURE_INTERFACE_OPTIONS_DIALOG,          /**< Help for the per-interface capture options dialog */
    HELP_PREFERENCES_DIALOG,                        /**< Help for the Preferences dialog */
    HELP_CAPTURE_INFO_DIALOG,                       /**< Help for the Capture Information dialog */
    HELP_EXPORT_FILE_DIALOG,                        /**< Help for the Export Packet Dissections dialog */
    HELP_EXPORT_BYTES_DIALOG,                       /**< Help for the Export Selected Packet Bytes dialog */
    HELP_EXPORT_PDUS_DIALOG,                        /**< Help for the Export PDUs to File dialog */
    HELP_STRIP_HEADERS_DIALOG,                      /**< Help for the Strip Headers dialog */
    HELP_EXPORT_OBJECT_LIST,                        /**< Help for the Export Objects dialog */
    HELP_OPEN_DIALOG,                               /**< Help for the Open Capture File dialog */
    HELP_MERGE_DIALOG,                              /**< Help for the Merge Capture File dialog */
    HELP_IMPORT_DIALOG,                             /**< Help for the Import from Hex Dump dialog */
    HELP_SAVE_DIALOG,                               /**< Help for the Save Capture File dialog */
    HELP_EXPORT_FILE_WIN32_DIALOG,                  /**< Help for the Win32 Export Packet Dissections dialog */
    HELP_OPEN_WIN32_DIALOG,                         /**< Help for the Win32 Open Capture File dialog */
    HELP_MERGE_WIN32_DIALOG,                        /**< Help for the Win32 Merge Capture File dialog */
    HELP_SAVE_WIN32_DIALOG,                         /**< Help for the Win32 Save Capture File dialog */
    HELP_TIME_SHIFT_DIALOG,                         /**< Help for the Time Shift dialog */
    HELP_TELEPHONY_VOIP_CALLS_DIALOG,               /**< Help for the VoIP Calls telephony dialog */
    HELP_TELEPHONY_RTP_ANALYSIS_DIALOG,             /**< Help for the RTP Stream Analysis dialog */
    HELP_TELEPHONY_RTP_STREAMS_DIALOG,              /**< Help for the RTP Streams dialog */
    HELP_NEW_PACKET_DIALOG,                         /**< Help for the New Packet dialog */
    HELP_IAX2_ANALYSIS_DIALOG,                      /**< Help for the IAX2 Stream Analysis dialog */
    HELP_TELEPHONY_RTP_PLAYER_DIALOG,               /**< Help for the RTP Player dialog */
    HELP_STAT_FLOW_GRAPH,                           /**< Help for the Flow Graph / Sequence diagram dialog */
    HELP_STATS_PLOT_DIALOG                          /**< Help for the Stats Plot dialog */
} topic_action_e;

/** Given a page in the Wireshark User's Guide return its URL. Returns a
 *  URL to a local file if present, or to the online guide if the local
 *  file is unavailable.
 *
 * @param page A page in the User's Guide.
 * @return A static URL. The return value must be freed with g_free().
 */
WS_RETNONNULL char *user_guide_url(const char *page);

/** Given a topic action return its URL. If the attempt fails NULL
 *  will be returned.
 *
 * @param action Topic action.
 * @return A static URL. The return value must be freed with g_free().
 */
WS_RETNONNULL char *topic_action_url(topic_action_e action);

/** Open a specific topic (create a "Help" dialog box or open a webpage).
 *
 * @param topic the topic to display
 */
void topic_action(topic_action_e topic);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __HELP_URL_H__ */
