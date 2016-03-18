/* help_dlg.h
 *
 * Some content from gtk/help_dlg.h by Laurent Deniel <laurent.deniel@free.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
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
 *
 */

#ifndef __HELP_URL_H__
#define __HELP_URL_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file help_url.h
 * "Help" URLs.
 */

typedef enum {
    TOPIC_ACTION_NONE,

    /* pages online at www.wireshark.org */
    ONLINEPAGE_HOME,
    ONLINEPAGE_WIKI,
    ONLINEPAGE_USERGUIDE,
    ONLINEPAGE_FAQ,
    ONLINEPAGE_DOWNLOAD,
    ONLINEPAGE_SAMPLE_FILES,
    ONLINEPAGE_CAPTURE_SETUP,
    ONLINEPAGE_NETWORK_MEDIA,
    ONLINEPAGE_SAMPLE_CAPTURES,
    ONLINEPAGE_SECURITY,
    ONLINEPAGE_CHIMNEY,
    ONLINEPAGE_ASK,

    /* local manual pages */
    LOCALPAGE_MAN_WIRESHARK = 100,
    LOCALPAGE_MAN_WIRESHARK_FILTER,
    LOCALPAGE_MAN_CAPINFOS,
    LOCALPAGE_MAN_DUMPCAP,
    LOCALPAGE_MAN_EDITCAP,
    LOCALPAGE_MAN_MERGECAP,
    LOCALPAGE_MAN_RAWSHARK,
    LOCALPAGE_MAN_REORDERCAP,
    LOCALPAGE_MAN_TEXT2PCAP,
    LOCALPAGE_MAN_TSHARK,

    /* help pages (textfiles or local HTML User's Guide) */
    HELP_CONTENT = 200,
    HELP_GETTING_STARTED,           /* currently unused */
    HELP_CAPTURE_OPTIONS_DIALOG,
    HELP_CAPTURE_FILTERS_DIALOG,
    HELP_DISPLAY_FILTERS_DIALOG,
    HELP_FILTER_EXPRESSION_DIALOG,
    HELP_COLORING_RULES_DIALOG,
    HELP_CONFIG_PROFILES_DIALOG,
    HELP_MANUAL_ADDR_RESOLVE_DIALOG, /* GTK+ only? */
    HELP_PRINT_DIALOG,
    HELP_FIND_DIALOG,
    HELP_FILESET_DIALOG,
    HELP_FIREWALL_DIALOG,
    HELP_GOTO_DIALOG,
    HELP_CAPTURE_INTERFACES_DIALOG,
    HELP_CAPTURE_MANAGE_INTERFACES_DIALOG,
    HELP_ENABLED_PROTOCOLS_DIALOG,
    HELP_ENABLED_HEURISTICS_DIALOG,
    HELP_DECODE_AS_DIALOG,
    HELP_DECODE_AS_SHOW_DIALOG,
    HELP_FOLLOW_STREAM_DIALOG,
    HELP_SHOW_PACKET_BYTES_DIALOG,
    HELP_EXPERT_INFO_DIALOG,
#ifdef HAVE_EXTCAP
    HELP_EXTCAP_OPTIONS_DIALOG,
#endif
    HELP_STATS_SUMMARY_DIALOG,
    HELP_STATS_PROTO_HIERARCHY_DIALOG,
    HELP_STATS_ENDPOINTS_DIALOG,
    HELP_STATS_CONVERSATIONS_DIALOG,
    HELP_STATS_IO_GRAPH_DIALOG,
    HELP_STATS_COMPARE_FILES_DIALOG,
    HELP_STATS_LTE_MAC_TRAFFIC_DIALOG,
    HELP_STATS_LTE_RLC_TRAFFIC_DIALOG,
    HELP_STATS_WLAN_TRAFFIC_DIALOG,
    HELP_CAPTURE_INTERFACE_OPTIONS_DIALOG,
    HELP_CAPTURE_INTERFACES_DETAILS_DIALOG,
    HELP_PREFERENCES_DIALOG,
    HELP_CAPTURE_INFO_DIALOG,
    HELP_EXPORT_FILE_DIALOG,
    HELP_EXPORT_BYTES_DIALOG,
    HELP_EXPORT_OBJECT_LIST,
    HELP_OPEN_DIALOG,
    HELP_MERGE_DIALOG,
    HELP_IMPORT_DIALOG,
    HELP_SAVE_DIALOG,
    HELP_EXPORT_FILE_WIN32_DIALOG,
    HELP_EXPORT_BYTES_WIN32_DIALOG,
    HELP_OPEN_WIN32_DIALOG,
    HELP_MERGE_WIN32_DIALOG,
    HELP_SAVE_WIN32_DIALOG,
    HELP_TIME_SHIFT_DIALOG,
    HELP_FILTER_SAVE_DIALOG,
    HELP_TELEPHONY_VOIP_CALLS_DIALOG,
    HELP_RTP_ANALYSIS_DIALOG,
    HELP_NEW_PACKET_DIALOG,
    HELP_IAX2_ANALYSIS_DIALOG,
    HELP_TELEPHONY_RTP_PLAYER_DIALOG
} topic_action_e;

/** Given a filename return a filesystem URL. Relative paths are prefixed with
 * the datafile directory path.
 *
 * @param filename A file name or path. Relative paths will be prefixed with
 * the data file directory path.
 * @return A filesystem URL for the file or NULL on failure. A non-NULL return
 * value must be freed with g_free().
 */
gchar *data_file_url(const gchar *filename);

/** Given a topic action return its online (www.wireshark.org) URL or NULL.
 *
 * @param action Topic action, e.g. ONLINEPAGE_HOME or ONLINEPAGE_ASK.
 * @return A static URL or NULL. MUST NOT be freed.
 */
const char *topic_online_url(topic_action_e action);

/** Given a page in the Wireshark User's Guide return its URL. On Windows
 *  an attempt will be made to open User Guide URLs with HTML Help. If
 *  the attempt succeeds NULL will be returned.
 *
 * @param page A page in the User's Guide.
 * @return A static URL or NULL. A non-NULL return value must be freed
 * with g_free().
 */
gchar *user_guide_url(const gchar *page);

/** Given a topic action return its URL. On Windows an attempt will be
 *  made to open User Guide URLs with HTML Help. If the attempt succeeds
 *  NULL will be returned.
 *
 * @param action Topic action.
 * @return A static URL or NULL. A non-NULL return value must be freed
 * with g_free().
 */
gchar *topic_action_url(topic_action_e action);

/** Open a specific topic (create a "Help" dialog box or open a webpage).
 *
 * @param topic the topic to display
 */
void topic_action(topic_action_e topic);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __HELP_URL_H__ */

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
