/* help_dlg.h
 *
 * $Id$
 *
 * Laurent Deniel <laurent.deniel@free.fr>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifndef __HELP_DLG_H__
#define __HELP_DLG_H__

/** @file
 * "Help" dialog box.
 *  @ingroup dialog_group
 */

typedef enum {
    /* pages online at www.wireshark.org */
    ONLINEPAGE_HOME,
    ONLINEPAGE_WIKI,
    ONLINEPAGE_USERGUIDE,
    ONLINEPAGE_FAQ,
    ONLINEPAGE_DOWNLOAD,
    ONLINEPAGE_SAMPLE_FILES,

    /* local manual pages */
    LOCALPAGE_MAN_WIRESHARK = 100,
    LOCALPAGE_MAN_WIRESHARK_FILTER,
    LOCALPAGE_MAN_TSHARK,
    LOCALPAGE_MAN_DUMPCAP,
    LOCALPAGE_MAN_MERGECAP,
    LOCALPAGE_MAN_EDITCAP,
    LOCALPAGE_MAN_TEXT2PCAP,

    /* help pages (textfiles or local HTML User's Guide) */
    HELP_CONTENT = 200,
    HELP_GETTING_STARTED,           /* currently unused */
    HELP_CAPTURE_OPTIONS_DIALOG,
    HELP_CAPTURE_FILTERS_DIALOG,
    HELP_DISPLAY_FILTERS_DIALOG,
    HELP_COLORING_RULES_DIALOG,
    HELP_PRINT_DIALOG,
    HELP_FIND_DIALOG,
    HELP_FILESET_DIALOG,
    HELP_GOTO_DIALOG,
    HELP_CAPTURE_INTERFACES_DIALOG,
    HELP_ENABLED_PROTOCOLS_DIALOG,
    HELP_DECODE_AS_DIALOG,
    HELP_DECODE_AS_SHOW_DIALOG,
    HELP_FOLLOW_TCP_STREAM_DIALOG,  /* currently unused */
    HELP_STATS_SUMMARY_DIALOG,
    HELP_STATS_PROTO_HIERARCHY_DIALOG,
    HELP_STATS_ENDPOINTS_DIALOG,
    HELP_STATS_CONVERSATIONS_DIALOG,
    HELP_STATS_IO_GRAPH_DIALOG,
    HELP_CAPTURE_INTERFACES_DETAILS_DIALOG,
    HELP_PREFERENCES_DIALOG,
    HELP_CAPTURE_INFO_DIALOG
} topic_action_e;


/** Open a specific topic (create a "Help" dialog box or open a webpage).
 *
 * @param widget parent widget (unused)
 * @param topic the topic to display
 */
void topic_cb(GtkWidget *widget, topic_action_e topic);

/** Open a specific topic called from a menu item.
 *
 * @param widget parent widget (unused)
 * @param data user_data (unused)
 * @param topic the topic to display
 */
void topic_menu_cb(GtkWidget *widget _U_, gpointer data _U_, topic_action_e topic);

/** Check, if a specific topic is available.
 *
 * @param action the topic action to display
 * @return TRUE, if topic is available, FALSE if not
 */
gboolean topic_available(topic_action_e action);

/** Redraw all the help dialog text widgets, to use a new font. */
void help_redraw(void);

#endif
