/* help_dlg.h
 *
 * $Id$
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

/** User requested the "Help" dialog box by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
void help_cb(GtkWidget *widget, gpointer data);

/** Create a "Help" dialog box and start with a specific topic.
 *  Will show the first page if topic is not found.
 *
 * @param widget parent widget (unused)
 * @param topic the topic to display (a string)
 */
void help_topic_cb(GtkWidget *widget, gpointer topic);

/** Redraw all the text widgets, to use a new font. */
void help_redraw(void);

typedef enum {
    /* pages online at www.ethereal.com */
    ONLINEPAGE_HOME,
    ONLINEPAGE_WIKI,
    ONLINEPAGE_USERGUIDE,
    ONLINEPAGE_FAQ,
    ONLINEPAGE_DOWNLOAD,
    ONLINEPAGE_SAMPLE_FILES,

    /* local manual pages */
    LOCALPAGE_MAN_ETHEREAL = 100,
    LOCALPAGE_MAN_ETHEREAL_FILTER,
    LOCALPAGE_MAN_TETHEREAL,
    LOCALPAGE_MAN_MERGECAP,
    LOCALPAGE_MAN_EDITCAP,
    LOCALPAGE_MAN_TEXT2PCAP,

    /* local help pages (User's Guide) */
#ifdef ETHEREAL_EUG_DIR
    HELP_CONTENT = 200,
    HELP_CAPTURE_OPTIONS_DIALOG,
    HELP_CAPTURE_FILTERS_DIALOG,
    HELP_DISPLAY_FILTERS_DIALOG
#endif
} url_page_action_e;


/** User requested one of the html pages.
 *
 * @param action the page to show
 */
extern void
url_page_action(url_page_action_e action);

/** User requested one of the html pages by button click.
 *
 * @param widget parent widget (unused)
 * @param action the page to show
 */
extern void
url_page_cb(GtkWidget *w _U_, url_page_action_e action);

/** User requested one of the html pages by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 * @param action the page to show
 */
extern void url_page_menu_cb( GtkWidget *widget, gpointer data, url_page_action_e action);

#endif
