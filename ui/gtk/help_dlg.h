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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef __HELP_DLG_H__
#define __HELP_DLG_H__

#include "ui/help_url.h"

/** @file
 * "Help" dialog box.
 *  @ingroup dialog_group
 */


/** Open a specific topic (create a "Help" dialog box or open a webpage).
 *
 * @param widget parent widget (unused)
 * @param topic the topic to display
 */
void topic_cb(GtkWidget *widget, topic_action_e topic);

/** Open a specific topic called from a menu item.
 *
 * @param widget parent widget (unused)
 * @param event A GdkEventButton *event
 * @param user_data the topic to display
 * @return TRUE
 */
gboolean topic_menu_cb(GtkWidget *widget _U_, GdkEventButton *event _U_, gpointer user_data);

/** Redraw all the help dialog text widgets, to use a new font. */
void help_redraw(void);

#endif
