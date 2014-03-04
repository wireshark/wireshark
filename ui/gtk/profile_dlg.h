/* profile_dlg.h
 * Definitions for dialog box for profiles editing.
 * Stig Bjorlykke <stig@bjorlykke.org>, 2008
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

#ifndef __PROFILE_DLG_H__
#define __PROFILE_DLG_H__

/** @file
 * "Configuration Profiles" dialog box
 * @ingroup dialog_group
 */

/** User requested the "Configuration Profiles" popup menu.
 *
 * @param w parent widget
 * @param event button event
 * @param user_data pointer to user_data (unused)
 */
gboolean profile_show_popup_cb(GtkWidget *w _U_, GdkEvent *event, gpointer user_data _U_);

/** User requested to create a new profile.
 *
 * @param w parent widget (unused)
 * @param data pointer to user_data (unused)
 */
void profile_new_cb (GtkWidget *w _U_, gpointer data _U_);

/** User requested to delete the current profile.
 *
 * @param w parent widget (unused)
 * @param data pointer to user_data (unused)
 */
void profile_delete_cb (GtkWidget *w _U_, gpointer data _U_);

/** User requested to edit the current profile.
 *
 * @param w parent widget (unused)
 * @param data pointer to user_data (unused)
 */
void profile_rename_cb (GtkWidget *w _U_, gpointer data _U_);

/** User requested the "Configuration Profiles" dialog box by menu or toolbar.
 *
 * @param widget parent widget
 */
void profile_dialog_cb(GtkWidget *widget);

#endif /* profile_dlg.h */
