/* dlg_utils.h
 * Declarations of utilities to use when constructing dialogs
 *
 * $Id: dlg_utils.h,v 1.5 2000/08/23 06:55:39 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 */

#ifndef __DLG_UTILS_H__
#define __DLG_UTILS_H__

/* Create a dialog box window that belongs to Ethereal's main window. */
GtkWidget *dlg_window_new(const gchar *);

/* Set the "activate" signal for a widget to call a routine to
   activate the "OK" button for a dialog box. */
void dlg_set_activate(GtkWidget *widget, GtkWidget *ok_button);

/* Set the "key_press_event" signal for a top-level dialog window to
   call a routine to activate the "Cancel" button for a dialog box if
   the key being pressed is the <Esc> key. */
void dlg_set_cancel(GtkWidget *widget, GtkWidget *cancel_button);

GtkWidget *dlg_radio_button_new_with_label_with_mnemonic(GSList *group,
    const gchar *label, GtkAccelGroup *accel_group);
GtkWidget *dlg_check_button_new_with_label_with_mnemonic(const gchar *label,
    GtkAccelGroup *accel_group);

#endif
