/* dlg_utils.h
 * Declarations of utilities to use when constructing dialogs
 *
 * $Id: dlg_utils.h,v 1.15 2004/05/26 03:49:22 ulfl Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __DLG_UTILS_H__
#define __DLG_UTILS_H__

/* Create a dialog box window that belongs to Ethereal's main window,
 * see wíndow_new() for usage */
extern GtkWidget *dlg_window_new(const gchar *title);

/* Create a file selection dialog box window that belongs to Ethereal's
   main window. */
typedef enum {
	FILE_SELECTION_OPEN,
	FILE_SELECTION_SAVE
} file_selection_action_t;
extern GtkWidget *file_selection_new(const gchar *title, file_selection_action_t action);

/* Set the current folder for a file selection dialog. */
extern gboolean file_selection_set_current_folder(GtkWidget *fs, const gchar *filename);

/* Set the "extra" widget for a file selection dialog, with user-supplied
   options. */
extern void file_selection_set_extra_widget(GtkWidget *fs, GtkWidget *extra);

#define E_FILE_SEL_DIALOG_PTR_KEY "file_sel_dialog_ptr"

extern void
file_selection_browse(GtkWidget *file_bt, GtkWidget *file_te, const char *label, file_selection_action_t action);

/* Create a button row for a dialog */
/* the button widgets will be available by OBJECT_GET_DATA(stock_id) */
extern GtkWidget *dlg_button_row_new(gchar *stock_id_first, ...);

/* Set the "activate" signal for a widget to call a routine to
   activate the "OK" button for a dialog box. */
extern void dlg_set_activate(GtkWidget *widget, GtkWidget *ok_button);


/* used by compat_macros.h only */
extern GtkWidget *dlg_radio_button_new_with_label_with_mnemonic(GSList *group,
    const gchar *label, GtkAccelGroup *accel_group);
extern GtkWidget *dlg_check_button_new_with_label_with_mnemonic(const gchar *label,
    GtkAccelGroup *accel_group);
extern GtkWidget *dlg_toggle_button_new_with_label_with_mnemonic(const gchar *label,
			GtkAccelGroup *accel_group);

#endif
