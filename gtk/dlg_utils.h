/* dlg_utils.h
 * Declarations of utilities to use when constructing dialogs
 *
 * $Id: dlg_utils.h,v 1.18 2004/06/01 17:33:36 ulfl Exp $
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

/** @file
 * Utility functions for dialog boxes, depending on the window functions in 
 * ui_util.h. These dialog box windows will be related to Ethereal's main 
 * window. See window_new() and others in ui_util.h for further explanation 
 * of dialogs and windows in Ethereal.
 */

#ifndef __DLG_UTILS_H__
#define __DLG_UTILS_H__

/** Get the latest opened directory.
 *
 * @return the dirname
 */
char *get_last_open_dir(void);

/** Set the latest opened directory.
 *  Will already be done when using file_selection_new().
 *
 * @param dirname the dirname
 */
void set_last_open_dir(char *dirname);


/** Create a dialog box window that belongs to Ethereal's main window.
 * If you want to create a window, use window_new() instead. 
 * See window_new() for general window usage.
 *
 * @param title the title for the new dialog
 * @return the newly created dialog
 */
extern GtkWidget *dlg_window_new(const gchar *title);

/** the action a file selection is designed for */
typedef enum {
	FILE_SELECTION_OPEN,    /**< open a file */
	FILE_SELECTION_SAVE     /**< save/export a file */
} file_selection_action_t;

/** Create a file selection dialog box window that belongs to Ethereal's
 *  main window. See window_new() for usage.
 *
 * @param title the title for the new file selection dialog
 * @param action the desired action
 * @return the newly created file selection dialog
 */
extern GtkWidget *file_selection_new(const gchar *title, file_selection_action_t action);

/** Set the current folder for a file selection dialog.
 *
 * @param fs the file selection dialog from file_selection_new()
 * @param filename the folder to set
 * @return ???
 * @todo what's the return value?
 */
extern gboolean file_selection_set_current_folder(GtkWidget *fs, const gchar *filename);

/** Set the "extra" widget for a file selection dialog. This is needed to support 
 *  user-supplied options.
 *
 * @param fs the file selection dialog from file_selection_new()
 * @param extra the widget to set
 */
extern void file_selection_set_extra_widget(GtkWidget *fs, GtkWidget *extra);

/** @todo ??? */
#define E_FILE_SEL_DIALOG_PTR_KEY "file_sel_dialog_ptr"

/** Browse the files and fill in the associated text entry.
 *
 * @param file_bt the button that called us (to get the toplevel widget)
 * @param file_te the GtkEntry the dialog will have to fill in the filename
 * @param title the title for the file selection dialog
 * @param action the desired action
 * @todo use the parent widget as the first parameter, not the button
 */
extern void
file_selection_browse(GtkWidget *file_bt, GtkWidget *file_te, const char *title, file_selection_action_t action);

/** Create a button row (with variable number of buttons) for a dialog.
 *  The button widgets will be available by OBJECT_GET_DATA(dlg, stock_id) later.
 *
 * @param stock_id_first the first button (e.g. GTK_STOCK_OK)
 * @param ... the next buttons, just like stock_id_first
 * @return the new button row
 * @todo move this to ui_util.h
 */
extern GtkWidget *dlg_button_row_new(gchar *stock_id_first, ...);

/** Set the "activate" signal for a widget to call a routine to
 *  activate the "OK" button for a dialog box.
 *
 * @param widget a widget which should be connected (usually a GtkEntry)
 * @param ok_button the button to be activated
 * @todo move this to ui_util.h
 */
extern void dlg_set_activate(GtkWidget *widget, GtkWidget *ok_button);


/** used by compat_macros.h only, don't use directly */
extern GtkWidget *dlg_radio_button_new_with_label_with_mnemonic(GSList *group,
    const gchar *label, GtkAccelGroup *accel_group);
/** used by compat_macros.h only, don't use directly */
extern GtkWidget *dlg_check_button_new_with_label_with_mnemonic(const gchar *label,
    GtkAccelGroup *accel_group);
/** used by compat_macros.h only, don't use directly */
extern GtkWidget *dlg_toggle_button_new_with_label_with_mnemonic(const gchar *label,
			GtkAccelGroup *accel_group);

#endif
