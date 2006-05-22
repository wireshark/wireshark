/* file_utils.h
 * Declarations of utilities to use when constructing file selection dialogs
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/** @defgroup filesel_dialog_group File Selection Dialogs
 *
 * Dialogs are specially created windows and are related to their parent windows (usually the main window). 
 * See: @ref howto_window_page for details.
 *
 * File selection dialogs are created using file_selection_new().
 *
 * - "Browse" file_selection_browse()
 * - "Open Capture File" file_open_cmd()
 * - "Save Capture File As" file_save_as_cmd()
 * - "Import Color Filters" file_color_import_cmd_cb()
 * - "Export Color Filters" file_color_export_cmd_cb()
 * - "Save TCP Follow Stream As" follow_save_as_cmd_cb()
 * - "Export Selected Packet Bytes" savehex_cb()
 * - "Save Data As CSV" save_csv_as_cb()
 * - "Save Payload As ..." on_save_bt_clicked()
 * - "Save selected stream in rtpdump" rtpstream_on_save()
 * 
 */

/** @file
 * Utilities for file selection dialog boxes. Depending on the window
 * functions in gui_utils.h, see: @ref howto_window_page for details.
 * @ingroup filesel_dialog_group
 */

#ifndef __FILE_DLG_H__
#define __FILE_DLG_H__

/** the action a file selection is designed for */
typedef enum {
	FILE_SELECTION_OPEN,            /**< open a file */
	FILE_SELECTION_READ_BROWSE,     /**< browse for a file to read */
	FILE_SELECTION_SAVE,            /**< save/export a file */
	FILE_SELECTION_WRITE_BROWSE     /**< browse for a file to write to */
} file_selection_action_t;

/** Create a file selection dialog box window that belongs to Wireshark's
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
 * @return TRUE if the folder could be changed successfully
 */
extern gboolean file_selection_set_current_folder(GtkWidget *fs, const gchar *filename);

/** Set the "extra" widget for a file selection dialog. This is needed to support 
 *  user-supplied options.
 *
 * @param fs the file selection dialog from file_selection_new()
 * @param extra the widget to set
 */
extern void file_selection_set_extra_widget(GtkWidget *fs, GtkWidget *extra);

/** The function file_selection_browse() will OBJECT_SET_DATA() itself on it's parent window.
 *  When destroying the parent window, it can close the corresponding file selection. */
#define E_FILE_SEL_DIALOG_PTR_KEY "file_sel_dialog_ptr"

/** Browse the files and fill in the associated text entry.
 *
 * @param file_bt the button that called us (to get the toplevel widget)
 * @param file_te the GtkEntry the dialog will have to fill in the filename
 * @param title the title for the file selection dialog
 * @param action the desired action
 */
extern void
file_selection_browse(GtkWidget *file_bt, GtkWidget *file_te, const char *title, file_selection_action_t action);

/** Get the latest opened directory.
 *
 * @return the dirname
 */
extern char *get_last_open_dir(void);

/** Set the latest opened directory.
 *  Will already be done when using file_selection_new().
 *
 * @param dirname the dirname
 */
extern void set_last_open_dir(char *dirname);

#endif
