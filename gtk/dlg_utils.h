/* dlg_utils.h
 * Declarations of utilities to use when constructing dialogs
 *
 * $Id$
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

/** @defgroup dialog_group Dialogs
 *
 * Dialogs are specially created windows and are related to their parent windows (usually the main window). 
 * See: @ref howto_window_page for details.
 *
 * @section normal_dialogs Normal dialogs 
 *
 * Normal dialogs are created using dlg_window_new().
 *
 * - "About" about_ethereal_cb()
 * - "Capture Options" capture_prep()
 * - "Capture" capture_info_ui_create()
 * - "Interface Options" ifopts_edit_cb()
 * - "Coloring Rules" colorize_dialog_new()
 * - "Edit Color Filter" edit_color_filter_dialog_new()
 * - "Compute DCE-RPC SRT statistics" gtk_dcerpcstat_cb()
 * - "Decode As: Show" decode_show_cb()
 * - "Decode As" decode_as_cb()
 * - "Filter Expression" dfilter_expr_dlg_new()
 * - "Compute Fibre Channel Service Response Time statistics" gtk_fcstat_cb()
 * - "Filter" (display and capture) filter_dialog_new()
 * - "Find Packet" find_frame_cb()
 * - "Follow TCP stream" follow_stream_cb()
 * - "Go To Packet" goto_frame_cb()
 * - "Compute LDAP Service Response Time statistics" gtk_ldapstat_cb()
 * - "Preferences" tools_plugins_cmd_cb()
 * - "Print" / "Export" open_print_dialog()
 * - "Progress" create_progress_dlg()
 * - "Enabled Protocols" proto_cb()
 * - "Compute ONC-RPC SRT statistics" gtk_rpcstat_cb()
 * - "RTP Streams" rtpstream_dlg_create()
 * - "Simple Dialog" display_simple_dialog()
 * - "Compute SMB SRT statistics" gtk_smbstat_cb()
 * - "Compute ..." tap_dfilter_dlg_cb()
 * - "Tcp Graph" create_drawing_area()
 * - "Tcp Graph Control" control_panel_create()
 * - "Help for TCP graphing" callback_create_help()
 * - "Tcp Graph Magnify" magnify_create()
 *
 * @section file_sel_dialogs File selection dialogs 
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
 * Utilities for dialog boxes. Depending on the window functions in 
 * gui_utils.h, see: @ref howto_window_page for details.
 * @ingroup dialog_group
 */

#ifndef __DLG_UTILS_H__
#define __DLG_UTILS_H__


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
	FILE_SELECTION_OPEN,            /**< open a file */
	FILE_SELECTION_READ_BROWSE,     /**< browse for a file to read */
	FILE_SELECTION_SAVE,            /**< save/export a file */
	FILE_SELECTION_WRITE_BROWSE     /**< browse for a file to write to */
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


/** Create a button row (with variable number of buttons) for a dialog.
 *  The button widgets will be available by OBJECT_GET_DATA(dlg, stock_id) later.
 *
 * @param stock_id_first the first button (e.g. GTK_STOCK_OK)
 * @param ... the next buttons, just like stock_id_first
 * @return the new button row
 * @todo move this to gui_utils.h
 */
extern GtkWidget *dlg_button_row_new(const gchar *stock_id_first, ...);

/** Set the "activate" signal for a widget to call a routine to
 *  activate the "OK" button for a dialog box.
 *
 * @param widget a widget which should be connected (usually a GtkEntry)
 * @param ok_button the button to be activated
 * @todo move this to gui_utils.h
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
