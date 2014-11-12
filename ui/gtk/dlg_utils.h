/* dlg_utils.h
 * Declarations of utilities to use when constructing dialogs
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

/** @defgroup dialog_group Dialogs
 *
 * Dialogs are specially created windows and are related to their parent windows (usually the main window).
 * See: @ref howto_window_page for details.
 *
 * Normal dialogs are created using dlg_window_new().
 *
 * - "About" about_wireshark_cb()
 * - "Capture Options" capture_prep_cb()
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
 * - "Compute ..." tap_param_dlg_cb()
 * - "Tcp Graph" create_drawing_area()
 * - "Tcp Graph Control" control_panel_create()
 * - "Help for TCP graphing" callback_create_help()
 * - "Tcp Graph Magnify" magnify_create()
 */

/** @file
 * Utilities for dialog boxes. Depending on the window functions in
 * gui_utils.h, see: @ref howto_window_page for details.
 * @ingroup dialog_group
 */

#ifndef __DLG_UTILS_H__
#define __DLG_UTILS_H__

#if defined(_WIN32)
/*
 * We should calculate these values dynamically using MapDialogRect().
 * Unfortunately that requires passing a valid dialog HWND, which we
 * don't have in many cases.
 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa511279.aspx#sizingspacing
 */

#define DLG_OUTER_MARGIN 11
#define DLG_BUTTON_SPACING 7
#define DLG_LABEL_SPACING 5
#define DLG_UNRELATED_SPACING 11

/* elif defined (__APPLE__) */
#else /* Use the GNOME HIG */

/* http://developer.gnome.org/hig-book/3.2/design-window.html.en */

#define DLG_OUTER_MARGIN 12
#define DLG_BUTTON_SPACING 6
#define DLG_LABEL_SPACING 4 /* Not specified. Guessing. */
#define DLG_UNRELATED_SPACING 12

#endif

/** Create a dialog box window that belongs to Wireshark's main window.
 * If you want to create a window, use window_new() instead.
 * See window_new() for general window usage.
 *
 * @param title the title for the new dialog
 * @return the newly created dialog
 */
extern GtkWidget *dlg_window_new(const gchar *title);

/** Create a dialog box window that belongs to Wireshark's main window.
 * If you want to create a window, use window_new_with_geom() instead.
 * See window_new_with_geom() for general window usage.
 *
 * @param title the title for the new dialog
 * @param geom_name A unique name for the geometry of this new dialog
 * @param pos the initial position of the window if a previously saved geometry was not saved or found.
 *     If the initial position does not matter, specify GTK_WIN_POS_NONE.
 * @return the newly created dialog
 */
extern GtkWidget *
dlg_window_new_with_geom(const gchar *title, const gchar *geom_name, GtkWindowPosition pos);

/** Create a configuration dialog box window that belongs to Wireshark's
 * main window and add the name of the current profile name to its title bar
 * If you want to create a window, use window_new() instead.
 * See window_new() for general window usage.
 *
 * @param title the title for the new dialog
 * @return the newly created dialog
 */
extern GtkWidget *dlg_conf_window_new(const gchar *title);

/** Create a button row (with variable number of buttons) for a dialog.
 *  The button widgets will be available by g_object_get_data(dlg, stock_id) later.
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

/** Set the focus and default for the nth item in a button row.
 *
 * @param hbox A button row returned by dlg_button_row_new().
 * @param focus_item The button to focus (0 is the first).
 * @see dlg_button_row_new()
 */
void dlg_button_focus_nth(GtkWidget *hbox, gint focus_item);

#endif
