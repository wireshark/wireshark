/* capture_file_dlg.h
 * Definitions for dialog boxes for handling files
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

#ifndef __CAPTURE_FILE_DLG_H__
#define __CAPTURE_FILE_DLG_H__

/** @file
 *  "Open" / "Close" / "Save" / "Save As" / etc dialog boxes.
 *  @ingroup dialog_group
 */

/** If there are unsaved changes, ask the user whether to save them,
 * discard them, or cancel the operation that would cause the changes
 * to be lost if not saved.
 *
 * @param cf the capture_file structure for the file to be closed
 * @param from_quit TRUE if this is from a quit operation
 * @param before_what description of the operation, or a null string
 * for an explicit close operation
 *
 * @return TRUE if the user didn't cancel the operation, FALSE if they did
 */
gboolean do_file_close(capture_file *cf, gboolean from_quit, const char *before_what);

/** User requested the "Open" dialog box.
 *
 * @param widget parent widget
 * @param data unused
 */
void file_open_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested the "Merge" dialog box.
 *
 * @param widget parent widget
 * @param data unused
 */
void file_merge_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested the "Save" dialog box.
 *
 * @param widget parent widget
 * @param data unused
 */
void file_save_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested the "Save As" dialog box.
 *
 * @param widget parent widget
 * @param data unused
 */
void file_save_as_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested "Close".
 *
 * @param widget parent widget
 * @param data unused
 */
void file_close_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested the "Export Specified Packets" dialog box.
 *
 * @param widget parent widget
 * @param data unused
 */
void file_export_specified_packets_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested the "Export PDUs to file" dialogue box
 *  and pressed OK to start the export
 *
 * @param widget  parent widget
 * @param data    pointer to internal data used by the export pdu part
 */
void file_export_pdu_ok_cb(GtkWidget *widget, gpointer data);

/** User requested "Reload".
 *
 * @param widget parent widget
 * @param data unused
 */
void file_reload_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested "Import". Currently only called from the color dialog.
 *
 * @param widget parent widget
 * @param data unused
 */
void file_color_import_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested "Export". Currently only called from the color dialog.
 *
 * @param widget parent widget
 * @param data unused
 */
void file_color_export_cmd_cb(GtkWidget *widget, gpointer data);

#endif /* capture_file_dlg.h */
