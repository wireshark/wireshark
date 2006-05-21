/* capture_file_dlg.h
 * Definitions for dialog boxes for handling files
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

#ifndef __CAPTURE_FILE_DLG_H__
#define __CAPTURE_FILE_DLG_H__

/** @file
 *  "Open" / "Close" / "Save" / "Save As" / etc dialog boxes.
 *  @ingroup dialog_group
 */

/** the action to take, after save has been done */
typedef enum {
    after_save_no_action,           /**< no action to take */
    after_save_close_file,          /**< close the file */
    after_save_open_dialog,         /**< open the file open dialog */
    after_save_open_recent_file,    /**< open the specified recent file */
    after_save_open_dnd_file,       /**< open the specified file from drag and drop */
    after_save_merge_dialog,        /**< open the file merge dialog */
    after_save_capture_dialog,      /**< open the capture dialog */
    after_save_exit                 /**< exit program */
} action_after_save_e;

/** Open the "Save As" dialog box.
 *
 * @param action_after_save the action to take, when save completed
 * @param action_after_save_data data for action_after_save
 */
void file_save_as_cmd(action_after_save_e action_after_save, gpointer action_after_save_data);

/** Destroy the save as dialog.
 */
void file_save_as_destroy(void);

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

/*
 * Set the "Save only marked packets" toggle button as appropriate for
 * the current output file type and count of marked packets.
 * Called when the "Save As..." dialog box is created and when either
 * the file type or the marked count changes.
 */
void file_save_update_dynamics(void);

#endif /* capture_file_dlg.h */
