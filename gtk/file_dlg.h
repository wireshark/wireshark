/* file_dlg.h
 * Definitions for dialog boxes for handling files
 *
 * $Id: file_dlg.h,v 1.9 2004/01/31 18:32:36 ulfl Exp $
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

#ifndef __FILE_DLG_H__
#define __FILE_DLG_H__

typedef enum {
    after_save_no_action,
    after_save_close_file,
    after_save_open_dialog,
    after_save_open_recent_file,
    after_save_open_dnd_file,
    after_save_capture_dialog,
    after_save_exit
} action_after_save_e;

void file_save_as_cmd(action_after_save_e action_after_save, gpointer action_after_save_data);


void file_open_cmd_cb(GtkWidget *, gpointer);
void file_save_cmd_cb(GtkWidget *, gpointer);
void file_save_as_cmd_cb(GtkWidget *, gpointer);
void file_close_cmd_cb(GtkWidget *, gpointer);
void file_reload_cmd_cb(GtkWidget *, gpointer);
void select_file_cb(GtkWidget *file_bt, const char *label);

void file_color_import_cmd_cb(GtkWidget *w, gpointer data);
void file_color_export_cmd_cb(GtkWidget *, gpointer);

/* Keys ... */
#define E_FILE_TE_PTR_KEY         "file_te_ptr"
#define E_FILE_SEL_DIALOG_PTR_KEY "file_sel_dialog_ptr"
#define E_FS_CALLER_PTR_KEY       "fs_caller_ptr"

/*
 * Set the "Save only marked packets" toggle button as appropriate for
 * the current output file type and count of marked packets.
 * Called when the "Save As..." dialog box is created and when either
 * the file type or the marked count changes.
 */
void file_set_save_marked_sensitive(void);

#endif /* file_dlg.h */
