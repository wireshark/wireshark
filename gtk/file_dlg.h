/* file_dlg.h
 * Definitions for dialog boxes for handling files
 *
 * $Id: file_dlg.h,v 1.2 2001/12/06 02:21:26 guy Exp $
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

void file_open_cmd_cb(GtkWidget *, gpointer);
void file_save_cmd_cb(GtkWidget *, gpointer);
void file_save_as_cmd_cb(GtkWidget *, gpointer);
void file_close_cmd_cb(GtkWidget *, gpointer);
void file_reload_cmd_cb(GtkWidget *, gpointer);

/*
 * Set the "Save only marked packets" toggle button as appropriate for
 * the current output file type and count of marked packets.
 * Called when the "Save As..." dialog box is created and when either
 * the file type or the marked count changes.
 */
void file_set_save_marked_sensitive(void);

#endif /* file_dlg.h */
