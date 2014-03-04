/* fileset_dlg.h
 * Definitions for the fileset dialog box
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

#ifndef __FILESET_DLG_H__
#define __FILESET_DLG_H__

/** @file
 *  "File Set" dialog box.
 *  @ingroup dialog_group
 */

/** Enable file set menu items and look for similar files
 *
 * @param cf Capture file struct
 */
extern void fileset_file_opened(const capture_file *cf);

/** Disable file set menu items
 */
extern void fileset_file_closed(void);


/** Open the fileset dialog.
 *
 * @param w calling widget (unused)
 * @param d data from calling widget (unused)
 */
extern void fileset_cb(GtkWidget *w, gpointer d);

/** Open the next file in the file set, or do nothing if already the last file.
 *
 * @param w calling widget (unused)
 * @param d data from calling widget (unused)
 */
extern void fileset_next_cb(GtkWidget *w, gpointer d);

/** Open the previous file in the file set, or do nothing if already the first file.
 *
 * @param w calling widget (unused)
 * @param d data from calling widget (unused)
 */
extern void fileset_previous_cb(GtkWidget *w, gpointer d);

#endif /* fileset_dlg.h */
