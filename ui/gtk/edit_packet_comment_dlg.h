/* edit_packet_comment_dlg.h
 * Dialog box for editing or adding packet comments.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __EDIT_PACKET_COMMENTS_H__
#define __EDIT_PACKET_COMMENTS_H__

void edit_packet_comment_dlg (GtkAction *action, gpointer data);
void show_packet_comment_summary_dlg(GtkAction *action, gpointer data);
void edit_capture_dlg_launch (void);

#endif /* __EDIT_PACKET_COMMENTS_H__ */
