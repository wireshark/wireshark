/* packet_win.h
 * Declarations for popping a window to display current packet
 *
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
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

#ifndef __PACKET_WIN_H__
#define __PACKET_WIN_H__

/** @file
 *  Pop up a window to display the current packet only.
 */

/** Create a new packet window.
 *
 * @param widget parent widget (unused)
 * @param reference open current packet or reference packet
 * @param editable packet window field are editable
 */
extern void new_packet_window(GtkWidget *widget, gboolean reference, gboolean editable);

/** Destroy all popup packet windows.
 */
void destroy_packet_wins(void);

/** Redraw the packet bytes panes of all packet windows. */
void redraw_packet_bytes_packet_wins(void);

/** Redissect all packet windows **/
void redissect_all_packet_windows(void);

#endif
