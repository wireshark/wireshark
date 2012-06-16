/* main_packet_panes.h
 * Definitions for GTK+ packet display structures and routines in the
 * main window (packet details and hex dump panes)
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

#ifndef __MAIN_PACKET_PANES_H__
#define __MAIN_PACKET_PANES_H__

/** @file
 *  Packet tree and details panes.
 *  @ingroup main_window_group
 */

/** Create byte views in the main window.
 */
void add_main_byte_views(epan_dissect_t *edt);

/** Display the protocol tree in the main window.
 */
void main_proto_tree_draw(proto_tree *protocol_tree);

#endif /* __MAIN_PACKET_PANES_H__ */
