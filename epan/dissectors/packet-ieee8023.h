/* packet-ieee8023.h
 * Declaration of routine for dissecting 802.3 (as opposed to D/I/X Ethernet)
 * packets.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __PACKET_IEEE8023_H__
#define __PACKET_IEEE8023_H__

void dissect_802_3(volatile int length, gboolean is_802_2, tvbuff_t *tvb,
    int offset_after_length, packet_info *pinfo, proto_tree *tree,
    proto_tree *fh_tree, int length_id, int trailer_id, expert_field* ei_len, int fcs_len);

#endif
