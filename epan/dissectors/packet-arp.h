/* packet-arp.h
 * Definitions of routines for ARP packet disassembly that are used
 * elsewhere
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

#ifndef __PACKET_ARP_H__
#define __PACKET_ARP_H__

const gchar *tvb_arphrdaddr_to_str(tvbuff_t *tvb, gint offset, int ad_len, guint16 type);

void dissect_atm_nsap(tvbuff_t *tvb, int offset, int len, proto_tree *tree);

extern const value_string arp_hrd_vals[];

#endif /* packet-atm.h */
