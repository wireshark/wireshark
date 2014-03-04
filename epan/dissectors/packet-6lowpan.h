/* packet-6lowpan.h
 * Routines for 6LoWPAN packet disassembly
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

#ifndef __PACKET_6LOWPAN_H__
#define __PACKET_6LOWPAN_H__

/* Inserts new compression context information into the 6LoWPAN context table.
 * The compression context is distributed via some options added to the neighbor
 * discovery protocol, so the ICMPv6 dissector needs to call this routine.
 */
extern void lowpan_context_insert(guint8 cid, guint16 pan, guint8 plen,
                        struct e_in6_addr *prefix, guint frame);

#endif /* __PACKET_6LOWPAN_H__ */
