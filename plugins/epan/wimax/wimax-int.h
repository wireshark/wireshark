/* wimax-int.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#ifndef __WIMAX_INT_H__
#define __WIMAX_INT_H__

void wimax_proto_register_wimax_cdma(void);
void wimax_proto_register_wimax_compact_dlmap_ie(void);
void wimax_proto_register_wimax_compact_ulmap_ie(void);
void wimax_proto_register_wimax_fch(void);
void wimax_proto_register_wimax_ffb(void);
void wimax_proto_register_wimax_hack(void);
void wimax_proto_register_wimax_harq_map(void);
void wimax_proto_register_wimax_pdu(void);
void wimax_proto_register_wimax_phy_attributes(void);
void wimax_proto_register_wimax_utility_decoders(void);
void wimax_proto_register_mac_header_generic(void);
void wimax_proto_register_mac_header_type_1(void);
void wimax_proto_register_mac_header_type_2(void);

void wimax_proto_reg_handoff_wimax_pdu(void);
void wimax_proto_reg_handoff_mac_header_generic(void);

#endif
