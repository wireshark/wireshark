/* wimax-int.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
