/* packet-arp.h
 * Definitions of routines for ARP packet disassembly that are used
 * elsewhere
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ARP_H__
#define __PACKET_ARP_H__

const char *tvb_arphrdaddr_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, int offset, int ad_len, uint16_t type);

void dissect_atm_nsap(tvbuff_t *tvb, packet_info* pinfo, int offset, int len, proto_tree *tree);

extern const value_string arp_hrd_vals[];

#endif /* packet-atm.h */
