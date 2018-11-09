/* packet-icmp-int.h
 * Functions which are shared between ICMPv4 and ICMPv6
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ICMP_INT_H__
#define __PACKET_ICMP_INT_H__


gint dissect_icmp_extension_structure(tvbuff_t * tvb, packet_info *pinfo, gint offset, proto_tree * tree);
#endif
