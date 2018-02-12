/* packet-vxlan.h
 *
 * Routines for Virtual eXtensible Local Area Network (VXLAN) packet dissection
 * RFC 7348 plus draft-smith-vxlan-group-policy-01
 *
 * (c) Copyright 2016, Sumit Kumar Jha <sjha3@ncsu.edu>
 * Support for VXLAN GPE (https://www.ietf.org/id/draft-ietf-nvo3-vxlan-gpe-02.txt)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_VXLAN_H__
#define __PACKET_VXLAN_H__

#define VXLAN_IPV4     1
#define VXLAN_IPV6     2
#define VXLAN_ETHERNET 3
#define VXLAN_NSH      4
#define VXLAN_MPLS     5

#endif /* __PACKET_VXLAN_H__ */
