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

#ifndef __PACKET_VXLAN_H__
#define __PACKET_VXLAN_H__

#define VXLAN_IPV4     1
#define VXLAN_IPV6     2
#define VXLAN_ETHERNET 3
#define VXLAN_NSH      4
#define VXLAN_MPLS     5

#endif /* __PACKET_VXLAN_H__ */