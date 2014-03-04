/* packet-rgmp.h
 * Declarations of routines for IGMP/RGMP packet disassembly
 * Copyright 2006 Jaap Keuter
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

#ifndef __PACKET_RGMP_H__
#define __PACKET_RGMP_H__

#define IGMP_RGMP_LEAVE 0xFC
#define IGMP_RGMP_JOIN  0xFD
#define IGMP_RGMP_BYE   0xFE
#define IGMP_RGMP_HELLO 0xFF

int dissect_rgmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);

#endif
