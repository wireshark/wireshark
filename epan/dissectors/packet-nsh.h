/* packet-nsh.h
 *
 * Routines for Network Service Header
 * draft-ietf-sfc-nsh-01
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

#ifndef __PACKET_NSH_H__
#define __PACKET_NSH_H__

/*Network Service Header (NSH) Next Protocol field values */

#define NSH_IPV4            1
#define NSH_IPV6            2
#define NSH_ETHERNET        3
#define NSH_NSH             4
#define NSH_MPLS            5
#define NSH_EXPERIMENT_1    254
#define NSH_EXPERIMENT_2    255

#endif /* __PACKET_NSH_H__ */
