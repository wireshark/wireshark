/* packet-gre.h
 * Routines and data exported by the dissection code for the
 * Generic Routing Encapsulation (GRE) protocol
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

#define GRE_KEEPALIVE		0x0000
#define GRE_NHRP		0x2001
#define GRE_WCCP		0x883E
#define GRE_ERSPAN_88BE		0x88BE
#define GRE_ERSPAN_22EB		0x22EB
#define GRE_MIKROTIK_EOIP	0x6400
#define GRE_AIROHIVE		0xFEAE
/* ************************************************************************* */
/*              Aruba GRE Encapsulation ID                                   */
/* ************************************************************************* */
#define GRE_ARUBA_8200		0x8200
#define GRE_ARUBA_8210		0x8210
#define GRE_ARUBA_8220		0x8220
#define GRE_ARUBA_8230		0x8230
#define GRE_ARUBA_8240		0x8240
#define GRE_ARUBA_8250		0x8250
#define GRE_ARUBA_8260		0x8260
#define GRE_ARUBA_8270		0x8270
#define GRE_ARUBA_8280		0x8280
#define GRE_ARUBA_8290		0x8290
#define GRE_ARUBA_82A0		0x82A0
#define GRE_ARUBA_82B0		0x82B0
#define GRE_ARUBA_82C0		0x82C0
#define GRE_ARUBA_82D0		0x82D0
#define GRE_ARUBA_82E0		0x82E0
#define GRE_ARUBA_82F0		0x82F0
#define GRE_ARUBA_8300		0x8300
#define GRE_ARUBA_8310		0x8310
#define GRE_ARUBA_8320		0x8320
#define GRE_ARUBA_8330		0x8330
#define GRE_ARUBA_8340		0x8340
#define GRE_ARUBA_8350		0x8350
#define GRE_ARUBA_8360		0x8360
#define GRE_ARUBA_8370		0x8370
#define GRE_ARUBA_9000		0x9000

extern const value_string gre_typevals[];
