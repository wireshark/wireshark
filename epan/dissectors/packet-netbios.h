/* packet-netbios.h
 * Declarations of public routines for NetBIOS protocol packet disassembly
 * Jeff Foster <foste@woodward.com>
 * Copyright 1999 Jeffrey C. Foster
 *
 * derived from the packet-nbns.c
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_NETBIOS_H__
#define __PACKET_NETBIOS_H__

/* Length of NetBIOS names */
#define NETBIOS_NAME_LEN	16

void capture_netbios(packet_counts *);

extern int process_netbios_name(const guchar *name_ptr, char *name_ret, int name_ret_len);
extern int get_netbios_name(tvbuff_t *tvb, int offset,
    char *name_ret, int name_ret_len);
extern const char *netbios_name_type_descr(int name_type);
extern void netbios_add_name( const char* label, tvbuff_t *tvb, int offset,
    proto_tree *tree);
extern void dissect_netbios_payload(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree);

#endif
