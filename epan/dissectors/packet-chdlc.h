/* packet-chdlc.h
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

#ifndef __PACKET_CHDLC_H__
#define __PACKET_CHDLC_H__

/*
 * See section 4.3.1 of RFC 1547, and
 *
 *	http://www.nethelp.no/net/cisco-hdlc.txt
 */

#define CHDLC_ADDR_UNICAST	0x0f
#define CHDLC_ADDR_MULTICAST	0x8f

extern
gboolean capture_chdlc(const guchar *, int, int, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header);

extern const value_string chdlc_vals[];

void
chdlctype(guint16 chdlctype, tvbuff_t *tvb, int offset_after_chdlctype,
	  packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
	  int chdlctype_id);

#endif
