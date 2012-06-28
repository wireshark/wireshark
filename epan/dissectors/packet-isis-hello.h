/* packet-isis-hello.h
 * Declares for hello handling inside isis.
 *
 * $Id$
 * Stuart Stanley <stuarts@mxmail.net>
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

#ifndef _PACKET_ISIS_HELLO_H
#define _PACKET_ISIS_HELLO_H

/*
 * Declarations for L1/L2 hello base header.
 */
#define ISIS_HELLO_CTYPE_MASK		0x03
#define ISIS_HELLO_CT_RESERVED_MASK	0xfc
#define ISIS_HELLO_PRIORITY_MASK	0x7f
#define ISIS_HELLO_P_RESERVED_MASK	0x80

#define ISIS_HELLO_TYPE_RESERVED	0
#define ISIS_HELLO_TYPE_LEVEL_1		1
#define ISIS_HELLO_TYPE_LEVEL_2		2
#define ISIS_HELLO_TYPE_LEVEL_12	3

/*
 * misc. bittest macros
 */

#define ISIS_RESTART_RR                 0x01
#define ISIS_RESTART_RA                 0x02
#define ISIS_RESTART_SA                 0x04
#define ISIS_MASK_RESTART_RR(x)            ((x)&ISIS_RESTART_RR)
#define ISIS_MASK_RESTART_RA(x)            ((x)&ISIS_RESTART_RA)
#define ISIS_MASK_RESTART_SA(x)            ((x)&ISIS_RESTART_SA)

/*
 * Published API functions.  NOTE, this are "local" API functions and
 * are only valid from with isis decodes.
 */
extern void isis_dissect_isis_hello(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	int offset, int hello_type, int header_length,int id_length);
extern void isis_register_hello(int proto_isis);

#endif /* _PACKET_ISIS_HELLO_H */
