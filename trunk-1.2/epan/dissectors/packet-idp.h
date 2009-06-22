/* packet-idp.h
 * Declarations for XNS IDP
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

#ifndef __PACKET_IDP_H__
#define __PACKET_IPX_H__

#define IDP_PACKET_TYPE_RIP	1
#define IDP_PACKET_TYPE_ECHO	2
#define IDP_PACKET_TYPE_ERROR	3
#define IDP_PACKET_TYPE_PEP	4
#define IDP_PACKET_TYPE_SPP	5

/*
 * 3Com SMB-over-XNS?
 */
#define IDP_SOCKET_SMB		0x0bbc

#endif
