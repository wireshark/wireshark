/* packet-dcerpc-mapi.h
 * Routines for MS Exchange MAPI dissection
 * Copyright 2002, Ronnie Sahlberg
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

#ifndef __PACKET_DCERPC_MAPI_H
#define __PACKET_DCERPC_MAPI_H

#define MAPI_EC_DO_CONNECT			0x00
#define MAPI_EC_DO_DISCONNECT			0x01
#define MAPI_EC_DO_RPC				0x02
#define MAPI_EC_GET_MORE_RPC			0x03
#define MAPI_EC_REGISTER_PUSH_NOTIFICATION 	0x04
#define MAPI_EC_UNREGISTER_PUSH_NOTIFICATION	0x05
#define MAPI_EC_DUMMY_RPC			0x06
#define MAPI_EC_GET_DC_NAME			0x07
#define MAPI_EC_NET_GET_DC_NAME			0x08
#define MAPI_EC_DO_RPC_EXT			0x09 


#endif
