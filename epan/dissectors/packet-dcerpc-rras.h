/* packet-dcerpc-rras.h
 * Routines for the rras (Routing and Remote Access service) MSRPC interface
 * Copyright 2005 Jean-Baptiste Marchand <jbm@hsc.fr>
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

#ifndef __PACKET_DCERPC_RRAS_H
#define __PACKET_DCERPC_RRAS_H

/* MSRPC functions available in the rras interface */

#define RRAS_ADMIN_SERVER_GETINFO 		0x00
#define RRAS_ADMIN_CONNECTION_ENUM		0x01
#define RRAS_ADMIN_CONNECTION_GETINFO		0x02
#define RRAS_ADMIN_CONNECTION_CLEARSTATS 	0x03
#define RRAS_ADMIN_PORT_ENUM			0x04
#define RRAS_ADMIN_PORT_GETINFO			0x05
#define RRAS_ADMIN_PORT_CLEARSTATS		0x06
#define RRAS_ADMIN_PORT_RESET			0x07
#define RRAS_ADMIN_PORT_DISCONNECT		0x08
#define RRAS_RI_TRANS_SET_GLOBALINFO		0x09
#define RRAS_RI_TRANS_GET_GLOBALINFO		0x0a
#define RRAS_RI_GET_HANDLE			0x0b
#define RRAS_RI_CREATE				0x0c
#define RRAS_RI_GETINFO				0x0d
#define RRAS_RI_SETINFO				0x0e
#define RRAS_RI_DELETE				0x0f
#define RRAS_TRANS_REMOVE			0x10
#define RRAS_TRANS_ADD				0x11
#define RRAS_TRANS_GETINFO			0x12
#define RRAS_TRANS_SETINFO			0x13
#define RRAS_RI_ENUM				0x14
#define RRAS_RI_CONNECT				0x15
#define RRAS_RI_DISCONNECT			0x16
#define RRAS_RI_UPDATE_ROUTES			0x17
#define RRAS_RI_QUERY_UPDATE_RESULT		0x18
#define RRAS_RI_UPDATE_PB_INFO			0x19
#define RRAS_MIB_ENTRY_CREATE			0x1a
#define RRAS_MIB_ENTRY_DELETE			0x1b
#define RRAS_MIB_ENTRY_SET			0x1c
#define RRAS_MIB_ENTRY_GET			0x1d
#define RRAS_MIB_GET_FIRST			0x1e
#define RRAS_MIB_GET_NEXT			0x1f
#define RRAS_GET_TRAP_INFO			0x20
#define RRAS_SET_TRAP_INFO			0x21
#define RRAS_ADMIN_CONNECTION_NOTIFICATION	0x22
#define RRAS_ADMIN_SEND_USER_MSG		0x23
#define RRAS_ROUTER_DEVICE_ENUM			0x24
#define RRAS_RI_TRANSPORT_CREATE		0x25
#define RRAS_RI_DEV_GETINFO			0x26
#define RRAS_RI_DEV_SETINFO			0x27
#define RRAS_RI_SET_CRED_EX			0x28
#define RRAS_RI_GET_CRED_EX			0x29
#define RRAS_ADMIN_CONNECTION_REM_QUARANT	0x2a

#endif /* packet-dcerpc-rras.h */



