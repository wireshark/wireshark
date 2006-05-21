/* packet-dcerpc-dfs.h
 * Routines for SMB \PIPE\netdfs packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
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

#ifndef __PACKET_DCERPC_DFS_H
#define __PACKET_DCERPC_DFS_H

/* Functions available on the NETDFS pipe.  From Samba, include/rpc_dfs.h */

#define DFS_MANAGER_GET_VERSION 	0x00
#define DFS_ADD 			0x01
#define DFS_REMOVE 			0x02
#define DFS_SET_INFO			0x03
#define DFS_GET_INFO 			0x04
#define DFS_ENUM			0x05
#define DFS_RENAME			0x06
#define DFS_MOVE			0x07
#define DFS_MANAGER_GET_CONFIG_INFO	0x08 
#define DFS_MANAGER_SEND_SITE_INFO	0x09
#define DFS_ADD_FT_ROOT			0x0a
#define DFS_REMOVE_FT_ROOT		0x0b
#define DFS_ADD_STD_ROOT		0x0c
#define DFS_REMOVE_STD_ROOT		0x0d
#define DFS_MANAGER_INITIALIZE		0x0e
#define DFS_ADD_STD_ROOT_FORCED		0x0f
#define DFS_GET_DC_ADDRESS		0x10
#define DFS_SET_DC_ADDRESS		0x11
#define DFS_FLUSH_FT_TABLE		0x12
#define DFS_ADD2			0x13
#define DFS_REMOVE2			0x14
#define DFS_ENUM_EX			0x15
#define DFS_SET_INFO_2			0x16

#endif /* packet-dcerpc-dfs.h */
