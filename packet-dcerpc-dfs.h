/* packet-dcerpc-dfs.h
 * Routines for SMB \PIPE\netdfs packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-dfs.h,v 1.3 2001/12/16 20:08:22 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#define DFS_EXIST                0x00
#define DFS_ADD                  0x01
#define DFS_REMOVE               0x02
#define DFS_GET_INFO             0x04
#define DFS_ENUM                 0x05

#endif /* packet-dcerpc-dfs.h */
