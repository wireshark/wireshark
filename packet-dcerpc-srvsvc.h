/* packet-msrpc-srvsvc.h
 * Routines for SMB \\PIPE\\srvsvc packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-srvsvc.h,v 1.1 2001/11/21 02:08:57 guy Exp $
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

#ifndef __PACKET_MSRPC_SRVSVC_H
#define __PACKET_MSRPC_SRVSVC_H

/* Functions available on the SRVSVC pipe.  From Samba, include/rpc_srvsvc.h */

#define SRV_NETCONNENUM        0x08
#define SRV_NETFILEENUM        0x09
#define SRV_NETSESSENUM        0x0c
#define SRV_NET_SHARE_ADD      0x0e
#define SRV_NETSHAREENUM_ALL   0x0f
#define SRV_NET_SHARE_GET_INFO 0x10
#define SRV_NET_SHARE_SET_INFO 0x11
#define SRV_NET_SHARE_DEL      0x12
#define SRV_NET_SRV_GET_INFO   0x15
#define SRV_NET_SRV_SET_INFO   0x16
#define SRV_NET_DISK_ENUM      0x17
#define SRV_NET_REMOTE_TOD     0x1c
#define SRV_NET_NAME_VALIDATE  0x21
#define SRV_NETSHAREENUM       0x24
#define SRV_NETFILEQUERYSECDESC 0x27
#define SRV_NETFILESETSECDESC	0x28

#endif /* packet-msrpc-srvsvc.h */
