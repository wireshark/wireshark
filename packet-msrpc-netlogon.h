/* packet-msrpc-netlogon.h
 * Routines for SMB \\PIPE\\NETLOGON packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-msrpc-netlogon.h,v 1.1 2001/11/12 08:58:43 guy Exp $
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

#ifndef __PACKET_MSRPC_NETLOGON_H
#define __PACKET_MSRPC_NETLOGON_H

/* Functions available on the NETLOGON pipe.  From Samba, 
   include/rpc_netlogon.h */

#define NET_SAMLOGON           0x02
#define NET_SAMLOGOFF          0x03
#define NET_REQCHAL            0x04
#define NET_AUTH               0x05
#define NET_SRVPWSET           0x06
#define NET_SAM_DELTAS         0x07
#define NET_LOGON_CTRL         0x0c
#define NET_AUTH2              0x0f
#define NET_LOGON_CTRL2        0x0e
#define NET_SAM_SYNC           0x10
#define NET_TRUST_DOM_LIST     0x13

#endif /* packet-msrpc-netlogon.h */
