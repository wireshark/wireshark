/* packet-netflow.h
 * Routines for Cisco NetFlow packet disassembly
 * Matthew Smart <smart@monkey.org>
 *
 * Cisco links:
 * http://www.cisco.com/warp/public/cc/pd/iosw/ioft/neflct/tech/napps_wp.htm
 * http://www.cisco.com/univercd/cc/td/doc/product/rtrmgmt/nfc/nfc_3_0/nfc_ug/nfcform.htm#18955
 *
 * ICMP type is stored in the top byte of the destination port and the ICMP
 * code is stored in the bottom byte.
 *	icmp_type = ntohs(dst_port) >> 8;
 *	icmp_code = ntohs(dst_port) & 0xff;
 *
 * $Id: packet-netflow.h,v 1.3 2002/09/09 20:22:51 guy Exp $
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

#ifndef __PACKET_NETFLOW_H
#define __PACKET_NETFLOW_H

#include <glib.h>

#define UDP_PORT_NETFLOW	5000	/* XXX */

#define NETFLOW_V1_HDR	(4 * 4)
#define NETFLOW_V1_REC	(4 * 13)
#define NETFLOW_V5_HDR	(4 * 6)
#define NETFLOW_V5_REC	(4 * 12)
#define NETFLOW_V7_HDR	(4 * 6)
#define NETFLOW_V7_REC	(4 * 13)
#define NETFLOW_V8_HDR	(4 * 7)
#define NETFLOW_V8_REC	(-1)	/* There are many record sizes for v8 */

#endif
