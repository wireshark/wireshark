/* packet-netflow.h
 * Routines for Cisco NetFlow packet disassembly
 * Matthew Smart <smart@monkey.org>
 *
 * $Id: packet-netflow.h,v 1.1 2002/09/04 20:23:54 guy Exp $
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

struct netflow5_hdr {
	guint16	version;
	guint16	count;		/* Number of records */
	guint32	sys_uptime;	/* Time in msec since router booted */
	guint32	unix_sec;	/* Seconds since 0000 UTC 1970 */
	guint32	unix_nsec;	/* Residual nsec since 0000 UTC 1970 */
	guint32	flow_sequence;	/* Sequence num of flows seen */
	guint8	engine_type;	/* Type of flow switching engine */
	guint8	engine_id;	/* Slot number of switching engine */
	guint16	reserved;
};

struct netflow5_rec {
	guint32	src_addr;
	guint32	dst_addr;
	guint32	next_hop;
	guint16	input_iface;
	guint16	output_iface;
	guint32	pkts_sent;	/* Between start_time and end_time */
	guint32	bytes_sent;	/* Between start_time and end_time */
	guint32	start_time;	/* Milliseconds since sys_uptime */
	guint32	end_time;	/* Milliseconds since sys_uptime */
	guint16	src_port;
	guint16	dst_port;
	guint8	pad1;
	guint8	tcp_flags;
	guint8	ip_prot;
	guint8	tos;
	guint16	src_as;
	guint16	dst_as;
	guint8	src_mask;
	guint8	dst_mask;
	guint16	pad2;
};

#endif
