/* packet-tcp.h
 *
 * $Id: packet-tcp.h,v 1.7 2001/09/30 23:14:43 guy Exp $
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

#ifndef __PACKET_TCP_H__
#define __PACKET_TCP_H__

/*
 * Private data passed from the TCP dissector to subdissectors.
 */
struct tcpinfo {
	gboolean is_reassembled; /* This is reassembled data. */
	guint16	urgent_pointer;  /* Urgent pointer value for the current packet. */
};


extern void decode_tcp_ports(tvbuff_t *, int, packet_info *,
	proto_tree *, int, int);

#endif
