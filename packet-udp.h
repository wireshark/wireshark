/* packet-udp.h
 *
 * $Id: packet-udp.h,v 1.7 2003/03/03 23:46:48 sahlberg Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __PACKET_UDP_H__
#define __PACKET_UDP_H__

/* UDP structs and definitions */
typedef struct _e_udphdr {
  guint16 uh_sport;
  guint16 uh_dport;
  guint16 uh_ulen;
  guint16 uh_sum;
  /* This can be either a ipv4 or a ipv6 header struct so make sure you know
     what you try to dereference */
  void *ip_header;
} e_udphdr;


extern void decode_udp_ports(tvbuff_t *, int, packet_info *,
	proto_tree *, int, int);

#endif
