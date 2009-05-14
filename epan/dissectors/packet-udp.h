/* packet-udp.h
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
  guint16 uh_sum_cov;
  guint16 uh_sum;
  address ip_src;
  address ip_dst;
} e_udphdr;

/* Conversation and process structures originally copied from packet-tcp.c */
typedef struct _udp_flow_t {
	/* Process info, currently discovered via IPFIX */
	guint32 process_uid;    /* UID of local process */
	guint32 process_pid;    /* PID of local process */
	gchar *username;	/* Username of the local process */
	gchar *command;         /* Local process name + path + args */
} udp_flow_t;

struct udp_analysis {
	/* These two structs are managed based on comparing the source
	 * and destination addresses and, if they're equal, comparing
	 * the source and destination ports.
	 *
	 * If the source is greater than the destination, then stuff
	 * sent from src is in ual1.
	 *
	 * If the source is less than the destination, then stuff
	 * sent from src is in ual2.
	 *
	 * XXX - if the addresses and ports are equal, we don't guarantee
	 * the behavior.
	 */
	udp_flow_t	flow1;
	udp_flow_t	flow2;

	/* These pointers are set by get_tcp_conversation_data()
	 * fwd point in the same direction as the current packet
	 * and rev in the reverse direction
	 */
	udp_flow_t	*fwd;
	udp_flow_t	*rev;
};

/** Associate process information with a given flow
 *
 * @param local_addr The local IPv4 or IPv6 address of the process
 * @param remote_addr The remote IPv4 or IPv6 address of the process
 * @param local_port The local TCP port of the process
 * @param remote_port The remote TCP port of the process
 * @param uid The numeric user ID of the process
 * @param pid The numeric PID of the process
 * @param username Ephemeral string containing the full or partial process name
 * @param command Ephemeral string containing the full or partial process name
 */
extern void add_udp_process_info(guint32 frame_num, address *local_addr, address *remote_addr, guint16 local_port, guint16 remote_port, guint32 uid, guint32 pid, gchar *username, gchar *command);


extern void decode_udp_ports(tvbuff_t *, int, packet_info *,
	proto_tree *, int, int, int);

#endif
