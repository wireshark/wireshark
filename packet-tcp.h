/* packet-tcp.h
 *
 * $Id: packet-tcp.h,v 1.13 2002/12/17 11:49:32 sahlberg Exp $
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

/* TCP flags */
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECN  0x40
#define TH_CWR  0x80


/* the tcp header structure, passed to tap listeners */
struct tcpheader {
	guint32 th_seq;
	guint32 th_ack;
	guint32 th_seglen;
	guint16 th_win;
	guint16 th_sport;
	guint16 th_dport;
	guint8  th_hlen;
	guint8  th_flags;
};

/*
 * Private data passed from the TCP dissector to subdissectors.
 */
struct tcpinfo {
	guint32 seq;             /* Sequence number of first byte in the data */
	gboolean is_reassembled; /* This is reassembled data. */
	gboolean urgent;         /* TRUE if "urgent_pointer" is valid */
	guint16	urgent_pointer;  /* Urgent pointer value for the current packet. */
};

/*
 * Loop for dissecting PDUs within a TCP stream; assumes that a PDU
 * consists of a fixed-length chunk of data that contains enough information
 * to determine the length of the PDU, followed by rest of the PDU.
 *
 * The first three arguments are the arguments passed to the dissector
 * that calls this routine.
 *
 * "proto_desegment" is the dissector's flag controlling whether it should
 * desegment PDUs that cross TCP segment boundaries.
 *
 * "fixed_len" is the length of the fixed-length part of the PDU.
 *
 * "get_pdu_len()" is a routine called to get the length of the PDU from
 * the fixed-length part of the PDU; it's passed "tvb" and "offset".
 *
 * "dissect_pdu()" is the routine to dissect a PDU.
 */
extern void
tcp_dissect_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		 gboolean proto_desegment, guint fixed_len,
		 guint (*get_pdu_len)(tvbuff_t *, int),
		 void (*dissect_pdu)(tvbuff_t *, packet_info *, proto_tree *));

extern void decode_tcp_ports(tvbuff_t *, int, packet_info *,
	proto_tree *, int, int);

#endif
