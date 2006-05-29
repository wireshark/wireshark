/* packet-tcp.h
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
	gboolean th_have_seglen;	/* TRUE if th_seglen is valid */
	guint32 th_seglen;
	guint32 th_win;   /* make it 32 bits so we can handle some scaling */
	guint16 th_sport;
	guint16 th_dport;
	guint8  th_hlen;
	guint8  th_flags;
	address ip_src;
	address ip_dst;
};

/*
 * Private data passed from the TCP dissector to subdissectors. Passed to the 
 * subdissectors in pinfo->private_data
 */
struct tcpinfo {
	guint32 seq;             /* Sequence number of first byte in the data */
	guint32 nxtseq;          /* Sequence number of first byte after data */
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
		 dissector_t dissect_pdu);


typedef struct _tcp_unacked_t {
	struct _tcp_unacked_t *next;
	guint32 frame;
	guint32	seq;
	guint32	nextseq;
	nstime_t ts;
} tcp_unacked_t;

struct tcp_acked {
	guint32 frame_acked;
	nstime_t ts;
	
	guint32  rto_frame;	
	nstime_t rto_ts;	/* Time since previous packet for 
				   retransmissions. */
	guint16 flags;
	guint32 dupack_num;	/* dup ack number */
	guint32 dupack_frame;	/* dup ack to frame # */
};

/* One instance of this structure is created for each pdu that spans across
 * multiple tcp segments.
 */
struct tcp_multisegment_pdu {
	guint32 seq;
	guint32 nxtpdu;
	guint32 first_frame;
	guint32 last_frame;
        nstime_t last_frame_time;
};

typedef struct _tcp_flow_t {
	guint32 base_seq;	/* base seq number (used by relative sequence numbers)
				 * or 0 if not yet known.
				 */
	tcp_unacked_t *segments;
	guint32 lastack;	/* last seen ack */
	nstime_t lastacktime;	/* Time of the last ack packet */ 
	guint32 lastnondupack;	/* frame number of last seen non dupack */
	guint32 dupacknum;	/* dupack number */
	guint32 nextseq;	/* highest seen nextseq */
	guint32 nextseqframe;	/* frame number for segment with highest
				 * sequence number
				 */
	nstime_t nextseqtime;	/* Time of the nextseq packet so we can 
				 * distinguish between retransmission, 
				 * fast retransmissions and outoforder 
				 */
	guint32 window;		/* last seen window */
	gint16	win_scale;	/* -1 is we dont know */
	guint32 lastsegmentflags;

	/* This tree is indexed by sequence number and keeps track of all
	 * all pdus spanning multiple segments for this flow.
	 */
	se_tree_t *multisegment_pdus;
} tcp_flow_t;
	

struct tcp_analysis {
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
	tcp_flow_t	flow1;
	tcp_flow_t	flow2;

	/* These pointers are set by get_tcp_conversation_data()
	 * fwd point in the same direction as the current packet
	 * and rev in the reverse direction
	 */
	tcp_flow_t	*fwd;
	tcp_flow_t	*rev;

	/* This pointer is NULL   or points to a tcp_acked struct if this
	 * packet has "interesting" properties such as being a KeepAlive or
	 * similar 
	 */
	struct tcp_acked *ta;
	/* This structure contains a tree containing all the various ta's
	 * keyed by frame number.
	 */
	se_tree_t *acked_table;
};


extern void dissect_tcp_payload(tvbuff_t *tvb, packet_info *pinfo, int offset,
				guint32 seq, guint32 nxtseq, guint32 sport,
				guint32 dport, proto_tree *tree,
				proto_tree *tcp_tree,
				struct tcp_analysis *tcpd);

extern struct tcp_analysis *get_tcp_conversation_data(packet_info *pinfo);

extern gboolean decode_tcp_ports(tvbuff_t *, int, packet_info *, proto_tree *, int, int, struct tcp_analysis *);


#endif
