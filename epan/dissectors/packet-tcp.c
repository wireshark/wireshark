/* packet-tcp.c
 * Routines for TCP packet disassembly
 *
 * $Id$
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/in_cksum.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/ip_opts.h>
#include <epan/follow.h>
#include <epan/prefs.h>
#include "packet-tcp.h"
#include "packet-ip.h"
#include "packet-frame.h"
#include <epan/conversation.h>
#include <epan/strutil.h>
#include <epan/reassemble.h>
#include <epan/tap.h>
#include <epan/emem.h>
#include <epan/slab.h>
#include <epan/expert.h>

static int tcp_tap = -1;

/* Place TCP summary in proto tree */
static gboolean tcp_summary_in_tree = TRUE;

/*
 * Flag to control whether to check the TCP checksum.
 *
 * In at least some Solaris network traces, there are packets with bad
 * TCP checksums, but the traffic appears to indicate that the packets
 * *were* received; the packets were probably sent by the host on which
 * the capture was being done, on a network interface to which
 * checksumming was offloaded, so that DLPI supplied an un-checksummed
 * packet to the capture program but a checksummed packet got put onto
 * the wire.
 */
static gboolean tcp_check_checksum = TRUE;

extern FILE* data_out_file;

static int proto_tcp = -1;
static int hf_tcp_srcport = -1;
static int hf_tcp_dstport = -1;
static int hf_tcp_port = -1;
static int hf_tcp_seq = -1;
static int hf_tcp_nxtseq = -1;
static int hf_tcp_ack = -1;
static int hf_tcp_hdr_len = -1;
static int hf_tcp_flags = -1;
static int hf_tcp_flags_cwr = -1;
static int hf_tcp_flags_ecn = -1;
static int hf_tcp_flags_urg = -1;
static int hf_tcp_flags_ack = -1;
static int hf_tcp_flags_push = -1;
static int hf_tcp_flags_reset = -1;
static int hf_tcp_flags_syn = -1;
static int hf_tcp_flags_fin = -1;
static int hf_tcp_window_size = -1;
static int hf_tcp_checksum = -1;
static int hf_tcp_checksum_bad = -1;
static int hf_tcp_len = -1;
static int hf_tcp_urgent_pointer = -1;
static int hf_tcp_analysis_flags = -1;
static int hf_tcp_analysis_acks_frame = -1;
static int hf_tcp_analysis_ack_rtt = -1;
static int hf_tcp_analysis_rto = -1;
static int hf_tcp_analysis_rto_frame = -1;
static int hf_tcp_analysis_retransmission = -1;
static int hf_tcp_analysis_fast_retransmission = -1;
static int hf_tcp_analysis_out_of_order = -1;
static int hf_tcp_analysis_lost_packet = -1;
static int hf_tcp_analysis_ack_lost_packet = -1;
static int hf_tcp_analysis_window_update = -1;
static int hf_tcp_analysis_window_full = -1;
static int hf_tcp_analysis_keep_alive = -1;
static int hf_tcp_analysis_keep_alive_ack = -1;
static int hf_tcp_analysis_duplicate_ack = -1;
static int hf_tcp_analysis_duplicate_ack_num = -1;
static int hf_tcp_analysis_duplicate_ack_frame = -1;
static int hf_tcp_analysis_zero_window = -1;
static int hf_tcp_analysis_zero_window_probe = -1;
static int hf_tcp_analysis_zero_window_violation = -1;
static int hf_tcp_continuation_to = -1;
static int hf_tcp_pdu_time = -1;
static int hf_tcp_pdu_last_frame = -1;
static int hf_tcp_reassembled_in = -1;
static int hf_tcp_segments = -1;
static int hf_tcp_segment = -1;
static int hf_tcp_segment_overlap = -1;
static int hf_tcp_segment_overlap_conflict = -1;
static int hf_tcp_segment_multiple_tails = -1;
static int hf_tcp_segment_too_long_fragment = -1;
static int hf_tcp_segment_error = -1;
static int hf_tcp_option_mss = -1;
static int hf_tcp_option_mss_val = -1;
static int hf_tcp_option_wscale = -1;
static int hf_tcp_option_wscale_val = -1;
static int hf_tcp_option_sack_perm = -1;
static int hf_tcp_option_sack = -1;
static int hf_tcp_option_sack_sle = -1;
static int hf_tcp_option_sack_sre = -1;
static int hf_tcp_option_echo = -1;
static int hf_tcp_option_echo_reply = -1;
static int hf_tcp_option_time_stamp = -1;
static int hf_tcp_option_cc = -1;
static int hf_tcp_option_ccnew = -1;
static int hf_tcp_option_ccecho = -1;
static int hf_tcp_option_md5 = -1;

static gint ett_tcp = -1;
static gint ett_tcp_flags = -1;
static gint ett_tcp_options = -1;
static gint ett_tcp_option_sack = -1;
static gint ett_tcp_analysis = -1;
static gint ett_tcp_analysis_faults = -1;
static gint ett_tcp_segments = -1;
static gint ett_tcp_segment  = -1;


/* not all of the hf_fields below make sense for TCP but we have to provide 
   them anyways to comply with the api (which was aimed for ip fragment 
   reassembly) */
static const fragment_items tcp_segment_items = {
	&ett_tcp_segment,
	&ett_tcp_segments,
	&hf_tcp_segments,
	&hf_tcp_segment,
	&hf_tcp_segment_overlap,
	&hf_tcp_segment_overlap_conflict,
	&hf_tcp_segment_multiple_tails,
	&hf_tcp_segment_too_long_fragment,
	&hf_tcp_segment_error,
	&hf_tcp_reassembled_in,
	"Segments"
};

static dissector_table_t subdissector_table;
static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t data_handle;

/* TCP structs and definitions */

static void
process_tcp_payload(tvbuff_t *tvb, volatile int offset, packet_info *pinfo,
	proto_tree *tree, proto_tree *tcp_tree, int src_port, int dst_port,
	guint32 seq, guint32 nxtseq, gboolean is_tcp_segment);

/* **************************************************************************
 * stuff to analyze TCP sequencenumbers for retransmissions, missing segments,
 * RTT and reltive sequence numbers.
 * **************************************************************************/
static gboolean tcp_analyze_seq = TRUE;
static gboolean tcp_relative_seq = TRUE;

typedef struct _tcp_unacked_t {
	struct _tcp_unacked_t *next;
	guint32 frame;
	guint32	seq;
	guint32 nextseq;
	nstime_t ts;

	/* this is to keep track of zero window and zero window probe */
	guint32 window;

	guint32 flags;
} tcp_unacked_t;

/* SLAB allocator for tcp_unacked structures
 */
SLAB_ITEM_TYPE_DEFINE(tcp_unacked_t)
static SLAB_FREE_LIST_DEFINE(tcp_unacked_t)
#define TCP_UNACKED_NEW(fi)					\
	SLAB_ALLOC(fi, tcp_unacked_t)
#define TCP_UNACKED_FREE(fi)					\
	SLAB_FREE(fi, tcp_unacked_t)


/* Idea for gt: either x > y, or y is much bigger (assume wrap) */
#define GT_SEQ(x, y) ((gint32)((y) - (x)) < 0)
#define LT_SEQ(x, y) ((gint32)((x) - (y)) < 0)
#define GE_SEQ(x, y) ((gint32)((y) - (x)) <= 0)
#define LE_SEQ(x, y) ((gint32)((x) - (y)) <= 0)
#define EQ_SEQ(x, y) ((x) == (y))

#define TCP_A_RETRANSMISSION		0x0001
#define TCP_A_LOST_PACKET		0x0002
#define TCP_A_ACK_LOST_PACKET		0x0004
#define TCP_A_KEEP_ALIVE		0x0008
#define TCP_A_DUPLICATE_ACK		0x0010
#define TCP_A_ZERO_WINDOW		0x0020
#define TCP_A_ZERO_WINDOW_PROBE		0x0040
#define TCP_A_ZERO_WINDOW_VIOLATION	0x0080
#define TCP_A_KEEP_ALIVE_ACK		0x0100
#define TCP_A_OUT_OF_ORDER		0x0200
#define TCP_A_FAST_RETRANSMISSION	0x0400
#define TCP_A_WINDOW_UPDATE		0x0800
#define TCP_A_WINDOW_FULL		0x1000
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
static GHashTable *tcp_analyze_acked_table = NULL;

struct tcp_rel_seq {
	guint32 seq_base;
	guint32 ack_base;
	gint16  win_scale;
};
static GHashTable *tcp_rel_seq_table = NULL;

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
	tcp_unacked_t *ual1;		/* UnAcked List 1*/
	guint32 base_seq1;
	tcp_unacked_t *ual2;		/* UnAcked List 2*/
	guint32 base_seq2;
	gint16 win_scale1, win_scale2;
	gint32 win1, win2;
	guint32 ack1, ack2;
	guint32 ack1_frame, ack2_frame;
	nstime_t ack1_time, ack2_time;
	guint32 num1_acks, num2_acks;

	/* these two lists are used to track when PDUs may start
	   inside a segment.
	*/
	struct tcp_next_pdu *pdu_seq1;
	struct tcp_next_pdu *pdu_seq2;
};


struct tcp_next_pdu {
	struct tcp_next_pdu *next;
	guint32 seq;
	guint32 nxtpdu;
	guint32 first_frame;
	guint32 last_frame;
        nstime_t last_frame_time;
};
static GHashTable *tcp_pdu_tracking_table = NULL;
static GHashTable *tcp_pdu_skipping_table = NULL;
static GHashTable *tcp_pdu_time_table = NULL;


static struct tcp_analysis *
get_tcp_conversation_data(packet_info *pinfo)
{
	conversation_t *conv=NULL;
	struct tcp_analysis *tcpd=NULL;

	/* Have we seen this conversation before? */
	if( (conv=find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0)) == NULL){
		/* No this is a new conversation. */
		conv=conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	}

	/* check if we have any data for this conversation */
	tcpd=conversation_get_proto_data(conv, proto_tcp);
	if(!tcpd){
		/* No no such data yet. Allocate and init it */
		tcpd=se_alloc(sizeof(struct tcp_analysis));
		tcpd->ual1=NULL;
		tcpd->base_seq1=0;
		tcpd->win1=-1;
		tcpd->win_scale1=-1;
		tcpd->ack1=0;
		tcpd->ack1_frame=0;
		tcpd->ack1_time.secs=0;
		tcpd->ack1_time.nsecs=0;
		tcpd->num1_acks=0;
		tcpd->ual2=NULL;
		tcpd->base_seq2=0;
		tcpd->win2=-1;
		tcpd->win_scale2=-1;
		tcpd->ack2=0;
		tcpd->ack2_frame=0;
		tcpd->ack2_time.secs=0;
		tcpd->ack2_time.nsecs=0;
		tcpd->num2_acks=0;

		tcpd->pdu_seq1=NULL;
		tcpd->pdu_seq2=NULL;

		conversation_add_proto_data(conv, proto_tcp, tcpd);
	}

	return tcpd;
}

/* This function is called from the tcp analysis code to provide
   clues on how the seq and ack numbers are changed.
   To prevent the next_pdu lists from growing uncontrollable in size we
   use this function to do the following :
   IF we see an ACK then we assume that the left edge of the window has changed
      at least to this point and assuming it is rare with reordering and
      trailing duplicate/retransmitted segments, we just assume that after
      we have seen the ACK we will not see any more segments prior to the 
      ACK value.
      If we will not see any segments prior to the ACK value then we can just
      delete all next_pdu entries that describe pdu's starting prior to the 
      ACK.
      If this heuristics is prooved to be too simplistic we can just enhance it
      later.
*/   
/* XXX this function should be ehnanced to handle sequence number wrapping */
/* XXX to handle retransmissions and reordered packets maybe we should only
       discard entries that are more than (guesstimate) 50kb older than the
       specified sequence number ?
*/
static void
prune_next_pdu_list(struct tcp_next_pdu **tnp, guint32 seq)
{
	struct tcp_next_pdu *tmptnp;

	if(*tnp == NULL){
		return;
	}

	for(tmptnp=*tnp;tmptnp;tmptnp=tmptnp->next){
		if(tmptnp->nxtpdu<=seq){
			struct tcp_next_pdu *oldtnp;
			oldtnp=tmptnp;

			if(tmptnp==*tnp){
				tmptnp=tmptnp->next;
				*tnp=tmptnp;
				if(!tmptnp){
					return;
				}
				continue;
			} else {
				for(tmptnp=*tnp;tmptnp;tmptnp=tmptnp->next){
					if(tmptnp->next==oldtnp){
						tmptnp->next=oldtnp->next;
						break;
					}
				}
				if(!tmptnp){
					return;
				}
			}
		}
	}
}
		

static void
print_pdu_tracking_data(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tcp_tree, struct tcp_next_pdu *tnp)
{
	proto_item *item;

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[Continuation to #%u] ", tnp->first_frame);
	}
	item=proto_tree_add_uint(tcp_tree, hf_tcp_continuation_to,
		tvb, 0, 0, tnp->first_frame);
	PROTO_ITEM_SET_GENERATED(item);
}

/* if we know that a PDU starts inside this segment, return the adjusted 
   offset to where that PDU starts or just return offset back
   and let TCP try to find out what it can about this segment
*/
static int
scan_for_next_pdu(tvbuff_t *tvb, proto_tree *tcp_tree, packet_info *pinfo, int offset, guint32 seq, guint32 nxtseq)
{
	struct tcp_analysis *tcpd=NULL;
	struct tcp_next_pdu *tnp=NULL;
	int direction;

	if(!pinfo->fd->flags.visited){
		/* find(or create if needed) the conversation for this tcp session */
		tcpd=get_tcp_conversation_data(pinfo);
		/* check direction and get pdu start lists */
		direction=CMP_ADDRESS(&pinfo->src, &pinfo->dst);
		/* if the addresses are equal, match the ports instead */
		if(direction==0) {
			direction= (pinfo->srcport > pinfo->destport)*2-1;
		}
		if(direction>=0){
			tnp=tcpd->pdu_seq1;
		} else {
			tnp=tcpd->pdu_seq2;
		}

		/* scan and see if we find any pdus starting inside this tvb */
		for(;tnp;tnp=tnp->next){
			/* XXX here we should also try to handle sequence number
			   wrapping
			*/
			/* If this segment is completely within a previous PDU
			 * then we just skip this packet
			 */
			if(seq>tnp->seq && nxtseq<=tnp->nxtpdu){
				tnp->last_frame=pinfo->fd->num;
				tnp->last_frame_time=pinfo->fd->abs_ts;
				g_hash_table_insert(tcp_pdu_skipping_table, 
					GINT_TO_POINTER(pinfo->fd->num), (void *)tnp);
				print_pdu_tracking_data(pinfo, tvb, tcp_tree, tnp);

				return -1;
			}			
			if(seq<tnp->nxtpdu && nxtseq>tnp->nxtpdu){
				g_hash_table_insert(tcp_pdu_tracking_table, 
					GINT_TO_POINTER(pinfo->fd->num), GUINT_TO_POINTER(tnp->nxtpdu));
				offset+=tnp->nxtpdu-seq;
				break;
			}
		}
	} else {
		guint32 pduseq;

		tnp=(struct tcp_next_pdu *)g_hash_table_lookup(tcp_pdu_time_table, GINT_TO_POINTER(pinfo->fd->num));
		if(tnp){
			proto_item *item;
		 	nstime_t ns;

			item=proto_tree_add_uint(tcp_tree, hf_tcp_pdu_last_frame, tvb, 0, 0, tnp->last_frame);
			PROTO_ITEM_SET_GENERATED(item);

			nstime_delta(&ns, &tnp->last_frame_time, &pinfo->fd->abs_ts);
			item = proto_tree_add_time(tcp_tree, hf_tcp_pdu_time,
					tvb, 0, 0, &ns);
			PROTO_ITEM_SET_GENERATED(item);
		}

		/* check if this is a segment in the middle of a pdu */
		tnp=(struct tcp_next_pdu *)g_hash_table_lookup(tcp_pdu_skipping_table, GINT_TO_POINTER(pinfo->fd->num));
		if(tnp){
			print_pdu_tracking_data(pinfo, tvb, tcp_tree, tnp);
			return -1;
		}

		pduseq=GPOINTER_TO_UINT(g_hash_table_lookup(tcp_pdu_tracking_table, GINT_TO_POINTER(pinfo->fd->num)));
		if(pduseq){
			offset+=pduseq-seq;
		}
	}

	return offset;
}

/* if we saw a PDU that extended beyond the end of the segment,
   use this function to remember where the next pdu starts
*/
static void
pdu_store_sequencenumber_of_next_pdu(packet_info *pinfo, guint32 seq, guint32 nxtpdu)
{
	struct tcp_analysis *tcpd=NULL;
	struct tcp_next_pdu *tnp=NULL;
	int direction;

 	/* find(or create if needed) the conversation for this tcp session */
	tcpd=get_tcp_conversation_data(pinfo);

	tnp=se_alloc(sizeof(struct tcp_next_pdu));
	tnp->nxtpdu=nxtpdu;
	tnp->seq=seq;
	tnp->first_frame=pinfo->fd->num;
	tnp->last_frame=pinfo->fd->num;
	tnp->last_frame_time=pinfo->fd->abs_ts;

	/* check direction and get pdu start list */
	direction=CMP_ADDRESS(&pinfo->src, &pinfo->dst);
	/* if the addresses are equal, match the ports instead */
	if(direction==0) {
		direction= (pinfo->srcport > pinfo->destport)*2-1;
	}
	if(direction>=0){
		tnp->next=tcpd->pdu_seq1;
		tcpd->pdu_seq1=tnp;
	} else {
		tnp->next=tcpd->pdu_seq2;
		tcpd->pdu_seq2=tnp;
	}
	/*QQQ 
	  Add check for ACKs and purge list of sequence numbers
	  already acked.
	*/
	g_hash_table_insert(tcp_pdu_time_table, GINT_TO_POINTER(pinfo->fd->num), (void *)tnp);
}

/* This is called for SYN+ACK packets and the purpose is to verify that we
 * have seen window scaling in both directions.
 * If we cant find window scaling being set in both directions
 * that means it was present in the SYN but not in the SYN+ACK
 * (or the SYN was missing) and then we disable the window scaling
 * for this tcp session.
 */
static void verify_tcp_window_scaling(packet_info *pinfo)
{
	struct tcp_analysis *tcpd=NULL;

	/* find(or create if needed) the conversation for this tcp session */
	tcpd=get_tcp_conversation_data(pinfo);

	if( (tcpd->win_scale1==-1) || (tcpd->win_scale2==-1) ){
		tcpd->win_scale1=-1;
		tcpd->win_scale2=-1;
	}
}

/* if we saw a window scaling option, store it for future reference 
*/
static void pdu_store_window_scale_option(packet_info *pinfo, guint8 ws)
{
	struct tcp_analysis *tcpd=NULL;
	int direction;

	/* find(or create if needed) the conversation for this tcp session */
	tcpd=get_tcp_conversation_data(pinfo);

	/* check direction and get pdu start list */
	direction=CMP_ADDRESS(&pinfo->src, &pinfo->dst);
	/* if the addresses are equal, match the ports instead */
	if(direction==0) {
		direction= (pinfo->srcport > pinfo->destport)*2-1;
	}
	if(direction>=0){
		tcpd->win_scale1=ws;
	} else {
		tcpd->win_scale2=ws;
	}
}

static void
tcp_get_relative_seq_ack(guint32 frame, guint32 *seq, guint32 *ack, guint32 *win)
{
	struct tcp_rel_seq *trs;

	trs=g_hash_table_lookup(tcp_rel_seq_table, GUINT_TO_POINTER(frame));
	if(!trs){
		return;
	}

	(*seq) -= trs->seq_base;
	(*ack) -= trs->ack_base;
	if(trs->win_scale!=-1){
		(*win)<<=trs->win_scale;
	}
}

static struct tcp_acked *
tcp_analyze_get_acked_struct(guint32 frame, gboolean createflag)
{
	struct tcp_acked *ta;

	ta=g_hash_table_lookup(tcp_analyze_acked_table, GUINT_TO_POINTER(frame));
	if((!ta) && createflag){
		ta=se_alloc(sizeof(struct tcp_acked));
		ta->frame_acked=0;
		ta->ts.secs=0;
		ta->ts.nsecs=0;
		ta->flags=0;
		ta->dupack_num=0;
		ta->dupack_frame=0;
		g_hash_table_insert(tcp_analyze_acked_table, GUINT_TO_POINTER(frame), ta);
	}
	return ta;
}

static void
tcp_analyze_sequence_number(packet_info *pinfo, guint32 seq, guint32 ack, guint32 seglen, guint8 flags, guint32 window)
{
	struct tcp_analysis *tcpd=NULL;
	int direction;
	tcp_unacked_t *ual1=NULL;
	tcp_unacked_t *ual2=NULL;
	tcp_unacked_t *ual=NULL;
	guint32 base_seq;
	guint32 base_ack;
	guint32 ack1, ack2;
	guint32 ack1_frame, ack2_frame;
	nstime_t *ack1_time, *ack2_time;
	guint32 num1_acks, num2_acks;
	gint32 win1,win2;
	gint16  win_scale1,win_scale2;
	struct tcp_next_pdu **tnp=NULL;

	/* find(or create if needed) the conversation for this tcp session */
	tcpd=get_tcp_conversation_data(pinfo);

	/* check direction and get ua lists */
	direction=CMP_ADDRESS(&pinfo->src, &pinfo->dst);
	/* if the addresses are equal, match the ports instead */
	if(direction==0) {
		direction= (pinfo->srcport > pinfo->destport)*2-1;
	}
	if(direction>=0){
		ual1=tcpd->ual1;
		ual2=tcpd->ual2;
		ack1=tcpd->ack1;
		ack2=tcpd->ack2;
		ack1_frame=tcpd->ack1_frame;
		ack2_frame=tcpd->ack2_frame;
		ack1_time=&tcpd->ack1_time;
		ack2_time=&tcpd->ack2_time;
		num1_acks=tcpd->num1_acks;
		num2_acks=tcpd->num2_acks;
		tnp=&tcpd->pdu_seq2;
		base_seq=(tcp_relative_seq && (ual1==NULL))?seq:tcpd->base_seq1;
		base_ack=(tcp_relative_seq && (ual2==NULL))?ack:tcpd->base_seq2;
		win_scale1=tcpd->win_scale1;
		win1=tcpd->win1;
		win_scale2=tcpd->win_scale2;
		win2=tcpd->win2;
	} else {
		ual1=tcpd->ual2;
		ual2=tcpd->ual1;
		ack1=tcpd->ack2;
		ack2=tcpd->ack1;
		ack1_frame=tcpd->ack2_frame;
		ack2_frame=tcpd->ack1_frame;
		ack1_time=&tcpd->ack2_time;
		ack2_time=&tcpd->ack1_time;
		num1_acks=tcpd->num2_acks;
		num2_acks=tcpd->num1_acks;
		tnp=&tcpd->pdu_seq1;
		base_seq=(tcp_relative_seq && (ual1==NULL))?seq:tcpd->base_seq2;
		base_ack=(tcp_relative_seq && (ual2==NULL))?ack:tcpd->base_seq1;
		win_scale1=tcpd->win_scale2;
		win1=tcpd->win2;
		win_scale2=tcpd->win_scale1;
		win2=tcpd->win1;
	}

	if(!seglen){
		if(!ack2_frame){
			ack2_frame=pinfo->fd->num;
			ack2=ack;
			*ack2_time=pinfo->fd->abs_ts;
			num2_acks=0;
		} else if(GT_SEQ(ack, ack2)){
			ack2_frame=pinfo->fd->num;
			ack2=ack;
			*ack2_time=pinfo->fd->abs_ts;
			num2_acks=0;
		}
	}

#ifdef REMOVED
/* useful debug ouput   
 * it prints the two lists of the sliding window emulation 
 */
{
tcp_unacked_t *u=NULL;
printf("\n");
printf("analyze_sequence_number(frame:%d seq:%d nextseq:%d ack:%d  baseseq:0x%08x baseack:0x%08x)\n",pinfo->fd->num,seq,seq+seglen,ack,base_seq,base_ack);
printf("UAL1:\n");
for(u=ual1;u;u=u->next){
printf("  Frame:%d seq:%d nseq:%d time:%d.%09d ack:%d:%d\n",u->frame,u->seq,u->nextseq,u->ts.secs,u->ts.nsecs,ack1,ack2);
}
printf("UAL2:\n");
for(u=ual2;u;u=u->next){
printf("  Frame:%d seq:%d nseq:%d time:%d.%09d ack:%d:%d\n",u->frame,u->seq,u->nextseq,u->ts.secs,u->ts.nsecs,ack1,ack2);
}
}
#endif

	/* To handle FIN, just add 1 to the length.
	   else the ACK following the FIN-ACK will look like it was
	   outside the window. */
	if( flags&TH_FIN ){
		seglen+=1;
	}

	/* handle the sequence numbers */
	/* if this was a SYN packet, then remove existing list and
	 * put SEQ+1 first the list, just "forget" the existing nodes */
	if(flags&TH_SYN){
		for(ual=ual1;ual1;ual1=ual){
			ual=ual1->next;
			TCP_UNACKED_FREE(ual1);
		}
		TCP_UNACKED_NEW(ual1);
		ual1->next=NULL;
		ual1->frame=pinfo->fd->num;
		ack1_frame=0;
		ack2_frame=0;
		ack1=0;
		ack2=0;
		num1_acks=0;
		num2_acks=0;
		ual1->seq=seq;
		ual1->nextseq=seq+1;
		ual1->ts=pinfo->fd->abs_ts;
		ual1->window=window;
		ual1->flags=0;
		if(tcp_relative_seq){
			base_seq=seq;
			/* if this was an SYN|ACK packet then set base_ack
			 * reflect the start of the sequence, i.e. one less 
			 */
			if(flags&TH_ACK){
				base_ack=ack-1;
			} else {
				base_ack=ack;
			}
		}
		goto seq_finished;
	}

	/* if this is the first segment we see then just add it */
	if( !ual1 ){
		TCP_UNACKED_NEW(ual1);
		ual1->next=NULL;
		ual1->frame=pinfo->fd->num;
		ual1->seq=seq;
		ual1->nextseq=seq+seglen;
		ual1->ts=pinfo->fd->abs_ts;
		ual1->window=window;
		ual1->flags=0;
		if(tcp_relative_seq){
			base_seq=seq;
			base_ack=ack;
		}
		goto seq_finished;
	}

	/* if we get past here we know that ual1 points to a segment */


	/* if seq is beyond ual1->nextseq we have lost a segment */
	if (GT_SEQ(seq, ual1->nextseq)) {
		struct tcp_acked *ta;

		ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
		ta->flags|=TCP_A_LOST_PACKET;

		/* just add the segment to the beginning of the list */
		TCP_UNACKED_NEW(ual);
		ual->next=ual1;
		ual->frame=pinfo->fd->num;
		ual->seq=seq;
		ual->nextseq=seq+seglen;
		ual->ts=pinfo->fd->abs_ts;
		ual->window=window;
		ual->flags=0;
		ual1=ual;
		goto seq_finished;
	}

	/* keep-alives are empty segments with a sequence number -1 of what
	 * we would expect.
         *
	 * Solaris is an exception, Solaris does not really use KeepAlives
	 * according to RFC793, instead they move the left window edge one
	 * byte to the left and makes up a fake byte to fill in this position
	 * of the enlarged window.
	 * This means that Solaris will do "weird" KeepAlives that actually
	 * contains a one-byte segment with "random" junk data which the
	 * Solaris host then will try to transmit, and posisbly retransmit
	 * to the other side. Of course the other side will ignore this junk
	 * byte since it is outside (left of) the window.
	 * This is actually a brilliant trick that gives them, for free, 
	 * semi-reliable KeepAlives.
	 * (since normal retransmission will handle any lost keepalive segments
	 * , brilliant)
	 */
	if( (seglen<=1) && EQ_SEQ(seq, (ual1->nextseq-1)) ){
		if(!(flags&TH_FIN)){ /* FIN segments are not keepalives */
			struct tcp_acked *ta;
	
			ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
			ta->flags|=TCP_A_KEEP_ALIVE;
			ual1->flags|=TCP_A_KEEP_ALIVE;
			goto seq_finished;
		}
	}

	/* if this is an empty segment, just skip it all */
	if( !seglen ){
		goto seq_finished;
	}

	/* check if the sequence number is lower than expected, i.e. either a 
	 * retransmission a fast retransmission or an out of order segment
	 */
	if( LT_SEQ(seq, ual1->nextseq )){
		gboolean outoforder;
		tcp_unacked_t *tu,*ntu;

		/* assume it is a fast retransmission if
		 * 1 we have seen >=3 dupacks in the other direction for this 
		 *   segment (i.e. >=4 acks)
		 * 2 if this segment is the next unacked segment
		 * 3 this segment came within 10ms of the last dupack
		 *   (10ms is arbitrary but should be low enough not to be
		 *   confused with a retransmission timeout 
		 */
		if( (num1_acks>=4) && (seq==ack1) ){
			guint32 t;

			t=(pinfo->fd->abs_ts.secs-ack1_time->secs)*1000000000;
			t=t+(pinfo->fd->abs_ts.nsecs)-ack1_time->nsecs;
			if(t<10000000){
				/* has to be a retransmission then */
				struct tcp_acked *ta;

				ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
				ta->flags|=TCP_A_FAST_RETRANSMISSION;
				goto seq_finished;
			}
		}

		/* check it is a suspected out of order segment.
		 * we assume it is an out of order segment if 
		 * 1 it has not been ACKed yet.
		 * 2 we have not seen the segment before
		 * 3 it arrived within (arbitrary value) 4ms of the
		 *      next semgent in the sequence.
		 *   4 there were no dupacks in the opposite direction.
		 */
		outoforder=TRUE;
#ifdef REMOVED
		/* dont do this test.  For full-duplex capture devices that 
		 * capture in both directions using two NICs it is more common
		 * than one would expect for this to happen since they often
		 * lose the time integrity between the two NICs
		 */
		/* 1 has it already been ACKed ? */
		if(LT_SEQ(seq,ack1)){
			outoforder=FALSE;
		}
#endif
		/* 2 have we seen this segment before ? */
		for(tu=ual1;tu;tu=tu->next){
			if((tu->frame)&&(tu->seq==seq)){
				outoforder=FALSE;
			}
		}
		/* 3 was it received within 4ms of the next segment ?*/
		ntu=NULL;
		for(tu=ual1;tu;tu=tu->next){
			if(LT_SEQ(seq,tu->seq)){
				if(tu->frame){
					ntu=tu;
				}
			}
		}
		if(ntu){
			if(pinfo->fd->abs_ts.secs > ntu->ts.secs+2){
				outoforder=FALSE;
			} else if(pinfo->fd->abs_ts.secs+2 < ntu->ts.secs){
				outoforder=FALSE;
			} else {
				guint32 t;

				t=(ntu->ts.secs-pinfo->fd->abs_ts.secs)*1000000000;
				t=t+ntu->ts.nsecs-(pinfo->fd->abs_ts.nsecs);

				if(t>4000000){
					outoforder=FALSE;
				}
			}
		}

		
		if(outoforder) {
			struct tcp_acked *ta;

			ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
			ta->flags|=TCP_A_OUT_OF_ORDER;
		} else {
			/* has to be a retransmission then */
			struct tcp_acked *ta;

			ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
			ta->flags|=TCP_A_RETRANSMISSION;

#ifdef REMOVED
/* The code in the block here and is ifdeffed out tries to measure the RTO
 * as the delta between the time the original pakcet was lost and this packet,
 * which is essentially what the RTO is all about. We dont do that here.
 *
 * Instead we define the RTO as the delta between the retransmitted packet
 * and the last previous data segment on the same session.
 * This is an metric on how long the link were idle due to the RTO
 * and thus since this reflects the real damage to performance  this is much
 * more interesting for most people.
 * Measuring the RTO in this way, while technically not entirely correct,
 * allows us to SUM(tcp.analysis.rto) for a session and we will have the amount
 * of time for that session that was spent waiting for a retransmission instead
 * of pushing data across.
 */ 
			/* measure RTO from the most recent frame we have in 
			 * the sliding window that has a sequence number equal
			 * to or less than the retransmitted frame.
			 */
			ntu=NULL;
			for(tu=ual1;tu;tu=tu->next){
				if(GE_SEQ(seq,tu->seq)){
					if(tu->frame){
						ntu=tu;
						break;
					}
				}
			}
#endif
			ntu=ual1;
			if(ntu){
				/* Set RTO to the delta since the previous 
				 * segment with an equal or lower sequence 
				 * number.
				 */
				nstime_delta(&ta->rto_ts, &pinfo->fd->abs_ts, &ntu->ts);
				ta->rto_frame=ntu->frame;
			} else {
				/* we didnt see any previous packet so we
				 * cant calculate the RTO 
				 */
				ta->rto_ts.secs=0;
				ta->rto_ts.nsecs=0;
				ta->rto_frame=0;
			}

			/* did this segment contain any more data we havent seen yet?
			 * if so we can just increase nextseq
			 */
			if(GT_SEQ((seq+seglen), ual1->nextseq)){
				ual1->nextseq=seq+seglen;
				ual1->frame=pinfo->fd->num;
				ual1->ts=pinfo->fd->abs_ts;
			}
		}
		goto seq_finished;
	}

	/* just add the segment to the beginning of the list */
	TCP_UNACKED_NEW(ual);
	ual->next=ual1;
	ual->frame=pinfo->fd->num;
	ual->seq=seq;
	ual->nextseq=seq+seglen;
	ual->ts=pinfo->fd->abs_ts;
	ual->window=window;
	ual->flags=0;
	ual1=ual;

seq_finished:



	/* handle the ack numbers */

	/* if we dont have the ack flag its not much we can do */
	if( !(flags&TH_ACK)){
		goto ack_finished;
	}

	/* if we havent seen anything yet in the other direction we dont
	 * know what this one acks */
	if( !ual2 ){
		goto ack_finished;
	}

	/* if we dont have any real segments in the other direction not
	 * acked yet (as we see from the magic frame==0 entry)
	 * then there is no point in continuing
	 */
	if( !ual2->frame ){
		goto ack_finished;
	}

	/* if we get here we know ual2 is valid */

	/* if we are acking beyong what we have seen in the other direction
	 * we must have lost packets. Not much point in keeping the segments
	 * in the other direction either. Just "forget" the old nodes.
	 */
	if( GT_SEQ(ack, ual2->nextseq )){
		struct tcp_acked *ta;

		ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
		ta->flags|=TCP_A_ACK_LOST_PACKET;
		for(ual=ual2;ual2;ual2=ual){
			ual=ual2->next;
			TCP_UNACKED_FREE(ual2);
		}
		prune_next_pdu_list(tnp, ack-base_ack);
		goto ack_finished;
	}


	/* does this ACK ack all semgents we have seen in the other direction?*/
	if( EQ_SEQ(ack, ual2->nextseq )){
		struct tcp_acked *ta;

		ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
		ta->frame_acked=ual2->frame;
		nstime_delta(&ta->ts, &pinfo->fd->abs_ts, &ual2->ts);

		/* its all been ACKed so we dont need to keep them anymore */
		for(ual=ual2;ual2;ual2=ual){
			ual=ual2->next;
			TCP_UNACKED_FREE(ual2);
		}
		prune_next_pdu_list(tnp, ack-base_ack);
		goto ack_finished;
	}

	/* ok it only ACKs part of what we have seen. Find out how much
	 * update and remove the ACKed segments
	 */
	for(ual=ual2;ual->next;ual=ual->next){
		if( GE_SEQ(ack, ual->next->nextseq)){
			break;
		}
	}
	if(ual->next){
		tcp_unacked_t *tmpual=NULL;
		tcp_unacked_t *ackedual=NULL;
		struct tcp_acked *ta;

		/* XXX normal ACK*/
		ackedual=ual->next;

		ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
		ta->frame_acked=ackedual->frame;
		nstime_delta(&ta->ts, &pinfo->fd->abs_ts, &ackedual->ts);

		/* just delete all ACKed segments */
		tmpual=ual->next;
		ual->next=NULL;
		for(ual=tmpual;ual;ual=tmpual){
			tmpual=ual->next;
			TCP_UNACKED_FREE(ual);
		}
		prune_next_pdu_list(tnp, ack-base_ack);
	}

ack_finished:
	/* we might have deleted the entire ual2 list, if this is an ACK,
	   make sure ual2 at least has a dummy entry for the current ACK */
	if( (!ual2) && (flags&TH_ACK) ){
		TCP_UNACKED_NEW(ual2);
		ual2->next=NULL;
		ual2->frame=0;
		ual2->seq=ack;
		ual2->nextseq=ack;
		ual2->ts.secs=0;
		ual2->ts.nsecs=0;
		ual2->window=window;
		ual2->flags=0;
	}

	/* update the ACK counter and check for
	   duplicate ACKs*/
	/* go to the oldest segment in the list of segments 
	   in the other direction */
	/* XXX we should guarantee ual2 to always be non NULL here
	   so we can skip the ual/ual2 tests */
	for(ual=ual2;ual&&ual->next;ual=ual->next)
		;
	if(ual2){
		/* we only consider this being a potential duplicate ack
		   if the segment length is 0 (ack only segment)
		   and if it acks something previous to oldest segment
		   in the other direction */
		if((!seglen)&&LE_SEQ(ack,ual->seq)){
			/* if this is the first ack to keep track of, it is not
			   a duplicate */
			if(num2_acks==0){
				ack2=ack;
				ack2_frame=pinfo->fd->num;
				num2_acks=1;
			/* if this ack is different, store this one 
			   instead and forget the previous one(s) */
			} else if(ack2!=ack){
				ack2=ack;
				ack2_frame=pinfo->fd->num;
				num2_acks=1;
			/* this has to be a duplicate ack */
			} else {
				num2_acks++;
			}	
			
			/* is this an ACK to a KeepAlive? */
			if( (ual->flags&TCP_A_KEEP_ALIVE)
			&& (ack==ual->seq) ){
				struct tcp_acked *ta;
				ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
				ta->flags|=TCP_A_KEEP_ALIVE_ACK;
				ual->flags^=TCP_A_KEEP_ALIVE;
			} else if(num2_acks>1) {
			/* ok we have found a potential duplicate ack */
				struct tcp_acked *ta;
				ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
				/* keepalives are not dupacks and 
				 * netiher are RST/FIN segments
				 */
				if( (!(ta->flags&TCP_A_KEEP_ALIVE))
				  &&(!(flags&(TH_RST|TH_FIN))) ){
					/* well then   
					 * this could then either be a dupack
					 * or maybe just a window update.
					 */
					if(win1==(gint32)window){
						ta->flags|=TCP_A_DUPLICATE_ACK;
						ta->dupack_num=num2_acks-1;
						ta->dupack_frame=ack2_frame;
					} else {
						ta->flags|=TCP_A_WINDOW_UPDATE;
					}
				}
			}
		}		

	}

	/* see if this semgent has filled up the window completely,
	 * i.e. same thing as if the other side would start sending
	 * zero windows back to us.
	 */
	if( !(flags&TH_RST)){ /* RST segments are never WindowFull segments*/
	  if(win_scale2==-1){
	    if( EQ_SEQ( (seq+seglen), (win2+ack1) ) ){
	      struct tcp_acked *ta;
	      ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
	      ta->flags|=TCP_A_WINDOW_FULL;
	    }
	  } else {
	    if( EQ_SEQ( (seq+seglen), ((win2<<win_scale2)+ack1) ) ){
	      struct tcp_acked *ta;
	      ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
	      ta->flags|=TCP_A_WINDOW_FULL;
	    }
	  }
	}

	/* check for zero window probes 
	   a zero window probe is when a TCP tries to write 1 byte segments
	   where the remote side has advertised a window of 0 bytes.
	   We only do this check if we actually have seen anything from the
	   other side of this connection.

	   We also assume ual still points to the last entry in the ual2
	   list from the section above.

	   At the same time, check for violations, i.e. attempts to write >1
	   byte to a zero-window.
	*/
	/* XXX we should not need to do the ual->frame check here?
	   might be a bug somewhere. look for it later .
	*/
	if(ual2&&(ual->frame)){
		if((seglen==1)&&(ual->window==0)){
			struct tcp_acked *ta;
			ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
			ta->flags|=TCP_A_ZERO_WINDOW_PROBE;
		}
		if((seglen>1)&&(ual->window==0)){
			struct tcp_acked *ta;
			ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
			ta->flags|=TCP_A_ZERO_WINDOW_VIOLATION;
		}
	}

	/* check for zero window
	 * dont check for RST/FIN segments since the window field is 
	 * meaningless for those
	 */
	if( (!window)
	  &&(!(flags&(TH_RST|TH_FIN))) ){
		struct tcp_acked *ta;
		ta=tcp_analyze_get_acked_struct(pinfo->fd->num, TRUE);
		ta->flags|=TCP_A_ZERO_WINDOW;
	}


	/* store the lists back in our struct */
	if(direction>=0){
		/*
		 * XXX - if direction == 0, that'll be true for packets
		 * from both sides of the connection, so this won't
		 * work.
		 *
		 * That'd be a connection from a given port on a machine
		 * to that same port on the same machine; does that ever
		 * happen?
		 */
		tcpd->ual1=ual1;
		tcpd->ual2=ual2;
		tcpd->ack1=ack1;
		tcpd->ack2=ack2;
		tcpd->ack1_frame=ack1_frame;
		tcpd->ack2_frame=ack2_frame;
		tcpd->num1_acks=num1_acks;
		tcpd->num2_acks=num2_acks;
		tcpd->base_seq1=base_seq;
		tcpd->base_seq2=base_ack;
		tcpd->win1=window;
	} else {
		tcpd->ual1=ual2;
		tcpd->ual2=ual1;
		tcpd->ack1=ack2;
		tcpd->ack2=ack1;
		tcpd->ack1_frame=ack2_frame;
		tcpd->ack2_frame=ack1_frame;
		tcpd->num1_acks=num2_acks;
		tcpd->num2_acks=num1_acks;
		tcpd->base_seq2=base_seq;
		tcpd->base_seq1=base_ack;
		tcpd->win2=window;
	}


	if(tcp_relative_seq){
		struct tcp_rel_seq *trs;
		/* remember relative seq/ack number base for this packet */
		trs=se_alloc(sizeof(struct tcp_rel_seq));
		trs->seq_base=base_seq;
		trs->ack_base=base_ack;
		trs->win_scale=win_scale1;
		g_hash_table_insert(tcp_rel_seq_table, GINT_TO_POINTER(pinfo->fd->num), trs);
	}
}

static void
tcp_print_sequence_number_analysis(packet_info *pinfo, tvbuff_t *tvb, proto_tree *parent_tree)
{
	struct tcp_acked *ta;
	proto_item *item;
	proto_tree *tree;

	ta=tcp_analyze_get_acked_struct(pinfo->fd->num, FALSE);
	if(!ta){
		return;
	}

	item=proto_tree_add_text(parent_tree, tvb, 0, 0, "SEQ/ACK analysis");
	PROTO_ITEM_SET_GENERATED(item);
	tree=proto_item_add_subtree(item, ett_tcp_analysis);

	/* encapsulate all proto_tree_add_xxx in ifs so we only print what
	   data we actually have */
	if(ta->frame_acked){
		item = proto_tree_add_uint(tree, hf_tcp_analysis_acks_frame,
			tvb, 0, 0, ta->frame_acked);
        	PROTO_ITEM_SET_GENERATED(item);

		/* only display RTT if we actually have something we are acking */
		if( ta->ts.secs || ta->ts.nsecs ){
			item = proto_tree_add_time(tree, hf_tcp_analysis_ack_rtt,
			tvb, 0, 0, &ta->ts);
        		PROTO_ITEM_SET_GENERATED(item);
		}
	}

	if(ta->flags){
		proto_item *flags_item=NULL;
		proto_tree *flags_tree=NULL;

		flags_item = proto_tree_add_item(tree, hf_tcp_analysis_flags, tvb, 0, -1, FALSE);
        PROTO_ITEM_SET_GENERATED(flags_item);
		flags_tree=proto_item_add_subtree(flags_item, ett_tcp_analysis);
		if( ta->flags&TCP_A_RETRANSMISSION ){
			flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_retransmission, tvb, 0, 0, "This frame is a (suspected) retransmission");
			PROTO_ITEM_SET_GENERATED(flags_item);
			expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE, "Retransmission (suspected)");
			if(check_col(pinfo->cinfo, COL_INFO)){
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Retransmission] ");
			}
			if( ta->rto_ts.secs || ta->rto_ts.nsecs ){
				item = proto_tree_add_time(flags_tree, hf_tcp_analysis_rto,
					tvb, 0, 0, &ta->rto_ts);
				PROTO_ITEM_SET_GENERATED(item);
				item=proto_tree_add_uint(flags_tree, hf_tcp_analysis_rto_frame, tvb, 0, 0, ta->rto_frame);
				PROTO_ITEM_SET_GENERATED(item);
			}
		}
		if( ta->flags&TCP_A_FAST_RETRANSMISSION ){
			flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_fast_retransmission, tvb, 0, 0, "This frame is a (suspected) fast retransmission");
			PROTO_ITEM_SET_GENERATED(flags_item);
			expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_WARN, "Fast retransmission (suspected)");
			flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_retransmission, tvb, 0, 0, "This frame is a (suspected) retransmission");
			PROTO_ITEM_SET_GENERATED(flags_item);
			if(check_col(pinfo->cinfo, COL_INFO)){
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Fast Retransmission] ");
			}
		}
		if( ta->flags&TCP_A_OUT_OF_ORDER ){
			flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_out_of_order, tvb, 0, 0, "This frame is a (suspected) out-of-order segment");
			PROTO_ITEM_SET_GENERATED(flags_item);
			expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_WARN, "Out-Of-Order segment");
			if(check_col(pinfo->cinfo, COL_INFO)){
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Out-Of-Order] ");
			}
		}
		if( ta->flags&TCP_A_LOST_PACKET ){
			flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_lost_packet, tvb, 0, 0, "A segment before this frame was lost");
			PROTO_ITEM_SET_GENERATED(flags_item);
			expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_WARN, "Previous segment lost (common at capture start)");
			if(check_col(pinfo->cinfo, COL_INFO)){
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Previous segment lost] ");
			}
		}
		if( ta->flags&TCP_A_ACK_LOST_PACKET ){
			flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_ack_lost_packet, tvb, 0, 0, "This frame ACKs a segment we have not seen (lost?)");
			PROTO_ITEM_SET_GENERATED(flags_item);
			expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_WARN, "ACKed lost segment (common at capture start)");
			if(check_col(pinfo->cinfo, COL_INFO)){
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP ACKed lost segment] ");
			}
		}
		if( ta->flags&TCP_A_WINDOW_UPDATE ){
			flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_window_update, tvb, 0, 0, "This is a tcp window update");
			PROTO_ITEM_SET_GENERATED(flags_item);
			expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE, "Window update");
			if(check_col(pinfo->cinfo, COL_INFO)){
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Window Update] ");
			}
		}
		if( ta->flags&TCP_A_WINDOW_FULL ){
			flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_window_full, tvb, 0, 0, "The transmission window is now completely full");
			PROTO_ITEM_SET_GENERATED(flags_item);
			expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE, "Window is full");
			if(check_col(pinfo->cinfo, COL_INFO)){
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Window Full] ");
			}
		}
		if( ta->flags&TCP_A_KEEP_ALIVE ){
			flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_keep_alive, tvb, 0, 0, "This is a TCP keep-alive segment");
			PROTO_ITEM_SET_GENERATED(flags_item);
			expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE, "Keep-Alive");
			if(check_col(pinfo->cinfo, COL_INFO)){
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Keep-Alive] ");
			}
		}
		if( ta->flags&TCP_A_KEEP_ALIVE_ACK ){
			flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_keep_alive_ack, tvb, 0, 0, "This is an ACK to a TCP keep-alive segment");
			PROTO_ITEM_SET_GENERATED(flags_item);
			expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE, "Keep-Alive ACK");
			if(check_col(pinfo->cinfo, COL_INFO)){
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Keep-Alive ACK] ");
			}
		}
		if( ta->dupack_num){
			if( ta->flags&TCP_A_DUPLICATE_ACK ){
				flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_duplicate_ack, tvb, 0, 0, "This is a TCP duplicate ack");
				PROTO_ITEM_SET_GENERATED(flags_item);
				if(check_col(pinfo->cinfo, COL_INFO)){
					col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP Dup ACK %u#%u] ", ta->dupack_frame, ta->dupack_num);
				}
			}
			flags_item=proto_tree_add_uint(tree, hf_tcp_analysis_duplicate_ack_num,
				tvb, 0, 0, ta->dupack_num);
			PROTO_ITEM_SET_GENERATED(flags_item);
			flags_item=proto_tree_add_uint(tree, hf_tcp_analysis_duplicate_ack_frame,
				tvb, 0, 0, ta->dupack_frame);
			PROTO_ITEM_SET_GENERATED(flags_item);
			expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE, "Duplicate ACK (#%u) to ACK in packet #%u", 
				ta->dupack_num, ta->dupack_frame);
		}
		if( ta->flags&TCP_A_ZERO_WINDOW_PROBE ){
			flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_zero_window_probe, tvb, 0, 0, "This is a TCP zero-window-probe");
			PROTO_ITEM_SET_GENERATED(flags_item);
			expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE, "Zero window probe");
			if(check_col(pinfo->cinfo, COL_INFO)){
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP ZeroWindowProbe] ");
			}
		}
		if( ta->flags&TCP_A_ZERO_WINDOW ){
			flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_zero_window, tvb, 0, 0, "This is a ZeroWindow segment");
			PROTO_ITEM_SET_GENERATED(flags_item);
			expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE, "Zero window");
			if(check_col(pinfo->cinfo, COL_INFO)){
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP ZeroWindow] ");
			}
		}
		if( ta->flags&TCP_A_ZERO_WINDOW_VIOLATION ){
			flags_item=proto_tree_add_none_format(flags_tree, hf_tcp_analysis_zero_window_violation, tvb, 0, 0, "This is a ZeroWindow violation, attempts to write >1 byte of data to a zero-window");
			PROTO_ITEM_SET_GENERATED(flags_item);
			expert_add_info_format(pinfo, flags_item, PI_SEQUENCE, PI_NOTE, "Zero window violation");
			if(check_col(pinfo->cinfo, COL_INFO)){
				col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[TCP ZeroWindowViolation] ");
			}
		}
	}

}


/* Do we still need to do this ...remove_all() even though we dont need
 * to do anything special?  The glib docs are not clear on this and
 * its better safe than sorry
 */
static gboolean
free_all_acked(gpointer key_arg _U_, gpointer value _U_, gpointer user_data _U_)
{
	return TRUE;
}

static guint
tcp_acked_hash(gconstpointer k)
{
	guint32 frame = GPOINTER_TO_UINT(k);

	return frame;
}
static gint
tcp_acked_equal(gconstpointer k1, gconstpointer k2)
{
	guint32 frame1 = GPOINTER_TO_UINT(k1);
	guint32 frame2 = GPOINTER_TO_UINT(k2);

	return frame1==frame2;
}

static void
tcp_analyze_seq_init(void)
{
	/* first destroy the tables */
	if( tcp_analyze_acked_table ){
		g_hash_table_foreach_remove(tcp_analyze_acked_table,
			free_all_acked, NULL);
		g_hash_table_destroy(tcp_analyze_acked_table);
		tcp_analyze_acked_table = NULL;
	}
	if( tcp_rel_seq_table ){
		g_hash_table_foreach_remove(tcp_rel_seq_table,
			free_all_acked, NULL);
		g_hash_table_destroy(tcp_rel_seq_table);
		tcp_rel_seq_table = NULL;
	}
	if( tcp_pdu_tracking_table ){
		g_hash_table_foreach_remove(tcp_pdu_tracking_table,
			free_all_acked, NULL);
		g_hash_table_destroy(tcp_pdu_tracking_table);
		tcp_pdu_tracking_table = NULL;
	}
	if( tcp_pdu_time_table ){
		g_hash_table_foreach_remove(tcp_pdu_time_table,
			free_all_acked, NULL);
		g_hash_table_destroy(tcp_pdu_time_table);
		tcp_pdu_time_table = NULL;
	}
	if( tcp_pdu_skipping_table ){
		g_hash_table_foreach_remove(tcp_pdu_skipping_table,
			free_all_acked, NULL);
		g_hash_table_destroy(tcp_pdu_skipping_table);
		tcp_pdu_skipping_table = NULL;
	}

	if(tcp_analyze_seq){
		tcp_analyze_acked_table = g_hash_table_new(tcp_acked_hash,
			tcp_acked_equal);
		tcp_rel_seq_table = g_hash_table_new(tcp_acked_hash,
			tcp_acked_equal);
		tcp_pdu_time_table = g_hash_table_new(tcp_acked_hash,
			tcp_acked_equal);
		tcp_pdu_tracking_table = g_hash_table_new(tcp_acked_hash,
			tcp_acked_equal);
		tcp_pdu_skipping_table = g_hash_table_new(tcp_acked_hash,
			tcp_acked_equal);
	}

}

/* **************************************************************************
 * End of tcp sequence number analysis
 * **************************************************************************/




/* Minimum TCP header length. */
#define	TCPH_MIN_LEN	20

/*
 *	TCP option
 */

#define TCPOPT_NOP		1	/* Padding */
#define TCPOPT_EOL		0	/* End of options */
#define TCPOPT_MSS		2	/* Segment size negotiating */
#define TCPOPT_WINDOW		3	/* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_ECHO             6
#define TCPOPT_ECHOREPLY        7
#define TCPOPT_TIMESTAMP	8	/* Better RTT estimations/PAWS */
#define TCPOPT_CC               11
#define TCPOPT_CCNEW            12
#define TCPOPT_CCECHO           13
#define TCPOPT_MD5              19      /* RFC2385 */

/*
 *     TCP option lengths
 */

#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_SACK_MIN       2
#define TCPOLEN_ECHO           6
#define TCPOLEN_ECHOREPLY      6
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_CC             6
#define TCPOLEN_CCNEW          6
#define TCPOLEN_CCECHO         6
#define TCPOLEN_MD5            18



/* Desegmentation of TCP streams */
/* table to hold defragmented TCP streams */
static GHashTable *tcp_fragment_table = NULL;
static void
tcp_fragment_init(void)
{
	fragment_table_init(&tcp_fragment_table);
}

/* functions to trace tcp segments */
/* Enable desegmenting of TCP streams */
static gboolean tcp_desegment = TRUE;

static GHashTable *tcp_segment_table = NULL;
static GMemChunk *tcp_segment_key_chunk = NULL;
static int tcp_segment_init_count = 200;
static GMemChunk *tcp_segment_address_chunk = NULL;
static int tcp_segment_address_init_count = 500;

typedef struct _tcp_segment_key {
	/* for own bookkeeping inside packet-tcp.c */
	address *src;
	address *dst;
	guint32 seq;
	/* xxx */
	guint16 sport;
	guint16 dport;
	guint32 start_seq;
	guint32 tot_len;
	guint32 first_frame;
} tcp_segment_key;

static gboolean
free_all_segments(gpointer key_arg, gpointer value _U_, gpointer user_data _U_)
{
	tcp_segment_key *key = key_arg;

	if((key->src)&&(key->src->data)){
		g_free((gpointer)key->src->data);
		key->src->data=NULL;
	}

	if((key->dst)&&(key->dst->data)){
		g_free((gpointer)key->dst->data);
		key->dst->data=NULL;
	}

	return TRUE;
}

static guint
tcp_segment_hash(gconstpointer k)
{
	const tcp_segment_key *key = (const tcp_segment_key *)k;

	return key->seq+key->sport;
}

static gint
tcp_segment_equal(gconstpointer k1, gconstpointer k2)
{
	const tcp_segment_key *key1 = (const tcp_segment_key *)k1;
	const tcp_segment_key *key2 = (const tcp_segment_key *)k2;

	return ( ( (key1->seq==key2->seq)
		 &&(ADDRESSES_EQUAL(key1->src, key2->src))
		 &&(ADDRESSES_EQUAL(key1->dst, key2->dst))
		 &&(key1->sport==key2->sport)
		 &&(key1->dport==key2->dport)
		 ) ? TRUE:FALSE);
}

static void
tcp_desegment_init(void)
{
	/*
	 * Free this before freeing any memory chunks; those
	 * chunks contain data we'll look at in "free_all_segments()".
	 */
	if(tcp_segment_table){
		g_hash_table_foreach_remove(tcp_segment_table,
			free_all_segments, NULL);
		g_hash_table_destroy(tcp_segment_table);
		tcp_segment_table = NULL;
	}

	if(tcp_segment_key_chunk){
		g_mem_chunk_destroy(tcp_segment_key_chunk);
		tcp_segment_key_chunk = NULL;
	}
	if(tcp_segment_address_chunk){
		g_mem_chunk_destroy(tcp_segment_address_chunk);
		tcp_segment_address_chunk = NULL;
	}

	/* dont allocate any hash table or memory chunks unless the user
	   really uses this option
	*/
	if(!tcp_desegment){
		return;
	}

	tcp_segment_table = g_hash_table_new(tcp_segment_hash,
		tcp_segment_equal);

	tcp_segment_key_chunk = g_mem_chunk_new("tcp_segment_key_chunk",
		sizeof(tcp_segment_key),
		tcp_segment_init_count*sizeof(tcp_segment_key),
		G_ALLOC_ONLY);

	tcp_segment_address_chunk = g_mem_chunk_new("tcp_segment_address_chunk",
		sizeof(address),
		tcp_segment_address_init_count*sizeof(address),
		G_ALLOC_ONLY);
}

static void
desegment_tcp(tvbuff_t *tvb, packet_info *pinfo, int offset,
		guint32 seq, guint32 nxtseq,
		guint32 sport, guint32 dport,
		proto_tree *tree, proto_tree *tcp_tree)
{
	struct tcpinfo *tcpinfo = pinfo->private_data;
	fragment_data *ipfd_head=NULL;
	tcp_segment_key old_tsk, *tsk;
	gboolean must_desegment = FALSE;
	gboolean called_dissector = FALSE;
	int deseg_offset;
	guint32 deseg_seq;
	gint nbytes;
    proto_item *item;
    proto_item *frag_tree_item;
    proto_item *tcp_tree_item;


	/*
	 * Initialize these to assume no desegmentation.
	 * If that's not the case, these will be set appropriately
	 * by the subdissector.
	 */
	pinfo->desegment_offset = 0;
	pinfo->desegment_len = 0;

	/*
	 * Initialize this to assume that this segment will just be
	 * added to the middle of a desegmented chunk of data, so
	 * that we should show it all as data.
	 * If that's not the case, it will be set appropriately.
	 */
	deseg_offset = offset;

	/* First we must check if this TCP segment should be desegmented.
	   This is only to check if we should desegment this packet,
	   so we dont spend time doing COPY_ADDRESS/g_free.
	   We just "borrow" some address structures from pinfo instead. Cheaper.
	*/
	old_tsk.src = &pinfo->src;
	old_tsk.dst = &pinfo->dst;
	old_tsk.sport = sport;
	old_tsk.dport = dport;
	old_tsk.seq = seq;
	tsk = g_hash_table_lookup(tcp_segment_table, &old_tsk);

	if(tsk){
		/* OK, this segment was found, which means it continues
		   a higher-level PDU. This means we must desegment it.
		   Add it to the defragmentation lists.
		*/
		ipfd_head = fragment_add(tvb, offset, pinfo, tsk->first_frame,
			tcp_fragment_table,
			seq - tsk->start_seq,
			nxtseq - seq,
			(LT_SEQ (nxtseq,tsk->start_seq + tsk->tot_len)) );

		if(!ipfd_head){
			/* fragment_add() returned NULL, This means that
			   desegmentation is not completed yet.
			   (its like defragmentation but we know we will
			    always add the segments in order).
			   XXX - no, we don't; there is no guarantee that
			   TCP segments are in order on the wire.

			   we must add next segment to our table so we will
			   find it later.
			*/
			tcp_segment_key *new_tsk;

			new_tsk = g_mem_chunk_alloc(tcp_segment_key_chunk);
			memcpy(new_tsk, tsk, sizeof(tcp_segment_key));
			new_tsk->seq=nxtseq;
			g_hash_table_insert(tcp_segment_table,new_tsk,new_tsk);
		}
	} else {
		/* This segment was not found in our table, so it doesn't
		   contain a continuation of a higher-level PDU.
		   Call the normal subdissector.
		*/
		process_tcp_payload(tvb, offset, pinfo, tree, tcp_tree,
				sport, dport, 0, 0, FALSE);
		called_dissector = TRUE;

		/* Did the subdissector ask us to desegment some more data
		   before it could handle the packet?
		   If so we have to create some structures in our table but
		   this is something we only do the first time we see this
		   packet.
		*/
		if(pinfo->desegment_len) {
			if (!pinfo->fd->flags.visited)
				must_desegment = TRUE;

			/*
			 * Set "deseg_offset" to the offset in "tvb"
			 * of the first byte of data that the
			 * subdissector didn't process.
			 */
			deseg_offset = offset + pinfo->desegment_offset;
		}

		/* Either no desegmentation is necessary, or this is
		   segment contains the beginning but not the end of
		   a higher-level PDU and thus isn't completely
		   desegmented.
		*/
		ipfd_head = NULL;
	}

	/* is it completely desegmented? */
	if(ipfd_head){
		fragment_data *ipfd;

		/*
		 * Yes, we think it is.
		 * We only call subdissector for the last segment.
		 * Note that the last segment may include more than what
		 * we needed.
		 */
		if(GE_SEQ(nxtseq, tsk->start_seq + tsk->tot_len)){
			/*
			 * OK, this is the last segment.
			 * Let's call the subdissector with the desegmented
			 * data.
			 */
			tvbuff_t *next_tvb;
			int old_len;

			/* create a new TVB structure for desegmented data */
			next_tvb = tvb_new_real_data(ipfd_head->data,
					ipfd_head->datalen, ipfd_head->datalen);

			/* add this tvb as a child to the original one */
			tvb_set_child_real_data_tvbuff(tvb, next_tvb);

			/* add desegmented data to the data source list */
			add_new_data_source(pinfo, next_tvb, "Reassembled TCP");

			/*
			 * Supply the sequence number of the first of the
			 * reassembled bytes.
			 */
			tcpinfo->seq = tsk->start_seq;

			/* indicate that this is reassembled data */
			tcpinfo->is_reassembled = TRUE;

			/* call subdissector */
			process_tcp_payload(next_tvb, 0, pinfo, tree,
			    tcp_tree, sport, dport, 0, 0, FALSE);
			called_dissector = TRUE;

			/*
			 * OK, did the subdissector think it was completely
			 * desegmented, or does it think we need even more
			 * data?
			 */
			old_len=(int)(tvb_reported_length(next_tvb)-tvb_reported_length_remaining(tvb, offset));
			if(pinfo->desegment_len &&
			    pinfo->desegment_offset<=old_len){
				tcp_segment_key *new_tsk;

				/*
				 * "desegment_len" isn't 0, so it needs more
				 * data for something - and "desegment_offset"
				 * is before "old_len", so it needs more data
				 * to dissect the stuff we thought was
				 * completely desegmented (as opposed to the
				 * stuff at the beginning being completely
				 * desegmented, but the stuff at the end
				 * being a new higher-level PDU that also
				 * needs desegmentation).
				 */
				fragment_set_partial_reassembly(pinfo,tsk->first_frame,tcp_fragment_table);
				tsk->tot_len = tvb_reported_length(next_tvb) + pinfo->desegment_len;

				/*
				 * Update tsk structure.
				 * Can ask ->next->next because at least there's a hdr and one
				 * entry in fragment_add()
				 */
				for(ipfd=ipfd_head->next; ipfd->next; ipfd=ipfd->next){
					old_tsk.seq = tsk->start_seq + ipfd->offset;
					new_tsk = g_hash_table_lookup(tcp_segment_table, &old_tsk);
					new_tsk->tot_len = tsk->tot_len;
				}

				/* this is the next segment in the sequence we want */
				new_tsk = g_mem_chunk_alloc(tcp_segment_key_chunk);
				memcpy(new_tsk, tsk, sizeof(tcp_segment_key));
				new_tsk->seq = nxtseq;
				g_hash_table_insert(tcp_segment_table,new_tsk,new_tsk);
			} else {
				/*
				 * Show the stuff in this TCP segment as
				 * just raw TCP segment data.
				 */
				nbytes =
				    tvb_reported_length_remaining(tvb, offset);
				proto_tree_add_text(tcp_tree, tvb, offset, -1,
				    "TCP segment data (%u byte%s)", nbytes,
				    plurality(nbytes, "", "s"));

				/*
				 * The subdissector thought it was completely
				 * desegmented (although the stuff at the
				 * end may, in turn, require desegmentation),
				 * so we show a tree with all segments.
				 */
				show_fragment_tree(ipfd_head, &tcp_segment_items,
					tree, pinfo, next_tvb, &frag_tree_item);
				/*
				 * The toplevel fragment subtree is now
				 * behind all desegmented data; move it
				 * right behind the TCP tree.
				 */
				tcp_tree_item = proto_tree_get_parent(tcp_tree);
				if(frag_tree_item && tcp_tree_item) {
					proto_tree_move_item(tree, tcp_tree_item, frag_tree_item);
				}

				/* Did the subdissector ask us to desegment
				   some more data?  This means that the data
				   at the beginning of this segment completed
				   a higher-level PDU, but the data at the
				   end of this segment started a higher-level
				   PDU but didn't complete it.

				   If so, we have to create some structures
				   in our table, but this is something we
				   only do the first time we see this packet.
				*/
				if(pinfo->desegment_len) {
					if (!pinfo->fd->flags.visited)
						must_desegment = TRUE;

					/* The stuff we couldn't dissect
					   must have come from this segment,
					   so it's all in "tvb".

				 	   "pinfo->desegment_offset" is
				 	   relative to the beginning of
				 	   "next_tvb"; we want an offset
				 	   relative to the beginning of "tvb".

				 	   First, compute the offset relative
				 	   to the *end* of "next_tvb" - i.e.,
				 	   the number of bytes before the end
				 	   of "next_tvb" at which the
				 	   subdissector stopped.  That's the
				 	   length of "next_tvb" minus the
				 	   offset, relative to the beginning
				 	   of "next_tvb, at which the
				 	   subdissector stopped.
				 	*/
					deseg_offset =
					    ipfd_head->datalen - pinfo->desegment_offset;

					/* "tvb" and "next_tvb" end at the
					   same byte of data, so the offset
					   relative to the end of "next_tvb"
					   of the byte at which we stopped
					   is also the offset relative to
					   the end of "tvb" of the byte at
					   which we stopped.

					   Convert that back into an offset
					   relative to the beginninng of
					   "tvb", by taking the length of
					   "tvb" and subtracting the offset
					   relative to the end.
					*/
					deseg_offset=tvb_reported_length(tvb) - deseg_offset;
				}
			}
		}
	}

	if (must_desegment) {
	    tcp_segment_key *tsk, *new_tsk;

	    /*
	     * The sequence number at which the stuff to be desegmented
	     * starts is the sequence number of the byte at an offset
	     * of "deseg_offset" into "tvb".
	     *
	     * The sequence number of the byte at an offset of "offset"
	     * is "seq", i.e. the starting sequence number of this
	     * segment, so the sequence number of the byte at
	     * "deseg_offset" is "seq + (deseg_offset - offset)".
	     */
	    deseg_seq = seq + (deseg_offset - offset);

	    /*
	     * XXX - how do we detect out-of-order transmissions?
	     * We can't just check for "nxtseq" being greater than
	     * "tsk->start_seq"; for now, we check for the difference
	     * being less than a megabyte, but this is a really
	     * gross hack - we really need to handle out-of-order
	     * transmissions correctly.
	     */
	    if ((nxtseq - deseg_seq) <= 1024*1024) {
		/* OK, subdissector wants us to desegment
		   some data before it can process it. Add
		   what remains of this packet and set
		   up next packet/sequence number as well.

		   We must remember this segment
		*/
		tsk = g_mem_chunk_alloc(tcp_segment_key_chunk);
		tsk->src = g_mem_chunk_alloc(tcp_segment_address_chunk);
		COPY_ADDRESS(tsk->src, &pinfo->src);
		tsk->dst = g_mem_chunk_alloc(tcp_segment_address_chunk);
		COPY_ADDRESS(tsk->dst, &pinfo->dst);
		tsk->seq = deseg_seq;
		tsk->start_seq = tsk->seq;
		tsk->tot_len = nxtseq - tsk->start_seq + pinfo->desegment_len;
		tsk->first_frame = pinfo->fd->num;
		tsk->sport=sport;
		tsk->dport=dport;
		g_hash_table_insert(tcp_segment_table, tsk, tsk);

		/* Add portion of segment unprocessed by the subdissector
		   to defragmentation lists */
		fragment_add(tvb, deseg_offset, pinfo, tsk->first_frame,
		    tcp_fragment_table,
		    tsk->seq - tsk->start_seq,
		    nxtseq - tsk->start_seq,
		    LT_SEQ (nxtseq, tsk->start_seq + tsk->tot_len));

		/* this is the next segment in the sequence we want */
		new_tsk = g_mem_chunk_alloc(tcp_segment_key_chunk);
		memcpy(new_tsk, tsk, sizeof(tcp_segment_key));
		new_tsk->seq = nxtseq;
		g_hash_table_insert(tcp_segment_table,new_tsk,new_tsk);
	    }
	}

	if (!called_dissector || pinfo->desegment_len != 0) {
		if (ipfd_head != NULL && ipfd_head->reassembled_in != 0 &&
		    !(ipfd_head->flags & FD_PARTIAL_REASSEMBLY)) {
			/*
			 * We know what frame this PDU is reassembled in;
			 * let the user know.
			 */
			item=proto_tree_add_uint(tcp_tree, hf_tcp_reassembled_in,
			    tvb, 0, 0, ipfd_head->reassembled_in);
			PROTO_ITEM_SET_GENERATED(item);
		}

		/*
		 * Either we didn't call the subdissector at all (i.e.,
		 * this is a segment that contains the middle of a
		 * higher-level PDU, but contains neither the beginning
		 * nor the end), or the subdissector couldn't dissect it
		 * all, as some data was missing (i.e., it set
		 * "pinfo->desegment_len" to the amount of additional
		 * data it needs).
		 */
		if (pinfo->desegment_offset == 0) {
			/*
			 * It couldn't, in fact, dissect any of it (the
			 * first byte it couldn't dissect is at an offset
			 * of "pinfo->desegment_offset" from the beginning
			 * of the payload, and that's 0).
			 * Just mark this as TCP.
			 */
			if (check_col(pinfo->cinfo, COL_PROTOCOL)){
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCP");
			}
			if (check_col(pinfo->cinfo, COL_INFO)){
				col_set_str(pinfo->cinfo, COL_INFO, "[TCP segment of a reassembled PDU]");
			}
		}

		/*
		 * Show what's left in the packet as just raw TCP segment
		 * data.
		 * XXX - remember what protocol the last subdissector
		 * was, and report it as a continuation of that, instead?
		 */
		nbytes = tvb_reported_length_remaining(tvb, deseg_offset);
		proto_tree_add_text(tcp_tree, tvb, deseg_offset, -1,
		    "TCP segment data (%u byte%s)", nbytes,
		    plurality(nbytes, "", "s"));
	}
	pinfo->can_desegment=0;
	pinfo->desegment_offset = 0;
	pinfo->desegment_len = 0;
}

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
void
tcp_dissect_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		 gboolean proto_desegment, guint fixed_len,
		 guint (*get_pdu_len)(tvbuff_t *, int),
		 dissector_t dissect_pdu)
{
  volatile int offset = 0;
  int offset_before;
  guint length_remaining;
  guint plen;
  guint length;
  tvbuff_t *next_tvb;

  while (tvb_reported_length_remaining(tvb, offset) != 0) {
    /*
     * We use "tvb_ensure_length_remaining()" to make sure there actually
     * *is* data remaining.  The protocol we're handling could conceivably
     * consists of a sequence of fixed-length PDUs, and therefore the
     * "get_pdu_len" routine might not actually fetch anything from
     * the tvbuff, and thus might not cause an exception to be thrown if
     * we've run past the end of the tvbuff.
     *
     * This means we're guaranteed that "length_remaining" is positive.
     */
    length_remaining = tvb_ensure_length_remaining(tvb, offset);

    /*
     * Can we do reassembly?
     */
    if (proto_desegment && pinfo->can_desegment) {
      /*
       * Yes - is the fixed-length part of the PDU split across segment
       * boundaries?
       */
      if (length_remaining < fixed_len) {
	/*
	 * Yes.  Tell the TCP dissector where the data for this message
	 * starts in the data it handed us, and how many more bytes we
	 * need, and return.
	 */
	pinfo->desegment_offset = offset;
	pinfo->desegment_len = fixed_len - length_remaining;
	return;
      }
    }

    /*
     * Get the length of the PDU.
     */
    plen = (*get_pdu_len)(tvb, offset);
    if (plen < fixed_len) {
      /*
       * The PDU length from the fixed-length portion probably didn't
       * include the fixed-length portion's length, and was probably so
       * large that the total length overflowed.
       *
       * Report this as an error.
       */
      show_reported_bounds_error(tvb, pinfo, tree);
      return;
    }

    /* give a hint to TCP where the next PDU starts
     * so that it can attempt to find it in case it starts
     * somewhere in the middle of a segment.
     */
    if(!pinfo->fd->flags.visited && tcp_analyze_seq){
       guint remaining_bytes;
       remaining_bytes=tvb_reported_length_remaining(tvb, offset);
       if(plen>remaining_bytes){
          pinfo->want_pdu_tracking=2;
          pinfo->bytes_until_next_pdu=plen-remaining_bytes;
       }
    }

    /*
     * Can we do reassembly?
     */
    if (proto_desegment && pinfo->can_desegment) {
      /*
       * Yes - is the PDU split across segment boundaries?
       */
      if (length_remaining < plen) {
	/*
	 * Yes.  Tell the TCP dissector where the data for this message
	 * starts in the data it handed us, and how many more bytes we
	 * need, and return.
	 */
	pinfo->desegment_offset = offset;
	pinfo->desegment_len = plen - length_remaining;
	return;
      }
    }

    /*
     * Construct a tvbuff containing the amount of the payload we have
     * available.  Make its reported length the amount of data in the PDU.
     *
     * XXX - if reassembly isn't enabled. the subdissector will throw a
     * BoundsError exception, rather than a ReportedBoundsError exception.
     * We really want a tvbuff where the length is "length", the reported
     * length is "plen", and the "if the snapshot length were infinite"
     * length is the minimum of the reported length of the tvbuff handed
     * to us and "plen", with a new type of exception thrown if the offset
     * is within the reported length but beyond that third length, with
     * that exception getting the "Unreassembled Packet" error.
     */
    length = length_remaining;
    if (length > plen)
	length = plen;
    next_tvb = tvb_new_subset(tvb, offset, length, plen);

    /*
     * Dissect the PDU.
     *
     * Catch the ReportedBoundsError exception; if this particular message
     * happens to get a ReportedBoundsError exception, that doesn't mean
     * that we should stop dissecting PDUs within this frame or chunk of
     * reassembled data.
     *
     * If it gets a BoundsError, we can stop, as there's nothing more to
     * see, so we just re-throw it.
     */
    TRY {
      (*dissect_pdu)(next_tvb, pinfo, tree);
    }
    CATCH(BoundsError) {
      RETHROW;
    }
    CATCH(ReportedBoundsError) {
      show_reported_bounds_error(tvb, pinfo, tree);
    }
    ENDTRY;

    /*
     * Step to the next PDU.
     * Make sure we don't overflow.
     */
    offset_before = offset;
    offset += plen;
    if (offset <= offset_before)
      break;
  }
}

static void
tcp_info_append_uint(packet_info *pinfo, const char *abbrev, guint32 val)
{
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s=%u", abbrev, val);
}

static void
dissect_tcpopt_maxseg(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
  guint16 mss;

  mss = tvb_get_ntohs(tvb, offset + 2);
  proto_tree_add_boolean_hidden(opt_tree, hf_tcp_option_mss, tvb, offset,
				optlen, TRUE);
  proto_tree_add_uint_format(opt_tree, hf_tcp_option_mss_val, tvb, offset,
			     optlen, mss, "%s: %u bytes", optp->name, mss);
  tcp_info_append_uint(pinfo, "MSS", mss);
}

static void
dissect_tcpopt_wscale(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
  guint8 ws;

  ws = tvb_get_guint8(tvb, offset + 2);
  proto_tree_add_boolean_hidden(opt_tree, hf_tcp_option_wscale, tvb, 
				offset, optlen, TRUE);
  proto_tree_add_uint_format(opt_tree, hf_tcp_option_wscale_val, tvb,
			     offset, optlen, ws, "%s: %u (multiply by %u)", 
			     optp->name, ws, 1 << ws);
  tcp_info_append_uint(pinfo, "WS", ws);
  if(!pinfo->fd->flags.visited && tcp_analyze_seq && tcp_relative_seq){
    pdu_store_window_scale_option(pinfo, ws);
  }
}

static void
dissect_tcpopt_sack(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
  proto_tree *field_tree = NULL;
  proto_item *tf=NULL;
  guint32 leftedge, rightedge;
  struct tcp_analysis *tcpd=NULL;
  int direction;
  guint32 base_ack=0;

  if(tcp_analyze_seq && tcp_relative_seq){
    /* find(or create if needed) the conversation for this tcp session */
    tcpd=get_tcp_conversation_data(pinfo);

    /* check direction and get ua lists */
    direction=CMP_ADDRESS(&pinfo->src, &pinfo->dst);
    /* if the addresses are equal, match the ports instead */
    if(direction==0) {
      direction= (pinfo->srcport > pinfo->destport)*2-1;
    }
    if(direction>=0){
      base_ack=tcpd->base_seq2;
    } else {
      base_ack=tcpd->base_seq1;
    }
  }

  tf = proto_tree_add_text(opt_tree, tvb, offset,      optlen, "%s:", optp->name);
  offset += 2;	/* skip past type and length */
  optlen -= 2;	/* subtract size of type and length */
  while (optlen > 0) {
    if (field_tree == NULL) {
      /* Haven't yet made a subtree out of this option.  Do so. */
      field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
      proto_tree_add_boolean_hidden(field_tree, hf_tcp_option_sack, tvb, 
				    offset, optlen, TRUE);
    }
    if (optlen < 4) {
      proto_tree_add_text(field_tree, tvb, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }
    leftedge = tvb_get_ntohl(tvb, offset)-base_ack;
    proto_tree_add_uint_format(field_tree, hf_tcp_option_sack_sle, tvb, 
			       offset, 4, leftedge, 
			       "left edge = %u%s", leftedge,
			       tcp_relative_seq ? " (relative)" : "");

    optlen -= 4;
    if (optlen < 4) {
      proto_tree_add_text(field_tree, tvb, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }
    /* XXX - check whether it goes past end of packet */
    rightedge = tvb_get_ntohl(tvb, offset + 4)-base_ack;
    optlen -= 4;
    proto_tree_add_uint_format(field_tree, hf_tcp_option_sack_sre, tvb, 
			       offset+4, 4, rightedge, 
			       "right edge = %u%s", rightedge,
			       tcp_relative_seq ? " (relative)" : "");
    tcp_info_append_uint(pinfo, "SLE", leftedge);
    tcp_info_append_uint(pinfo, "SRE", rightedge);
    proto_item_append_text(field_tree, " %u-%u", leftedge, rightedge);
    offset += 8;
  }
}

static void
dissect_tcpopt_echo(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
  guint32 echo;

  echo = tvb_get_ntohl(tvb, offset + 2);
  proto_tree_add_boolean_hidden(opt_tree, hf_tcp_option_echo, tvb, offset,
				optlen, TRUE);
  proto_tree_add_text(opt_tree, tvb, offset,      optlen,
			"%s: %u", optp->name, echo);
  tcp_info_append_uint(pinfo, "ECHO", echo);
}

static void
dissect_tcpopt_timestamp(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
  guint32 tsv, tser;

  tsv = tvb_get_ntohl(tvb, offset + 2);
  tser = tvb_get_ntohl(tvb, offset + 6);
  proto_tree_add_boolean_hidden(opt_tree, hf_tcp_option_time_stamp, tvb, 
				offset, optlen, TRUE);
  proto_tree_add_text(opt_tree, tvb, offset,      optlen,
    "%s: tsval %u, tsecr %u", optp->name, tsv, tser);
  tcp_info_append_uint(pinfo, "TSV", tsv);
  tcp_info_append_uint(pinfo, "TSER", tser);
}

static void
dissect_tcpopt_cc(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
  guint32 cc;

  cc = tvb_get_ntohl(tvb, offset + 2);
  proto_tree_add_boolean_hidden(opt_tree, hf_tcp_option_cc, tvb, offset,
				optlen, TRUE);
  proto_tree_add_text(opt_tree, tvb, offset,      optlen,
			"%s: %u", optp->name, cc);
  tcp_info_append_uint(pinfo, "CC", cc);
}

static const ip_tcp_opt tcpopts[] = {
  {
    TCPOPT_EOL,
    "EOL",
    NULL,
    NO_LENGTH,
    0,
    NULL,
  },
  {
    TCPOPT_NOP,
    "NOP",
    NULL,
    NO_LENGTH,
    0,
    NULL,
  },
  {
    TCPOPT_MSS,
    "Maximum segment size",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_MSS,
    dissect_tcpopt_maxseg
  },
  {
    TCPOPT_WINDOW,
    "Window scale",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_WINDOW,
    dissect_tcpopt_wscale
  },
  {
    TCPOPT_SACK_PERM,
    "SACK permitted",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_SACK_PERM,
    NULL,
  },
  {
    TCPOPT_SACK,
    "SACK",
    &ett_tcp_option_sack,
    VARIABLE_LENGTH,
    TCPOLEN_SACK_MIN,
    dissect_tcpopt_sack
  },
  {
    TCPOPT_ECHO,
    "Echo",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_ECHO,
    dissect_tcpopt_echo
  },
  {
    TCPOPT_ECHOREPLY,
    "Echo reply",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_ECHOREPLY,
    dissect_tcpopt_echo
  },
  {
    TCPOPT_TIMESTAMP,
    "Time stamp",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_TIMESTAMP,
    dissect_tcpopt_timestamp
  },
  {
    TCPOPT_CC,
    "CC",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_CC,
    dissect_tcpopt_cc
  },
  {
    TCPOPT_CCNEW,
    "CC.NEW",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_CCNEW,
    dissect_tcpopt_cc
  },
  {
    TCPOPT_CCECHO,
    "CC.ECHO",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_CCECHO,
    dissect_tcpopt_cc
  },
  {
    TCPOPT_MD5,
    "TCP MD5 signature",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_MD5,
    NULL
  }
};

#define N_TCP_OPTS	(sizeof tcpopts / sizeof tcpopts[0])

/* Determine if there is a sub-dissector and call it; return TRUE
   if there was a sub-dissector, FALSE otherwise.

   This has been separated into a stand alone routine to other protocol
   dissectors can call to it, e.g., SOCKS. */

static gboolean try_heuristic_first = FALSE;

gboolean
decode_tcp_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, int src_port, int dst_port)
{
  tvbuff_t *next_tvb;
  int low_port, high_port;

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);

/* determine if this packet is part of a conversation and call dissector */
/* for the conversation if available */

  if (try_conversation_dissector(&pinfo->src, &pinfo->dst, PT_TCP,
		src_port, dst_port, next_tvb, pinfo, tree)){
    pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
    return TRUE;
  }

  if (try_heuristic_first) {
    /* do lookup with the heuristic subdissector table */
    if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree)){
       pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
       return TRUE;
    }
  }

  /* Do lookups with the subdissector table.
     We try the port number with the lower value first, followed by the
     port number with the higher value.  This means that, for packets
     where a dissector is registered for *both* port numbers:

	1) we pick the same dissector for traffic going in both directions;

	2) we prefer the port number that's more likely to be the right
	   one (as that prefers well-known ports to reserved ports);

     although there is, of course, no guarantee that any such strategy
     will always pick the right port number.

     XXX - we ignore port numbers of 0, as some dissectors use a port
     number of 0 to disable the port. */
  if (src_port > dst_port) {
    low_port = dst_port;
    high_port = src_port;
  } else {
    low_port = src_port;
    high_port = dst_port;
  }
  if (low_port != 0 &&
      dissector_try_port(subdissector_table, low_port, next_tvb, pinfo, tree)){
    pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
    return TRUE;
  }
  if (high_port != 0 &&
      dissector_try_port(subdissector_table, high_port, next_tvb, pinfo, tree)){
    pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
    return TRUE;
  }

  if (!try_heuristic_first) {
    /* do lookup with the heuristic subdissector table */
    if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree)){
       pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
       return TRUE;
    }
  }

  /* Oh, well, we don't know this; dissect it as data. */
  call_dissector(data_handle,next_tvb, pinfo, tree);

  pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
  return FALSE;
}

static void
process_tcp_payload(tvbuff_t *tvb, volatile int offset, packet_info *pinfo,
	proto_tree *tree, proto_tree *tcp_tree, int src_port, int dst_port,
	guint32 seq, guint32 nxtseq, gboolean is_tcp_segment)
{
	pinfo->want_pdu_tracking=0;

	TRY {
		if(is_tcp_segment){
			/*qqq   see if it is an unaligned PDU */
			if(tcp_analyze_seq && (!tcp_desegment)){
				if(seq || nxtseq){
					offset=scan_for_next_pdu(tvb, tcp_tree, pinfo, offset,
						seq, nxtseq);
				}
			}
		}
		/* if offset is -1 this means that this segment is known
		 * to be fully inside a previously detected pdu
		 * so we dont even need to try to dissect it either.
		 */
		if( (offset!=-1) &&
		    decode_tcp_ports(tvb, offset, pinfo, tree, src_port,
		        dst_port) ){
			/*
			 * We succeeded in handing off to a subdissector.
			 *
			 * Is this a TCP segment or a reassembled chunk of
			 * TCP payload?
			 */
			if(is_tcp_segment){
				/* if !visited, check want_pdu_tracking and
				   store it in table */
				if((!pinfo->fd->flags.visited) &&
				    tcp_analyze_seq && pinfo->want_pdu_tracking){
					if(seq || nxtseq){
						pdu_store_sequencenumber_of_next_pdu(
						    pinfo,
                	                            seq,
						    nxtseq+pinfo->bytes_until_next_pdu);
					}
				}
			}
		}
	}
	CATCH_ALL {
		/* We got an exception. At this point the dissection is
		 * completely aborted and execution will be transfered back
		 * to (probably) the frame dissector.
		 * Here we have to place whatever we want the dissector
		 * to do before aborting the tcp dissection.
		 */
		/*
		 * Is this a TCP segment or a reassembled chunk of TCP
		 * payload?
		 */
		if(is_tcp_segment){
			/*
			 * It's from a TCP segment.
			 *
			 * if !visited, check want_pdu_tracking and store it
			 * in table 
			 */
			if((!pinfo->fd->flags.visited) && tcp_analyze_seq && pinfo->want_pdu_tracking){
				if(seq || nxtseq){
					pdu_store_sequencenumber_of_next_pdu(pinfo,
        	                            seq,
					    nxtseq+pinfo->bytes_until_next_pdu);
				}
			}
		}
		RETHROW;
	}
	ENDTRY;
}

void
dissect_tcp_payload(tvbuff_t *tvb, packet_info *pinfo, int offset, guint32 seq,
		    guint32 nxtseq, guint32 sport, guint32 dport,
		    proto_tree *tree, proto_tree *tcp_tree)
{
  gboolean save_fragmented;

  /* Can we desegment this segment? */
  if (pinfo->can_desegment) {
    /* Yes. */
    desegment_tcp(tvb, pinfo, offset, seq, nxtseq, sport, dport, tree,
        tcp_tree);
  } else {
    /* No - just call the subdissector.
       Mark this as fragmented, so if somebody throws an exception,
       we don't report it as a malformed frame. */
    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = TRUE;
    process_tcp_payload(tvb, offset, pinfo, tree, tcp_tree, sport, dport,
        seq, nxtseq, TRUE);
    pinfo->fragmented = save_fragmented;
  }
}

static void
dissect_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8  th_off_x2; /* combines th_off and th_x2 */
  guint16 th_sum;
  guint16 th_urp;
  proto_tree *tcp_tree = NULL, *field_tree = NULL;
  proto_item *ti = NULL, *tf;
  int        offset = 0;
  gchar      *flags = "<None>";
  const gchar *fstr[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECN", "CWR" };
  size_t     fpos = 0, returned_length;
  gint       i;
  guint      bpos;
  guint      optlen;
  guint32    nxtseq = 0;
  guint      reported_len;
  vec_t      cksum_vec[4];
  guint32    phdr[2];
  guint16    computed_cksum;
  guint16    real_window;
  guint      length_remaining;
  gboolean   desegment_ok;
  struct tcpinfo tcpinfo;
  static struct tcpheader tcphstruct[4], *tcph;
  static int tcph_count=0;
  proto_item *tf_syn = NULL, *tf_fin = NULL, *tf_rst = NULL;

  tcph_count++;
  if(tcph_count>=4){
     tcph_count=0;
  }
  tcph=&tcphstruct[tcph_count];
  SET_ADDRESS(&tcph->ip_src, pinfo->src.type, pinfo->src.len, pinfo->src.data);
  SET_ADDRESS(&tcph->ip_dst, pinfo->dst.type, pinfo->dst.len, pinfo->dst.data);

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCP");

  /* Clear out the Info column. */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  tcph->th_sport = tvb_get_ntohs(tvb, offset);
  tcph->th_dport = tvb_get_ntohs(tvb, offset + 2);
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s > %s",
      get_tcp_port(tcph->th_sport), get_tcp_port(tcph->th_dport));
  }
  if (tree) {
    if (tcp_summary_in_tree) {
	    ti = proto_tree_add_protocol_format(tree, proto_tcp, tvb, 0, -1,
		"Transmission Control Protocol, Src Port: %s (%u), Dst Port: %s (%u)",
		get_tcp_port(tcph->th_sport), tcph->th_sport,
		get_tcp_port(tcph->th_dport), tcph->th_dport);
    }
    else {
	    ti = proto_tree_add_item(tree, proto_tcp, tvb, 0, -1, FALSE);
    }
    tcp_tree = proto_item_add_subtree(ti, ett_tcp);
    proto_tree_add_uint_format(tcp_tree, hf_tcp_srcport, tvb, offset, 2, tcph->th_sport,
	"Source port: %s (%u)", get_tcp_port(tcph->th_sport), tcph->th_sport);
    proto_tree_add_uint_format(tcp_tree, hf_tcp_dstport, tvb, offset + 2, 2, tcph->th_dport,
	"Destination port: %s (%u)", get_tcp_port(tcph->th_dport), tcph->th_dport);
    proto_tree_add_uint_hidden(tcp_tree, hf_tcp_port, tvb, offset, 2, tcph->th_sport);
    proto_tree_add_uint_hidden(tcp_tree, hf_tcp_port, tvb, offset + 2, 2, tcph->th_dport);
  }

  /* Set the source and destination port numbers as soon as we get them,
     so that they're available to the "Follow TCP Stream" code even if
     we throw an exception dissecting the rest of the TCP header. */
  pinfo->ptype = PT_TCP;
  pinfo->srcport = tcph->th_sport;
  pinfo->destport = tcph->th_dport;

  tcph->th_seq = tvb_get_ntohl(tvb, offset + 4);
  tcph->th_ack = tvb_get_ntohl(tvb, offset + 8);
  th_off_x2 = tvb_get_guint8(tvb, offset + 12);
  tcph->th_flags = tvb_get_guint8(tvb, offset + 13);
  tcph->th_win = tvb_get_ntohs(tvb, offset + 14);
  real_window = tcph->th_win;
  tcph->th_hlen = hi_nibble(th_off_x2) * 4;  /* TCP header length, in bytes */

  /*
   * If we've been handed an IP fragment, we don't know how big the TCP
   * segment is, so don't do anything that requires that we know that.
   *
   * The same applies if we're part of an error packet.  (XXX - if the
   * ICMP and ICMPv6 dissectors could set a "this is how big the IP
   * header says it is" length in the tvbuff, we could use that; such
   * a length might also be useful for handling packets where the IP
   * length is bigger than the actual data available in the frame; the
   * dissectors should trust that length, and then throw a
   * ReportedBoundsError exception when they go past the end of the frame.)
   *
   * We also can't determine the segment length if the reported length
   * of the TCP packet is less than the TCP header length.
   */
  reported_len = tvb_reported_length(tvb);

  if (!pinfo->fragmented && !pinfo->in_error_pkt) {
    if (reported_len < tcph->th_hlen) {
      proto_tree_add_text(tcp_tree, tvb, offset, 0,
        "Short segment. Segment/fragment does not contain a full TCP header"
        " (might be NMAP or someone else deliberately sending unusual packets)");
      tcph->th_have_seglen = FALSE;
    } else {
      /* Compute the length of data in this segment. */
      tcph->th_seglen = reported_len - tcph->th_hlen;
      tcph->th_have_seglen = TRUE;

      if (tree) { /* Add the seglen as an invisible field */

        proto_tree_add_uint_hidden(ti, hf_tcp_len, tvb, offset, 4, tcph->th_seglen);

      }

      /* handle TCP seq# analysis parse all new segments we see */
      if(tcp_analyze_seq){
          if(!(pinfo->fd->flags.visited)){
              tcp_analyze_sequence_number(pinfo, tcph->th_seq, tcph->th_ack, tcph->th_seglen, tcph->th_flags, tcph->th_win);
          }
          if(tcp_relative_seq){
              tcp_get_relative_seq_ack(pinfo->fd->num, &(tcph->th_seq), &(tcph->th_ack), &(tcph->th_win));
          }
      }

      /* Compute the sequence number of next octet after this segment. */
      nxtseq = tcph->th_seq + tcph->th_seglen;
    }
  } else
    tcph->th_have_seglen = FALSE;

  if (check_col(pinfo->cinfo, COL_INFO) || tree) {
#define MAX_FLAGS_LEN 64
    flags=ep_alloc(MAX_FLAGS_LEN);
    flags[0]=0;
    for (i = 0; i < 8; i++) {
      bpos = 1 << i;
      if (tcph->th_flags & bpos) {
        returned_length = g_snprintf(&flags[fpos], MAX_FLAGS_LEN-fpos, "%s%s",
		fpos?", ":"",
		fstr[i]);
	fpos += MIN(returned_length, MAX_FLAGS_LEN-fpos);
      }
    }
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
    if(tcph->th_flags&TH_ACK){
      col_append_fstr(pinfo->cinfo, COL_INFO, " [%s] Seq=%u Ack=%u Win=%u",
        flags, tcph->th_seq, tcph->th_ack, tcph->th_win);
    } else {
      col_append_fstr(pinfo->cinfo, COL_INFO, " [%s] Seq=%u",
        flags, tcph->th_seq);
    }
  }

  if (tree) {
    if (tcp_summary_in_tree) {
      proto_item_append_text(ti, ", Seq: %u", tcph->th_seq);
    }
    if(tcp_relative_seq){
      proto_tree_add_uint_format(tcp_tree, hf_tcp_seq, tvb, offset + 4, 4, tcph->th_seq, "Sequence number: %u    (relative sequence number)", tcph->th_seq);
    } else {
      proto_tree_add_uint(tcp_tree, hf_tcp_seq, tvb, offset + 4, 4, tcph->th_seq);
    }
  }

  if (tcph->th_hlen < TCPH_MIN_LEN) {
    /* Give up at this point; we put the source and destination port in
       the tree, before fetching the header length, so that they'll
       show up if this is in the failing packet in an ICMP error packet,
       but it's now time to give up if the header length is bogus. */
    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, ", bogus TCP header length (%u, must be at least %u)",
        tcph->th_hlen, TCPH_MIN_LEN);
    if (tree) {
      proto_tree_add_uint_format(tcp_tree, hf_tcp_hdr_len, tvb, offset + 12, 1, tcph->th_hlen,
       "Header length: %u bytes (bogus, must be at least %u)", tcph->th_hlen,
       TCPH_MIN_LEN);
    }
    return;
  }

  if (tree) {
    if (tcp_summary_in_tree) {
      if(tcph->th_flags&TH_ACK){
        proto_item_append_text(ti, ", Ack: %u", tcph->th_ack);
      }
      if (tcph->th_have_seglen)
        proto_item_append_text(ti, ", Len: %u", tcph->th_seglen);
    }
    proto_item_set_len(ti, tcph->th_hlen);
    if (tcph->th_have_seglen) {
      if (nxtseq != tcph->th_seq) {
        if(tcp_relative_seq){
          tf=proto_tree_add_uint_format(tcp_tree, hf_tcp_nxtseq, tvb, offset, 0, nxtseq, "Next sequence number: %u    (relative sequence number)", nxtseq);
        } else {
          tf=proto_tree_add_uint(tcp_tree, hf_tcp_nxtseq, tvb, offset, 0, nxtseq);
        }
        PROTO_ITEM_SET_GENERATED(tf);
      }
    }
    if (tcph->th_flags & TH_ACK) {
      if(tcp_relative_seq){
        proto_tree_add_uint_format(tcp_tree, hf_tcp_ack, tvb, offset + 8, 4, tcph->th_ack, "Acknowledgement number: %u    (relative ack number)", tcph->th_ack);
      } else {
        proto_tree_add_uint(tcp_tree, hf_tcp_ack, tvb, offset + 8, 4, tcph->th_ack);
      }
    }
    proto_tree_add_uint_format(tcp_tree, hf_tcp_hdr_len, tvb, offset + 12, 1, tcph->th_hlen,
	"Header length: %u bytes", tcph->th_hlen);
    tf = proto_tree_add_uint_format(tcp_tree, hf_tcp_flags, tvb, offset + 13, 1,
	tcph->th_flags, "Flags: 0x%04x (%s)", tcph->th_flags, flags);
    field_tree = proto_item_add_subtree(tf, ett_tcp_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_cwr, tvb, offset + 13, 1, tcph->th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_ecn, tvb, offset + 13, 1, tcph->th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_urg, tvb, offset + 13, 1, tcph->th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_ack, tvb, offset + 13, 1, tcph->th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_push, tvb, offset + 13, 1, tcph->th_flags);
    tf_rst = proto_tree_add_boolean(field_tree, hf_tcp_flags_reset, tvb, offset + 13, 1, tcph->th_flags);
    tf_syn = proto_tree_add_boolean(field_tree, hf_tcp_flags_syn, tvb, offset + 13, 1, tcph->th_flags);
    tf_fin = proto_tree_add_boolean(field_tree, hf_tcp_flags_fin, tvb, offset + 13, 1, tcph->th_flags);
    if(tcp_relative_seq && (tcph->th_win!=real_window)){
      proto_tree_add_uint_format(tcp_tree, hf_tcp_window_size, tvb, offset + 14, 2, tcph->th_win, "Window size: %u (scaled)", tcph->th_win);
    } else {
      proto_tree_add_uint(tcp_tree, hf_tcp_window_size, tvb, offset + 14, 2, tcph->th_win);
    }
  }

  if(tcph->th_flags & TH_SYN) {
    if(tcph->th_flags & TH_ACK)
      expert_add_info_format(pinfo, tf_syn, PI_SEQUENCE, PI_CHAT, "Connection establish acknowledge (SYN+ACK): %s -> %s",
                             get_tcp_port(tcph->th_sport), get_tcp_port(tcph->th_dport));
    else
      expert_add_info_format(pinfo, tf_syn, PI_SEQUENCE, PI_CHAT, "Connection establish request (SYN): %s -> %s",
                             get_tcp_port(tcph->th_sport), get_tcp_port(tcph->th_dport));
  }
  if(tcph->th_flags & TH_FIN)
    expert_add_info_format(pinfo, tf_fin, PI_SEQUENCE, PI_CHAT, "Connection finish (FIN): %s -> %s",
                           get_tcp_port(tcph->th_sport), get_tcp_port(tcph->th_dport));
  if(tcph->th_flags & TH_RST)
    expert_add_info_format(pinfo, tf_rst, PI_SEQUENCE, PI_CHAT, "Connection reset (RST): %s -> %s",
                           get_tcp_port(tcph->th_sport), get_tcp_port(tcph->th_dport));

  /* Supply the sequence number of the first byte and of the first byte
     after the segment. */
  tcpinfo.seq = tcph->th_seq;
  tcpinfo.nxtseq = nxtseq;

  /* Assume we'll pass un-reassembled data to subdissectors. */
  tcpinfo.is_reassembled = FALSE;

  pinfo->private_data = &tcpinfo;

  /*
   * Assume, initially, that we can't desegment.
   */
  pinfo->can_desegment = 0;
  th_sum = tvb_get_ntohs(tvb, offset + 16);
  if (!pinfo->fragmented && tvb_bytes_exist(tvb, 0, reported_len)) {
    /* The packet isn't part of an un-reassembled fragmented datagram
       and isn't truncated.  This means we have all the data, and thus
       can checksum it and, unless it's being returned in an error
       packet, are willing to allow subdissectors to request reassembly
       on it. */

    if (tcp_check_checksum) {
      /* We haven't turned checksum checking off; checksum it. */

      /* Set up the fields of the pseudo-header. */
      cksum_vec[0].ptr = pinfo->src.data;
      cksum_vec[0].len = pinfo->src.len;
      cksum_vec[1].ptr = pinfo->dst.data;
      cksum_vec[1].len = pinfo->dst.len;
      cksum_vec[2].ptr = (const guint8 *)&phdr;
      switch (pinfo->src.type) {

      case AT_IPv4:
        phdr[0] = g_htonl((IP_PROTO_TCP<<16) + reported_len);
        cksum_vec[2].len = 4;
        break;

      case AT_IPv6:
        phdr[0] = g_htonl(reported_len);
        phdr[1] = g_htonl(IP_PROTO_TCP);
        cksum_vec[2].len = 8;
        break;

      default:
        /* TCP runs only atop IPv4 and IPv6.... */
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
      }
      cksum_vec[3].ptr = tvb_get_ptr(tvb, offset, reported_len);
      cksum_vec[3].len = reported_len;
      computed_cksum = in_cksum(&cksum_vec[0], 4);
      if (computed_cksum == 0) {
        proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
          offset + 16, 2, th_sum, "Checksum: 0x%04x [correct]", th_sum);

        /* Checksum is valid, so we're willing to desegment it. */
        desegment_ok = TRUE;
      } else {
        proto_item *item;

        item = proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
           offset + 16, 2, th_sum,
	   "Checksum: 0x%04x [incorrect, should be 0x%04x]", th_sum,
	   in_cksum_shouldbe(th_sum, computed_cksum));
		expert_add_info_format(pinfo, item, PI_CHECKSUM, PI_ERROR, "Bad checksum");
        item = proto_tree_add_boolean(tcp_tree, hf_tcp_checksum_bad, tvb,
	   offset + 16, 2, TRUE);
        PROTO_ITEM_SET_GENERATED(item);
		/* XXX - don't use hidden fields for checksums */
        PROTO_ITEM_SET_HIDDEN(item);

        if (check_col(pinfo->cinfo, COL_INFO))
          col_append_fstr(pinfo->cinfo, COL_INFO, " [TCP CHECKSUM INCORRECT]");

        /* Checksum is invalid, so we're not willing to desegment it. */
        desegment_ok = FALSE;
        pinfo->noreassembly_reason = " [incorrect TCP checksum]";
      }
    } else {
      proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
         offset + 16, 2, th_sum, "Checksum: 0x%04x [validation disabled]", th_sum);

      /* We didn't check the checksum, and don't care if it's valid,
         so we're willing to desegment it. */
      desegment_ok = TRUE;
    }
  } else {
    /* We don't have all the packet data, so we can't checksum it... */
    proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
       offset + 16, 2, th_sum, "Checksum: 0x%04x [unchecked, not all data available]", th_sum);

    /* ...and aren't willing to desegment it. */
    desegment_ok = FALSE;
  }

  if (desegment_ok) {
    /* We're willing to desegment this.  Is desegmentation enabled? */
    if (tcp_desegment) {
      /* Yes - is this segment being returned in an error packet? */
      if (!pinfo->in_error_pkt) {
	/* No - indicate that we will desegment.
	   We do NOT want to desegment segments returned in error
	   packets, as they're not part of a TCP connection. */
	pinfo->can_desegment = 2;
      }
    }
  }

  if (tcph->th_flags & TH_URG) {
    th_urp = tvb_get_ntohs(tvb, offset + 18);
    /* Export the urgent pointer, for the benefit of protocols such as
       rlogin. */
    tcpinfo.urgent = TRUE;
    tcpinfo.urgent_pointer = th_urp;
    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, " Urg=%u", th_urp);
    if (tcp_tree != NULL)
      proto_tree_add_uint(tcp_tree, hf_tcp_urgent_pointer, tvb, offset + 18, 2, th_urp);
  } else
    tcpinfo.urgent = FALSE;

  if (tcph->th_have_seglen) {
    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, " Len=%u", tcph->th_seglen);
  }

  /* Decode TCP options, if any. */
  if (tcph->th_hlen > TCPH_MIN_LEN) {
    /* There's more than just the fixed-length header.  Decode the
       options. */
    optlen = tcph->th_hlen - TCPH_MIN_LEN; /* length of options, in bytes */
    tvb_ensure_bytes_exist(tvb, offset +  20, optlen);
    if (tcp_tree != NULL) {
      tf = proto_tree_add_text(tcp_tree, tvb, offset +  20, optlen,
        "Options: (%u bytes)", optlen);
      field_tree = proto_item_add_subtree(tf, ett_tcp_options);
    } else
      field_tree = NULL;
    dissect_ip_tcp_options(tvb, offset + 20, optlen,
      tcpopts, N_TCP_OPTS, TCPOPT_EOL, pinfo, field_tree);
  }

  /* If there was window scaling in the SYN packet byt none in the SYN+ACK
   * then we should just forget about the windowscaling completely.
   */
  if(!pinfo->fd->flags.visited){
    if(tcp_analyze_seq && tcp_relative_seq){
      if((tcph->th_flags & (TH_SYN|TH_ACK))==(TH_SYN|TH_ACK)) {
        verify_tcp_window_scaling(pinfo);
      }
    }
  }

  /* Skip over header + options */
  offset += tcph->th_hlen;

  /* Check the packet length to see if there's more data
     (it could be an ACK-only packet) */
  length_remaining = tvb_length_remaining(tvb, offset);

  if (tcph->th_have_seglen) {
    if( data_out_file ) {
      reassemble_tcp( tcph->th_seq,		/* sequence number */
          tcph->th_seglen,			/* data length */
          tvb_get_ptr(tvb, offset, length_remaining),	/* data */
          length_remaining,		/* captured data length */
          ( tcph->th_flags & TH_SYN ),		/* is syn set? */
          &pinfo->net_src,
          &pinfo->net_dst,
          pinfo->srcport,
          pinfo->destport);
    }
  }

  /* handle TCP seq# analysis, print any extra SEQ/ACK data for this segment*/
  if(tcp_analyze_seq){
      tcp_print_sequence_number_analysis(pinfo, tvb, tcp_tree);
  }
  tap_queue_packet(tcp_tap, pinfo, tcph);

  /*
   * XXX - what, if any, of this should we do if this is included in an
   * error packet?  It might be nice to see the details of the packet
   * that caused the ICMP error, but it might not be nice to have the
   * dissector update state based on it.
   * Also, we probably don't want to run TCP taps on those packets.
   */
  if (length_remaining != 0) {
    if (tcph->th_flags & TH_RST) {
      /*
       * RFC1122 says:
       *
       *	4.2.2.12  RST Segment: RFC-793 Section 3.4
       *
       *	  A TCP SHOULD allow a received RST segment to include data.
       *
       *	  DISCUSSION
       * 	       It has been suggested that a RST segment could contain
       * 	       ASCII text that encoded and explained the cause of the
       *	       RST.  No standard has yet been established for such
       *	       data.
       *
       * so for segments with RST we just display the data as text.
       */
      proto_tree_add_text(tcp_tree, tvb, offset, length_remaining,
			    "Reset cause: %s",
			    tvb_format_text(tvb, offset, length_remaining));
    } else {
      dissect_tcp_payload(tvb, pinfo, offset, tcph->th_seq, nxtseq,
                          tcph->th_sport, tcph->th_dport, tree, tcp_tree);
    }
  }
}

void
proto_register_tcp(void)
{
	static hf_register_info hf[] = {

		{ &hf_tcp_srcport,
		{ "Source Port",		"tcp.srcport", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_dstport,
		{ "Destination Port",		"tcp.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_port,
		{ "Source or Destination Port",	"tcp.port", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_seq,
		{ "Sequence number",		"tcp.seq", FT_UINT32, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_nxtseq,
		{ "Next sequence number",	"tcp.nxtseq", FT_UINT32, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_ack,
		{ "Acknowledgement number",	"tcp.ack", FT_UINT32, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_hdr_len,
		{ "Header Length",		"tcp.hdr_len", FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_flags,
		{ "Flags",			"tcp.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_flags_cwr,
		{ "Congestion Window Reduced (CWR)",			"tcp.flags.cwr", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_CWR,
			"", HFILL }},

		{ &hf_tcp_flags_ecn,
		{ "ECN-Echo",			"tcp.flags.ecn", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_ECN,
			"", HFILL }},

		{ &hf_tcp_flags_urg,
		{ "Urgent",			"tcp.flags.urg", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_URG,
			"", HFILL }},

		{ &hf_tcp_flags_ack,
		{ "Acknowledgment",		"tcp.flags.ack", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_ACK,
			"", HFILL }},

		{ &hf_tcp_flags_push,
		{ "Push",			"tcp.flags.push", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_PUSH,
			"", HFILL }},

		{ &hf_tcp_flags_reset,
		{ "Reset",			"tcp.flags.reset", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_RST,
			"", HFILL }},

		{ &hf_tcp_flags_syn,
		{ "Syn",			"tcp.flags.syn", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_SYN,
			"", HFILL }},

		{ &hf_tcp_flags_fin,
		{ "Fin",			"tcp.flags.fin", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_FIN,
			"", HFILL }},

		/* 32 bits so we can present some values adjusted to window scaling */
		{ &hf_tcp_window_size,
		{ "Window size",		"tcp.window_size", FT_UINT32, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_checksum,
		{ "Checksum",			"tcp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_checksum_bad,
		{ "Bad Checksum",		"tcp.checksum_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_analysis_flags,
		{ "TCP Analysis Flags",		"tcp.analysis.flags", FT_NONE, BASE_NONE, NULL, 0x0,
			"This frame has some of the TCP analysis flags set", HFILL }},

		{ &hf_tcp_analysis_retransmission,
		{ "Retransmission",		"tcp.analysis.retransmission", FT_NONE, BASE_NONE, NULL, 0x0,
			"This frame is a suspected TCP retransmission", HFILL }},

		{ &hf_tcp_analysis_fast_retransmission,
		{ "Fast Retransmission",		"tcp.analysis.fast_retransmission", FT_NONE, BASE_NONE, NULL, 0x0,
			"This frame is a suspected TCP fast retransmission", HFILL }},

		{ &hf_tcp_analysis_out_of_order,
		{ "Out Of Order",		"tcp.analysis.out_of_order", FT_NONE, BASE_NONE, NULL, 0x0,
			"This frame is a suspected Out-Of-Order segment", HFILL }},

		{ &hf_tcp_analysis_lost_packet,
		{ "Previous Segment Lost",		"tcp.analysis.lost_segment", FT_NONE, BASE_NONE, NULL, 0x0,
			"A segment before this one was lost from the capture", HFILL }},

		{ &hf_tcp_analysis_ack_lost_packet,
		{ "ACKed Lost Packet",		"tcp.analysis.ack_lost_segment", FT_NONE, BASE_NONE, NULL, 0x0,
			"This frame ACKs a lost segment", HFILL }},

		{ &hf_tcp_analysis_window_update,
		{ "Window update",		"tcp.analysis.window_update", FT_NONE, BASE_NONE, NULL, 0x0,
			"This frame is a tcp window update", HFILL }},

		{ &hf_tcp_analysis_window_full,
		{ "Window full",		"tcp.analysis.window_full", FT_NONE, BASE_NONE, NULL, 0x0,
			"This segment has caused the allowed window to become 100% full", HFILL }},

		{ &hf_tcp_analysis_keep_alive,
		{ "Keep Alive",		"tcp.analysis.keep_alive", FT_NONE, BASE_NONE, NULL, 0x0,
			"This is a keep-alive segment", HFILL }},

		{ &hf_tcp_analysis_keep_alive_ack,
		{ "Keep Alive ACK",		"tcp.analysis.keep_alive_ack", FT_NONE, BASE_NONE, NULL, 0x0,
			"This is an ACK to a keep-alive segment", HFILL }},

		{ &hf_tcp_analysis_duplicate_ack,
		{ "Duplicate ACK",		"tcp.analysis.duplicate_ack", FT_NONE, BASE_NONE, NULL, 0x0,
			"This is a duplicate ACK", HFILL }},

		{ &hf_tcp_analysis_duplicate_ack_num,
		{ "Duplicate ACK #",		"tcp.analysis.duplicate_ack_num", FT_UINT32, BASE_DEC, NULL, 0x0,
			"This is duplicate ACK number #", HFILL }},

		{ &hf_tcp_analysis_duplicate_ack_frame,
		{ "Duplicate to the ACK in frame",		"tcp.analysis.duplicate_ack_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"This is a duplicate to the ACK in frame #", HFILL }},

		{ &hf_tcp_continuation_to,
		{ "This is a continuation to the PDU in frame",		"tcp.continuation_to", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"This is a continuation to the PDU in frame #", HFILL }},

		{ &hf_tcp_analysis_zero_window_violation,
		{ "Zero Window Violation",		"tcp.analysis.zero_window_violation", FT_NONE, BASE_NONE, NULL, 0x0,
			"This is a zero-window violation, an attempt to write >1 byte to a zero-window", HFILL }},

		{ &hf_tcp_analysis_zero_window_probe,
		{ "Zero Window Probe",		"tcp.analysis.zero_window_probe", FT_NONE, BASE_NONE, NULL, 0x0,
			"This is a zero-window-probe", HFILL }},

		{ &hf_tcp_analysis_zero_window,
		{ "Zero Window",		"tcp.analysis.zero_window", FT_NONE, BASE_NONE, NULL, 0x0,
			"This is a zero-window", HFILL }},

		{ &hf_tcp_len,
		  { "TCP Segment Len",            "tcp.len", FT_UINT32, BASE_DEC, NULL, 0x0,
		    "", HFILL}},

		{ &hf_tcp_analysis_acks_frame,
		  { "This is an ACK to the segment in frame",            "tcp.analysis.acks_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "Which previous segment is this an ACK for", HFILL}},

		{ &hf_tcp_analysis_ack_rtt,
		  { "The RTT to ACK the segment was",            "tcp.analysis.ack_rtt", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		    "How long time it took to ACK the segment (RTT)", HFILL}},

		{ &hf_tcp_analysis_rto,
		  { "The RTO for this segment was",            "tcp.analysis.rto", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		    "How long transmission was delayed before this segment was retransmitted (RTO)", HFILL}},

		{ &hf_tcp_analysis_rto_frame,
		  { "RTO based on delta from frame", "tcp.analysis.rto_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"This is the frame we measure the RTO from", HFILL }},

		{ &hf_tcp_urgent_pointer,
		{ "Urgent pointer",		"tcp.urgent_pointer", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_segment_overlap,
		{ "Segment overlap",	"tcp.segment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Segment overlaps with other segments", HFILL }},

		{ &hf_tcp_segment_overlap_conflict,
		{ "Conflicting data in segment overlap",	"tcp.segment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Overlapping segments contained conflicting data", HFILL }},

		{ &hf_tcp_segment_multiple_tails,
		{ "Multiple tail segments found",	"tcp.segment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Several tails were found when reassembling the pdu", HFILL }},

		{ &hf_tcp_segment_too_long_fragment,
		{ "Segment too long",	"tcp.segment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Segment contained data past end of the pdu", HFILL }},

		{ &hf_tcp_segment_error,
		{ "Reassembling error", "tcp.segment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"Reassembling error due to illegal segments", HFILL }},

		{ &hf_tcp_segment,
		{ "TCP Segment", "tcp.segment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"TCP Segment", HFILL }},

		{ &hf_tcp_segments,
		{ "Reassembled TCP Segments", "tcp.segments", FT_NONE, BASE_NONE, NULL, 0x0,
			"TCP Segments", HFILL }},

		{ &hf_tcp_reassembled_in,
		{ "Reassembled PDU in frame", "tcp.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"The PDU that doesn't end in this segment is reassembled in this frame", HFILL }},

		{ &hf_tcp_option_mss,
		  { "TCP MSS Option", "tcp.options.mss", FT_BOOLEAN, 
		    BASE_NONE, NULL, 0x0, "TCP MSS Option", HFILL }},

		{ &hf_tcp_option_mss_val,
		  { "TCP MSS Option Value", "tcp.options.mss_val", FT_UINT16,
		    BASE_DEC, NULL, 0x0, "TCP MSS Option Value", HFILL}},

		{ &hf_tcp_option_wscale,
		  { "TCP Window Scale Option", "tcp.options.wscale", 
		    FT_BOOLEAN, 
		    BASE_NONE, NULL, 0x0, "TCP Window Option", HFILL}},

		{ &hf_tcp_option_wscale_val,
		  { "TCP Windows Scale Option Value", "tcp.options.wscale_val",
		    FT_UINT8, BASE_DEC, NULL, 0x0, "TCP Window Scale Value",
		    HFILL}},

		{ &hf_tcp_option_sack_perm, 
		  { "TCP Sack Perm Option", "tcp.options.sack_perm", 
		    FT_BOOLEAN,
		    BASE_NONE, NULL, 0x0, "TCP Sack Perm Option", HFILL}},

		{ &hf_tcp_option_sack,
		  { "TCP Sack Option", "tcp.options.sack", FT_BOOLEAN, 
		    BASE_NONE, NULL, 0x0, "TCP Sack Option", HFILL}},

		{ &hf_tcp_option_sack_sle,
		  {"TCP Sack Left Edge", "tcp.options.sack_le", FT_UINT32,
		   BASE_DEC, NULL, 0x0, "TCP Sack Left Edge", HFILL}},

		{ &hf_tcp_option_sack_sre,
		  {"TCP Sack Right Edge", "tcp.options.sack_re", FT_UINT32,
		   BASE_DEC, NULL, 0x0, "TCP Sack Right Edge", HFILL}},

		{ &hf_tcp_option_echo,
		  { "TCP Echo Option", "tcp.options.echo", FT_BOOLEAN, 
		    BASE_NONE, NULL, 0x0, "TCP Sack Echo", HFILL}},

		{ &hf_tcp_option_echo_reply,
		  { "TCP Echo Reply Option", "tcp.options.echo_reply", 
		    FT_BOOLEAN,
		    BASE_NONE, NULL, 0x0, "TCP Echo Reply Option", HFILL}},

		{ &hf_tcp_option_time_stamp,
		  { "TCP Time Stamp Option", "tcp.options.time_stamp", 
		    FT_BOOLEAN,
		    BASE_NONE, NULL, 0x0, "TCP Time Stamp Option", HFILL}},

		{ &hf_tcp_option_cc,
		  { "TCP CC Option", "tcp.options.cc", FT_BOOLEAN, BASE_NONE,
		    NULL, 0x0, "TCP CC Option", HFILL}},

		{ &hf_tcp_option_ccnew,
		  { "TCP CC New Option", "tcp.options.ccnew", FT_BOOLEAN, 
		    BASE_NONE, NULL, 0x0, "TCP CC New Option", HFILL}},

		{ &hf_tcp_option_ccecho,
		  { "TCP CC Echo Option", "tcp.options.ccecho", FT_BOOLEAN,
		    BASE_NONE, NULL, 0x0, "TCP CC Echo Option", HFILL}},

		{ &hf_tcp_option_md5,
		  { "TCP MD5 Option", "tcp.options.md5", FT_BOOLEAN, BASE_NONE,
		    NULL, 0x0, "TCP MD5 Option", HFILL}},

		{ &hf_tcp_pdu_time,
		  { "Time until the last segment of this PDU", "tcp.pdu.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		    "How long time has passed until the last frame of this PDU", HFILL}},
		{ &hf_tcp_pdu_last_frame,
		  { "Last frame of this PDU", "tcp.pdu.last_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"This is the last frame of the PDU starting in this segment", HFILL }},

	};
	static gint *ett[] = {
		&ett_tcp,
		&ett_tcp_flags,
		&ett_tcp_options,
		&ett_tcp_option_sack,
		&ett_tcp_analysis_faults,
		&ett_tcp_analysis,
		&ett_tcp_segments,
		&ett_tcp_segment
	};
	module_t *tcp_module;

	proto_tcp = proto_register_protocol("Transmission Control Protocol",
	    "TCP", "tcp");
	proto_register_field_array(proto_tcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	subdissector_table = register_dissector_table("tcp.port",
	    "TCP port", FT_UINT16, BASE_DEC);
	register_heur_dissector_list("tcp", &heur_subdissector_list);

	/* Register configuration preferences */
	tcp_module = prefs_register_protocol(proto_tcp, NULL);
	prefs_register_bool_preference(tcp_module, "summary_in_tree",
	    "Show TCP summary in protocol tree",
	    "Whether the TCP summary line should be shown in the protocol tree",
	    &tcp_summary_in_tree);
	prefs_register_bool_preference(tcp_module, "check_checksum",
	    "Validate the TCP checksum if possible",
	    "Whether to validate the TCP checksum",
	    &tcp_check_checksum);
	prefs_register_bool_preference(tcp_module, "desegment_tcp_streams",
	    "Allow subdissector to reassemble TCP streams",
	    "Whether subdissector can request TCP streams to be reassembled",
	    &tcp_desegment);
	prefs_register_bool_preference(tcp_module, "analyze_sequence_numbers",
	    "Analyze TCP sequence numbers",
	    "Make the TCP dissector analyze TCP sequence numbers to find and flag segment retransmissions, missing segments and RTT",
	    &tcp_analyze_seq);
	prefs_register_bool_preference(tcp_module, "relative_sequence_numbers",
	    "Relative sequence numbers and window scaling",
	    "Make the TCP dissector use relative sequence numbers instead of absolute ones. "
	    "To use this option you must also enable \"Analyze TCP sequence numbers\". "
	    "This option will also try to track and adjust the window field according to any TCP window scaling options seen.",
	    &tcp_relative_seq);
	prefs_register_bool_preference(tcp_module, "try_heuristic_first",
	    "Try heuristic sub-dissectors first",
	    "Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port",
	    &try_heuristic_first);

	register_init_routine(tcp_analyze_seq_init);
	register_init_routine(tcp_desegment_init);
	register_init_routine(tcp_fragment_init);
}

void
proto_reg_handoff_tcp(void)
{
	dissector_handle_t tcp_handle;

	tcp_handle = create_dissector_handle(dissect_tcp, proto_tcp);
	dissector_add("ip.proto", IP_PROTO_TCP, tcp_handle);
	data_handle = find_dissector("data");
	tcp_tap = register_tap("tcp");
}
