/* packet-tcp.c
 * Routines for TCP packet disassembly
 *
 * $Id: packet-tcp.c,v 1.125 2002/01/17 09:28:22 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "in_cksum.h"

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "resolv.h"
#include "ipproto.h"
#include "follow.h"
#include "prefs.h"
#include "packet-tcp.h"
#include "packet-ip.h"
#include "conversation.h"
#include "strutil.h"
#include "reassemble.h"

/* Place TCP summary in proto tree */
static gboolean tcp_summary_in_tree = TRUE;

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
static int hf_tcp_urgent_pointer = -1;

static gint ett_tcp = -1;
static gint ett_tcp_flags = -1;
static gint ett_tcp_options = -1;
static gint ett_tcp_option_sack = -1;
static gint ett_tcp_segments = -1;

static dissector_table_t subdissector_table;
static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t data_handle;

/* TCP structs and definitions */

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECN  0x40
#define TH_CWR  0x80

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
static gboolean tcp_desegment = FALSE;

static GHashTable *tcp_segment_table = NULL;
static GMemChunk *tcp_segment_key_chunk = NULL;
static int tcp_segment_init_count = 200;
static GMemChunk *tcp_segment_address_chunk = NULL;
static int tcp_segment_address_init_count = 500;

typedef struct _tcp_segment_key {
	/* for ouwn bookkeeping inside packet-tcp.c */
	address *src;
	address *dst;
	guint32 seq;
	/* xxx */
	guint32 start_seq;
	guint32 tot_len;
	guint32 first_frame;
} tcp_segment_key;

static gboolean
free_all_segments(gpointer key_arg, gpointer value, gpointer user_data)
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
	tcp_segment_key *key = (tcp_segment_key *)k;

	return key->seq;
}

static gint
tcp_segment_equal(gconstpointer k1, gconstpointer k2)
{
	tcp_segment_key *key1 = (tcp_segment_key *)k1;
	tcp_segment_key *key2 = (tcp_segment_key *)k2;

	return ( ( (key1->seq==key2->seq)
		 &&(ADDRESSES_EQUAL(key1->src, key2->src))
		 &&(ADDRESSES_EQUAL(key1->dst, key2->dst))
		 ) ? TRUE:FALSE);
}

static void
tcp_desegment_init(void)
{

	/* dont allocate any memory chunks unless the user really
	   uses this option
	*/
	if(!tcp_desegment){
		return;
	}

	if(tcp_segment_table){
		g_hash_table_foreach_remove(tcp_segment_table,
			free_all_segments, NULL);
	} else {
		tcp_segment_table = g_hash_table_new(tcp_segment_hash,
			tcp_segment_equal);
	}

	if(tcp_segment_key_chunk){
		g_mem_chunk_destroy(tcp_segment_key_chunk);
	}
	tcp_segment_key_chunk = g_mem_chunk_new("tcp_segment_key_chunk",
		sizeof(tcp_segment_key),
		tcp_segment_init_count*sizeof(tcp_segment_key),
		G_ALLOC_ONLY);

	if(tcp_segment_address_chunk){
		g_mem_chunk_destroy(tcp_segment_address_chunk);
	}
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
	fragment_data *ipfd_head;
	tcp_segment_key old_tsk, *tsk;
	gboolean must_desegment = FALSE;
	gboolean called_dissector = FALSE;
	int deseg_offset;
	guint32 deseg_seq;

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
	old_tsk.seq = seq;
	tsk = g_hash_table_lookup(tcp_segment_table, &old_tsk);

	if(tsk){
		/* OK, this segment was found, which means it continues
		   a higher-level PDU. This means we must desegment it.
		   Add it to the defragmentation lists.
		*/
		ipfd_head = fragment_add(tvb, offset, pinfo, tsk->start_seq,
			tcp_fragment_table,
			seq - tsk->start_seq,
			nxtseq - seq,
			(nxtseq < (tsk->start_seq + tsk->tot_len)) );

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
		decode_tcp_ports(tvb, offset, pinfo, tree, 
				sport, dport);
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
		proto_tree *st = NULL;
		proto_item *si = NULL;

		/* first we show a tree with all segments */
		si = proto_tree_add_text(tcp_tree, tvb, 0, 0,
				"Segments");
		st = proto_item_add_subtree(si, ett_tcp_segments);
		for(ipfd=ipfd_head->next; ipfd; ipfd=ipfd->next){
			proto_tree_add_text(st, tvb, 0, 0,
				"Frame:%u  seq#:%u-%u [%u-%u]",
				ipfd->frame,
				tsk->start_seq + ipfd->offset,
				tsk->start_seq + ipfd->offset + ipfd->len - 1,
				ipfd->offset,
				ipfd->offset + ipfd->len - 1); 
		}

		/*
		 * We only call subdissector for the last segment.
		 * Note that the last segment may include more than what
		 * we needed.
		 */
		if(nxtseq >= (tsk->start_seq + tsk->tot_len)){
			/* ok, lest call subdissector with desegmented data */
			tvbuff_t *next_tvb;

			/* create a new TVB structure for desegmented data */
			next_tvb = tvb_new_real_data(ipfd_head->data,
					ipfd_head->datalen, ipfd_head->datalen,
					"Desegmented");

			/* add this tvb as a child to the original one */
			tvb_set_child_real_data_tvbuff(tvb, next_tvb);

			/* add desegmented data to the data source list */
			pinfo->fd->data_src = g_slist_append(pinfo->fd->data_src, next_tvb);

			/* indicate that this is reassembled data */
			tcpinfo->is_reassembled = TRUE;

			/* call subdissector */
			decode_tcp_ports(next_tvb, 0, pinfo, tree,
				sport, dport);
			called_dissector = TRUE;

			/* Did the subdissector ask us to desegment some more
			   data?  This means that the data at the beginning
			   of this segment completed a higher-level PDU,
			   but the data at the end of this segment started
			   a higher-level PDU but didn't complete it.

			   If so we have to create some structures in our
			   table but this is something we only do the first
			   time we see this packet.
			*/
			if(pinfo->desegment_len) {
				if (!pinfo->fd->flags.visited)
					must_desegment = TRUE;

				/*
				 * The stuff we couldn't dissect must have
				 * come from this segment, so it's all in
				 * "tvb".
				 *
				 * "pinfo->desegment_offset" is relative
				 * to the beginning of "next_tvb";
				 * we want an offset relative to the
				 * beginning of "tvb".
				 *
				 * First, compute the offset relative to
				 * the *end* of "next_tvb" - i.e., the number
				 * of bytes before the end of "next_tvb"
				 * at which the subdissector stopped.
				 * That's the length of "next_tvb" minus
				 * the offset, relative to the beginning
				 * of "next_tvb, at which the subdissector
				 * stopped.
				 */
				deseg_offset =
				    ipfd_head->datalen - pinfo->desegment_offset;

				/*
				 * "tvb" and "next_tvb" end at the same byte
				 * of data, so the offset relative to the
				 * end of "next_tvb" of the byte at which
				 * we stopped is also the offset relative
				 * to the end of "tvb" of the byte at which
				 * we stopped.
				 *
				 * Convert that back into an offset relative
				 * to the beginninng of "tvb", by taking
				 * the length of "tvb" and subtracting the
				 * offset relative to the end.
				 */
				deseg_offset = tvb_length(tvb) - deseg_offset;
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
		g_hash_table_insert(tcp_segment_table, tsk, tsk);

		/* Add portion of segment unprocessed by the subdissector
		   to defragmentation lists */
		fragment_add(tvb, deseg_offset, pinfo, tsk->start_seq,
		    tcp_fragment_table,
		    tsk->seq - tsk->start_seq,
		    nxtseq - tsk->start_seq,
		    (nxtseq < tsk->start_seq + tsk->tot_len));

		/* this is the next segment in the sequence we want */
		new_tsk = g_mem_chunk_alloc(tcp_segment_key_chunk);
		memcpy(new_tsk, tsk, sizeof(tcp_segment_key));
		new_tsk->seq = nxtseq;
		g_hash_table_insert(tcp_segment_table,new_tsk,new_tsk);
	    }
	}

	if (!called_dissector || pinfo->desegment_len != 0) {
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
				col_set_str(pinfo->cinfo, COL_INFO, "[Desegmented TCP]");
			}
		}

		/*
		 * Show what's left in the packet as data.
		 * XXX - remember what protocol the last subdissector
		 * was, and report it as a continuation of that, instead.
		 */
		call_dissector(data_handle,tvb_new_subset(tvb, deseg_offset,-1,tvb_reported_length_remaining(tvb,deseg_offset)), pinfo, tree);
	}
	pinfo->can_desegment=0;
	pinfo->desegment_offset = 0;
	pinfo->desegment_len = 0;
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
  proto_tree_add_text(opt_tree, tvb, offset,      optlen,
			"%s: %u bytes", optp->name, mss);
  tcp_info_append_uint(pinfo, "MSS", mss);
}

static void
dissect_tcpopt_wscale(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
  guint8 ws;

  ws = tvb_get_guint8(tvb, offset + 2);
  proto_tree_add_text(opt_tree, tvb, offset,      optlen,
			"%s: %u bytes", optp->name, ws);
  tcp_info_append_uint(pinfo, "WS", ws);
}

static void
dissect_tcpopt_sack(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
  proto_tree *field_tree = NULL;
  proto_item *tf;
  guint leftedge, rightedge;

  tf = proto_tree_add_text(opt_tree, tvb, offset,      optlen, "%s:", optp->name);
  offset += 2;	/* skip past type and length */
  optlen -= 2;	/* subtract size of type and length */
  while (optlen > 0) {
    if (field_tree == NULL) {
      /* Haven't yet made a subtree out of this option.  Do so. */
      field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    }
    if (optlen < 4) {
      proto_tree_add_text(field_tree, tvb, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }
    leftedge = tvb_get_ntohl(tvb, offset);
    optlen -= 4;
    if (optlen < 4) {
      proto_tree_add_text(field_tree, tvb, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }
    /* XXX - check whether it goes past end of packet */
    rightedge = tvb_get_ntohl(tvb, offset + 4);
    optlen -= 4;
    proto_tree_add_text(field_tree, tvb, offset,      8,
        "left edge = %u, right edge = %u", leftedge, rightedge);
    tcp_info_append_uint(pinfo, "SLE", leftedge);
    tcp_info_append_uint(pinfo, "SRE", rightedge);
    offset += 8;
  }
}

static void
dissect_tcpopt_echo(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
  guint32 echo;

  echo = tvb_get_ntohl(tvb, offset + 2);
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

/* TCP flags flag */
static const true_false_string flags_set_truth = {
  "Set",
  "Not set"
};


/* Determine if there is a sub-dissector and call it.  This has been */
/* separated into a stand alone routine to other protocol dissectors */
/* can call to it, ie. socks	*/

void
decode_tcp_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, int src_port, int dst_port)
{
  tvbuff_t *next_tvb;

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);

/* determine if this packet is part of a conversation and call dissector */
/* for the conversation if available */

  if (try_conversation_dissector(&pinfo->src, &pinfo->dst, PT_TCP,
		src_port, dst_port, next_tvb, pinfo, tree))
    return;

  /* do lookup with the subdissector table */
  if (dissector_try_port(subdissector_table, src_port, next_tvb, pinfo, tree) ||
      dissector_try_port(subdissector_table, dst_port, next_tvb, pinfo, tree))
    return;

  /* do lookup with the heuristic subdissector table */
  if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree))
    return;

  /* Oh, well, we don't know this; dissect it as data. */
  call_dissector(data_handle,next_tvb, pinfo, tree);
}


static void
dissect_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint16 th_sport;
  guint16 th_dport;
  guint32 th_seq;
  guint32 th_ack;
  guint8  th_off_x2; /* combines th_off and th_x2 */
  guint8  th_flags;
  guint16 th_win;
  guint16 th_sum;
  guint16 th_urp;
  proto_tree *tcp_tree = NULL, *field_tree = NULL;
  proto_item *ti = NULL, *tf;
  int        offset = 0;
  gchar      flags[64] = "<None>";
  gchar     *fstr[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECN", "CWR" };
  gint       fpos = 0, i;
  guint      bpos;
  guint      hlen;
  guint      optlen;
  guint32    seglen;
  guint32    nxtseq;
  guint      len;
  guint      reported_len;
  vec_t      cksum_vec[4];
  guint32    phdr[2];
  guint16    computed_cksum;
  guint      length_remaining;
  struct tcpinfo tcpinfo;
  gboolean   save_fragmented;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCP");

  /* Clear out the Info column. */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  th_sport = tvb_get_ntohs(tvb, offset);
  th_dport = tvb_get_ntohs(tvb, offset + 2);
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s > %s",
      get_tcp_port(th_sport), get_tcp_port(th_dport));
  }
  
  if (tree) {
    if (tcp_summary_in_tree) {
	    ti = proto_tree_add_protocol_format(tree, proto_tcp, tvb, 0,
		tvb_length(tvb),
		"Transmission Control Protocol, Src Port: %s (%u), Dst Port: %s (%u)",
		get_tcp_port(th_sport), th_sport,
		get_tcp_port(th_dport), th_dport);
    }
    else {
	    ti = proto_tree_add_item(tree, proto_tcp, tvb, 0,
		tvb_length(tvb), FALSE);
    }
    tcp_tree = proto_item_add_subtree(ti, ett_tcp);
    proto_tree_add_uint_format(tcp_tree, hf_tcp_srcport, tvb, offset, 2, th_sport,
	"Source port: %s (%u)", get_tcp_port(th_sport), th_sport);
    proto_tree_add_uint_format(tcp_tree, hf_tcp_dstport, tvb, offset + 2, 2, th_dport,
	"Destination port: %s (%u)", get_tcp_port(th_dport), th_dport);
    proto_tree_add_uint_hidden(tcp_tree, hf_tcp_port, tvb, offset, 2, th_sport);
    proto_tree_add_uint_hidden(tcp_tree, hf_tcp_port, tvb, offset + 2, 2, th_dport);
  }

  th_seq = tvb_get_ntohl(tvb, offset + 4);
  th_ack = tvb_get_ntohl(tvb, offset + 8);
  th_off_x2 = tvb_get_guint8(tvb, offset + 12);
  th_flags = tvb_get_guint8(tvb, offset + 13);
  th_win = tvb_get_ntohs(tvb, offset + 14);
  
  if (check_col(pinfo->cinfo, COL_INFO) || tree) {  
    for (i = 0; i < 8; i++) {
      bpos = 1 << i;
      if (th_flags & bpos) {
        if (fpos) {
          strcpy(&flags[fpos], ", ");
          fpos += 2;
        }
        strcpy(&flags[fpos], fstr[i]);
        fpos += 3;
      }
    }
    flags[fpos] = '\0';
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, " [%s] Seq=%u Ack=%u Win=%u",
      flags, th_seq, th_ack, th_win);
  }

  if (tree) {
    if (tcp_summary_in_tree)
      proto_item_append_text(ti, ", Seq: %u", th_seq);
    proto_tree_add_uint(tcp_tree, hf_tcp_seq, tvb, offset + 4, 4, th_seq);
  }

  hlen = hi_nibble(th_off_x2) * 4;  /* TCP header length, in bytes */

  if (hlen < TCPH_MIN_LEN) {
    /* Give up at this point; we put the source and destination port in
       the tree, before fetching the header length, so that they'll
       show up if this is in the failing packet in an ICMP error packet,
       but it's now time to give up if the header length is bogus. */
    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, ", bogus TCP header length (%u, must be at least %u)",
        hlen, TCPH_MIN_LEN);
    if (tree) {
      proto_tree_add_uint_format(tcp_tree, hf_tcp_hdr_len, tvb, offset + 12, 1, hlen,
       "Header length: %u bytes (bogus, must be at least %u)", hlen,
       TCPH_MIN_LEN);
    }
    return;
  }

  reported_len = tvb_reported_length(tvb);
  len = tvb_length(tvb);

  /* Compute the length of data in this segment. */
  seglen = reported_len - hlen;

  /* Compute the sequence number of next octet after this segment. */
  nxtseq = th_seq + seglen;

  if (tree) {
    if (tcp_summary_in_tree)
      proto_item_append_text(ti, ", Ack: %u", th_ack);
    proto_item_set_len(ti, hlen);
    if (nxtseq != th_seq)
      proto_tree_add_uint(tcp_tree, hf_tcp_nxtseq, tvb, offset, 0, nxtseq);
    if (th_flags & TH_ACK)
      proto_tree_add_uint(tcp_tree, hf_tcp_ack, tvb, offset + 8, 4, th_ack);
    proto_tree_add_uint_format(tcp_tree, hf_tcp_hdr_len, tvb, offset + 12, 1, hlen,
	"Header length: %u bytes", hlen);
    tf = proto_tree_add_uint_format(tcp_tree, hf_tcp_flags, tvb, offset + 13, 1,
	th_flags, "Flags: 0x%04x (%s)", th_flags, flags);
    field_tree = proto_item_add_subtree(tf, ett_tcp_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_cwr, tvb, offset + 13, 1, th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_ecn, tvb, offset + 13, 1, th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_urg, tvb, offset + 13, 1, th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_ack, tvb, offset + 13, 1, th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_push, tvb, offset + 13, 1, th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_reset, tvb, offset + 13, 1, th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_syn, tvb, offset + 13, 1, th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_fin, tvb, offset + 13, 1, th_flags);
    proto_tree_add_uint(tcp_tree, hf_tcp_window_size, tvb, offset + 14, 2, th_win);
  }

  /* Assume we'll pass un-reassembled data to subdissectors. */
  tcpinfo.is_reassembled = FALSE;

  pinfo->private_data = &tcpinfo;

  /*
   * Assume, initially, that we can't desegment.
   */
  pinfo->can_desegment = 0;

  th_sum = tvb_get_ntohs(tvb, offset + 16);
  if (!pinfo->fragmented && len >= reported_len) {
    /* The packet isn't part of a fragmented datagram, isn't being
       returned inside an ICMP error packet, and isn't truncated, so we
       can checksum it.
       XXX - make a bigger scatter-gather list once we do fragment
       reassembly? */

    /* Set up the fields of the pseudo-header. */
    cksum_vec[0].ptr = pinfo->src.data;
    cksum_vec[0].len = pinfo->src.len;
    cksum_vec[1].ptr = pinfo->dst.data;
    cksum_vec[1].len = pinfo->dst.len;
    cksum_vec[2].ptr = (const guint8 *)&phdr;
    switch (pinfo->src.type) {

    case AT_IPv4:
	phdr[0] = htonl((IP_PROTO_TCP<<16) + reported_len);
	cksum_vec[2].len = 4;
	break;

    case AT_IPv6:
        phdr[0] = htonl(reported_len);
        phdr[1] = htonl(IP_PROTO_TCP);
        cksum_vec[2].len = 8;
        break;

    default:
        /* TCP runs only atop IPv4 and IPv6.... */
        g_assert_not_reached();
        break;
    }
    cksum_vec[3].ptr = tvb_get_ptr(tvb, offset, len);
    cksum_vec[3].len = reported_len;
    computed_cksum = in_cksum(&cksum_vec[0], 4);
    if (computed_cksum == 0) {
      /*
       * We have all the data for this TCP segment, and the checksum of
       * the header and the data is good, so we can desegment it.
       * Is desegmentation enabled?
       */
      if (tcp_desegment) {
	/* Yes - is this segment being returned in an error packet? */
	if (!pinfo->in_error_pkt) {
	  /* No - indicate that we will desegment.
	     We do NOT want to desegment segments returned in error
	     packets, as they're not part of a TCP connection. */
	  pinfo->can_desegment = 2;
	}
      }
      proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
         offset + 16, 2, th_sum, "Checksum: 0x%04x (correct)", th_sum);
    } else {
      proto_tree_add_boolean_hidden(tcp_tree, hf_tcp_checksum_bad, tvb,
	   offset + 16, 2, TRUE);
      proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
           offset + 16, 2, th_sum,
	   "Checksum: 0x%04x (incorrect, should be 0x%04x)", th_sum,
	   in_cksum_shouldbe(th_sum, computed_cksum));
    }
  } else {
    proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
       offset + 16, 2, th_sum, "Checksum: 0x%04x", th_sum);
  }
  if (th_flags & TH_URG) {
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

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, " Len=%u", seglen);

  /* Decode TCP options, if any. */
  if (tree && hlen > TCPH_MIN_LEN) {
    /* There's more than just the fixed-length header.  Decode the
       options. */
    optlen = hlen - TCPH_MIN_LEN; /* length of options, in bytes */
    tf = proto_tree_add_text(tcp_tree, tvb, offset +  20, optlen,
      "Options: (%u bytes)", optlen);
    field_tree = proto_item_add_subtree(tf, ett_tcp_options);
    dissect_ip_tcp_options(tvb, offset + 20, optlen,
      tcpopts, N_TCP_OPTS, TCPOPT_EOL, pinfo, field_tree);
  }

  /* Skip over header + options */
  offset += hlen;

  pinfo->ptype = PT_TCP;
  pinfo->srcport = th_sport;
  pinfo->destport = th_dport;
  
  /* Check the packet length to see if there's more data
     (it could be an ACK-only packet) */
  length_remaining = tvb_length_remaining(tvb, offset);
  if (length_remaining != 0) {
    if (th_flags & TH_RST) {
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
      /* Can we desegment this segment? */
      if (pinfo->can_desegment) {
        /* Yes. */
        desegment_tcp(tvb, pinfo, offset, th_seq, nxtseq, th_sport, th_dport, tree, tcp_tree);
      } else {
        /* No - just call the subdissector.
           Mark this as fragmented, so if somebody throws an exception,
           we don't report it as a malformed frame. */
        save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;
        decode_tcp_ports(tvb, offset, pinfo, tree, th_sport, th_dport);
        pinfo->fragmented = save_fragmented;
      }
    }
  }
 
  if( data_out_file ) {
    reassemble_tcp( th_seq,		/* sequence number */
        seglen,				/* data length */
        tvb_get_ptr(tvb, offset, length_remaining),	/* data */
        length_remaining,		/* captured data length */
        ( th_flags & TH_SYN ),		/* is syn set? */
        &pinfo->net_src,
	&pinfo->net_dst,
	pinfo->srcport,
	pinfo->destport);
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

		{ &hf_tcp_window_size,
		{ "Window size",		"tcp.window_size", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_checksum,
		{ "Checksum",			"tcp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_checksum_bad,
		{ "Bad Checksum",		"tcp.checksum_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_tcp_urgent_pointer,
		{ "Urgent pointer",		"tcp.urgent_pointer", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},
	};
	static gint *ett[] = {
		&ett_tcp,
		&ett_tcp_flags,
		&ett_tcp_options,
		&ett_tcp_option_sack,
		&ett_tcp_segments,
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
	prefs_register_bool_preference(tcp_module, "tcp_summary_in_tree",
	    "Show TCP summary in protocol tree",
"Whether the TCP summary line should be shown in the protocol tree",
	    &tcp_summary_in_tree);
	prefs_register_bool_preference(tcp_module, "desegment_tcp_streams",
	    "Allow subdissector to desegment TCP streams",
"Whether subdissector can request TCP streams to be desegmented",
	    &tcp_desegment);

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
}
