/* packet-t38.c
 * Routines for T.38 packet dissection
 * 2003  Hans Viens
 * 2004  Alejandro Vaquero, add support Conversations for SDP
 * 2006  Alejandro Vaquero, add T30 reassemble and dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/* Depending on what ASN.1 specification is used you may have to change
 * the preference setting regarding Pre-Corrigendum ASN.1 specification:
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/1998/T38.html  (Pre-Corrigendum=TRUE)
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/2003/T38(1998).html (Pre-Corrigendum=TRUE)
 *
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/2003/T38(2002).html (Pre-Corrigendum=FALSE)
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/2002/t38.html  (Pre-Corrigendum=FALSE)
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/2002-Amd1/T38.html (Pre-Corrigendum=FALSE)
 */

/* TO DO:
 * - TCP desegmentation is currently not supported for T.38 IFP directly over TCP.
 * - H.245 dissectors should be updated to start conversations for T.38 similar to RTP.
 * - Sometimes the last octet is not high-lighted when selecting something in the tree. Bug in PER dissector?
 * - Add support for RTP payload audio/t38 (draft-jones-avt-audio-t38-03.txt), i.e. T38 in RTP packets.
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/ipproto.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>

#include "packet-t38.h"
#include "packet-per.h"
#include "packet-tpkt.h"
#include "packet-acdr.h"

void proto_register_t38(void);

static int t38_tap = -1;

/* dissect using the Pre Corrigendum T.38 ASN.1 specification (1998) */
static gboolean use_pre_corrigendum_asn1_specification = TRUE;

/* dissect packets that looks like RTP version 2 packets as RTP     */
/* instead of as T.38. This may result in that some T.38 UPTL       */
/* packets with sequence number values higher than 32767 may be     */
/* shown as RTP packets.                                            */
static gboolean dissect_possible_rtpv2_packets_as_rtp = FALSE;


/* Reassembly of T.38 PDUs over TPKT over TCP */
static gboolean t38_tpkt_reassembly = TRUE;

/* Preference setting whether TPKT header is used when sending T.38 over TCP.
 * The default setting is Maybe where the dissector will look on the first
 * bytes to try to determine whether TPKT header is used or not. This may not
 * work so well in some cases. You may want to change the setting to Always or
 * Newer.
 */
#define T38_TPKT_NEVER 0   /* Assume that there is never a TPKT header    */
#define T38_TPKT_ALWAYS 1  /* Assume that there is always a TPKT header   */
#define T38_TPKT_MAYBE 2   /* Assume TPKT if first octets are 03-00-xx-xx */
static gint t38_tpkt_usage = T38_TPKT_MAYBE;

static const enum_val_t t38_tpkt_options[] = {
  {"never", "Never", T38_TPKT_NEVER},
  {"always", "Always", T38_TPKT_ALWAYS},
  {"maybe", "Maybe", T38_TPKT_MAYBE},
  {NULL, NULL, -1}
};



/* T38 */
static dissector_handle_t t38_udp_handle;
static dissector_handle_t t38_tcp_handle;
static dissector_handle_t t38_tcp_pdu_handle;
static dissector_handle_t rtp_handle;
static dissector_handle_t t30_hdlc_handle;
static dissector_handle_t data_handle;

static gint32 Type_of_msg_value;
static guint32 Data_Field_field_type_value;
static guint32 Data_value;
static guint32 T30ind_value;
static guint32 Data_Field_item_num;

static int proto_t38 = -1;
static int proto_acdr = -1;
#include "packet-t38-hf.c"

/* T38 setup fields */
static int hf_t38_setup        = -1;
static int hf_t38_setup_frame  = -1;
static int hf_t38_setup_method = -1;

/* T38 Data reassemble fields */
static int hf_t38_fragments = -1;
static int hf_t38_fragment = -1;
static int hf_t38_fragment_overlap = -1;
static int hf_t38_fragment_overlap_conflicts = -1;
static int hf_t38_fragment_multiple_tails = -1;
static int hf_t38_fragment_too_long_fragment = -1;
static int hf_t38_fragment_error = -1;
static int hf_t38_fragment_count = -1;
static int hf_t38_reassembled_in = -1;
static int hf_t38_reassembled_length = -1;

static gint ett_t38 = -1;
#include "packet-t38-ett.c"
static gint ett_t38_setup = -1;

static gint ett_data_fragment = -1;
static gint ett_data_fragments = -1;

static expert_field ei_t38_malformed = EI_INIT;

static gboolean primary_part = TRUE;
static guint32 seq_number = 0;

/* Tables for reassembly of Data fragments. */
static reassembly_table data_reassembly_table;

static const fragment_items data_frag_items = {
	/* Fragment subtrees */
	&ett_data_fragment,
	&ett_data_fragments,
	/* Fragment fields */
	&hf_t38_fragments,
	&hf_t38_fragment,
	&hf_t38_fragment_overlap,
	&hf_t38_fragment_overlap_conflicts,
	&hf_t38_fragment_multiple_tails,
	&hf_t38_fragment_too_long_fragment,
	&hf_t38_fragment_error,
	&hf_t38_fragment_count,
	/* Reassembled in field */
	&hf_t38_reassembled_in,
	/* Reassembled length field */
	&hf_t38_reassembled_length,
	/* Reassembled data field */
	NULL,
	/* Tag */
	"Data fragments"
};

typedef struct _fragment_key {
	address src;
	address dst;
	guint32	id;
} fragment_key;

static conversation_t *p_conv= NULL;
static t38_conv *p_t38_conv = NULL;
static t38_conv *p_t38_packet_conv = NULL;
static t38_conv_info *p_t38_conv_info = NULL;
static t38_conv_info *p_t38_packet_conv_info = NULL;

/* RTP Version is the first 2 bits of the first octet in the UDP payload*/
#define RTP_VERSION(octet)	((octet) >> 6)

void proto_reg_handoff_t38(void);

static void show_setup_info(tvbuff_t *tvb, proto_tree *tree, t38_conv *p_t38_conv);
/* Preferences bool to control whether or not setup info should be shown */
static gboolean global_t38_show_setup_info = TRUE;

/* Can tap up to 4 T38 packets within same packet */
/* We only tap the primary part, not the redundancy */
#define MAX_T38_MESSAGES_IN_PACKET 4
static t38_packet_info t38_info_arr[MAX_T38_MESSAGES_IN_PACKET];
static int t38_info_current=0;
static t38_packet_info *t38_info=NULL;


/* Set up an T38 conversation */
void t38_add_address(packet_info *pinfo,
                     address *addr, int port,
                     int other_port,
                     const gchar *setup_method, guint32 setup_frame_number)
{
        address null_addr;
        conversation_t* p_conversation;
        t38_conv* p_conversation_data = NULL;

        /*
         * If this isn't the first time this packet has been processed,
         * we've already done this work, so we don't need to do it
         * again.
         */
        if ((pinfo->fd->visited) || (t38_udp_handle == NULL))
        {
                return;
        }

        clear_address(&null_addr);

        /*
         * Check if the ip address and port combination is not
         * already registered as a conversation.
         */
        p_conversation = find_conversation( setup_frame_number, addr, &null_addr, ENDPOINT_UDP, port, other_port,
                                NO_ADDR_B | (!other_port ? NO_PORT_B : 0));

        /*
         * If not, create a new conversation.
         */
        if ( !p_conversation || p_conversation->setup_frame != setup_frame_number) {
                p_conversation = conversation_new( setup_frame_number, addr, &null_addr, ENDPOINT_UDP,
                                           (guint32)port, (guint32)other_port,
                                                                   NO_ADDR2 | (!other_port ? NO_PORT2 : 0));
        }

        /* Set dissector */
        conversation_set_dissector(p_conversation, t38_udp_handle);

        /*
         * Check if the conversation has data associated with it.
         */
        p_conversation_data = (t38_conv*)conversation_get_proto_data(p_conversation, proto_t38);

        /*
         * If not, add a new data item.
         */
        if ( ! p_conversation_data ) {
                /* Create conversation data */
                p_conversation_data = wmem_new(wmem_file_scope(), t38_conv);

                conversation_add_proto_data(p_conversation, proto_t38, p_conversation_data);
        }

        /*
         * Update the conversation data.
         */
        (void) g_strlcpy(p_conversation_data->setup_method, setup_method, MAX_T38_SETUP_METHOD_SIZE);
        p_conversation_data->setup_frame_number = setup_frame_number;
        p_conversation_data->src_t38_info.reass_ID = 0;
        p_conversation_data->src_t38_info.reass_start_seqnum = -1;
        p_conversation_data->src_t38_info.reass_data_type = 0;
        p_conversation_data->src_t38_info.last_seqnum = -1;
        p_conversation_data->src_t38_info.packet_lost = 0;
        p_conversation_data->src_t38_info.burst_lost = 0;
        p_conversation_data->src_t38_info.time_first_t4_data = 0;
        p_conversation_data->src_t38_info.additional_hdlc_data_field_counter = 0;
        p_conversation_data->src_t38_info.seqnum_prev_data_field = -1;

        p_conversation_data->dst_t38_info.reass_ID = 0;
        p_conversation_data->dst_t38_info.reass_start_seqnum = -1;
        p_conversation_data->dst_t38_info.reass_data_type = 0;
        p_conversation_data->dst_t38_info.last_seqnum = -1;
        p_conversation_data->dst_t38_info.packet_lost = 0;
        p_conversation_data->dst_t38_info.burst_lost = 0;
        p_conversation_data->dst_t38_info.time_first_t4_data = 0;
        p_conversation_data->dst_t38_info.additional_hdlc_data_field_counter = 0;
        p_conversation_data->dst_t38_info.seqnum_prev_data_field = -1;
}


static fragment_head *
force_reassemble_seq(reassembly_table *table, packet_info *pinfo, guint32 id)
{
	fragment_head *fd_head;
	fragment_item *fd_i;
	fragment_item *last_fd;
	guint32 dfpos, size, packet_lost, burst_lost, seq_num;
	guint8 *data;

	fd_head = fragment_get(table, pinfo, id, NULL);

	/* have we already seen this frame ?*/
	if (pinfo->fd->visited) {
		if (fd_head != NULL && fd_head->flags & FD_DEFRAGMENTED) {
			return fd_head;
		} else {
			return NULL;
		}
	}

	if (fd_head==NULL){
		/* we must have it to continue */
		return NULL;
	}

	/* check for packet lost and count the burst of packet lost */
	packet_lost = 0;
	burst_lost = 0;
	seq_num = 0;
	for(fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
		if (seq_num != fd_i->offset) {
			packet_lost += fd_i->offset - seq_num;
			if ( (fd_i->offset - seq_num) > burst_lost ) {
				burst_lost = fd_i->offset - seq_num;
			}
		}
		seq_num = fd_i->offset + 1;
	}

	/* we have received an entire packet, defragment it and
	 * free all fragments
	 */
	size=0;
	last_fd=NULL;
	for(fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
	  if(!last_fd || last_fd->offset!=fd_i->offset){
	    size+=fd_i->len;
	  }
	  last_fd=fd_i;
	}

	data = (guint8 *) wmem_alloc(pinfo->pool, size);
	fd_head->tvb_data = tvb_new_real_data(data, size, size);
	fd_head->len = size;		/* record size for caller	*/

	/* add all data fragments */
	dfpos = 0;
	last_fd=NULL;
	for (fd_i=fd_head->next;fd_i && fd_i->len + dfpos <= size;fd_i=fd_i->next) {
	  if (fd_i->len) {
	    if(!last_fd || last_fd->offset!=fd_i->offset){
	      tvb_memcpy(fd_i->tvb_data, data+dfpos, 0, fd_i->len);
	      dfpos += fd_i->len;
	    } else {
	      /* duplicate/retransmission/overlap */
	      fd_i->flags    |= FD_OVERLAP;
	      fd_head->flags |= FD_OVERLAP;
	      if( (last_fd->len!=fd_i->len)
		  || tvb_memeql(last_fd->tvb_data, 0, tvb_get_ptr(fd_i->tvb_data, 0, last_fd->len), last_fd->len) ){
			fd_i->flags    |= FD_OVERLAPCONFLICT;
			fd_head->flags |= FD_OVERLAPCONFLICT;
	      }
	    }
	  }
	  last_fd=fd_i;
	}

	/* we have defragmented the pdu, now free all fragments*/
	for (fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
	  if(fd_i->tvb_data){
	    tvb_free(fd_i->tvb_data);
	    fd_i->tvb_data=NULL;
	  }
	}

	/* mark this packet as defragmented */
	fd_head->flags |= FD_DEFRAGMENTED;
	fd_head->reassembled_in=pinfo->num;

	col_append_fstr(pinfo->cinfo, COL_INFO, " (t4-data Reassembled: %d pack lost, %d pack burst lost)", packet_lost, burst_lost);

	p_t38_packet_conv_info->packet_lost = packet_lost;
	p_t38_packet_conv_info->burst_lost = burst_lost;

	return fd_head;
}

/* T38 Routines */
#include "packet-t38-fn.c"

/* initialize the tap t38_info and the conversation */
static void
init_t38_info_conv(packet_info *pinfo)
{
	/* tap info */
	t38_info_current++;
	if (t38_info_current==MAX_T38_MESSAGES_IN_PACKET) {
		t38_info_current=0;
	}
	t38_info = &t38_info_arr[t38_info_current];

	t38_info->seq_num = 0;
	t38_info->type_msg = 0;
	t38_info->data_value = 0;
	t38_info->t30ind_value =0;
	t38_info->setup_frame_number = 0;
	t38_info->Data_Field_field_type_value = 0;
	t38_info->desc[0] = '\0';
	t38_info->desc_comment[0] = '\0';
	t38_info->time_first_t4_data = 0;
	t38_info->frame_num_first_t4_data = 0;


	/*
		p_t38_packet_conv hold the conversation info in each of the packets.
		p_t38_conv hold the conversation info used to reassemble the HDLC packets, and also the Setup info (e.g SDP)
		If we already have p_t38_packet_conv in the packet, it means we already reassembled the HDLC packets, so we don't
		need to use p_t38_conv
	*/
	p_t38_packet_conv = NULL;
	p_t38_conv = NULL;

	/* Use existing packet info if available */
	p_t38_packet_conv = (t38_conv *)p_get_proto_data(wmem_file_scope(), pinfo, proto_t38, 0);


	/* find the conversation used for Reassemble and Setup Info */
	p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                                   conversation_pt_to_endpoint_type(pinfo->ptype),
                                   pinfo->destport, pinfo->srcport, NO_ADDR_B | NO_PORT_B);

	/* create a conv if it doen't exist */
	if (!p_conv) {
		p_conv = conversation_new(pinfo->num, &pinfo->net_src, &pinfo->net_dst,
			      conversation_pt_to_endpoint_type(pinfo->ptype), pinfo->srcport, pinfo->destport, NO_ADDR2 | NO_PORT2);

		/* Set dissector */
		conversation_set_dissector(p_conv, t38_udp_handle);
	}

	p_t38_conv = (t38_conv *)conversation_get_proto_data(p_conv, proto_t38);

	/* create the conversation if it doesn't exist */
	if (!p_t38_conv) {
		p_t38_conv = wmem_new(wmem_file_scope(), t38_conv);
		p_t38_conv->setup_method[0] = '\0';
		p_t38_conv->setup_frame_number = 0;

		p_t38_conv->src_t38_info.reass_ID = 0;
		p_t38_conv->src_t38_info.reass_start_seqnum = -1;
		p_t38_conv->src_t38_info.reass_data_type = 0;
		p_t38_conv->src_t38_info.last_seqnum = -1;
		p_t38_conv->src_t38_info.packet_lost = 0;
		p_t38_conv->src_t38_info.burst_lost = 0;
		p_t38_conv->src_t38_info.time_first_t4_data = 0;
		p_t38_conv->src_t38_info.additional_hdlc_data_field_counter = 0;
		p_t38_conv->src_t38_info.seqnum_prev_data_field = -1;

		p_t38_conv->dst_t38_info.reass_ID = 0;
		p_t38_conv->dst_t38_info.reass_start_seqnum = -1;
		p_t38_conv->dst_t38_info.reass_data_type = 0;
		p_t38_conv->dst_t38_info.last_seqnum = -1;
		p_t38_conv->dst_t38_info.packet_lost = 0;
		p_t38_conv->dst_t38_info.burst_lost = 0;
		p_t38_conv->dst_t38_info.time_first_t4_data = 0;
		p_t38_conv->dst_t38_info.additional_hdlc_data_field_counter = 0;
		p_t38_conv->dst_t38_info.seqnum_prev_data_field = -1;

		conversation_add_proto_data(p_conv, proto_t38, p_t38_conv);
	}

	if (!p_t38_packet_conv) {
		/* copy the t38 conversation info to the packet t38 conversation */
		p_t38_packet_conv = wmem_new(wmem_file_scope(), t38_conv);
		(void) g_strlcpy(p_t38_packet_conv->setup_method, p_t38_conv->setup_method, MAX_T38_SETUP_METHOD_SIZE);
		p_t38_packet_conv->setup_frame_number = p_t38_conv->setup_frame_number;

		memcpy(&(p_t38_packet_conv->src_t38_info), &(p_t38_conv->src_t38_info), sizeof(t38_conv_info));
		memcpy(&(p_t38_packet_conv->dst_t38_info), &(p_t38_conv->dst_t38_info), sizeof(t38_conv_info));

		p_add_proto_data(wmem_file_scope(), pinfo, proto_t38, 0, p_t38_packet_conv);
	}

	if (addresses_equal(conversation_key_addr1(p_conv->key_ptr), &pinfo->net_src)) {
		p_t38_conv_info = &(p_t38_conv->src_t38_info);
		p_t38_packet_conv_info = &(p_t38_packet_conv->src_t38_info);
	} else {
		p_t38_conv_info = &(p_t38_conv->dst_t38_info);
		p_t38_packet_conv_info = &(p_t38_packet_conv->dst_t38_info);
	}

	/* update t38_info */
	t38_info->setup_frame_number = p_t38_packet_conv->setup_frame_number;
}

/* Entry point for dissection */
static int
dissect_t38_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint8 octet1;
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;

	/*
	 * XXX - heuristic to check for misidentified packets.
	 */
	if (dissect_possible_rtpv2_packets_as_rtp){
		octet1 = tvb_get_guint8(tvb, offset);
		if (RTP_VERSION(octet1) == 2){
			return call_dissector(rtp_handle,tvb,pinfo,tree);
		}
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.38");
	col_clear(pinfo->cinfo, COL_INFO);

	primary_part = TRUE;

	/* This indicate the item number in the primary part of the T38 message, it is used for the reassemble of T30 packets */
	Data_Field_item_num = 0;

	it=proto_tree_add_protocol_format(tree, proto_t38, tvb, 0, -1, "ITU-T Recommendation T.38");
	tr=proto_item_add_subtree(it, ett_t38);

	/* init tap and conv info */
	init_t38_info_conv(pinfo);

	/* Show Conversation setup info if exists*/
	if (global_t38_show_setup_info) {
		show_setup_info(tvb, tr, p_t38_packet_conv);
	}

	col_append_str(pinfo->cinfo, COL_INFO, "UDP: UDPTLPacket ");

	offset = dissect_UDPTLPacket_PDU(tvb, pinfo, tr, NULL);

	if (tvb_reported_length_remaining(tvb,offset)>0){
		proto_tree_add_expert_format(tr, pinfo, &ei_t38_malformed, tvb, offset, tvb_reported_length_remaining(tvb, offset),
				"[MALFORMED PACKET or wrong preference settings]");
		col_append_str(pinfo->cinfo, COL_INFO, " [Malformed?]");
	}
	return tvb_captured_length(tvb);
}

static int
dissect_t38_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;
        tvbuff_t *next_tvb;
	guint16 ifp_packet_number=1;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.38");
	col_clear(pinfo->cinfo, COL_INFO);

	primary_part = TRUE;

	/* This indicate the item number in the primary part of the T38 message, it is used for the reassemble of T30 packets */
	Data_Field_item_num = 0;

	it=proto_tree_add_protocol_format(tree, proto_t38, tvb, 0, -1, "ITU-T Recommendation T.38");
	tr=proto_item_add_subtree(it, ett_t38);

	/* init tap and conv info */
	init_t38_info_conv(pinfo);

	/* Show Conversation setup info if exists*/
	if (global_t38_show_setup_info) {
		show_setup_info(tvb, tr, p_t38_packet_conv);
	}

	col_append_str(pinfo->cinfo, COL_INFO, "TCP: IFPPacket");

	while(tvb_reported_length_remaining(tvb,offset)>0)
	{
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		offset += dissect_IFPPacket_PDU(next_tvb, pinfo, tr, NULL);
		ifp_packet_number++;

		if(tvb_reported_length_remaining(tvb,offset)>0){
			if(t38_tpkt_usage == T38_TPKT_ALWAYS){
				proto_tree_add_expert_format(tr, pinfo, &ei_t38_malformed, tvb, offset, tvb_reported_length_remaining(tvb, offset),
						"[MALFORMED PACKET or wrong preference settings]");
				col_append_str(pinfo->cinfo, COL_INFO, " [Malformed?]");
				break;
			}else {
				col_append_fstr(pinfo->cinfo, COL_INFO, " IFPPacket#%u",ifp_packet_number);
			}
		}
	}

	return tvb_captured_length(tvb);
}

static int
dissect_t38_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	primary_part = TRUE;

	if(t38_tpkt_usage == T38_TPKT_ALWAYS){
		dissect_tpkt_encap(tvb,pinfo,tree,t38_tpkt_reassembly,t38_tcp_pdu_handle);
	}
	else if((t38_tpkt_usage == T38_TPKT_NEVER) || (is_tpkt(tvb,1) == -1)){
		dissect_t38_tcp_pdu(tvb, pinfo, tree, data);
	}
	else {
		dissect_tpkt_encap(tvb,pinfo,tree,t38_tpkt_reassembly,t38_tcp_pdu_handle);
	}
	return tvb_captured_length(tvb);
}

/* Look for conversation info and display any setup info found */
void
show_setup_info(tvbuff_t *tvb, proto_tree *tree, t38_conv *p_t38_conversation)
{
	proto_tree *t38_setup_tree;
	proto_item *ti;

	if (!p_t38_conversation || p_t38_conversation->setup_frame_number == 0) {
		/* there is no Setup info */
		return;
	}

	ti =  proto_tree_add_string_format(tree, hf_t38_setup, tvb, 0, 0,
                      "",
                      "Stream setup by %s (frame %u)",
                      p_t38_conversation->setup_method,
                      p_t38_conversation->setup_frame_number);
    proto_item_set_generated(ti);
    t38_setup_tree = proto_item_add_subtree(ti, ett_t38_setup);
    if (t38_setup_tree)
    {
		/* Add details into subtree */
		proto_item* item = proto_tree_add_uint(t38_setup_tree, hf_t38_setup_frame,
                                                               tvb, 0, 0, p_t38_conversation->setup_frame_number);
		proto_item_set_generated(item);
		item = proto_tree_add_string(t38_setup_tree, hf_t38_setup_method,
                                                     tvb, 0, 0, p_t38_conversation->setup_method);
		proto_item_set_generated(item);
    }
}

/* This function tries to understand if the payload is sitting on top of AC DR */
static gboolean
dissect_t38_acdr_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint acdr_prot = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_acdr, 0));
	if (acdr_prot == ACDR_T38)
		return dissect_t38_udp(tvb, pinfo, tree, NULL);
	return FALSE;
}


/* Wireshark Protocol Registration */
void
proto_register_t38(void)
{
	static hf_register_info hf[] =
	{
#include "packet-t38-hfarr.c"
		{   &hf_t38_setup,
		    { "Stream setup", "t38.setup", FT_STRING, BASE_NONE,
		    NULL, 0x0, "Stream setup, method and frame number", HFILL }},
		{   &hf_t38_setup_frame,
            { "Stream frame", "t38.setup-frame", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, "Frame that set up this stream", HFILL }},
        {   &hf_t38_setup_method,
            { "Stream Method", "t38.setup-method", FT_STRING, BASE_NONE,
            NULL, 0x0, "Method used to set up this stream", HFILL }},
		{&hf_t38_fragments,
			{"Message fragments", "t38.fragments",
			FT_NONE, BASE_NONE, NULL, 0x00,	NULL, HFILL } },
		{&hf_t38_fragment,
			{"Message fragment", "t38.fragment",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_t38_fragment_overlap,
			{"Message fragment overlap", "t38.fragment.overlap",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{&hf_t38_fragment_overlap_conflicts,
			{"Message fragment overlapping with conflicting data",
			"t38.fragment.overlap.conflicts",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{&hf_t38_fragment_multiple_tails,
			{"Message has multiple tail fragments",
			"t38.fragment.multiple_tails",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{&hf_t38_fragment_too_long_fragment,
			{"Message fragment too long", "t38.fragment.too_long_fragment",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{&hf_t38_fragment_error,
			{"Message defragmentation error", "t38.fragment.error",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_t38_fragment_count,
			{"Message fragment count", "t38.fragment.count",
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
		{&hf_t38_reassembled_in,
			{"Reassembled in", "t38.reassembled.in",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_t38_reassembled_length,
			{"Reassembled T38 length", "t38.reassembled.length",
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
	};

	static gint *ett[] =
	{
		&ett_t38,
#include "packet-t38-ettarr.c"
		&ett_t38_setup,
		&ett_data_fragment,
		&ett_data_fragments
	};

	static ei_register_info ei[] = {
		{ &ei_t38_malformed, { "t38.malformed", PI_MALFORMED, PI_ERROR, "Malformed packet", EXPFILL }},
	};

	module_t *t38_module;
	expert_module_t* expert_t38;

	proto_t38 = proto_register_protocol("T.38", "T.38", "t38");
	proto_register_field_array(proto_t38, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_t38 = expert_register_protocol(proto_t38);
	expert_register_field_array(expert_t38, ei, array_length(ei));
	register_dissector("t38_udp", dissect_t38_udp, proto_t38);

	/* Register reassemble tables for HDLC */
	reassembly_table_register(&data_reassembly_table,
                              &addresses_reassembly_table_functions);

	t38_tap = register_tap("t38");

	t38_module = prefs_register_protocol(proto_t38, NULL);
	prefs_register_bool_preference(t38_module, "use_pre_corrigendum_asn1_specification",
	    "Use the Pre-Corrigendum ASN.1 specification",
	    "Whether the T.38 dissector should decode using the Pre-Corrigendum T.38 "
		"ASN.1 specification (1998).",
	    &use_pre_corrigendum_asn1_specification);
	prefs_register_bool_preference(t38_module, "dissect_possible_rtpv2_packets_as_rtp",
	    "Dissect possible RTP version 2 packets with RTP dissector",
	    "Whether a UDP packet that looks like RTP version 2 packet will "
		"be dissected as RTP packet or T.38 packet. If enabled there is a risk that T.38 UDPTL "
		"packets with sequence number higher than 32767 may be dissected as RTP.",
	    &dissect_possible_rtpv2_packets_as_rtp);
	prefs_register_bool_preference(t38_module, "reassembly",
		"Reassemble T.38 PDUs over TPKT over TCP",
		"Whether the dissector should reassemble T.38 PDUs spanning multiple TCP segments "
		"when TPKT is used over TCP. "
		"To use this option, you must also enable \"Allow subdissectors to reassemble "
		"TCP streams\" in the TCP protocol settings.",
		&t38_tpkt_reassembly);
	prefs_register_enum_preference(t38_module, "tpkt_usage",
		"TPKT used over TCP",
		"Whether T.38 is used with TPKT for TCP",
		(gint *)&t38_tpkt_usage,t38_tpkt_options,FALSE);

	prefs_register_bool_preference(t38_module, "show_setup_info",
                "Show stream setup information",
                "Where available, show which protocol and frame caused "
                "this T.38 stream to be created",
                &global_t38_show_setup_info);

}

void
proto_reg_handoff_t38(void)
{
	t38_udp_handle=create_dissector_handle(dissect_t38_udp, proto_t38);
	t38_tcp_handle=create_dissector_handle(dissect_t38_tcp, proto_t38);
	t38_tcp_pdu_handle=create_dissector_handle(dissect_t38_tcp_pdu, proto_t38);
	rtp_handle = find_dissector_add_dependency("rtp", proto_t38);
	t30_hdlc_handle = find_dissector_add_dependency("t30.hdlc", proto_t38);
	proto_acdr = proto_get_id_by_filter_name("acdr");
	data_handle = find_dissector("data");
	dissector_add_for_decode_as("tcp.port", t38_tcp_handle);
	dissector_add_for_decode_as("udp.port", t38_udp_handle);
	heur_dissector_add("udp", dissect_t38_acdr_heur, "T38 over AC DR", "t38_acdr", proto_t38, HEURISTIC_ENABLE);
	dissector_add_uint("acdr.media_type", ACDR_T38, t38_udp_handle);
}
