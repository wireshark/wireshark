/* packet-ltp.c
 * Routines for LTP dissection
 * Copyright 2009, Mithun Roy <mithunroy13@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Licklider Transmission Protocol - RFC 5326.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>

#include "packet-dtn.h"

#define LTP_MIN_DATA_BUFFER  5
#define LTP_MAX_HDR_EXTN    16
#define LTP_MAX_TRL_EXTN    16

void proto_reg_handoff_ltp(void);

/* For reassembling LTP segments */
static GHashTable *ltp_fragment_table = NULL;
static GHashTable *ltp_reassembled_table = NULL;

/* Initialize the protocol and registered fields */
static int proto_ltp = -1;

/* LTP Header variables */
static int hf_ltp_version       = -1;
static int hf_ltp_type          = -1;
static int hf_ltp_session_id    = -1;
static int hf_ltp_session_orig  = -1;
static int hf_ltp_session_no    = -1;
static int hf_ltp_hdr_extn_cnt  = -1;
static int hf_ltp_trl_extn_cnt  = -1;

/* LTP Data Segment variable */
static int hf_ltp_data_clid     = -1;
static int hf_ltp_data_offset   = -1;
static int hf_ltp_data_length   = -1;
static int hf_ltp_data_chkp     = -1;
static int hf_ltp_data_rpt      = -1;
static int hf_ltp_data_clidata  = -1;

/* LTP Report Segment variable */
static int hf_ltp_rpt_sno       = -1;
static int hf_ltp_rpt_chkp      = -1;
static int hf_ltp_rpt_ub        = -1;
static int hf_ltp_rpt_lb        = -1;
static int hf_ltp_rpt_clm_cnt   = -1;
static int hf_ltp_rpt_clm_off   = -1;
static int hf_ltp_rpt_clm_len   = -1;

/* LTP Report Ack Segment Variable */
static int hf_ltp_rpt_ack_sno   = -1;

/* LTP Session Management Segment Variable */
static int hf_ltp_cancel_code   = -1;

/* LTP Header Extension Segment */
static int hf_ltp_hdr_extn_tag  = -1;
static int hf_ltp_hdr_extn_len  = -1;
static int hf_ltp_hdr_extn_val  = -1;

/* LTP Trailer Extension Segment */
static int hf_ltp_trl_extn_tag  = -1;
static int hf_ltp_trl_extn_len  = -1;
static int hf_ltp_trl_extn_val  = -1;

/*LTP reassembly */
static int hf_ltp_fragments = -1;
static int hf_ltp_fragment = -1;
static int hf_ltp_fragment_overlap = -1;
static int hf_ltp_fragment_overlap_conflicts = -1;
static int hf_ltp_fragment_multiple_tails = -1;
static int hf_ltp_fragment_too_long_fragment = -1;
static int hf_ltp_fragment_error = -1;
static int hf_ltp_fragment_count = -1;
static int hf_ltp_reassembled_in = -1;
static int hf_ltp_reassembled_length = -1;

static const value_string ltp_type_codes[] = {
	{0x0, "Red data, NOT {Checkpoint, EORP or EOB}"},
	{0x1, "Red data, Checkpoint, NOT {EORP or EOB}"},
	{0x2, "Red data, Checkpoint, EORP, NOT EOB"},
	{0x3, "Red data, Checkpoint, EORP, EOB"},
	{0x4, "Green data, NOT EOB"},
	{0x5, "Green data, undefined"},
	{0x6, "Green data, undefined"},
	{0x7, "Green data, EOB"},
	{0x8, "Report segment"},
	{0x9, "Report-acknowledgment segment"},
	{0xa, "Control segment, undefined"},
	{0xb, "Control segment, undefined"},
	{0xc, "Cancel segment from block sender"},
	{0xd, "Cancel-acknowledgment segment to block sender"},
	{0xe, "Cancel segment from block receiver"},
	{0xf, "Cancel-acknowledgment segment to block receiver"},
	{0,NULL}
};

static const value_string ltp_type_col_info[] = {
	{0x0, "Red data"},
	{0x1, "Red data"},
	{0x2, "Red data"},
	{0x3, "Red data"},
	{0x4, "Green data"},
	{0x5, "Green data"},
	{0x6, "Green data"},
	{0x7, "Green data"},
	{0x8, "Report segment"},
	{0x9, "Report ack segment"},
	{0xa, "Control segment"},
	{0xb, "Control segment"},
	{0xc, "Cancel segment"},
	{0xd, "Cancel ack segment"},
	{0xe, "Cancel segment"},
	{0xf, "Cancel ack segment"},
	{0, NULL}
};

static const value_string ltp_cancel_codes[] = {
	{0x00, "Client service canceled session"},
	{0x01, "Unreachable client service"},
	{0x02, "Retransmission limit exceeded"},
	{0x03, "Miscolored segment"},
	{0x04, "A system error"},
	{0x05, "Exceeded the Retransmission-Cycles limit"},
	{0, NULL}
};

static const value_string extn_tag_codes[] = {
	{0x00, "LTP authentication extension"},
	{0x01, "LTP cookie extension"},
	{0, NULL}
};


static guint ltp_port = 1113;

/* Initialize the subtree pointers */
static gint ett_ltp             = -1;
static gint ett_ltp_hdr         = -1;
static gint ett_hdr_session     = -1;
static gint ett_hdr_extn        = -1;
static gint ett_data_segm       = -1;
static gint ett_data_data_segm  = -1;
static gint ett_rpt_segm        = -1;
static gint ett_rpt_clm         = -1;
static gint ett_rpt_ack_segm    = -1;
static gint ett_session_mgmt    = -1;
static gint ett_trl_extn        = -1;
static gint ett_ltp_fragment	= -1;
static gint ett_ltp_fragments	= -1;

static const fragment_items ltp_frag_items = {
    /*Fragment subtrees*/
    &ett_ltp_fragment,
    &ett_ltp_fragments,
    /*Fragment Fields*/
    &hf_ltp_fragments,
    &hf_ltp_fragment,
    &hf_ltp_fragment_overlap,
    &hf_ltp_fragment_overlap_conflicts,
    &hf_ltp_fragment_multiple_tails,
    &hf_ltp_fragment_too_long_fragment,
    &hf_ltp_fragment_error,
    &hf_ltp_fragment_count,
    /*Reassembled in field*/
    &hf_ltp_reassembled_in,
    /*Reassembled length field*/
    &hf_ltp_reassembled_length,
    /*Tag*/
    "LTP fragments"
};

static int
dissect_data_segment(proto_tree *ltp_tree, tvbuff_t *tvb,packet_info *pinfo,int frame_offset,int ltp_type, guint64 session_num){
	guint64 client_id;
	guint64 offset;
	guint64 length;
	guint64 chkp_sno = 0;
	guint64 rpt_sno = 0;

	int segment_offset = 0;

	int client_id_size;
	int offset_size;
	int length_size;
	int chkp_sno_size;
	int rpt_sno_size;

	int data_offset = 0;
	int data_length;
	int bundle_size = 0;
	int dissected_data_size = 0;
	int data_count = 1;

	proto_item *ltp_data_item;
	proto_item *ltp_data_data_item;

	proto_tree *ltp_data_tree;
	proto_tree *ltp_data_data_tree;

	tvbuff_t *datatvb;

	fragment_data *frag_msg = NULL;
	gboolean more_frags = TRUE;

	tvbuff_t *new_tvb = NULL;

	/* Extract the info for the data segment */
	client_id = evaluate_sdnv_64(tvb,frame_offset + segment_offset,&client_id_size);
	segment_offset+= client_id_size;

	if((unsigned)(frame_offset + segment_offset) >= tvb_length(tvb)){
	/* This would mean the data segment is incomplete */
		return 0;
	}
	offset = evaluate_sdnv_64(tvb,frame_offset + segment_offset,&offset_size);
	segment_offset+= offset_size;

	if((unsigned)(frame_offset + segment_offset) >= tvb_length(tvb)){
	/* This would mean the data segment is incomplete */
		return 0;
	}

	length = evaluate_sdnv_64(tvb,frame_offset + segment_offset,&length_size);
	segment_offset+= length_size;

	if((unsigned)(frame_offset + segment_offset) >= tvb_length(tvb)){
	/* This would mean the data segment is incomplete */
		return 0;
	}

	if(ltp_type != 0 )
	{
		chkp_sno = evaluate_sdnv_64(tvb,frame_offset + segment_offset,&chkp_sno_size);
		segment_offset+= chkp_sno_size;

		if((unsigned)(frame_offset + segment_offset) >= tvb_length(tvb)){
		/* This would mean the data segment is incomplete */
			return 0;
		}

		rpt_sno = evaluate_sdnv_64(tvb,frame_offset + segment_offset,&rpt_sno_size);
		segment_offset+= rpt_sno_size;

		if((unsigned)(frame_offset + segment_offset) >= tvb_length(tvb)){
		/* This would mean the data segment is incomplete */
			return 0;
		}
	}
	/* Adding size of the data */
	if ((segment_offset + (int)length < segment_offset) || (segment_offset + (int)length < (int)length)) {
	/* Addition result has wrapped */
		return 0;
	}
	segment_offset+= (int)length;

	if ((segment_offset + frame_offset < segment_offset) || (segment_offset + frame_offset < frame_offset)) {
	/* Addition result has wrapped */
		return 0;
	}
	if((unsigned)(frame_offset + segment_offset) > tvb_length(tvb)){
	/* This would mean the data segment is incomplete */
		return 0;
	}

	/* Create a subtree for data segment and add the other fields under it */
	ltp_data_item = proto_tree_add_text(ltp_tree, tvb,frame_offset, segment_offset, "Data Segment");
	ltp_data_tree = proto_item_add_subtree(ltp_data_item, ett_data_segm);

	proto_tree_add_uint64(ltp_data_tree,hf_ltp_data_clid, tvb, frame_offset,client_id_size,client_id);
	frame_offset += client_id_size;

	proto_tree_add_uint64(ltp_data_tree, hf_ltp_data_offset, tvb, frame_offset,offset_size, offset);
	frame_offset += offset_size;

	proto_tree_add_uint64(ltp_data_tree,hf_ltp_data_length, tvb, frame_offset,length_size,length);
	frame_offset += length_size;

	if(ltp_type != 0 )
	{
		proto_tree_add_uint64(ltp_data_tree, hf_ltp_data_chkp, tvb, frame_offset,chkp_sno_size, chkp_sno);
		frame_offset += chkp_sno_size;

		proto_tree_add_uint64(ltp_data_tree, hf_ltp_data_rpt, tvb, frame_offset,rpt_sno_size, rpt_sno);
		frame_offset += rpt_sno_size;

		more_frags = FALSE;
		frag_msg = fragment_add_check(tvb, frame_offset, pinfo, (guint32)session_num, ltp_fragment_table,
			  ltp_reassembled_table, (guint32)offset, (guint32)length, more_frags);
	}
	else
	{
		more_frags = TRUE;
		frag_msg = fragment_add_check(tvb, frame_offset, pinfo, (guint32)session_num, ltp_fragment_table,
			 ltp_reassembled_table, (guint32)offset, (guint32)length, more_frags);

	}


	if(frag_msg)
	{
		/* Checking if the segment is completely reassembled */
		if(!(frag_msg->flags & FD_PARTIAL_REASSEMBLY))
		{
			/* if the segment has not been fragmented, then no reassembly is needed */
			if(!more_frags && offset == 0)
			{
				new_tvb = tvb_new_subset(tvb,frame_offset,tvb_length(tvb)-frame_offset,-1);
			}
			else
			{
				new_tvb = process_reassembled_data(tvb, frame_offset, pinfo, "Reassembled LTP Segment",
					frag_msg, &ltp_frag_items,NULL, ltp_data_tree);

			}
		}
	}

	if(new_tvb)
	{
		data_length = tvb_length(new_tvb);
		while((unsigned)dissected_data_size < length)
		{
			ltp_data_data_item = proto_tree_add_text(ltp_data_tree, tvb,frame_offset, 0, "Data[%d]",data_count);
			ltp_data_data_tree = proto_item_add_subtree(ltp_data_data_item, ett_data_data_segm);

			datatvb = tvb_new_subset(new_tvb, data_offset, (int)data_length - dissected_data_size, tvb_length(new_tvb));
			bundle_size = dissect_complete_bundle(datatvb, pinfo, ltp_data_data_tree);
			if(bundle_size == 0) {  /*Couldn't parse bundle*/
				col_set_str(pinfo->cinfo, COL_INFO, "Dissection Failed");
				return 0;           /*Give up*/
			}
			data_offset += bundle_size;
			dissected_data_size += bundle_size;
			data_count++;
		}
	}
	else
	{
		if(frag_msg && more_frags)
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, "[Reassembled in %d] ",frag_msg->reassembled_in);
		}
		else
		{
			col_append_str(pinfo->cinfo, COL_INFO, "[Unfinished LTP Segment] ");
		}

	}

	return segment_offset;
}


static int
dissect_report_segment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ltp_tree, int frame_offset) {
	guint64 rpt_sno;
	guint64 chkp_sno;
	guint64 upper_bound;
	guint64 lower_bound;
	int rcpt_clm_cnt;
	guint64 offset;
	guint64 length;

	int rpt_sno_size;
	int chkp_sno_size;
	int upper_bound_size;
	int lower_bound_size;
	int rcpt_clm_cnt_size;
	int offset_size;
	int length_size;

	int segment_offset = 0;
	int i;

	proto_item *ltp_rpt_item;
	proto_item *ltp_rpt_clm_item;

	proto_tree *ltp_rpt_tree;
	proto_tree *ltp_rpt_clm_tree;

	/* Create the subtree for report segment under the main LTP tree and all the report segment fields under it */
	ltp_rpt_item = proto_tree_add_text(ltp_tree, tvb, frame_offset, -1, "Report Segment");
	ltp_rpt_tree = proto_item_add_subtree(ltp_rpt_item, ett_rpt_segm);

	/* Extract the report segment info */
	rpt_sno = evaluate_sdnv_64(tvb, frame_offset, &rpt_sno_size);
	proto_tree_add_uint64(ltp_rpt_tree, hf_ltp_rpt_sno, tvb, frame_offset + segment_offset, rpt_sno_size, rpt_sno);
	segment_offset += rpt_sno_size;

	chkp_sno = evaluate_sdnv_64(tvb, frame_offset + segment_offset, &chkp_sno_size);
	proto_tree_add_uint64(ltp_rpt_tree, hf_ltp_rpt_chkp, tvb, frame_offset + segment_offset, chkp_sno_size, chkp_sno);
	segment_offset += chkp_sno_size;

	upper_bound = evaluate_sdnv(tvb, frame_offset + segment_offset, &upper_bound_size);
	proto_tree_add_uint64(ltp_rpt_tree, hf_ltp_rpt_ub, tvb, frame_offset + segment_offset, upper_bound_size, upper_bound);
	segment_offset += upper_bound_size;

	lower_bound = evaluate_sdnv(tvb, frame_offset + segment_offset, &lower_bound_size);
	proto_tree_add_uint64(ltp_rpt_tree, hf_ltp_rpt_lb, tvb, frame_offset + segment_offset, lower_bound_size, lower_bound);
	segment_offset += lower_bound_size;

	rcpt_clm_cnt = evaluate_sdnv(tvb, frame_offset + segment_offset, &rcpt_clm_cnt_size);
	if (rcpt_clm_cnt < 0){
		proto_item_set_end(ltp_rpt_item, tvb, frame_offset + segment_offset);
		expert_add_info_format(pinfo, ltp_tree, PI_UNDECODED, PI_ERROR, "Negative reception claim count: %d", rcpt_clm_cnt);
		return 0;
	}
	proto_tree_add_uint(ltp_rpt_tree, hf_ltp_rpt_clm_cnt, tvb, frame_offset + segment_offset, rcpt_clm_cnt_size, rcpt_clm_cnt);
	segment_offset += rcpt_clm_cnt_size;

	ltp_rpt_clm_item = proto_tree_add_text(ltp_rpt_tree, tvb, frame_offset + segment_offset, -1, "Reception claims");
	ltp_rpt_clm_tree = proto_item_add_subtree(ltp_rpt_clm_item, ett_rpt_clm);

	/* There can be multiple reception claims in the same report segment */
	for(i = 0; i<rcpt_clm_cnt; i++){
		offset = evaluate_sdnv(tvb,frame_offset + segment_offset, &offset_size);
		proto_tree_add_uint64_format(ltp_rpt_clm_tree, hf_ltp_rpt_clm_off, tvb, frame_offset + segment_offset, offset_size, offset,
				"Offset[%d] : %"G_GINT64_MODIFIER"d", i, offset);
		segment_offset += offset_size;

		length = evaluate_sdnv(tvb,frame_offset + segment_offset, &length_size);
		proto_tree_add_uint64_format(ltp_rpt_clm_tree, hf_ltp_rpt_clm_len, tvb, frame_offset + segment_offset, length_size, length,
				"Length[%d] : %"G_GINT64_MODIFIER"d",i, length);
		segment_offset += length_size;
	}
	proto_item_set_end(ltp_rpt_clm_item, tvb, frame_offset + segment_offset);
	proto_item_set_end(ltp_rpt_item, tvb, frame_offset + segment_offset);
	return segment_offset;
}


static int
dissect_report_ack_segment(proto_tree *ltp_tree, tvbuff_t *tvb,int frame_offset){
	guint64 rpt_sno;

	int rpt_sno_size;
	int segment_offset = 0;

	proto_item *ltp_rpt_ack_item;
	proto_tree *ltp_rpt_ack_tree;

	/* Extracing receipt serial number info */
	rpt_sno = evaluate_sdnv_64(tvb,frame_offset, &rpt_sno_size);
	segment_offset += rpt_sno_size;

	if((unsigned)(frame_offset + segment_offset) > tvb_length(tvb)){
		return 0;
	}

	/* Creating tree for the report ack segment */
	ltp_rpt_ack_item = proto_tree_add_text(ltp_tree, tvb,frame_offset, segment_offset, "Report Ack Segment");
	ltp_rpt_ack_tree = proto_item_add_subtree(ltp_rpt_ack_item, ett_rpt_ack_segm);

	proto_tree_add_uint64(ltp_rpt_ack_tree, hf_ltp_rpt_ack_sno, tvb, frame_offset,rpt_sno_size, rpt_sno);
	return segment_offset;
}


static int
dissect_cancel_segment(proto_tree * ltp_tree, tvbuff_t *tvb,int frame_offset){
	guint8 reason_code;

	proto_item *ltp_cancel_item;
	proto_tree *ltp_cancel_tree;

	/* The cancel segment has only one byte, which contains the reason code. */
	reason_code = tvb_get_guint8(tvb,frame_offset);

	/* Creating tree for the cancel segment */
	ltp_cancel_item = proto_tree_add_text(ltp_tree, tvb,frame_offset, 1, "Cancel Segment");
	ltp_cancel_tree = proto_item_add_subtree(ltp_cancel_item, ett_session_mgmt);

	proto_tree_add_uint_format_value(ltp_cancel_tree, hf_ltp_cancel_code, tvb, frame_offset, 1, reason_code,
			"%x (%s)", reason_code, val_to_str(reason_code,ltp_cancel_codes,"Reserved"));
	return 1;
}

static int
dissect_header_extn(proto_tree *ltp_tree, tvbuff_t *tvb,int frame_offset,int hdr_extn_cnt){
	guint8 extn_type[LTP_MAX_HDR_EXTN];
	guint64 length[LTP_MAX_HDR_EXTN];
	guint64 value[LTP_MAX_HDR_EXTN];

	int length_size[LTP_MAX_HDR_EXTN];
	int value_size[LTP_MAX_HDR_EXTN];

	int i;
	int extn_offset = 0;

	proto_item *ltp_hdr_extn_item;
	proto_tree *ltp_hdr_extn_tree;

	/*  There can be more than one header extensions */
	for(i = 0; i < hdr_extn_cnt; i++){
		extn_type[i] = tvb_get_guint8(tvb,frame_offset);
		extn_offset++;

		if((unsigned)(frame_offset + extn_offset) >= tvb_length(tvb)){
			return 0;
		}
		length[i] = evaluate_sdnv_64(tvb,frame_offset,&length_size[i]);
		extn_offset += length_size[i];
		if((unsigned)(frame_offset + extn_offset) >= tvb_length(tvb)){
			return 0;
		}
		value[i] = evaluate_sdnv_64(tvb,frame_offset,&value_size[i]);
		extn_offset += value_size[i];
		if((unsigned)(frame_offset + extn_offset) >= tvb_length(tvb)){
			return 0;
		}
	}
	ltp_hdr_extn_item = proto_tree_add_text(ltp_tree, tvb,frame_offset, extn_offset, "Header Extension");
	ltp_hdr_extn_tree = proto_item_add_subtree(ltp_hdr_extn_item, ett_hdr_extn);

	for(i = 0; i < hdr_extn_cnt; i++){
		proto_tree_add_uint_format_value(ltp_hdr_extn_tree, hf_ltp_hdr_extn_tag, tvb, frame_offset, 1, extn_type[i], "%x (%s)", extn_type[i], val_to_str(extn_type[i],extn_tag_codes,"Unassigned/Reserved"));

		proto_tree_add_uint64_format(ltp_hdr_extn_tree, hf_ltp_hdr_extn_len, tvb, frame_offset, length_size[i],length[i], "Length [%d]: %"G_GINT64_MODIFIER"d",i+1,length[i]);
		frame_offset += length_size[i];

		proto_tree_add_uint64_format(ltp_hdr_extn_tree, hf_ltp_hdr_extn_val, tvb, frame_offset, value_size[i],value[i], "Value [%d]: %"G_GINT64_MODIFIER"d",i+1,value[i]);
		frame_offset += value_size[i];
	}
	return extn_offset;
}

static int
dissect_trailer_extn(proto_tree *ltp_tree, tvbuff_t *tvb,int frame_offset,int trl_extn_cnt){
	guint8 extn_type[LTP_MAX_TRL_EXTN];
	guint64 length[LTP_MAX_TRL_EXTN];
	guint64 value[LTP_MAX_TRL_EXTN];

	int length_size[LTP_MAX_TRL_EXTN];
	int value_size[LTP_MAX_TRL_EXTN];

	int i;
	int extn_offset = 0;

	proto_item *ltp_trl_extn_item;
	proto_tree *ltp_trl_extn_tree;

	DISSECTOR_ASSERT(trl_extn_cnt < LTP_MAX_TRL_EXTN);

	for(i = 0; i < trl_extn_cnt; i++){
		extn_type[i] = tvb_get_guint8(tvb,frame_offset);
		extn_offset++;

		if((unsigned)(frame_offset + extn_offset) >= tvb_length(tvb)){
			return 0;
		}

		length[i] = evaluate_sdnv_64(tvb,frame_offset,&length_size[i]);
		extn_offset += length_size[i];

		if((unsigned)(frame_offset + extn_offset) >= tvb_length(tvb)){
			return 0;
		}

		value[i] = evaluate_sdnv_64(tvb,frame_offset,&value_size[i]);
		extn_offset += value_size[i];

		if((unsigned)(frame_offset + extn_offset) >= tvb_length(tvb)){
			return 0;
		}
	}
	ltp_trl_extn_item = proto_tree_add_text(ltp_tree, tvb,frame_offset, extn_offset, "Header Extension");
	ltp_trl_extn_tree = proto_item_add_subtree(ltp_trl_extn_item, ett_trl_extn);

	for(i = 0; i < trl_extn_cnt; i++){
		proto_tree_add_uint_format_value(ltp_trl_extn_tree, hf_ltp_trl_extn_tag, tvb, frame_offset, 1, extn_type[i], "%x (%s)", extn_type[i], val_to_str(extn_type[i],extn_tag_codes,"Unassigned/Reserved"));

		proto_tree_add_uint64_format(ltp_trl_extn_tree, hf_ltp_trl_extn_len, tvb, frame_offset, length_size[i], length[i], "Length [%d]: %"G_GINT64_MODIFIER"d",i+1,length[i]);
		frame_offset += length_size[i];

		proto_tree_add_uint64_format(ltp_trl_extn_tree, hf_ltp_trl_extn_val, tvb, frame_offset, value_size[i], value[i], "Value [%d]: %"G_GINT64_MODIFIER"d",i+0,value[i]);
		frame_offset += value_size[i];
	}
	return extn_offset;
}


static int
dissect_ltp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti = NULL;
	proto_tree *ltp_tree = NULL;
	int frame_offset;
	int header_offset;
	int segment_offset = 0;
	int hdr_extn_offset = 0;
	int trl_extn_offset = 0;

	guint8  ltp_hdr;
	gint    ltp_type;
	guint8  ltp_extn_cnt;
	gint    hdr_extn_cnt;
	gint    trl_extn_cnt;

	guint64 engine_id;
	guint64 session_num;
	int engine_id_size;
	int session_num_size;

	proto_item *ltp_header_item = NULL;
	proto_item *ltp_session_item = NULL;

	proto_tree *ltp_header_tree = NULL;
	proto_tree *ltp_session_tree = NULL;

	/* Check that there's enough data */
	if(tvb_length(tvb) < LTP_MIN_DATA_BUFFER){
		return 0;
	}
	frame_offset = 0;
	header_offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTP Segment");

	/* Extract all the header info from the packet */
	ltp_hdr = tvb_get_guint8(tvb, frame_offset);
	header_offset++;

	engine_id = evaluate_sdnv_64(tvb,frame_offset + header_offset,&engine_id_size);
	header_offset += engine_id_size;
	if((unsigned)header_offset >= tvb_length(tvb)){
		col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
		return 0;
	}

	session_num = evaluate_sdnv_64(tvb,frame_offset + header_offset,&session_num_size);
	header_offset += session_num_size;
	if((unsigned)header_offset >= tvb_length(tvb)){
		col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
		return 0;
	}

	ti = proto_tree_add_item(tree, proto_ltp, tvb, 0, -1, ENC_NA);
	ltp_tree = proto_item_add_subtree(ti, ett_ltp);

	/* Adding Header Subtree */
	ltp_header_item = proto_tree_add_text(ltp_tree, tvb, frame_offset, header_offset+1, "LTP Header");
	ltp_header_tree = proto_item_add_subtree(ltp_header_item, ett_ltp_hdr);

	proto_tree_add_uint(ltp_header_tree,hf_ltp_version,tvb,frame_offset,1,hi_nibble(ltp_hdr));
	ltp_type = lo_nibble(ltp_hdr);
	proto_tree_add_uint_format_value(ltp_header_tree,hf_ltp_type,tvb,frame_offset,1,ltp_type,"%x (%s)",
			 ltp_type,val_to_str(ltp_type,ltp_type_codes,"Invalid"));

	frame_offset++;
	/* Adding the session id subtree */
	ltp_session_item = proto_tree_add_item(ltp_header_item,hf_ltp_session_id,tvb,frame_offset, engine_id_size + session_num_size,ENC_NA);
	ltp_session_tree = proto_item_add_subtree(ltp_session_item,ett_hdr_session);
	proto_tree_add_uint64(ltp_session_tree,hf_ltp_session_orig,tvb,frame_offset,engine_id_size,engine_id);
	frame_offset+=engine_id_size;
	proto_tree_add_uint64(ltp_session_tree,hf_ltp_session_no, tvb, frame_offset,session_num_size,session_num);
	frame_offset+=session_num_size;

	/* Adding Extension count to the header tree */
	ltp_extn_cnt = tvb_get_guint8(tvb,frame_offset);
	hdr_extn_cnt = hi_nibble(ltp_extn_cnt);
	trl_extn_cnt = lo_nibble(ltp_extn_cnt);

	proto_tree_add_uint(ltp_header_tree,hf_ltp_hdr_extn_cnt,tvb,frame_offset,1,hdr_extn_cnt);
	proto_tree_add_uint(ltp_header_tree,hf_ltp_trl_extn_cnt,tvb,frame_offset,1,trl_extn_cnt);
	frame_offset++;

	col_add_str(pinfo->cinfo, COL_INFO, val_to_str_const(ltp_type,ltp_type_col_info,"Protocol Error"));

	if((unsigned)frame_offset >= tvb_length(tvb)){
		col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
		return 0;
	}

	/* Check if there are any header extensions */
	if(hdr_extn_cnt > 0){
		hdr_extn_offset = dissect_header_extn(ltp_tree, tvb, frame_offset,hdr_extn_cnt);
		if(hdr_extn_offset == 0){
			col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
			return 0;
		}
		frame_offset += hdr_extn_offset;
	}

	if((unsigned)frame_offset >= tvb_length(tvb)){
		col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
		return 0;
	}

	/* Call sub routines to handle the segment content*/
	if((ltp_type >= 0) && (ltp_type < 8)){
		segment_offset = dissect_data_segment(ltp_tree,tvb,pinfo,frame_offset,ltp_type,session_num);
		if(segment_offset == 0){
			col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
			return 0;
		}
	}
	else if(ltp_type == 8){
		segment_offset = dissect_report_segment(tvb, pinfo, ltp_tree,frame_offset);
		if(segment_offset == 0){
			col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
			return 0;
		}
	}
	else if(ltp_type == 9){
		segment_offset = dissect_report_ack_segment(ltp_tree,tvb,frame_offset);
		if(segment_offset == 0){
			col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
			return 0;
		}
	}
	else if(ltp_type == 12 || ltp_type == 14){
		segment_offset = dissect_cancel_segment(ltp_tree,tvb,frame_offset);
		if(segment_offset == 0){
			col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
			return 0;
		}
	}
	frame_offset += segment_offset;
	/* Check to see if there are any trailer extensions */
	if(trl_extn_cnt > 0){
		if((unsigned)frame_offset >= tvb_length(tvb)){
		    col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
		    return 0;
		}
		trl_extn_offset = dissect_trailer_extn(ltp_tree, tvb, frame_offset,trl_extn_cnt);
		if(trl_extn_offset == 0){
		    col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
		    return 0;
		}
	}
	/* Return the amount of data this dissector was able to dissect */
	return tvb_length(tvb);
}

static void
ltp_defragment_init(void) {
    fragment_table_init(&ltp_fragment_table);
    reassembled_table_init(&ltp_reassembled_table);
}

/* Register the protocol with Wireshark */
void
proto_register_ltp(void)
{
	module_t *ltp_module;

	static hf_register_info hf[] = {
	  {&hf_ltp_version,
		  {"LTP Version","ltp.version",
		  FT_UINT8,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_type,
		  {"LTP Type","ltp.type",
		  FT_UINT8,BASE_HEX,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_session_id,
		  {"Session ID","ltp.session",
		  FT_NONE,BASE_NONE,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_session_orig,
		  {"Session originator","ltp.session.orig",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_session_no,
		  {"Session number","ltp.session.number",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_hdr_extn_cnt,
		  {"Header Extension Count","ltp.hdr.extn.cnt",
		  FT_UINT8,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_trl_extn_cnt,
		  {"Trailer Extension Count","ltp.trl.extn.cnt",
		  FT_UINT8,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_clid,
		  {"Client service ID","ltp.data.client.id",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_offset,
		  {"Offset","ltp.data.offset",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_length,
		  {"Length","ltp.data.length",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_chkp,
		  {"Checkpoint serial number","ltp.data.chkp",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_rpt,
		  {"Report serial number","ltp.data.rpt",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_clidata,
		  {"Client service data","ltp.data.data",
		  FT_BYTES,BASE_NONE,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_sno,
		  {"Report serial number","ltp.rpt.sno",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_chkp,
		  {"Checkpoint serial number","ltp.rpt.chkp",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_ub,
		  {"Upper bound","ltp.rpt.ub",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_lb,
		  {"Lower bound","ltp.rpt.lb",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_clm_cnt,
		  {"Reception claim count","ltp.rpt.clm.cnt",
		  FT_UINT8,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_clm_off,
		  {"Offset","ltp.rpt.clm.off",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_clm_len,
		  {"Length","ltp.rpt.clm.len",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_ack_sno,
		  {"Report serial number","ltp.rpt.ack.sno",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_cancel_code,
		  {"Cancel code","ltp.cancel.code",
		  FT_UINT8,BASE_HEX,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_hdr_extn_tag,
		  {"Extension tag","ltp.hdr.extn.tag",
		  FT_UINT8,BASE_HEX,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_hdr_extn_len,
		  {"Length","ltp.hdr.extn.len",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_hdr_extn_val,
		  {"Value","ltp.hdr.extn.val",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_trl_extn_tag,
		  {"Extension tag","ltp.hdr.extn.tag",
		  FT_UINT8,BASE_HEX,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_trl_extn_len,
		  {"Length","ltp.hdr.extn.len",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_trl_extn_val,
		  {"Value","ltp.hdr.extn.val",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_fragments,
		  {"LTP Fragments", "ltp.fragments",
		  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_fragment,
		  {"LTP Fragment", "ltp.fragment",
		  FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_fragment_overlap,
		  {"LTP fragment overlap", "ltp.fragment.overlap",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_fragment_overlap_conflicts,
		  {"LTP fragment overlapping with conflicting data",
		   "ltp.fragment.overlap.conflicts",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_fragment_multiple_tails,
		  {"LTP has multiple tails", "ltp.fragment.multiple_tails",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_fragment_too_long_fragment,
		  {"LTP fragment too long", "ltp.fragment.too_long_fragment",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_fragment_error,
		  {"LTP defragmentation error", "ltp.fragment.error",
		  FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_fragment_count,
		  {"LTP fragment count", "ltp.fragment.count",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_reassembled_in,
		  {"LTP reassembled in", "ltp.reassembled.in",
		  FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_reassembled_length,
		  {"LTP reassembled length", "ltp.reassembled.length",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
	  }
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ltp,
		&ett_ltp_hdr,
		&ett_hdr_session,
		&ett_hdr_extn,
		&ett_data_segm,
		&ett_data_data_segm,
		&ett_rpt_segm,
		&ett_rpt_clm,
		&ett_rpt_ack_segm,
		&ett_session_mgmt,
		&ett_trl_extn,
		&ett_ltp_fragment,
		&ett_ltp_fragments
	};

/* Register the protocol name and description */
	proto_ltp = proto_register_protocol("Licklider Transmission Protocol",
		"LTP", "ltp");

	proto_register_field_array(proto_ltp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	ltp_module = prefs_register_protocol(proto_ltp, proto_reg_handoff_ltp);

	prefs_register_uint_preference(ltp_module, "udp.port", "LTP UDP Port",
		"UDP Port to accept LTP Connections",
		10, &ltp_port);
	register_init_routine(ltp_defragment_init);
}

void
proto_reg_handoff_ltp(void)
{
	static gboolean initialized = FALSE;
	static dissector_handle_t ltp_handle;
	static int currentPort;

	if (!initialized) {
		ltp_handle = new_create_dissector_handle(dissect_ltp, proto_ltp);
		initialized = TRUE;
	} else {
		dissector_delete_uint("udp.port", currentPort, ltp_handle);
	}

	currentPort = ltp_port;

	dissector_add_uint("udp.port", currentPort, ltp_handle);
}
