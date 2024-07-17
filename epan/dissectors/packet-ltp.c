/* packet-ltp.c
 * Routines for LTP dissection
 * Copyright 2009, Mithun Roy <mithunroy13@gmail.com>
 * Copyright 2017, Krishnamurthy Mayya <krishnamurthymayya@gmail.com>
     Revision: Minor modifications to Header and Trailer extensions
               by correcting the offset handling.
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 *    Modifications were made to this file under designation MFS-33289-1 and
 *    are Copyright 2015 United States Government as represented by NASA
 *       Marshall Space Flight Center. All Rights Reserved.
 *
 *    Released under the GNU GPL with NASA legal approval granted 2016-06-10.
 *
 *    The subject software is provided "AS IS" WITHOUT ANY WARRANTY of any kind,
 *    either expressed, implied or statutory and this agreement does not,
 *    in any manner, constitute an endorsement by government agency of any
 *    results, designs or products resulting from use of the subject software.
 *    See the Agreement for the specific language governing permissions and
 *    limitations.
 */

/*
 * Licklider Transmission Protocol - RFC 5326.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include <epan/conversation_table.h>
#include <epan/conversation_filter.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>
#include <epan/stats_tree.h>
#include <epan/to_str.h>
#include <wsutil/wmem/wmem_map.h>
#include <wsutil/wmem/wmem_interval_tree.h>

void proto_register_ltp(void);
void proto_reg_handoff_ltp(void);

static dissector_handle_t ltp_handle;

#define LTP_MIN_DATA_BUFFER  5

/// Unique session identifier
typedef struct {
	/// Session originator
	uint64_t orig_eng_id;
	/// Session number
	uint64_t sess_num;
} ltp_session_id_t;

/** Function to match the GHashFunc signature.
 */
static unsigned
ltp_session_id_hash(const void *ptr)
{
	const ltp_session_id_t *obj = ptr;
	return (
		g_int64_hash(&(obj->orig_eng_id))
		^ g_int64_hash(&(obj->sess_num))
	);
}

/** Function to match the GEqualFunc signature.
 */
static gboolean
ltp_session_id_equal(const void *a, const void *b)
{
	const ltp_session_id_t *aobj = a;
	const ltp_session_id_t *bobj = b;
	return (
		(aobj->orig_eng_id == bobj->orig_eng_id)
		&& (aobj->sess_num == bobj->sess_num)
	);
}

/// Reassembly function
static void *
ltp_session_new_key(const packet_info *pinfo _U_, const uint32_t id _U_,
		const void *data)
{
	const ltp_session_id_t *obj = data;
	ltp_session_id_t *key = g_slice_new(ltp_session_id_t);

	key->orig_eng_id = obj->orig_eng_id;
	key->sess_num = obj->sess_num;

	return (void *)key;
}

/// Reassembly function
static void
ltp_session_free_key(void *ptr)
{
	ltp_session_id_t *key = (ltp_session_id_t *)ptr;
	g_slice_free(ltp_session_id_t, key);
}

typedef struct {
	uint32_t frame_num;
	nstime_t abs_ts;
} ltp_frame_info_t;

static ltp_frame_info_t *
ltp_frame_info_new(const packet_info *pinfo)
{
	ltp_frame_info_t *obj = wmem_new(wmem_file_scope(), ltp_frame_info_t);
	obj->frame_num = pinfo->num;
	obj->abs_ts = pinfo->abs_ts;
	return obj;
}

/** Function to match the GCompareFunc signature.
 */
static int
ltp_frame_info_find_pinfo(const void *a, const void *b)
{
	const ltp_frame_info_t *aobj = a;
	const packet_info *bobj = b;
	if (aobj->frame_num < bobj->num) return -1;
	if (aobj->frame_num > bobj->num) return 1;
	return 0;
}

/// A session is an LTP conversation
typedef struct {
	/** Map from first-seen segment data ranges to data frame info (ltp_frame_info_t*) */
	wmem_itree_t *data_segs;
	/** Map from report ID (uint64_t) to tree (wmem_itree_t*) of
	 * first-seen segment data ranges to data frame info (ltp_frame_info_t*) */
	wmem_map_t *rpt_segs;
	/** Set after seeing EORP */
	uint64_t *red_size;
	/** Set after seeing EOB */
	uint64_t *block_size;

	/** Map from checkpoint ID (uint64_t) to wmem_list_t of frame info (ltp_frame_info_t*) */
	wmem_map_t *checkpoints;
	/** Map from checkpoint ID (uint64_t) to wmem_list_t of frame info (ltp_frame_info_t*) */
	wmem_map_t *chkp_acks;
	/** Map from report ID (uint64_t) to wmem_list_t of frame info (ltp_frame_info_t*) */
	wmem_map_t *reports;
	/** Map from report ID (uint64_t) to wmem_list_t of frame info (ltp_frame_info_t*) */
	wmem_map_t *rpt_acks;
	/** Map from report ID (uint64_t) to wmem_list_t of frame info (ltp_frame_info_t*) */
	wmem_map_t *rpt_datas;
	/** Map from cancel segment type (uint64_t) to wmem_list_t of frame info (ltp_frame_info_t*) */
	wmem_map_t *cancels;
	/** Map from cancel segment type (uint64_t) to wmem_list_t of frame info (ltp_frame_info_t*) */
	wmem_map_t *cancel_acks;
} ltp_session_data_t;

/// Tap info for single segment
typedef struct {
	/// Associated session context (optional)
	ltp_session_data_t *session;
	/// Segment type
	uint8_t seg_type;
	/// Session ID
	ltp_session_id_t sess_id;
	/// Text form of session name, scoped to file
	const char *sess_name;
	/// Full segment size
	unsigned seg_size;
	/// If non-zero, the size of the contained block
	unsigned block_size;
	/// For red data segment or report, is this original
	bool corr_orig;
} ltp_tap_info_t;

/* For reassembling LTP segments */
static reassembly_table ltp_reassembly_table;

/* Initialize the protocol and registered fields */
static int proto_ltp;

static int ltp_tap;

static bool ltp_reassemble_block = true;
static bool ltp_analyze_sequence = true;

/* LTP Header variables */
static int hf_ltp_version;
static int hf_ltp_type;
static int hf_ltp_session_name;
static int hf_ltp_session_orig;
static int hf_ltp_session_no;
static int hf_ltp_hdr_extn_cnt;
static int hf_ltp_trl_extn_cnt;

/* LTP Data Segment variable */
static int hf_ltp_data_clid;
static int hf_ltp_data_offset;
static int hf_ltp_data_length;
static int hf_ltp_data_chkp;
static int hf_ltp_data_chkp_rpt_ref;
static int hf_ltp_data_chkp_rpt_time;
static int hf_ltp_data_rpt;
static int hf_ltp_data_rpt_ref;
static int hf_ltp_data_rpt_time;
static int hf_ltp_data_sda_clid;
static int hf_ltp_data_clidata;
static int hf_ltp_data_retrans;
static int hf_ltp_data_clm_rpt;
static int hf_ltp_block_red_size;
static int hf_ltp_block_green_size;
static int hf_ltp_block_bundle_size;
static int hf_ltp_block_bundle_cnt;

/* LTP Report Segment variable */
static int hf_ltp_rpt_sno;
static int hf_ltp_rpt_sno_ack_ref;
static int hf_ltp_rpt_sno_ack_time;
static int hf_ltp_rpt_sno_data_ref;
static int hf_ltp_rpt_sno_data_time;
static int hf_ltp_rpt_chkp;
static int hf_ltp_rpt_chkp_ref;
static int hf_ltp_rpt_chkp_time;
static int hf_ltp_rpt_ub;
static int hf_ltp_rpt_lb;
static int hf_ltp_rpt_len;
static int hf_ltp_rpt_retrans;
static int hf_ltp_rpt_clm_cnt;
static int hf_ltp_rpt_clm_off;
static int hf_ltp_rpt_clm_len;
static int hf_ltp_rpt_clm_fst;
static int hf_ltp_rpt_clm_lst;
static int hf_ltp_rpt_clm_ref;
static int hf_ltp_rpt_gap;
static int hf_ltp_rpt_gap_fst;
static int hf_ltp_rpt_gap_lst;
static int hf_ltp_rpt_gap_ref;
static int hf_ltp_rpt_gap_total;

/* LTP Report Ack Segment Variable */
static int hf_ltp_rpt_ack_sno;
static int hf_ltp_rpt_ack_dupe_ref;
static int hf_ltp_rpt_ack_ref;
static int hf_ltp_rpt_ack_time;

/* LTP Session Management Segment Variable */
static int hf_ltp_cancel_code;
static int hf_ltp_cancel_dupe_ref;
static int hf_ltp_cancel_ref;
static int hf_ltp_cancel_time;

static int hf_ltp_cancel_ack;
static int hf_ltp_cancel_ack_dupe_ref;
static int hf_ltp_cancel_ack_ref;
static int hf_ltp_cancel_ack_time;

/* LTP Header Extension Segment */
static int hf_ltp_hdr_extn_tag;
static int hf_ltp_hdr_extn_len;
static int hf_ltp_hdr_extn_val;

/* LTP Trailer Extension Segment */
static int hf_ltp_trl_extn_tag;
static int hf_ltp_trl_extn_len;
static int hf_ltp_trl_extn_val;

/*LTP reassembly */
static int hf_ltp_fragments;
static int hf_ltp_fragment;
static int hf_ltp_fragment_overlap;
static int hf_ltp_fragment_overlap_conflicts;
static int hf_ltp_fragment_multiple_tails;
static int hf_ltp_fragment_too_long_fragment;
static int hf_ltp_fragment_error;
static int hf_ltp_fragment_count;
static int hf_ltp_reassembled_in;
static int hf_ltp_reassembled_length;

static expert_field ei_ltp_mal_reception_claim;
static expert_field ei_ltp_sdnv_length;
static expert_field ei_ltp_sno_larger_than_ccsds;
static expert_field ei_ltp_report_async;
static expert_field ei_ltp_data_chkp_norpt;
static expert_field ei_ltp_data_rptno_norpt;
static expert_field ei_ltp_rpt_noack;
static expert_field ei_ltp_rpt_nochkp;
static expert_field ei_ltp_rpt_ack_norpt;
static expert_field ei_ltp_cancel_noack;
static expert_field ei_ltp_cancel_ack_nocancel;

static dissector_handle_t bundle_handle;

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

static const val64_string client_service_id_info[] = {
	{0x01, "Bundle Protocol"},
	{0x02, "CCSDS LTP Service Data Aggregation"},
	{0, NULL}
};

#define LTP_PORT    1113

/* Initialize the subtree pointers */
static int ett_ltp;
static int ett_ltp_hdr;
static int ett_hdr_session;
static int ett_hdr_extn;
static int ett_frame_ref;
static int ett_data_segm;
static int ett_block;
static int ett_rpt_segm;
static int ett_rpt_clm;
static int ett_rpt_gap;
static int ett_rpt_ack_segm;
static int ett_session_mgmt;
static int ett_trl_extn;
static int ett_ltp_fragment;
static int ett_ltp_fragments;

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
	/* Reassembled data field */
	NULL,
	/*Tag*/
	"LTP fragments"
};

/** Add a cross-reference value source.
 * @param map The map to add to.
 * @param ref_num The cross-reference value.
 * @param pinfo The source frame of the value.
 */
static void
ltp_ref_src(wmem_map_t *map, uint64_t ref_num, const packet_info *pinfo)
{
	wmem_list_t *found = wmem_map_lookup(map, &ref_num);
	if (!found)
	{
		uint64_t *key = wmem_new(wmem_file_scope(), uint64_t);
		*key = ref_num;
		found = wmem_list_new(wmem_file_scope());
		wmem_map_insert(map, key, found);
	}

	if (wmem_list_find_custom(found, pinfo, ltp_frame_info_find_pinfo))
	{
		return;
	}
	ltp_frame_info_t *val = ltp_frame_info_new(pinfo);
	wmem_list_append(found, val);
}

/** Show cross-reference value sources as tree items.
 * @param map The map to search in.
 * @param ref_num The cross-reference value.
 * @param pinfo The frame using the reference (to avoid duplicates).
 * @param tree The tree to show references under.
 * @param hf_ref The field index to add source frame numbers.
 * @param hf_time The field index to report time differences.
 * @param tap Non-null if this use is an acknowledgement of an earlier segment and should
 * be later in time than the referenced segment.
 */
static void
ltp_ref_use(wmem_map_t *map, uint64_t ref_num, packet_info *pinfo, proto_tree *tree, int hf_ref, expert_field *ei_notfound, int hf_time, ltp_tap_info_t *tap)
{
	const wmem_list_t *found = wmem_map_lookup(map, &ref_num);
	if (!found)
	{
		if (ei_notfound)
		{
			expert_add_info(pinfo, proto_tree_get_parent(tree), ei_notfound);
		}
		return;
	}

	for (wmem_list_frame_t *it = wmem_list_head(found); it != NULL;
		it = wmem_list_frame_next(it))
	{
		const ltp_frame_info_t *frame_refd = wmem_list_frame_data(it);
		if (frame_refd->frame_num == pinfo->num)
		{
			continue;
		}
		PROTO_ITEM_SET_GENERATED(
			proto_tree_add_uint(tree, hf_ref, NULL, 0, 0, frame_refd->frame_num)
		);

		// tap is present for responses, where the other frame is earlier
		const nstime_t *ta, *tb;
		if (tap)
		{
			tb = &(pinfo->abs_ts);
			ta = &(frame_refd->abs_ts);
		}
		else
		{
			tb = &(frame_refd->abs_ts);
			ta = &(pinfo->abs_ts);
		}
		nstime_t td;
		nstime_delta(&td, tb, ta);

		if (hf_time >= 0)
		{
			PROTO_ITEM_SET_GENERATED(
				proto_tree_add_time(tree, hf_time, NULL, 0, 0, &td)
			);
		}
	}
}

static proto_item *
add_sdnv64_to_tree(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, int offset, int hf_sdnv, uint64_t *retval, int *lenretval)
{
	proto_item *ti;
	ti = proto_tree_add_item_ret_varint(tree, hf_sdnv, tvb, offset, -1, ENC_VARINT_SDNV, retval, lenretval);

	if (*lenretval <= 0) {
		expert_add_info(pinfo, ti, &ei_ltp_sdnv_length);
	}
	return ti;
}

/// Summary of a data segment tree item
typedef struct {
	/// Data segment packet info
	packet_info *pinfo;
	/// Tree of the data segment
	proto_tree *ltp_data_tree;
	/// The first offset of this segment
	uint64_t data_fst;
	/// The last offset of this segment
	uint64_t data_lst;
} ltp_data_seg_info_t;

static void
ltp_data_seg_find_report(void *key _U_, void *value, void *user_data)
{
	wmem_itree_t *rpt_clms = value;
	const ltp_data_seg_info_t *data_seg = user_data;
	if (!(data_seg->data_fst <= data_seg->data_lst))
	{
		return;
	}

	wmem_list_t *found = wmem_itree_find_intervals(rpt_clms, data_seg->pinfo->pool, data_seg->data_fst, data_seg->data_lst);
	for (wmem_list_frame_t *it = wmem_list_head(found); it != NULL;
		it = wmem_list_frame_next(it))
	{
		const ltp_frame_info_t *frame = wmem_list_frame_data(it);
		// report must be after this data segment
		if (frame->frame_num < data_seg->pinfo->num)
		{
			continue;
		}
		PROTO_ITEM_SET_GENERATED(
			proto_tree_add_uint(data_seg->ltp_data_tree, hf_ltp_data_clm_rpt, NULL, 0, 0, frame->frame_num)
		);
	}

}

static int
dissect_data_segment(proto_tree *ltp_tree, tvbuff_t *tvb,packet_info *pinfo,int frame_offset,
		     int *data_len, ltp_tap_info_t *tap)
{
	ltp_session_data_t *session = tap->session;
	int ltp_type = tap->seg_type;
	uint64_t client_id;
	uint64_t data_offset;
	uint64_t data_length;
	uint64_t chkp_sno = 0;
	uint64_t rpt_sno = 0;
	uint64_t sda_client_id = 0;

	unsigned segment_size = 0;

	int sdnv_length;

	proto_tree *ltp_data_tree;
	proto_item *ti;

	fragment_head *frag_msg = NULL;

	tvbuff_t *new_tvb = NULL;

	/* Create a subtree for data segment and add the other fields under it */
	ltp_data_tree = proto_tree_add_subtree(ltp_tree, tvb, frame_offset, tvb_captured_length_remaining(tvb, frame_offset), ett_data_segm, NULL, "Data Segment");

	/* Client ID - 0 = Bundle Protocol, 1 = CCSDS LTP Service Data Aggregation */
	add_sdnv64_to_tree(ltp_data_tree, tvb, pinfo, frame_offset, hf_ltp_data_clid, &client_id, &sdnv_length);
	frame_offset += sdnv_length;
	segment_size += sdnv_length;

	/* data segment offset */
	add_sdnv64_to_tree(ltp_data_tree, tvb, pinfo, frame_offset, hf_ltp_data_offset, &data_offset, &sdnv_length);
	if (sdnv_length > 0) {
		frame_offset += sdnv_length;
		segment_size += sdnv_length;
	} else {
		return 0;
	}

	/* data segment length */
	add_sdnv64_to_tree(ltp_data_tree, tvb, pinfo, frame_offset, hf_ltp_data_length, &data_length, &sdnv_length);
	if (sdnv_length > 0) {
		frame_offset += sdnv_length;
		segment_size += sdnv_length;

		/* add in the data length also */
		segment_size += (unsigned int) data_length;
	} else {
		return 0;
	}
	*data_len = (int) data_length;

	const uint64_t data_fst = data_offset;
	const uint64_t data_lst = data_offset + data_length - 1;
	bool newdata = true;
	if (ltp_analyze_sequence && session)
	{
		if (data_fst <= data_lst)
		{
			wmem_list_t *found = wmem_itree_find_intervals(session->data_segs, pinfo->pool, data_fst, data_lst);
			for (wmem_list_frame_t *it = wmem_list_head(found); it != NULL;
				it = wmem_list_frame_next(it))
			{
				const ltp_frame_info_t *frame = wmem_list_frame_data(it);
				if (frame->frame_num == pinfo->num)
				{
					continue;
				}
				PROTO_ITEM_SET_GENERATED(
					proto_tree_add_uint(ltp_data_tree, hf_ltp_data_retrans, NULL, 0, 0, frame->frame_num)
				);
				newdata = false;
			}

			if (newdata)
			{
				ltp_frame_info_t *val = ltp_frame_info_new(pinfo);
				wmem_itree_insert(session->data_segs, data_fst, data_lst, val);
			}
		}

		ltp_data_seg_info_t data_seg_info;
		data_seg_info.pinfo = pinfo;
		data_seg_info.ltp_data_tree = ltp_data_tree;
		data_seg_info.data_fst = data_fst;
		data_seg_info.data_lst = data_lst;
		wmem_map_foreach(session->rpt_segs, ltp_data_seg_find_report, &data_seg_info);

	}
	tap->corr_orig = newdata;

	if (ltp_type != 0 && ltp_type < 4)
	{
		/* checkpoint serial number - 32 bits per CCSDS */
		ti = add_sdnv64_to_tree(ltp_data_tree, tvb, pinfo, frame_offset, hf_ltp_data_chkp, &chkp_sno, &sdnv_length);
		if (sdnv_length > 0) {
			frame_offset += sdnv_length;
			segment_size += sdnv_length;

			if (chkp_sno > 4294967295U) {
				/* just a warning - continue processing */
				expert_add_info(pinfo, ti, &ei_ltp_sno_larger_than_ccsds);
			}
		} else {
			return 0;
		}
		if (ltp_analyze_sequence && session)
		{
			proto_tree *tree_chkp_sno = proto_item_add_subtree(ti, ett_frame_ref);
			ltp_ref_src(session->checkpoints, chkp_sno, pinfo);
			ltp_ref_use(session->chkp_acks, chkp_sno, pinfo, tree_chkp_sno, hf_ltp_data_chkp_rpt_ref, &ei_ltp_data_chkp_norpt, hf_ltp_data_chkp_rpt_time, NULL);
		}

		/* report serial number - 32 bits per CCSDS */
		ti = add_sdnv64_to_tree(ltp_data_tree, tvb, pinfo, frame_offset, hf_ltp_data_rpt, &rpt_sno, &sdnv_length);
		if (sdnv_length > 0) {
			frame_offset += sdnv_length;
			segment_size += sdnv_length;

			if (rpt_sno > 4294967295U) {
				/* just a warning - continue processing */
				expert_add_info(pinfo, ti, &ei_ltp_sno_larger_than_ccsds);
			}
		} else {
			return 0;
		}
		if (ltp_analyze_sequence && session && (rpt_sno != 0))
		{
			ltp_ref_src(session->rpt_datas, rpt_sno, pinfo);
			ltp_ref_use(session->reports, rpt_sno, pinfo, proto_item_add_subtree(ti, ett_frame_ref), hf_ltp_data_rpt_ref, &ei_ltp_data_rptno_norpt, hf_ltp_data_rpt_time, tap);
		}
	}
	const bool is_green = (ltp_type >= 4) && (ltp_type <= 7);
	const bool is_eorp = (ltp_type == 2) || (ltp_type == 3);
	const bool is_eob = (ltp_type == 3) || (ltp_type == 7);
	if (session)
	{
		if ((is_green && (data_offset == 0)) && !(session->red_size))
		{
			session->red_size = wmem_new(wmem_file_scope(), uint64_t);
			*(session->red_size) = 0;
		}
		if (is_eorp && !(session->red_size))
		{
			session->red_size = wmem_new(wmem_file_scope(), uint64_t);
			*(session->red_size) = data_offset + data_length;
		}
		if (is_eob && !(session->block_size))
		{
			session->block_size = wmem_new(wmem_file_scope(), uint64_t);
			*(session->block_size) = data_offset + data_length;
		}
	}

	proto_tree_add_item(ltp_data_tree, hf_ltp_data_clidata, tvb, frame_offset, (int) data_length, ENC_NA);

	col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
			"range %" G_GINT64_MODIFIER "u-%" G_GINT64_MODIFIER "u",
			data_fst, data_lst);

	if (ltp_reassemble_block)
	{
		frag_msg = fragment_add_check(
			&ltp_reassembly_table,
			tvb, frame_offset, pinfo, 0, &(tap->sess_id),
			(uint32_t)data_offset, (uint32_t)data_length, !is_eob
		);
	}
	if(frag_msg)
	{
		/* Checking if the segment is completely reassembled */
		if(!(frag_msg->flags & FD_PARTIAL_REASSEMBLY))
		{
			/* if the segment has not been fragmented, then no reassembly is needed */
			if(is_eob && data_offset == 0)
			{
				new_tvb = tvb_new_subset_length(tvb, frame_offset, (int) data_length);
			}
			else
			{
				new_tvb = process_reassembled_data(tvb, frame_offset, pinfo, "Reassembled LTP Block",
									frag_msg, &ltp_frag_items,NULL, ltp_tree);

			}
		}
	}

	if(new_tvb)
	{
		uint64_t data_count = 0;
		int parse_length = tvb_reported_length(new_tvb);
		int parse_offset = 0;
		proto_tree *root_tree = proto_tree_get_parent_tree(ltp_tree);

		/* Data associated with the full block, not just this segment */
		proto_tree *block_tree = proto_tree_add_subtree_format(ltp_tree, new_tvb, 0, -1, ett_block, NULL,
				"Block, size: %d bytes", parse_length);
		tap->block_size = parse_length;

		if (session && session->red_size && session->block_size)
		{
			uint64_t red_size = *(session->red_size);
			uint64_t green_size = *(session->block_size) - *(session->red_size);
			PROTO_ITEM_SET_GENERATED(
				proto_tree_add_uint64(block_tree, hf_ltp_block_red_size, new_tvb, 0, (int)red_size, red_size)
			);
			PROTO_ITEM_SET_GENERATED(
				proto_tree_add_uint64(block_tree, hf_ltp_block_green_size, new_tvb, (int)red_size, (int)green_size, green_size)
			);
		}

		while(parse_offset < parse_length)
		{
			int bundle_size;
			tvbuff_t *datatvb;

			if (client_id == 2) {
				add_sdnv64_to_tree(ltp_data_tree, tvb, pinfo, frame_offset+parse_offset, hf_ltp_data_sda_clid, &sda_client_id, &sdnv_length);
				parse_offset += sdnv_length;
				if (parse_offset == parse_length) {
					col_set_str(pinfo->cinfo, COL_INFO, "CCSDS LTP SDA Protocol Error");
					return 0;	/* Give up*/
				}
			}

			datatvb = tvb_new_subset_remaining(new_tvb, parse_offset);
			bundle_size = call_dissector(bundle_handle, datatvb, pinfo, root_tree);
			if(bundle_size == 0) {  /*Couldn't parse bundle*/
				col_set_str(pinfo->cinfo, COL_INFO, "Dissection Failed");
				return 0;           /*Give up*/
			}
			proto_tree_add_uint64(block_tree, hf_ltp_block_bundle_size, datatvb, 0, bundle_size, bundle_size);

			parse_offset += bundle_size;
			data_count++;
		}
		PROTO_ITEM_SET_GENERATED(
			proto_tree_add_uint64(block_tree, hf_ltp_block_bundle_cnt, new_tvb, 0, parse_offset, data_count)
		);
	}
	else
	{
		if(ltp_reassemble_block && frag_msg && (frag_msg->flags & FD_DEFRAGMENTED))
		{
			col_append_frame_number(pinfo, COL_INFO, " [Reassembled in #%d] ",frag_msg->reassembled_in);
		}
		else if (!newdata)
		{
			col_append_str(pinfo->cinfo, COL_INFO, " [Retransmission] ");
		}
		else if (ltp_reassemble_block)
		{
			col_append_str(pinfo->cinfo, COL_INFO, " [Unfinished LTP Block] ");
		}
	}

	return segment_size;
}


static void
ltp_check_reception_gap(proto_tree *ltp_rpt_tree, packet_info *pinfo,
		ltp_session_data_t *session, uint64_t prec_lst, uint64_t next_fst,
		int *gap_count, uint64_t *gap_total) {
	const uint64_t gap_len = next_fst - (prec_lst + 1);
	if (gap_len <= 0) {
		return;
	}
	proto_item *gap_item = proto_tree_add_uint64_format(ltp_rpt_tree, hf_ltp_rpt_gap, NULL, 0, 0, gap_len,
		"Reception gap: %" PRIu64 "-%" PRIu64 " (%" PRIu64 " bytes)",
		prec_lst + 1, next_fst - 1, gap_len
	);
	PROTO_ITEM_SET_GENERATED(gap_item);
	*gap_count += 1;
	*gap_total += gap_len;

	if (ltp_analyze_sequence && session)
	{
		proto_tree *gap_tree = proto_item_add_subtree(gap_item, ett_rpt_gap);

		const uint64_t gap_fst = prec_lst + 1;
		const uint64_t gap_lst = next_fst - 1;
		PROTO_ITEM_SET_GENERATED(
			proto_tree_add_uint64(gap_tree, hf_ltp_rpt_gap_fst, NULL, 0, 0, gap_fst)
		);
		PROTO_ITEM_SET_GENERATED(
			proto_tree_add_uint64(gap_tree, hf_ltp_rpt_gap_lst, NULL, 0, 0, gap_lst)
		);

		wmem_list_t *found = wmem_itree_find_intervals(session->data_segs, pinfo->pool, gap_fst, gap_lst);
		for (wmem_list_frame_t *it = wmem_list_head(found); it != NULL;
			it = wmem_list_frame_next(it))
		{
			const ltp_frame_info_t *frame = wmem_list_frame_data(it);
			if (frame->frame_num > pinfo->num)
			{
				continue;
			}
			PROTO_ITEM_SET_GENERATED(
				proto_tree_add_uint(gap_tree, hf_ltp_rpt_gap_ref, NULL, 0, 0, frame->frame_num)
			);
		}
	}
}


static int
dissect_report_segment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ltp_tree, int frame_offset, ltp_tap_info_t *tap) {
	ltp_session_data_t *session = tap->session;
	int64_t rpt_sno;
	int64_t chkp_sno;
	uint64_t upper_bound;
	uint64_t lower_bound;
	uint64_t rcpt_clm_cnt;
	uint64_t offset;
	uint64_t length;
	uint64_t clm_fst, clm_lst;

	int rpt_sno_size;
	int chkp_sno_size;
	int upper_bound_size;
	int lower_bound_size;
	int rcpt_clm_cnt_size;
	int offset_size;
	int length_size;

	int segment_offset = 0;
	int gap_count = 0;
	uint64_t gap_total = 0;

	proto_item *ltp_rpt_item;
	proto_item *ltp_rpt_clm_cnt;
	proto_item *ltp_rpt_clm_item;
	proto_item *item_rpt_sno, *item_chkp_sno;

	proto_tree *ltp_rpt_tree;
	proto_tree *ltp_rpt_clm_tree;

	/* Create the subtree for report segment under the main LTP tree and all the report segment fields under it */
	ltp_rpt_tree = proto_tree_add_subtree(ltp_tree, tvb, frame_offset, -1, ett_rpt_segm, &ltp_rpt_item, "Report Segment");

	/* Extract the report segment info */
	item_rpt_sno = add_sdnv64_to_tree(ltp_rpt_tree, tvb, pinfo, frame_offset + segment_offset, hf_ltp_rpt_sno, &rpt_sno, &rpt_sno_size);
	segment_offset += rpt_sno_size;
	if (ltp_analyze_sequence && session)
	{
		proto_tree *tree_rpt_sno = proto_item_add_subtree(item_rpt_sno, ett_frame_ref);
		ltp_ref_src(session->reports, rpt_sno, pinfo);
		ltp_ref_use(session->rpt_acks, rpt_sno, pinfo, tree_rpt_sno, hf_ltp_rpt_sno_ack_ref, &ei_ltp_rpt_noack, hf_ltp_rpt_sno_ack_time, NULL);
		ltp_ref_use(session->rpt_datas, rpt_sno, pinfo, tree_rpt_sno, hf_ltp_rpt_sno_data_ref, NULL, hf_ltp_rpt_sno_data_time, NULL);
	}

	item_chkp_sno = add_sdnv64_to_tree(ltp_rpt_tree, tvb, pinfo, frame_offset + segment_offset, hf_ltp_rpt_chkp, &chkp_sno, &chkp_sno_size);
	segment_offset += chkp_sno_size;
	if (ltp_analyze_sequence && session)
	{
		if (chkp_sno == 0)
		{
			expert_add_info(pinfo, item_chkp_sno, &ei_ltp_report_async);
		}
		else
		{
			proto_tree *tree_chkp_sno = proto_item_add_subtree(item_chkp_sno, ett_frame_ref);
			ltp_ref_src(session->chkp_acks, chkp_sno, pinfo);
			ltp_ref_use(session->checkpoints, chkp_sno, pinfo, tree_chkp_sno, hf_ltp_rpt_chkp_ref, &ei_ltp_rpt_nochkp, hf_ltp_rpt_chkp_time, tap);
		}
	}

	add_sdnv64_to_tree(ltp_rpt_tree, tvb, pinfo, frame_offset + segment_offset, hf_ltp_rpt_ub, &upper_bound, &upper_bound_size);
	segment_offset += upper_bound_size;

	add_sdnv64_to_tree(ltp_rpt_tree, tvb, pinfo, frame_offset + segment_offset, hf_ltp_rpt_lb, &lower_bound, &lower_bound_size);
	segment_offset += lower_bound_size;

	PROTO_ITEM_SET_GENERATED(
		proto_tree_add_uint64(ltp_rpt_tree, hf_ltp_rpt_len, tvb, 0, 0, upper_bound - lower_bound)
	);
	col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
		"range %" G_GINT64_MODIFIER "u-%" G_GINT64_MODIFIER "u",
		lower_bound, upper_bound-1);

	bool newdata = true;
	if (ltp_analyze_sequence && session)
	{
		const uint64_t data_fst = lower_bound;
		const uint64_t data_lst = upper_bound - 1;

		// All segments for a single report ID
		wmem_itree_t *rpt = wmem_map_lookup(session->rpt_segs, &rpt_sno);
		if (!rpt)
		{
			uint64_t *key = wmem_new(wmem_file_scope(), uint64_t);
			*key = rpt_sno;
			rpt = wmem_itree_new(wmem_file_scope());
			wmem_map_insert(session->rpt_segs, key, rpt);
		}

		if (data_fst <= data_lst) {
			wmem_list_t *found = wmem_itree_find_intervals(rpt, pinfo->pool, data_fst, data_lst);
			for (wmem_list_frame_t *it = wmem_list_head(found); it != NULL;
				it = wmem_list_frame_next(it))
			{
				const ltp_frame_info_t *frame = wmem_list_frame_data(it);
				if (frame->frame_num == pinfo->num)
				{
					continue;
				}
				PROTO_ITEM_SET_GENERATED(
					proto_tree_add_uint(ltp_rpt_tree, hf_ltp_rpt_retrans, NULL, 0, 0, frame->frame_num)
				);
				newdata = false;
			}

			if (newdata)
			{
				ltp_frame_info_t *val = ltp_frame_info_new(pinfo);
				wmem_itree_insert(rpt, data_fst, data_lst, val);
			}
		}
	}
	tap->corr_orig = newdata;

	ltp_rpt_clm_cnt = add_sdnv64_to_tree(ltp_rpt_tree, tvb, pinfo, frame_offset + segment_offset, hf_ltp_rpt_clm_cnt, &rcpt_clm_cnt, &rcpt_clm_cnt_size);
	segment_offset += rcpt_clm_cnt_size;
	/* Each reception claim is at least 2 bytes, so if the count is larger than the
	 * max number of claims we can possibly squeeze into the remaining tvbuff, then
	 * the packet is malformed.
	 */
	if (rcpt_clm_cnt > (uint64_t)tvb_captured_length_remaining(tvb, frame_offset + segment_offset) / 2) {
		expert_add_info_format(pinfo, ltp_rpt_clm_cnt, &ei_ltp_mal_reception_claim,
				"Reception claim count impossibly large: %" G_GINT64_MODIFIER "d > %d", rcpt_clm_cnt,
				tvb_captured_length_remaining(tvb, frame_offset + segment_offset) / 2);
		return 0;
	}

	clm_lst = lower_bound - 1;

	/* There can be multiple reception claims in the same report segment */
	for(uint64_t ix = 0; ix < rcpt_clm_cnt; ix++){
		/* Peek at the offset to see if there is a preceding gap */
		tvb_get_varint(tvb, frame_offset + segment_offset, FT_VARINT_MAX_LEN, &offset, ENC_VARINT_SDNV);
		clm_fst = lower_bound + offset;
		ltp_check_reception_gap(ltp_rpt_tree, pinfo, session, clm_lst, clm_fst, &gap_count, &gap_total);

		ltp_rpt_clm_tree = proto_tree_add_subtree(ltp_rpt_tree, tvb, frame_offset + segment_offset, -1, ett_rpt_clm, &ltp_rpt_clm_item, "Reception claim");

		add_sdnv64_to_tree(ltp_rpt_clm_tree, tvb, pinfo, frame_offset + segment_offset, hf_ltp_rpt_clm_off, &offset, &offset_size);
		segment_offset += offset_size;

		add_sdnv64_to_tree(ltp_rpt_clm_tree, tvb, pinfo, frame_offset + segment_offset, hf_ltp_rpt_clm_len, &length, &length_size);
		segment_offset += length_size;

		PROTO_ITEM_SET_GENERATED(
			proto_tree_add_uint64(ltp_rpt_clm_tree, hf_ltp_rpt_clm_fst, tvb, 0, 0, clm_fst)
		);
		clm_lst = clm_fst + length - 1;
		PROTO_ITEM_SET_GENERATED(
			proto_tree_add_uint64(ltp_rpt_clm_tree, hf_ltp_rpt_clm_lst, tvb, 0, 0, clm_lst)
		);

		proto_item_append_text(ltp_rpt_clm_item,
			": %" PRIu64 "-%" PRIu64 " (%" PRIu64 " bytes)",
			clm_fst, clm_lst, length
		);
		proto_item_set_end(ltp_rpt_clm_item, tvb, frame_offset + segment_offset);

		if (ltp_analyze_sequence && session && (clm_fst <= clm_lst))
		{
			wmem_list_t *found = wmem_itree_find_intervals(session->data_segs, pinfo->pool, clm_fst, clm_lst);
			for (wmem_list_frame_t *it = wmem_list_head(found); it != NULL;
				it = wmem_list_frame_next(it))
			{
				const ltp_frame_info_t *frame = wmem_list_frame_data(it);
				if (frame->frame_num > pinfo->num)
				{
					continue;
				}
				PROTO_ITEM_SET_GENERATED(
					proto_tree_add_uint(ltp_rpt_clm_tree, hf_ltp_rpt_clm_ref, NULL, 0, 0, frame->frame_num)
				);
			}
		}
	}
	proto_item_set_end(ltp_rpt_item, tvb, frame_offset + segment_offset);

	ltp_check_reception_gap(ltp_rpt_tree, pinfo, session, clm_lst, upper_bound, &gap_count, &gap_total);
	PROTO_ITEM_SET_GENERATED(
		proto_tree_add_uint64(ltp_rpt_tree, hf_ltp_rpt_gap_total, NULL, 0, 0, gap_total)
	);
	col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "gaps: %d, gap total: %"PRIu64, gap_count, gap_total);

	return segment_offset;
}


static int
dissect_report_ack_segment(proto_tree *ltp_tree, tvbuff_t *tvb, packet_info *pinfo, int frame_offset, ltp_tap_info_t *tap){
	ltp_session_data_t *session = tap->session;
	int64_t rpt_sno;
	int rpt_sno_size;
	int segment_offset = 0;

	proto_item *ltp_rpt_ack_item, *item_rpt_sno;
	proto_tree *ltp_rpt_ack_tree;

	/* Creating tree for the report ack segment */
	ltp_rpt_ack_tree = proto_tree_add_subtree(ltp_tree, tvb,frame_offset, -1,
												ett_rpt_ack_segm, &ltp_rpt_ack_item, "Report Ack Segment");

	/* Extracting receipt serial number info */
	item_rpt_sno = add_sdnv64_to_tree(ltp_rpt_ack_tree, tvb, pinfo, frame_offset + segment_offset, hf_ltp_rpt_ack_sno, &rpt_sno, &rpt_sno_size);
	segment_offset += rpt_sno_size;

	proto_item_set_end(ltp_rpt_ack_item, tvb, frame_offset + segment_offset);

	if (ltp_analyze_sequence && session)
	{
		proto_tree *tree_rpt_sno = proto_item_add_subtree(item_rpt_sno, ett_frame_ref);
		ltp_ref_src(session->rpt_acks, rpt_sno, pinfo);
		ltp_ref_use(session->rpt_acks, rpt_sno, pinfo, tree_rpt_sno, hf_ltp_rpt_ack_dupe_ref, NULL, -1, NULL);
		ltp_ref_use(session->reports, rpt_sno, pinfo, tree_rpt_sno, hf_ltp_rpt_ack_ref, &ei_ltp_rpt_ack_norpt, hf_ltp_rpt_ack_time, tap);
	}

	return segment_offset;
}


static int
dissect_cancel_segment(proto_tree *ltp_tree, tvbuff_t *tvb, packet_info *pinfo, int frame_offset, ltp_tap_info_t *tap){
	ltp_session_data_t *session = tap->session;

	/* The cancel segment has only one byte, which contains the reason code. */
	uint8_t reason_code = tvb_get_uint8(tvb,frame_offset);

	/* Creating tree for the cancel segment */
	proto_tree *tree_cancel = proto_tree_add_subtree(ltp_tree, tvb,frame_offset, 1, ett_session_mgmt, NULL, "Cancel Segment");

	proto_tree_add_uint(tree_cancel, hf_ltp_cancel_code, tvb, frame_offset, 1, reason_code);

	if (ltp_analyze_sequence && session)
	{
		const uint64_t cancel_type = tap->seg_type;
		ltp_ref_src(session->cancels, cancel_type, pinfo);
		ltp_ref_use(session->cancels, cancel_type, pinfo, tree_cancel, hf_ltp_cancel_dupe_ref, NULL, -1, NULL);
		ltp_ref_use(session->cancel_acks, cancel_type, pinfo, tree_cancel, hf_ltp_cancel_ref, &ei_ltp_cancel_noack, hf_ltp_cancel_time, NULL);
	}

	return 1;
}


static int
dissect_cancel_ack_segment(proto_tree *ltp_tree, tvbuff_t *tvb, packet_info *pinfo, int frame_offset _U_, ltp_tap_info_t *tap){
	ltp_session_data_t *session = tap->session;
	proto_item *item_ack = proto_tree_add_item(ltp_tree, hf_ltp_cancel_ack, tvb, 0, 0, ENC_NA);
	proto_tree *tree_ack = proto_item_add_subtree(item_ack, ett_session_mgmt);

	if (ltp_analyze_sequence && session)
	{
		const uint64_t cancel_type = tap->seg_type - 1;
		ltp_ref_src(session->cancel_acks, cancel_type, pinfo);
		ltp_ref_use(session->cancel_acks, cancel_type, pinfo, tree_ack, hf_ltp_cancel_ack_dupe_ref, NULL, -1, NULL);
		ltp_ref_use(session->cancels, cancel_type, pinfo, tree_ack, hf_ltp_cancel_ack_ref, &ei_ltp_cancel_ack_nocancel, hf_ltp_cancel_ack_time, tap);
	}

	return 0;
}

static int
dissect_header_extn(proto_tree *ltp_tree, tvbuff_t *tvb, packet_info *pinfo, int frame_offset,int hdr_extn_cnt){
	int64_t length;
	int length_size;

	int extn_offset = 0;

	proto_item *ltp_hdr_extn_item;
	proto_tree *ltp_hdr_extn_tree;

	ltp_hdr_extn_tree = proto_tree_add_subtree(ltp_tree, tvb,frame_offset, -1, ett_hdr_extn, &ltp_hdr_extn_item, "Header Extension");

	for(int ix = 0; ix < hdr_extn_cnt; ix++){
		/* From RFC-5326, the total length of the Header Extension Tree will be length of the following:
			a) Extension type length (1 byte)
			b) The length of the 'length' field (as defined by the SDNV which handles dynamic size)
			c) The length of the value field which is the decoded length */
		proto_tree_add_item(ltp_hdr_extn_tree, hf_ltp_hdr_extn_tag, tvb, frame_offset + extn_offset, 1, ENC_NA);
		extn_offset += 1;

		add_sdnv64_to_tree(ltp_hdr_extn_tree, tvb, pinfo, frame_offset + extn_offset, hf_ltp_hdr_extn_len, &length, &length_size);
		extn_offset += length_size;

		proto_tree_add_item(ltp_hdr_extn_tree, hf_ltp_hdr_extn_val, tvb, frame_offset + extn_offset, (int)length, ENC_NA);
		extn_offset += (int)length;
	}

	proto_item_set_end(ltp_hdr_extn_item, tvb, frame_offset + extn_offset);
	return extn_offset;
}

static int
dissect_trailer_extn(proto_tree *ltp_tree, tvbuff_t *tvb, packet_info *pinfo, int frame_offset,int trl_extn_cnt){
	int64_t length;
	int length_size;

	int extn_offset = 0;

	proto_item *ltp_trl_extn_item;
	proto_tree *ltp_trl_extn_tree;

	ltp_trl_extn_tree = proto_tree_add_subtree(ltp_tree, tvb,frame_offset, -1, ett_trl_extn, &ltp_trl_extn_item, "Trailer Extension");

	for(int ix = 0; ix < trl_extn_cnt; ix++){
		proto_tree_add_item(ltp_trl_extn_tree, hf_ltp_trl_extn_tag, tvb, frame_offset + extn_offset, 1, ENC_NA);
		frame_offset += 1;

		add_sdnv64_to_tree(ltp_trl_extn_tree, tvb, pinfo, frame_offset + extn_offset, hf_ltp_hdr_extn_len, &length, &length_size);
		frame_offset += length_size;

		proto_tree_add_item(ltp_trl_extn_tree, hf_ltp_trl_extn_val, tvb, frame_offset + extn_offset, (int)length, ENC_NA);
		frame_offset += (int)length;
	}

	proto_item_set_end(ltp_trl_extn_item, tvb, frame_offset + extn_offset);
	return extn_offset;
}


static int
dissect_ltp_segment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti = NULL;
	proto_tree *ltp_tree = NULL;
	int frame_offset = offset;
	int segment_offset = 0;
	int data_len = 0;

	int     ltp_type;
	uint64_t bitsval;
	int     hdr_extn_cnt;
	int     trl_extn_cnt;

	int engine_id_size;
	int session_num_size;
	const char *sess_name;
	ltp_session_data_t *session = NULL;

	proto_tree *ltp_header_tree = NULL;
	proto_item *ltp_header_item = NULL;
	proto_tree *ltp_session_tree = NULL;
	proto_item *ltp_session_item = NULL;

	/* Check that there's enough data */
	if(tvb_reported_length(tvb) < LTP_MIN_DATA_BUFFER){
		return 0;
	}

	/* Extract all the header info from the packet */
	ti = proto_tree_add_item(tree, proto_ltp, tvb, offset, -1, ENC_NA);
	ltp_tree = proto_item_add_subtree(ti, ett_ltp);

	ltp_tap_info_t *tap = wmem_new0(pinfo->pool, ltp_tap_info_t);

	/* Adding Header Subtree */
	ltp_header_tree = proto_tree_add_subtree(ltp_tree, tvb, frame_offset, 0, ett_ltp_hdr, NULL, "LTP Header");
	ltp_header_item = proto_tree_get_parent(ltp_header_tree);

	proto_tree_add_bits_ret_val(ltp_header_tree, hf_ltp_version, tvb, frame_offset, 4, &bitsval, ENC_BIG_ENDIAN);
	proto_tree_add_bits_ret_val(ltp_header_tree, hf_ltp_type, tvb, frame_offset+4, 4, &bitsval, ENC_BIG_ENDIAN);
	ltp_type = (int)bitsval;
	tap->seg_type = ltp_type;
	frame_offset++;

	/* Adding the session id subtree */
	ltp_session_tree = proto_tree_add_subtree(ltp_header_tree, tvb, frame_offset, 0, ett_hdr_session, NULL, "Session ID");
	ltp_session_item = proto_tree_get_parent(ltp_session_tree);

	add_sdnv64_to_tree(ltp_session_tree, tvb, pinfo, frame_offset, hf_ltp_session_orig, &(tap->sess_id.orig_eng_id), &engine_id_size);
	frame_offset += engine_id_size;

	add_sdnv64_to_tree(ltp_session_tree, tvb, pinfo, frame_offset, hf_ltp_session_no, &(tap->sess_id.sess_num), &session_num_size);
	frame_offset += session_num_size;

	proto_item_set_end(ltp_session_item, tvb, frame_offset);

	sess_name = wmem_strdup_printf(
		wmem_file_scope(),
		"%" PRId64 "/%" PRIu64,
		tap->sess_id.orig_eng_id, tap->sess_id.sess_num
	);
	tap->sess_name = sess_name;
	PROTO_ITEM_SET_GENERATED(
		proto_tree_add_string(ltp_session_tree, hf_ltp_session_name, tvb,
			frame_offset - engine_id_size - session_num_size,
			engine_id_size + session_num_size, sess_name)
	);
	proto_item_append_text(ltp_session_item,": %s", sess_name);
	proto_item_append_text(ti,", Session: %s", sess_name);
	p_add_proto_data(pinfo->pool, pinfo, proto_ltp, pinfo->curr_layer_num, (void *)sess_name);

	if (tree && ltp_analyze_sequence)
	{
		// LTP sessions exist independently of network addresses and transport ports
		conversation_element_t *conv_key = wmem_alloc_array(pinfo->pool, conversation_element_t, 3);
		conv_key[0].type = CE_UINT64;
		conv_key[0].uint64_val = tap->sess_id.orig_eng_id;
		conv_key[1].type = CE_UINT64;
		conv_key[1].uint64_val = tap->sess_id.sess_num;
		conv_key[2].type = CE_CONVERSATION_TYPE;
		conv_key[2].conversation_type_val = CONVERSATION_LTP;

		pinfo->use_conv_addr_port_endpoints = false;
		pinfo->conv_addr_port_endpoints = NULL;
		pinfo->conv_elements = conv_key;
		conversation_t *convo = find_or_create_conversation(pinfo);

		session = conversation_get_proto_data(convo, proto_ltp);
		if (!session)
		{
			session = wmem_new0(wmem_file_scope(), ltp_session_data_t);
			session->data_segs = wmem_itree_new(wmem_file_scope());
			session->rpt_segs = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
			session->checkpoints = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
			session->chkp_acks = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
			session->reports = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
			session->rpt_acks = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
			session->rpt_datas = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
			session->cancels = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
			session->cancel_acks = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);

			conversation_add_proto_data(convo, proto_ltp, session);
		}
	}
	tap->session = session;

	/* Adding Extension count to the header tree */
	proto_tree_add_bits_ret_val(ltp_header_tree, hf_ltp_hdr_extn_cnt, tvb, 8*frame_offset, 4, &bitsval, ENC_BIG_ENDIAN);
	hdr_extn_cnt = (int)bitsval;
	proto_tree_add_bits_ret_val(ltp_header_tree, hf_ltp_trl_extn_cnt, tvb, 8*frame_offset+4, 4, &bitsval, ENC_BIG_ENDIAN);
	trl_extn_cnt = (int)bitsval;
	frame_offset++;

	proto_item_set_end(ltp_header_item, tvb, frame_offset);

	col_add_fstr(pinfo->cinfo, COL_INFO, "Session %s, %s", sess_name, val_to_str_const(ltp_type,ltp_type_col_info,"Protocol Error"));

	/* Check if there are any header extensions */
	if(hdr_extn_cnt > 0)
	{
		int hdr_extn_offset = dissect_header_extn(ltp_tree, tvb, pinfo, frame_offset,hdr_extn_cnt);
		frame_offset += hdr_extn_offset;
	}

	/* Call sub routines to handle the segment content*/
	if((ltp_type >= 0) && (ltp_type < 8)){
		segment_offset = dissect_data_segment(ltp_tree, tvb, pinfo, frame_offset, &data_len, tap);
		if(segment_offset == 0){
			col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
			return 0;
		}
	}
	else if(ltp_type == 8){
		segment_offset = dissect_report_segment(tvb, pinfo, ltp_tree, frame_offset, tap);
		if(segment_offset == 0){
			col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
			return 0;
		}
	}
	else if(ltp_type == 9){
		segment_offset = dissect_report_ack_segment(ltp_tree, tvb, pinfo, frame_offset, tap);
		if(segment_offset == 0){
			col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
			return 0;
		}
	}
	else if(ltp_type == 12 || ltp_type == 14){
		segment_offset = dissect_cancel_segment(ltp_tree, tvb, pinfo, frame_offset, tap);
		if(segment_offset == 0){
			col_set_str(pinfo->cinfo, COL_INFO, "Protocol Error");
			return 0;
		}
	}
	else if(ltp_type == 13 || ltp_type == 15){
		segment_offset = dissect_cancel_ack_segment(ltp_tree, tvb, pinfo, frame_offset, tap);
	}
	frame_offset += segment_offset;

	/* Check to see if there are any trailer extensions */
	const int trl_start = frame_offset;
	if(trl_extn_cnt > 0)
	{
		int trl_length = dissect_trailer_extn(ltp_tree, tvb, pinfo, frame_offset,trl_extn_cnt);
		frame_offset += trl_length;
	}

	const int frame_len = frame_offset - offset;
	proto_item_set_len(ti, trl_start - data_len);
	proto_tree_set_appendix(ltp_tree, tvb, trl_start, frame_offset - trl_start);
	tap->seg_size = frame_len;
	if (tree)
	{
		tap_queue_packet(ltp_tap, pinfo, tap);
	}

	/* Return the amount of data this dissector was able to dissect */
	return frame_len;
}

static int
dissect_ltp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	const int packet_len = tvb_reported_length(tvb);
	int offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LTP");

	while (offset < packet_len)
	{
		const int sublen = dissect_ltp_segment(tvb, offset, pinfo, tree);
		if (sublen == 0)
		{
			break;
		}
		offset += sublen;
	}
	return offset;
}

static bool
dissect_ltp_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	const int packet_len = tvb_reported_length(tvb);
	if (packet_len <= LTP_MIN_DATA_BUFFER)
	{
		return false;
	}

	int offset = 0;
	TRY {
		// unlike dissect_ltp() this requires the entire datagram to be dissected
		while (offset < packet_len)
		{
			const int sublen = dissect_ltp_segment(tvb, offset, pinfo, NULL);
			if (sublen == 0)
			{
				offset = 0;
				break;
			}
			offset += sublen;
		}
	}
	CATCH_BOUNDS_ERRORS {
		offset = 0;
	}
	ENDTRY;
	if (offset != packet_len)
	{
		return false;
	}

	dissect_ltp(tvb, pinfo, tree, data);
	return true;
}

/// Conversation address for the session receiver
static const char *const ltp_conv_receiver = "receiver";
/// Assigned during proto_register_ltp()
static address ltp_addr_receiver = ADDRESS_INIT_NONE;

static const char *
ltp_conv_get_filter_type(conv_item_t *conv _U_, conv_filter_type_e filter)
{
	switch (conv->dst_address.type)
	{
	case AT_STRINGZ:
		switch (filter)
		{
		case CONV_FT_SRC_ADDRESS:
		case CONV_FT_DST_ADDRESS:
		case CONV_FT_ANY_ADDRESS:
			return "ltp.session.name";
		default:
			break;
		}
		break;
	default:
		break;
	}

	return CONV_FILTER_INVALID;
}

static ct_dissector_info_t ltp_ct_dissector_info = {
	&ltp_conv_get_filter_type
};

static tap_packet_status
ltp_conv_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
	conv_hash_t *hash = (conv_hash_t*) tapdata;
	ltp_tap_info_t *ltp = (ltp_tap_info_t *)data;
	address *src = wmem_new0(pinfo->pool, address);
	address *dst = wmem_new0(pinfo->pool, address);

	address *diraddr, *othaddr;
	switch (ltp->seg_type) {
	case 0x8:
	case 0xd:
	case 0xe:
		// report, cancel ack to sender, cancel from receiver
		diraddr = dst;
		othaddr = src;
		break;
	default:
		diraddr = src;
		othaddr = dst;
		break;
	}
	set_address(diraddr, AT_STRINGZ, (int) strlen(ltp->sess_name) + 1, ltp->sess_name);
	copy_address_shallow(othaddr, &ltp_addr_receiver);

	add_conversation_table_data(hash, src, dst, 0, 0, 1, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts,
			&ltp_ct_dissector_info, CONVERSATION_NONE);

	return TAP_PACKET_REDRAW;
}

static const char *
ltp_endp_get_filter_type(endpoint_item_t *host, conv_filter_type_e filter)
{
	switch (filter)
	{
	case CONV_FT_SRC_ADDRESS:
	case CONV_FT_DST_ADDRESS:
	case CONV_FT_ANY_ADDRESS:
		if (host->myaddress.type == AT_NUMERIC)
		{
			return "ltp.session.orig";
		}
		break;
	default:
		break;
	}

	return CONV_FILTER_INVALID;
}

static et_dissector_info_t  ltp_endp_dissector_info = {
	&ltp_endp_get_filter_type
};

static tap_packet_status
ltp_endp_packet(void *tapdata _U_, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *data _U_, tap_flags_t flags _U_)
{
	conv_hash_t *hash = (conv_hash_t*) tapdata;
	ltp_tap_info_t *ltp = (ltp_tap_info_t *)data;
	address *diraddr = wmem_new0(pinfo->pool, address);

	set_address(diraddr, AT_NUMERIC, (int) sizeof(ltp->sess_id.orig_eng_id), &(ltp->sess_id.orig_eng_id));
	bool sender;
	switch (ltp->seg_type) {
	case 0x8:
	case 0xd:
	case 0xe:
		// report, cancel ack to sender, cancel from receiver
		sender = false;
		break;
	default:
		sender = true;
		break;
	}

	add_endpoint_table_data(hash, diraddr, 0, sender, 1, pinfo->fd->pkt_len,
			&ltp_endp_dissector_info, ENDPOINT_NONE);

	return TAP_PACKET_REDRAW;
}

static bool
ltp_filter_valid(packet_info *pinfo, void *user_data _U_)
{
	return proto_is_frame_protocol(pinfo->layers, "ltp");
}

static char*
ltp_build_filter(packet_info *pinfo, void *user_data _U_)
{
	char *result = NULL;
	int layer_num = 1;
	for (wmem_list_frame_t *protos = wmem_list_head(pinfo->layers);
		protos != NULL; protos = wmem_list_frame_next(protos), ++layer_num)
	{
		const int proto_id = GPOINTER_TO_INT(wmem_list_frame_data(protos));
		if (proto_id != proto_ltp)
		{
			continue;
		}
		const char *sess_name = p_get_proto_data(pinfo->pool, pinfo, proto_ltp, layer_num);
		if (!sess_name)
		{
			continue;
		}

		char *filter = g_strdup_printf(
			"ltp.session.name == \"%s\"",
			sess_name
		);

		if (result)
		{
			char *oldresult = result;
			result = g_strjoin(" || ", oldresult, filter, NULL);
			g_free(oldresult);
			g_free(filter);
		}
		else
		{
			result = filter;
		}
	}

	return result;
}

static const char* st_str_segs = "Segment Size (by Type)";
static const char* st_str_red = "Red Data";
static const char* st_str_corr_orig = "Original";
static const char* st_str_corr_ret = "Retransmission seen";
static const char* st_str_green = "Green Data";
static const char* st_str_rpt = "Report";
static const char* st_str_canc_src = "Cancel by Sender";
static const char* st_str_canc_dst = "Cancel by Receiver";
static const char* st_str_ack = "Report/Cancel Ack";
static const char* st_str_engs = "Segment Addr (by Engine ID)";
static const char* st_str_blks = "Block Size (by Engine ID)";
static int st_node_segs = -1;
static int st_node_red = -1;
static int st_node_green = -1;
static int st_node_rpt = -1;
static int st_node_engs = -1;
static int st_node_blks = -1;

static void
ltp_stats_tree_init(stats_tree *st)
{
	st_node_segs = stats_tree_create_node(st, st_str_segs, 0, STAT_DT_INT, false);
	st_node_red = stats_tree_create_node(st, st_str_red, st_node_segs, STAT_DT_INT, true);
	stats_tree_create_node(st, st_str_corr_orig, st_node_red, STAT_DT_INT, false);
	stats_tree_create_node(st, st_str_corr_ret, st_node_red, STAT_DT_INT, false);
	st_node_green = stats_tree_create_node(st, st_str_green, st_node_segs, STAT_DT_INT, false);
	st_node_rpt = stats_tree_create_node(st, st_str_rpt, st_node_segs, STAT_DT_INT, true);
	stats_tree_create_node(st, st_str_corr_orig, st_node_rpt, STAT_DT_INT, false);
	stats_tree_create_node(st, st_str_corr_ret, st_node_rpt, STAT_DT_INT, false);
	stats_tree_create_node(st, st_str_canc_src, st_node_segs, STAT_DT_INT, false);
	stats_tree_create_node(st, st_str_canc_dst, st_node_segs, STAT_DT_INT, false);
	stats_tree_create_node(st, st_str_ack, st_node_segs, STAT_DT_INT, false);

	st_node_engs = stats_tree_create_pivot(st, st_str_engs, 0);
	st_node_blks = stats_tree_create_pivot(st, st_str_blks, 0);
}

static tap_packet_status
ltp_stats_tree_packet(stats_tree *st, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *p, tap_flags_t flags _U_)
{
	const ltp_tap_info_t *tap = (const ltp_tap_info_t *)p;

	tick_stat_node(st, st_str_segs, 0, false);

	switch (tap->seg_type)
	{
	case 0x0:
	case 0x1:
	case 0x2:
	case 0x3:
		avg_stat_node_add_value_int(st, st_str_red, 0, false, tap->seg_size);
		avg_stat_node_add_value_int(st, tap->corr_orig ? st_str_corr_orig : st_str_corr_ret, st_node_red, true, tap->seg_size);
		break;
	case 0x4:
	case 0x7:
		avg_stat_node_add_value_int(st, st_str_green, 0, false, tap->seg_size);
		break;
	case 0x8:
		avg_stat_node_add_value_int(st, st_str_rpt, 0, false, tap->seg_size);
		avg_stat_node_add_value_int(st, tap->corr_orig ? st_str_corr_orig : st_str_corr_ret, st_node_rpt, true, tap->seg_size);
		break;
	case 0xc:
		avg_stat_node_add_value_int(st, st_str_canc_src, 0, false, tap->seg_size);
		break;
	case 0xe:
		avg_stat_node_add_value_int(st, st_str_canc_dst, 0, false, tap->seg_size);
		break;
	case 0x9:
	case 0xd:
	case 0xf:
		avg_stat_node_add_value_int(st, st_str_ack, 0, false, tap->seg_size);
		break;
	}

	tick_stat_node(st, st_str_engs, 0, true);
	const char *eng_id = wmem_strdup_printf(pinfo->pool, "%" PRIu64, tap->sess_id.orig_eng_id);
	int st_eng_id = tick_stat_node(st, eng_id, st_node_engs, true);
	if (tap->block_size > 0)
	{
		avg_stat_node_add_value_int(st, st_str_blks, 0, true, tap->block_size);
		avg_stat_node_add_value_int(st, eng_id, st_node_blks, false, tap->block_size);
	}

	const address *eng_addr = NULL;
	switch (tap->seg_type)
	{
	case 0x0:
	case 0x1:
	case 0x2:
	case 0x3:
	case 0x4:
	case 0x7:
	case 0x9:
	case 0xc: // cancel from sender
	case 0xf:
		eng_addr = &(pinfo->src);
		break;
	case 0x8: // report
	case 0xd:
	case 0xe: // cancel from receiver
		eng_addr = &(pinfo->dst);
		break;
	}
	const char *eng_addr_str = eng_addr ? address_to_display(pinfo->pool, eng_addr) : NULL;
	if (eng_addr_str)
	{
		tick_stat_node(st, eng_addr_str, st_eng_id, false);
	}

	return TAP_PACKET_REDRAW;
}

/* Register the protocol with Wireshark */
void
proto_register_ltp(void)
{
	static hf_register_info hf[] = {
	  {&hf_ltp_version,
		  {"LTP Version","ltp.version",
		  FT_UINT8,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_type,
		  {"LTP Type","ltp.type",
		  FT_UINT8,BASE_HEX,VALS(ltp_type_codes), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_session_orig,
		  {"Session originator","ltp.session.orig",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_session_no,
		  {"Session number","ltp.session.number",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_session_name,
		  {"Session Name","ltp.session.name",
		  FT_STRING,BASE_NONE,NULL, 0x0, NULL, HFILL}
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
		  FT_UINT64,BASE_DEC | BASE_VAL64_STRING, VALS64(client_service_id_info), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_offset,
		  {"Offset","ltp.data.offset",
		  FT_UINT64,BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_length,
		  {"Length","ltp.data.length",
		  FT_UINT64,BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_chkp,
		  {"Checkpoint serial number","ltp.data.chkp",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_chkp_rpt_ref,
		  {"Checkpoint report segment in frame","ltp.data.chkp.rpt",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_chkp_rpt_time,
		  {"Time to checkpoint report segment","ltp.data.chkp.rpt.time",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_rpt,
		  {"Report serial number","ltp.data.rpt",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_rpt_ref,
		  {"Response to report segment in frame","ltp.data.rpt.ref",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_rpt_time,
		  {"Time since report","ltp.data.rpt.time",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_clidata,
		  {"Client service data","ltp.data.data",
		  FT_BYTES,BASE_NONE,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_retrans,
		  {"Retransmission of data in frame","ltp.data.retrans",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RETRANS_PREV), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_data_clm_rpt,
		  {"Claimed in report segment in frame","ltp.data.clm_rpt",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_block_red_size,
		  {"Red part size", "ltp.block.red_size",
		  FT_UINT64,BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_block_green_size,
		  {"Green part size", "ltp.block.green_size",
		  FT_UINT64,BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_block_bundle_size,
		  {"Bundle size", "ltp.block.bundle_size",
		  FT_UINT64,BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
		  "The dissected bundle is below in the protocol tree", HFILL}
	  },
	  {&hf_ltp_block_bundle_cnt,
		  {"Bundles within the block", "ltp.block.bundle_cnt",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_sno,
		  {"Report serial number","ltp.rpt.sno",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_sno_ack_ref,
		  {"Report ack segment in frame","ltp.rpt.sno.ack",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_sno_ack_time,
		  {"Time to report ack segment","ltp.rpt.sno.ack.time",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_sno_data_ref,
		  {"Responding data segment in frame","ltp.rpt.sno.data",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_sno_data_time,
		  {"Time to checkpoint data segment","ltp.rpt.sno.data.time",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_chkp,
		  {"Checkpoint serial number","ltp.rpt.chkp",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_chkp_ref,
		  {"Checkpoint data segment in frame","ltp.rpt.chkp.ref",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_chkp_time,
		  {"Time since checkpoint","ltp.rpt.chkp.time",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_ub,
		  {"Upper bound","ltp.rpt.ub",
		  FT_UINT64,BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_lb,
		  {"Lower bound","ltp.rpt.lb",
		  FT_UINT64,BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_len,
		  {"Report bound length","ltp.rpt.bound_len",
		  FT_UINT64,BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_retrans,
		  {"Retransmission of report in frame","ltp.rpt.retrans",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RETRANS_PREV), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_clm_cnt,
		  {"Reception claim count","ltp.rpt.clm.cnt",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_clm_off,
		  {"Offset","ltp.rpt.clm.off",
		  FT_UINT64,BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_clm_len,
		  {"Length","ltp.rpt.clm.len",
		  FT_UINT64,BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_clm_fst,
		  {"First block index","ltp.rpt.clm.first",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_clm_lst,
		  {"Last block index","ltp.rpt.clm.last",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_clm_ref,
		  {"Data segment in frame","ltp.rpt.clm.ref",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0,
		  "Which previous data segment is this an ACK for", HFILL}
	  },
	  {&hf_ltp_rpt_gap,
		  {"Reception gap","ltp.rpt.gap",
		  FT_UINT64,BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_gap_fst,
		  {"First block index","ltp.rpt.gap.first",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_gap_lst,
		  {"Last block index","ltp.rpt.gap.last",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_gap_ref,
		  {"Data segment in frame","ltp.rpt.gap.ref",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0,
		  "Which previous data segment is this an NACK for", HFILL}
	  },
	  {&hf_ltp_rpt_gap_total,
		  {"Total gap length","ltp.rpt.gap_total",
		  FT_UINT64,BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_ack_sno,
		  {"Report serial number","ltp.rpt.ack.sno",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_ack_dupe_ref,
		  {"Same ack report number in frame","ltp.rpt.ack.sno.dupe",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RETRANS_PREV), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_ack_ref,
		  {"Response to report segment in frame","ltp.rpt.ack.sno.ref",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_rpt_ack_time,
		  {"Time since report","ltp.rpt.ack.sno.time",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_cancel_code,
		  {"Cancel code","ltp.cancel.code",
		  FT_UINT8,BASE_HEX, VALS(ltp_cancel_codes), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_cancel_dupe_ref,
		  {"Same session cancel in frame","ltp.cancel.dupe.ref",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RETRANS_PREV), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_cancel_ref,
		  {"Acknowledgement segment in frame", "ltp.cancel.ack.ref",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_cancel_time,
		  {"Time to cancel ack","ltp.cancel.ack.time",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_cancel_ack,
		  {"Cancel Ack", "ltp.cancel_ack",
		  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_cancel_ack_dupe_ref,
		  {"Same acknowledgement in frame","ltp.cancel_ack.dupe.ref",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RETRANS_PREV), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_cancel_ack_ref,
		  {"Response to cancel segment in frame", "ltp.cancel_ack.cancel.ref",
		  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_cancel_ack_time,
		  {"Time since cancel","ltp.cancel_ack.cancel.time",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_hdr_extn_tag,
		  {"Extension tag","ltp.hdr.extn.tag",
		  FT_UINT8,BASE_HEX,VALS(extn_tag_codes), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_hdr_extn_len,
		  {"Length","ltp.hdr.extn.len",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_hdr_extn_val,
		  {"Value","ltp.hdr.extn.val",
		  FT_BYTES,BASE_NONE,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_trl_extn_tag,
		  {"Extension tag","ltp.trl.extn.tag",
		  FT_UINT8,BASE_HEX,VALS(extn_tag_codes), 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_trl_extn_len,
		  {"Length","ltp.trl.extn.len",
		  FT_UINT64,BASE_DEC,NULL, 0x0, NULL, HFILL}
	  },
	  {&hf_ltp_trl_extn_val,
		  {"Value","ltp.trl.extn.val",
		  FT_BYTES,BASE_NONE,NULL, 0x0, NULL, HFILL}
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
	  },
	  {&hf_ltp_data_sda_clid,
		  {"Client service ID", "ltp.data.sda.client.id",
		  FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
	  }
	};

/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_ltp,
		&ett_ltp_hdr,
		&ett_hdr_session,
		&ett_hdr_extn,
		&ett_frame_ref,
		&ett_data_segm,
		&ett_block,
		&ett_rpt_segm,
		&ett_rpt_clm,
		&ett_rpt_gap,
		&ett_rpt_ack_segm,
		&ett_session_mgmt,
		&ett_trl_extn,
		&ett_ltp_fragment,
		&ett_ltp_fragments
	};

	static ei_register_info ei[] = {
		{ &ei_ltp_mal_reception_claim, { "ltp.mal_reception_claim", PI_MALFORMED, PI_ERROR, "Reception claim count impossibly large", EXPFILL }},
		{ &ei_ltp_sdnv_length, { "ltp.sdnv_length_invalid", PI_PROTOCOL, PI_ERROR, "SDNV length error", EXPFILL }},
		{ &ei_ltp_sno_larger_than_ccsds, { "ltp.serial_number_too_large", PI_PROTOCOL, PI_WARN, "Serial number larger than CCSDS specification", EXPFILL }},
		{ &ei_ltp_report_async, { "ltp.report_async", PI_SEQUENCE, PI_CHAT, "Report segment not sent in response to a data checkpoint", EXPFILL }},
		{ &ei_ltp_data_chkp_norpt, { "ltp.data_chkp_norpt", PI_SEQUENCE, PI_CHAT, "Data with checkpoint has no corresponding report segment", EXPFILL }},
		{ &ei_ltp_data_rptno_norpt, { "ltp.data_rptno_norpt", PI_SEQUENCE, PI_CHAT, "Data with report serial has no corresponding report segment", EXPFILL }},
		{ &ei_ltp_rpt_noack, { "ltp.rpt_noack", PI_SEQUENCE, PI_CHAT, "Report segment has no corresponding acknowledgement", EXPFILL }},
		{ &ei_ltp_rpt_nochkp, { "ltp.rpt_nochkp", PI_SEQUENCE, PI_CHAT, "Report segment has no corresponding checkpoint data segment", EXPFILL }},
		{ &ei_ltp_rpt_ack_norpt, { "ltp.rpt_ack_norpt", PI_SEQUENCE, PI_CHAT, "Report has no report acknowledgement segment", EXPFILL }},
		{ &ei_ltp_cancel_noack, { "ltp.cancel_noack", PI_SEQUENCE, PI_CHAT, "Cancel segment has no cancel acknowledgement segment", EXPFILL }},
		{ &ei_ltp_cancel_ack_nocancel, { "ltp.cancel_ack_nocancel", PI_SEQUENCE, PI_CHAT, "Cancel acknowledgement has no corresponding cancel segment", EXPFILL }}
	};

	expert_module_t* expert_ltp;

	/* Register the protocol name and description */
	proto_ltp = proto_register_protocol("Licklider Transmission Protocol", "LTP", "ltp");

	module_t *module_ltp = prefs_register_protocol(proto_ltp, NULL);
	prefs_register_bool_preference(
		module_ltp,
		"analyze_sequence",
		"Analyze segment sequences",
		"Whether the dissector should analyze the sequencing and "
		"cross-references of the segments within each session.",
		&ltp_analyze_sequence
	);
	prefs_register_bool_preference(
		module_ltp,
		"reassemble_block",
		"Reassemble block segments",
		"Whether the dissector should combine block segments "
		"together into a full block.",
		&ltp_reassemble_block
	);

	proto_register_field_array(proto_ltp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_ltp = expert_register_protocol(proto_ltp);
	expert_register_field_array(expert_ltp, ei, array_length(ei));

	ltp_handle = register_dissector("ltp", dissect_ltp, proto_ltp);

	set_address(&ltp_addr_receiver, AT_STRINGZ, (int) strlen(ltp_conv_receiver) + 1, ltp_conv_receiver);
	register_conversation_table(proto_ltp, true, ltp_conv_packet, ltp_endp_packet);
	register_conversation_filter("ltp", "LTP", ltp_filter_valid, ltp_build_filter, NULL);
	ltp_tap = register_tap("ltp");

	static const reassembly_table_functions ltp_session_reassembly_table_functions = {
		ltp_session_id_hash,
		ltp_session_id_equal,
		ltp_session_new_key,
		ltp_session_new_key,
		ltp_session_free_key,
		ltp_session_free_key
	};
	reassembly_table_register(&ltp_reassembly_table,
		&ltp_session_reassembly_table_functions);
}

void
proto_reg_handoff_ltp(void)
{
	bundle_handle = find_dissector_add_dependency("bundle", proto_ltp);

	dissector_add_uint_with_preference("udp.port", LTP_PORT, ltp_handle);
	dissector_add_uint_with_preference("dccp.port", LTP_PORT, ltp_handle);
	heur_dissector_add("udp", dissect_ltp_heur_udp, "LTP over UDP", "ltp_udp", proto_ltp, HEURISTIC_DISABLE);

	stats_tree_register("ltp", "ltp", "LTP", ST_SORT_COL_COUNT, ltp_stats_tree_packet, ltp_stats_tree_init, NULL);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
