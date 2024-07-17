/* packet-iwarp-ddp-rdmap.c
 * Routines for Direct Data Placement (DDP) and
 * Remote Direct Memory Access Protocol (RDMAP) dissection
 * According to IETF RFC 5041 and RFC 5040
 * Copyright 2008, Yves Geissbuehler <yves.geissbuehler@gmx.net>
 * Copyright 2008, Philip Frey <frey.philip@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* INCLUDES */
#include "config.h"

#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>

#include "packet-iwarp-ddp-rdmap.h"

void proto_register_iwarp_ddp_rdmap(void);

/* DEFINES */

/* header field byte lengths */
#define DDP_CONTROL_FIELD_LEN 1
#define DDP_TAGGED_HEADER_LEN 14
#define DDP_TAGGED_RSVDULP_LEN 4
#define DDP_STAG_LEN 4
#define DDP_TO_LEN 8
#define DDP_UNTAGGED_HEADER_LEN 18
#define DDP_UNTAGGED_RSVDULP_LEN 5
#define DDP_QN_LEN 4
#define DDP_MSN_LEN 4
#define DDP_MO_LEN 4
#define DDP_BUFFER_MODEL_LEN 12

#define RDMA_CONTROL_FIELD_LEN 1
#define RDMA_RESERVED_FIELD_LEN 4
#define RDMA_INVAL_STAG_LEN 4
#define RDMA_SINKSTAG_LEN 4
#define RDMA_SINKTO_LEN 8
#define RDMA_RDMARDSZ_LEN 4
#define RDMA_SRCSTAG_LEN 4
#define RDMA_SRCTO_LEN 8
#define RDMA_DDP_SEGLEN_LEN 2
#define RDMA_TERMINATED_RDMA_LEN 28

/* RDMA messages */
#define	RDMA_WRITE 0x00
#define RDMA_READ_REQUEST 0x01
#define RDMA_READ_RESPONSE 0x02
#define RDMA_SEND 0x03
#define RDMA_SEND_INVALIDATE 0x04
#define RDMA_SEND_SE 0x05
#define RDMA_SEND_SE_INVALIDATE 0x06
#define RDMA_TERMINATE 0x07
#define RDMA_ATOMIC_REQUEST 0x0A
#define RDMA_ATOMIC_RESPONSE 0x0B

/* bitmasks */
#define	DDP_TAGGED_FLAG 0x80
#define DDP_LAST_FLAG 0x40
#define DDP_RSVD 0x3C
#define DDP_DV 0x03
#define RDMA_RV 0xC0
#define RDMA_RSV 0x30
#define RDMA_OPCODE 0x0F

#define IWARP_LAYER 0xF0
#define IWARP_ETYPE 0x0F
#define IWARP_HDRCT 0xE0
#define IWARP_HDRCT_M 0x80
#define IWARP_HDRCT_D 0x40
#define IWARP_HDRCT_R 0x20
#define IWARP_TERM_RES 0x1FFF

#define IWARP_LAYER_RDMA 0x00
#define IWARP_LAYER_DDP  0x01
#define IWARP_LAYER_LLP  0x02

#define IWARP_ETYPE_DDP_TAGGED 0x01
#define IWARP_ETYPE_DDP_UNTAGGED 0x02

/* GLOBALS */
static int proto_iwarp_ddp_rdmap;
static int ett_iwarp_ddp_rdmap;

/*
 * DDP: initialize the protocol and registered fields
 */
static int hf_iwarp_ddp;

/* DDP Control Field */
static int hf_iwarp_ddp_control_field;
static int hf_iwarp_ddp_t_flag;
static int hf_iwarp_ddp_l_flag;
static int hf_iwarp_ddp_rsvd;
static int hf_iwarp_ddp_dv;

/* DDP rsvdULP[8:39] field */
static int hf_iwarp_ddp_rsvdulp;

/* Tagged Buffer Model Header */
static int hf_iwarp_ddp_tagged_header;
static int hf_iwarp_ddp_stag;
static int hf_iwarp_ddp_to;

/* Untagged Buffer Model Header */
static int hf_iwarp_ddp_untagged_header;
static int hf_iwarp_ddp_qn;
static int hf_iwarp_ddp_msn;
static int hf_iwarp_ddp_mo;

/* initialize the subtree pointers */
static int ett_iwarp_ddp;

static int ett_iwarp_ddp_control_field;
static int ett_iwarp_ddp_tagged_header;
static int ett_iwarp_ddp_untagged_header;

/*
 * RDMAP: initialize the protocol and registered fields
 */
static int hf_iwarp_rdma;

/* Control Field */
static int hf_iwarp_rdma_control_field;
static int hf_iwarp_rdma_version;
static int hf_iwarp_rdma_rsvd;
static int hf_iwarp_rdma_opcode;

/* DDP rsvdULP[8:39] RDMA interpretations */
static int hf_iwarp_rdma_reserved;
static int hf_iwarp_rdma_inval_stag;

/* Read Request Header */
static int hf_iwarp_rdma_rr_header;
static int hf_iwarp_rdma_sinkstag;
static int hf_iwarp_rdma_sinkto;
static int hf_iwarp_rdma_rdmardsz;
static int hf_iwarp_rdma_srcstag;
static int hf_iwarp_rdma_srcto;

/* Terminate Header */
static int hf_iwarp_rdma_terminate_header;
static int hf_iwarp_rdma_term_ctrl;
static int hf_iwarp_rdma_term_layer;
static int hf_iwarp_rdma_term_etype;
static int hf_iwarp_rdma_term_etype_rdma;
static int hf_iwarp_rdma_term_etype_ddp;
static int hf_iwarp_rdma_term_etype_llp;
static int hf_iwarp_rdma_term_errcode;
static int hf_iwarp_rdma_term_errcode_rdma;
static int hf_iwarp_rdma_term_errcode_ddp_untagged;
static int hf_iwarp_rdma_term_errcode_ddp_tagged;
static int hf_iwarp_rdma_term_errcode_llp;
static int hf_iwarp_rdma_term_hdrct;
static int hf_iwarp_rdma_term_hdrct_m;
static int hf_iwarp_rdma_term_hdrct_d;
static int hf_iwarp_rdma_term_hdrct_r;
static int hf_iwarp_rdma_term_rsvd;
static int hf_iwarp_rdma_term_ddp_seg_len;
static int hf_iwarp_rdma_term_ddp_h;
static int hf_iwarp_rdma_term_rdma_h;

/* Atomic */
static int hf_iwarp_rdma_atomic_reserved;
static int hf_iwarp_rdma_atomic_opcode;
static int hf_iwarp_rdma_atomic_request_identifier;
static int hf_iwarp_rdma_atomic_remote_stag;
static int hf_iwarp_rdma_atomic_remote_tagged_offset;
static int hf_iwarp_rdma_atomic_add_data;
static int hf_iwarp_rdma_atomic_add_mask;
static int hf_iwarp_rdma_atomic_swap_data;
static int hf_iwarp_rdma_atomic_swap_mask;
static int hf_iwarp_rdma_atomic_compare_data;
static int hf_iwarp_rdma_atomic_compare_mask;
static int hf_iwarp_rdma_atomic_original_request_identifier;
static int hf_iwarp_rdma_atomic_original_remote_data_value;

static int hf_iwarp_rdma_send_fragments;
static int hf_iwarp_rdma_send_fragment;
static int hf_iwarp_rdma_send_fragment_overlap;
static int hf_iwarp_rdma_send_fragment_overlap_conflict;
static int hf_iwarp_rdma_send_fragment_multiple_tails;
static int hf_iwarp_rdma_send_fragment_too_long_fragment;
static int hf_iwarp_rdma_send_fragment_error;
static int hf_iwarp_rdma_send_fragment_count;
static int hf_iwarp_rdma_send_reassembled_in;
static int hf_iwarp_rdma_send_reassembled_length;
static int hf_iwarp_rdma_send_reassembled_data;

/* initialize the subtree pointers */
static int ett_iwarp_rdma;

static int ett_iwarp_rdma_control_field;
static int ett_iwarp_rdma_rr_header;
static int ett_iwarp_rdma_terminate_header;
static int ett_iwarp_rdma_term_ctrl;
static int ett_iwarp_rdma_term_hdrct;

static int ett_iwarp_rdma_send_fragment;
static int ett_iwarp_rdma_send_fragments;

static const fragment_items iwarp_rdma_send_frag_items = {
	&ett_iwarp_rdma_send_fragment,
	&ett_iwarp_rdma_send_fragments,
	&hf_iwarp_rdma_send_fragments,
	&hf_iwarp_rdma_send_fragment,
	&hf_iwarp_rdma_send_fragment_overlap,
	&hf_iwarp_rdma_send_fragment_overlap_conflict,
	&hf_iwarp_rdma_send_fragment_multiple_tails,
	&hf_iwarp_rdma_send_fragment_too_long_fragment,
	&hf_iwarp_rdma_send_fragment_error,
	&hf_iwarp_rdma_send_fragment_count,
	&hf_iwarp_rdma_send_reassembled_in,
	&hf_iwarp_rdma_send_reassembled_length,
	&hf_iwarp_rdma_send_reassembled_data,
	"iWarp RDMA Send fragments"
};

static const value_string rdmap_messages[] = {
		{ RDMA_WRITE,		   "Write" },
		{ RDMA_READ_REQUEST,	   "Read Request" },
		{ RDMA_READ_RESPONSE,	   "Read Response" },
		{ RDMA_SEND,		   "Send" },
		{ RDMA_SEND_INVALIDATE,	   "Send with Invalidate" },
		{ RDMA_SEND_SE,		   "Send with SE" },
		{ RDMA_SEND_SE_INVALIDATE, "Send with SE and Invalidate" },
		{ RDMA_TERMINATE,	   "Terminate" },
		{ RDMA_ATOMIC_REQUEST,	   "Atomic Request" },
		{ RDMA_ATOMIC_RESPONSE,	   "Atomic Response" },
		{ 0, NULL	}
};

static const value_string layer_names[] = {
		{ IWARP_LAYER_RDMA, "RDMA" },
		{ IWARP_LAYER_DDP,  "DDP" },
		{ IWARP_LAYER_LLP,  "LLP" },
		{ 0, NULL }
};


static const value_string rdma_etype_names[] = {
		{ 0x00, "Local Catastrophic Error" },
		{ 0x01, "Remote Protection Error" },
		{ 0x02, "Remote Operation Error" },
		{ 0, NULL }
};

static const value_string rdma_errcode_names[] = {
		{ 0x00, "Invalid STag" },
		{ 0x01, "Base or bounds violation" },
		{ 0x02, "Access rights violation" },
		{ 0x03, "STag not associated with RDMAP Stream" },
		{ 0x04, "TO wrap" },
		{ 0x05, "Invalid RDMAP version" },
		{ 0x06, "Unexpected OpCode" },
		{ 0x07, "Catastrophic error, localized to RDMAP Stream" },
		{ 0x08, "Catastrophic error, global" },
		{ 0x09, "STag cannot be Invalidated" },
		{ 0xFF, "Unspecific Error" },
		{ 0, NULL }
};

static const value_string ddp_etype_names[] = {
		{ 0x00, "Local Catastrophic Error" },
		{ 0x01, "Tagged Buffer Error" },
		{ 0x02, "Untagged Buffer Error" },
		{ 0x03, "Reserved for the use by the LLP" },
		{ 0, NULL }
};

static const value_string ddp_errcode_tagged_names[] = {
		{ 0x00, "Invalid STag" },
		{ 0x01, "Base or bounds violation" },
		{ 0x02, "STag not associated with DDP Stream" },
		{ 0x03, "TO wrap" },
		{ 0x04, "Invalid DDP version" },
		{ 0, NULL }
};

static const value_string ddp_errcode_untagged_names[] = {
		{ 0x01, "Invalid QN" },
		{ 0x02, "Invalid MSN - no buffer available" },
		{ 0x03, "Invalid MSN - MSN range is not valid" },
		{ 0x04, "Invalid MO" },
		{ 0x05, "DDP Message too long for available buffer" },
		{ 0x06, "Invalid DDP version" },
		{ 0, NULL }
};

static const value_string mpa_etype_names[] = {
		{ 0x00, "MPA Error" },
		{ 0, NULL }
};

static const value_string mpa_errcode_names[] = {
		{ 0x01, "TCP connection closed, terminated or lost" },
		{ 0x02, "MPA CRC Error" },
		{ 0x03, "MPA Marker and ULPDU Length field mismatch" },
		{ 0x04, "Invalid MPA Request Frame or MPA Response Frame" },
		{ 0x05, "Local Catastrophic Error" },
		{ 0x06, "Insufficient IRD Resources" },
		{ 0x07, "No Matching RTR Option" },
		{ 0, NULL }
};

static const value_string rdma_atomic_opcode_names[] = {
		{ 0x00, "FetchAdd" },
		{ 0x02, "CmpSwap" },
		{ 0, NULL }
};


static heur_dissector_list_t rdmap_heur_subdissector_list;

static bool iwarp_rdma_send_reassemble = true;
static reassembly_table iwarp_rdma_send_reassembly_table;

static void
dissect_rdmap_payload(tvbuff_t *tvb, packet_info *pinfo,
		      proto_tree *tree, rdmap_info_t *info)
{
	bool save_fragmented = pinfo->fragmented;
	int save_visited = pinfo->fd->visited;
	conversation_t *conversation = NULL;
	fragment_head *fd_head = NULL;
	bool more_frags = false;
	bool fd_head_not_cached = false;
	heur_dtbl_entry_t *hdtbl_entry;

	switch (info->opcode) {
	case RDMA_SEND:
	case RDMA_SEND_INVALIDATE:
	case RDMA_SEND_SE:
	case RDMA_SEND_SE_INVALIDATE:
		if (iwarp_rdma_send_reassemble) {
			break;
		}
		/* FALLTHRU */
	default:
		goto dissect_payload;
	}

	conversation = find_or_create_conversation(pinfo);

	if (!info->last_flag) {
		more_frags = true;
	}

	fd_head = (fragment_head *)p_get_proto_data(wmem_file_scope(), pinfo, proto_iwarp_ddp_rdmap, 0);
	if (fd_head == NULL) {
		fd_head_not_cached = true;

		pinfo->fd->visited = 0;
		fd_head = fragment_add_seq_next(&iwarp_rdma_send_reassembly_table,
						tvb, 0, pinfo,
						conversation->conv_index,
						NULL, tvb_captured_length(tvb),
						more_frags);
	}

	if (fd_head == NULL) {
		/*
		 * We really want the fd_head and pass it to
		 * process_reassembled_data()
		 *
		 * So that individual fragments gets the
		 * reassembled in field.
		 */
		fd_head = fragment_get_reassembled_id(&iwarp_rdma_send_reassembly_table,
						      pinfo,
						      conversation->conv_index);
	}

	if (fd_head == NULL) {
		/*
		 * we need more data...
		 */
		goto done;
	}

	if (fd_head_not_cached) {
		p_add_proto_data(wmem_file_scope(), pinfo,
				 proto_iwarp_ddp_rdmap, 0, fd_head);
	}

	tvb = process_reassembled_data(tvb, 0, pinfo,
				       "Reassembled SMB Direct",
				       fd_head,
				       &iwarp_rdma_send_frag_items,
				       NULL, /* update_col_info*/
				       tree);
	if (tvb == NULL) {
		/*
		 * we need more data...
		 */
		goto done;
	}

dissect_payload:
	pinfo->fragmented = false;
	if (!dissector_try_heuristic(rdmap_heur_subdissector_list,
					tvb, pinfo, tree, &hdtbl_entry, info)) {
		call_data_dissector(tvb, pinfo, tree);
	}
done:
	pinfo->fragmented = save_fragmented;
	pinfo->fd->visited = save_visited;
	return;
}

/* update packet list pane in the GUI */
static void
ddp_rdma_packetlist(packet_info *pinfo, bool ddp_last_flag,
		uint8_t rdma_msg_opcode)
{
	const char *ddp_fragment_state;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DDP/RDMA");

	if (ddp_last_flag) {
		ddp_fragment_state = "[last DDP segment]";
	} else {
		ddp_fragment_state = "[more DDP segments]";
	}

	col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d %s %s", pinfo->srcport,
				pinfo->destport, val_to_str(rdma_msg_opcode, rdmap_messages,
						"Unknown %d"), ddp_fragment_state);
}

/* dissects RDMA Read Request and Terminate message header */
static int
dissect_iwarp_rdmap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *rdma_tree, uint32_t offset,
		rdmap_info_t *info)
{
	proto_tree *rdma_header_tree = NULL;
	proto_tree *term_ctrl_field_tree = NULL;
	proto_tree *header_ctrl_field_tree = NULL;

	proto_item *rdma_header_subitem = NULL;
	proto_item *term_ctrl_field_subitem = NULL;
	proto_item *header_ctrl_field_subitem = NULL;

	uint8_t layer, etype, hdrct;

	if (info->opcode == RDMA_READ_REQUEST) {
		info->read_request = wmem_new(pinfo->pool, rdmap_request_t);

		rdma_header_subitem = proto_tree_add_item(rdma_tree,
				hf_iwarp_rdma_rr_header, tvb, offset, -1, ENC_NA);
		rdma_header_tree = proto_item_add_subtree(rdma_header_subitem,
				ett_iwarp_rdma);

		proto_tree_add_item_ret_uint(rdma_header_tree, hf_iwarp_rdma_sinkstag, tvb,
				offset, RDMA_SINKSTAG_LEN, ENC_BIG_ENDIAN,
				&info->read_request->sink_stag);
		offset += RDMA_SINKSTAG_LEN;
		proto_tree_add_item_ret_uint64(rdma_header_tree, hf_iwarp_rdma_sinkto, tvb,
				offset, RDMA_SINKTO_LEN, ENC_BIG_ENDIAN,
				&info->read_request->sink_toffset);
		offset += RDMA_SINKTO_LEN;

		proto_tree_add_item_ret_uint(rdma_header_tree,
				hf_iwarp_rdma_rdmardsz, tvb, offset,
				RDMA_RDMARDSZ_LEN, ENC_BIG_ENDIAN,
				&info->read_request->message_size);

		offset += RDMA_RDMARDSZ_LEN;
		proto_tree_add_item_ret_uint(rdma_header_tree, hf_iwarp_rdma_srcstag, tvb,
				offset, RDMA_SRCSTAG_LEN, ENC_BIG_ENDIAN,
				&info->read_request->source_stag);
		offset += RDMA_SRCSTAG_LEN;
		proto_tree_add_item_ret_uint64(rdma_header_tree, hf_iwarp_rdma_srcto, tvb,
				offset, RDMA_SRCTO_LEN, ENC_BIG_ENDIAN,
				&info->read_request->source_toffset);
		offset += RDMA_SRCTO_LEN;
	}

	if (rdma_tree) {
		if (info->opcode == RDMA_TERMINATE) {
			rdma_header_subitem = proto_tree_add_item(rdma_tree,
					hf_iwarp_rdma_terminate_header, tvb, offset, -1, ENC_NA);
			rdma_header_tree = proto_item_add_subtree(rdma_header_subitem,
					ett_iwarp_rdma);

			/* Terminate Control Field */
			layer = tvb_get_uint8(tvb, offset) & IWARP_LAYER;
			etype = tvb_get_uint8(tvb, offset) & IWARP_ETYPE;

			term_ctrl_field_subitem = proto_tree_add_item(rdma_header_tree,
					hf_iwarp_rdma_term_ctrl, tvb, offset, 3, ENC_NA);
			term_ctrl_field_tree = proto_item_add_subtree(
					term_ctrl_field_subitem, ett_iwarp_rdma);
			proto_tree_add_item(term_ctrl_field_tree, hf_iwarp_rdma_term_layer,
					tvb, offset, 1, ENC_BIG_ENDIAN);

			switch (layer >> 4) {
				case IWARP_LAYER_RDMA:
					proto_tree_add_item(term_ctrl_field_tree,
							hf_iwarp_rdma_term_etype_rdma, tvb, offset, 1,
							ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(term_ctrl_field_tree,
							etype ? hf_iwarp_rdma_term_errcode_rdma : hf_iwarp_rdma_term_errcode,
							tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					break;
				case IWARP_LAYER_DDP:
					proto_tree_add_item(term_ctrl_field_tree,
							hf_iwarp_rdma_term_etype_ddp, tvb, offset, 1,
							ENC_BIG_ENDIAN);
					offset += 1;
					switch (etype) {
						case IWARP_ETYPE_DDP_TAGGED:
							proto_tree_add_item(term_ctrl_field_tree,
									hf_iwarp_rdma_term_errcode_ddp_tagged, tvb,
									offset, 1, ENC_BIG_ENDIAN);
							offset += 1;
							break;
						case IWARP_ETYPE_DDP_UNTAGGED:
							proto_tree_add_item(term_ctrl_field_tree,
									hf_iwarp_rdma_term_errcode_ddp_untagged, tvb,
									offset, 1, ENC_BIG_ENDIAN);
							offset += 1;
							break;
						default:
							proto_tree_add_item(term_ctrl_field_tree,
									hf_iwarp_rdma_term_errcode, tvb, offset, 1,
									ENC_BIG_ENDIAN);
							offset += 1;
							break;
					}
					break;
				case IWARP_LAYER_LLP:
					proto_tree_add_item(term_ctrl_field_tree,
							hf_iwarp_rdma_term_etype_llp, tvb, offset, 1,
							ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(term_ctrl_field_tree,
							etype ? hf_iwarp_rdma_term_errcode : hf_iwarp_rdma_term_errcode_llp,
							tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					break;
				default:
					proto_tree_add_item(term_ctrl_field_tree,
							hf_iwarp_rdma_term_etype, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(term_ctrl_field_tree,
							hf_iwarp_rdma_term_errcode, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					break;
			}

			/* header control bits (hdctr), part of Terminate Control Field */
			header_ctrl_field_subitem = proto_tree_add_item(
					term_ctrl_field_tree, hf_iwarp_rdma_term_hdrct, tvb,
					offset, 1, ENC_NA);
			header_ctrl_field_tree = proto_item_add_subtree(
					header_ctrl_field_subitem, ett_iwarp_rdma);

			hdrct = tvb_get_uint8(tvb, offset) & IWARP_HDRCT;

			proto_tree_add_item(header_ctrl_field_tree,
					hf_iwarp_rdma_term_hdrct_m, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(header_ctrl_field_tree,
					hf_iwarp_rdma_term_hdrct_d, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(header_ctrl_field_tree,
					hf_iwarp_rdma_term_hdrct_r, tvb, offset, 1, ENC_BIG_ENDIAN);

			proto_tree_add_item(rdma_header_tree, hf_iwarp_rdma_term_rsvd, tvb,
					offset, 2, ENC_BIG_ENDIAN);
			offset += 2;


			if (hdrct & IWARP_HDRCT_D) {
				/* DDP Segment Length (if any) */
				proto_tree_add_item(rdma_header_tree,
						hf_iwarp_rdma_term_ddp_seg_len, tvb,
						offset, RDMA_DDP_SEGLEN_LEN, ENC_NA);
				offset += RDMA_DDP_SEGLEN_LEN;

				/* Terminated DDP Header (if any), tagged or untagged */
				if (etype == IWARP_ETYPE_DDP_TAGGED) {
					proto_tree_add_item(rdma_header_tree,
							hf_iwarp_rdma_term_ddp_h, tvb,
							offset, DDP_TAGGED_HEADER_LEN, ENC_NA);
					offset += DDP_TAGGED_HEADER_LEN;
				} else {
					proto_tree_add_item(rdma_header_tree,
							hf_iwarp_rdma_term_ddp_h, tvb,
							offset, DDP_UNTAGGED_HEADER_LEN, ENC_NA);
					offset += DDP_UNTAGGED_HEADER_LEN;
				}
			}

			/* Terminated RDMA Header (if any) */
			if (hdrct & IWARP_HDRCT_R) {
				proto_tree_add_item(rdma_header_tree, hf_iwarp_rdma_term_rdma_h,
						tvb, offset, RDMA_TERMINATED_RDMA_LEN, ENC_NA);
			}
		}
	}
	return offset;
}

/* dissects RDMA Atomic Request and Terminate message header */
static int
dissect_iwarp_atomic(tvbuff_t *tvb, proto_tree *atomic_tree, uint32_t offset,
		uint8_t rdma_msg_opcode)
{
	switch(rdma_msg_opcode){
		case RDMA_ATOMIC_REQUEST:{
			uint32_t atomic_opcode;
			proto_tree_add_item(atomic_tree, hf_iwarp_rdma_atomic_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(atomic_tree, hf_iwarp_rdma_atomic_opcode, tvb, offset, 4, ENC_BIG_ENDIAN);
			atomic_opcode = tvb_get_ntohl(tvb, offset);
			offset += 4;
			proto_tree_add_item(atomic_tree, hf_iwarp_rdma_atomic_request_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(atomic_tree, hf_iwarp_rdma_atomic_remote_stag, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(atomic_tree, hf_iwarp_rdma_atomic_remote_tagged_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;
			switch(atomic_opcode){
				case 0: /* Add */
					proto_tree_add_item(atomic_tree, hf_iwarp_rdma_atomic_add_data, tvb, offset, 8, ENC_BIG_ENDIAN);
					offset += 8;
					proto_tree_add_item(atomic_tree, hf_iwarp_rdma_atomic_add_mask, tvb, offset, 8, ENC_BIG_ENDIAN);
					offset += 8;
				break;
				case 2: /* Swap */
					proto_tree_add_item(atomic_tree, hf_iwarp_rdma_atomic_swap_data, tvb, offset, 8, ENC_BIG_ENDIAN);
					offset += 8;
					proto_tree_add_item(atomic_tree, hf_iwarp_rdma_atomic_swap_mask, tvb, offset, 8, ENC_BIG_ENDIAN);
					offset += 8;
				break;
			}
			proto_tree_add_item(atomic_tree, hf_iwarp_rdma_atomic_compare_data, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;
			proto_tree_add_item(atomic_tree, hf_iwarp_rdma_atomic_compare_mask, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;
		}
		break;
		case RDMA_ATOMIC_RESPONSE:
			proto_tree_add_item(atomic_tree, hf_iwarp_rdma_atomic_original_request_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(atomic_tree, hf_iwarp_rdma_atomic_original_remote_data_value, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 4;
		break;
	}
	return offset;
}

/*
 * Main dissection routine which dissects a DDP segment and interprets the
 * header field rsvdULP according to RDMAP.
 */
static int
dissect_iwarp_ddp_rdmap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree *ddp_rdma_tree = NULL;
	proto_tree *ddp_tree = NULL;
	proto_tree *ddp_ctrl_field_tree = NULL;
	proto_tree *ddp_buffer_model_tree = NULL;
	proto_tree *rdma_tree = NULL;
	proto_tree *rdma_ctrl_field_tree = NULL;

	proto_item *ddp_rdma_item = NULL;
	proto_item *ddp_item = NULL;
	proto_item *ddp_ctrl_field_item = NULL;
	proto_item *ddp_buffer_model_item = NULL;
	proto_item *rdma_item = NULL;
	proto_item *rdma_ctrl_field_item = NULL;

	tvbuff_t *next_tvb = NULL;

	uint8_t ddp_ctrl_field, rdma_ctrl_field;
	rdmap_info_t info = { 0, 0, 0, {{0, 0}}, NULL };
	uint32_t header_end;
	uint32_t offset = 0;

	ddp_ctrl_field = tvb_get_uint8(tvb, 0);
	rdma_ctrl_field = tvb_get_uint8(tvb, 1);
	info.opcode = rdma_ctrl_field & RDMA_OPCODE;
	info.is_tagged = (ddp_ctrl_field & DDP_TAGGED_FLAG) ? true : false;
	info.last_flag = (ddp_ctrl_field & DDP_LAST_FLAG)   ? true : false;

	ddp_rdma_packetlist(pinfo, info.last_flag, info.opcode);

	offset = 0;

	/* determine header length */
	if (info.is_tagged) {
		header_end = DDP_TAGGED_HEADER_LEN;
	} else {
		header_end = DDP_UNTAGGED_HEADER_LEN;
	}

	if (info.opcode == RDMA_READ_REQUEST
			|| info.opcode == RDMA_TERMINATE) {
		header_end = -1;
	}

	/* DDP/RDMA protocol tree */
	ddp_rdma_item = proto_tree_add_item(tree, proto_iwarp_ddp_rdmap,
			tvb, offset, header_end, ENC_NA);
	ddp_rdma_tree = proto_item_add_subtree(ddp_rdma_item,
			ett_iwarp_ddp_rdmap);

	/* DDP protocol header subtree */
	ddp_item = proto_tree_add_item(ddp_rdma_tree, hf_iwarp_ddp, tvb,
			offset, header_end, ENC_NA);
	ddp_tree = proto_item_add_subtree(ddp_item, ett_iwarp_ddp);

	/* DDP control field */
	ddp_ctrl_field_item = proto_tree_add_item(ddp_tree,
			hf_iwarp_ddp_control_field, tvb, offset,
			DDP_CONTROL_FIELD_LEN, ENC_NA);
	ddp_ctrl_field_tree = proto_item_add_subtree(ddp_ctrl_field_item,
			ett_iwarp_ddp);

	proto_tree_add_item(ddp_ctrl_field_tree, hf_iwarp_ddp_t_flag, tvb,
			offset, DDP_CONTROL_FIELD_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(ddp_ctrl_field_tree, hf_iwarp_ddp_l_flag, tvb,
			offset, DDP_CONTROL_FIELD_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(ddp_ctrl_field_tree, hf_iwarp_ddp_rsvd, tvb,
			offset, DDP_CONTROL_FIELD_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(ddp_ctrl_field_tree, hf_iwarp_ddp_dv, tvb, offset,
			DDP_CONTROL_FIELD_LEN, ENC_BIG_ENDIAN);
	offset += DDP_CONTROL_FIELD_LEN;


	/* DDP header field RsvdULP */
	if (!info.is_tagged) {
		proto_tree_add_item(ddp_tree, hf_iwarp_ddp_rsvdulp, tvb,
				offset, DDP_UNTAGGED_RSVDULP_LEN, ENC_NA);
	}

	/* RDMA protocol header subtree */
	if (info.is_tagged) {
		header_end = RDMA_CONTROL_FIELD_LEN;
	} else {
		header_end = RDMA_CONTROL_FIELD_LEN + RDMA_RESERVED_FIELD_LEN;
	}

	rdma_item = proto_tree_add_item(ddp_rdma_tree, hf_iwarp_rdma, tvb,
				offset, header_end, ENC_NA);
	rdma_tree = proto_item_add_subtree(rdma_item, ett_iwarp_rdma);

	/* RDMA Control Field */
	rdma_ctrl_field_item = proto_tree_add_item(rdma_tree,
			hf_iwarp_rdma_control_field, tvb, offset,
			RDMA_CONTROL_FIELD_LEN, ENC_NA);
	rdma_ctrl_field_tree = proto_item_add_subtree(rdma_ctrl_field_item,
			ett_iwarp_rdma);

	proto_tree_add_item(rdma_ctrl_field_tree, hf_iwarp_rdma_version, tvb,
			offset, RDMA_CONTROL_FIELD_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(rdma_ctrl_field_tree, hf_iwarp_rdma_rsvd, tvb,
			offset, RDMA_CONTROL_FIELD_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(rdma_ctrl_field_tree, hf_iwarp_rdma_opcode, tvb,
			offset, RDMA_CONTROL_FIELD_LEN, ENC_BIG_ENDIAN);
	offset += RDMA_CONTROL_FIELD_LEN;

	/* dissection of DDP rsvdULP[8:39] with respect to RDMAP */
	if (info.opcode == RDMA_READ_REQUEST
			|| info.opcode == RDMA_SEND
			|| info.opcode == RDMA_SEND_SE
			|| info.opcode == RDMA_TERMINATE) {
		proto_tree_add_item(rdma_tree, hf_iwarp_rdma_reserved,
				tvb, offset, RDMA_RESERVED_FIELD_LEN, ENC_NA);
	}

	if (info.opcode == RDMA_SEND_INVALIDATE
			|| info.opcode == RDMA_SEND_SE_INVALIDATE) {
		proto_tree_add_item(rdma_tree, hf_iwarp_rdma_inval_stag,
			tvb, offset, RDMA_INVAL_STAG_LEN, ENC_BIG_ENDIAN);
	}

	if (!info.is_tagged) {
		offset += RDMA_RESERVED_FIELD_LEN;
	}

	/* DDP Buffer Model dissection */
	if (info.is_tagged) {

		/* Tagged Buffer Model Case */
		ddp_buffer_model_item = proto_tree_add_item(ddp_tree,
				hf_iwarp_ddp_tagged_header, tvb, offset,
				DDP_BUFFER_MODEL_LEN, ENC_NA);
		ddp_buffer_model_tree = proto_item_add_subtree(ddp_buffer_model_item,
				ett_iwarp_ddp);

		proto_tree_add_item_ret_uint(ddp_buffer_model_tree, hf_iwarp_ddp_stag, tvb,
				offset, DDP_STAG_LEN, ENC_BIG_ENDIAN, &info.steering_tag);
		offset += DDP_STAG_LEN;
		proto_tree_add_item_ret_uint64(ddp_buffer_model_tree, hf_iwarp_ddp_to, tvb,
				offset, DDP_TO_LEN, ENC_BIG_ENDIAN, &info.tagged_offset);
		offset += DDP_TO_LEN;

		if( info.opcode == RDMA_READ_RESPONSE
				|| info.opcode == RDMA_WRITE) {

			/* display the payload */
			next_tvb = tvb_new_subset_remaining(tvb, DDP_TAGGED_HEADER_LEN);
			dissect_rdmap_payload(next_tvb, pinfo, tree, &info);
		}

	} else {

		/* Untagged Buffer Model Case */
		ddp_buffer_model_item = proto_tree_add_item(ddp_tree,
				hf_iwarp_ddp_untagged_header, tvb, offset,
				DDP_BUFFER_MODEL_LEN, ENC_NA);
		ddp_buffer_model_tree = proto_item_add_subtree(ddp_buffer_model_item,
				ett_iwarp_ddp);

		proto_tree_add_item_ret_uint(ddp_buffer_model_tree, hf_iwarp_ddp_qn, tvb,
				offset, DDP_QN_LEN, ENC_BIG_ENDIAN, &info.queue_number);
		offset += DDP_QN_LEN;
		proto_tree_add_item_ret_uint(ddp_buffer_model_tree, hf_iwarp_ddp_msn, tvb,
				offset, DDP_MSN_LEN, ENC_BIG_ENDIAN, &info.message_seq_num);
		offset += DDP_MSN_LEN;
		proto_tree_add_item_ret_uint(ddp_buffer_model_tree, hf_iwarp_ddp_mo, tvb,
				offset, DDP_MO_LEN, ENC_BIG_ENDIAN, &info.message_offset);
		offset += DDP_MO_LEN;

		if (info.opcode == RDMA_SEND
				|| info.opcode == RDMA_SEND_INVALIDATE
				|| info.opcode == RDMA_SEND_SE
				|| info.opcode == RDMA_SEND_SE_INVALIDATE) {

			/* display the payload */
			next_tvb = tvb_new_subset_remaining(tvb, DDP_UNTAGGED_HEADER_LEN);
			dissect_rdmap_payload(next_tvb, pinfo, tree, &info);
		}
	}

	/* do further dissection for RDMA messages RDMA Read Request & Terminate */
	if (info.opcode == RDMA_READ_REQUEST) {
		offset = dissect_iwarp_rdmap(tvb, pinfo, rdma_tree, offset, &info);
		/* Call upper layer dissector for message reassembly */
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		dissect_rdmap_payload(next_tvb, pinfo, tree, &info);
	} else if (info.opcode == RDMA_TERMINATE) {
		dissect_iwarp_rdmap(tvb, pinfo, rdma_tree, offset, &info);
	}

	/* do further dissection for RDMA messages RDMA Atomic Request & Response */
	if (info.opcode == RDMA_ATOMIC_REQUEST
			|| info.opcode == RDMA_ATOMIC_RESPONSE) {
		dissect_iwarp_atomic(tvb, rdma_tree, offset, info.opcode);
	}

	return tvb_captured_length(tvb);
}

/* register the protocol with Wireshark */
void
proto_register_iwarp_ddp_rdmap(void)
{
	/* setup list of header fields */
	static hf_register_info hf[] = {

		/* DDP */
		{ &hf_iwarp_ddp, {
				"DDP header", "iwarp_ddp",
				FT_NONE, BASE_NONE, NULL, 0x0,
				NULL, HFILL } },
		{ &hf_iwarp_ddp_control_field, {
				"DDP control field", "iwarp_ddp.control_field",
				FT_NONE, BASE_NONE, NULL, 0x0,
				NULL, HFILL } },
		{ &hf_iwarp_ddp_tagged_header, {
				"Tagged buffer model", "iwarp_ddp.tagged",
				FT_NONE, BASE_NONE, NULL, 0x0,
				"DDP Tagged Buffer Model Header", HFILL} },
		{ &hf_iwarp_ddp_untagged_header, {
				"Untagged buffer model", "iwarp_ddp.untagged",
				FT_NONE, BASE_NONE, NULL, 0x0,
				"DDP Untagged Buffer Model Header", HFILL} },
		{ &hf_iwarp_ddp_t_flag, {
				"Tagged flag", "iwarp_ddp.tagged_flag",
				FT_BOOLEAN, 8, NULL, DDP_TAGGED_FLAG,
				NULL, HFILL} },
		{ &hf_iwarp_ddp_l_flag, {
				"Last flag", "iwarp_ddp.last_flag",
				FT_BOOLEAN, 8, NULL, DDP_LAST_FLAG,
				NULL, HFILL} },
		{ &hf_iwarp_ddp_rsvd, {
				"Reserved", "iwarp_ddp.rsvd",
				FT_UINT8, BASE_HEX, NULL, DDP_RSVD,
				NULL, HFILL} },
		{ &hf_iwarp_ddp_dv, {
				"DDP protocol version", "iwarp_ddp.dv",
				FT_UINT8, BASE_DEC, NULL, DDP_DV,
				NULL, HFILL} },
		{ &hf_iwarp_ddp_rsvdulp, {
				"Reserved for use by the ULP", "iwarp_ddp.rsvdulp",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_ddp_stag, {
				"(Data Sink) Steering Tag", "iwarp_ddp.stag",
				FT_UINT32, BASE_HEX, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_ddp_to, {
				"(Data Sink) Tagged offset", "iwarp_ddp.tagged_offset",
				FT_UINT64, BASE_HEX, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_ddp_qn, {
				"Queue number", "iwarp_ddp.qn",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_ddp_msn, {
				"Message sequence number", "iwarp_ddp.msn",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_ddp_mo, {
				"Message offset", "iwarp_ddp.mo",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL}
		},

		/* RDMAP */
		{ &hf_iwarp_rdma, {
				"RDMAP header", "iwarp_rdma",
				FT_NONE, BASE_NONE, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_control_field, {
				"RDMAP control field", "iwarp_rdma.control_field",
				FT_NONE, BASE_NONE, NULL, 0x0,
				"RDMA Control Field", HFILL} },
		{ &hf_iwarp_rdma_version, {
				"Version", "iwarp_rdma.version",
				FT_UINT8, BASE_DEC, NULL, RDMA_RV,
				"RDMA Version Field", HFILL} },
		{ &hf_iwarp_rdma_rsvd, {
				"Reserved", "iwarp_rdma.rsv",
				FT_UINT8, BASE_HEX, NULL, RDMA_RSV,
				"RDMA Control Field Reserved", HFILL} },
		{ &hf_iwarp_rdma_opcode, {
				"OpCode", "iwarp_rdma.opcode",
				FT_UINT8, BASE_HEX, VALS(rdmap_messages), RDMA_OPCODE,
				"RDMA OpCode Field", HFILL} },
		{ &hf_iwarp_rdma_reserved, {
				"Reserved", "iwarp_rdma.reserved",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_inval_stag, {
				"Invalidate STag", "iwarp_rdma.inval_stag",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				"RDMA Invalidate STag", HFILL} },
		{ &hf_iwarp_rdma_rr_header, {
				"Read request", "iwarp_rdma.rr",
				FT_NONE, BASE_NONE, NULL, 0x0,
				"RDMA Read Request Header", HFILL} },
		{ &hf_iwarp_rdma_terminate_header, {
				"Terminate", "iwarp_rdma.terminate",
				FT_NONE, BASE_NONE, NULL, 0x0,
				"RDMA Terminate Header", HFILL} },
		{ &hf_iwarp_rdma_sinkstag, {
				"Data Sink STag", "iwarp_rdma.sinkstag",
				FT_UINT32, BASE_HEX, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_sinkto, {
				"Data Sink Tagged Offset", "iwarp_rdma.sinkto",
				FT_UINT64, BASE_HEX, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_rdmardsz, {
				"RDMA Read Message Size", "iwarp_rdma.rdmardsz",
				FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_srcstag, {
				"Data Source STag", "iwarp_rdma.srcstag",
				FT_UINT32, BASE_HEX, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_srcto, {
				"Data Source Tagged Offset", "iwarp_rdma.srcto",
				FT_UINT64, BASE_HEX, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_term_ctrl, {
				"Terminate Control", "iwarp_rdma.term_ctrl",
				FT_NONE, BASE_NONE, NULL, 0x0,
				"RDMA Terminate Control Field", HFILL} },
		{ &hf_iwarp_rdma_term_layer, {
				"Layer", "iwarp_rdma.term_layer",
				FT_UINT8, BASE_HEX, VALS(layer_names), IWARP_LAYER,
				"Terminate Control Field: Layer", HFILL} },
		{ &hf_iwarp_rdma_term_etype_rdma, {
				"Error Types for RDMA layer", "iwarp_rdma.term_etype_rdma",
				FT_UINT8, BASE_HEX, VALS(rdma_etype_names), IWARP_ETYPE,
				"Terminate Control Field: Error Type", HFILL} },
		{ &hf_iwarp_rdma_term_etype_ddp, {
				"Error Types for DDP layer", "iwarp_rdma.term_etype_ddp",
				FT_UINT8, BASE_HEX, VALS(ddp_etype_names), IWARP_ETYPE,
				"Terminate Control Field: Error Type", HFILL} },
		{ &hf_iwarp_rdma_term_etype_llp, {
				"Error Types for LLP layer", "iwarp_rdma.term_etype_llp",
				FT_UINT8, BASE_HEX, VALS(mpa_etype_names), IWARP_ETYPE,
				"Terminate Control Field: Error Type", HFILL} },
		{ &hf_iwarp_rdma_term_etype, {
				"Error Types", "iwarp_rdma.term_etype",
				FT_UINT8, BASE_HEX, NULL, IWARP_ETYPE,
				"Terminate Control Field: Error Type", HFILL} },
		{ &hf_iwarp_rdma_term_errcode_rdma, {
				"Error Code for RDMA layer", "iwarp_rdma.term_errcode_rdma",
				FT_UINT8, BASE_HEX, VALS(rdma_errcode_names), 0x0,
				"Terminate Control Field: Error Code", HFILL} },
		{ &hf_iwarp_rdma_term_errcode_ddp_tagged, {
				"Error Code for DDP Tagged Buffer",
				"iwarp_rdma.term_errcode_ddp_tagged",
				FT_UINT8, BASE_HEX, VALS(ddp_errcode_tagged_names), 0x0,
				"Terminate Control Field: Error Code", HFILL} },
		{ &hf_iwarp_rdma_term_errcode_ddp_untagged, {
				"Error Code for DDP Untagged Buffer",
				"iwarp_rdma.term_errcode_ddp_untagged",
				FT_UINT8, BASE_HEX, VALS(ddp_errcode_untagged_names), 0x0,
				"Terminate Control Field: Error Code", HFILL} },
		{ &hf_iwarp_rdma_term_errcode, {
				"Error Code", "iwarp_rdma.term_errcode",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				"Terminate Control Field: Error Code", HFILL} },
		{ &hf_iwarp_rdma_term_errcode_llp, {
				"Error Code for LLP layer", "iwarp_rdma.term_errcode_llp",
				FT_UINT8, BASE_HEX, VALS(mpa_errcode_names), 0x0,
				"Terminate Control Field: Lower Layer Protocol Error Code",
				HFILL} },
		{ &hf_iwarp_rdma_term_hdrct, {
				"Header control bits", "iwarp_rdma.term_hdrct",
				FT_NONE, BASE_NONE, NULL, 0x0,
				"Terminate Control Field: Header control bits", HFILL} },
		{ &hf_iwarp_rdma_term_hdrct_m, {
				"M bit", "iwarp_rdma.term_hdrct_m",
				FT_BOOLEAN, 8, TFS(&tfs_set_notset), IWARP_HDRCT_M,
				"Header control bit m: DDP Segment Length valid", HFILL} },
		{ &hf_iwarp_rdma_term_hdrct_d, {
				"D bit", "iwarp_rdma.hdrct_d",
				FT_BOOLEAN, 8, TFS(&tfs_set_notset), IWARP_HDRCT_D,
				"Header control bit d: DDP Header Included", HFILL} },
		{ &hf_iwarp_rdma_term_hdrct_r, {
				"R bit", "iwarp_rdma.hdrct_r",
				FT_BOOLEAN, 8, TFS(&tfs_set_notset), IWARP_HDRCT_R,
				"Header control bit r: RDMAP Header Included", HFILL} },
		{ &hf_iwarp_rdma_term_rsvd, {
				"Reserved", "iwarp_rdma.term_rsvd",
				FT_UINT16, BASE_HEX, NULL, IWARP_TERM_RES,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_term_ddp_seg_len, {
				"DDP Segment Length", "iwarp_rdma.term_ddp_seg_len",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_term_ddp_h, {
				"Terminated DDP Header", "iwarp_rdma.term_ddp_h",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_term_rdma_h, {
				"Terminated RDMA Header", "iwarp_rdma.term_rdma_h",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL} },

		/* Atomic */
		{ &hf_iwarp_rdma_atomic_reserved, {
				"Reserved", "iwarp_rdma.atomic.reserved",
				FT_UINT32, BASE_DEC, NULL, 0xFFFFFFF0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_atomic_opcode, {
				"OpCode", "iwarp_rdma.atomic.opcode",
				FT_UINT32, BASE_DEC, VALS(rdma_atomic_opcode_names), 0x0000000F,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_atomic_request_identifier, {
				"Request Identifier", "iwarp_rdma.atomic.request_identifier",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_atomic_remote_stag, {
				"Remote STag", "iwarp_rdma.atomic.remote_stag",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_atomic_remote_tagged_offset, {
				"Remote Tagged Offset", "iwarp_rdma.atomic.remote_tagged_offset",
				FT_UINT64, BASE_DEC, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_atomic_add_data, {
				"Add Data", "iwarp_rdma.atomic.add_data",
				FT_UINT64, BASE_DEC, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_atomic_add_mask, {
				"Add Mask", "iwarp_rdma.atomic.add_mask",
				FT_UINT64, BASE_HEX, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_atomic_swap_data, {
				"Swap Data", "iwarp_rdma.atomic.swap_data",
				FT_UINT64, BASE_DEC, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_atomic_swap_mask, {
				"Swap Mask", "iwarp_rdma.atomic.swap_mask",
				FT_UINT64, BASE_HEX, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_atomic_compare_data, {
				"Compare Data", "iwarp_rdma.atomic.compare_data",
				FT_UINT64, BASE_DEC, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_atomic_compare_mask, {
				"Compare Mask", "iwarp_rdma.atomic.compare_mask",
				FT_UINT64, BASE_HEX, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_atomic_original_request_identifier, {
				"Original Request Identifier", "iwarp_rdma.atomic.original_request_identifier",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_atomic_original_remote_data_value, {
				"Original Request Identifier", "iwarp_rdma.atomic.original_remote_data_value",
				FT_UINT64, BASE_DEC, NULL, 0x0,
				NULL, HFILL} },

		{ &hf_iwarp_rdma_send_fragments, {
				"Reassembled SMB Direct Fragments", "iwarp_rdma.send.fragments",
				FT_NONE, BASE_NONE, NULL, 0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_send_fragment, {
				"iWarp RDMA Send Fragment", "iwarp_rdma.send.fragment",
				FT_FRAMENUM, BASE_NONE, NULL, 0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_send_fragment_overlap, {
				"Fragment overlap", "iwarp_rdma.send.fragment.overlap",
				FT_BOOLEAN, BASE_NONE, NULL, 0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_send_fragment_overlap_conflict, {
				"Conflicting data in fragment overlap", "iwarp_rdma.send.fragment.overlap.conflict",
				FT_BOOLEAN, BASE_NONE, NULL, 0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_send_fragment_multiple_tails, {
				"Multiple tail fragments found", "iwarp_rdma.send.fragment.multipletails",
				FT_BOOLEAN, BASE_NONE, NULL, 0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_send_fragment_too_long_fragment, {
				"Fragment too long", "iwarp_rdma.send.fragment.toolongfragment",
				FT_BOOLEAN, BASE_NONE, NULL, 0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_send_fragment_error, {
				"Defragmentation error", "iwarp_rdma.send.fragment.error",
				FT_FRAMENUM, BASE_NONE, NULL, 0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_send_fragment_count, {
				"Fragment count", "iwarp_rdma.send.fragment.count",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_send_reassembled_in, {
				"Reassembled PDU in frame", "iwarp_rdma.send.reassembled_in",
				FT_FRAMENUM, BASE_NONE, NULL, 0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_send_reassembled_length, {
				"Reassembled iWarp RDMA Send length", "iwarp_rdma.send.reassembled.length",
				FT_UINT32, BASE_DEC, NULL, 0,
				NULL, HFILL} },
		{ &hf_iwarp_rdma_send_reassembled_data, {
				"Reassembled iWarp RDMA Send data", "iwarp_rdma.send.reassembled.data",
				FT_BYTES, BASE_NONE, NULL, 0,
				NULL, HFILL} },
	};

	/* setup protocol subtree array */
	static int *ett[] = {

		&ett_iwarp_ddp_rdmap,

		/* DDP */
		&ett_iwarp_ddp,

		&ett_iwarp_ddp_control_field,
		&ett_iwarp_ddp_tagged_header,
		&ett_iwarp_ddp_untagged_header,

		/* RDMAP */
		&ett_iwarp_rdma,

		&ett_iwarp_rdma_control_field,
		&ett_iwarp_rdma_rr_header,
		&ett_iwarp_rdma_terminate_header,
		&ett_iwarp_rdma_term_ctrl,
		&ett_iwarp_rdma_term_hdrct,

		&ett_iwarp_rdma_send_fragment,
		&ett_iwarp_rdma_send_fragments,
	};
	module_t *iwarp_dep_rdmap_module;

	/* register the protocol name and description */
	proto_iwarp_ddp_rdmap = proto_register_protocol("iWARP Direct Data Placement and Remote Direct Memory Access Protocol", "IWARP_DDP_RDMAP", "iwarp_ddp_rdmap");

	/* required function calls to register the header fields and subtrees */
	proto_register_field_array(proto_iwarp_ddp_rdmap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	rdmap_heur_subdissector_list = register_heur_dissector_list_with_description("iwarp_ddp_rdmap", "iWARP RDMAP payload", proto_iwarp_ddp_rdmap);

	register_dissector("iwarp_ddp_rdmap", dissect_iwarp_ddp_rdmap,
			proto_iwarp_ddp_rdmap);

	iwarp_dep_rdmap_module = prefs_register_protocol(proto_iwarp_ddp_rdmap, NULL);
	prefs_register_bool_preference(iwarp_dep_rdmap_module,
				       "reassemble_iwarp_rdma_send",
				       "Reassemble iWarp RDMA Send fragments",
				       "Whether the iWarp RDMA dissector should reassemble Send fragmented payloads",
				       &iwarp_rdma_send_reassemble);
	reassembly_table_register(&iwarp_rdma_send_reassembly_table,
	    &addresses_ports_reassembly_table_functions);
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
