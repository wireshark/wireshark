/* packet-frame.c
 *
 * Top-most dissector. Decides dissector based on Wiretap Encapsulation Type.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#ifdef _MSC_VER
#include <windows.h>
#endif

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/epan.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include <epan/sequence_analysis.h>
#include <epan/tap.h>
#include <epan/expert.h>
#include <epan/tfs.h>
#include <wsutil/application_flavor.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/str_util.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>
#include <epan/addr_resolv.h>
#include <epan/wmem_scopes.h>
#include <epan/column-info.h>

#include "packet-frame.h"

#include <epan/color_filters.h>

void proto_register_frame(void);
void proto_reg_handoff_frame(void);

static int proto_frame;
static int proto_pkt_comment;
static int proto_syscall;

static int hf_frame_arrival_time_local;
static int hf_frame_arrival_time_utc;
static int hf_frame_arrival_time_epoch;
static int hf_frame_shift_offset;
static int hf_frame_time_delta;
static int hf_frame_time_delta_displayed;
static int hf_frame_time_relative;
static int hf_frame_time_relative_cap;
static int hf_frame_time_reference;
static int hf_frame_number;
static int hf_frame_len;
static int hf_frame_capture_len;
static int hf_frame_p2p_dir;
static int hf_frame_file_off;
static int hf_frame_md5_hash;
static int hf_frame_marked;
static int hf_frame_ignored;
static int hf_frame_link_number;
static int hf_frame_packet_id;
static int hf_frame_hash;
static int hf_frame_hash_bytes;
static int hf_frame_verdict;
static int hf_frame_verdict_hardware;
static int hf_frame_verdict_tc;
static int hf_frame_verdict_xdp;
static int hf_frame_verdict_unknown;
static int hf_frame_drop_count;
static int hf_frame_protocols;
static int hf_frame_color_filter_name;
static int hf_frame_color_filter_text;
static int hf_frame_section_number;
static int hf_frame_interface_id;
static int hf_frame_interface_name;
static int hf_frame_interface_description;
static int hf_frame_interface_queue;
static int hf_frame_pack_flags;
static int hf_frame_pack_direction;
static int hf_frame_pack_reception_type;
static int hf_frame_pack_fcs_length;
static int hf_frame_pack_reserved;
static int hf_frame_pack_crc_error;
static int hf_frame_pack_wrong_packet_too_long_error;
static int hf_frame_pack_wrong_packet_too_short_error;
static int hf_frame_pack_wrong_inter_frame_gap_error;
static int hf_frame_pack_unaligned_frame_error;
static int hf_frame_pack_start_frame_delimiter_error;
static int hf_frame_pack_preamble_error;
static int hf_frame_pack_symbol_error;
static int hf_frame_wtap_encap;
static int hf_frame_cb_pen;
static int hf_frame_cb_copy_allowed;
static int hf_frame_comment;
static int hf_frame_encoding;

static int ett_frame;
static int ett_ifname;
static int ett_flags;
static int ett_comments;
static int ett_hash;
static int ett_verdict;

static expert_field ei_comments_text;
static expert_field ei_arrive_time_out_of_range;
static expert_field ei_incomplete;
static expert_field ei_len_lt_caplen;

static int frame_tap;

static dissector_handle_t docsis_handle;
static dissector_handle_t sysdig_handle;
static dissector_handle_t systemd_journal_handle;

/* Preferences */
static bool show_file_off;
static bool force_docsis_encap;
static bool generate_md5_hash;
static bool generate_bits_field = true;
static bool disable_packet_size_limited_in_summary;
static unsigned max_comment_lines   = 30;

static const value_string p2p_dirs[] = {
	{ P2P_DIR_UNKNOWN, "Unknown" },
	{ P2P_DIR_SENT,	   "Sent" },
	{ P2P_DIR_RECV,    "Received" },
	{ 0, NULL }
};

static const value_string packet_word_directions[] = {
	{ PACK_FLAGS_DIRECTION_UNKNOWN,  "Unknown" },
	{ PACK_FLAGS_DIRECTION_INBOUND,  "Inbound" },
	{ PACK_FLAGS_DIRECTION_OUTBOUND, "Outbound" },
	{ 0, NULL }
};

static const value_string packet_word_reception_types[] = {
	{ PACK_FLAGS_RECEPTION_TYPE_UNSPECIFIED, "Not specified" },
	{ PACK_FLAGS_RECEPTION_TYPE_UNICAST,     "Unicast" },
	{ PACK_FLAGS_RECEPTION_TYPE_MULTICAST,   "Multicast" },
	{ PACK_FLAGS_RECEPTION_TYPE_BROADCAST,   "Broadcast" },
	{ PACK_FLAGS_RECEPTION_TYPE_PROMISCUOUS, "Promiscuous" },
	{ 0, NULL }
};

static const value_string packet_char_enc_types[] = {
	{ PACKET_CHAR_ENC_CHAR_ASCII, "ASCII" },
	{ PACKET_CHAR_ENC_CHAR_EBCDIC, "EBCDIC" },
	{ 0, NULL }
};

static const val64_string verdict_ebpf_tc_types[] = {
	{ -1, "TC_ACT_UNSPEC"},
	{ 0, "TC_ACT_OK"},
	{ 1, "TC_ACT_RECLASSIFY"},
	{ 2, "TC_ACT_SHOT"},
	{ 3, "TC_ACT_PIPE"},
	{ 4, "TC_ACT_STOLEN"},
	{ 5, "TC_ACT_QUEUED"},
	{ 6, "TC_ACT_REPEAT"},
	{ 7, "TC_ACT_REDIRECT"},
	{ 8, "TC_ACT_TRAP"},
	{ 0, NULL }
};

static const val64_string verdict_ebpf_xdp_types[] = {
	{ 0, "XDP_ABORTED"},
	{ 1, "XDP_DROP"},
	{ 2, "XDP_PASS"},
	{ 3, "XDP_TX"},
	{ 4, "XDP_REDIRECT"},
	{ 0, NULL }
};

static dissector_table_t wtap_encap_dissector_table;
static dissector_table_t wtap_fts_rec_dissector_table;
static dissector_table_t block_pen_dissector_table;
static dissector_table_t binary_option_pen_dissector_table;

/* The number of tree items required to add an exception to the tree */
#define EXCEPTION_TREE_ITEMS 10

/* OPT_EPB_VERDICT sub-types */
#define OPT_VERDICT_TYPE_HW  0
#define OPT_VERDICT_TYPE_TC  1
#define OPT_VERDICT_TYPE_XDP 2

/* OPT_EPB_HASH sub-types */
#define OPT_HASH_2COMP    0
#define OPT_HASH_XOR	  1
#define OPT_HASH_CRC32    2
#define OPT_HASH_MD5      3
#define OPT_HASH_SHA1     4
#define OPT_HASH_TOEPLITZ 5

/* Structure for passing as userdata to wtap_block_foreach_option */
typedef struct fr_foreach_s {
	proto_item *item;
	proto_tree *tree;
	tvbuff_t *tvb;
	packet_info *pinfo;
	unsigned n_changes;
} fr_foreach_t;

static const char *
get_verdict_type_string(uint8_t type)
{
	switch(type) {
	case OPT_VERDICT_TYPE_HW:
		return "Hardware";
	case OPT_VERDICT_TYPE_TC:
		return "eBPF_TC";
	case OPT_VERDICT_TYPE_XDP:
		return "eBPF_XDP";
	}
	return "Unknown";
}

static const char *
get_hash_type_string(uint8_t type)
{
	switch(type) {
	case OPT_HASH_2COMP:
		return "2's Complement";
	case OPT_HASH_XOR:
		return "XOR";
	case OPT_HASH_CRC32:
		return "CRC32";
	case OPT_HASH_MD5:
		return "MD5";
	case OPT_HASH_SHA1:
		return "SHA1";
	case OPT_HASH_TOEPLITZ:
		return "Toeplitz";
	default:
		return "Unknown";
	}
}

static void
ensure_tree_item(proto_tree *tree, unsigned count)
{
	/*
	 * Ensure that no exception is thrown in proto.c when adding the
	 * next tree item. Even if the maximum number of items is
	 * reached, we know for sure that no infinite loop will occur.
	 */
	if (tree && PTREE_DATA(tree)->count > count)
		PTREE_DATA(tree)->count -= count;
}

/****************************************************************************/
/* whenever a frame packet is seen by the tap listener */
/* Add a new frame into the graph */
static tap_packet_status
frame_seq_analysis_packet( void *ptr, packet_info *pinfo, epan_dissect_t *edt _U_, const void *dummy _U_, tap_flags_t flags _U_)
{
	seq_analysis_info_t *sainfo = (seq_analysis_info_t *) ptr;
	seq_analysis_item_t *sai = sequence_analysis_create_sai_with_addresses(pinfo, sainfo);

	if (!sai)
		return TAP_PACKET_DONT_REDRAW;

	sai->frame_number = pinfo->num;

	sequence_analysis_use_color_filter(pinfo, sai);

	sai->port_src=pinfo->srcport;
	sai->port_dst=pinfo->destport;

	sequence_analysis_use_col_info_as_label_comment(pinfo, sai);

	sai->line_style = 1;
	sai->conv_num = 0;
	sai->display = true;

	g_queue_push_tail(sainfo->items, sai);

	return TAP_PACKET_REDRAW;
}

/*
 * Routine used to register frame end routine.  The routine should only
 * be registered when the dissector is used in the frame, not in the
 * proto_register_XXX function.
 */
void
register_frame_end_routine(packet_info *pinfo, void (*func)(void))
{
	pinfo->frame_end_routines = g_slist_append(pinfo->frame_end_routines, (void *)func);
}

typedef void (*void_func_t)(void);

static void
call_frame_end_routine(void *routine)
{
	void_func_t func = (void_func_t)routine;
	(*func)();
}

static bool
frame_add_comment(wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t *option, void *user_data)
{
	fr_foreach_t *fr_user_data = (fr_foreach_t *)user_data;
	proto_item *comment_item;
	proto_item *hidden_item;
	proto_tree *comments_tree;
	char *newline;             /* location of next newline in comment */
	char *ch;                  /* utility pointer */
	unsigned i;                    /* track number of lines */

	if (option_id == OPT_COMMENT) {
		ch = option->stringval;
		newline = strchr(ch, '\n');
		if (newline == NULL) {
			/* Single-line comment, no special treatment needed */
			comment_item = proto_tree_add_string_format(fr_user_data->tree,
					hf_frame_comment,
					fr_user_data->tvb, 0, 0,
					ch,
					"%s", ch);
		}
		else {
			/* Multi-line comment. Temporarily change the first
			 * newline to a null so we only show the first line
			 */
			*newline = '\0';
			comment_item = proto_tree_add_string_format(fr_user_data->tree,
					hf_frame_comment,
					fr_user_data->tvb, 0, 0,
					ch,
					"%s [...]", ch);
			comments_tree = proto_item_add_subtree(comment_item, ett_comments);
			for (i = 0; i < max_comment_lines; i++) {
				/* Add each line as a separate item under
				 * the comment tree
				 */
				proto_tree_add_string_format(comments_tree, hf_frame_comment,
					fr_user_data->tvb, 0, 0,
					ch,
					"%s", ch);
				if (newline == NULL) {
					/* This was set in the previous loop
					 * iteration; it means we've added the
					 * final line
					 */
					break;
				}
				else {
					/* Put back the newline we removed */
					*newline = '\n';
					ch = newline + 1;
					if (*ch == '\0') {
						break;
					}
					/* Find next newline to repeat the process
					 * in the next iteration
					 */
					newline = strchr(ch, '\n');
					if (newline != NULL) {
						*newline = '\0';
					}
				}
			}
			if (i == max_comment_lines) {
				/* Put back a newline if we still have one dangling */
				if (newline != NULL) {
					*newline = '\n';
				}
				/* Add truncation notice */
				proto_tree_add_string_format(comments_tree, hf_frame_comment,
					fr_user_data->tvb, 0, 0,
					"",
					"[comment truncated at %d line%s]",
					max_comment_lines,
					plurality(max_comment_lines, "", "s"));
			}
			/* Add the original comment unchanged as a hidden
			 * item, so searches still work like before
			 */
			hidden_item = proto_tree_add_string(comments_tree,
					hf_frame_comment,
					fr_user_data->tvb, 0, 0,
					option->stringval);
			proto_item_set_hidden(hidden_item);

			comment_item = comments_tree;
		}
		hidden_item = expert_add_info_format(fr_user_data->pinfo, comment_item, &ei_comments_text,
				"%s",  option->stringval);
		proto_item_set_hidden(hidden_item);
	}
	fr_user_data->n_changes++;
	return true;
}

static bool
frame_add_hash(wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t *option, void *user_data)
{
	fr_foreach_t *fr_user_data = (fr_foreach_t *)user_data;

	if (option_id == OPT_PKT_HASH) {
		packet_hash_opt_t *hash = &option->packet_hash;
		const char *format
			= fr_user_data->n_changes ? ", %s (%u)" : "%s (%u)";

		proto_item_append_text(fr_user_data->item, format,
				       get_hash_type_string(hash->type),
				       hash->type);

		proto_tree_add_bytes_with_length(fr_user_data->tree,
						 hf_frame_hash_bytes,
						 fr_user_data->tvb, 0, 0,
						 hash->hash_bytes->data,
						 hash->hash_bytes->len);
	}
	fr_user_data->n_changes++;
	return true;
}

static bool
frame_add_verdict(wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t *option, void *user_data)
{
	fr_foreach_t *fr_user_data = (fr_foreach_t *)user_data;

	if (option_id == OPT_PKT_VERDICT) {
		packet_verdict_opt_t *verdict = &option->packet_verdictval;
		char *format = fr_user_data->n_changes ? ", %s (%u)" : "%s (%u)";

		proto_item_append_text(fr_user_data->item, format,
				       get_verdict_type_string(verdict->type),
				       verdict->type);

		switch(verdict->type) {
			case OPT_VERDICT_TYPE_TC:
				proto_tree_add_int64(fr_user_data->tree,
						     hf_frame_verdict_tc,
						     fr_user_data->tvb, 0, 0,
						     verdict->data.verdict_linux_ebpf_tc);
				break;
			case OPT_VERDICT_TYPE_XDP:
				proto_tree_add_int64(fr_user_data->tree,
						     hf_frame_verdict_xdp,
						     fr_user_data->tvb, 0, 0,
						     verdict->data.verdict_linux_ebpf_xdp);
				break;
			case OPT_VERDICT_TYPE_HW:
				proto_tree_add_bytes_with_length(fr_user_data->tree,
								 hf_frame_verdict_hardware,
								 fr_user_data->tvb, 0, 0,
								 verdict->data.verdict_bytes->data,
								 verdict->data.verdict_bytes->len);
				break;
			default:
				proto_tree_add_bytes_with_length(fr_user_data->tree,
								 hf_frame_verdict_unknown,
								 fr_user_data->tvb, 0, 0,
								 verdict->data.verdict_bytes->data,
								 verdict->data.verdict_bytes->len);
				break;
		}
	}
	fr_user_data->n_changes++;
	return true;
}

struct custom_binary_opt_cb_data {
	tvbuff_t *tvb;
	packet_info *pinfo;
	proto_tree *tree;
	struct custom_binary_opt_data data;
};

static bool
handle_packet_option(wtap_block_t block _U_, unsigned option_id,
    wtap_opttype_e option_type _U_, wtap_optval_t *optval, void *user_data)
{
	struct custom_binary_opt_cb_data *cb_data = (struct custom_binary_opt_cb_data *)user_data;

	switch (option_id) {

	case OPT_CUSTOM_STR_COPY:
	case OPT_CUSTOM_STR_NO_COPY:
		/* Display it */
		break;

	case OPT_CUSTOM_BIN_COPY:
	case OPT_CUSTOM_BIN_NO_COPY:
		/* Process it */
		cb_data->data.optval = optval;
		dissector_try_uint_with_data(binary_option_pen_dissector_table,
		    optval->custom_binaryval.pen, cb_data->tvb,
		    cb_data->pinfo, cb_data->tree, false, &cb_data->data);
		break;

	default:
		/* Process these too? */
		break;
	}

	return true;
}

static int
dissect_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
	proto_item  *volatile ti = NULL;
	unsigned     cap_len = 0, frame_len = 0;
	nstime_t     rel_ts;
	uint32_t     pack_flags;
	uint32_t     interface_queue;
	uint64_t     drop_count;
	uint64_t     packetid;
	proto_tree  *volatile tree;
	proto_tree  *comments_tree;
	proto_tree  *volatile fh_tree = NULL;
	proto_item  *item;
	const char *cap_plurality, *frame_plurality;
	frame_data_t *fr_data = (frame_data_t*)data;
	const color_filter_t *color_filter;
	dissector_handle_t dissector_handle;
	fr_foreach_t fr_user_data;

	tree=parent_tree;

	DISSECTOR_ASSERT(fr_data);

	/*
	 * Set the protocol to the record type name.
	 */
	pinfo->current_proto = pinfo->rec->rec_type_name;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, pinfo->rec->rec_type_name);

	if (wtap_block_count_option(fr_data->pkt_block, OPT_COMMENT) > 0) {
		item = proto_tree_add_item(tree, proto_pkt_comment, tvb, 0, 0, ENC_NA);
		comments_tree = proto_item_add_subtree(item, ett_comments);
		fr_user_data.item = item;
		fr_user_data.tree = comments_tree;
		fr_user_data.pinfo = pinfo;
		fr_user_data.tvb = tvb;
		fr_user_data.n_changes = 0;
		wtap_block_foreach_option(fr_data->pkt_block, frame_add_comment, (void *)&fr_user_data);
	}

	cap_len = tvb_captured_length(tvb);
	frame_len = tvb_reported_length(tvb);

	/* If FRAME is not referenced from any filters we don't need to
	   worry about generating any tree items.

	   We do, however, have to worry about generating expert infos,
	   as those have to show up if, for example, the user requests
	   the expert info dialog.

	   Therefore, the dissection code has to be careful about
	   what stuff it does only if do_frame_dissection is true.

	   XXX - all these tricks to optimize dissection if only some
	   information is required are fragile.  Something better that
	   handles this automatically would be useful. */
	bool do_frame_dissection = proto_field_is_referenced(tree, proto_frame);
	cap_plurality = plurality(cap_len, "", "s");
	frame_plurality = plurality(frame_len, "", "s");

	/* Put in frame header information. */
	if (do_frame_dissection) {
		ti = proto_tree_add_protocol_format(tree, proto_frame, tvb, 0, tvb_captured_length(tvb),
		    "Frame %u: %s", pinfo->num, pinfo->rec->rec_type_name);
	} else {
		ti = NULL;
	}
	switch (pinfo->rec->rec_type) {

	case REC_TYPE_PACKET:
		if (do_frame_dissection) {
			proto_item_append_text(ti, ", %u byte%s on wire",
			    frame_len, frame_plurality);
			if (generate_bits_field)
				proto_item_append_text(ti, " (%u bits)", frame_len * 8);
			proto_item_append_text(ti, ", %u byte%s captured",
			    cap_len, cap_plurality);
			if (generate_bits_field) {
				proto_item_append_text(ti, " (%u bits)",
				    cap_len * 8);
			}
			if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID) {
				const char *interface_name = epan_get_interface_name(pinfo->epan,
				    pinfo->rec->rec_header.packet_header.interface_id,
				    pinfo->rec->presence_flags & WTAP_HAS_SECTION_NUMBER ? pinfo->rec->section_number : 0);
				if (interface_name != NULL) {
					proto_item_append_text(ti, " on interface %s, id %u",
					    interface_name, pinfo->rec->rec_header.packet_header.interface_id);
				} else {
					proto_item_append_text(ti, " on unnamed interface, id %u",
					    pinfo->rec->rec_header.packet_header.interface_id);
				}
			}
		}
		if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_uint32_option_value(fr_data->pkt_block, OPT_PKT_FLAGS, &pack_flags)) {
			switch (PACK_FLAGS_DIRECTION(pack_flags)) {

			case PACK_FLAGS_DIRECTION_UNKNOWN:
			default:
				pinfo->p2p_dir = P2P_DIR_UNKNOWN;
				break;

			case PACK_FLAGS_DIRECTION_INBOUND:
				pinfo->p2p_dir = P2P_DIR_RECV;
				if (do_frame_dissection)
					proto_item_append_text(ti, " (inbound)");
				break;

			case PACK_FLAGS_DIRECTION_OUTBOUND:
				pinfo->p2p_dir = P2P_DIR_SENT;
				if (do_frame_dissection)
					proto_item_append_text(ti, " (outbound)");
				break;
			}
		}

		/*
		 * If the pseudo-header *and* the packet record both
		 * have direction information, the pseudo-header
		 * overrides the packet record.
		 */
		if (pinfo->pseudo_header != NULL) {
			switch (pinfo->rec->rec_header.packet_header.pkt_encap) {

			case WTAP_ENCAP_WFLEET_HDLC:
			case WTAP_ENCAP_CHDLC_WITH_PHDR:
			case WTAP_ENCAP_PPP_WITH_PHDR:
			case WTAP_ENCAP_SDLC:
			case WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR:
				pinfo->p2p_dir = pinfo->pseudo_header->p2p.sent ?
				    P2P_DIR_SENT : P2P_DIR_RECV;
				break;

			case WTAP_ENCAP_BLUETOOTH_HCI:
				pinfo->p2p_dir = pinfo->pseudo_header->bthci.sent ?
					P2P_DIR_SENT : P2P_DIR_RECV;
				break;

			case WTAP_ENCAP_LAPB:
			case WTAP_ENCAP_FRELAY_WITH_PHDR:
				pinfo->p2p_dir =
				    (pinfo->pseudo_header->dte_dce.flags & FROM_DCE) ?
				    P2P_DIR_RECV : P2P_DIR_SENT;
				break;

			case WTAP_ENCAP_ISDN:
			case WTAP_ENCAP_V5_EF:
			case WTAP_ENCAP_DPNSS:
			case WTAP_ENCAP_BACNET_MS_TP_WITH_PHDR:
				pinfo->p2p_dir = pinfo->pseudo_header->isdn.uton ?
				    P2P_DIR_SENT : P2P_DIR_RECV;
				break;

			case WTAP_ENCAP_LINUX_LAPD:
				pinfo->p2p_dir = (pinfo->pseudo_header->lapd.pkttype == 3 ||
					pinfo->pseudo_header->lapd.pkttype == 4) ?
					P2P_DIR_SENT : P2P_DIR_RECV;
				break;

			case WTAP_ENCAP_MTP2_WITH_PHDR:
				pinfo->p2p_dir = pinfo->pseudo_header->mtp2.sent ?
				    P2P_DIR_SENT : P2P_DIR_RECV;
				pinfo->link_number  = pinfo->pseudo_header->mtp2.link_number;
				break;

			case WTAP_ENCAP_GSM_UM:
				pinfo->p2p_dir = pinfo->pseudo_header->gsm_um.uplink ?
				    P2P_DIR_SENT : P2P_DIR_RECV;
				break;
			}
		}
		break;

	case REC_TYPE_FT_SPECIFIC_EVENT:
		break;

	case REC_TYPE_FT_SPECIFIC_REPORT:
		break;

	case REC_TYPE_SYSCALL:
		if (do_frame_dissection) {
			/*
			 * This gives us a top-of-tree "syscall" protocol
			 * with "frame" fields underneath. Should we create
			 * corresponding syscall.time, .time_epoch, etc
			 * fields and use them instead or would frame.*
			 * be preferred?
			 *
			 * XXX - is this length value relevant?
			 */
			proto_item_append_text(ti, ", %u byte%s",
			    frame_len, frame_plurality);
		}
		break;

	case REC_TYPE_SYSTEMD_JOURNAL_EXPORT:
		if (do_frame_dissection) {
			/*
			 * XXX - we need to rethink what's handled by
			 * packet-record.c, what's handled by packet-frame.c.
			 * and what's handled by the syscall and systemd
			 * journal dissectors (and maybe even the packet
			 * dissector).
			 *
			 * XXX - is this length value relevant?
			 */
			proto_item_append_text(ti, ", %u byte%s",
			    frame_len, frame_plurality);
		}
		break;

	case REC_TYPE_CUSTOM_BLOCK:
		if (do_frame_dissection) {
			proto_item_append_text(ti, ", %u byte%s",
			    frame_len, frame_plurality);
			proto_item_append_text(ti, ", copying%s allowed",
			                       pinfo->rec->rec_header.custom_block_header.copy_allowed ? "" : " not");
		}
		break;

	default:
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "UNKNOWN");
		col_add_fstr(pinfo->cinfo, COL_INFO, "Record type %u",
		    pinfo->rec->rec_type);
		call_data_dissector(tvb, pinfo, parent_tree);
		return tvb_captured_length(tvb);
	}

	if (do_frame_dissection) {
		fh_tree = proto_item_add_subtree(ti, ett_frame);
	} else {
		fh_tree = NULL;
	}

	if (pinfo->rec->presence_flags & WTAP_HAS_SECTION_NUMBER &&
	    do_frame_dissection &&
	    (proto_field_is_referenced(tree, hf_frame_section_number))) {
		/* Show it as 1-origin */
		proto_tree_add_uint(fh_tree, hf_frame_section_number, tvb,
				    0, 0, pinfo->rec->section_number + 1);
	}

	if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID &&
	    do_frame_dissection &&
	    ((proto_field_is_referenced(tree, hf_frame_interface_id) || proto_field_is_referenced(tree, hf_frame_interface_name) || proto_field_is_referenced(tree, hf_frame_interface_description)))) {
		unsigned section_number = pinfo->rec->presence_flags & WTAP_HAS_SECTION_NUMBER ? pinfo->rec->section_number : 0;
		const char *interface_name = epan_get_interface_name(pinfo->epan, pinfo->rec->rec_header.packet_header.interface_id, section_number);
		const char *interface_description = epan_get_interface_description(pinfo->epan, pinfo->rec->rec_header.packet_header.interface_id, section_number);
		proto_tree *if_tree;
		proto_item *if_item;

		if (interface_name) {
			if_item = proto_tree_add_uint_format_value(fh_tree, hf_frame_interface_id, tvb, 0, 0,
								   pinfo->rec->rec_header.packet_header.interface_id, "%u (%s)",
								   pinfo->rec->rec_header.packet_header.interface_id, interface_name);
			if_tree = proto_item_add_subtree(if_item, ett_ifname);
			proto_tree_add_string(if_tree, hf_frame_interface_name, tvb, 0, 0, interface_name);
		} else {
			if_item = proto_tree_add_uint(fh_tree, hf_frame_interface_id, tvb, 0, 0, pinfo->rec->rec_header.packet_header.interface_id);
		}

		if (interface_description) {
			if_tree = proto_item_add_subtree(if_item, ett_ifname);
			proto_tree_add_string(if_tree, hf_frame_interface_description, tvb, 0, 0, interface_description);
		}
	}

	if (pinfo->rec->rec_type == REC_TYPE_PACKET) {
		if (do_frame_dissection) {
			if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_uint32_option_value(fr_data->pkt_block, OPT_PKT_QUEUE, &interface_queue)) {
				proto_tree_add_uint(fh_tree, hf_frame_interface_queue, tvb, 0, 0, interface_queue);
			}

			if (wtap_block_count_option(fr_data->pkt_block, OPT_PKT_HASH) > 0) {
				proto_tree *hash_tree;
				proto_item *hash_item;

				hash_item = proto_tree_add_string(fh_tree, hf_frame_hash, tvb, 0, 0, "");
				hash_tree = proto_item_add_subtree(hash_item, ett_hash);
				fr_user_data.item = hash_item;
				fr_user_data.tree = hash_tree;
				fr_user_data.pinfo = pinfo;
				fr_user_data.tvb = tvb;
				fr_user_data.n_changes = 0;
				wtap_block_foreach_option(fr_data->pkt_block, frame_add_hash, (void *)&fr_user_data);
			}

			if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_uint32_option_value(fr_data->pkt_block, OPT_PKT_FLAGS, &pack_flags)) {
				proto_tree *flags_tree;
				proto_item *flags_item;
				static int * const flags[] = {
					&hf_frame_pack_direction,
					&hf_frame_pack_reception_type,
					&hf_frame_pack_fcs_length,
					&hf_frame_pack_reserved,
					&hf_frame_pack_crc_error,
					&hf_frame_pack_wrong_packet_too_long_error,
					&hf_frame_pack_wrong_packet_too_short_error,
					&hf_frame_pack_wrong_inter_frame_gap_error,
					&hf_frame_pack_unaligned_frame_error,
					&hf_frame_pack_start_frame_delimiter_error,
					&hf_frame_pack_preamble_error,
					&hf_frame_pack_symbol_error,
					NULL
				};

				flags_item = proto_tree_add_uint(fh_tree, hf_frame_pack_flags, tvb, 0, 0, pack_flags);
				flags_tree = proto_item_add_subtree(flags_item, ett_flags);
				proto_tree_add_bitmask_list_value(flags_tree, tvb, 0, 0, flags, pack_flags);
			}

			if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_uint64_option_value(fr_data->pkt_block, OPT_PKT_PACKETID, &packetid)) {
				proto_tree_add_uint64(fh_tree, hf_frame_packet_id, tvb, 0, 0, packetid);
			}

			if (wtap_block_count_option(fr_data->pkt_block, OPT_PKT_VERDICT) > 0) {
				proto_tree *verdict_tree;
				proto_item *verdict_item;

				verdict_item = proto_tree_add_string(fh_tree, hf_frame_verdict, tvb, 0, 0, "");
				verdict_tree = proto_item_add_subtree(verdict_item, ett_verdict);
				fr_user_data.item = verdict_item;
				fr_user_data.tree = verdict_tree;
				fr_user_data.pinfo = pinfo;
				fr_user_data.tvb = tvb;
				fr_user_data.n_changes = 0;
				wtap_block_foreach_option(pinfo->rec->block, frame_add_verdict, (void *)&fr_user_data);
			}

			proto_tree_add_int(fh_tree, hf_frame_wtap_encap, tvb, 0, 0, pinfo->rec->rec_header.packet_header.pkt_encap);
		}
	}

	if (pinfo->presence_flags & PINFO_HAS_TS) {
		if (do_frame_dissection) {
			proto_tree_add_time(fh_tree, hf_frame_arrival_time_local, tvb, 0, 0, &pinfo->abs_ts);
			proto_tree_add_time(fh_tree, hf_frame_arrival_time_utc, tvb, 0, 0, &pinfo->abs_ts);
			proto_tree_add_time(fh_tree, hf_frame_arrival_time_epoch, tvb, 0, 0, &pinfo->abs_ts);
		}
		if (pinfo->abs_ts.nsecs < 0 || pinfo->abs_ts.nsecs >= 1000000000) {
			expert_add_info_format(pinfo, ti, &ei_arrive_time_out_of_range,
							  "Arrival Time: Fractional second %09ld is invalid,"
							  " the valid range is 0-1000000000",
							  (long) pinfo->abs_ts.nsecs);
		}
		if (do_frame_dissection) {
			item = proto_tree_add_time(fh_tree, hf_frame_shift_offset, tvb,
					    0, 0, &(pinfo->fd->shift_offset));
			proto_item_set_generated(item);

			if (proto_field_is_referenced(tree, hf_frame_time_delta)) {
				nstime_t     del_cap_ts;

				if (frame_delta_time_prev_captured(pinfo->epan, pinfo->fd, &del_cap_ts)) {
					item = proto_tree_add_time(fh_tree, hf_frame_time_delta, tvb,
								   0, 0, &(del_cap_ts));
					proto_item_set_generated(item);
				}
			}

			if (proto_field_is_referenced(tree, hf_frame_time_delta_displayed)) {
				nstime_t del_dis_ts;

				if (frame_delta_time_prev_displayed(pinfo->epan, pinfo->fd, &del_dis_ts)) {
					item = proto_tree_add_time(fh_tree, hf_frame_time_delta_displayed, tvb,
								   0, 0, &(del_dis_ts));
					proto_item_set_generated(item);
				}
			}

			if (frame_rel_time(pinfo->epan, pinfo->fd, &rel_ts)) {
				item = proto_tree_add_time(fh_tree, hf_frame_time_relative, tvb,
							   0, 0, &(rel_ts));
				proto_item_set_generated(item);
			}

			if (pinfo->fd->ref_time) {
				ti = proto_tree_add_item(fh_tree, hf_frame_time_reference, tvb, 0, 0, ENC_NA);
				proto_item_set_generated(ti);
			}

			if (pinfo->rel_cap_ts_present) {
				item = proto_tree_add_time(fh_tree, hf_frame_time_relative_cap, tvb,
							   0, 0, &(pinfo->rel_cap_ts));
				proto_item_set_generated(item);
			}
		}
	}

	if (do_frame_dissection) {
		proto_tree_add_uint(fh_tree, hf_frame_number, tvb,
				    0, 0, pinfo->num);

		item = proto_tree_add_uint_format_value(fh_tree, hf_frame_len, tvb,
						  0, 0, frame_len, "%u byte%s (%u bits)",
						  frame_len, frame_plurality, frame_len * 8);
	} else {
		item = NULL;
	}
	if (frame_len < cap_len) {
		/*
		 * A reported length less than a captured length
		 * is bogus, as you cannot capture more data
		 * than there is in a packet.
		 */
		expert_add_info(pinfo, item, &ei_len_lt_caplen);
	}

	if (do_frame_dissection) {
		proto_tree_add_uint_format_value(fh_tree, hf_frame_capture_len, tvb,
					   0, 0, cap_len, "%u byte%s (%u bits)",
					   cap_len, cap_plurality, cap_len * 8);

		if (pinfo->rec->rec_type == REC_TYPE_PACKET) {
			if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_uint64_option_value(fr_data->pkt_block, OPT_PKT_DROPCOUNT, &drop_count)) {
				proto_tree_add_uint64(fh_tree, hf_frame_drop_count, tvb, 0, 0, drop_count);
			}
		}

		if (generate_md5_hash) {
			const uint8_t *cp;
			uint8_t       digest[HASH_MD5_LENGTH];
			const char   *digest_string;

			cp = tvb_get_ptr(tvb, 0, cap_len);

			gcry_md_hash_buffer(GCRY_MD_MD5, digest, cp, cap_len);
			digest_string = bytes_to_str_punct(pinfo->pool, digest, HASH_MD5_LENGTH, '\0');
			ti = proto_tree_add_string(fh_tree, hf_frame_md5_hash, tvb, 0, 0, digest_string);
			proto_item_set_generated(ti);
		}

		ti = proto_tree_add_boolean(fh_tree, hf_frame_marked, tvb, 0, 0, pinfo->fd->marked);
		proto_item_set_generated(ti);

		ti = proto_tree_add_boolean(fh_tree, hf_frame_ignored, tvb, 0, 0, pinfo->fd->ignored);
		proto_item_set_generated(ti);
	}

	if (pinfo->rec->rec_type == REC_TYPE_PACKET) {
		if (do_frame_dissection) {
			/* Check for existences of P2P pseudo header */
			if (pinfo->p2p_dir != P2P_DIR_UNKNOWN) {
				proto_tree_add_int(fh_tree, hf_frame_p2p_dir, tvb,
						   0, 0, pinfo->p2p_dir);
			}

			/* Check for existences of MTP2 link number */
			if ((pinfo->pseudo_header != NULL) &&
			    (pinfo->rec->rec_header.packet_header.pkt_encap == WTAP_ENCAP_MTP2_WITH_PHDR)) {
				proto_tree_add_uint(fh_tree, hf_frame_link_number, tvb,
						    0, 0, pinfo->link_number);
			}
		}

		/*
		 * Process custom options.
		 */
		struct custom_binary_opt_cb_data cb_data;

		cb_data.pinfo = pinfo;
		cb_data.tvb = tvb;
		cb_data.tree = fh_tree;
		cb_data.data.optval = NULL;
		wtap_block_foreach_option(fr_data->pkt_block,
		    handle_packet_option, &cb_data);
	}

	if (do_frame_dissection) {
		if (show_file_off) {
			proto_tree_add_int64_format_value(fh_tree, hf_frame_file_off, tvb,
						    0, 0, pinfo->fd->file_off,
						    "%" PRId64 " (0x%" PRIx64 ")",
						    pinfo->fd->file_off, pinfo->fd->file_off);
		}
	}

	if (pinfo->fd->ignored) {
		/* Ignored package, stop handling here */
		col_set_str(pinfo->cinfo, COL_INFO, "<Ignored>");
		proto_tree_add_boolean_format(tree, hf_frame_ignored, tvb, 0, 0, true, "This frame is marked as ignored");
		return tvb_captured_length(tvb);
	}

	if (frame_len < cap_len) {
		/*
		 * Fix the reported length; a reported length less than
		 * a captured length is bogus, as you cannot capture
		 * more data than there is in a packet.
		 */
		tvb_fix_reported_length(tvb);
	}

	/* Portable Exception Handling to trap Wireshark specific exceptions like BoundsError exceptions */
	TRY {
#ifdef _MSC_VER
		/* Win32: Visual-C Structured Exception Handling (SEH) to trap hardware exceptions
		   like memory access violations.
		   (a running debugger will be called before the except part below) */
		/* Note: A Windows "exceptional exception" may leave the kazlib's (Portable Exception Handling)
		   stack in an inconsistent state thus causing a crash at some point in the
		   handling of the exception.
		   See: https://lists.wireshark.org/archives/wireshark-dev/200704/msg00243.html
		*/
		__try {
#endif
			switch (pinfo->rec->rec_type) {

			case REC_TYPE_PACKET:
				if ((force_docsis_encap) && (docsis_handle)) {
					dissector_handle = docsis_handle;
				} else {
					/*
					 * XXX - we don't use dissector_try_uint_with_data()
					 * because we don't want to have to
					 * treat a zero return from the dissector
					 * as meaning "packet not accepted,
					 * because that doesn't work for
					 * packets where libwiretap strips
					 * off the metadata header and puts
					 * it into the pseudo-header, leaving
					 * zero bytes worth of payload.  See
					 * bug 15630.
					 *
					 * If the dissector for the packet's
					 * purported link-layer header type
					 * rejects the packet, that's a sign
					 * of a bug somewhere, so making it
					 * impossible for those dissectors
					 * to reject packets isn't a problem.
					 */
					dissector_handle =
					    dissector_get_uint_handle(wtap_encap_dissector_table,
					        pinfo->rec->rec_header.packet_header.pkt_encap);
				}
				if (dissector_handle != NULL) {
					uint32_t save_match_uint = pinfo->match_uint;

					pinfo->match_uint =
					    pinfo->rec->rec_header.packet_header.pkt_encap;
					call_dissector_only(dissector_handle,
					    tvb, pinfo, parent_tree,
					    (void *)pinfo->pseudo_header);
					pinfo->match_uint = save_match_uint;
				} else {
					col_set_str(pinfo->cinfo, COL_PROTOCOL, "UNKNOWN");
					col_add_fstr(pinfo->cinfo, COL_INFO, "WTAP_ENCAP = %d",
						     pinfo->rec->rec_header.packet_header.pkt_encap);
					call_data_dissector(tvb, pinfo, parent_tree);
				}
				break;

			case REC_TYPE_FT_SPECIFIC_EVENT:
			case REC_TYPE_FT_SPECIFIC_REPORT:
				{
					int file_type_subtype;

					file_type_subtype = fr_data->file_type_subtype;

					if (!dissector_try_uint(wtap_fts_rec_dissector_table, file_type_subtype,
					    tvb, pinfo, parent_tree)) {
						col_set_str(pinfo->cinfo, COL_PROTOCOL, "UNKNOWN");
						col_add_fstr(pinfo->cinfo, COL_INFO, "WTAP FT ST = %d",
							     file_type_subtype);
						call_data_dissector(tvb, pinfo, parent_tree);
					}
				}
				break;

			case REC_TYPE_SYSCALL:
				/* Sysdig is the only type we currently handle. */
				if (sysdig_handle) {
					call_dissector_with_data(sysdig_handle,
					    tvb, pinfo, parent_tree,
					    (void *)pinfo->pseudo_header);
				}
				break;

			case REC_TYPE_SYSTEMD_JOURNAL_EXPORT:
				if (systemd_journal_handle) {
					call_dissector_with_data(systemd_journal_handle,
					    tvb, pinfo, parent_tree,
					    (void *)pinfo->pseudo_header);
				}
				break;

			case REC_TYPE_CUSTOM_BLOCK:
				if (!dissector_try_uint(block_pen_dissector_table,
				    pinfo->rec->rec_header.custom_block_header.pen,
				    tvb, pinfo, parent_tree)) {
					col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCAPNG");
					proto_tree_add_uint_format_value(fh_tree, hf_frame_cb_pen, tvb, 0, 0,
					                                 pinfo->rec->rec_header.custom_block_header.pen,
					                                 "%s (%u)",
					                                 enterprises_lookup(pinfo->rec->rec_header.custom_block_header.pen, "Unknown"),
					                                 pinfo->rec->rec_header.custom_block_header.pen);
					proto_tree_add_boolean(fh_tree, hf_frame_cb_copy_allowed, tvb, 0, 0, pinfo->rec->rec_header.custom_block_header.copy_allowed);
					col_add_fstr(pinfo->cinfo, COL_INFO, "Custom Block: PEN = %s (%d), will%s be copied",
					             enterprises_lookup(pinfo->rec->rec_header.custom_block_header.pen, "Unknown"),
					             pinfo->rec->rec_header.custom_block_header.pen,
					             pinfo->rec->rec_header.custom_block_header.copy_allowed ? "" : " not");
					call_data_dissector(tvb, pinfo, parent_tree);
				}
				break;
			}
#ifdef _MSC_VER
		} __except(EXCEPTION_EXECUTE_HANDLER /* handle all exceptions */) {
			ensure_tree_item(parent_tree, EXCEPTION_TREE_ITEMS);
			switch (GetExceptionCode()) {
			case(STATUS_ACCESS_VIOLATION):
				show_exception(tvb, pinfo, parent_tree, DissectorError,
					       "STATUS_ACCESS_VIOLATION: dissector accessed an invalid memory address");
				break;
			case(STATUS_INTEGER_DIVIDE_BY_ZERO):
				show_exception(tvb, pinfo, parent_tree, DissectorError,
					       "STATUS_INTEGER_DIVIDE_BY_ZERO: dissector tried an integer division by zero");
				break;
			case(STATUS_STACK_OVERFLOW):
				show_exception(tvb, pinfo, parent_tree, DissectorError,
					       "STATUS_STACK_OVERFLOW: dissector overflowed the stack (e.g. endless loop)");
				/* XXX - this will have probably corrupted the stack,
				   which makes problems later in the exception code */
				break;
				/* XXX - add other hardware exception codes as required */
			default:
				show_exception(tvb, pinfo, parent_tree, DissectorError,
					       ws_strdup_printf("dissector caused an unknown exception: 0x%x", GetExceptionCode()));
			}
		}
#endif
	}
	CATCH_BOUNDS_AND_DISSECTOR_ERRORS {
		ensure_tree_item(parent_tree, EXCEPTION_TREE_ITEMS);
		show_exception(tvb, pinfo, parent_tree, EXCEPT_CODE, GET_MESSAGE);
	}
	ENDTRY;

	if (proto_field_is_referenced(tree, hf_frame_protocols)) {
		wmem_strbuf_t *val = wmem_strbuf_new_sized(pinfo->pool, 128);
		wmem_list_frame_t *frame;
		/* skip the first entry, it's always the "frame" protocol */
		frame = wmem_list_frame_next(wmem_list_head(pinfo->layers));
		if (frame) {
			wmem_strbuf_append(val, proto_get_protocol_filter_name(GPOINTER_TO_UINT(wmem_list_frame_data(frame))));
			frame = wmem_list_frame_next(frame);
		}
		while (frame) {
			wmem_strbuf_append_c(val, ':');
			wmem_strbuf_append(val, proto_get_protocol_filter_name(GPOINTER_TO_UINT(wmem_list_frame_data(frame))));
			frame = wmem_list_frame_next(frame);
		}
		ensure_tree_item(fh_tree, 1);
		ti = proto_tree_add_string(fh_tree, hf_frame_protocols, tvb, 0, 0, wmem_strbuf_get_str(val));
		proto_item_set_generated(ti);
	}

	proto_tree_add_uint(fh_tree, hf_frame_encoding, tvb, 0, 0, pinfo->fd->encoding);

	/* Add the columns as fields. We have to do this here, so that
	 * they're available for postdissectors that want all the fields.
	 *
	 * Note the coloring rule names are set after this, which means
	 * that you can set a coloring rule based on the value of a column,
	 * like _ws.col.protocol or _ws.col.info.
	 * OTOH, if we created _ws.col.custom, and a custom column used
	 * frame.coloring_rule.name, filtering with it wouldn't work -
	 * but you can filter on that field directly, so that doesn't matter.
	 */
	col_dissect(tvb, pinfo, parent_tree);

	/*  Call postdissectors if we have any (while trying to avoid another
	 *  TRY/CATCH)
	 */
	if (have_postdissector()) {
		TRY {
#ifdef _MSC_VER
			/* Win32: Visual-C Structured Exception Handling (SEH)
			   to trap hardware exceptions like memory access violations */
			/* (a running debugger will be called before the except part below) */
			/* Note: A Windows "exceptional exception" may leave the kazlib's (Portable Exception Handling)
			   stack in an inconsistent state thus causing a crash at some point in the
			   handling of the exception.
			   See: https://lists.wireshark.org/archives/wireshark-dev/200704/msg00243.html
			*/
			__try {
#endif
				call_all_postdissectors(tvb, pinfo, parent_tree);
#ifdef _MSC_VER
			} __except(EXCEPTION_EXECUTE_HANDLER /* handle all exceptions */) {
				ensure_tree_item(parent_tree, EXCEPTION_TREE_ITEMS);
				switch (GetExceptionCode()) {
				case(STATUS_ACCESS_VIOLATION):
					show_exception(tvb, pinfo, parent_tree, DissectorError,
						       "STATUS_ACCESS_VIOLATION: dissector accessed an invalid memory address");
					break;
				case(STATUS_INTEGER_DIVIDE_BY_ZERO):
					show_exception(tvb, pinfo, parent_tree, DissectorError,
						       "STATUS_INTEGER_DIVIDE_BY_ZERO: dissector tried an integer division by zero");
					break;
				case(STATUS_STACK_OVERFLOW):
					show_exception(tvb, pinfo, parent_tree, DissectorError,
						       "STATUS_STACK_OVERFLOW: dissector overflowed the stack (e.g. endless loop)");
					/* XXX - this will have probably corrupted the stack,
					   which makes problems later in the exception code */
					break;
					/* XXX - add other hardware exception codes as required */
				default:
					show_exception(tvb, pinfo, parent_tree, DissectorError,
						       ws_strdup_printf("dissector caused an unknown exception: 0x%x", GetExceptionCode()));
				}
			}
#endif
		}
		CATCH_BOUNDS_AND_DISSECTOR_ERRORS {
			ensure_tree_item(parent_tree, EXCEPTION_TREE_ITEMS);
			show_exception(tvb, pinfo, parent_tree, EXCEPT_CODE, GET_MESSAGE);
		}
		ENDTRY;
	}

	/* Attempt to (re-)calculate color filters (if any). */
	if (pinfo->fd->need_colorize) {
		color_filter = color_filters_colorize_packet(fr_data->color_edt);
		pinfo->fd->color_filter = color_filter;
		pinfo->fd->need_colorize = 0;
	} else {
		color_filter = pinfo->fd->color_filter;
	}
	if (color_filter) {
		ensure_tree_item(fh_tree, 1);
		item = proto_tree_add_string(fh_tree, hf_frame_color_filter_name, tvb,
					     0, 0, color_filter->filter_name);
		proto_item_set_generated(item);
		ensure_tree_item(fh_tree, 1);
		item = proto_tree_add_string(fh_tree, hf_frame_color_filter_text, tvb,
					     0, 0, color_filter->filter_text);
		proto_item_set_generated(item);
	}

	tap_queue_packet(frame_tap, pinfo, NULL);


	if (pinfo->frame_end_routines) {
		g_slist_free_full(pinfo->frame_end_routines, &call_frame_end_routine);
		pinfo->frame_end_routines = NULL;
	}

	if (prefs.enable_incomplete_dissectors_check && tree && tree->tree_data->visible) {
		char* decoded;
		unsigned length;
		unsigned i;
		unsigned byte;
		unsigned bit;

		length = tvb_captured_length(tvb);
		decoded = proto_find_undecoded_data(tree, length);

		for (i = 0; i < length; i++) {
			byte = i / 8;
			bit = i % 8;
			if (!(decoded[byte] & (1 << bit))) {
				field_info* fi = proto_find_field_from_offset(tree, i, tvb);
				if (fi && fi->hfinfo->id != proto_frame) {
					if (prefs.incomplete_dissectors_check_debug)
						ws_log(LOG_DOMAIN_CAPTURE, LOG_LEVEL_WARNING,
							"Dissector %s incomplete in frame %u: undecoded byte number %u "
							"(0x%.4X+%u)",
							fi->hfinfo->abbrev,
							pinfo->num, i, i - i % 16, i % 16);
					ensure_tree_item(tree, 1);
					proto_tree_add_expert_format(tree, pinfo, &ei_incomplete, tvb, i, 1, "Undecoded byte number: %u (0x%.4X+%u)", i, i - i % 16, i % 16);
				}
			}
		}
	}

	return tvb_captured_length(tvb);
}

void
proto_register_frame(void)
{
	static hf_register_info hf[] = {
		{ &hf_frame_arrival_time_local,
		  { "Arrival Time", "frame.time",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    "Absolute time when this frame was captured, in local time", HFILL }},

		{ &hf_frame_arrival_time_utc,
		  { "UTC Arrival Time", "frame.time_utc",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
		    "Absolute time when this frame was captured, in Coordinated Universal Time (UTC)", HFILL }},

		{ &hf_frame_arrival_time_epoch,
		  { "Epoch Arrival Time", "frame.time_epoch",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UNIX, NULL, 0x0,
		    "Absolute time when this frame was captured, in Epoch time (also known as Unix time)", HFILL }},

		{ &hf_frame_shift_offset,
		  { "Time shift for this packet", "frame.offset_shift",
		    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		    "Time shift applied to this packet", HFILL }},

		{ &hf_frame_time_delta,
		  { "Time delta from previous captured frame", "frame.time_delta",
		    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_time_delta_displayed,
		  { "Time delta from previous displayed frame", "frame.time_delta_displayed",
		    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_time_relative,
		  { "Time since reference or first frame", "frame.time_relative",
		    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		    "Time relative to time reference or first frame", HFILL }},

		{ &hf_frame_time_relative_cap,
		  { "Time since start of capturing", "frame.time_relative_capture_start",
		    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		    "Time relative to the capture start", HFILL }},

		{ &hf_frame_time_reference,
		  { "This is a Time Reference frame", "frame.ref_time",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    "This frame is a Time Reference frame", HFILL }},

		{ &hf_frame_number,
		  { "Frame Number", "frame.number",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_len,
		  { "Frame Length", "frame.len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Frame length on the wire", HFILL }},

		{ &hf_frame_capture_len,
		  { "Capture Length", "frame.cap_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Frame length stored into the capture file", HFILL }},

		{ &hf_frame_md5_hash,
		  { "Frame MD5 Hash", "frame.md5_hash",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_p2p_dir,
		  { "Point-to-Point Direction", "frame.p2p_dir",
		    FT_INT8, BASE_DEC, VALS(p2p_dirs), 0x0,
		    NULL, HFILL }},

		{ &hf_frame_link_number,
		  { "Link Number", "frame.link_nr",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_file_off,
		  { "File Offset", "frame.file_off",
		    FT_INT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_marked,
		  { "Frame is marked", "frame.marked",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Frame is marked in the GUI", HFILL }},

		{ &hf_frame_ignored,
		  { "Frame is ignored", "frame.ignored",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Frame is ignored by the dissectors", HFILL }},

		{ &hf_frame_protocols,
		  { "Protocols in frame", "frame.protocols",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Protocols carried by this frame", HFILL }},

		{ &hf_frame_color_filter_name,
		  { "Coloring Rule Name", "frame.coloring_rule.name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "The frame matched the coloring rule with this name", HFILL }},

		{ &hf_frame_color_filter_text,
		  { "Coloring Rule String", "frame.coloring_rule.string",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "The frame matched this coloring rule string", HFILL }},

		{ &hf_frame_section_number,
		  { "Section number", "frame.section_number",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "The number of the file section this frame is in", HFILL }},

		{ &hf_frame_interface_id,
		  { "Interface id", "frame.interface_id",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_interface_name,
		  { "Interface name", "frame.interface_name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "The friendly name for this interface", HFILL }},

		{ &hf_frame_interface_description,
		  { "Interface description", "frame.interface_description",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "The description for this interface", HFILL }},

		{ &hf_frame_interface_queue,
		  { "Interface queue", "frame.interface_queue",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_pack_flags,
		  { "Packet flags", "frame.packet_flags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_pack_direction,
		  { "Direction", "frame.packet_flags_direction",
		    FT_UINT32, BASE_HEX, VALS(packet_word_directions), PACK_FLAGS_DIRECTION_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_reception_type,
		  { "Reception type", "frame.packet_flags_reception_type",
		    FT_UINT32, BASE_DEC, VALS(packet_word_reception_types), PACK_FLAGS_RECEPTION_TYPE_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_fcs_length,
		  { "FCS length", "frame.packet_flags_fcs_length",
		    FT_UINT32, BASE_DEC, NULL, PACK_FLAGS_FCS_LENGTH_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_reserved,
		  { "Reserved", "frame.packet_flags_reserved",
		    FT_UINT32, BASE_DEC, NULL, PACK_FLAGS_RESERVED_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_crc_error,
		  { "CRC error", "frame.packet_flags_crc_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACK_FLAGS_CRC_ERROR,
		    NULL, HFILL }},

		{ &hf_frame_pack_wrong_packet_too_long_error,
		  { "Packet too long error", "frame.packet_flags_packet_too_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACK_FLAGS_PACKET_TOO_LONG,
		    NULL, HFILL }},

		{ &hf_frame_pack_wrong_packet_too_short_error,
		  { "Packet too short error", "frame.packet_flags_packet_too_short_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACK_FLAGS_PACKET_TOO_SHORT,
		    NULL, HFILL }},

		{ &hf_frame_pack_wrong_inter_frame_gap_error,
		  { "Wrong interframe gap error", "frame.packet_flags_wrong_inter_frame_gap_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACK_FLAGS_WRONG_INTER_FRAME_GAP,
		    NULL, HFILL }},

		{ &hf_frame_pack_unaligned_frame_error,
		  { "Unaligned frame error", "frame.packet_flags_unaligned_frame_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACK_FLAGS_UNALIGNED_FRAME,
		    NULL, HFILL }},

		{ &hf_frame_pack_start_frame_delimiter_error,
		  { "Start frame delimiter error", "frame.packet_flags_start_frame_delimiter_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACK_FLAGS_START_FRAME_DELIMITER_ERROR,
		    NULL, HFILL }},

		{ &hf_frame_pack_preamble_error,
		  { "Preamble error", "frame.packet_flags_preamble_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACK_FLAGS_PREAMBLE_ERROR,
		    NULL, HFILL }},

		{ &hf_frame_pack_symbol_error,
		  { "Symbol error", "frame.packet_flags_symbol_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACK_FLAGS_SYMBOL_ERROR,
		    NULL, HFILL }},

		{ &hf_frame_comment,
		  { "Comment", "frame.comment",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_packet_id,
		  { "Packet id", "frame.packet_id",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_hash,
		  { "Hash Algorithm", "frame.hash",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_hash_bytes,
		  { "Hash Value", "frame.hash.value",
		    FT_BYTES, SEP_SPACE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_verdict,
		  { "Verdict", "frame.verdict",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_verdict_hardware,
		  { "Hardware", "frame.verdict.hw",
		    FT_BYTES, SEP_SPACE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_verdict_tc,
		  { "eBPF TC", "frame.verdict.ebpf_tc",
		    FT_INT64, BASE_DEC|BASE_VAL64_STRING,
		    VALS64(verdict_ebpf_tc_types), 0x0,
		    NULL, HFILL }},

		{ &hf_frame_verdict_xdp,
		  { "eBPF XDP", "frame.verdict.ebpf_xdp",
		    FT_INT64, BASE_DEC|BASE_VAL64_STRING,
		    VALS64(verdict_ebpf_xdp_types), 0x0,
		    NULL, HFILL }},

		{ &hf_frame_verdict_unknown,
		  { "Unknown", "frame.verdict.unknown",
		    FT_BYTES, SEP_SPACE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_drop_count,
		  { "Drop Count", "frame.drop_count",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    "Number of frames lost between this frame and the preceding one on the same interface", HFILL }},

		{ &hf_frame_cb_pen,
		  { "Private Enterprise Number", "frame.cb_pen",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "IANA assigned private enterprise number (PEN)", HFILL }},

		{ &hf_frame_cb_copy_allowed,
		  { "Copying", "frame.cb_copy",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_allowed_not_allowed), 0x0,
		    "Whether the custom block will be written or not", HFILL }},

		{ &hf_frame_encoding,
		  { "Character encoding", "frame.encoding",
		    FT_UINT32, BASE_DEC, VALS(packet_char_enc_types), 0x0,
		    "Character encoding (ASCII, EBCDIC...)", HFILL }},

	};

	static hf_register_info hf_encap =
		{ &hf_frame_wtap_encap,
		  { "Encapsulation type", "frame.encap_type",
		    FT_INT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }};

	static int *ett[] = {
		&ett_frame,
		&ett_ifname,
		&ett_flags,
		&ett_comments,
		&ett_hash,
		&ett_verdict,
	};

	static ei_register_info ei[] = {
		{ &ei_comments_text, { "frame.comment.expert", PI_COMMENTS_GROUP, PI_COMMENT, "Formatted comment", EXPFILL }},
		{ &ei_arrive_time_out_of_range, { "frame.time_invalid", PI_SEQUENCE, PI_NOTE, "Arrival Time: Fractional second out of range (0-1000000000)", EXPFILL }},
		{ &ei_incomplete, { "frame.incomplete", PI_UNDECODED, PI_NOTE, "Incomplete dissector", EXPFILL }},
		{ &ei_len_lt_caplen, { "frame.len_lt_caplen", PI_MALFORMED, PI_ERROR, "Frame length is less than captured length", EXPFILL }}
	};

	module_t *frame_module;
	expert_module_t* expert_frame;

	if (hf_encap.hfinfo.strings == NULL) {
		int encap_count = wtap_get_num_encap_types();
		value_string *arr;
		int i;

		hf_encap.hfinfo.strings = arr = wmem_alloc_array(wmem_epan_scope(), value_string, encap_count+1);

		for (i = 0; i < encap_count; i++) {
			arr[i].value = i;
			arr[i].strptr = wtap_encap_description(i);
		}
		arr[encap_count].value = 0;
		arr[encap_count].strptr = NULL;
	}

	proto_frame = proto_register_protocol("Frame", "Frame", "frame");
	if (application_flavor_is_wireshark()) {
		proto_pkt_comment = proto_register_protocol_in_name_only("Packet comments", "Pkt_Comment", "pkt_comment", proto_frame, FT_PROTOCOL);
		proto_register_alias(proto_pkt_comment, "evt_comment");
	} else {
		proto_pkt_comment = proto_register_protocol_in_name_only("Event comments", "Evt_Comment", "evt_comment", proto_frame, FT_PROTOCOL);
		proto_register_alias(proto_pkt_comment, "pkt_comment");
	}
	proto_syscall = proto_register_protocol("System Call", "Syscall", "syscall");

	proto_register_field_array(proto_frame, hf, array_length(hf));
	proto_register_field_array(proto_frame, &hf_encap, 1);
	proto_register_subtree_array(ett, array_length(ett));
	expert_frame = expert_register_protocol(proto_frame);
	expert_register_field_array(expert_frame, ei, array_length(ei));
	register_dissector("frame",dissect_frame,proto_frame);

	wtap_encap_dissector_table = register_dissector_table("wtap_encap",
	    "Wiretap encapsulation type", proto_frame, FT_UINT32, BASE_DEC);
	wtap_fts_rec_dissector_table = register_dissector_table("wtap_fts_rec",
	    "Wiretap file type for file-type-specific records", proto_frame, FT_UINT32, BASE_DEC);
	block_pen_dissector_table = register_dissector_table("pcapng_custom_block",
	    "PcapNG custom block PEN", proto_frame, FT_UINT32, BASE_DEC);
	binary_option_pen_dissector_table = register_dissector_table("pcapng_custom_binary_option",
	    "PcapNG custom binary option PEN", proto_frame, FT_UINT32, BASE_DEC);
	register_capture_dissector_table("wtap_encap", "Wiretap encapsulation type");

	/* You can't disable dissection of "Frame", as that would be
	   tantamount to not doing any dissection whatsoever. */
	proto_set_cant_toggle(proto_frame);

	register_seq_analysis("any", "All Flows", proto_frame, NULL, TL_REQUIRES_COLUMNS, frame_seq_analysis_packet);

	/* Our preferences */
	frame_module = prefs_register_protocol(proto_frame, NULL);
	prefs_register_bool_preference(frame_module, "show_file_off",
	    "Show File Offset", "Show offset of frame in capture file", &show_file_off);
	prefs_register_bool_preference(frame_module, "force_docsis_encap",
	    "Treat all frames as DOCSIS frames", "Treat all frames as DOCSIS Frames", &force_docsis_encap);
	prefs_register_bool_preference(frame_module, "generate_md5_hash",
	    "Generate an MD5 hash of each frame",
	    "Whether or not MD5 hashes should be generated for each frame, useful for finding duplicate frames.",
	    &generate_md5_hash);
	prefs_register_obsolete_preference(frame_module, "generate_epoch_time");
	prefs_register_bool_preference(frame_module, "generate_bits_field",
	    "Show the number of bits in the frame",
	    "Whether or not the number of bits in the frame should be shown.",
	    &generate_bits_field);
	prefs_register_bool_preference(frame_module, "disable_packet_size_limited_in_summary",
	    "Disable 'packet size limited during capture' message in summary",
	    "Whether or not 'packet size limited during capture' message in shown in Info column.",
	    &disable_packet_size_limited_in_summary);
	prefs_register_uint_preference(frame_module, "max_comment_lines",
	    "Maximum number of lines to display for one packet comment",
	    "Show at most this many lines of a multi-line packet comment"
	    " (applied separately to each comment)",
	    10, &max_comment_lines);

	frame_tap=register_tap("frame");
}

void
proto_reg_handoff_frame(void)
{
	docsis_handle = find_dissector_add_dependency("docsis", proto_frame);
	sysdig_handle = find_dissector_add_dependency("sysdig", proto_frame);
	systemd_journal_handle = find_dissector_add_dependency("systemd_journal", proto_frame);
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
