/* packet-frame.c
 *
 * Top-most dissector. Decides dissector based on Wiretap Encapsulation Type.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#ifdef _MSC_VER
#include <windows.h>
#endif

#include <glib.h>

#include <wsutil/md5.h>

#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include <wiretap/wtap.h>
#include <epan/tap.h>
#include <epan/expert.h>

#include "packet-frame.h"

#include "color.h"
#include "color_filters.h"

void proto_register_frame(void);
void proto_reg_handoff_frame(void);

int proto_frame = -1;
static int proto_pkt_comment = -1;
int hf_frame_arrival_time = -1;
static int hf_frame_shift_offset = -1;
static int hf_frame_arrival_time_epoch = -1;
static int hf_frame_time_delta = -1;
static int hf_frame_time_delta_displayed = -1;
static int hf_frame_time_relative = -1;
static int hf_frame_time_reference = -1;
int hf_frame_number = -1;
int hf_frame_len = -1;
int hf_frame_capture_len = -1;
static int hf_frame_p2p_dir = -1;
static int hf_frame_file_off = -1;
static int hf_frame_md5_hash = -1;
static int hf_frame_marked = -1;
static int hf_frame_ignored = -1;
static int hf_link_number = -1;
static int hf_frame_protocols = -1;
static int hf_frame_color_filter_name = -1;
static int hf_frame_color_filter_text = -1;
static int hf_frame_interface_id = -1;
static int hf_frame_pack_flags = -1;
static int hf_frame_pack_direction = -1;
static int hf_frame_pack_reception_type = -1;
static int hf_frame_pack_fcs_length = -1;
static int hf_frame_pack_reserved = -1;
static int hf_frame_pack_crc_error = -1;
static int hf_frame_pack_wrong_packet_too_long_error = -1;
static int hf_frame_pack_wrong_packet_too_short_error = -1;
static int hf_frame_pack_wrong_inter_frame_gap_error = -1;
static int hf_frame_pack_unaligned_frame_error = -1;
static int hf_frame_pack_start_frame_delimiter_error = -1;
static int hf_frame_pack_preamble_error = -1;
static int hf_frame_pack_symbol_error = -1;
static int hf_frame_wtap_encap = -1;
static int hf_comments_text = -1;
static int hf_frame_num_p_prot_data = -1;

static gint ett_frame = -1;
static gint ett_flags = -1;
static gint ett_comments = -1;

static expert_field ei_comments_text = EI_INIT;
static expert_field ei_arrive_time_out_of_range = EI_INIT;

static int frame_tap = -1;

static dissector_handle_t data_handle;
static dissector_handle_t docsis_handle;

/* Preferences */
static gboolean show_file_off       = FALSE;
static gboolean force_docsis_encap  = FALSE;
static gboolean generate_md5_hash   = FALSE;
static gboolean generate_epoch_time = TRUE;
static gboolean generate_bits_field = TRUE;

static const value_string p2p_dirs[] = {
	{ P2P_DIR_UNKNOWN, "Unknown" },
	{ P2P_DIR_SENT,	"Sent" },
	{ P2P_DIR_RECV, "Received" },
	{ 0, NULL }
};

#define PACKET_WORD_DIRECTION_MASK                        0x00000003
#define PACKET_WORD_RECEPTION_TYPE_MASK                   0x0000001C
#define PACKET_WORD_FCS_LENGTH_MASK                       0x000001E0
#define PACKET_WORD_RESERVED_MASK                         0x0000FE00
#define PACKET_WORD_CRC_ERR_MASK                          0x01000000
#define PACKET_WORD_PACKET_TOO_LONG_ERR_MASK              0x02000000
#define PACKET_WORD_PACKET_TOO_SHORT_ERR_MASK             0x04000000
#define PACKET_WORD_WRONG_INTER_FRAME_GAP_ERR_MASK        0x08000000
#define PACKET_WORD_UNALIGNED_FRAME_ERR_MASK              0x10000000
#define PACKET_WORD_START_FRAME_DELIMITER_ERR_MASK        0x20000000
#define PACKET_WORD_PREAMBLE_ERR_MASK                     0x40000000
#define PACKET_WORD_SYMBOL_ERR_MASK                       0x80000000

static const value_string packet_word_directions[] = {
	{ 0x00, "Not available" },
	{ 0x01, "Inbound" },
	{ 0x02, "Outbound" },
	{ 0x03, "Undefined" },
	{ 0, NULL }
};

static const value_string packet_word_reception_types[] = {
	{ 0x00, "Not specified" },
	{ 0x01, "Unicast" },
	{ 0x02, "Multicast" },
	{ 0x03, "Broadcast" },
	{ 0x04, "Promiscuous" },
	{ 0x05, "Undefined" },
	{ 0x06, "Undefined" },
	{ 0x07, "Undefined" },
	{ 0, NULL }
};

dissector_table_t wtap_encap_dissector_table;
static dissector_table_t wtap_fts_rec_dissector_table;;

/*
 * Routine used to register frame end routine.  The routine should only
 * be registered when the dissector is used in the frame, not in the
 * proto_register_XXX function.
 */
void
register_frame_end_routine(packet_info *pinfo, void (*func)(void))
{
	pinfo->frame_end_routines = g_slist_append(pinfo->frame_end_routines, (gpointer)func);
}

typedef void (*void_func_t)(void);

static void
call_frame_end_routine(gpointer routine, gpointer dummy _U_)
{
	void_func_t func = (void_func_t)routine;
	(*func)();
}

static void
dissect_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item  *volatile ti = NULL, *comment_item;
	guint	     cap_len = 0, frame_len = 0;
	proto_tree  *volatile tree;
	proto_tree  *comments_tree;
	proto_item  *item;
	const gchar *cap_plurality, *frame_plurality;

	tree=parent_tree;

	switch (pinfo->phdr->rec_type) {

	case REC_TYPE_PACKET:
		pinfo->current_proto = "Frame";
		if (pinfo->pseudo_header != NULL) {
			switch (pinfo->fd->lnk_t) {

			case WTAP_ENCAP_WFLEET_HDLC:
			case WTAP_ENCAP_CHDLC_WITH_PHDR:
			case WTAP_ENCAP_PPP_WITH_PHDR:
			case WTAP_ENCAP_SDLC:
			case WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR:
				pinfo->p2p_dir = pinfo->pseudo_header->p2p.sent ?
				    P2P_DIR_SENT : P2P_DIR_RECV;
				break;

			case WTAP_ENCAP_BLUETOOTH_HCI:
				pinfo->p2p_dir = pinfo->pseudo_header->bthci.sent;
				break;

			case WTAP_ENCAP_LAPB:
			case WTAP_ENCAP_FRELAY_WITH_PHDR:
				pinfo->p2p_dir =
				    (pinfo->pseudo_header->x25.flags & FROM_DCE) ?
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
				pinfo->annex_a_used = pinfo->pseudo_header->mtp2.annex_a_used;
				break;

			case WTAP_ENCAP_GSM_UM:
				pinfo->p2p_dir = pinfo->pseudo_header->gsm_um.uplink ?
				    P2P_DIR_SENT : P2P_DIR_RECV;
				break;
			}
		}
		break;

	case REC_TYPE_FT_SPECIFIC_EVENT:
		pinfo->current_proto = "Event";
		break;

	case REC_TYPE_FT_SPECIFIC_REPORT:
		pinfo->current_proto = "Report";
		break;

	default:
		g_assert_not_reached();
		break;
	}

	if(pinfo->pkt_comment){
		item = proto_tree_add_item(tree, proto_pkt_comment, tvb, 0, 0, ENC_NA);
		comments_tree = proto_item_add_subtree(item, ett_comments);
		comment_item = proto_tree_add_string_format(comments_tree, hf_comments_text, tvb, 0, 0,
							                   pinfo->pkt_comment, "%s",
							                   pinfo->pkt_comment);
		expert_add_info_format(pinfo, comment_item, &ei_comments_text,
					                       "%s",  pinfo->pkt_comment);


	}

	/* if FRAME is not referenced from any filters we dont need to worry about
	   generating any tree items.  */
	if(!proto_field_is_referenced(tree, proto_frame)) {
		tree=NULL;
		if(pinfo->fd->flags.has_ts) {
			if(pinfo->fd->abs_ts.nsecs < 0 || pinfo->fd->abs_ts.nsecs >= 1000000000)
				expert_add_info(pinfo, NULL, &ei_arrive_time_out_of_range);
		}
	} else {
		proto_tree *fh_tree;
		gboolean old_visible;

		/* Put in frame header information. */
		cap_len = tvb_length(tvb);
		frame_len = tvb_reported_length(tvb);

		cap_plurality = plurality(cap_len, "", "s");
		frame_plurality = plurality(frame_len, "", "s");

		ti = proto_tree_add_protocol_format(tree, proto_frame, tvb, 0, tvb_captured_length(tvb),
		    "Frame %u: %u byte%s on wire",
		    pinfo->fd->num, frame_len, frame_plurality);
		if (generate_bits_field)
			proto_item_append_text(ti, " (%u bits)", frame_len * 8);
		proto_item_append_text(ti, ", %u byte%s captured",
		    cap_len, cap_plurality);
		if (generate_bits_field) {
			proto_item_append_text(ti, " (%u bits)",
			    cap_len * 8);
		}
		if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID) {
			proto_item_append_text(ti, " on interface %u",
			    pinfo->phdr->interface_id);
		}
		if (pinfo->phdr->presence_flags & WTAP_HAS_PACK_FLAGS) {
			if (pinfo->phdr->pack_flags & 0x00000001) {
				proto_item_append_text(ti, " (inbound)");
				pinfo->p2p_dir = P2P_DIR_RECV;
			}
			if (pinfo->phdr->pack_flags & 0x00000002) {
				proto_item_append_text(ti, " (outbound)");
				pinfo->p2p_dir = P2P_DIR_SENT;
			}
		}

		fh_tree = proto_item_add_subtree(ti, ett_frame);

		if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID && proto_field_is_referenced(tree, hf_frame_interface_id)) {
			const char *interface_name = epan_get_interface_name(pinfo->epan, pinfo->phdr->interface_id);

			if (interface_name)
				proto_tree_add_uint_format_value(fh_tree, hf_frame_interface_id, tvb, 0, 0, pinfo->phdr->interface_id, "%u (%s)", pinfo->phdr->interface_id, interface_name);
			else
				proto_tree_add_uint(fh_tree, hf_frame_interface_id, tvb, 0, 0, pinfo->phdr->interface_id);
		}

		if (pinfo->phdr->presence_flags & WTAP_HAS_PACK_FLAGS) {
			proto_tree *flags_tree;
			proto_item *flags_item;

			flags_item = proto_tree_add_uint(fh_tree, hf_frame_pack_flags, tvb, 0, 0, pinfo->phdr->pack_flags);
			flags_tree = proto_item_add_subtree(flags_item, ett_flags);
			proto_tree_add_uint(flags_tree, hf_frame_pack_direction, tvb, 0, 0, pinfo->phdr->pack_flags);
			proto_tree_add_uint(flags_tree, hf_frame_pack_reception_type, tvb, 0, 0, pinfo->phdr->pack_flags);
			proto_tree_add_uint(flags_tree, hf_frame_pack_fcs_length, tvb, 0, 0, pinfo->phdr->pack_flags);
			proto_tree_add_uint(flags_tree, hf_frame_pack_reserved, tvb, 0, 0, pinfo->phdr->pack_flags);
			proto_tree_add_boolean(flags_tree, hf_frame_pack_crc_error, tvb, 0, 0, pinfo->phdr->pack_flags);
			proto_tree_add_boolean(flags_tree, hf_frame_pack_wrong_packet_too_long_error, tvb, 0, 0, pinfo->phdr->pack_flags);
			proto_tree_add_boolean(flags_tree, hf_frame_pack_wrong_packet_too_short_error, tvb, 0, 0, pinfo->phdr->pack_flags);
			proto_tree_add_boolean(flags_tree, hf_frame_pack_wrong_inter_frame_gap_error, tvb, 0, 0, pinfo->phdr->pack_flags);
			proto_tree_add_boolean(flags_tree, hf_frame_pack_unaligned_frame_error, tvb, 0, 0, pinfo->phdr->pack_flags);
			proto_tree_add_boolean(flags_tree, hf_frame_pack_start_frame_delimiter_error, tvb, 0, 0, pinfo->phdr->pack_flags);
			proto_tree_add_boolean(flags_tree, hf_frame_pack_preamble_error, tvb, 0, 0, pinfo->phdr->pack_flags);
			proto_tree_add_boolean(flags_tree, hf_frame_pack_symbol_error, tvb, 0, 0, pinfo->phdr->pack_flags);
		}

		if (pinfo->phdr->rec_type == REC_TYPE_PACKET)
			proto_tree_add_int(fh_tree, hf_frame_wtap_encap, tvb, 0, 0, pinfo->fd->lnk_t);

		if (pinfo->fd->flags.has_ts) {
			proto_tree_add_time(fh_tree, hf_frame_arrival_time, tvb,
					    0, 0, &(pinfo->fd->abs_ts));
			if(pinfo->fd->abs_ts.nsecs < 0 || pinfo->fd->abs_ts.nsecs >= 1000000000) {
				expert_add_info_format(pinfo, ti, &ei_arrive_time_out_of_range,
								  "Arrival Time: Fractional second %09ld is invalid,"
								  " the valid range is 0-1000000000",
								  (long) pinfo->fd->abs_ts.nsecs);
			}
			item = proto_tree_add_time(fh_tree, hf_frame_shift_offset, tvb,
					    0, 0, &(pinfo->fd->shift_offset));
			PROTO_ITEM_SET_GENERATED(item);

			if(generate_epoch_time) {
				proto_tree_add_time(fh_tree, hf_frame_arrival_time_epoch, tvb,
						    0, 0, &(pinfo->fd->abs_ts));
			}

			if (proto_field_is_referenced(tree, hf_frame_time_delta)) {
				nstime_t     del_cap_ts;

				frame_delta_abs_time(pinfo->epan, pinfo->fd, pinfo->fd->num - 1, &del_cap_ts);

				item = proto_tree_add_time(fh_tree, hf_frame_time_delta, tvb,
							   0, 0, &(del_cap_ts));
				PROTO_ITEM_SET_GENERATED(item);
			}

			if (proto_field_is_referenced(tree, hf_frame_time_delta_displayed)) {
				nstime_t del_dis_ts;

				frame_delta_abs_time(pinfo->epan, pinfo->fd, pinfo->fd->prev_dis_num, &del_dis_ts);

				item = proto_tree_add_time(fh_tree, hf_frame_time_delta_displayed, tvb,
							   0, 0, &(del_dis_ts));
				PROTO_ITEM_SET_GENERATED(item);
			}

			item = proto_tree_add_time(fh_tree, hf_frame_time_relative, tvb,
						   0, 0, &(pinfo->rel_ts));
			PROTO_ITEM_SET_GENERATED(item);

			if(pinfo->fd->flags.ref_time){
				ti = proto_tree_add_item(fh_tree, hf_frame_time_reference, tvb, 0, 0, ENC_NA);
				PROTO_ITEM_SET_GENERATED(ti);
			}
		}

		proto_tree_add_uint(fh_tree, hf_frame_number, tvb,
				    0, 0, pinfo->fd->num);

		proto_tree_add_uint_format(fh_tree, hf_frame_len, tvb,
					   0, 0, frame_len, "Frame Length: %u byte%s (%u bits)",
					   frame_len, frame_plurality, frame_len * 8);

		proto_tree_add_uint_format(fh_tree, hf_frame_capture_len, tvb,
					   0, 0, cap_len, "Capture Length: %u byte%s (%u bits)",
					   cap_len, cap_plurality, cap_len * 8);

		if (generate_md5_hash) {
			const guint8 *cp;
			md5_state_t   md_ctx;
			md5_byte_t    digest[16];
			const gchar  *digest_string;

			cp = tvb_get_ptr(tvb, 0, cap_len);

			md5_init(&md_ctx);
			md5_append(&md_ctx, cp, cap_len);
			md5_finish(&md_ctx, digest);

			digest_string = bytestring_to_str(wmem_packet_scope(), digest, 16, '\0');
			ti = proto_tree_add_string(fh_tree, hf_frame_md5_hash, tvb, 0, 0, digest_string);
			PROTO_ITEM_SET_GENERATED(ti);
		}

		ti = proto_tree_add_boolean(fh_tree, hf_frame_marked, tvb, 0, 0,pinfo->fd->flags.marked);
		PROTO_ITEM_SET_GENERATED(ti);

		ti = proto_tree_add_boolean(fh_tree, hf_frame_ignored, tvb, 0, 0,pinfo->fd->flags.ignored);
		PROTO_ITEM_SET_GENERATED(ti);

		if(proto_field_is_referenced(tree, hf_frame_protocols)) {
			/* we are going to be using proto_item_append_string() on
			 * hf_frame_protocols, and we must therefore disable the
			 * TRY_TO_FAKE_THIS_ITEM() optimisation for the tree by
			 * setting it as visible.
			 *
			 * See proto.h for details.
			 */
			old_visible = proto_tree_set_visible(fh_tree, TRUE);
			ti = proto_tree_add_string(fh_tree, hf_frame_protocols, tvb, 0, 0, "");
			PROTO_ITEM_SET_GENERATED(ti);
			proto_tree_set_visible(fh_tree, old_visible);
		}

		if(pinfo->fd->pfd != 0){
			proto_item *ppd_item;
			guint num_entries = g_slist_length(pinfo->fd->pfd);
			guint i;
			ppd_item = proto_tree_add_uint(fh_tree, hf_frame_num_p_prot_data, tvb, 0, 0, num_entries);
			PROTO_ITEM_SET_GENERATED(ppd_item);
			for(i=0; i<num_entries; i++){
				proto_tree_add_text (fh_tree, tvb, 0, 0, "%s",p_get_proto_name_and_key(wmem_file_scope(), pinfo, i));
			}
		}
		/* Check for existences of P2P pseudo header */
		if (pinfo->p2p_dir != P2P_DIR_UNKNOWN) {
			proto_tree_add_int(fh_tree, hf_frame_p2p_dir, tvb,
					   0, 0, pinfo->p2p_dir);
		}

		/* Check for existences of MTP2 link number */
		if ((pinfo->pseudo_header != NULL ) && (pinfo->fd->lnk_t == WTAP_ENCAP_MTP2_WITH_PHDR)) {
			proto_tree_add_uint(fh_tree, hf_link_number, tvb,
					    0, 0, pinfo->link_number);
		}

		if (show_file_off) {
			proto_tree_add_int64_format_value(fh_tree, hf_frame_file_off, tvb,
						    0, 0, pinfo->fd->file_off,
						    "%" G_GINT64_MODIFIER "d (0x%" G_GINT64_MODIFIER "x)",
						    pinfo->fd->file_off, pinfo->fd->file_off);
		}

		if(pinfo->fd->color_filter != NULL) {
			const color_filter_t *color_filter = (const color_filter_t *)pinfo->fd->color_filter;
			item = proto_tree_add_string(fh_tree, hf_frame_color_filter_name, tvb,
						     0, 0, color_filter->filter_name);
			PROTO_ITEM_SET_GENERATED(item);
			item = proto_tree_add_string(fh_tree, hf_frame_color_filter_text, tvb,
						     0, 0, color_filter->filter_text);
			PROTO_ITEM_SET_GENERATED(item);
		}
	}

	if (pinfo->fd->flags.ignored) {
		/* Ignored package, stop handling here */
		col_set_str(pinfo->cinfo, COL_INFO, "<Ignored>");
		proto_tree_add_text (tree, tvb, 0, 0, "This frame is marked as ignored");
		return;
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
                   See: https://www.wireshark.org/lists/wireshark-dev/200704/msg00243.html
                */
		__try {
#endif
			switch (pinfo->phdr->rec_type) {

			case REC_TYPE_PACKET:
				if ((force_docsis_encap) && (docsis_handle)) {
					call_dissector(docsis_handle, tvb, pinfo, parent_tree);
				} else {
					if (!dissector_try_uint(wtap_encap_dissector_table, pinfo->fd->lnk_t,
								tvb, pinfo, parent_tree)) {

						col_set_str(pinfo->cinfo, COL_PROTOCOL, "UNKNOWN");
						col_add_fstr(pinfo->cinfo, COL_INFO, "WTAP_ENCAP = %d",
							     pinfo->fd->lnk_t);
						call_dissector(data_handle,tvb, pinfo, parent_tree);
					}
				}
				break;

			case REC_TYPE_FT_SPECIFIC_EVENT:
			case REC_TYPE_FT_SPECIFIC_REPORT:
				if (!dissector_try_uint(wtap_fts_rec_dissector_table, pinfo->file_type_subtype,
							tvb, pinfo, parent_tree)) {

					col_set_str(pinfo->cinfo, COL_PROTOCOL, "UNKNOWN");
					col_add_fstr(pinfo->cinfo, COL_INFO, "WTAP_ENCAP = %d",
						     pinfo->file_type_subtype);
					call_dissector(data_handle,tvb, pinfo, parent_tree);
				}
				break;
			}
#ifdef _MSC_VER
		} __except(EXCEPTION_EXECUTE_HANDLER /* handle all exceptions */) {
			switch(GetExceptionCode()) {
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
					       g_strdup_printf("dissector caused an unknown exception: 0x%x", GetExceptionCode()));
			}
		}
#endif
	}
	CATCH_BOUNDS_AND_DISSECTOR_ERRORS {
		show_exception(tvb, pinfo, parent_tree, EXCEPT_CODE, GET_MESSAGE);
	}
	ENDTRY;

        if(proto_field_is_referenced(tree, hf_frame_protocols)) {
		wmem_strbuf_t *val = wmem_strbuf_sized_new(wmem_packet_scope(), 128, 0);
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
		proto_item_append_string(ti, wmem_strbuf_get_str(val));
	}

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
                           See: https://www.wireshark.org/lists/wireshark-dev/200704/msg00243.html
                        */
			__try {
#endif
				call_all_postdissectors(tvb, pinfo, parent_tree);
#ifdef _MSC_VER
			} __except(EXCEPTION_EXECUTE_HANDLER /* handle all exceptions */) {
				switch(GetExceptionCode()) {
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
						       g_strdup_printf("dissector caused an unknown exception: 0x%x", GetExceptionCode()));
				}
			}
#endif
		}
		CATCH_BOUNDS_AND_DISSECTOR_ERRORS {
			show_exception(tvb, pinfo, parent_tree, EXCEPT_CODE, GET_MESSAGE);
		}
		ENDTRY;
	}

	tap_queue_packet(frame_tap, pinfo, NULL);


	if (pinfo->frame_end_routines) {
		g_slist_foreach(pinfo->frame_end_routines, &call_frame_end_routine, NULL);
		g_slist_free(pinfo->frame_end_routines);
		pinfo->frame_end_routines = NULL;
	}
}

void
proto_register_frame(void)
{
	static hf_register_info hf[] = {
		{ &hf_frame_arrival_time,
		  { "Arrival Time", "frame.time",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    "Absolute time when this frame was captured", HFILL }},

		{ &hf_frame_shift_offset,
		  { "Time shift for this packet", "frame.offset_shift",
		    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		    "Time shift applied to this packet", HFILL }},

		{ &hf_frame_arrival_time_epoch,
		  { "Epoch Time", "frame.time_epoch",
		    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		    "Epoch time when this frame was captured", HFILL }},

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

		{ &hf_frame_time_reference,
		  { "This is a Time Reference frame", "frame.ref_time",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    "This frame is a Time Reference frame", HFILL }},

		{ &hf_frame_number,
		  { "Frame Number", "frame.number",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_len,
		  { "Frame length on the wire", "frame.len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_capture_len,
		  { "Frame length stored into the capture file", "frame.cap_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_md5_hash,
		  { "Frame MD5 Hash", "frame.md5_hash",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_p2p_dir,
		  { "Point-to-Point Direction", "frame.p2p_dir",
		    FT_INT8, BASE_DEC, VALS(p2p_dirs), 0x0,
		    NULL, HFILL }},

		{ &hf_link_number,
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

		{ &hf_frame_interface_id,
		  { "Interface id", "frame.interface_id",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_pack_flags,
		  { "Packet flags", "frame.packet_flags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_pack_direction,
		  { "Direction", "frame.packet_flags_direction",
		    FT_UINT32, BASE_HEX, VALS(packet_word_directions), PACKET_WORD_DIRECTION_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_reception_type,
		  { "Reception type", "frame.packet_flags_reception_type",
		    FT_UINT32, BASE_DEC, VALS(packet_word_reception_types), PACKET_WORD_RECEPTION_TYPE_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_fcs_length,
		  { "FCS length", "frame.packet_flags_fcs_length",
		    FT_UINT32, BASE_DEC, NULL, PACKET_WORD_FCS_LENGTH_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_reserved,
		  { "Reserved", "frame.packet_flags_reserved",
		    FT_UINT32, BASE_DEC, NULL, PACKET_WORD_RESERVED_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_crc_error,
		  { "CRC error", "frame.packet_flags_crc_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACKET_WORD_CRC_ERR_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_wrong_packet_too_long_error,
		  { "Packet too long error", "frame.packet_flags_packet_too_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACKET_WORD_PACKET_TOO_LONG_ERR_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_wrong_packet_too_short_error,
		  { "Packet too short error", "frame.packet_flags_packet_too_short_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACKET_WORD_PACKET_TOO_SHORT_ERR_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_wrong_inter_frame_gap_error,
		  { "Wrong interframe gap error", "frame.packet_flags_wrong_inter_frame_gap_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACKET_WORD_WRONG_INTER_FRAME_GAP_ERR_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_unaligned_frame_error,
		  { "Unaligned frame error", "frame.packet_flags_unaligned_frame_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACKET_WORD_UNALIGNED_FRAME_ERR_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_start_frame_delimiter_error,
		  { "Start frame delimiter error", "frame.packet_flags_start_frame_delimiter_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACKET_WORD_START_FRAME_DELIMITER_ERR_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_preamble_error,
		  { "Preamble error", "frame.packet_flags_preamble_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACKET_WORD_PREAMBLE_ERR_MASK,
		    NULL, HFILL }},

		{ &hf_frame_pack_symbol_error,
		  { "Symbol error", "frame.packet_flags_symbol_error",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), PACKET_WORD_SYMBOL_ERR_MASK,
		    NULL, HFILL }},

		{ &hf_comments_text,
		  { "Comment", "frame.comment",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_frame_num_p_prot_data,
		  { "Number of per-protocol-data", "frame.p_prot_data",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
	};

	static hf_register_info hf_encap =
		{ &hf_frame_wtap_encap,
		  { "Encapsulation type", "frame.encap_type",
		    FT_INT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }};

 	static gint *ett[] = {
		&ett_frame,
		&ett_flags,
		&ett_comments
	};

	static ei_register_info ei[] = {
		{ &ei_comments_text, { "frame.comment.expert", PI_COMMENTS_GROUP, PI_COMMENT, "Formatted comment", EXPFILL }},
		{ &ei_arrive_time_out_of_range, { "frame.time_invalid", PI_SEQUENCE, PI_NOTE, "Arrival Time: Fractional second out of range (0-1000000000)", EXPFILL }},
	};

	module_t *frame_module;
	expert_module_t* expert_frame;

	if (hf_encap.hfinfo.strings == NULL) {
		int encap_count = wtap_get_num_encap_types();
		value_string *arr;
		int i;

		hf_encap.hfinfo.strings = arr = g_new(value_string, encap_count+1);

		for (i = 0; i < encap_count; i++) {
			arr[i].value = i;
			arr[i].strptr = wtap_encap_string(i);
		}
		arr[encap_count].value = 0;
		arr[encap_count].strptr = NULL;
	}

	wtap_encap_dissector_table = register_dissector_table("wtap_encap",
	    "Wiretap encapsulation type", FT_UINT32, BASE_DEC);
	wtap_fts_rec_dissector_table = register_dissector_table("wtap_fts_rec",
	    "Wiretap file type for file-type-specific records", FT_UINT32, BASE_DEC);

	proto_frame = proto_register_protocol("Frame", "Frame", "frame");
	proto_pkt_comment = proto_register_protocol("Packet comments", "Pkt_Comment", "pkt_comment");
	proto_register_field_array(proto_frame, hf, array_length(hf));
	proto_register_field_array(proto_frame, &hf_encap, 1);
	proto_register_subtree_array(ett, array_length(ett));
	expert_frame = expert_register_protocol(proto_frame);
	expert_register_field_array(expert_frame, ei, array_length(ei));
	register_dissector("frame",dissect_frame,proto_frame);

	/* You can't disable dissection of "Frame", as that would be
	   tantamount to not doing any dissection whatsoever. */
	proto_set_cant_toggle(proto_frame);

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
	prefs_register_bool_preference(frame_module, "generate_epoch_time",
	    "Generate an epoch time entry for each frame",
	    "Whether or not an Epoch time entry should be generated for each frame.",
	    &generate_epoch_time);
	prefs_register_bool_preference(frame_module, "generate_bits_field",
	    "Show the number of bits in the frame",
	    "Whether or not the number of bits in the frame should be shown.",
	    &generate_bits_field);

	frame_tap=register_tap("frame");
}

void
proto_reg_handoff_frame(void)
{
	data_handle = find_dissector("data");
	docsis_handle = find_dissector("docsis");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
