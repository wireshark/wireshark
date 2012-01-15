/* packet-frame.c
 *
 * Top-most dissector. Decides dissector based on Wiretap Encapsulation Type.
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef _MSC_VER
#include <windows.h>
#endif


#include <glib.h>
#include <epan/packet.h>
#include <epan/timestamp.h>
#include "packet-frame.h"
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/expert.h>
#include <epan/crypt/md5.h>

#include "color.h"
#include "color_filters.h"

int proto_frame = -1;
int hf_frame_arrival_time = -1;
int hf_frame_shift_offset = -1;
int hf_frame_arrival_time_epoch = -1;
static int hf_frame_time_invalid = -1;
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

static int proto_short = -1;
int proto_malformed = -1;
static int proto_unreassembled = -1;

static gint ett_frame = -1;

static int frame_tap = -1;

static dissector_handle_t data_handle;
static dissector_handle_t docsis_handle;

/* Preferences */
static gboolean show_file_off = FALSE;
static gboolean force_docsis_encap = FALSE;
static gboolean generate_md5_hash = FALSE;
static gboolean generate_epoch_time = TRUE;
static gboolean generate_bits_field = TRUE;

static const value_string p2p_dirs[] = {
	{ P2P_DIR_UNKNOWN, "Unknown" },
	{ P2P_DIR_SENT,	"Sent" },
	{ P2P_DIR_RECV, "Received" },
	{ 0, NULL }
};

dissector_table_t wtap_encap_dissector_table;

static GSList *frame_end_routines = NULL;

/*
 * Routine used to register frame end routine.  The routine should only
 * be registered when the dissector is used in the frame, not in the
 * proto_register_XXX function.
 */
void
register_frame_end_routine(void (*func)(void))
{
	frame_end_routines = g_slist_append(frame_end_routines, (gpointer)func);
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
	proto_item	*volatile ti = NULL;
	guint		cap_len = 0, frame_len = 0;
	proto_tree	*volatile tree;
        proto_item  *item;
	const gchar *cap_plurality, *frame_plurality;

	tree=parent_tree;

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

	/* if FRAME is not referenced from any filters we dont need to worry about
	   generating any tree items.  */
	if(!proto_field_is_referenced(tree, proto_frame)) {
		tree=NULL;
        if(pinfo->fd->abs_ts.nsecs < 0 || pinfo->fd->abs_ts.nsecs >= 1000000000)
		expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_WARN,
				       "Arrival Time: Fractional second out of range (0-1000000000)");
	} else {
		proto_tree	*fh_tree;
		gboolean old_visible;

		/* Put in frame header information. */
		cap_len = tvb_length(tvb);
		frame_len = tvb_reported_length(tvb);

		cap_plurality = plurality(cap_len, "", "s");
		frame_plurality = plurality(frame_len, "", "s");

		if (generate_bits_field)
			ti = proto_tree_add_protocol_format(tree, proto_frame, tvb, 0, -1,
			    "Frame %u: %u byte%s on wire (%u bits), %u byte%s captured (%u bits)",
			    pinfo->fd->num, frame_len, frame_plurality, frame_len * 8,
			    cap_len, cap_plurality, cap_len * 8);
		else
			ti = proto_tree_add_protocol_format(tree, proto_frame, tvb, 0, -1,
			    "Frame %u: %u byte%s on wire, %u byte%s captured", pinfo->fd->num,
			     frame_len, frame_plurality, cap_len, cap_plurality);

		fh_tree = proto_item_add_subtree(ti, ett_frame);

		proto_tree_add_time(fh_tree, hf_frame_arrival_time, tvb,
				    0, 0, &(pinfo->fd->abs_ts));
		if(pinfo->fd->abs_ts.nsecs < 0 || pinfo->fd->abs_ts.nsecs >= 1000000000) {
			item = proto_tree_add_none_format(fh_tree, hf_frame_time_invalid, tvb,
							  0, 0, "Arrival Time: Fractional second %09ld is invalid, the valid range is 0-1000000000", (long) pinfo->fd->abs_ts.nsecs);
			PROTO_ITEM_SET_GENERATED(item);
			expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "Arrival Time: Fractional second out of range (0-1000000000)");
		}
		item = proto_tree_add_time(fh_tree, hf_frame_shift_offset, tvb,
				    0, 0, &(pinfo->fd->shift_offset));
		PROTO_ITEM_SET_GENERATED(item);

		if(generate_epoch_time) {
			proto_tree_add_time(fh_tree, hf_frame_arrival_time_epoch, tvb,
					    0, 0, &(pinfo->fd->abs_ts));
		}

		item = proto_tree_add_time(fh_tree, hf_frame_time_delta, tvb,
					   0, 0, &(pinfo->fd->del_cap_ts));
		PROTO_ITEM_SET_GENERATED(item);

		item = proto_tree_add_time(fh_tree, hf_frame_time_delta_displayed, tvb,
					   0, 0, &(pinfo->fd->del_dis_ts));
		PROTO_ITEM_SET_GENERATED(item);

		item = proto_tree_add_time(fh_tree, hf_frame_time_relative, tvb,
					   0, 0, &(pinfo->fd->rel_ts));
		PROTO_ITEM_SET_GENERATED(item);

		if(pinfo->fd->flags.ref_time){
			ti = proto_tree_add_item(fh_tree, hf_frame_time_reference, tvb, 0, 0, ENC_NA);
			PROTO_ITEM_SET_GENERATED(ti);
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
			md5_state_t md_ctx;
			md5_byte_t digest[16];
			gchar *digest_string;

			cp = tvb_get_ptr(tvb, 0, cap_len);

			md5_init(&md_ctx);
			md5_append(&md_ctx, cp, cap_len);
			md5_finish(&md_ctx, digest);

			digest_string = bytestring_to_str(digest, 16, '\0');
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

			pinfo->layer_names = g_string_new("");
		}
		else
			pinfo->layer_names = NULL;

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
			proto_tree_add_int64_format(fh_tree, hf_frame_file_off, tvb,
						    0, 0, pinfo->fd->file_off,
						    "File Offset: %" G_GINT64_MODIFIER "d (0x%" G_GINT64_MODIFIER "x)",
						    pinfo->fd->file_off, pinfo->fd->file_off);
		}

		if(pinfo->fd->color_filter != NULL) {
			const color_filter_t *color_filter = pinfo->fd->color_filter;
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
		proto_tree_add_text (tree, tvb, 0, -1, "This frame is marked as ignored");
		return;
	}

	/* Portable Exception Handling to trap Wireshark specific exceptions like BoundsError exceptions */
	TRY {
#ifdef _MSC_VER
		/* Win32: Visual-C Structured Exception Handling (SEH) to trap hardware exceptions like memory access violations */
		/* (a running debugger will be called before the except part below) */
		__try {
#endif
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
				/* XXX - this will have probably corrupted the stack, which makes problems later in the exception code */
				break;
				/* XXX - add other hardware exception codes as required */
			default:
				show_exception(tvb, pinfo, parent_tree, DissectorError,
					       g_strdup_printf("dissector caused an unknown exception: 0x%x", GetExceptionCode()));
			}
		}
#endif
	}
	CATCH(OutOfMemoryError) {
		RETHROW;
	}
	CATCH_ALL {
		show_exception(tvb, pinfo, parent_tree, EXCEPT_CODE, GET_MESSAGE);
	}
	ENDTRY;

	if (tree && pinfo->layer_names) {
		proto_item_append_string(ti, pinfo->layer_names->str);
		g_string_free(pinfo->layer_names, TRUE);
		pinfo->layer_names = NULL;
	}

	/*  Call postdissectors if we have any (while trying to avoid another
	 *  TRY/CATCH)
	 */
	if (have_postdissector()) {
		TRY {
#ifdef _MSC_VER
			/* Win32: Visual-C Structured Exception Handling (SEH) to trap hardware exceptions like memory access violations */
			/* (a running debugger will be called before the except part below) */
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
					/* XXX - this will have probably corrupted the stack, which makes problems later in the exception code */
					break;
					/* XXX - add other hardware exception codes as required */
				default:
					show_exception(tvb, pinfo, parent_tree, DissectorError,
						       g_strdup_printf("dissector caused an unknown exception: 0x%x", GetExceptionCode()));
				}
			}
#endif
		}
		CATCH(OutOfMemoryError) {
			RETHROW;
		}
		CATCH_ALL {
			show_exception(tvb, pinfo, parent_tree, EXCEPT_CODE, GET_MESSAGE);
		}
		ENDTRY;
	}

	tap_queue_packet(frame_tap, pinfo, NULL);


	if (frame_end_routines) {
		g_slist_foreach(frame_end_routines, &call_frame_end_routine, NULL);
		g_slist_free(frame_end_routines);
		frame_end_routines = NULL;
	}
}

void
show_exception(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	       unsigned long exception, const char *exception_message)
{
	static const char dissector_error_nomsg[] =
		"Dissector writer didn't bother saying what the error was";
	proto_item *item;


	switch (exception) {

	case ScsiBoundsError:
		col_append_str(pinfo->cinfo, COL_INFO, "[SCSI transfer limited due to allocation_length too small]");
		/*item =*/ proto_tree_add_protocol_format(tree, proto_short, tvb, 0, 0,
				"SCSI transfer limited due to allocation_length too small: %s truncated]", pinfo->current_proto);
		/* Don't record ScsiBoundsError exceptions as expert events - they merely
		 * reflect a normal SCSI condition.
		 * (any case where it's caused by something else is a bug). */
		/* expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Packet size limited");*/
		break;

	case BoundsError:
		col_append_str(pinfo->cinfo, COL_INFO, "[Packet size limited during capture]");
		/*item =*/ proto_tree_add_protocol_format(tree, proto_short, tvb, 0, 0,
				"[Packet size limited during capture: %s truncated]", pinfo->current_proto);
		/* Don't record BoundsError exceptions as expert events - they merely
		 * reflect a capture done with a snapshot length too short to capture
		 * all of the packet
		 * (any case where it's caused by something else is a bug). */
		/* expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Packet size limited");*/
		break;

	case ReportedBoundsError:
		show_reported_bounds_error(tvb, pinfo, tree);
		break;

	case DissectorError:
		col_append_fstr(pinfo->cinfo, COL_INFO,
		    "[Dissector bug, protocol %s: %s]",
		    pinfo->current_proto,
		    exception_message == NULL ?
		        dissector_error_nomsg : exception_message);
		item = proto_tree_add_protocol_format(tree, proto_malformed, tvb, 0, 0,
		    "[Dissector bug, protocol %s: %s]",
		    pinfo->current_proto,
		    exception_message == NULL ?
		        dissector_error_nomsg : exception_message);
		g_warning("Dissector bug, protocol %s, in packet %u: %s",
		    pinfo->current_proto, pinfo->fd->num,
		    exception_message == NULL ?
		        dissector_error_nomsg : exception_message);
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
		    "%s",
		    exception_message == NULL ?
		        dissector_error_nomsg : exception_message);
		break;

	default:
		/* XXX - we want to know, if an unknown exception passed until here, don't we? */
		g_assert_not_reached();
	}
}

void
show_reported_bounds_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;

	if (pinfo->fragmented) {
		/*
		 * We were dissecting an unreassembled fragmented
		 * packet when the exception was thrown, so the
		 * problem isn't that the dissector expected
		 * something but it wasn't in the packet, the
		 * problem is that the dissector expected something
		 * but it wasn't in the fragment we dissected.
		 */
		col_append_fstr(pinfo->cinfo, COL_INFO,
		    "[Unreassembled Packet%s] ",
		    pinfo->noreassembly_reason);
		item = proto_tree_add_protocol_format(tree, proto_unreassembled,
		    tvb, 0, 0, "[Unreassembled Packet%s: %s]",
		    pinfo->noreassembly_reason, pinfo->current_proto);
		expert_add_info_format(pinfo, item, PI_REASSEMBLE, PI_WARN, "Unreassembled Packet (Exception occurred)");
	} else {
		col_append_str(pinfo->cinfo, COL_INFO,
		    "[Malformed Packet]");
		item = proto_tree_add_protocol_format(tree, proto_malformed,
		    tvb, 0, 0, "[Malformed Packet: %s]", pinfo->current_proto);
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Packet (Exception occurred)");
	}
}

void
proto_register_frame(void)
{
	static hf_register_info hf[] = {
		{ &hf_frame_arrival_time,
		{ "Arrival Time",		"frame.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
			"Absolute time when this frame was captured", HFILL }},

		{ &hf_frame_shift_offset,
		{ "Time shift for this packet","frame.offset_shift", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
			"Time shift applied to this packet", HFILL }},

		{ &hf_frame_arrival_time_epoch,
		{ "Epoch Time",			"frame.time_epoch", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
			"Epoch time when this frame was captured", HFILL }},

		{ &hf_frame_time_invalid,
		{ "Arrival Timestamp invalid",		"frame.time_invalid", FT_NONE, BASE_NONE, NULL, 0x0,
			"The timestamp from the capture is out of the valid range", HFILL }},

		{ &hf_frame_time_delta,
		{ "Time delta from previous captured frame",	"frame.time_delta", FT_RELATIVE_TIME, BASE_NONE, NULL,
			0x0,
			NULL, HFILL }},

		{ &hf_frame_time_delta_displayed,
		{ "Time delta from previous displayed frame",	"frame.time_delta_displayed", FT_RELATIVE_TIME, BASE_NONE, NULL,
			0x0,
			NULL, HFILL }},

		{ &hf_frame_time_relative,
		{ "Time since reference or first frame",	"frame.time_relative", FT_RELATIVE_TIME, BASE_NONE, NULL,
			0x0,
			"Time relative to time reference or first frame", HFILL }},

		{ &hf_frame_time_reference,
		{ "This is a Time Reference frame",	"frame.ref_time", FT_NONE, BASE_NONE, NULL, 0x0,
			"This frame is a Time Reference frame", HFILL }},

		{ &hf_frame_number,
		{ "Frame Number",		"frame.number", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_frame_len,
		{ "Frame length on the wire",		"frame.len", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_frame_capture_len,
		{ "Frame length stored into the capture file",	"frame.cap_len", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_frame_md5_hash,
		{ "Frame MD5 Hash",	"frame.md5_hash", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_frame_p2p_dir,
		{ "Point-to-Point Direction",	"frame.p2p_dir", FT_INT8, BASE_DEC, VALS(p2p_dirs), 0x0,
			NULL, HFILL }},

		{ &hf_link_number,
		{ "Link Number",		"frame.link_nr", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_frame_file_off,
		{ "File Offset",	"frame.file_off", FT_INT64, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_frame_marked,
		{ "Frame is marked",	"frame.marked", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Frame is marked in the GUI", HFILL }},

		{ &hf_frame_ignored,
		{ "Frame is ignored",	"frame.ignored", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Frame is ignored by the dissectors", HFILL }},

		{ &hf_frame_protocols,
		{ "Protocols in frame",	"frame.protocols", FT_STRING, BASE_NONE, NULL, 0x0,
			"Protocols carried by this frame", HFILL }},

		{ &hf_frame_color_filter_name,
		{ "Coloring Rule Name",	"frame.coloring_rule.name", FT_STRING, BASE_NONE, NULL, 0x0,
			"The frame matched the coloring rule with this name", HFILL }},

		{ &hf_frame_color_filter_text,
		{ "Coloring Rule String", "frame.coloring_rule.string", FT_STRING, BASE_NONE, NULL, 0x0,
			"The frame matched this coloring rule string", HFILL }}
	};
	static gint *ett[] = {
		&ett_frame
	};
	module_t *frame_module;

	wtap_encap_dissector_table = register_dissector_table("wtap_encap",
	    "Wiretap encapsulation type", FT_UINT32, BASE_DEC);

	proto_frame = proto_register_protocol("Frame", "Frame", "frame");
	proto_register_field_array(proto_frame, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("frame",dissect_frame,proto_frame);

	/* You can't disable dissection of "Frame", as that would be
	   tantamount to not doing any dissection whatsoever. */
	proto_set_cant_toggle(proto_frame);

	proto_short = proto_register_protocol("Short Frame", "Short frame", "short");
	proto_malformed = proto_register_protocol("Malformed Packet",
	    "Malformed packet", "malformed");
	proto_unreassembled = proto_register_protocol(
	    "Unreassembled Fragmented Packet",
	    "Unreassembled fragmented packet", "unreassembled");

	/* "Short Frame", "Malformed Packet", and "Unreassembled Fragmented
	   Packet" aren't really protocols, they're error indications;
	   disabling them makes no sense. */
	proto_set_cant_toggle(proto_short);
	proto_set_cant_toggle(proto_malformed);
	proto_set_cant_toggle(proto_unreassembled);

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
