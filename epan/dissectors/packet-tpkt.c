/* packet-tpkt.c
 *
 * Routine to check for RFC 1006 TPKT header and to dissect TPKT header
 * Copyright 2000, Philips Electronics N.V.
 * Andreas Sikkema <h323@ramdyne.nl>
 *
 * Routine to dissect RFC 1006 TPKT packet containing OSI TP PDU
 * Copyright 2001, Martin Thomas <Martin_A_Thomas@yahoo.com>
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

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>

#include "packet-tpkt.h"
#include "packet-frame.h"
#include <epan/prefs.h>

/* TPKT header fields             */
static int proto_tpkt          = -1;
static protocol_t *proto_tpkt_ptr;
static int hf_tpkt_version     = -1;
static int hf_tpkt_reserved    = -1;
static int hf_tpkt_length      = -1;

/* TPKT fields defining a sub tree */
static gint ett_tpkt           = -1;

/* desegmentation of OSI over TPKT over TCP */
static gboolean tpkt_desegment = TRUE;

#define TCP_PORT_TPKT	102

/* find the dissector for OSI TP (aka COTP) */
static dissector_handle_t osi_tp_handle;

/*
 * Check whether this could be a TPKT-encapsulated PDU.
 * Returns -1 if it's not, and the PDU length from the TPKT header
 * if it is.
 *
 * "min_len" is the minimum length of the PDU; the length field in the
 * TPKT header must be at least "4+min_len" in order for this to be a
 * valid TPKT PDU for the protocol in question.
 */
int
is_tpkt(tvbuff_t *tvb, int min_len)
{
	guint16 pkt_len;

	/*
	 * If TPKT is disabled, don't dissect it, just return -1, meaning
	 * "this isn't TPKT".
	 */
	if (!proto_is_protocol_enabled(proto_tpkt_ptr))
		return -1;

	/* There should at least be 4 bytes left in the frame */
	if (!tvb_bytes_exist(tvb, 0, 4))
		return -1;	/* there aren't */

	/*
	 * The first octet should be 3 and the second one should be 0
	 * The H.323 implementers guide suggests that this might not
	 * always be the case....
	 */
	if (!(tvb_get_guint8(tvb, 0) == 3 && tvb_get_guint8(tvb, 1) == 0))
		return -1;	/* they're not */

	/*
	 * Get the length from the TPKT header.  Make sure it's large
	 * enough.
	 */
	pkt_len = tvb_get_ntohs(tvb, 2);
	if (pkt_len < 4 + min_len)
		return -1;	/* it's not */

	/*
	 * Return the length from the header.
	 */
	return pkt_len;
}

/*
 * Dissect TPKT-encapsulated data in a TCP stream.
 */
void
dissect_tpkt_encap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean desegment, dissector_handle_t subdissector_handle)
{
	proto_item *ti = NULL;
	proto_tree *tpkt_tree = NULL;
	volatile int offset = 0;
	int length_remaining;
	int data_len;
	volatile int length;
	tvbuff_t *next_tvb;
	const char *saved_proto;

	/*
	 * If we're reassembling segmented TPKT PDUs, empty the COL_INFO
	 * column, so subdissectors can append information
	 * without having to worry about emptying the column.
	 *
	 * We use "col_add_str()" because the subdissector
	 * might be appending information to the column, in
	 * which case we'd have to zero the buffer out explicitly
	 * anyway.
	 */
	if (desegment && check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO, "");

	while (tvb_reported_length_remaining(tvb, offset) != 0) {
		/*
		 * Is the first byte of this putative TPKT header
		 * a valid TPKT version number, i.e. 3?
		 */
		if (tvb_get_guint8(tvb, offset) != 3) {
			/*
			 * No, so don't assume this is a TPKT header;
			 * we might be in the middle of TPKT data,
			 * so don't get the length and don't try to
			 * do reassembly.
			 */
			if (check_col(pinfo->cinfo, COL_PROTOCOL))
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "TPKT");
			if (check_col(pinfo->cinfo, COL_INFO))
				col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
			if (tree) {
				ti = proto_tree_add_item(tree, proto_tpkt, tvb,
				    offset, -1, FALSE);
				tpkt_tree = proto_item_add_subtree(ti, ett_tpkt);
				proto_item_set_text(ti, "TPKT");

				proto_tree_add_text(tpkt_tree, tvb, offset, -1,
				    "Continuation data");
			}
			return;
		}

		length_remaining = tvb_length_remaining(tvb, offset);

		/*
		 * Can we do reassembly?
		 */
		if (desegment && pinfo->can_desegment) {
			/*
			 * Yes - is the TPKT header split across segment
			 * boundaries?
			 */
			if (length_remaining < 4) {
				/*
				 * Yes.  Tell the TCP dissector where
				 * the data for this message starts in
				 * the data it handed us, and how many
				 * more bytes we need, and return.
				 */
				pinfo->desegment_offset = offset;
				pinfo->desegment_len = 4 - length_remaining;
				return;
			}
		}

		/*
		 * Get the length from the TPKT header.
		 */
		data_len = tvb_get_ntohs(tvb, offset + 2);

		/*
		 * Can we do reassembly?
		 */
		if (desegment && pinfo->can_desegment) {
			/*
			 * Yes - is the payload split across segment
			 * boundaries?
			 */
			if (length_remaining < data_len) {
				/*
				 * Yes.  Tell the TCP dissector where
				 * the data for this message starts in
				 * the data it handed us, and how many
				 * more bytes we need, and return.
				 */
				pinfo->desegment_offset = offset;
				pinfo->desegment_len =
				    data_len - length_remaining;
				return;
			}
		}

		/*
		 * Dissect the TPKT header.
		 * Save and restore "pinfo->current_proto".
		 */
		saved_proto = pinfo->current_proto;
		pinfo->current_proto = "TPKT";

		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "TPKT");
		/*
		 * Don't add the TPKT header information if we're
		 * reassembling segmented TPKT PDUs or if this
		 * PDU isn't reassembled.
		 *
		 * XXX - the first is so that subdissectors can append
		 * information without getting TPKT stuff in the middle;
		 * why the second?
		 */
		if (!desegment && !pinfo->fragmented
		    && check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "TPKT Data length = %u", data_len);
		}

		if (tree) {
			ti = proto_tree_add_item(tree, proto_tpkt, tvb,
			    offset, 4, FALSE);
			tpkt_tree = proto_item_add_subtree(ti, ett_tpkt);
			proto_item_set_text(ti, "TPKT");

			/* Version */
			proto_tree_add_item(tpkt_tree, hf_tpkt_version, tvb,
			    offset, 1, FALSE);
			proto_item_append_text(ti, ", Version: 3");

			/* Reserved octet*/
			proto_tree_add_item(tpkt_tree, hf_tpkt_reserved, tvb,
			    offset + 1, 1, FALSE);

			/* Length */
			proto_tree_add_uint(tpkt_tree, hf_tpkt_length, tvb,
			    offset + 2, 2, data_len);
			proto_item_append_text(ti, ", Length: %u", data_len);
		}
		pinfo->current_proto = saved_proto;

		/* Skip the TPKT header. */
		offset += 4;
		data_len -= 4;

		/*
		 * Construct a tvbuff containing the amount of the payload
		 * we have available.  Make its reported length the
		 * amount of data in this TPKT packet.
		 *
		 * XXX - if reassembly isn't enabled. the subdissector
		 * will throw a BoundsError exception, rather than a
		 * ReportedBoundsError exception.  We really want
		 * a tvbuff where the length is "length", the reported
		 * length is "plen + 2", and the "if the snapshot length
		 * were infinite" length were the minimum of the
		 * reported length of the tvbuff handed to us and "plen+2",
		 * with a new type of exception thrown if the offset is
		 * within the reported length but beyond that third length,
		 * with that exception getting the "Unreassembled Packet"
		 * error.
		 */
		length = length_remaining - 4;
		if (length > data_len)
			length = data_len;
		next_tvb = tvb_new_subset(tvb, offset, length, data_len);

		/*
		 * Call the subdissector.
		 *
		 * Catch the ReportedBoundsError exception; if this
		 * particular message happens to get a ReportedBoundsError
		 * exception, that doesn't mean that we should stop
		 * dissecting TPKT messages within this frame or chunk
		 * of reassembled data.
		 *
		 * If it gets a BoundsError, we can stop, as there's nothing
		 * more to see, so we just re-throw it.
		 */
		TRY {
			call_dissector(subdissector_handle, next_tvb, pinfo,
			    tree);
		}
		CATCH(BoundsError) {
			RETHROW;
		}
		CATCH(ReportedBoundsError) {
			show_reported_bounds_error(tvb, pinfo, tree);
		}
		ENDTRY;

		/*
		 * Skip the payload.
		 */
		offset += length;
	}
}

/*
 * Dissect RFC 1006 TPKT, which wraps a TPKT header around an OSI TP
 * PDU.
 */
static void
dissect_tpkt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_tpkt_encap(tvb, pinfo, tree, tpkt_desegment, osi_tp_handle);
}

void
proto_register_tpkt(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_tpkt_version,
			{
				"Version",
				"tpkt.version",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Version, only version 3 is defined", HFILL
			}
		},
		{
			&hf_tpkt_reserved,
			{
				"Reserved",
				"tpkt.reserved",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Reserved, should be 0", HFILL
			}
		},
		{
			&hf_tpkt_length,
			{
				"Length",
				"tpkt.length",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"Length of data unit, including this header", HFILL
			}
		},
	};

	static gint *ett[] =
	{
		&ett_tpkt,
	};
	module_t *tpkt_module;

	proto_tpkt = proto_register_protocol("TPKT - ISO on TCP - RFC1006", "TPKT", "tpkt");
	proto_tpkt_ptr = find_protocol_by_id(proto_tpkt);
	proto_register_field_array(proto_tpkt, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	tpkt_module = prefs_register_protocol(proto_tpkt, NULL);
	prefs_register_bool_preference(tpkt_module, "desegment",
	    "Reassemble TPKT messages spanning multiple TCP segments",
	    "Whether the TPKT dissector should reassemble messages spanning multiple TCP segments. "
	    "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	    &tpkt_desegment);
}

void
proto_reg_handoff_tpkt(void)
{
	dissector_handle_t tpkt_handle;

	osi_tp_handle = find_dissector("ositp");
	tpkt_handle = create_dissector_handle(dissect_tpkt, proto_tpkt);
	dissector_add("tcp.port", TCP_PORT_TPKT, tpkt_handle);
}
