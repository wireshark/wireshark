/* packet-xot.c
 * Routines for X.25 over TCP dissection (RFC 1613)
 *
 * Copyright 2000, Paul Ionescu	<paul@acorp.ro>
 *
 * $Id: packet-xot.c,v 1.10 2002/04/09 08:15:02 guy Exp $
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
#include <stdlib.h>
#include <ctype.h>

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include "packet-frame.h"
#include "prefs.h"

#define TCP_PORT_XOT 1998

static gint proto_xot = -1;
static gint hf_xot_version = -1;
static gint hf_xot_length = -1;

static gint ett_xot = -1;

/* desegmentation of X.25 over TCP */
static gboolean xot_desegment = TRUE;

static dissector_handle_t x25_handle;

static void dissect_xot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  volatile int offset = 0;
  int length_remaining;
  guint16 version;
  guint16 plen;
  int length;
  proto_item *ti;
  proto_tree *xot_tree;
  tvbuff_t   *next_tvb; 

  while (tvb_reported_length_remaining(tvb, offset) != 0) {
    length_remaining = tvb_length_remaining(tvb, offset);

    /*
     * Can we do reassembly?
     */
    if (xot_desegment && pinfo->can_desegment) {
      /*
       * Yes - is the X.25-over-TCP header split across segment boundaries?
       */
      if (length_remaining < 4) {
	/*
	 * Yes.  Tell the TCP dissector where the data for this message
	 * starts in the data it handed us, and how many
	 * more bytes we need, and return.
	 */
	pinfo->desegment_offset = offset;
	pinfo->desegment_len = 4 - length_remaining;
	return;
      }
    }

    /*
     * Get the length of the XOT packet.
     */
    version = tvb_get_ntohs(tvb, offset + 0);
    if (version != 0)
      return;
    plen    = tvb_get_ntohs(tvb, offset + 2);

    /*
     * Can we do reassembly?
     */
    if (xot_desegment && pinfo->can_desegment) {
      /*
       * Yes - is the XOT packet split across segment boundaries?
       */
      if (length_remaining < plen + 4) {
	/*
	 * Yes.  Tell the TCP dissector where the data for this message
	 * starts in the data it handed us, and how many more bytes we
	 * need, and return.
	 */
	pinfo->desegment_offset = offset;
	pinfo->desegment_len = (plen + 4) - length_remaining;
	return;
      }
    }

    /*
     * Dissect the X.25-over-TCP packet.
     *
     * Catch the ReportedBoundsError exception; if this particular message
     * happens to get a ReportedBoundsError exception, that doesn't mean
     * that we should stop dissecting X.25-over-TCP messages within this
     * frame or chunk of reassembled data.
     *
     * If it gets a BoundsError, we can stop, as there's nothing more to see,
     * so we just re-throw it.
     */
    TRY {
      if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "XOT");
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "XOT Version = %u, size = %u",
		     version,plen );

      if (tree) {
	ti = proto_tree_add_protocol_format(tree, proto_xot, tvb, offset, 4,
					    "X.25 over TCP");
	xot_tree = proto_item_add_subtree(ti, ett_xot);
     
	proto_tree_add_uint(xot_tree, hf_xot_version, tvb, offset, 2, version);
	proto_tree_add_uint(xot_tree, hf_xot_length, tvb, offset + 2, 2, plen);
      }

      /*
       * Construct a tvbuff containing the amount of the payload we have
       * available.  Make its reported length the amount of data in the
       * X.25-over-TCP packet.
       *
       * XXX - if reassembly isn't enabled. the subdissector will throw a
       * BoundsError exception, rather than a ReportedBoundsError exception.
       * We really want a tvbuff where the length is "length", the reported
       * length is "plen + 4", and the "if the snapshot length were infinite"
       * length is the minimum of the reported length of the tvbuff handed
       * to us and "plen+4", with a new type of exception thrown if the offset
       * is within the reported length but beyond that third length, with that
       * exception getting the "Unreassembled Packet" error.
       */
      length = length_remaining - 4;
      if (length > plen)
        length = plen;
      next_tvb = tvb_new_subset(tvb, offset + 4, length, plen);
      call_dissector(x25_handle,next_tvb,pinfo,tree);
    }
    CATCH(BoundsError) {
      RETHROW;
    }
    CATCH(ReportedBoundsError) {
      show_reported_bounds_error(tvb, pinfo, tree);
    }
    ENDTRY;

    /*
     * Skip the X.25-over-TCP header and the payload.
     */
    offset += plen + 4;
  }
}

/* Register the protocol with Ethereal */
void 
proto_register_xot(void)
{
	static hf_register_info hf[] = {
		{ &hf_xot_version,
			{ "Version", "xot.version", FT_UINT16, BASE_DEC,
			NULL, 0, "Version of X.25 over TCP protocol", HFILL }},

		{ &hf_xot_length,
			{ "Length", "xot.length", FT_UINT16, BASE_DEC,
			NULL, 0, "Length of X.25 over TCP packet", HFILL }}

	};

	static gint *ett[] = {
		&ett_xot,
	};
	module_t *xot_module;

	proto_xot = proto_register_protocol("X.25 over TCP", "XOT", "xot");
	proto_register_field_array(proto_xot, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	xot_module = prefs_register_protocol(proto_xot, NULL);
	prefs_register_bool_preference(xot_module, "desegment",
	    "Desegment all X.25-over-TCP messages spanning multiple TCP segments",
	    "Whether the X.25-over-TCP dissector should desegment all messages spanning multiple TCP segments",
	    &xot_desegment);
}

void
proto_reg_handoff_xot(void)
{
	dissector_handle_t xot_handle;

	/*
	 * Get a handle for the X.25 dissector.
	 */
	x25_handle = find_dissector("x.25");

	xot_handle = create_dissector_handle(dissect_xot, proto_xot);
	dissector_add("tcp.port", TCP_PORT_XOT, xot_handle);
}
