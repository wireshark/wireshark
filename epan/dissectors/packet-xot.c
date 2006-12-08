/* packet-xot.c
 * Routines for X.25 over TCP dissection (RFC 1613)
 *
 * Copyright 2000, Paul Ionescu	<paul@acorp.ro>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
#include <epan/emem.h>
#include "packet-tcp.h"
#include <epan/prefs.h>

#define TCP_PORT_XOT 1998

static gint proto_xot = -1;
static gint hf_xot_version = -1;
static gint hf_xot_length = -1;

static gint ett_xot = -1;

/* desegmentation of X.25 over TCP */
static gboolean xot_desegment = TRUE;

static dissector_handle_t x25_handle;

static guint get_xot_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint16 plen;

  /*
   * Get the length of the X.25-over-TCP packet.
   */
  plen = tvb_get_ntohs(tvb, offset + 2);

  /*
   * That length doesn't include the header; add that in.
   */
  return plen + 4;
}

static void dissect_xot_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int offset = 0;
  guint16 version;
  guint16 plen;
  int length;
  proto_item *ti;
  proto_tree *xot_tree;
  tvbuff_t   *next_tvb;

  /*
   * Dissect the X.25-over-TCP packet.
   */
  version = tvb_get_ntohs(tvb, offset + 0);
  plen = tvb_get_ntohs(tvb, offset + 2);
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "XOT");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "XOT Version = %u, size = %u",
		 version, plen);

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
   */
  length = tvb_length_remaining(tvb, offset + 4);
  if (length > plen)
    length = plen;
  if (plen > 0)
  {
    next_tvb = tvb_new_subset(tvb, offset + 4, length, plen);
    call_dissector(x25_handle, next_tvb, pinfo, tree);
  }
}

static int dissect_xot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /*
   * Do we have the full version number and, if so, is it zero?
   * If we have it but it's not zero, reject this segment.
   */
  if (tvb_bytes_exist(tvb, 0, 2)) {
    if (tvb_get_ntohs(tvb, 0) != 0)
      return 0;
  }

  /*
   * The version number's OK, so dissect this segment.
   */
  tcp_dissect_pdus(tvb, pinfo, tree, xot_desegment, 4, get_xot_pdu_len,
		   dissect_xot_pdu);

  return tvb_length(tvb);
}

/* Register the protocol with Wireshark */
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
	new_register_dissector("xot", dissect_xot, proto_xot);

	xot_module = prefs_register_protocol(proto_xot, NULL);
	prefs_register_bool_preference(xot_module, "desegment",
	    "Reassemble X.25-over-TCP messages spanning multiple TCP segments",
	    "Whether the X.25-over-TCP dissector should reassemble messages spanning multiple TCP segments. "
	    "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
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

	xot_handle = new_create_dissector_handle(dissect_xot, proto_xot);
	dissector_add("tcp.port", TCP_PORT_XOT, xot_handle);
}
