/* packet-rsh.c
 * Routines for rsh packet disassembly
 *
 * Robert Tsai <rtsai@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
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
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>

static int proto_rsh = -1;
static int hf_rsh_response = -1;
static int hf_rsh_request = -1;
static gint ett_rsh = -1;

#define TCP_PORT_RSH			514

static void
dissect_rsh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*rsh_tree;
	proto_item	*ti, *hidden_item;
	gint		offset = 0;
	gint		next_offset;
	int		linelen;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RSH");
	if (check_col(pinfo->cinfo, COL_INFO)) {
		/* Put the first line from the buffer into the summary. */
		tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
		linelen = next_offset - offset;	/* include the line terminator */

		/*
		 * Make sure the line terminator isn't past the end of
		 * the captured data in the packet, so we don't throw
		 * an exception in the "tvb_get_ptr()" call.
		 */
		if (linelen > (int) tvb_length(tvb))
			linelen = tvb_length(tvb);
		col_add_str(pinfo->cinfo, COL_INFO,
		    tvb_format_text(tvb, offset, linelen));
	}
	if (tree) {
		ti = proto_tree_add_item(tree, proto_rsh, tvb, offset, -1,
		    ENC_NA);
		rsh_tree = proto_item_add_subtree(ti, ett_rsh);

		/*
		 * Process the packet data, a line at a time.
		 */
		while (tvb_offset_exists(tvb, offset)) {
			/*
			 * Find the end of the line.
			 */
			tvb_find_line_end(tvb, offset, -1, &next_offset,
			    FALSE);

			/*
			 * Put this line.
			 */
			proto_tree_add_text(rsh_tree, tvb, offset,
			    next_offset - offset, "%s",
			    tvb_format_text(tvb, offset, next_offset - offset));
			offset = next_offset;
		}

		if (pinfo->match_uint == pinfo->destport) {
			hidden_item = proto_tree_add_boolean(rsh_tree,
			    hf_rsh_request, tvb, 0, 0, 1);
                } else {
			hidden_item = proto_tree_add_boolean(rsh_tree,
			    hf_rsh_response, tvb, 0, 0, 1);
                }
                PROTO_ITEM_SET_HIDDEN(hidden_item);
	}
}

void
proto_register_rsh(void)
{

	static hf_register_info hf[] = {
		{ &hf_rsh_response,
		{ "Response",		"rsh.response",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if rsh response", HFILL }},
		{ &hf_rsh_request,
		{ "Request",		"rsh.request",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if rsh request", HFILL }},
	};

	static gint *ett[] = {
		&ett_rsh,
	};

	proto_rsh = proto_register_protocol("Remote Shell", "RSH", "rsh");
	proto_register_field_array(proto_rsh, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rsh(void)
{
	dissector_handle_t rsh_handle;

	rsh_handle = create_dissector_handle(dissect_rsh, proto_rsh);
	dissector_add_uint("tcp.port", TCP_PORT_RSH, rsh_handle);
}
