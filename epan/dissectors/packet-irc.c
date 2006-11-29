/* packet-irc.c
 * Routines for IRC packet dissection
 *
 * See
 *
 *	http://www.irchelp.org/irchelp/rfc/
 *
 * and the RFCs and other documents it mentions, such as RFC 1459, RFCs
 * 2810, 2811, 2812, and 2813,
 *
 *	http://www.irchelp.org/irchelp/rfc/ctcpspec.html
 *
 * and
 *
 *	http://www.invlogic.com/irc/ctcp.html
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

static int proto_irc = -1;
static int hf_irc_request = -1;
static int hf_irc_response = -1;

static gint ett_irc = -1;

#define TCP_PORT_IRC			6667
	/* good candidate for dynamic port specification */

static void
dissect_irc_request(proto_tree *tree, tvbuff_t *tvb, int offset, int linelen)
{
	proto_tree_add_item(tree, hf_irc_request, tvb, offset, linelen, TRUE);
}

static void
dissect_irc_response(proto_tree *tree, tvbuff_t *tvb, int offset, int linelen)
{
	proto_tree_add_item(tree, hf_irc_response, tvb, offset, linelen, TRUE);
}

static void
dissect_irc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *irc_tree, *ti;
	gint		offset = 0;
	gint		next_offset;
	int		linelen;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "IRC");

	if (check_col(pinfo->cinfo, COL_INFO))
	{
		col_set_str(pinfo->cinfo, COL_INFO,
		    (pinfo->match_port == pinfo->destport) ? "Request" : "Response");
	}

	if (tree)
	{
		ti = proto_tree_add_item(tree, proto_irc, tvb, 0, -1, FALSE);
		irc_tree = proto_item_add_subtree(ti, ett_irc);

		/*
		 * Process the packet data, a line at a time.
		 */
		while (tvb_reported_length_remaining(tvb, offset) > 0)
		{
			/*
			 * Find the end of the line.
			 */
			linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
			if (next_offset == offset) {
				/*
				 * XXX - we really want the "show data a
				 * line at a time" loops in various
				 * dissectors to do reassembly and to
				 * throw an exception if there's no
				 * line ending in the current packet
				 * and we're not doing reassembly.
				 */
				break;
			}

			if (linelen != 0)
			{
				if (pinfo->match_port == pinfo->destport)
				{
					dissect_irc_request(irc_tree, tvb, offset, linelen);
				}
				else
				{
					dissect_irc_response(irc_tree, tvb, offset, linelen);
				}
			}
			offset = next_offset;
		}
	}
}

void
proto_register_irc(void)
{
	static hf_register_info hf[] = {
	  { &hf_irc_response,
	    { "Response",           "irc.response",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      "Line of response message", HFILL }},

	  { &hf_irc_request,
	    { "Request",            "irc.request",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      "Line of request message", HFILL }},
	};

	static gint *ett[] = {
		&ett_irc,
	};
	proto_irc = proto_register_protocol("Internet Relay Chat", "IRC", "irc");
	proto_register_field_array(proto_irc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_irc(void)
{
	dissector_handle_t irc_handle;

	irc_handle = create_dissector_handle(dissect_irc, proto_irc);
	dissector_add("tcp.port", TCP_PORT_IRC, irc_handle);
}
