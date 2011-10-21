/* packet-xmpp.c
 * Routines for XMPP packet dissection
 * Copyright 2003, Brad Hards <bradh@frogmouth.net>
 * Heavily based in packet-acap.c, which in turn is heavily based on
 * packet-imap.c, Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-acap.c
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
 *
 * Ref http://xmpp.org/
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>

static int proto_xmpp = -1;
static int hf_xmpp_response = -1;
static int hf_xmpp_request = -1;

static gint ett_xmpp = -1;
static gint ett_xmpp_reqresp = -1;

#define TCP_PORT_XMPP			5222
static dissector_handle_t xml_handle=NULL;

static void
dissect_xmpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gboolean         is_request;
    proto_tree      *xmpp_tree = NULL;
    proto_item      *ti, *hidden_item;
	gint		     offset = 0;
	const guchar	*line;
	gint             next_offset;
	int	             linelen;
	tvbuff_t        *xmltvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "XMPP");

	/*
	 * Find the end of the first line.
	 *
	 * Note that "tvb_find_line_end()" will return a value that is
	 * not longer than what's in the buffer, so the "tvb_get_ptr()"
	 * call won't throw an exception.
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
	line = tvb_get_ptr(tvb, offset, linelen);

	if (pinfo->match_uint == pinfo->destport)
		is_request = TRUE;
	else
		is_request = FALSE;

	/*
	 * Put the first line from the buffer into the summary
	 * (but leave out the line terminator).
	 */
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
	    is_request ? "Request" : "Response",
	    format_text(line, linelen));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_xmpp, tvb, offset, -1,
		    ENC_NA) ;
		xmpp_tree = proto_item_add_subtree(ti, ett_xmpp);

		if (is_request) {
			hidden_item = proto_tree_add_boolean(xmpp_tree,
			    hf_xmpp_request, tvb, 0, 0, TRUE);
		} else {
			hidden_item = proto_tree_add_boolean(xmpp_tree,
			    hf_xmpp_response, tvb, 0, 0, TRUE);
		}
		PROTO_ITEM_SET_HIDDEN(hidden_item);
	}

        xmltvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(xml_handle, xmltvb, pinfo, xmpp_tree);
}

void
proto_register_xmpp(void)
{
  static hf_register_info hf[] = {
    { &hf_xmpp_response,
      { "Response",           "xmpp.response",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if XMPP response", HFILL }},

    { &hf_xmpp_request,
      { "Request",            "xmpp.request",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if XMPP request", HFILL }}
  };
  static gint *ett[] = {
    &ett_xmpp,
    &ett_xmpp_reqresp,
  };

  proto_xmpp = proto_register_protocol("Extensible Messaging and Presence Protocol",
				       "XMPP", "xmpp");
  proto_register_field_array(proto_xmpp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_xmpp(void)
{
  dissector_handle_t xmpp_handle;

  xml_handle = find_dissector("xml");

  xmpp_handle = create_dissector_handle(dissect_xmpp, proto_xmpp);
  dissector_add_uint("tcp.port", TCP_PORT_XMPP, xmpp_handle);
}
