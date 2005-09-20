/* packet-jabber.c
 * Routines for Jabber packet dissection
 * Copyright 2003, Brad Hards <bradh@frogmouth.net>
 * Heavily based in packet-acap.c, which in turn is heavily based on 
 * packet-imap.c, Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>

static int proto_jabber = -1;
static int hf_jabber_response = -1;
static int hf_jabber_request = -1;

static gint ett_jabber = -1;
static gint ett_jabber_reqresp = -1;

#define TCP_PORT_JABBER			5222
static dissector_handle_t xml_handle=NULL;

static void
dissect_jabber(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        gboolean        is_request;
        proto_tree      *jabber_tree;
        proto_item      *ti;
	gint		offset = 0;
	const guchar	*line;
	gint		next_offset;
	int		linelen;
	tvbuff_t *xmltvb;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Jabber");

	/*
	 * Find the end of the first line.
	 *
	 * Note that "tvb_find_line_end()" will return a value that is
	 * not longer than what's in the buffer, so the "tvb_get_ptr()"
	 * call won't throw an exception.
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
	line = tvb_get_ptr(tvb, offset, linelen);

	if (pinfo->match_port == pinfo->destport)
		is_request = TRUE;
	else
		is_request = FALSE;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
		 * (but leave out the line terminator).
		 */
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
		    is_request ? "Request" : "Response",
		    format_text(line, linelen));
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_jabber, tvb, offset, -1,
		    FALSE);
		jabber_tree = proto_item_add_subtree(ti, ett_jabber);

		if (is_request) {
			proto_tree_add_boolean_hidden(jabber_tree,
			    hf_jabber_request, tvb, 0, 0, TRUE);
		} else {
			proto_tree_add_boolean_hidden(jabber_tree,
			    hf_jabber_response, tvb, 0, 0, TRUE);
		}

		xmltvb = tvb_new_subset(tvb, offset, -1, -1);
		call_dissector(xml_handle, xmltvb, pinfo, jabber_tree);
	}
}

void
proto_register_jabber(void)
{
  static hf_register_info hf[] = {
    { &hf_jabber_response,
      { "Response",           "jabber.response",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if Jabber response", HFILL }},

    { &hf_jabber_request,
      { "Request",            "jabber.request",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if Jabber request", HFILL }}
  };
  static gint *ett[] = {
    &ett_jabber,
    &ett_jabber_reqresp,
  };

  proto_jabber = proto_register_protocol("Jabber XML Messaging",
				       "Jabber", "jabber");
  proto_register_field_array(proto_jabber, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_jabber(void)
{
  dissector_handle_t jabber_handle;

  xml_handle = find_dissector("xml");

  jabber_handle = create_dissector_handle(dissect_jabber, proto_jabber);
  dissector_add("tcp.port", TCP_PORT_JABBER, jabber_handle);
}
