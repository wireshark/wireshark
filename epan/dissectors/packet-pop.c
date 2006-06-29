/* packet-pop.c
 * Routines for pop packet dissection
 * RFC 1939
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
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
#include <epan/strutil.h>

static int proto_pop = -1;

static int hf_pop_response = -1;
static int hf_pop_response_indicator = -1;
static int hf_pop_response_description = -1;
static int hf_pop_response_data = -1;

static int hf_pop_request = -1;
static int hf_pop_request_command = -1;
static int hf_pop_request_parameter = -1;
static int hf_pop_request_data = -1;

static gint ett_pop = -1;
static gint ett_pop_reqresp = -1;

static dissector_handle_t data_handle;

#define TCP_PORT_POP			110

static gboolean response_is_continuation(const guchar *data);

static void
dissect_pop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gboolean     is_request;
	gboolean     is_continuation;
	proto_tree   *pop_tree, *reqresp_tree;
	proto_item   *ti;
	gint         offset = 0;
	const guchar *line;
	gint         next_offset;
	int          linelen;
	int          tokenlen;
	const guchar *next_token;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "POP");

	/*
	 * Find the end of the first line.
	 *
	 * Note that "tvb_find_line_end()" will return a value that is
	 * not longer than what's in the buffer, so the "tvb_get_ptr()"
	 * call won't throw an exception.
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
	line = tvb_get_ptr(tvb, offset, linelen);

	if (pinfo->match_port == pinfo->destport) {
		is_request = TRUE;
		is_continuation = FALSE;
	} else {
		is_request = FALSE;
		is_continuation = response_is_continuation(line);
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
		 * if it's a POP request or reply (but leave out the
		 * line terminator).
		 * Otherwise, just call it a continuation.
		 */
		if (is_continuation)
			col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
			    is_request ? "Request" : "Response",
			    format_text(line, linelen));
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_pop, tvb, offset, -1,
		    FALSE);
		pop_tree = proto_item_add_subtree(ti, ett_pop);

		if (is_continuation) {
			/*
			 * Put the whole packet into the tree as data.
			 */
			call_dissector(data_handle,tvb, pinfo, pop_tree);
			return;
		}

		/*
		 * Put the line into the protocol tree.
		 */
		ti = proto_tree_add_string_format(pop_tree,
		                                  (is_request) ?
		                                      hf_pop_request :
		                                      hf_pop_response,
		                                  tvb, offset,
		                                  next_offset - offset,
		                                  "", "%s",
		                                  tvb_format_text(tvb, offset, next_offset - offset));
		reqresp_tree = proto_item_add_subtree(ti, ett_pop_reqresp);

		/*
		 * Extract the first token, and, if there is a first
		 * token, add it as the request or reply code.
		 */
		tokenlen = get_token_len(line, line + linelen, &next_token);
		if (tokenlen != 0) {
			proto_tree_add_item(reqresp_tree,
			                    (is_request) ?
			                        hf_pop_request_command :
			                        hf_pop_response_indicator,
			                    tvb, offset, tokenlen, FALSE);

			offset += next_token - line;
			linelen -= next_token - line;
			line = next_token;
		}

		/*
		 * Add the rest of the first line as request or
		 * reply param/description.
		 */
		if (linelen != 0) {
			proto_tree_add_item(reqresp_tree,
			                    (is_request) ?
			                        hf_pop_request_parameter :
			                        hf_pop_response_description,
			                    tvb, offset, linelen, FALSE);
		}
		offset = next_offset;

		/*
		 * Show the rest of the request or response as text,
		 * a line at a time.
		 */
		while (tvb_offset_exists(tvb, offset)) {
			/*
			 * Find the end of the line.
			 */
			linelen = tvb_find_line_end(tvb, offset, -1,
			    &next_offset, FALSE);

			/*
			 * Put this line.
			 */
			proto_tree_add_string_format(pop_tree,
			                             (is_request) ?
			                                 hf_pop_request_data :
			                                 hf_pop_response_data,
			                             tvb, offset,
			                             next_offset - offset,
			                             "", "%s",
			                             tvb_format_text(tvb, offset, next_offset - offset));
			offset = next_offset;
		}
	}
}

static gboolean response_is_continuation(const guchar *data)
{
  if (strncmp(data, "+OK", strlen("+OK")) == 0)
    return FALSE;

  if (strncmp(data, "-ERR", strlen("-ERR")) == 0)
    return FALSE;

  return TRUE;
}

void
proto_register_pop(void)
{

  static hf_register_info hf[] = {
    { &hf_pop_response,
      { "Response",           "pop.response",
	    FT_STRING, BASE_NONE, NULL, 0x0,
      	"Response", HFILL }},
    { &hf_pop_response_indicator,
      { "Response indicator",           "pop.response.indicator",
	    FT_STRING, BASE_NONE, NULL, 0x0,
      	"Response indicator", HFILL }},
    { &hf_pop_response_description,
      { "Response description",           "pop.response.description",
	     FT_STRING, BASE_NONE, NULL, 0x0,
	     "Response description", HFILL }},
    { &hf_pop_response_data,
      { "Data",           "pop.response.data",
	     FT_STRING, BASE_NONE, NULL, 0x0,
	     "Response Data", HFILL }},

    { &hf_pop_request,
      { "Request",           "pop.request",
	    FT_STRING, BASE_NONE, NULL, 0x0,
      	"Request", HFILL }},
    { &hf_pop_request_command,
      { "Request command",            "pop.request.command",
	    FT_STRING, BASE_NONE, NULL, 0x0,
      	"Request command", HFILL }},
    { &hf_pop_request_parameter,
      { "Request parameter",            "pop.request.parameter",
	    FT_STRING, BASE_NONE, NULL, 0x0,
      	"Request parameter", HFILL }},
    { &hf_pop_request_data,
      { "Data",           "pop.request.data",
	     FT_STRING, BASE_NONE, NULL, 0x0,
	     "Request data", HFILL }},

  };
  static gint *ett[] = {
    &ett_pop,
    &ett_pop_reqresp,
  };

  proto_pop = proto_register_protocol("Post Office Protocol", "POP", "pop");
  register_dissector("pop", dissect_pop, proto_pop);
  proto_register_field_array(proto_pop, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pop(void)
{
  dissector_handle_t pop_handle;

  pop_handle = create_dissector_handle(dissect_pop, proto_pop);
  dissector_add("tcp.port", TCP_PORT_POP, pop_handle);
  data_handle = find_dissector("data");
}
