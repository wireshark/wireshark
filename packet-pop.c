/* packet-pop.c
 * Routines for pop packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-pop.c,v 1.29 2002/01/21 07:36:38 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>

static int proto_pop = -1;
static int hf_pop_response = -1;
static int hf_pop_request = -1;

static gint ett_pop = -1;

static dissector_handle_t data_handle;

#define TCP_PORT_POP			110

static gboolean response_is_continuation(const u_char *data);
	
static void
dissect_pop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        gboolean        is_request;
        gboolean	is_continuation;
        proto_tree      *pop_tree;
	proto_item	*ti;
	gint		offset = 0;
	const u_char	*line;
	gint		next_offset;
	int		linelen;
	int		tokenlen;
	const u_char	*next_token;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "POP");

	/*
	 * Find the end of the first line.
	 *
	 * Note that "tvb_find_line_end()" will return a value that is
	 * not longer than what's in the buffer, so the "tvb_get_ptr()"
	 * call won't throw an exception.
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset);
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
		ti = proto_tree_add_item(tree, proto_pop, tvb, offset,
		    tvb_length_remaining(tvb, offset), FALSE);
		pop_tree = proto_item_add_subtree(ti, ett_pop);

		if (is_continuation) {
			/*
			 * Put the whole packet into the tree as data.
			 */
			call_dissector(data_handle,tvb, pinfo, pop_tree);
			return;
		}

		if (is_request) {
			proto_tree_add_boolean_hidden(pop_tree,
			    hf_pop_request, tvb, 0, 0, TRUE);
		} else {
			proto_tree_add_boolean_hidden(pop_tree,
			    hf_pop_response, tvb, 0, 0, TRUE);
		}

		/*
		 * Extract the first token, and, if there is a first
		 * token, add it as the request or reply code.
		 */
		tokenlen = get_token_len(line, line + linelen, &next_token);
		if (tokenlen != 0) {
			if (is_request) {
				proto_tree_add_text(pop_tree, tvb, offset,
				    tokenlen, "Request: %s",
				    format_text(line, tokenlen));
			} else {
				proto_tree_add_text(pop_tree, tvb, offset,
				    tokenlen, "Response: %s",
				    format_text(line, tokenlen));
			}
			offset += next_token - line;
			linelen -= next_token - line;
			line = next_token;
		}

		/*
		 * Add the rest of the first line as request or
		 * reply data.
		 */
		if (linelen != 0) {
			if (is_request) {
				proto_tree_add_text(pop_tree, tvb, offset,
				    linelen, "Request Arg: %s",
				    format_text(line, linelen));
			} else {
				proto_tree_add_text(pop_tree, tvb, offset,
				    linelen, "Response Arg: %s",
				    format_text(line, linelen));
			}
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
			    &next_offset);

			/*
			 * Put this line.
			 */
			proto_tree_add_text(pop_tree, tvb, offset,
			    next_offset - offset, "%s",
			    tvb_format_text(tvb, offset, next_offset - offset));
			offset = next_offset;
		}
	}
}

static gboolean response_is_continuation(const u_char *data)
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
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if POP response", HFILL }},

    { &hf_pop_request,
      { "Request",            "pop.request",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if POP request", HFILL }}
  };
  static gint *ett[] = {
    &ett_pop,
  };

  proto_pop = proto_register_protocol("Post Office Protocol", "POP", "pop");
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
