/* packet-nntp.c
 * Routines for nntp packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-nntp.c,v 1.11 2000/08/07 03:20:56 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"

static int proto_nntp = -1;
static int hf_nntp_response = -1;
static int hf_nntp_request = -1;

static gint ett_nntp = -1;

#define TCP_PORT_NNTP			119

static void
dissect_nntp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
        gchar           *type;
        proto_tree      *nntp_tree, *ti;
	const u_char	*data, *dataend;
	const u_char	*lineend, *eol;
	int		linelen;
	int		max_data = pi.captured_len - offset;

	data = &pd[offset];
	dataend = data + END_OF_FRAME;
	if (dataend > data + max_data)
		dataend = data + max_data;

        if (pi.match_port == pi.destport)
        	type = "Request";
        else
        	type = "Response";

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "NNTP");

	if (check_col(fd, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary.
		 */
		lineend = find_line_end(data, dataend, &eol);
		linelen = eol - data;
		col_add_fstr(fd, COL_INFO, "%s: %s", type,
		    format_text(data, linelen));
	}

	if (tree) {

	  ti = proto_tree_add_item(tree, proto_nntp, NullTVB, offset, END_OF_FRAME, FALSE);
	  nntp_tree = proto_item_add_subtree(ti, ett_nntp);

	  if (pi.match_port == pi.destport) {
	    proto_tree_add_boolean_hidden(nntp_tree, hf_nntp_request, NullTVB, 0, 0, TRUE);
	  } else {
	    proto_tree_add_boolean_hidden(nntp_tree, hf_nntp_response, NullTVB, 0, 0, TRUE);
	  }

	  /*
	   * Show the request or response as text, a line at a time.
	   * XXX - for requests, we could display the stuff after the
	   * first line, if any, based on what the request was, and
	   * for responses, we could display it based on what the
	   * matching request was, although the latter requires us to
	   * know what the matching request was....
	   */
	  while (data < dataend) {
		/*
		 * Find the end of the line.
		 */
		lineend = find_line_end(data, dataend, &eol);
		linelen = lineend - data;

		/*
		 * Put this line.
		 */
		proto_tree_add_text(nntp_tree, NullTVB, offset, linelen, "%s",
		    format_text(data, linelen));
		offset += linelen;
		data = lineend;
	  }
	}
}

void
proto_register_nntp(void)
{
  
  static hf_register_info hf[] = {
    { &hf_nntp_response,
      { "Response",           "nntp.response",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if NNTP response" }},

    { &hf_nntp_request,
      { "Request",            "nntp.request",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if NNTP request" }}
  };
  static gint *ett[] = {
    &ett_nntp,
  };

  proto_nntp = proto_register_protocol("Network News Transfer Protocol", 
				       "nntp");
  proto_register_field_array(proto_nntp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nntp(void)
{
  old_dissector_add("tcp.port", TCP_PORT_NNTP, dissect_nntp);
}
