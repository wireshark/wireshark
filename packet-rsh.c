/* packet-rsh.c
 * Routines for rsh packet disassembly
 *
 * Robert Tsai <rtsai@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-rsh.c,v 1.2 2000/08/12 12:56:23 deniel Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <glib.h>
#include "packet.h"

static int proto_rsh = -1;
static int hf_rsh_response = -1;
static int hf_rsh_request = -1;
static gint ett_rsh = -1;

#define TCP_PORT_RSH			514

void
dissect_rsh(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_item	*ti;
	proto_tree	*rsh_tree;
	const u_char	*data, *dataend;
	const u_char	*lineend, *eol;
	int		linelen;

	data = &pd[offset];
	dataend = data + END_OF_FRAME;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "RSH");
	if (check_col(fd, COL_INFO)) {
		/* Put the first line from the buffer into the summary. */
		lineend = find_line_end(data, dataend, &eol);
		linelen = lineend - data;
		col_add_str(fd, COL_INFO, format_text(data, linelen));
	}
	if (tree) {
		ti = proto_tree_add_item(tree, proto_rsh, NullTVB, offset,
			END_OF_FRAME, FALSE);
		rsh_tree = proto_item_add_subtree(ti, ett_rsh);

		while (data < dataend) {
			/*
			 * Find the end of the line.
			 */
			lineend = find_line_end(data, dataend, &eol);
			linelen = lineend - data;

			/*
			 * Put this line.
			 */
			proto_tree_add_text(rsh_tree, NullTVB, offset,
				linelen, "%s", format_text(data, linelen));
			offset += linelen;
			data = lineend;
		}

		if (pi.match_port == pi.destport) 
			proto_tree_add_boolean_hidden(rsh_tree, 
						      hf_rsh_request, NullTVB, 0, 0, 1);
		else
			proto_tree_add_boolean_hidden(rsh_tree, 
						      hf_rsh_response, NullTVB, 0, 0, 1);

		if (data < dataend)
			old_dissect_data(&pd[offset], offset, fd, rsh_tree);
	}
}

void
proto_register_rsh(void)
{

	static hf_register_info hf[] = {
		{ &hf_rsh_response,
		{ "Response",		"rsh.response",  
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if rsh response" }},
		{ &hf_rsh_request,
		{ "Request",		"rsh.request",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if rsh request" }},
	};

	static gint *ett[] = {
		&ett_rsh,
	};

	proto_rsh = proto_register_protocol("Remote Shell", "rsh");
	proto_register_field_array(proto_rsh, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rsh(void)
{
	old_dissector_add("tcp.port", TCP_PORT_RSH, dissect_rsh);
}
