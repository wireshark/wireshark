/* packet-irc.c
 * Routines for IRC packet dissection
 *
 * $Id: packet-irc.c,v 1.17 2002/01/21 07:36:35 guy Exp $
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

static int proto_irc = -1;
static int hf_irc_request = -1;
static int hf_irc_response = -1;
static int hf_irc_command = -1;

static gint ett_irc = -1;

#define TCP_PORT_IRC			6667
	/* good candidate for dynamic port specification */

static void
dissect_irc_request(proto_tree *tree, tvbuff_t *tvb, int offset, int len,
    const char *line, int linelen)
{
	proto_tree_add_boolean_hidden(tree, hf_irc_request, tvb, offset, len,
	    TRUE);
	proto_tree_add_text(tree, tvb, offset, len, "Request Line: %.*s",
	    linelen, line);
}

static void
dissect_irc_response(proto_tree *tree, tvbuff_t *tvb, int offset, int len,
    const char *line, int linelen)
{
	proto_tree_add_boolean_hidden(tree, hf_irc_response, tvb, offset, len,
	    TRUE);
	proto_tree_add_text(tree, tvb, offset, len, "Response Line: %.*s",
	    linelen, line);
}

static void
dissect_irc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *irc_tree, *ti;
	gint		offset = 0;
	const u_char	*line;
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
		ti = proto_tree_add_item(tree, proto_irc, tvb, 0,
		    tvb_length(tvb), FALSE);
		irc_tree = proto_item_add_subtree(ti, ett_irc);

		/*
		 * Process the packet data, a line at a time.
		 */
		while (tvb_offset_exists(tvb, offset))
		{
			/*
			 * Find the end of the line.
			 */
			linelen = tvb_find_line_end(tvb, offset, -1,
			    &next_offset);

			/*
			 * Get a buffer that refers to the line (without
			 * the line terminator).
			 */
			line = tvb_get_ptr(tvb, offset, linelen);

			if (linelen != 0)
			{
				if (pinfo->match_port == pinfo->destport)
				{
					dissect_irc_request(irc_tree, tvb,
					    offset, next_offset - offset,
					    line, linelen);
				}
				else
				{
					dissect_irc_response(irc_tree, tvb,
					    offset, next_offset - offset,
					    line, linelen);
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
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      "TRUE if IRC response", HFILL }},
	  
	  { &hf_irc_request,
	    { "Request",            "irc.request",
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      "TRUE if IRC request", HFILL }},

	  { &hf_irc_command,
	    { "Command",            "irc.command",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      "Command associated with request", HFILL }}
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
