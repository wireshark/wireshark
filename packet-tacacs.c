/* packet-tacacs.c
 * Routines for cisco tacacs/tacplus/AAA packet dissection
 *
 * $Id: packet-tacacs.c,v 1.3 2000/04/08 07:07:39 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
#include "packet.h"

static int proto_tacacs = -1;
static int hf_tacacs_request = -1;
static int hf_tacacs_response = -1;
static int hf_tacacs_version = -1;

static gint ett_tacacs = -1;

#define UDP_PORT_TACACS	49
#define TCP_PORT_TACACS	49

static void
dissect_tacacs(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree      *tacacs_tree, *ti;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "TACACS");

	if (check_col(fd, COL_INFO))
	{
		col_add_fstr(fd, COL_INFO, "%s", 
			(pi.match_port == pi.destport) ? "Request" : "Response");	  
	}

	if (tree) 
	{
		ti = proto_tree_add_item(tree, proto_tacacs, offset, END_OF_FRAME, NULL);
		tacacs_tree = proto_item_add_subtree(ti, ett_tacacs);

		proto_tree_add_item(tacacs_tree, hf_tacacs_version, 0, 0, "XTacacs");

		if (pi.match_port == pi.destport)
		{
		        proto_tree_add_item_hidden(tacacs_tree, hf_tacacs_request,
						   offset, END_OF_FRAME, TRUE);
			proto_tree_add_text(tacacs_tree, offset, 
				END_OF_FRAME, "Request: <opaque data>" );
		}
		else
		{
		        proto_tree_add_item_hidden(tacacs_tree, hf_tacacs_response,
						   offset, END_OF_FRAME, TRUE);
			proto_tree_add_text(tacacs_tree, offset, 
				END_OF_FRAME, "Response: <opaque data>");
		}
	}
}

static void
dissect_tacplus(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree      *tacacs_tree, *ti;

	if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "TACACS");

	if (check_col(fd, COL_INFO))
	{
		col_add_fstr(fd, COL_INFO, "%s", 
			(pi.match_port == pi.destport) ? "Request" : "Response");	  
	}

	if (tree) 
	{
		ti = proto_tree_add_item(tree, proto_tacacs, offset, END_OF_FRAME, NULL);
		tacacs_tree = proto_item_add_subtree(ti, ett_tacacs);

		proto_tree_add_item(tacacs_tree, hf_tacacs_version, 0, 0, "Tacacs+");

		if (pi.match_port == pi.destport)
		{
		        proto_tree_add_item_hidden(tacacs_tree, hf_tacacs_request,
						   offset, END_OF_FRAME, TRUE);
			proto_tree_add_text(tacacs_tree, offset, 
				END_OF_FRAME, "Request: <opaque data>" );
		}
		else
		{
		        proto_tree_add_item_hidden(tacacs_tree, hf_tacacs_response,
						   offset, END_OF_FRAME, TRUE);
			proto_tree_add_text(tacacs_tree, offset, 
				END_OF_FRAME, "Response: <opaque data>");
		}
	}
}

void
proto_register_tacacs(void)
{
	static hf_register_info hf[] = {
	  { &hf_tacacs_version,
	    { "Tacacs Version",           "tacacs.version",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      "xtacacs or tacplus" }},
	  { &hf_tacacs_response,
	    { "Response",           "tacacs.response",
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      "TRUE if TACACS response" }},
	  { &hf_tacacs_request,
	    { "Request",            "tacacs.request",
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      "TRUE if TACACS request" }}
	};

	static gint *ett[] = {
		&ett_tacacs,
	};
	proto_tacacs = proto_register_protocol("TACACS", "tacacs");
	proto_register_field_array(proto_tacacs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_tacacs(void)
{
	dissector_add("udp.port", UDP_PORT_TACACS, dissect_tacacs);
	dissector_add("tcp.port", TCP_PORT_TACACS, dissect_tacplus);
}
