/* packet-mapi.c
 * Routines for MSX mapi packet dissection
 *
 * $Id: packet-mapi.c,v 1.3 1999/11/21 11:04:11 deniel Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

static int proto_mapi = -1;
static int hf_mapi_request = -1;
static int hf_mapi_response = -1;

static gint ett_mapi = -1;

void
dissect_mapi(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree      *mapi_tree, *ti;

	if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "MAPI");

	if (check_col(fd, COL_INFO))
	{
		col_add_fstr(fd, COL_INFO, "%s", 
			(pi.match_port == pi.destport) ? "Request" : "Response");	  
	}

	if (tree) 
	{
		ti = proto_tree_add_item(tree, proto_mapi, offset, END_OF_FRAME, NULL);
		mapi_tree = proto_item_add_subtree(ti, ett_mapi);

		if (pi.match_port == pi.destport)
		{
		        proto_tree_add_item_hidden(mapi_tree, hf_mapi_request,
						   offset, END_OF_FRAME, TRUE);
			proto_tree_add_text(mapi_tree, offset, 
				END_OF_FRAME, "Request: <opaque data>" );
		}
		else
		{
		        proto_tree_add_item_hidden(mapi_tree, hf_mapi_response,
						   offset, END_OF_FRAME, TRUE);
			proto_tree_add_text(mapi_tree, offset, 
				END_OF_FRAME, "Response: <opaque data>");
		}
	}
}

void
proto_register_mapi(void)
{
	static hf_register_info hf[] = {
	  { &hf_mapi_response,
	    { "Response",           "mapi.response",
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      "TRUE if MAPI response" }},
	  
	  { &hf_mapi_request,
	    { "Request",            "mapi.request",
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      "TRUE if MAPI request" }}
	};

	static gint *ett[] = {
		&ett_mapi,
	};
	proto_mapi = proto_register_protocol("MAPI", "mapi");
	proto_register_field_array(proto_mapi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
