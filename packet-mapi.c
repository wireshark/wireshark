/* packet-mapi.c
 * Routines for MSX mapi packet dissection
 *
 * $Id: packet-mapi.c,v 1.17 2001/12/03 03:59:37 guy Exp $
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
#include "packet.h"

static int proto_mapi = -1;
static int hf_mapi_request = -1;
static int hf_mapi_response = -1;

static gint ett_mapi = -1;

#define TCP_PORT_MAPI			1065

static void
dissect_mapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *mapi_tree, *ti;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "MAPI");

	if (check_col(pinfo->fd, COL_INFO))
	{
		col_add_fstr(pinfo->fd, COL_INFO, "%s", 
			(pinfo->match_port == pinfo->destport) ? "Request" : "Response");	  
	}

	/*
	 * XXX - MAPI is based on MS RPC, i.e. on DCE RPC.
	 * Unfortunately, at least as I read the DCE RPC 1.1 spec's
	 * description of RPC PDUs, not all PDUs necessarily have
	 * an interface UUID for connection-oriented RPC, and MAPI
	 * runs over TCP - i.e., it uses connection-oriented RPC - so if
	 * somebody ever does a dissector for the MAPI RPC calls,
	 * it's not clear how we'd arrange to call that dissector for
	 * MAPI calls if we haven't seen a bind operation.
	 *
	 * Currently, the DCE RPC dissector doesn't dissect enough
	 * to determine what service is being called, so without
	 * a dissector for the TCP port TCP_PORT_MAPI, MAPI traffic
	 * would just be identified as DCE RPC traffic, and, as per
	 * the above, even if the DCE RPC dissector did dissect enough
	 * to determine what service is being called, we might still
	 * need to check the port number to recognize MAPI traffic.
	 */
	if (tree) 
	{
		ti = proto_tree_add_item(tree, proto_mapi, tvb, 0,
		    tvb_length(tvb), FALSE);
		mapi_tree = proto_item_add_subtree(ti, ett_mapi);

		if (pinfo->match_port == pinfo->destport)
		{
		        proto_tree_add_boolean_hidden(mapi_tree, hf_mapi_request, tvb,
						   0, tvb_length(tvb), TRUE);
			proto_tree_add_text(mapi_tree, tvb, 0,
				tvb_length(tvb), "Request: <opaque data>" );
		}
		else
		{
		        proto_tree_add_boolean_hidden(mapi_tree, hf_mapi_response, tvb,
						   0, tvb_length(tvb), TRUE);
			proto_tree_add_text(mapi_tree, tvb, 0,
				tvb_length(tvb), "Response: <opaque data>");
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
	      "TRUE if MAPI response", HFILL }},
	  
	  { &hf_mapi_request,
	    { "Request",            "mapi.request",
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      "TRUE if MAPI request", HFILL }}
	};

	static gint *ett[] = {
		&ett_mapi,
	};
	proto_mapi = proto_register_protocol("MAPI", "MAPI", "mapi");
	proto_register_field_array(proto_mapi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mapi(void)
{
	dissector_handle_t mapi_handle;

	mapi_handle = create_dissector_handle(dissect_mapi, proto_mapi);
	dissector_add("tcp.port", TCP_PORT_MAPI, mapi_handle);
}
