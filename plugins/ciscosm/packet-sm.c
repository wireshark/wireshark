/* packet-sm.c
 * Routines for Cisco Session Management Protocol dissection
 * Copyright 2004, Duncan Sargeant <dunc-ethereal@rcpt.to>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * This is basically a glue dissector for the Cisco SM protocol.  It sits
 * between the RUDP and MTP3 layers in conversations on port 7000 between
 * SLTs and MGCs.  A link to an overview of the technology :
 * 
 * http://www.cisco.com/en/US/products/sw/netmgtsw/ps4883/products_installation_and_configuration_guide_chapter09186a008010950a.html
 *
 * Link showing debugs of the protocol:
 * http://www.cisco.com/univercd/cc/td/doc/product/access/sc/rel7/omts/omts_apb.htm#30052
 *
 * I'm unable to get local debugs of this protocol, as the SLT's are
 * slow cpu cisco 2600's, and they tend to drop the signalling links
 * if you turn any debugging on!  But there's not much interesting
 * here, its just glue to get the ISUP/MTP3 data nicely.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <gmodule.h>
#include <epan/packet.h>

#include "plugins/plugin_api.h"
#include "plugins/plugin_api_defs.h"
 /* Define version if we are not building ethereal statically */

#include "moduleinfo.h"

#ifndef ENABLE_STATIC
 G_MODULE_EXPORT const gchar version[] = VERSION;
#endif

/* Initialize the protocol and registered fields */
static int proto_sm = -1;

static int hf_sm_sm_msg_type = -1;
static int hf_sm_protocol = -1;
static int hf_sm_msg_id = -1;
static int hf_sm_msg_type = -1;
static int hf_sm_channel = -1;
static int hf_sm_bearer = -1;
static int hf_sm_len = -1;

/* Initialize the subtree pointers */
static gint ett_sm = -1;

/* Code to actually dissect the packets */
static void
dissect_sm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *sm_tree;
	tvbuff_t *next_tvb = NULL;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SM");

	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_set_str(pinfo->cinfo, COL_INFO, "Cisco SM Packet");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_sm, tvb, 0, 16, FALSE);
		sm_tree = proto_item_add_subtree(ti, ett_sm);
		ti = proto_tree_add_item(sm_tree, hf_sm_sm_msg_type, tvb, 0, 4, FALSE);
		ti = proto_tree_add_item(sm_tree, hf_sm_protocol, tvb, 4, 2, FALSE);
		ti = proto_tree_add_item(sm_tree, hf_sm_msg_id, tvb, 6, 2, FALSE);
		ti = proto_tree_add_item(sm_tree, hf_sm_msg_type, tvb, 8, 2, FALSE);
		ti = proto_tree_add_item(sm_tree, hf_sm_channel, tvb, 10, 2, FALSE);
		ti = proto_tree_add_item(sm_tree, hf_sm_bearer, tvb, 12, 2, FALSE);
		ti = proto_tree_add_item(sm_tree, hf_sm_len, tvb, 14, 2, FALSE);
	}

	next_tvb = tvb_new_subset(tvb, 16, -1, -1);
	if (tvb_length(next_tvb) && find_dissector("mtp3"))
		call_dissector(find_dissector("mtp3"), next_tvb, pinfo, tree);
}

void
proto_register_sm(void)
{                 
	static hf_register_info hf[] = {
		{ &hf_sm_sm_msg_type,
			{ "SM Message Type",           "sm.sm_msg_type",
			FT_UINT32, BASE_HEX, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_sm_protocol,
			{ "Protocol Type",           "sm.protocol",
			FT_UINT16, BASE_HEX, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_sm_msg_id,
			{ "Message ID",           "sm.msgid",
			FT_UINT16, BASE_HEX, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_sm_msg_type,
			{ "Message Type",           "sm.msg_type",
			FT_UINT16, BASE_HEX, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_sm_channel,
			{ "Channel ID",           "sm.channel",
			FT_UINT16, BASE_HEX, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_sm_bearer,
			{ "Bearer ID",           "sm.bearer",
			FT_UINT16, BASE_HEX, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_sm_len,
			{ "Length",           "sm.len",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_sm,
	};

/* Register the protocol name and description */
	proto_sm = proto_register_protocol("Cisco Session Management",
	    "SM", "sm");

	register_dissector("sm", dissect_sm, proto_sm);

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_sm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
plugin_reg_handoff_sm(void)
{
	return;
}

#ifndef ENABLE_STATIC

G_MODULE_EXPORT void
plugin_init(plugin_address_table_t *pat
#ifndef PLUGINS_NEED_ADDRESS_TABLE
_U_
#endif
)
{
	/* initialise the table of pointers needed in Win32 DLLs */
	plugin_address_table_init(pat);

	/* register the new protocol, protocol fields, and subtrees */
	if (proto_sm == -1) { /* execute protocol initialization only once */
		proto_register_sm();
	}

}

G_MODULE_EXPORT void
plugin_reg_handoff(void)
{
	plugin_reg_handoff_sm();
}

#endif
