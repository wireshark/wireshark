/* packet-wlccp.c
 * Routines for Cisco Wireless LAN Context Control Protocol dissection
 * Copyright 2006, Stephen Fisher <stephentfisher@yahoo.com>
 *
 * $Id: README.developer 18639 2006-07-03 09:26:19Z jake $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/etypes.h>

/* WLCCP uses both ETHERTYPE_WLCCP (0x872d) from etypes.h and UDP port 2887 */
#define WLCCP_UDP_PORT 2887

/* Field locations and lengths */
#define WLCCP_LENGTH_OFFSET 4
#define WLCCP_LENGTH_LENGTH 2

#define WLCCP_FLAGS_OFFSET 10
#define WLCCP_FLAGS_LENGTH 2

#define WLCCP_RSP_ID_OFFSET 21
#define WLCCP_RSP_ID_LENGTH 1

#define WLCCP_RSP_OFFSET 22
#define WLCCP_RSP_LENGTH 6

#define WLCCP_PRIORITY_OFFSET 38
#define WLCCP_PRIORITY_LENGTH 1

#define WLCCP_AGE_OFFSET 48
#define WLCCP_AGE_LENGTH 4

#define WLCCP_PERIOD_OFFSET 55
#define WLCCP_PERIOD_LENGTH 1

#define WLCCP_IPV4_ADDRESS_OFFSET 76
#define WLCCP_IPV4_ADDRESS_LENGTH 4


/* Forward declaration we need below */
void proto_reg_handoff_wlccp(void);

/* Initialize the protocol and registered fields */
static int proto_wlccp = -1;

static int hf_wlccp_length = -1;
static int hf_wlccp_flags = -1;
static int hf_wlccp_rsp_id = -1;
static int hf_wlccp_rsp = -1;
static int hf_wlccp_priority = -1;
static int hf_wlccp_age = -1;
static int hf_wlccp_period = -1;
static int hf_wlccp_ipv4_address = -1;

/* Initialize the subtree pointers */
static gint ett_wlccp = -1;

/* Code to actually dissect the packets */
static void
dissect_wlccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *wlccp_tree;

	guint32 ipv4_address; /* For extracting an IPv4 address from packet */

	/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "WLCCP");

	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_set_str(pinfo->cinfo, COL_INFO, "WLCCP frame");

	if (tree) {
		/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_wlccp, tvb, 0, -1, FALSE);

		wlccp_tree = proto_item_add_subtree(ti, ett_wlccp);

		proto_tree_add_item(wlccp_tree, hf_wlccp_length, tvb,
				    WLCCP_LENGTH_OFFSET,
				    WLCCP_LENGTH_LENGTH, FALSE);

		proto_tree_add_item(wlccp_tree, hf_wlccp_flags, tvb,
				    WLCCP_FLAGS_OFFSET,
				    WLCCP_FLAGS_LENGTH, FALSE);

		proto_tree_add_item(wlccp_tree, hf_wlccp_rsp_id, tvb,
				    WLCCP_RSP_ID_OFFSET,
				    WLCCP_RSP_ID_LENGTH, FALSE);

		proto_tree_add_item(wlccp_tree, hf_wlccp_rsp, tvb,
				    WLCCP_RSP_OFFSET,
				    WLCCP_RSP_LENGTH, FALSE);

		proto_tree_add_item(wlccp_tree, hf_wlccp_priority, tvb,
				    WLCCP_PRIORITY_OFFSET,
				    WLCCP_PRIORITY_LENGTH, FALSE);

		proto_tree_add_item(wlccp_tree, hf_wlccp_age, tvb,
				    WLCCP_AGE_OFFSET,
				    WLCCP_AGE_LENGTH, FALSE);

		proto_tree_add_item(wlccp_tree, hf_wlccp_period, tvb,
				    WLCCP_PERIOD_OFFSET,
				    WLCCP_PERIOD_LENGTH, FALSE);

		ipv4_address = tvb_get_ipv4(tvb, WLCCP_IPV4_ADDRESS_OFFSET);
		proto_tree_add_ipv4(wlccp_tree, hf_wlccp_ipv4_address, tvb,
				    WLCCP_IPV4_ADDRESS_OFFSET,
				    WLCCP_IPV4_ADDRESS_LENGTH, ipv4_address);


	}


	/* If this protocol has a sub-dissector call it here, see section 1.8 */
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_wlccp(void)
{                 
	/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_wlccp_length,
		  { "Length",           "wlccp.length",
		    FT_UINT16, BASE_DEC, NULL, 0,          
		    "Length of WLCCP payload (bytes)", HFILL }
		},

		{ &hf_wlccp_flags,
		  { "Flags",           "wlccp.flags",
		    FT_UINT16, BASE_HEX, NULL, 0,          
		    "Flags (unknown purpose)", HFILL }
		},

		{ &hf_wlccp_rsp_id,
		  { "Rsp ID",           "wlccp.rsp_id",
		    FT_UINT8, BASE_DEC, NULL, 0,          
		    "Rsp MAC address identifier (unknown purpose)", HFILL }
		},

		{ &hf_wlccp_rsp,
		  { "Rsp",           "wlccp.rsp",
		    FT_ETHER, BASE_NONE, NULL, 0,          
		    "Rsp MAC address (unknown purpose)", HFILL }
		},

		{ &hf_wlccp_priority,
		  { "Priority",           "wlccp.priority",
		    FT_UINT8, BASE_DEC, NULL, 0,          
		    "WDS priority of this access point", HFILL }
		},

		{ &hf_wlccp_age,
		  { "Age",           "wlccp.age",
		    FT_UINT32, BASE_DEC, NULL, 0,          
		    "Age (unknown purpose)", HFILL }
		},

		{ &hf_wlccp_period,
		  { "Period",           "wlccp.period",
		    FT_UINT8, BASE_DEC, NULL, 0,          
		    "Interval between announcements (seconds)", HFILL }
		},

		{ &hf_wlccp_ipv4_address,
		  { "IPv4 Address",           "wlccp.ipv4_address",
		    FT_IPv4, BASE_NONE, NULL, 0,          
		    "IPv4 address of this access point", HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_wlccp,
	};

	/* Register the protocol name and description */
	proto_wlccp = proto_register_protocol("Cisco Wireless LAN Context Control Protocol",
					      "WLCCP", "wlccp");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_wlccp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
        

}


void
proto_reg_handoff_wlccp(void)
{
        static gboolean inited = FALSE;
        
        if( !inited ) {

		dissector_handle_t wlccp_handle;

		wlccp_handle = create_dissector_handle(dissect_wlccp,
						       proto_wlccp);

		dissector_add("ethertype", ETHERTYPE_WLCCP, wlccp_handle);
		dissector_add("udp.port", WLCCP_UDP_PORT, wlccp_handle);
        
		inited = TRUE;
        }

}
