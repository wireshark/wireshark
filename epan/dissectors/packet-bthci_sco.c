/* packet-bthci_sco.c
 * Routines for the Bluetooth SCO dissection
 * Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
 *
 * Refactored for wireshark checkin
 *   Ronnie Sahlberg 2006
 *
 * $Id$
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
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <etypes.h>
#include <packet-hci_h4.h>

/* Initialize the protocol and registered fields */
static int proto_btsco = -1;
static int hf_btsco_chandle = -1;
static int hf_btsco_length = -1;
static int hf_btsco_data = -1;

/* Initialize the subtree pointers */
static gint ett_btsco = -1;


/* Code to actually dissect the packets */
static void 
dissect_btsco(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *btsco_tree;
  int offset=0;

  ti = proto_tree_add_item(tree, proto_btsco, tvb, offset, -1, FALSE);
  btsco_tree = proto_item_add_subtree(ti, ett_btsco);
  

  proto_tree_add_item(btsco_tree, hf_btsco_chandle, tvb, offset, 2, TRUE);
  offset+=2;

  proto_tree_add_item(btsco_tree, hf_btsco_length, tvb, offset, 1, TRUE);
  offset++;

  proto_tree_add_item(btsco_tree, hf_btsco_data, tvb, offset, -1, TRUE);
}


void
proto_register_btsco(void)
{                 
	static hf_register_info hf[] = {
		{ &hf_btsco_chandle,
			{ "Connection Handle",           "btsco.chandle",
			FT_UINT16, BASE_HEX, NULL, 0x0FFF,          
			"Connection Handle", HFILL }
		},
		{ &hf_btsco_length,
			{ "Data Total Length",           "btsco.length",
			FT_UINT8, BASE_DEC, NULL, 0x0,          
			"Data Total Length", HFILL }
		},
		{ &hf_btsco_data,
			{ "Data",           "btsco.data",
			FT_NONE, BASE_NONE, NULL, 0x0,          
			"Data", HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
	  &ett_btsco,
	};

	/* Register the protocol name and description */
	proto_btsco = proto_register_protocol("Bluetooth HCI SCO Packet", "HCI_SCO", "bthci_sco");
	register_dissector("bthci_sco", dissect_btsco, proto_btsco);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_btsco, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


void 
proto_reg_handoff_btsco(void)
{
	dissector_handle_t bthci_sco_handle;

	bthci_sco_handle = find_dissector("bthci_sco");
	dissector_add("hci_h4.type", HCI_H4_TYPE_SCO, bthci_sco_handle);
}


