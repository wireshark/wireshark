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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-hci_h4.h"

/* Initialize the protocol and registered fields */
static int proto_bthci_sco = -1;
static int hf_bthci_sco_chandle = -1;
static int hf_bthci_sco_length = -1;
static int hf_bthci_sco_data = -1;

/* Initialize the subtree pointers */
static gint ett_bthci_sco = -1;


/* Code to actually dissect the packets */
static void
dissect_bthci_sco(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *bthci_sco_tree;
    int         offset = 0;

    ti = proto_tree_add_item(tree, proto_bthci_sco, tvb, offset, -1, ENC_NA);
    bthci_sco_tree = proto_item_add_subtree(ti, ett_bthci_sco);


    proto_tree_add_item(bthci_sco_tree, hf_bthci_sco_chandle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    proto_tree_add_item(bthci_sco_tree, hf_bthci_sco_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(bthci_sco_tree, hf_bthci_sco_data, tvb, offset, -1, ENC_NA);
}


void
proto_register_bthci_sco(void)
{
    static hf_register_info hf[] = {
        { &hf_bthci_sco_chandle,
            { "Connection Handle",           "bthci_sco.chandle",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_bthci_sco_length,
            { "Data Total Length",           "bthci_sco.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_sco_data,
            { "Data",                        "bthci_sco.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
      &ett_bthci_sco,
    };

    /* Register the protocol name and description */
    proto_bthci_sco = proto_register_protocol("Bluetooth HCI SCO Packet", "HCI_SCO", "bthci_sco");
    register_dissector("bthci_sco", dissect_bthci_sco, proto_bthci_sco);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_bthci_sco, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_bthci_sco(void)
{
    dissector_handle_t bthci_sco_handle;

    bthci_sco_handle = find_dissector("bthci_sco");
    dissector_add_uint("hci_h4.type", HCI_H4_TYPE_SCO, bthci_sco_handle);
    dissector_add_uint("hci_h1.type", BTHCI_CHANNEL_SCO, bthci_sco_handle);
}


