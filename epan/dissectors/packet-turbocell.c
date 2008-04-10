/* packet-turbocell.c
 * Routines for Turbocell Header dissection
 * Copyright 2004, Colin Slater <kiltedtaco@xxxxxxxxx>
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

/* This dissector was written entirely from reverse engineering captured
 * packets. No documentation was used or supplied by Karlnet. Hence, this
 * dissector is very incomplete. If you have any insight into decoding
 * these packets, or if you can supply packet captures from turbocell 
 * networks, contact kiltedtaco@xxxxxxxxx */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

#include "oui.h"

#define TURBOCELL_TYPE_BEACON	0x00
#define TURBOCELL_TYPE_DATA	0x01
#define TURBOCELL_TYPE_MANAGEMENT	0x11
#define TURBOCELL_TYPE_NAME	0xA0

/* Initialize the protocol and registered fields */
static int proto_turbocell = -1;
static int hf_turbocell_type = -1;
static int hf_turbocell_baseid = -1;
static int hf_turbocell_counter = -1;
static int hf_turbocell_station_number = -1;
static int hf_turbocell_name = -1;
static int hf_turbocell_base[6];

/* Initialize the subtree pointers */
static gint ett_turbocell = -1;
static gint ett_network = -1;

/* The ethernet dissector we hand off to */
static dissector_handle_t eth_handle;

/* Guesses at what the first byte of the protocol id means */
static const value_string turbocell_type_values[] = {
    { TURBOCELL_TYPE_BEACON,     "Beacon" },
    { TURBOCELL_TYPE_DATA,       "Data packet" },
    { TURBOCELL_TYPE_MANAGEMENT, "Management Packet" },
    { TURBOCELL_TYPE_NAME,       "Name" },
    { 0, NULL }
};


static void
dissect_turbocell(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    proto_item *ti, *name_item;
    proto_tree *turbocell_tree, *network_tree;
    tvbuff_t   *next_tvb;
    int i;

    if (tree) {
        ti = proto_tree_add_item(tree, proto_turbocell, tvb, 0, -1, FALSE);

        turbocell_tree = proto_item_add_subtree(ti, ett_turbocell);

        proto_tree_add_item(turbocell_tree, hf_turbocell_type, tvb, 0, 1, FALSE);
        proto_tree_add_item(turbocell_tree, hf_turbocell_baseid, tvb, 4, 6, FALSE);
        proto_tree_add_item(turbocell_tree, hf_turbocell_station_number, tvb, 10, 1, FALSE);
        proto_tree_add_item(turbocell_tree, hf_turbocell_counter, tvb, 2, 2, FALSE);

        if (tvb_get_guint8(tvb, 0) == TURBOCELL_TYPE_NAME) {
            name_item = proto_tree_add_item(turbocell_tree, hf_turbocell_name, tvb, 0x14, 30, FALSE);
            network_tree = proto_item_add_subtree(name_item, ett_network);

            for (i=0; i<6; i++) {
                proto_tree_add_item(network_tree, hf_turbocell_base[i], tvb, 0x34+8*i, 6, FALSE);
            }
        }
    }

    if (tvb_get_guint8(tvb, 0) == TURBOCELL_TYPE_BEACON) {
        if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, "Turbocell Packet (Beacon)");
        if (check_col(pinfo->cinfo, COL_PROTOCOL))
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "Turbocell");
    } else if ((tvb_get_guint8(tvb, 0) == TURBOCELL_TYPE_DATA) || (tvb_get_guint8(tvb, 0) == TURBOCELL_TYPE_MANAGEMENT)) {
        /* The hardcoded 0x1A offset here is where the ethernet header
         * appears to always start. It would not suprize me if it changed
         * between different networks, though. */
        next_tvb = tvb_new_subset(tvb, 0x1a, -1, -1);
        call_dissector(eth_handle, next_tvb, pinfo, tree);
    } else if (tvb_get_guint8(tvb, 0) == TURBOCELL_TYPE_NAME) {
        if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, "Turbocell Packet (Name)");
        if (check_col(pinfo->cinfo, COL_PROTOCOL))
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "Turbocell");
    } else {
        if (check_col(pinfo->cinfo, COL_INFO))
            col_set_str(pinfo->cinfo, COL_INFO, "Turbocell Packet (Unknown)");
        if (check_col(pinfo->cinfo, COL_PROTOCOL))
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "Turbocell");
    }
}


/* Register the protocol with Wireshark */

void proto_register_turbocell(void)
{

    static hf_register_info hf[] = {
        { &hf_turbocell_type,
            { "Packet Type", "turbocell.type",
            FT_UINT8, BASE_HEX, VALS(turbocell_type_values), 0,
            NULL, HFILL }
        },
        { &hf_turbocell_baseid,
            { "Base Station ID", "turbocell.baseid",
            FT_ETHER, BASE_NONE, NULL, 0,
            "Seems to stay constant per base station", HFILL }
        },
        { &hf_turbocell_station_number,
            { "Station Number", "turbocell.stationnum",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Seems to stay constant per station", HFILL }
        },
        { &hf_turbocell_counter,
            { "Counter", "turbocell.counter",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Increments alot", HFILL }
        },
        { &hf_turbocell_name,
            { "Network Name", "turbocell.name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Name", HFILL }
        },
        { &hf_turbocell_base[0],
            { "Base 0", "turbocell.base0",
            FT_ETHER, BASE_NONE, NULL, 0,
            "Base station ID?", HFILL }
        },
        { &hf_turbocell_base[1],
            { "Base 1", "turbocell.base1",
            FT_ETHER, BASE_NONE, NULL, 0,
            "Base station ID?", HFILL }
        },
        { &hf_turbocell_base[2],
            { "Base 2", "turbocell.base2",
            FT_ETHER, BASE_NONE, NULL, 0,
            "Base station ID?", HFILL }
        },
        { &hf_turbocell_base[3],
            { "Base 3", "turbocell.base3",
            FT_ETHER, BASE_NONE, NULL, 0,
            "Base station ID?", HFILL }
        },
        { &hf_turbocell_base[4],
            { "Base 4", "turbocell.base4",
            FT_ETHER, BASE_NONE, NULL, 0,
            "Base station ID?", HFILL }
        },
        { &hf_turbocell_base[5],
            { "Base 5", "turbocell.base5",
            FT_ETHER, BASE_NONE, NULL, 0,
            "Base station ID?", HFILL }
        }
    };

    static gint *ett[] = {
        &ett_turbocell,
        &ett_network
    };

    proto_turbocell = proto_register_protocol("Turbocell Header", "Turbocell", "turbocell");

    register_dissector("turbocell", dissect_turbocell, proto_turbocell);

    proto_register_field_array(proto_turbocell, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_turbocell(void)
{
    dissector_handle_t turbocell_handle;

    eth_handle = find_dissector("eth_withoutfcs");

    turbocell_handle = create_dissector_handle(dissect_turbocell, proto_turbocell);
}

