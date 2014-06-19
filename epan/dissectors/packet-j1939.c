/* packet-j1939.c
 * Routines for dissection of SAE J1939
 *
 * Michael Mann
 * Copyright 2013
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

#include <glib.h>
#include <epan/packet.h>

void proto_register_j1939(void);

#define J1939_CANID_MASK        0x1FFFFFFF
#define J1939_11BIT_ID          0x000003FF

static int proto_j1939 = -1;

static int hf_j1939_can_id = -1;
static int hf_j1939_priority = -1;
static int hf_j1939_pgn = -1;
static int hf_j1939_data_page = -1;
static int hf_j1939_extended_data_page = -1;
static int hf_j1939_pdu_format = -1;
static int hf_j1939_pdu_specific = -1;
static int hf_j1939_src_addr = -1;
static int hf_j1939_dst_addr = -1;
static int hf_j1939_group_extension = -1;
static int hf_j1939_data = -1;

static gint ett_j1939 = -1;
static gint ett_j1939_can = -1;
static gint ett_j1939_message = -1;

static dissector_table_t   subdissector_pgn_table;

static const value_string j1939_address_vals[] = {
    {0,"Engine #1"},
    {1,"Engine #2"},
    {2,"Turbocharger"},
    {3,"Transmission #1"},
    {4,"Transmission #2"},
    {5,"Shift Console - Primary"},
    {6,"Shift Console - Secondary"},
    {7,"Power TakeOff - (Main or Rear)"},
    {8,"Axle - Steering"},
    {9,"Axle - Drive #1"},
    {10,"Axle - Drive #2"},
    {11,"Brakes - System Controller"},
    {12,"Brakes - Steer Axle"},
    {13,"Brakes - Drive axle #1"},
    {14,"Brakes - Drive Axle #2"},
    {15,"Retarder - Engine"},
    {16,"Retarder - Driveline"},
    {17,"Cruise Control"},
    {18,"Fuel System"},
    {19,"Steering Controller"},
    {20,"Suspension - Steer Axle"},
    {21,"Suspension - Drive Axle #1"},
    {22,"Suspension - Drive Axle #2"},
    {23,"Instrument Cluster #1"},
    {24,"Trip Recorder"},
    {25,"Passenger-Operator Climate Control #1"},
    {26,"Alternator/Electrical Charging System"},
    {27,"Aerodynamic Control"},
    {28,"Vehicle Navigation"},
    {29,"Vehicle Security"},
    {30,"Electrical System"},
    {31,"Starter System"},
    {32,"Tractor-Trailer Bridge #1"},
    {33,"Body Controller"},
    {34,"Auxiliary Valve Control or Engine Air System Valve Control"},
    {35,"Hitch Control"},
    {36,"Power TakeOff (Front or Secondary)"},
    {37,"Off Vehicle Gateway"},
    {38,"Virtual Terminal (in cab)"},
    {39,"Management Computer #1"},
    {40,"Cab Display #1"},
    {41,"Retarder, Exhaust, Engine #1"},
    {42,"Headway Controller"},
    {43,"On-Board Diagnostic Unit"},
    {44,"Retarder, Exhaust, Engine #2"},
    {45,"Endurance Braking System"},
    {46,"Hydraulic Pump Controller"},
    {47,"Suspension - System Controller #1"},
    {48,"Pneumatic - System Controller"},
    {49,"Cab Controller - Primary"},
    {50,"Cab Controller - Secondary"},
    {51,"Tire Pressure Controller"},
    {52,"Ignition Control Module #1"},
    {53,"Ignition Control Module #2"},
    {54,"Seat Control #1"},
    {55,"Lighting - Operator Controls"},
    {56,"Rear Axle Steering Controller #1"},
    {57,"Water Pump Controller"},
    {58,"Passenger-Operator Climate Control #2"},
    {59,"Transmission Display - Primary"},
    {60,"Transmission Display - Secondary"},
    {61,"Exhaust Emission Controller"},
    {62,"Vehicle Dynamic Stability Controller"},
    {63,"Oil Sensor"},
    {64,"Suspension - System Controller #2"},
    {65,"Information System Controller #1"},
    {66,"Ramp Control"},
    {67,"Clutch/Converter Unit"},
    {68,"Auxiliary Heater #1"},
    {69,"Auxiliary Heater #2"},
    {70,"Engine Valve Controller"},
    {71,"Chassis Controller #1"},
    {72,"Chassis Controller #2"},
    {73,"Propulsion Battery Charger"},
    {74,"Communications Unit, Cellular"},
    {75,"Communications Unit, Satellite"},
    {76,"Communications Unit, Radio"},
    {77,"Steering Column Unit"},
    {78,"Fan Drive Controller"},
    {79,"Seat Control #2"},
    {80,"Parking brake controller"},
    {81,"Aftertreatment #1 system gas intake"},
    {82,"Aftertreatment #1 system gas outlet"},
    {83,"Safety Restraint System"},
    {84,"Cab Display #2"},
    {85,"Diesel Particulate Filter Controller"},
    {86,"Aftertreatment #2 system gas intake"},
    {87,"Aftertreatment #2 system gas outlet"},
    {88,"Safety Restraint System #2"},
    {89,"Atmospheric Sensor"},
    {248,"File Server / Printer"},
    {249,"Off Board Diagnostic-Service Tool #1"},
    {250,"Off Board Diagnostic-Service Tool #2"},
    {251,"On-Board Data Logger"},
    {252,"Reserved for Experimental Use"},
    {253,"Reserved for OEM"},
    {254,"Null Address"},
    {255,"GLOBAL"},
    { 0, NULL }
};

value_string_ext j1939_address_vals_ext = VALUE_STRING_EXT_INIT(j1939_address_vals);

static void
j1939_fmt_address(gchar *result, guint32 addr )
{
    if ((addr < 128) || (addr > 247))
        g_snprintf(result, ITEM_LABEL_LENGTH, "%d (%s)", addr, val_to_str_ext_const(addr, &j1939_address_vals_ext, "Reserved"));
    else
        g_snprintf(result, ITEM_LABEL_LENGTH, "%d (Arbitrary)", addr);
}

struct can_identifier
{
    guint32 id;
};

static int dissect_j1939(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_item *ti, *can_id_item;
    proto_tree *j1939_tree, *can_tree, *msg_tree;

    gint offset = 0;
    struct can_identifier can_id;
    guint32 data_length = tvb_reported_length(tvb);
    guint32 pgn;
    guint8 *src_addr, *dest_addr;

    DISSECTOR_ASSERT(data);
    can_id = *((struct can_identifier*)data);

    if (can_id.id & (~J1939_CANID_MASK))
    {
        /* Not for us */
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "J1939");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_j1939, tvb, offset, -1, ENC_NA);
    j1939_tree = proto_item_add_subtree(ti, ett_j1939);

    ti = proto_tree_add_text(j1939_tree, tvb, 0, 0, "CAN Identifier: 0x%08x", can_id.id);
    can_tree = proto_item_add_subtree(ti, ett_j1939_can);
    can_id_item = proto_tree_add_uint(can_tree, hf_j1939_can_id, tvb, 0, 0, can_id.id);
    PROTO_ITEM_SET_GENERATED(can_id_item);
    ti = proto_tree_add_uint(can_tree, hf_j1939_priority, tvb, 0, 0, can_id.id);
    PROTO_ITEM_SET_GENERATED(ti);
    ti = proto_tree_add_uint(can_tree, hf_j1939_extended_data_page, tvb, 0, 0, can_id.id);
    PROTO_ITEM_SET_GENERATED(ti);
    ti = proto_tree_add_uint(can_tree, hf_j1939_data_page, tvb, 0, 0, can_id.id);
    PROTO_ITEM_SET_GENERATED(ti);
    ti = proto_tree_add_uint(can_tree, hf_j1939_pdu_format, tvb, 0, 0, can_id.id);
    PROTO_ITEM_SET_GENERATED(ti);
    ti = proto_tree_add_uint(can_tree, hf_j1939_pdu_specific, tvb, 0, 0, can_id.id);
    PROTO_ITEM_SET_GENERATED(ti);
    ti = proto_tree_add_uint(can_tree, hf_j1939_src_addr, tvb, 0, 0, can_id.id);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Set source address */
    src_addr = (guint8*)wmem_alloc(pinfo->pool, 1);
    *src_addr = (guint8)(can_id.id & 0xFF);
    SET_ADDRESS(&pinfo->src, AT_J1939, 1, (const void*)src_addr);

    pgn = (can_id.id & 0x3FFFF00) >> 8;

    /* If PF < 240, PS is destination address, last byte of PGN is cleared */
    if (((can_id.id & 0xFF00) >> 8) < 240)
    {
        pgn &= 0x3FF00;

        ti = proto_tree_add_uint(can_tree, hf_j1939_dst_addr, tvb, 0, 0, can_id.id);
        PROTO_ITEM_SET_GENERATED(ti);
    }
    else
    {
        ti = proto_tree_add_uint(can_tree, hf_j1939_group_extension, tvb, 0, 0, can_id.id);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    /* Fill in "destination" address even if its "broadcast" */
    dest_addr = (guint8*)wmem_alloc(pinfo->pool, 1);
    *dest_addr = (guint8)((can_id.id & 0xFF00) >> 8);
    SET_ADDRESS(&pinfo->dst, AT_J1939, 1, (const void*)dest_addr);

    col_add_fstr(pinfo->cinfo, COL_INFO, "PGN: %d", pgn);

    /* For now just include raw bytes */
    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_ep_str_punct(tvb, 0, data_length, ' '));

    ti = proto_tree_add_text(j1939_tree, tvb, 0, -1, "Message");
    msg_tree = proto_item_add_subtree(ti, ett_j1939_message);

    ti = proto_tree_add_uint(msg_tree, hf_j1939_pgn, tvb, 0, 0, pgn);
    PROTO_ITEM_SET_GENERATED(ti);

    if (!dissector_try_uint_new(subdissector_pgn_table, pgn, tvb, pinfo, msg_tree, TRUE, data))
    {
        proto_tree_add_item(msg_tree, hf_j1939_data, tvb, 0, -1, ENC_NA);
    }

    return tvb_length(tvb);
}

void proto_register_j1939(void)
{
    static hf_register_info hf[] = {
        { &hf_j1939_can_id,
            {"CAN Identifier", "j1939.can_id",
            FT_UINT32, BASE_HEX, NULL, J1939_CANID_MASK, NULL, HFILL }
        },
        { &hf_j1939_priority,
            {"Priority", "j1939.priority",
            FT_UINT32, BASE_DEC, NULL, 0x1C000000, NULL, HFILL }
        },
        { &hf_j1939_pgn,
            {"PGN", "j1939.pgn",
            FT_UINT32, BASE_DEC, NULL, 0x3FFFFFF, NULL, HFILL }
        },
        { &hf_j1939_extended_data_page,
            {"Extended Data Page", "j1939.ex_data_page",
            FT_UINT32, BASE_DEC, NULL, 0x02000000, NULL, HFILL }
        },
        { &hf_j1939_data_page,
            {"Data Page", "j1939.data_page",
            FT_UINT32, BASE_DEC, NULL, 0x01000000, NULL, HFILL }
        },
        { &hf_j1939_pdu_format,
            {"PDU Format", "j1939.pdu_format",
            FT_UINT32, BASE_DEC, NULL, 0x00FF0000, NULL, HFILL }
        },
        { &hf_j1939_pdu_specific,
            {"PDU Specific", "j1939.pdu_specific",
            FT_UINT32, BASE_DEC, NULL, 0x0000FF00, NULL, HFILL }
        },
        { &hf_j1939_src_addr,
            {"Source Address", "j1939.src_addr",
            FT_UINT32, BASE_CUSTOM, j1939_fmt_address, 0x000000FF, NULL, HFILL }
        },
        { &hf_j1939_dst_addr,
            {"Destination Address", "j1939.dst_addr",
            FT_UINT32, BASE_CUSTOM, j1939_fmt_address, 0x0000FF00, NULL, HFILL }
        },
        { &hf_j1939_group_extension,
            {"Group Extension", "j1939.group_extension",
            FT_UINT32, BASE_DEC, NULL, 0x0000FF00, NULL, HFILL }
        },
        { &hf_j1939_data,
            {"Data", "j1939.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_j1939,
        &ett_j1939_can,
        &ett_j1939_message
    };

    proto_j1939 = proto_register_protocol("SAE J1939", "J1939", "j1939");

    proto_register_field_array(proto_j1939, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    new_register_dissector("j1939", dissect_j1939, proto_j1939);

    subdissector_pgn_table = register_dissector_table("j1939.pgn", "PGN Handle", FT_UINT32, BASE_DEC);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
