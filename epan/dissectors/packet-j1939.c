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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <inttypes.h>
#include <epan/packet.h>
#include <epan/address_types.h>
#include <epan/to_str.h>

#include "packet-socketcan.h"

void proto_register_j1939(void);
void proto_reg_handoff_j1939(void);

static dissector_handle_t j1939_handle;

static int proto_j1939;

static int hf_j1939_can_id;
static int hf_j1939_priority;
static int hf_j1939_pgn;
static int hf_j1939_data_page;
static int hf_j1939_extended_data_page;
static int hf_j1939_pdu_format;
static int hf_j1939_pdu_specific;
static int hf_j1939_src_addr;
static int hf_j1939_dst_addr;
static int hf_j1939_group_extension;
static int hf_j1939_data;

static int ett_j1939;
static int ett_j1939_can;
static int ett_j1939_message;

static int j1939_address_type = -1;
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

static value_string_ext j1939_address_vals_ext = VALUE_STRING_EXT_INIT(j1939_address_vals);

static void
j1939_fmt_address(char *result, uint32_t addr )
{
    if ((addr < 128) || (addr > 247))
        snprintf(result, ITEM_LABEL_LENGTH, "%d (%s)", addr, val_to_str_ext_const(addr, &j1939_address_vals_ext, "Reserved"));
    else
        snprintf(result, ITEM_LABEL_LENGTH, "%d (Arbitrary)", addr);
}

static int dissect_j1939(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_item *ti, *can_id_item;
    proto_tree *j1939_tree, *can_tree, *msg_tree;

    int offset = 0;
    struct can_info can_info;
    uint32_t data_length = tvb_reported_length(tvb);
    uint32_t pgn;
    uint8_t *src_addr, *dest_addr;

    DISSECTOR_ASSERT(data);
    can_info = *((struct can_info*)data);

    if ((can_info.id & CAN_ERR_FLAG) ||
        !(can_info.id & CAN_EFF_FLAG))
    {
        /* Error frames and frames with standards ids are not for us */
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "J1939");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_j1939, tvb, offset, tvb_reported_length(tvb), ENC_NA);
    j1939_tree = proto_item_add_subtree(ti, ett_j1939);

    can_tree = proto_tree_add_subtree_format(j1939_tree, tvb, 0, 0,
                    ett_j1939_can, NULL, "CAN Identifier: 0x%08x", can_info.id);
    can_id_item = proto_tree_add_uint(can_tree, hf_j1939_can_id, tvb, 0, 0, can_info.id);
    proto_item_set_generated(can_id_item);
    ti = proto_tree_add_uint(can_tree, hf_j1939_priority, tvb, 0, 0, can_info.id);
    proto_item_set_generated(ti);
    ti = proto_tree_add_uint(can_tree, hf_j1939_extended_data_page, tvb, 0, 0, can_info.id);
    proto_item_set_generated(ti);
    ti = proto_tree_add_uint(can_tree, hf_j1939_data_page, tvb, 0, 0, can_info.id);
    proto_item_set_generated(ti);
    ti = proto_tree_add_uint(can_tree, hf_j1939_pdu_format, tvb, 0, 0, can_info.id);
    proto_item_set_generated(ti);
    ti = proto_tree_add_uint(can_tree, hf_j1939_pdu_specific, tvb, 0, 0, can_info.id);
    proto_item_set_generated(ti);
    ti = proto_tree_add_uint(can_tree, hf_j1939_src_addr, tvb, 0, 0, can_info.id);
    proto_item_set_generated(ti);

    /* Set source address */
    src_addr = (uint8_t*)wmem_alloc(pinfo->pool, 1);
    *src_addr = (uint8_t)(can_info.id & 0xFF);
    set_address(&pinfo->src, j1939_address_type, 1, (const void*)src_addr);

    pgn = (can_info.id & 0x3FFFF00) >> 8;

    /* If PF < 240, PS is destination address, last byte of PGN is cleared */
    if (((can_info.id & 0xFF0000) >> 16) < 240)
    {
        pgn &= 0x3FF00;

        ti = proto_tree_add_uint(can_tree, hf_j1939_dst_addr, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
    }
    else
    {
        ti = proto_tree_add_uint(can_tree, hf_j1939_group_extension, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
    }

    /* Fill in "destination" address even if its "broadcast" */
    dest_addr = (uint8_t*)wmem_alloc(pinfo->pool, 1);
    *dest_addr = (uint8_t)((can_info.id & 0xFF00) >> 8);
    set_address(&pinfo->dst, j1939_address_type, 1, (const void*)dest_addr);

    col_add_fstr(pinfo->cinfo, COL_INFO, "PGN: %-6"  PRIu32, pgn);

    if (can_info.id & CAN_RTR_FLAG)
    {
        /* RTR frames don't have payload */
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", "(Remote Transmission Request)");
    }
    else
    {
        /* For now just include raw bytes */
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, 0, data_length, ' '));
    }

    msg_tree = proto_tree_add_subtree(j1939_tree, tvb, 0, tvb_reported_length(tvb), ett_j1939_message, NULL, "Message");

    ti = proto_tree_add_uint(msg_tree, hf_j1939_pgn, tvb, 0, 0, pgn);
    proto_item_set_generated(ti);

    if (!dissector_try_uint_new(subdissector_pgn_table, pgn, tvb, pinfo, msg_tree, true, data))
    {
        proto_tree_add_item(msg_tree, hf_j1939_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    }

    return tvb_captured_length(tvb);
}

static int J1939_addr_to_str(const address* addr, char *buf, int buf_len)
{
    const uint8_t *addrdata = (const uint8_t *)addr->data;

    guint32_to_str_buf(*addrdata, buf, buf_len);
    return (int)strlen(buf);
}

static int J1939_addr_str_len(const address* addr _U_)
{
    return 11; /* Leaves required space (10 bytes) for uint_to_str_back() */
}

static const char* J1939_col_filter_str(const address* addr _U_, bool is_src)
{
    if (is_src)
        return "j1939.src_addr";

    return "j1939.dst_addr";
}

static int J1939_addr_len(void)
{
    return 1;
}

void proto_register_j1939(void)
{
    static hf_register_info hf[] = {
        { &hf_j1939_can_id,
            {"CAN Identifier", "j1939.can_id",
            FT_UINT32, BASE_HEX, NULL, CAN_EFF_MASK, NULL, HFILL }
        },
        { &hf_j1939_priority,
            {"Priority", "j1939.priority",
            FT_UINT32, BASE_DEC, NULL, 0x1C000000, NULL, HFILL }
        },
        { &hf_j1939_pgn,
            {"PGN", "j1939.pgn",
            FT_UINT32, BASE_DEC, NULL, 0x03FFFFFF, NULL, HFILL }
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
            FT_UINT32, BASE_CUSTOM, CF_FUNC(j1939_fmt_address), 0x000000FF, NULL, HFILL }
        },
        { &hf_j1939_dst_addr,
            {"Destination Address", "j1939.dst_addr",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(j1939_fmt_address), 0x0000FF00, NULL, HFILL }
        },
        { &hf_j1939_group_extension,
            {"Group Extension", "j1939.group_extension",
            FT_UINT32, BASE_DEC, NULL, 0x0000FF00, NULL, HFILL }
        },
        { &hf_j1939_data,
            {"Data", "j1939.data",
            FT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_j1939,
        &ett_j1939_can,
        &ett_j1939_message
    };

    proto_j1939 = proto_register_protocol("SAE J1939", "J1939", "j1939");

    proto_register_field_array(proto_j1939, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    subdissector_pgn_table = register_dissector_table("j1939.pgn", "PGN Handle", proto_j1939, FT_UINT32, BASE_DEC);

    j1939_address_type = address_type_dissector_register("AT_J1939", "J1939 Address", J1939_addr_to_str, J1939_addr_str_len, NULL, J1939_col_filter_str, J1939_addr_len, NULL, NULL);

    j1939_handle = register_dissector("j1939",  dissect_j1939, proto_j1939 );
}

void
proto_reg_handoff_j1939(void)
{
    dissector_add_for_decode_as("can.subdissector", j1939_handle );
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
