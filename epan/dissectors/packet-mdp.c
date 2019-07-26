/* packet-mdp.c
 * Routines for the disassembly of the "Meraki Discovery Protocol (MDP)"
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <stdio.h>
#include <epan/packet.h>

#define MDP_TLV_TYPE            0
#define MDP_TLV_LENGTH          1
#define MDP_TLV_DEVICE_INFO     2
#define MDP_TLV_NETWORK_INFO    3
#define MDP_TLV_LONGITUDE       4
#define MDP_TLV_LATITUDE        5
#define MDP_TLV_TYPE_SIX        6
#define MDP_TLV_TYPE_SEVEN      7
#define MDP_TLV_END             255

void proto_register_mdp(void);
void proto_reg_handoff_mdp(void);

static int proto_mdp = -1;
static int hf_mdp_preamble_data = -1;
static int hf_mdp_device_info = -1;
static int hf_mdp_network_info = -1;
static int hf_mdp_type = -1;
static int hf_mdp_length = -1;
static int hf_mdp_longitude = -1;
static int hf_mdp_latitude = -1;
static int hf_mdp_type_six = -1;
static int hf_mdp_type_seven = -1;
static int hf_mdp_data = -1;

static gint ett_mdp = -1;
static gint ett_mdp_tlv = -1;

static dissector_handle_t mdp_handle;

/* Format Identifier */
static const value_string type_vals[] = {
    { MDP_TLV_DEVICE_INFO, "Device Info" },
    { MDP_TLV_NETWORK_INFO, "Network Info" },
    { MDP_TLV_LONGITUDE, "Longitude" },
    { MDP_TLV_LATITUDE, "Latitude" },
    { MDP_TLV_TYPE_SIX, "Type 6 UID" },
    { MDP_TLV_TYPE_SEVEN, "Type 7 UID" },
    { MDP_TLV_END, "End" },
    { 0, NULL }
};

static int
dissect_mdp(tvbuff_t *mdp_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree  *mdp_tree, *tlv_tree;
    proto_item  *mdp_item, *tlv_item;
    guint32     mdp_type, mdp_length;
    gint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MDP");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "MDP");

    mdp_item = proto_tree_add_item(tree, proto_mdp, mdp_tvb, 0, -1, ENC_NA);
    mdp_tree = proto_item_add_subtree(mdp_item, ett_mdp);

    proto_tree_add_item(mdp_tree, hf_mdp_preamble_data, mdp_tvb, 0, 28, ENC_NA);
    offset += 28;

    while(tvb_reported_length_remaining(mdp_tvb, offset) != 0){
	tlv_tree = proto_tree_add_subtree(mdp_tree, mdp_tvb, offset + MDP_TLV_TYPE, -1, ett_mdp_tlv, &tlv_item, "");
        proto_tree_add_item_ret_uint(tlv_tree, hf_mdp_type, mdp_tvb, offset + MDP_TLV_TYPE, 1, ENC_BIG_ENDIAN, &mdp_type);
        proto_item_set_text(tlv_tree, "%s", val_to_str_const(mdp_type, type_vals, "Unknown type"));
        proto_tree_add_item_ret_uint(tlv_tree, hf_mdp_length, mdp_tvb, offset + MDP_TLV_LENGTH, 1, ENC_BIG_ENDIAN, &mdp_length);

        offset += 2;

        switch(mdp_type){
          case MDP_TLV_DEVICE_INFO:
            proto_tree_add_item(tlv_tree, hf_mdp_device_info, mdp_tvb, offset, mdp_length, ENC_UTF_8 | ENC_NA);
            break;
          case MDP_TLV_NETWORK_INFO:
            proto_tree_add_item(tlv_tree, hf_mdp_network_info, mdp_tvb, offset, mdp_length, ENC_UTF_8 | ENC_NA);
             break;
          case MDP_TLV_LONGITUDE:
            proto_tree_add_item(tlv_tree, hf_mdp_longitude, mdp_tvb, offset, mdp_length, ENC_UTF_8 | ENC_NA);
            break;
          case MDP_TLV_LATITUDE:
            proto_tree_add_item(tlv_tree, hf_mdp_latitude, mdp_tvb, offset, mdp_length, ENC_UTF_8 | ENC_NA);
            break;
          case MDP_TLV_TYPE_SIX:
            proto_tree_add_item(tlv_tree, hf_mdp_type_six, mdp_tvb, offset, mdp_length, ENC_UTF_8 | ENC_NA);
            break;
          case MDP_TLV_TYPE_SEVEN:
            proto_tree_add_item(tlv_tree, hf_mdp_type_seven, mdp_tvb, offset, mdp_length, ENC_UTF_8 | ENC_NA);
            break;
          case MDP_TLV_END:
            break;
          default:
            proto_tree_add_item(mdp_tree, hf_mdp_data, mdp_tvb, offset, mdp_length, ENC_NA);
            break;
        }
        proto_item_set_len(tlv_item, mdp_length + 2);
        offset += mdp_length;
    }
    return tvb_captured_length(mdp_tvb);
}

void
proto_register_mdp(void)
{

    static hf_register_info hf[] = {
        { &hf_mdp_preamble_data, {"Preamble Data","mdp.preamble_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mdp_device_info, {"Device Info", "mdp.device_info", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }},
        { &hf_mdp_network_info, {"Network Info", "mdp.network_info", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }},
        { &hf_mdp_longitude, {"Longitude", "mdp.longitude", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }},
        { &hf_mdp_latitude, {"Latitude", "mdp.latitude", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }},
        { &hf_mdp_type, {"Type", "mdp.type", FT_UINT8, BASE_DEC, VALS(type_vals), 0x0, NULL, HFILL }},
        { &hf_mdp_type_six, {"Type 6 UID", "mdp.type_six", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }},
        { &hf_mdp_type_seven, {"Type 7 UID", "mdp.type_seven", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }},
        { &hf_mdp_length, {"Length", "mdp.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_mdp_data, {"Unknown Data", "mdp.data", FT_BYTES, BASE_NONE, NULL, 0X0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_mdp,
        &ett_mdp_tlv
    };

    proto_mdp = proto_register_protocol("Meraki Discovery Protocol", "MDP", "mdp");
    proto_register_field_array(proto_mdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    mdp_handle = register_dissector("mdp", dissect_mdp, proto_mdp);
}

void
proto_reg_handoff_mdp(void)
{
    dissector_add_uint("ethertype", 0x0712, mdp_handle);
    dissector_add_uint("ethertype", 0x0713, mdp_handle);
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
