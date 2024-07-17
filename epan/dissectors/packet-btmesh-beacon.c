/* packet-btmesh-beacon.c
 * Routines for Bluetooth mesh PB-ADV dissection
 *
 * Copyright 2019, Piotr Winiarczyk <wino45@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: Mesh Profile v1.0
 * https://www.bluetooth.com/specifications/mesh-specifications
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-btmesh.h"

#define BEACON_UNPROVISION 0x00
#define BEACON_SECURE      0x01

void proto_register_btmesh_beacon(void);

static int proto_btmesh_beacon;

static int hf_btmesh_beacon_type;
static int hf_btmesh_beacon_uuid;
static int hf_btmesh_beacon_oob;
static int hf_btmesh_beacon_oob_other;
static int hf_btmesh_beacon_oob_electronic;
static int hf_btmesh_beacon_oob_2d_code;
static int hf_btmesh_beacon_oob_bar_code;
static int hf_btmesh_beacon_oob_nfc;
static int hf_btmesh_beacon_oob_number;
static int hf_btmesh_beacon_oob_string;
static int hf_btmesh_beacon_oob_rfu;
static int hf_btmesh_beacon_oob_on_box;
static int hf_btmesh_beacon_oob_inside_box;
static int hf_btmesh_beacon_oob_on_paper;
static int hf_btmesh_beacon_oob_inside_manual;
static int hf_btmesh_beacon_oob_on_device;
static int hf_btmesh_beacon_uri_hash;
static int hf_btmesh_beacon_flags;
static int hf_btmesh_beacon_flags_key_refresh;
static int hf_btmesh_beacon_flags_iv_update;
static int hf_btmesh_beacon_flags_rfu;
static int hf_btmesh_beacon_network_id;
static int hf_btmesh_beacon_ivindex;
//TODO: check authentication value
static int hf_btmesh_beacon_authentication_value;
static int hf_btmesh_beacon_unknown_data;

static int ett_btmesh_beacon;
static int ett_btmesh_beacon_oob;
static int ett_btmesh_beacon_flags;

static expert_field ei_btmesh_beacon_unknown_beacon_type;
static expert_field ei_btmesh_beacon_unknown_payload;
static expert_field ei_btmesh_beacon_rfu_not_zero;

static const value_string btmesh_beacon_type[] = {
    { 0, "Unprovisioned Device Beacon" },
    { 1, "Secure Network Beacon" },
    { 0, NULL }
};

static const true_false_string flags_key_refresh = {
  "Key Refresh in progress",
  "Key Refresh not in progress"
};

static const true_false_string flags_iv_update = {
  "IV Update active",
  "Normal operation"
};

static int
dissect_btmesh_beacon_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

    proto_item *item, *oob_item, *flags_item;
    proto_tree *sub_tree, *oob_tree, *flags_tree;
    unsigned offset = 0;
    unsigned data_size = 0;
    btle_mesh_transport_ctx_t *tr_ctx;
    btle_mesh_transport_ctx_t dummy_ctx = {E_BTMESH_TR_UNKNOWN, false, 0};
    uint16_t rfu_bits16;
    uint8_t rfu_bits8;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT Mesh Beacon");

    if (data == NULL) {
        tr_ctx = &dummy_ctx;
    } else {
        tr_ctx = (btle_mesh_transport_ctx_t *) data;
    }

    item = proto_tree_add_item(tree, proto_btmesh_beacon, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_btmesh_beacon);

    uint8_t beacon_type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(sub_tree, hf_btmesh_beacon_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(beacon_type, btmesh_beacon_type, "Unknown Beacon Type"));
    if (tr_ctx->fragmented) {
        switch (tr_ctx->transport) {
            case E_BTMESH_TR_PROXY:
                col_append_str(pinfo->cinfo, COL_INFO," (Last Segment)");

            break;
            default:
            //No default is needed since this is an additional information only

            break;
        }
    }

    switch(beacon_type) {
        case BEACON_UNPROVISION:
            proto_tree_add_item(sub_tree, hf_btmesh_beacon_uuid, tvb, offset, 16, ENC_NA);
            offset += 16;

            oob_item = proto_tree_add_item(sub_tree, hf_btmesh_beacon_oob, tvb, offset, 2, ENC_BIG_ENDIAN);
            oob_tree = proto_item_add_subtree(oob_item, ett_btmesh_beacon_oob);

            proto_tree_add_item(oob_tree, hf_btmesh_beacon_oob_other, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(oob_tree, hf_btmesh_beacon_oob_electronic, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(oob_tree, hf_btmesh_beacon_oob_2d_code, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(oob_tree, hf_btmesh_beacon_oob_bar_code, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(oob_tree, hf_btmesh_beacon_oob_nfc, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(oob_tree, hf_btmesh_beacon_oob_number, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(oob_tree, hf_btmesh_beacon_oob_string, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(oob_tree, hf_btmesh_beacon_oob_rfu, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(oob_tree, hf_btmesh_beacon_oob_on_box, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(oob_tree, hf_btmesh_beacon_oob_inside_box, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(oob_tree, hf_btmesh_beacon_oob_on_paper, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(oob_tree, hf_btmesh_beacon_oob_inside_manual, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(oob_tree, hf_btmesh_beacon_oob_on_device, tvb, offset, 2, ENC_NA);
            rfu_bits16 = (tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) & 0x0780) >> 7;
            if (rfu_bits16 != 0) {
                //RFU bits should be 0
                proto_tree_add_expert(oob_tree, pinfo, &ei_btmesh_beacon_rfu_not_zero, tvb, offset, -1);
            }
            offset += 2;

            data_size = tvb_reported_length(tvb);
            if (data_size == offset + 4 ) {
                proto_tree_add_item(sub_tree, hf_btmesh_beacon_uri_hash, tvb, offset, 4, ENC_NA);
                offset += 4;
            }
            //Wrong size handled outside switch/case

        break;
        case BEACON_SECURE:
            flags_item = proto_tree_add_item(sub_tree, hf_btmesh_beacon_flags, tvb, offset, 1, ENC_NA);
            flags_tree = proto_item_add_subtree(flags_item, ett_btmesh_beacon_flags);
            proto_tree_add_item(flags_tree, hf_btmesh_beacon_flags_key_refresh, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_btmesh_beacon_flags_iv_update, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_btmesh_beacon_flags_rfu, tvb, offset, 1, ENC_NA);
            rfu_bits8 = tvb_get_uint8(tvb, offset) >> 2;
            if (rfu_bits8 != 0) {
                //RFU bits should be 0
                proto_tree_add_expert(flags_tree, pinfo, &ei_btmesh_beacon_rfu_not_zero, tvb, offset, -1);
            }
            offset += 1;
            proto_tree_add_item(sub_tree, hf_btmesh_beacon_network_id, tvb, offset, 8, ENC_NA);
            offset += 8;
            proto_tree_add_item(sub_tree, hf_btmesh_beacon_ivindex, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(sub_tree, hf_btmesh_beacon_authentication_value, tvb, offset, 8, ENC_NA);
            offset += 8;
        break;
        default:
            //Unknown mesh beacon type, display data and flag it
            proto_tree_add_item(sub_tree, hf_btmesh_beacon_unknown_data, tvb, offset, -1, ENC_NA);
            proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_beacon_unknown_beacon_type, tvb, offset, -1);
            offset += tvb_captured_length_remaining(tvb, offset);
        break;
    }
    //There is still some data but all data should be already disssected
    if (tvb_captured_length_remaining(tvb, offset) != 0) {
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_beacon_unknown_payload, tvb, offset, -1);
    }

    return tvb_reported_length(tvb);
}

void
proto_register_btmesh_beacon(void)
{
    static hf_register_info hf[] = {
        { &hf_btmesh_beacon_type,
            { "Type", "beacon.type",
                FT_UINT8, BASE_DEC, VALS(btmesh_beacon_type), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_beacon_uuid,
            { "Device UUID", "beacon.uuid",
                FT_GUID, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_beacon_oob,
            { "OOB Information", "beacon.oob",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_beacon_oob_other,
            { "Other", "beacon.oob.other",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0001,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_oob_electronic,
            { "Electronic / URI", "beacon.oob.electronic",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0002,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_oob_2d_code,
            { "2D machine-readable code", "beacon.oob.2d_code",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0004,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_oob_bar_code,
            { "Bar code", "beacon.oob.bar_code",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0008,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_oob_nfc,
            { "Near Field Communication (NFC)", "beacon.oob.nfc",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0010,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_oob_number,
            { "Number", "beacon.oob.number",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0020,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_oob_string,
            { "String", "beacon.oob.string",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0040,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_oob_rfu,
            { "Reserved for Future Use", "beacon.oob.rfu",
                FT_UINT16, BASE_DEC, NULL, 0x0780,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_oob_on_box,
            { "On box", "beacon.oob.on_box",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0800,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_oob_inside_box,
            { "Inside box", "beacon.oob.inside_box",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x1000,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_oob_on_paper,
            { "On piece of paper", "beacon.oob.on_paper",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x2000,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_oob_inside_manual,
            { "Inside manual", "beacon.oob.inside_manual",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x4000,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_oob_on_device,
            { "On device", "beacon.oob.on_device",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x8000,
                NULL, HFILL }
        },
        { &hf_btmesh_beacon_uri_hash,
            { "URI Hash", "beacon.uri_hash",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_beacon_flags,
            { "Flags", "beacon.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_flags_key_refresh,
            { "Key Refresh Flag", "beacon.flags.key_refresh",
                FT_BOOLEAN, 8, TFS(&flags_key_refresh), 0x01,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_flags_iv_update,
            { "IV Update Flag", "beacon.flags.iv_update",
                FT_BOOLEAN, 8, TFS(&flags_iv_update), 0x02,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_flags_rfu,
            { "Reserved for Future Use", "beacon.flags.rfu",
                FT_UINT8, BASE_DEC, NULL, 0xFC,
                NULL, HFILL }
        },
       { &hf_btmesh_beacon_network_id,
            { "Network ID", "beacon.network_id",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_beacon_ivindex,
            { "IV Index", "beacon.ivindex",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_beacon_authentication_value,
            { "Authentication Value", "beacon.authentication_value",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_beacon_unknown_data,
            { "Unknown Data", "beacon.unknown_data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_btmesh_beacon,
        &ett_btmesh_beacon_oob,
        &ett_btmesh_beacon_flags,
    };

    static ei_register_info ei[] = {
        { &ei_btmesh_beacon_unknown_beacon_type,{ "beacon.unknown_beacon_type", PI_PROTOCOL, PI_ERROR, "Unknown Beacon Type", EXPFILL } },
        { &ei_btmesh_beacon_unknown_payload,{ "beacon.unknown_payload", PI_PROTOCOL, PI_ERROR, "Unknown Payload", EXPFILL } },
        { &ei_btmesh_beacon_rfu_not_zero,{ "beacon.rfu_not_zero", PI_PROTOCOL, PI_WARN, "Reserved for Future Use value not equal to 0", EXPFILL } },
    };

    expert_module_t* expert_btmesh_beacon;

    proto_btmesh_beacon = proto_register_protocol("Bluetooth Mesh Beacon", "BT Mesh beacon", "beacon");

    proto_register_field_array(proto_btmesh_beacon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_btmesh_beacon = expert_register_protocol(proto_btmesh_beacon);
    expert_register_field_array(expert_btmesh_beacon, ei, array_length(ei));

    prefs_register_protocol_subtree("Bluetooth", proto_btmesh_beacon, NULL);
    register_dissector("btmesh.beacon", dissect_btmesh_beacon_msg, proto_btmesh_beacon);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
