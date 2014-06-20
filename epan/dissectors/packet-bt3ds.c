/* packet-bt3ds.c
 * Routines for Bluetooth 3DS dissection
 *
 * Copyright 2013, Michal Labedzki for Tieto Corporation
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
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-btl2cap.h"
#include "packet-btsdp.h"

static int proto_bt3ds = -1;

static int hf_message_opcode                                               = -1;
static int hf_association_notification                                     = -1;
static int hf_user_request_for_battery_level_display                       = -1;
static int hf_reserved                                                     = -1;
static int hf_battery_level                                                = -1;

static expert_field ei_message_opcode_reserved                        = EI_INIT;
static expert_field ei_reserved                                       = EI_INIT;
static expert_field ei_battery_level_reserved                         = EI_INIT;
static expert_field ei_unexpected_data                                = EI_INIT;

static gint ett_bt3ds                                                      = -1;

static dissector_handle_t b3ds_handle;

static const value_string message_opcode_vals[] = {
    { 0x00,   "3DG Connection Announcement" },
    { 0, NULL }
};

void proto_register_bt3ds(void);
void proto_reg_handoff_bt3ds(void);

static gint
dissect_bt3ds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item     *main_item;
    proto_tree     *main_tree;
    proto_item     *sub_item;
    gint            offset = 0;
    guint8          value;

    main_item = proto_tree_add_item(tree, proto_bt3ds, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_bt3ds);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "3DS");

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
                pinfo->p2p_dir);
            break;
    }

    sub_item = proto_tree_add_item(main_tree, hf_message_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    value = tvb_get_guint8(tvb, offset);
    if (value > 0)
        expert_add_info(pinfo, sub_item, &ei_message_opcode_reserved);
    offset += 1;

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_const(value, message_opcode_vals, "Unknown"));

    sub_item = proto_tree_add_item(main_tree, hf_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(main_tree, hf_user_request_for_battery_level_display, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(main_tree, hf_association_notification, tvb, offset, 1, ENC_BIG_ENDIAN);
    value = tvb_get_guint8(tvb, offset) >> 2;
    if (value != 0)
        expert_add_info(pinfo, sub_item, &ei_reserved);
    offset += 1;

    sub_item = proto_tree_add_item(main_tree, hf_battery_level, tvb, offset, 1, ENC_BIG_ENDIAN);
    value = tvb_get_guint8(tvb, offset);
    if (value >= 101 && value <= 254)
        expert_add_info(pinfo, sub_item, &ei_battery_level_reserved);
    else if (value == 255)
        proto_item_append_text(sub_item, "Battery Level Reporting Not Supported");

    offset += 1;

    if (tvb_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert(main_tree, pinfo, &ei_unexpected_data, tvb, offset, -1);
        offset += tvb_length_remaining(tvb, offset);
    }

    return offset;
}


void
proto_register_bt3ds(void)
{
    module_t         *module;
    expert_module_t  *expert_bt3ds;

    static ei_register_info ei[] = {
        { &ei_message_opcode_reserved,           { "bt3ds.expert.message_opcode.reserved", PI_PROTOCOL, PI_NOTE, "Value is reserved", EXPFILL }},
        { &ei_reserved,                          { "bt3ds.expert.reserved", PI_PROTOCOL, PI_NOTE, "Value is reserved", EXPFILL }},
        { &ei_battery_level_reserved,            { "bt3ds.expert.battery_level.reserved", PI_PROTOCOL, PI_NOTE, "Value is reserved", EXPFILL }},
        { &ei_unexpected_data,                   { "bt3ds.expert.unexpected_data", PI_PROTOCOL, PI_WARN, "Unexpected data", EXPFILL }}
    };

    static hf_register_info hf[] = {
        { &hf_message_opcode,
            { "Message Opcode",                            "bt3ds.message_opcode",
            FT_UINT8, BASE_HEX, VALS(message_opcode_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_association_notification,
            { "Association Notification",                  "bt3ds.association_notification",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_user_request_for_battery_level_display,
            { "User Request for Battery Level Display",    "bt3ds.user_request_for_battery_level_display",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_reserved,
            { "Reserved",                                  "bt3ds.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_battery_level,
            { "Battery Level",                             "bt3ds.battery_level",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "0-100% of current charge level of battery", HFILL }
        }
    };

    static gint *ett[] = {
        &ett_bt3ds
    };

    proto_bt3ds = proto_register_protocol("Bluetooth 3DS Profile", "BT 3DS", "bt3ds");
    b3ds_handle = new_register_dissector("bt3ds", dissect_bt3ds, proto_bt3ds);

    proto_register_field_array(proto_bt3ds, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_bt3ds = expert_register_protocol(proto_bt3ds);
    expert_register_field_array(expert_bt3ds, ei, array_length(ei));

    module = prefs_register_protocol(proto_bt3ds, NULL);
    prefs_register_static_text_preference(module, "3ds.version",
            "Bluetooth Profile 3DS version: 1.0",
            "Version of profile supported by this dissector.");

}

void
proto_reg_handoff_bt3ds(void)
{
    dissector_add_uint("btl2cap.service", BTSDP_3D_SYNCHRONIZATION_UUID, b3ds_handle);
    dissector_add_uint("btl2cap.service", BTSDP_3D_DISPLAY_UUID, b3ds_handle);
    dissector_add_uint("btl2cap.service", BTSDP_3D_GLASSES_UUID, b3ds_handle);

    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_3DS, b3ds_handle);
    dissector_add_for_decode_as("btl2cap.cid", b3ds_handle);
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
