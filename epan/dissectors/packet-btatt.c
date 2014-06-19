/* packet-btatt.c
 * Routines for Bluetooth Attribute Protocol dissection
 *
 * Copyright 2012, Allan M. Madsen <allan.m@madsen.dk>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include "packet-bluetooth-hci.h"
#include "packet-btl2cap.h"

/* Initialize the protocol and registered fields */
static int proto_btatt = -1;

static int hf_btatt_opcode = -1;
static int hf_btatt_handle = -1;
static int hf_btatt_starting_handle = -1;
static int hf_btatt_ending_handle = -1;
static int hf_btatt_group_end_handle = -1;
static int hf_btatt_value = -1;
static int hf_btatt_req_opcode_in_error = -1;
static int hf_btatt_handle_in_error = -1;
static int hf_btatt_error_code = -1;
static int hf_btatt_uuid16 = -1;
static int hf_btatt_uuid128 = -1;
static int hf_btatt_client_rx_mtu = -1;
static int hf_btatt_server_rx_mtu = -1;
static int hf_btatt_uuid_format = -1;
static int hf_btatt_length = -1;
static int hf_btatt_offset = -1;
static int hf_btatt_flags = -1;
static int hf_btatt_sign_counter = -1;
static int hf_btatt_signature = -1;
static int hf_btatt_attribute_data = -1;
static int hf_btatt_handles_info = -1;

/* Initialize the subtree pointers */
static gint ett_btatt = -1;
static gint ett_btatt_list = -1;

static expert_field ei_btatt_uuid_format_unknown = EI_INIT;
static expert_field ei_btatt_handle_too_few = EI_INIT;

static dissector_handle_t btatt_handle;

/* Opcodes */
static const value_string opcode_vals[] = {
    {0x01, "Error Response"},
    {0x02, "Exchange MTU Request"},
    {0x03, "Exchange MTU Response"},
    {0x04, "Find Information Request"},
    {0x05, "Find Information Response"},
    {0x06, "Find By Type Value Request"},
    {0x07, "Find By Type Value Response"},
    {0x08, "Read By Type Request"},
    {0x09, "Read By Type Response"},
    {0x0a, "Read Request"},
    {0x0b, "Read Response"},
    {0x0c, "Read Blob Request"},
    {0x0d, "Read Blob Response"},
    {0x0e, "Read Multiple Request"},
    {0x0f, "Read Multiple Response"},
    {0x10, "Read By Group Type Request"},
    {0x11, "Read By Group Type Response"},
    {0x12, "Write Request"},
    {0x13, "Write Response"},
    {0x16, "Prepare Write Request"},
    {0x17, "Prepare Write Response"},
    {0x18, "Execute Write Request"},
    {0x19, "Execute Write Response"},
    {0x1B, "Handle Value Notification"},
    {0x1D, "Handle Value Indication"},
    {0x1E, "Handle Value Confirmation"},
    {0x52, "Write Command"},
    {0xD2, "Signed Write Command"},
    {0x0, NULL}
};

/* Error codes */
static const value_string error_vals[] = {
    {0x01, "Invalid Handle"},
    {0x02, "Read Not Permitted"},
    {0x03, "Write Not Permitted"},
    {0x04, "Invalid PDU"},
    {0x05, "Insufficient Authentication"},
    {0x06, "Request Not Supported"},
    {0x07, "Invalid Offset"},
    {0x08, "Insufficient Authorization"},
    {0x09, "Prepare Queue Full"},
    {0x0a, "Attribute Not Found"},
    {0x0b, "Attribute Not Long"},
    {0x0c, "Insufficient Encryption Key Size"},
    {0x0d, "Invalid Attribute Value Length"},
    {0x0e, "Unlikely Error"},
    {0x0f, "Insufficient Encryption"},
    {0x10, "Unsupported Group Type"},
    {0x11, "Insufficient Resources"},
    {0x80, "Application Error"},
    {0xfd, "Improper Client Characteristic Configuration Descriptor"},
    {0xfe, "Procedure Already In Progress"},
    {0xff, "Out of Range"},
    {0x0, NULL}
};

static const value_string uuid_format_vals[] = {
    {0x01, "16-bit UUIDs"},
    {0x02, "128-bit UUIDs"},
    {0x0, NULL}
};

static const value_string flags_vals[] = {
    {0x00, "Cancel All"},
    {0x01, "Immediately Write All"},
    {0x0, NULL}
};

void proto_register_btatt(void);
void proto_reg_handoff_btatt(void);

static int
dissect_btatt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    proto_item *ti, *item;
    proto_tree *st, *ltree;
    guint8 opcode;

    if (tvb_length_remaining(tvb, 0) < 1)
        return 0;

    ti = proto_tree_add_item(tree, proto_btatt, tvb, 0, -1, ENC_NA);
    st = proto_item_add_subtree(ti, ett_btatt);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATT");

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

    item = proto_tree_add_item(st, hf_btatt_opcode, tvb, 0, 1, ENC_LITTLE_ENDIAN);
    opcode = tvb_get_guint8(tvb, 0);
    offset++;

    col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(opcode, opcode_vals, "<unknown>"));

    switch (opcode) {
    case 0x01: /* Error Response */
        proto_tree_add_item(st, hf_btatt_req_opcode_in_error, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(st, hf_btatt_handle_in_error, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, " - %s, Handle: 0x%04x",
                        val_to_str_const(tvb_get_guint8(tvb, offset+2), error_vals, "<unknown>"),
                        tvb_get_letohs(tvb, offset));
        offset += 2;
        proto_tree_add_item(st, hf_btatt_error_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;

    case 0x02: /* Exchange MTU Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Client Rx MTU: %u", tvb_get_letohs(tvb, offset));
        proto_tree_add_item(st, hf_btatt_client_rx_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;

    case 0x03: /* Exchange MTU Response */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Server Rx MTU: %u", tvb_get_letohs(tvb, offset));
        proto_tree_add_item(st, hf_btatt_server_rx_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;

    case 0x04: /* Find Information Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handles: 0x%04x..0x%04x",
                            tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));
        proto_tree_add_item(st, hf_btatt_starting_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(st, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;

    case 0x05: /* Find Information Response */
        {
            guint8 format = tvb_get_guint8(tvb, offset);

            item = proto_tree_add_item(st, hf_btatt_uuid_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            if( format == 1 ) {
                while( tvb_length_remaining(tvb, offset) > 0) {
                    proto_tree_add_item(st, hf_btatt_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(st, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
            }
            else if( format == 2 ) {
                while( tvb_length_remaining(tvb, offset) > 0) {
                    proto_tree_add_item(st, hf_btatt_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(st, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
                    offset += 16;
                }
            }
            else {
                expert_add_info(pinfo, item, &ei_btatt_uuid_format_unknown);
            }
        }
        break;

    case 0x06: /* Find By Type Value Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, Handles: 0x%04x..0x%04x",
                            val_to_str_ext_const(tvb_get_letohs(tvb, offset+4), &bt_sig_uuid_vals_ext, "<unknown>"),
                            tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

        proto_tree_add_item(st, hf_btatt_starting_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(st, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(st, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(st, hf_btatt_value, tvb, offset, -1, ENC_NA);
        offset = tvb_reported_length(tvb);
        break;

    case 0x07: /* Find By Type Value Response */
        while( tvb_length_remaining(tvb, offset) > 0 ) {
            item = proto_tree_add_none_format(st, hf_btatt_handles_info, tvb, offset, 4,
                                            "Handles Info, Handle: 0x%04x, Group End Handle: 0x%04x",
                                            tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

            ltree = proto_item_add_subtree(item, ett_btatt_list);

            proto_tree_add_item(ltree, hf_btatt_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(ltree, hf_btatt_group_end_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        break;

    case 0x08: /* Read By Type Request */
    case 0x10: /* Read By Group Type Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, Handles: 0x%04x..0x%04x",
                            val_to_str_ext_const(tvb_get_letohs(tvb, offset+4), &bt_sig_uuid_vals_ext, "<unknown>"),
                            tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

        proto_tree_add_item(st, hf_btatt_starting_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(st, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (tvb_length_remaining(tvb, offset) == 2) {
            proto_tree_add_item(st, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        else if (tvb_length_remaining(tvb, offset) == 16) {
            item = proto_tree_add_item(st, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
            proto_item_append_text(item, " (%s)", val_to_str_ext_const(tvb_get_letohs(tvb, offset),
                                            &bt_sig_uuid_vals_ext, "<unknown>"));
            offset += 16;
        }
        break;

    case 0x09: /* Read By Type Response */
        {
            guint8 length = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(st, hf_btatt_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            if(length > 0) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Attribute List Length: %u",
                                        tvb_length_remaining(tvb, offset)/length);

                while (tvb_length_remaining(tvb, offset) >= length)
                {
                    item = proto_tree_add_none_format(st, hf_btatt_attribute_data, tvb,
                                                    offset, length, "Attribute Data, Handle: 0x%04x",
                                                    tvb_get_letohs(tvb, offset));

                    ltree = proto_item_add_subtree(item, ett_btatt_list);

                    proto_tree_add_item(ltree, hf_btatt_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(ltree, hf_btatt_value, tvb, offset, length - 2, ENC_NA);
                    offset += (length-2);
                }
            }
        }
        break;

    case 0x0a: /* Read Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x", tvb_get_letohs(tvb, offset));
        proto_tree_add_item(st, hf_btatt_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;

    case 0x0b: /* Read Response */
    case 0x0d: /* Read Blob Response */
    case 0x0f: /* Multiple Read Response */
        proto_tree_add_item(st, hf_btatt_value, tvb, offset, -1, ENC_NA);
        offset = tvb_reported_length(tvb);
        break;

    case 0x0c: /* Read Blob Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x, Offset: %u",
                        tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));
        proto_tree_add_item(st, hf_btatt_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(st, hf_btatt_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;

    case 0x0e: /* Multiple Read Request */
        if(tvb_length_remaining(tvb, offset) < 4) {
            expert_add_info(pinfo, item, &ei_btatt_handle_too_few);
            break;
        }

        col_append_str(pinfo->cinfo, COL_INFO, ", Handles: ");
        while (tvb_length_remaining(tvb, offset) >= 2) {
            proto_tree_add_item(st, hf_btatt_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, "0x%04x ", tvb_get_letohs(tvb, offset));
            offset += 2;
        }
        break;

    case 0x11: /* Read By Group Type Response */
        {
            guint8 length = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(st, hf_btatt_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            if(length > 0) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Attribute List Length: %u", tvb_length_remaining(tvb, offset)/length);

                while (tvb_length_remaining(tvb, offset) >= length) {
                    item = proto_tree_add_none_format(st, hf_btatt_attribute_data, tvb, offset, length,
                                                    "Attribute Data, Handle: 0x%04x, Group End Handle: 0x%04x",
                                                    tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

                    ltree = proto_item_add_subtree(item, ett_btatt_list);

                    proto_tree_add_item(ltree, hf_btatt_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(ltree, hf_btatt_group_end_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(ltree, hf_btatt_value, tvb, offset, length - 4, ENC_NA);
                    offset += (length-4);
                }
            }
        }
        break;

    case 0x12: /* Write Request */
    case 0x52: /* Write Command */
    case 0x1b: /* Handle Value Notification */
    case 0x1d: /* Handle Value Indication */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x", tvb_get_letohs(tvb, offset));
        proto_tree_add_item(st, hf_btatt_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(st, hf_btatt_value, tvb, offset, -1, ENC_NA);
        offset = tvb_reported_length(tvb);
        break;

    case 0x16: /* Prepare Write Request */
    case 0x17: /* Prepare Write Response */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x, Offset: %u",
                        tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));
        proto_tree_add_item(st, hf_btatt_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(st, hf_btatt_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(st, hf_btatt_value, tvb, offset, -1, ENC_NA);
        offset = tvb_reported_length(tvb);
        break;

    case 0x18: /* Execute Write Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                        val_to_str_const(tvb_get_guint8(tvb, offset), flags_vals, "<unknown>"));
        proto_tree_add_item(st, hf_btatt_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;

    case 0xd2: /* Signed Write Command */
        {
            guint8 length;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x", tvb_get_letohs(tvb, offset));
            proto_tree_add_item(st, hf_btatt_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            length = tvb_length_remaining(tvb, offset);
            if (length > 12) {
                proto_tree_add_item(st, hf_btatt_value, tvb, offset, length-12, ENC_NA);
                offset+=length-12;
            }

            proto_tree_add_item(st, hf_btatt_sign_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(st, hf_btatt_signature, tvb, offset, 8, ENC_NA);
            offset+=8;
        break;
        }
    default:
        break;
    }
    return offset;
}

void
proto_register_btatt(void)
{
    module_t *module;

    static hf_register_info hf[] = {
        {&hf_btatt_opcode,
            {"Opcode", "btatt.opcode",
            FT_UINT8, BASE_HEX, VALS(opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_handles_info,
            {"Handles Info", "btatt.handles_info",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_attribute_data,
            {"Attribute Data", "btatt.attribute_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_handle,
            {"Handle", "btatt.handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_starting_handle,
            {"Starting Handle", "btatt.starting_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ending_handle,
            {"Ending Handle", "btatt.ending_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_group_end_handle,
            {"Group End Handle", "btatt.group_end_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_value,
            {"Value", "btatt.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_req_opcode_in_error,
            {"Request Opcode in Error", "btatt.req_opcode_in_error",
            FT_UINT8, BASE_HEX, VALS(opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_handle_in_error,
            {"Handle in Error", "btatt.handle_in_error",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uuid16,
            {"UUID", "btatt.uuid16",
            FT_UINT16, BASE_HEX |BASE_EXT_STRING, &bt_sig_uuid_vals_ext, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uuid128,
            {"UUID", "btatt.uuid128",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_client_rx_mtu,
            {"Client Rx MTU", "btatt.client_rx_mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_server_rx_mtu,
            {"Server Rx MTU", "btatt.server_rx_mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uuid_format,
            {"UUID Format", "btatt.uuid_format",
            FT_UINT8, BASE_HEX, VALS(uuid_format_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_length,
            {"Length", "btatt.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of Handle/Value Pair", HFILL}
        },
        {&hf_btatt_offset,
            {"Offset", "btatt.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_flags,
            {"Flags", "btatt.flags",
            FT_UINT8, BASE_HEX, VALS(flags_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_sign_counter,
            {"Sign Counter", "btatt.sign_counter",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_signature,
            {"Signature", "btatt.signature",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_btatt,
        &ett_btatt_list
    };

    static ei_register_info ei[] = {
        { &ei_btatt_uuid_format_unknown, { "btatt.uuid_format.unknown", PI_PROTOCOL, PI_WARN, "Unknown format", EXPFILL }},
        { &ei_btatt_handle_too_few, { "btatt.handle.too_few", PI_PROTOCOL, PI_WARN, "Too few handles, should be 2 or more", EXPFILL }},
    };

    expert_module_t* expert_btatt;

    /* Register the protocol name and description */
    proto_btatt = proto_register_protocol("Bluetooth Attribute Protocol", "BT ATT", "btatt");

    btatt_handle = new_register_dissector("btatt", dissect_btatt, proto_btatt);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_btatt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_btatt = expert_register_protocol(proto_btatt);
    expert_register_field_array(expert_btatt, ei, array_length(ei));

    module = prefs_register_protocol(proto_btatt, NULL);
    prefs_register_static_text_preference(module, "att.version",
            "Bluetooth Protocol ATT version from Core 4.0",
            "Version of protocol supported by this dissector.");
}

void
proto_reg_handoff_btatt(void)
{
    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_ATT, btatt_handle);
    dissector_add_uint("btl2cap.cid", BTL2CAP_FIXED_CID_ATT, btatt_handle);
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
