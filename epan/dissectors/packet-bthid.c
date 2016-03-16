/* packet-bthid.c
 * Routines for Bluetooth HID dissection
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
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

static int proto_bthid                                                     = -1;
static int hf_bthid_transaction_type                                       = -1;
static int hf_bthid_parameter_reserved                                     = -1;
static int hf_bthid_parameter_reserved_31                                  = -1;
static int hf_bthid_parameter_reserved_32                                  = -1;
static int hf_bthid_parameter_reserved_2                                   = -1;
static int hf_bthid_parameter_result_code                                  = -1;
static int hf_bthid_parameter_control_operation                            = -1;
static int hf_bthid_parameter_size                                         = -1;
static int hf_bthid_protocol                                               = -1;
static int hf_bthid_idle_rate                                              = -1;
static int hf_bthid_parameter_report_type                                  = -1;
static int hf_bthid_report_id                                              = -1;
static int hf_bthid_buffer_size                                            = -1;
static int hf_bthid_protocol_code                                          = -1;
static int hf_bthid_data                                                   = -1;

static gint ett_bthid             = -1;

static expert_field ei_bthid_parameter_control_operation_deprecated = EI_INIT;
static expert_field ei_bthid_transaction_type_deprecated = EI_INIT;

static dissector_handle_t bthid_handle;
static dissector_handle_t usb_hid_boot_keyboard_input_report_handle;
static dissector_handle_t usb_hid_boot_keyboard_output_report_handle;
static dissector_handle_t usb_hid_boot_mouse_input_report_handle;

static gboolean show_deprecated = FALSE;

static const value_string transaction_type_vals[] = {
    { 0x00,   "HANDSHAKE" },
    { 0x01,   "HID_CONTROL" },
    { 0x02,   "reserved" },
    { 0x03,   "reserved" },
    { 0x04,   "GET_REPORT" },
    { 0x05,   "SET_REPORT" },
    { 0x06,   "GET_PROTOCOL" },
    { 0x07,   "SET_PROTOCOL" },
    { 0x08,   "GET_IDLE" },
    { 0x09,   "SET_IDLE" },
    { 0x0A,   "DATA" },
    { 0x0B,   "DATC" },
    { 0x0C,   "reserved" },
    { 0x0D,   "reserved" },
    { 0x0E,   "reserved" },
    { 0x0F,   "reserved" },
    { 0, NULL }
};

static const value_string report_type_vals[] = {
    { 0x00,   "Other" },
    { 0x01,   "Input" },
    { 0x02,   "Output" },
    { 0x03,   "Feature" },
    { 0, NULL }
};

static const value_string result_code_vals[] = {
    { 0x00,   "Successful" },
    { 0x01,   "Not Ready" },
    { 0x02,   "Error, Invalid Report ID" },
    { 0x03,   "Error, Unsupported Request" },
    { 0x04,   "Error, Invalid Parameters" },
    { 0x0E,   "Error, Unknown " },
    { 0x0F,   "Error, Fatal " },
    { 0, NULL }
};

static const value_string control_operation_vals[] = {
    { 0x00,   "NOP" },
    { 0x01,   "Hard Reset" },
    { 0x02,   "Soft Reset" },
    { 0x03,   "Suspend" },
    { 0x04,   "Exit Suspend" },
    { 0x05,   "Virtual Cable Unplug" },
    { 0, NULL }
};

static const value_string size_vals[] = {
    { 0x00,   "Buffer equal to report size" },
    { 0x01,   "BufferSize field follows the Report ID" },
    { 0, NULL }
};

static const value_string protocol_vals[] = {
    { 0x00,   "Report" },
    { 0x01,   "Boot" },
    { 0, NULL }
};

static const value_string protocol_code_vals[] = {
    { 0x00,   "None" },
    { 0x01,   "Keyboard" },
    { 0x02,   "Mouse" },
    { 0, NULL }
};

void proto_register_bthid(void);
void proto_reg_handoff_bthid(void);

static gint
dissect_hid_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, guint report_type)
{
    unsigned int protocol_code;

    proto_tree_add_item(tree, hf_bthid_protocol_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    protocol_code = tvb_get_guint8(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_const(protocol_code, protocol_code_vals, "unknown type"));
    offset += 1;

    switch (protocol_code) {
        case 0x01: /* Keyboard */
            if (report_type == 0x02) { /* Output - LEDs */
                offset += call_dissector_with_data(usb_hid_boot_keyboard_output_report_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree, NULL);

                break;
            } else if (report_type != 0x01) {/* is not Input (Keys) */
                break;
            }

            offset += call_dissector_with_data(usb_hid_boot_keyboard_input_report_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree, NULL);

            break;
        case 0x02: /* Mouse */
            offset += call_dissector_with_data(usb_hid_boot_mouse_input_report_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree, NULL);

            break;
    }

    return offset;
}

static int
dissect_bthid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item   *ti;
    proto_tree   *bthid_tree;
    gint          offset = 0;
    guint         transaction_type;
    guint         parameter;
    guint         protocol;
    guint         idle_rate;
    guint8        control_operation;
    proto_item   *pitem;

    ti = proto_tree_add_item(tree, proto_bthid, tvb, offset, -1, ENC_NA);
    bthid_tree = proto_item_add_subtree(ti, ett_bthid);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HID");
    col_clear(pinfo->cinfo, COL_INFO);

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
            break;
    }

    pitem = proto_tree_add_item(bthid_tree, hf_bthid_transaction_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    transaction_type = tvb_get_guint8(tvb, offset);
    parameter = transaction_type & 0x0F;
    transaction_type = transaction_type >> 4;

    col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(transaction_type, transaction_type_vals, "Unknown TransactionType"));

    switch(transaction_type) {
        case 0x00: /* HANDSHAKE */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, " - Result Code: %s", val_to_str_const(parameter, result_code_vals, "reserved"));
            break;
        case 0x01: /* HID_CONTROL */
            pitem = proto_tree_add_item(bthid_tree, hf_bthid_parameter_control_operation, tvb, offset, 1, ENC_BIG_ENDIAN);
            control_operation = tvb_get_guint8(tvb, offset);
            col_append_fstr(pinfo->cinfo, COL_INFO, " - Control Operation: %s", val_to_str_const(parameter, control_operation_vals, "reserved"));
            if (control_operation < 3 && show_deprecated)
                expert_add_info(pinfo, pitem, &ei_bthid_parameter_control_operation_deprecated);
            offset += 1;
            break;
        case 0x04: /* GET_REPORT */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_size, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_reserved_2, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_report_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, " - Size: %s, Report Type: %s",
                            val_to_str_const(parameter >> 3 , size_vals, "reserved"),
                            val_to_str_const(parameter & 0x03, report_type_vals, "reserved"));

            /* XXX: This is workaround, this should come from SDP:
               "This field is required in Report Protocol Mode when any Report ID
               Global Items are declared in the report descriptor, and in
               Boot Protocol Mode. Otherwise the field does not exist."
            */
            if (((parameter >> 3) && tvb_reported_length_remaining(tvb, offset) >= 3) ||
                    (!(parameter >> 3) && tvb_reported_length_remaining(tvb, offset) >= 1)) {
                proto_tree_add_item(bthid_tree, hf_bthid_report_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }

            if (parameter >> 3) {
                proto_tree_add_item(bthid_tree, hf_bthid_buffer_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
            break;
        case 0x05: /* SET_REPORT */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_reserved_32, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_report_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, " - Report Type: %s",
                            val_to_str_const(parameter & 0x03, report_type_vals, "reserved"));

            /* playload */
            proto_tree_add_item(bthid_tree, hf_bthid_data, tvb, offset, -1, ENC_NA);
            offset += tvb_captured_length_remaining(tvb, offset);
            break;
        case 0x06: /* GET_PROTOCOL */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(bthid_tree, hf_bthid_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
            protocol = tvb_get_guint8(tvb, offset) & 0x01;
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, " - Protocol: %s",
                            val_to_str_const(protocol, protocol_vals, "reserved"));

            break;
        case 0x07: /* SET_PROTOCOL */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_reserved_31, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bthid_tree, hf_bthid_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, " - Protocol: %s",
                            val_to_str_const(parameter & 0x01, protocol_vals, "reserved"));
            break;
        case 0x08: /* GET_IDLE */
        case 0x09: /* SET_IDLE */
            if (show_deprecated)
                expert_add_info(pinfo, pitem, &ei_bthid_transaction_type_deprecated);

            proto_tree_add_item(bthid_tree, hf_bthid_parameter_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            pitem = proto_tree_add_item(bthid_tree, hf_bthid_idle_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
            idle_rate = tvb_get_guint8(tvb, offset);
            proto_item_append_text(pitem, " (%u.%03u ms)", idle_rate * 4 / 1000, idle_rate * 4 % 1000);
            col_append_fstr(pinfo->cinfo, COL_INFO, " - Idle Rate: %u.%03u ms", idle_rate*4/1000, idle_rate*4%1000);
            offset += 1;
            break;
        case 0x0B: /* DATC */
            if (show_deprecated)
                expert_add_info(pinfo, pitem, &ei_bthid_transaction_type_deprecated);
        case 0x0A: /* DATA */
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_reserved_32, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bthid_tree, hf_bthid_parameter_report_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_const(parameter, report_type_vals, "reserved"));

            /* playload */
            offset = dissect_hid_data(tvb, pinfo,  bthid_tree, offset, parameter & 0x03);
            break;
    }

    return offset;
}


void
proto_register_bthid(void)
{
    module_t *module;
    expert_module_t* expert_bthid;

    static hf_register_info hf[] = {
        { &hf_bthid_transaction_type,
            { "Transaction Type",                "bthid.transaction_type",
            FT_UINT8, BASE_HEX, VALS(transaction_type_vals), 0xF0,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_reserved,
            { "Parameter reserved",              "bthid.parameter.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_reserved_32,
            { "Parameter reserved",              "bthid.parameter.reserved_32",
            FT_UINT8, BASE_HEX, NULL, 0x0C,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_reserved_31,
            { "Parameter reserved",              "bthid.parameter.reserved_31",
            FT_UINT8, BASE_HEX, NULL, 0x0E,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_reserved_2,
            { "Parameter reserved",              "bthid.parameter.reserved_2",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_report_type,
            { "Report Type",                     "bthid.parameter.report_type",
            FT_UINT8, BASE_HEX, VALS(report_type_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_size,
            { "Size",                            "bthid.parameter.size",
            FT_UINT8, BASE_HEX, VALS(size_vals), 0x08,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_result_code,
            { "Result Code",                     "bthid.result_code",
            FT_UINT8, BASE_HEX, VALS(result_code_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_bthid_parameter_control_operation,
            { "Control Operation",               "bthid.control_operation",
            FT_UINT8, BASE_HEX, VALS(control_operation_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_bthid_protocol,
            { "Protocol",                        "bthid.protocol",
            FT_UINT8, BASE_HEX, VALS(protocol_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_bthid_idle_rate,
            { "Idle Rate",                       "bthid.idle_rate",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_report_id,
            { "Report Id",                       "bthid.report_id",
            FT_UINT8, BASE_HEX, VALS(protocol_code_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_buffer_size,
            { "Buffer Size",                     "bthid.buffer_size",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_protocol_code,
            { "Protocol Code",                   "bthid.data.protocol_code",
            FT_UINT8, BASE_HEX, VALS(protocol_code_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_bthid_data,
            { "Data",                            "bthid.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },

    };

    static gint *ett[] = {
        &ett_bthid
    };

    static ei_register_info ei[] = {
        { &ei_bthid_parameter_control_operation_deprecated, { "bthid.control_operation.deprecated", PI_PROTOCOL, PI_WARN, "This value of Control Operation is deprecated by HID 1.1", EXPFILL }},
        { &ei_bthid_transaction_type_deprecated, { "bthid.transaction_type.deprecated", PI_PROTOCOL, PI_WARN, "This Transaction Type is deprecated by HID 1.1", EXPFILL }},
    };

    proto_bthid = proto_register_protocol("Bluetooth HID Profile", "BT HID", "bthid");
    bthid_handle = register_dissector("bthid", dissect_bthid, proto_bthid);

    proto_register_field_array(proto_bthid, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_bthid = expert_register_protocol(proto_bthid);
    expert_register_field_array(expert_bthid, ei, array_length(ei));

    module = prefs_register_protocol(proto_bthid, NULL);
    prefs_register_static_text_preference(module, "hid.version",
            "Bluetooth Profile HID version: 1.1",
            "Version of profile supported by this dissector.");

    prefs_register_bool_preference(module, "hid.deprecated",
            "Show what is deprecated in HID 1.1",
            "Show what is deprecated in HID 1.1", &show_deprecated);
}


void
proto_reg_handoff_bthid(void)
{
    usb_hid_boot_keyboard_input_report_handle  = find_dissector_add_dependency("usbhid.boot_report.keyboard.input", proto_bthid);
    usb_hid_boot_keyboard_output_report_handle = find_dissector_add_dependency("usbhid.boot_report.keyboard.output", proto_bthid);
    usb_hid_boot_mouse_input_report_handle     = find_dissector_add_dependency("usbhid.boot_report.mouse.input", proto_bthid);

    dissector_add_string("bluetooth.uuid", "11", bthid_handle);
    dissector_add_string("bluetooth.uuid", "1124", bthid_handle);

    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_HID_CTRL, bthid_handle);
    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_HID_INTR, bthid_handle);
    dissector_add_for_decode_as("btl2cap.cid", bthid_handle);
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
