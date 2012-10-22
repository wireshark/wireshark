/* packet-btatt.c
 * Routines for Bluetooth Attribute Protocol dissection
 *
 * Copyright 2012, Allan M. Madsen <allan.m@madsen.dk>
 *
 * $Id$
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

/* Initialize the subtree pointers */
static gint ett_btatt = -1;
static gint ett_btatt_list = -1;

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

static const value_string uuid_vals[] = {
    /* Services - http://developer.bluetooth.org/gatt/services/Pages/ServicesHome.aspx */
    {0x1800, "Generic Access"},
    {0x1801, "Generic Attribute"},
    {0x1802, "Immediate Alert"},
    {0x1803, "Link Loss"},
    {0x1804, "Tx Power"},
    {0x1805, "Current Time Service"},
    {0x1806, "Reference Time Update Service"},
    {0x1807, "Next DST Change Service"},
    {0x1808, "Glucose"},
    {0x1809, "Health Thermometer"},
    {0x180a, "Device Information"},
    {0x180d, "Heart Rate"},
    {0x180e, "Phone Alert Status Service"},
    {0x180f, "Battery Service"},
    {0x1810, "Blood Pressure"},
    {0x1811, "Alert Notification Service"},
    {0x1812, "Human Interface Device"},
    {0x1813, "Scan Parameters"},
    {0x1814, "Running Speed and Cadence"},
    {0x1816, "Cycling Speed and Cadence"},
    /* Declarations - http://developer.bluetooth.org/gatt/declarations/Pages/DeclarationsHome.aspx */
    {0x2800, "GATT Primary Service Declaration"},
    {0x2801, "GATT Secondary Service Declaration"},
    {0x2802, "GATT Include Declaration"},
    {0x2803, "GATT Characteristic Declaration"},
    /* Descriptors - http://developer.bluetooth.org/gatt/descriptors/Pages/DescriptorsHomePage.aspx */
    {0x2900, "Characteristic Extended Properties"},
    {0x2901, "Characteristic User Description"},
    {0x2902, "Client Characteristic Configuration"},
    {0x2903, "Server Characteristic Configuration"},
    {0x2904, "Characteristic Presentation Format"},
    {0x2905, "Characteristic Aggregate Format"},
    {0x2906, "Valid Range"},
    {0x2907, "External Report Reference"},
    {0x2908, "Report Reference"},
    /* Characteristics - http://developer.bluetooth.org/gatt/characteristics/Pages/CharacteristicsHome.aspx */
    {0x2a00, "Device Name"},
    {0x2a01, "Appearance"},
    {0x2a02, "Peripheral Privacy Flag"},
    {0x2a03, "Reconnection Address"},
    {0x2a04, "Peripheral Preferred Connection Parameters"},
    {0x2a05, "Service Changed"},
    {0x2a06, "Alert Level"},
    {0x2a07, "Tx Power Level"},
    {0x2a08, "Date Time"},
    {0x2a09, "Day of Week"},
    {0x2a0a, "Day Date Time"},
    {0x2a0c, "Exact Time 256"},
    {0x2a0d, "DST Offset"},
    {0x2a0e, "Time Zone"},
    {0x2a0f, "Local Time Information"},
    {0x2a11, "Time with DST"},
    {0x2a12, "Time Accuracy"},
    {0x2a13, "Time Source"},
    {0x2a14, "Reference Time Information"},
    {0x2a16, "Time Update Control Point"},
    {0x2a17, "Time Update State"},
    {0x2a18, "Glucose Measurement"},
    {0x2a19, "Battery Level"},
    {0x2a1c, "Temperature Measurement"},
    {0x2a1d, "Temperature Type"},
    {0x2a1e, "Intermediate Temperature"},
    {0x2a21, "Measurement Interval"},
    {0x2a22, "Boot Keyboard Input Report"},
    {0x2a23, "System ID"},
    {0x2a24, "Model Number String"},
    {0x2a25, "Serial Number String"},
    {0x2a26, "Firmware Revision String"},
    {0x2a27, "Hardware Revision String"},
    {0x2a28, "Software Revision String"},
    {0x2a29, "Manufacturer Name String"},
    {0x2a2a, "IEEE 11073-20601 Reg. Cert. Data List"},
    {0x2a2b, "Current Time"},
    {0x2a31, "Scan Refresh"},
    {0x2a32, "Boot Keyboard Output Report"},
    {0x2a33, "Boot Mouse Input Report"},
    {0x2a34, "Glucose Measurement Context"},
    {0x2a35, "Blood Pressure Measurement"},
    {0x2a36, "Intermediate Cuff Pressure"},
    {0x2a37, "Heart Rate Measurement"},
    {0x2a38, "Body Sensor Location"},
    {0x2a39, "Heart Rate Control Point"},
    {0x2a3f, "Alert Status"},
    {0x2a40, "Ringer Control Point"},
    {0x2a41, "Ringer Setting"},
    {0x2a42, "Alert Category ID Bit Mask"},
    {0x2a43, "Alert Category ID"},
    {0x2a44, "Alert Notification Control Point"},
    {0x2a45, "Unread Alert Status"},
    {0x2a46, "New Alert"},
    {0x2a47, "Supported New Alert Category"},
    {0x2a48, "Supported Unread Alert Category"},
    {0x2a49, "Blood Pressure Feature"},
    {0x2a4a, "HID Information"},
    {0x2a4b, "Report Map"},
    {0x2a4c, "HID Control Point"},
    {0x2a4d, "Report"},
    {0x2a4e, "Protocol Mode"},
    {0x2a4f, "Scan Interval Window"},
    {0x2a50, "PnP ID"},
    {0x2a51, "Glucose Feature"},
    {0x2a52, "Record Access Control Point"},
    {0x2a53, "RSC Measurement"},
    {0x2a54, "RSC Feature"},
    {0x2a55, "SC Control Point"},
    {0x2a5b, "CSC Measurement"},
    {0x2a5c, "CSC Feature"},
    {0x2a5d, "Sensor Location"},
    {0x0, NULL}
};
static value_string_ext uuid_vals_ext = VALUE_STRING_EXT_INIT(uuid_vals);

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

static void
dissect_btatt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    proto_item *ti, *item;
    proto_tree *st, *ltree;
    guint8 opcode;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATT");
    
    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_add_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_add_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    case P2P_DIR_UNKNOWN:
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
            pinfo->p2p_dir);
        break;
    }

    if (tvb_length_remaining(tvb, 0) < 1)
        return;

    ti = proto_tree_add_item(tree, proto_btatt, tvb, 0, -1, ENC_NA);
    st = proto_item_add_subtree(ti, ett_btatt);

    item = proto_tree_add_item(st, hf_btatt_opcode, tvb, 0, 1, ENC_LITTLE_ENDIAN);
    opcode = tvb_get_guint8(tvb, 0);
    offset++;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(opcode, opcode_vals, "<unknown>"));

    switch (opcode) {
    case 0x01: /* Error Response */
        proto_tree_add_item(st, hf_btatt_req_opcode_in_error, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(st, hf_btatt_handle_in_error, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, " - %s, Handle: 0x%04x",
                        val_to_str(tvb_get_guint8(tvb, offset+2), error_vals, "<unknown>"),
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
                expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "Unknown format");
            }
        }
        break;

    case 0x06: /* Find By Type Value Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, Handles: 0x%04x..0x%04x",
                            val_to_str_ext_const(tvb_get_letohs(tvb, offset+4), &uuid_vals_ext, "<unknown>"),
                            tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));
        
        proto_tree_add_item(st, hf_btatt_starting_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(st, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(st, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        if( tvb_length_remaining(tvb, offset)  > 0)
            proto_tree_add_item(st, hf_btatt_value, tvb, offset, -1, ENC_NA);
        break;

    case 0x07: /* Find By Type Value Response */
        while( tvb_length_remaining(tvb, offset) > 0 ) {
            item = proto_tree_add_text(st, tvb, offset, 4,
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
                            val_to_str_ext_const(tvb_get_letohs(tvb, offset+4), &uuid_vals_ext, "<unknown>"),
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
                                            &uuid_vals_ext, "<unknown>"));
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
                    item = proto_tree_add_text(st, tvb, offset, length, "Attribute Data, Handle: 0x%04x",
                                                    tvb_get_letohs(tvb, offset));

                    ltree = proto_item_add_subtree(item, ett_btatt_list);
                    
                    proto_tree_add_item(ltree, hf_btatt_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(ltree, hf_btatt_value, tvb, offset, length-2, ENC_LITTLE_ENDIAN);
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
            expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN,
                                                    "Too few handles, should be 2 or more");
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
                    item = proto_tree_add_text(st, tvb, offset, length,
                                                    "Attribute Data, Handle: 0x%04x, Group End Handle: 0x%04x",
                                                    tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

                    ltree = proto_item_add_subtree(item, ett_btatt_list);
                
                    proto_tree_add_item(ltree, hf_btatt_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(ltree, hf_btatt_group_end_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(ltree, hf_btatt_value, tvb, offset, length-4, ENC_LITTLE_ENDIAN);
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
        break;

    case 0x18: /* Execute Write Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                        val_to_str(tvb_get_guint8(tvb, offset), flags_vals, "<unknown>"));
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
            FT_UINT16, BASE_HEX |BASE_EXT_STRING, &uuid_vals_ext, 0x0,          
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

    /* Register the protocol name and description */
    proto_btatt = proto_register_protocol("Bluetooth Attribute Protocol", "ATT", "btatt");

    register_dissector("btatt", dissect_btatt, proto_btatt);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_btatt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module = prefs_register_protocol(proto_btatt, NULL);
    prefs_register_static_text_preference(module, "att.version",
            "Bluetooth Protocol ATT version from Core 4.0",
            "Version of protocol supported by this dissector.");
}

void
proto_reg_handoff_btatt(void)
{
    dissector_handle_t btatt_handle;

    btatt_handle = find_dissector("btatt");
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
