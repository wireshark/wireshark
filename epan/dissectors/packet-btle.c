/* packet-btle.c
 * Routines for Bluetooth Low Energy Link Layer dissection
 * https://www.bluetooth.org/Technical/Specifications/adopted.htm
 *
 * Copyright 2013, Mike Ryan, mikeryan /at/ isecpartners /dot/ com
 * Copyright 2013, Michal Labedzki for Tieto Corporation
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
#include <epan/prefs.h>
#include <epan/expert.h>
#include <wiretap/wtap.h>

#include "packet-bluetooth-hci.h"
#include "packet-bthci_acl.h"

static int proto_btle = -1;

static int hf_access_address = -1;
static int hf_crc = -1;
static int hf_advertising_header = -1;
static int hf_advertising_header_pdu_type = -1;
static int hf_advertising_header_rfu_1 = -1;
static int hf_advertising_header_randomized_tx = -1;
static int hf_advertising_header_randomized_rx = -1;
static int hf_advertising_header_length = -1;
static int hf_advertising_header_rfu_2 = -1;
static int hf_advertising_address = -1;
static int hf_initiator_addresss = -1;
static int hf_scanning_address = -1;
static int hf_scan_response_data = -1;
static int hf_link_layer_data = -1;
static int hf_link_layer_data_access_address = -1;
static int hf_link_layer_data_crc_init = -1;
static int hf_link_layer_data_window_size = -1;
static int hf_link_layer_data_window_offset = -1;
static int hf_link_layer_data_interval = -1;
static int hf_link_layer_data_latency = -1;
static int hf_link_layer_data_timeout = -1;
static int hf_link_layer_data_channel_map = -1;
static int hf_link_layer_data_hop = -1;
static int hf_link_layer_data_sleep_clock_accuracy = -1;
static int hf_data_header = -1;
static int hf_data_header_length = -1;
static int hf_data_header_rfu = -1;
static int hf_data_header_llid = -1;
static int hf_data_header_more_data = -1;
static int hf_data_header_sequence_number = -1;
static int hf_data_header_next_expected_sequence_number = -1;
static int hf_control_opcode = -1;
static int hf_l2cap_fragment = -1;
static int hf_control_data = -1;

static gint ett_btle = -1;
static gint ett_advertising_header = -1;
static gint ett_link_layer_data = -1;
static gint ett_data_header = -1;

static expert_field ei_unknown_data = EI_INIT;

static dissector_handle_t btle_handle;
static dissector_handle_t btcommon_ad_handle;
static dissector_handle_t btl2cap_handle;

static const value_string pdu_type_vals[] = {
    { 0x00, "ADV_IND" },
    { 0x01, "ADV_DIRECT_IND" },
    { 0x02, "ADV_NONCONN_IND" },
    { 0x03, "SCAN_REQ" },
    { 0x04, "SCAN_RSP" },
    { 0x05, "CONNECT_REQ" },
    { 0x06, "ADV_SCAN_IND" },
    { 0, NULL }
};
static value_string_ext pdu_type_vals_ext = VALUE_STRING_EXT_INIT(pdu_type_vals);

static const value_string sleep_clock_accuracy_vals[] = {
    { 0x00, "251 ppm to 500 ppm" },
    { 0x01, "151 ppm to 250 ppm" },
    { 0x02, "101 ppm to 150 ppm" },
    { 0x03, "76 ppm to 100 ppm" },
    { 0x04, "51 ppm to 75 ppm" },
    { 0x05, "31 ppm to 50 ppm" },
    { 0x06, "21 ppm to 30 ppm" },
    { 0x07, "0 ppm to 20 ppm" },
    { 0, NULL }
};
static value_string_ext sleep_clock_accuracy_vals_ext = VALUE_STRING_EXT_INIT(sleep_clock_accuracy_vals);

static const value_string llid_codes_vals[] = {
    { 0x01, "Continuation fragment of an L2CAP message, or an Empty PDU" },
    { 0x02, "Start of an L2CAP message or a complete L2CAP message with no fragmentation" },
    { 0x03, "Control PDU" },
    { 0, NULL }
};
static value_string_ext llid_codes_vals_ext = VALUE_STRING_EXT_INIT(llid_codes_vals);

static const value_string control_opcode_vals[] = {
    { 0x00, "LL_CONNECTION_UPDATE_REQ" },
    { 0x01, "LL_CHANNEL_MAP_REQ" },
    { 0x02, "LL_TERMINATE_IND" },
    { 0x03, "LL_ENC_REQ" },
    { 0x04, "LL_ENC_RSP" },
    { 0x05, "LL_START_ENC_REQ" },
    { 0x06, "LL_START_ENC_RSP" },
    { 0x07, "LL_UNKNOWN_RSP" },
    { 0x08, "LL_FEATURE_REQ" },
    { 0x09, "LL_FEATURE_RSP" },
    { 0x0A, "LL_PAUSE_ENC_REQ" },
    { 0x0B, "LL_PAUSE_ENC_RSP" },
    { 0x0C, "LL_VERSION_IND" },
    { 0x0D, "LL_REJECT_IND" },
    { 0x0E, "LL_SLAVE_FEATURE_REQ" },
    { 0x0F, "LL_CONNECTION_PARAM_REQ" },
    { 0x10, "LL_CONNECTION_PARAM_RSP" },
    { 0x11, "LL_REJECT_IND_EXT" },
    { 0x12, "LL_PING_REQ" },
    { 0x13, "LL_PING_RSP" },
    { 0, NULL }
};
static value_string_ext control_opcode_vals_ext = VALUE_STRING_EXT_INIT(control_opcode_vals);

void proto_register_btle(void);
void proto_reg_handoff_btle(void);


gint
dissect_bd_addr(gint hf_bd_addr, proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint8 bd_addr[6];

    bd_addr[5] = tvb_get_guint8(tvb, offset);
    bd_addr[4] = tvb_get_guint8(tvb, offset + 1);
    bd_addr[3] = tvb_get_guint8(tvb, offset + 2);
    bd_addr[2] = tvb_get_guint8(tvb, offset + 3);
    bd_addr[1] = tvb_get_guint8(tvb, offset + 4);
    bd_addr[0] = tvb_get_guint8(tvb, offset + 5);

    proto_tree_add_ether(tree, hf_bd_addr, tvb, offset, 6, bd_addr);
    offset += 6;

    return offset;
}

static gint
dissect_btle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *btle_item;
    proto_tree  *btle_tree;
    gint         offset = 0;
    guint32      access_address;
    guint8       length;
    tvbuff_t    *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LE LL");

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

    btle_item = proto_tree_add_item(tree, proto_btle, tvb, offset, -1, ENC_NA);
    btle_tree = proto_item_add_subtree(btle_item, ett_btle);

    proto_tree_add_item(btle_tree, hf_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    access_address = tvb_get_letohl(tvb, offset);
    offset += 4;

    if (access_address == ACCESS_ADDRESS_ADVERTISING) {
        proto_item  *advertising_header_item;
        proto_tree  *advertising_header_tree;
        proto_item  *link_layer_data_item;
        proto_tree  *link_layer_data_tree;
        guint8       pdu_type;

        advertising_header_item = proto_tree_add_item(btle_tree, hf_advertising_header, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        advertising_header_tree = proto_item_add_subtree(advertising_header_item, ett_advertising_header);

        proto_tree_add_item(advertising_header_tree, hf_advertising_header_rfu_1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(advertising_header_tree, hf_advertising_header_randomized_tx, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(advertising_header_tree, hf_advertising_header_randomized_rx, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(advertising_header_tree, hf_advertising_header_pdu_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        pdu_type = tvb_get_guint8(tvb, offset) & 0x0F;
        proto_item_append_text(advertising_header_item, " (PDU Type: %s, TxAdd=%s, RxAdd=%s)",
                val_to_str_ext_const(pdu_type, &pdu_type_vals_ext, "Unknown"),
                (tvb_get_guint8(tvb, offset) & 0x20) ? "true" : "false",
                (tvb_get_guint8(tvb, offset) & 0x10) ? "true" : "false");
        offset += 1;

        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(pdu_type, &pdu_type_vals_ext, "Unknown"));

        proto_tree_add_item(advertising_header_tree, hf_advertising_header_rfu_2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(advertising_header_tree, hf_advertising_header_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        switch (pdu_type) {
        case 0x00: /* ADV_IND */
        case 0x02: /* ADV_NONCONN_IND */
        case 0x06: /* ADV_SCAN_IND */
            offset = dissect_bd_addr(hf_advertising_address, btle_tree, tvb, offset);

            next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset) - 3, tvb_length_remaining(tvb, offset) - 3);
            call_dissector(btcommon_ad_handle, next_tvb, pinfo, btle_tree);

            offset += tvb_length_remaining(tvb, offset) - 3;

            break;
        case 0x01: /* ADV_DIRECT_IND */
            offset = dissect_bd_addr(hf_advertising_address, btle_tree, tvb, offset);
            offset = dissect_bd_addr(hf_initiator_addresss, btle_tree, tvb, offset);

            break;
        case 0x03: /* SCAN_REQ */
            offset = dissect_bd_addr(hf_scanning_address, btle_tree, tvb, offset);
            offset = dissect_bd_addr(hf_advertising_address, btle_tree, tvb, offset);

            break;
        case 0x04: /* SCAN_RSP */
            offset = dissect_bd_addr(hf_advertising_address, btle_tree, tvb, offset);

            proto_tree_add_item(btle_tree, hf_scan_response_data, tvb, offset, tvb_length_remaining(tvb, offset) - 3, ENC_NA);
            offset += tvb_length_remaining(tvb, offset) - 3;

            break;
        case 0x05: /* CONNECT_REQ */
            offset = dissect_bd_addr(hf_initiator_addresss, btle_tree, tvb, offset);
            offset = dissect_bd_addr(hf_advertising_address, btle_tree, tvb, offset);

            link_layer_data_item = proto_tree_add_item(btle_tree, hf_link_layer_data, tvb, offset, 22, ENC_NA);
            link_layer_data_tree = proto_item_add_subtree(link_layer_data_item, ett_link_layer_data);

            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_crc_init, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;

            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_window_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_window_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_channel_map, tvb, offset, 5, ENC_NA);
            offset += 5;

            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_hop, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_sleep_clock_accuracy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            break;
        default:
            if (tvb_length_remaining(tvb, offset) > 3) {
                proto_tree_add_expert(btle_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_length_remaining(tvb, offset) - 3);
                offset += tvb_length_remaining(tvb, offset) - 3;
            }
        }
    } else { /* data PDU */
        proto_item  *data_header_item;
        proto_tree  *data_header_tree;
        guint8       llid;
        guint8       control_opcode;

        data_header_item = proto_tree_add_item(btle_tree, hf_data_header, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        data_header_tree = proto_item_add_subtree(data_header_item, ett_data_header);

        proto_tree_add_item(data_header_tree, hf_data_header_rfu, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(data_header_tree, hf_data_header_more_data, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(data_header_tree, hf_data_header_sequence_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(data_header_tree, hf_data_header_next_expected_sequence_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(data_header_tree, hf_data_header_llid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        llid = tvb_get_guint8(tvb, offset) & 0x03;
        offset += 1;

        proto_tree_add_item(data_header_tree, hf_data_header_rfu, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(data_header_tree, hf_data_header_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        length = tvb_get_guint8(tvb, offset) & 0x1f;
        offset += 1;

        switch (llid) {
        case 0x01: /* Continuation fragment of an L2CAP message, or an Empty PDU */
/* TODO: Try reassemble cases 0x01 and 0x02 */
            if (length > 0) {
                col_append_str(pinfo->cinfo, COL_INFO, "L2CAP Fragment");
                proto_tree_add_item(btle_tree, hf_l2cap_fragment, tvb, offset, length, ENC_NA);
                offset += length;
            } else {
                col_append_str(pinfo->cinfo, COL_INFO, "Empty PDU");
            }

            break;
        case 0x02: /* Start of an L2CAP message or a complete L2CAP message with no fragmentation */
            if (length > 0) {
                if (tvb_get_letohs(tvb, offset) > length) {
/* TODO: Try reassemble cases 0x01 and 0x02 */
                    col_append_str(pinfo->cinfo, COL_INFO, "L2CAP Fragment");
                    proto_tree_add_item(btle_tree, hf_l2cap_fragment, tvb, offset, length, ENC_NA);
                    offset += length;
                } else {
                    bthci_acl_data_t  *acl_data;

                    col_append_str(pinfo->cinfo, COL_INFO, "L2CAP Data");
/* TODO: Temporary solution while chandle source/bd_addrs is unknown  */
                    acl_data = wmem_new(wmem_packet_scope(), bthci_acl_data_t);
                    acl_data->interface_id = HCI_INTERFACE_USB;
                    acl_data->adapter_id   = 0;
                    acl_data->chandle      = 0;
                    acl_data->remote_bd_addr_oui = 0;
                    acl_data->remote_bd_addr_id  = 0;

                    next_tvb = tvb_new_subset(tvb, offset, length, length);
                    call_dissector_with_data(btl2cap_handle, next_tvb, pinfo, btle_tree, acl_data);
                    offset += length;
                }
            }
            break;
        case 0x03: /* Control PDU */
            proto_tree_add_item(tree, hf_control_opcode, tvb, offset, 1, ENC_NA);
            control_opcode = tvb_get_guint8(tvb, offset);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, "Control Opcode: %s",
                    val_to_str_ext_const(control_opcode, &control_opcode_vals_ext, "Unknown"));

            switch (control_opcode) {
            case 0x05: /* LL_START_ENC_REQ */
            case 0x06: /* LL_START_ENC_RSP */
            case 0x0A: /* LL_PAUSE_ENC_REQ */
            case 0x0B: /* LL_PAUSE_ENC_RSP */
            case 0x12: /* LL_PING_REQ */
            case 0x13: /* LL_PING_RSP */
                if (tvb_length_remaining(tvb, offset) > 3) {
                    proto_tree_add_expert(btle_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_length_remaining(tvb, offset) - 3);
                    offset += tvb_length_remaining(tvb, offset) - 3;
                }

                break;
            case 0x00: /* LL_CONNECTION_UPDATE_REQ */
            case 0x01: /* LL_CHANNEL_MAP_REQ */
            case 0x02: /* LL_TERMINATE_IND */
            case 0x03: /* LL_ENC_REQ */
            case 0x04: /* LL_ENC_RSP */
            case 0x07: /* LL_UNKNOWN_RSP */
            case 0x08: /* LL_FEATURE_REQ */
            case 0x09: /* LL_FEATURE_RSP */
            case 0x0C: /* LL_VERSION_IND */
            case 0x0D: /* LL_REJECT_IND */
            case 0x0E: /* LL_SLAVE_FEATURE_REQ */
            case 0x0F: /* LL_CONNECTION_PARAM_REQ */
            case 0x10: /* LL_CONNECTION_PARAM_RSP */
            case 0x11: /* LL_REJECT_IND_EXT */
/* TODO: Implement above cases */
                if (tvb_length_remaining(tvb, offset) > 3) {
                    proto_tree_add_item(tree, hf_control_data, tvb, offset, tvb_length_remaining(tvb, offset) - 3, ENC_NA);
                    offset += tvb_length_remaining(tvb, offset) - 3;
                }

                break;
            default:
                if (tvb_length_remaining(tvb, offset) > 3) {
                    proto_tree_add_expert(btle_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_length_remaining(tvb, offset) - 3);
                    offset += tvb_length_remaining(tvb, offset) - 3;
                }
            }

            break;
        default:
            if (tvb_length_remaining(tvb, offset) > 3) {
                proto_tree_add_expert(btle_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_length_remaining(tvb, offset) - 3);
                offset += tvb_length_remaining(tvb, offset) - 3;
            }
        }
    }

    proto_tree_add_item(btle_tree, hf_crc, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    return offset;
}

void
proto_register_btle(void)
{
    module_t         *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_access_address,
            { "Access Address",                  "btle.access_address",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_advertising_header,
            { "Packet Header",                   "btle.advertising_header",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_advertising_header_pdu_type,
            { "PDU Type",                        "btle.advertising_header.pdu_type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &pdu_type_vals_ext, 0x0F,
            NULL, HFILL }
        },
        { &hf_advertising_header_rfu_1,
            { "RFU",                             "btle.advertising_header.rfu.1",
            FT_UINT8, BASE_DEC, NULL, 0xC0,
            NULL, HFILL }
        },
        { &hf_advertising_header_randomized_tx,
            { "Randomized Tx Address",           "btle.advertising_header.randomized_tx",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_advertising_header_randomized_rx,
            { "Randomized Rx Address",           "btle.advertising_header.randomized_rx",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_advertising_header_length,
            { "Length",                          "btle.advertising_header.length",
            FT_UINT8, BASE_DEC, NULL, 0x03f,
            NULL, HFILL }
        },
        { &hf_advertising_header_rfu_2,
            { "RFU",                             "btle.advertising_header.rfu.2",
            FT_UINT8, BASE_DEC, NULL, 0xC0,
            NULL, HFILL }
        },
        { &hf_advertising_address,
            { "Advertising Address",             "btle.advertising_address",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_initiator_addresss,
            { "Initator Address",                "btle.initiator_address",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scanning_address,
            { "Scanning Address",                "btle.scanning_address",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scan_response_data,
            { "Scan Response Data",              "btle.scan_responce_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data,
            { "Link Layer Data",                 "btle.link_layer_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_access_address,
            { "Access Address",                  "btle.link_layer_data.access_address",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_crc_init,
            { "CRC Init",                        "btle.link_layer_data.crc_init",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_window_size,
            { "Window Size",                     "btle.link_layer_data.window_size",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_window_offset,
            { "Window Offset",                   "btle.link_layer_data.window_offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_interval,
            { "Interval",                        "btle.link_layer_data.interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_latency,
            { "Latency",                         "btle.link_layer_data.latency",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_timeout,
            { "Timeout",                         "btle.link_layer_data.timeout",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_channel_map,
            { "Channel Map",                     "btle.link_layer_data.channel_map",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_hop,
            { "Hop",                             "btle.link_layer_data.hop",
            FT_UINT8, BASE_DEC, NULL, 0xf8,
            NULL, HFILL }
        },
        { &hf_link_layer_data_sleep_clock_accuracy,
            { "Sleep Clock Accuracy",            "btle.link_layer_data.sleep_clock_accuracy",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &sleep_clock_accuracy_vals_ext, 0x07,
            NULL, HFILL }
        },
        { &hf_data_header,
            { "Data Header",                     "btle.data_header",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_data_header_llid,
            { "LLID",                            "btle.data_header.llid",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &llid_codes_vals_ext, 0x03,
            NULL, HFILL }
        },
        { &hf_data_header_next_expected_sequence_number,
            { "Next Expected Sequence Number",   "btle.data_header.next_expected_sequence_number",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_data_header_sequence_number,
            { "Sequence Number",                 "btle.data_header.sequence_number",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_data_header_more_data,
            { "More Data",                       "btle.data_header.more_data",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_data_header_length,
            { "Length",                          "btle.data_header.length",
            FT_UINT8, BASE_DEC, NULL, 0x1F,
            NULL, HFILL }
        },
        { &hf_data_header_rfu,
            { "RFU",                             "btle.data_header.rfu",
            FT_UINT8, BASE_DEC, NULL, 0xE0,
            NULL, HFILL }
        },
        { &hf_control_opcode,
            { "Control Opcode",                  "btle.control_opcode",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &control_opcode_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_l2cap_fragment,
            { "L2CAP Fragment",                  "btle.l2cap_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_data,
            { "Control Data",                    "btle.control_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_crc,
            { "CRC",                             "btle.crc",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_unknown_data, { "btle.unknown_data", PI_PROTOCOL, PI_NOTE, "Unknown data", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_btle,
        &ett_advertising_header,
        &ett_link_layer_data,
        &ett_data_header
    };

    proto_btle = proto_register_protocol("Bluetooth Low Energy Link Layer",
            "BT LE LL", "btle");
    btle_handle = new_register_dissector("btle", dissect_btle, proto_btle);

    proto_register_field_array(proto_btle, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module = expert_register_protocol(proto_btle);
    expert_register_field_array(expert_module, ei, array_length(ei));

    module = prefs_register_protocol(proto_btle, NULL);
    prefs_register_static_text_preference(module, "version",
            "Bluetooth LE LL version: 4.1 (Core)",
            "Version of protocol supported by this dissector.");
}

void
proto_reg_handoff_btle(void)
{
    btcommon_ad_handle = find_dissector("btcommon.eir_ad.ad");
    btl2cap_handle = find_dissector("btl2cap");

    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LE_LL, btle_handle);
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
