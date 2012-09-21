/* packet-btsap.c
 * Routines for Bluetooth BNEP dissection
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
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
#include <epan/etypes.h>
#include <epan/expert.h>

#include "packet-btl2cap.h"
#include "packet-btsdp.h"

#define BNEP_TYPE_GENERAL_ETHERNET                                          0x00
#define BNEP_TYPE_CONTROL                                                   0x01
#define BNEP_TYPE_COMPRESSED_ETHERNET                                       0x02
#define BNEP_TYPE_COMPRESSED_ETHERNET_SOURCE_ONLY                           0x03
#define BNEP_TYPE_COMPRESSED_ETHERNET_DESTINATION_ONLY                      0x04
#define RESERVED_802                                                        0x7F

static int proto_btbnep                                                    = -1;
static int hf_btbnep_bnep_type                                             = -1;
static int hf_btbnep_extension_flag                                        = -1;
static int hf_btbnep_extension_type                                        = -1;
static int hf_btbnep_extension_length                                      = -1;
static int hf_btbnep_dst                                                   = -1;
static int hf_btbnep_src                                                   = -1;
static int hf_btbnep_type                                                  = -1;
static int hf_btbnep_addr                                                  = -1;
static int hf_btbnep_lg                                                    = -1;
static int hf_btbnep_ig                                                    = -1;
static int hf_btbnep_control_type                                          = -1;
static int hf_btbnep_unknown_control_type                                  = -1;
static int hf_btbnep_uuid_size                                             = -1;
static int hf_btbnep_destination_service_uuid                              = -1;
static int hf_btbnep_source_service_uuid                                   = -1;
static int hf_btbnep_setup_connection_response_message                     = -1;
static int hf_btbnep_filter_net_type_response_message                      = -1;
static int hf_btbnep_filter_multi_addr_response_message                    = -1;
static int hf_btbnep_list_length                                           = -1;
static int hf_btbnep_network_type_start                                    = -1;
static int hf_btbnep_network_type_end                                      = -1;
static int hf_btbnep_multicast_address_start                               = -1;
static int hf_btbnep_multicast_address_end                                 = -1;

static int hf_btbnep_data                                                  = -1;

static gint ett_btbnep                                                     = -1;
static gint ett_addr                                                       = -1;

static gboolean top_dissect                                                = TRUE;

static dissector_handle_t eth_handle;
static dissector_handle_t data_handle;

static const true_false_string ig_tfs = {
    "Group address (multicast/broadcast)",
    "Individual address (unicast)"
};

static const true_false_string lg_tfs = {
    "Locally administered address (this is NOT the factory default)",
    "Globally unique address (factory default)"
};

static const value_string bnep_type_vals[] = {
    { 0x00,   "General Ethernet" },
    { 0x01,   "Control" },
    { 0x02,   "Compressed Ethernet" },
    { 0x03,   "Compressed Ethernet Source Only" },
    { 0x04,   "Compressed Ethernet Destination Only" },
    { 0x7F,   "Reserved for 802.2 LLC Packets for IEEE 802.15.1 WG" },
    { 0, NULL }
};

static const value_string control_type_vals[] = {
    { 0x00,   "Command Not Understood" },
    { 0x01,   "Setup Connection Request" },
    { 0x02,   "Setup Connection Response" },
    { 0x03,   "Filter Net Type Set" },
    { 0x04,   "Filter Net Type Response" },
    { 0x05,   "Filter Multi Addr Set" },
    { 0x06,   "Filter Multi Addr Response" },
    { 0, NULL }
};

static const value_string extension_type_vals[] = {
    { 0x00,   "Extension Control" },
    { 0, NULL }
};

static const value_string setup_connection_response_message_vals[] = {
    { 0x0000,   "Operation Successful" },
    { 0x0001,   "Operation FAIL: Invalid Destination Service UUID" },
    { 0x0002,   "Operation FAIL: Invalid Source Service UUID" },
    { 0x0003,   "Operation FAIL: Invalid Service UUID Size" },
    { 0x0004,   "Operation FAIL: Connection Not Allowed" },
    { 0, NULL }
};

static const value_string filter_net_type_response_message_vals[] = {
    { 0x0000,   "Operation Successful" },
    { 0x0001,   "Unsupported Request" },
    { 0x0002,   "Operation FAIL: Invalid Networking Protocol Type Range" },
    { 0x0003,   "Operation FAIL: Too many filters" },
    { 0x0004,   "Operation FAIL: Unable to fulfill request due to security reasons" },
    { 0, NULL }
};

static const value_string filter_multi_addr_response_message_vals[] = {
    { 0x0000,   "Operation Successful" },
    { 0x0001,   "Unsupported Request" },
    { 0x0002,   "Operation FAIL: Invalid Multicast Address" },
    { 0x0003,   "Operation FAIL: Too many filters" },
    { 0x0004,   "Operation FAIL: Unable to fulfill request due to security reasons" },
    { 0, NULL }
};


static int
dissect_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item   *pitem = NULL;
    guint control_type;
    guint8 unknown_control_type;
    guint8 uuid_size;
    guint16 uuid_dst;
    guint16 uuid_src;
    guint16 response_message;
    guint list_length;
    guint i_item;

    proto_tree_add_item(tree, hf_btbnep_control_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    control_type = tvb_get_guint8(tvb, offset);
    offset += 1;

    col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str(control_type, control_type_vals,  "Unknown type"));

    switch(control_type) {
        case 0x00: /* Command Not Understood */
            proto_tree_add_item(tree, hf_btbnep_unknown_control_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            unknown_control_type = tvb_get_guint8(tvb, offset);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, " - Unknown(%s)", val_to_str(unknown_control_type, control_type_vals,  "Unknown type"));

            break;
        case 0x01: /* Setup Connection Request */
            proto_tree_add_item(tree, hf_btbnep_uuid_size, tvb, offset, 1, ENC_BIG_ENDIAN);
            uuid_size = tvb_get_guint8(tvb, offset);
            offset += 1;

            pitem = proto_tree_add_item(tree, hf_btbnep_destination_service_uuid, tvb, offset, uuid_size, ENC_BIG_ENDIAN);
            uuid_dst = tvb_get_ntohs(tvb, offset);
            proto_item_append_text(pitem, " (%s)", val_to_str_ext(uuid_dst, &vs_service_classes_ext,  "Unknown uuid"));
            offset += uuid_size;

            pitem = proto_tree_add_item(tree, hf_btbnep_source_service_uuid, tvb, offset, uuid_size, ENC_BIG_ENDIAN);
            uuid_src = tvb_get_ntohs(tvb, offset);
            proto_item_append_text(pitem, " (%s)", val_to_str_ext(uuid_src, &vs_service_classes_ext,  "Unknown uuid"));
            offset += uuid_size;

            col_append_fstr(pinfo->cinfo, COL_INFO, " - dst: <%s>, src: <%s>",
                    val_to_str_ext(uuid_dst, &vs_service_classes_ext,  "Unknown uuid"),
                    val_to_str_ext(uuid_src, &vs_service_classes_ext,  "Unknown uuid"));
            break;
        case 0x02: /* Setup Connection Response */
            proto_tree_add_item(tree, hf_btbnep_setup_connection_response_message, tvb, offset, 2, ENC_BIG_ENDIAN);
            response_message = tvb_get_ntohs(tvb, offset);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
                    val_to_str(response_message, setup_connection_response_message_vals,  "Unknown response message"));
            break;
        case 0x03: /* Filter Net Type Set */
            proto_tree_add_item(tree, hf_btbnep_list_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            list_length = tvb_get_ntohs(tvb, offset);
            offset += 2;

            for (i_item = 0; i_item < list_length; i_item += 4) {
                proto_tree_add_item(tree, hf_btbnep_network_type_start, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                proto_tree_add_item(tree, hf_btbnep_network_type_end, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            break;
        case 0x04: /* Filter Net Type Response */
            proto_tree_add_item(tree, hf_btbnep_filter_net_type_response_message, tvb, offset, 2, ENC_BIG_ENDIAN);
            response_message = tvb_get_ntohs(tvb, offset);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
                    val_to_str(response_message, filter_net_type_response_message_vals,  "Unknown response message"));
            break;
        case 0x05: /*Filter Multi Addr Set*/
            proto_tree_add_item(tree, hf_btbnep_list_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            list_length = tvb_get_ntohs(tvb, offset);
            offset += 2;

            for (i_item = 0; i_item < list_length; i_item += 12) {
                proto_tree_add_item(tree, hf_btbnep_multicast_address_start, tvb, offset, 6, ENC_BIG_ENDIAN);
                offset += 6;

                proto_tree_add_item(tree, hf_btbnep_multicast_address_end, tvb, offset, 6, ENC_BIG_ENDIAN);
                offset += 6;
            }
            break;
        case 0x06: /* Filter Multi Addr Response */
            proto_tree_add_item(tree, hf_btbnep_filter_multi_addr_response_message, tvb, offset, 2, ENC_BIG_ENDIAN);
            response_message = tvb_get_ntohs(tvb, offset);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
                    val_to_str(response_message, filter_multi_addr_response_message_vals,  "Unknown response message"));
            break;

    };

    return offset;
}

static int
dissect_extension(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    guint8 extension_flag;
    guint8 extension_type;
    guint16 extension_length;
    guint8 type;

    proto_tree_add_item(tree, hf_btbnep_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_btbnep_extension_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    type = tvb_get_guint8(tvb, offset);
    extension_flag = type & 0x01;
    extension_type = type >> 1;
    offset += 1;

    proto_tree_add_item(tree, hf_btbnep_extension_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    extension_length = tvb_get_ntohs(tvb, offset);
    offset += 2;

    if (extension_type == 0x00) {
        /* Extension Control */
        offset = dissect_control(tvb, pinfo, tree, offset);
    } else {
        offset += extension_length;
    }

    if (extension_flag) offset = dissect_extension(tvb, pinfo, tree, offset);

    return offset;
}

static void
dissect_btbnep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item   *pi;
    proto_tree   *btbnep_tree;
    int offset = 0;
    guint bnep_type;
    guint extension_flag;
    guint type = 0;
    proto_item   *addr_item;
    proto_tree   *addr_tree = NULL;
    const guint8 *src_addr;
    const guint8 *dst_addr;
    tvbuff_t     *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BNEP");
    col_clear(pinfo->cinfo, COL_INFO);

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_add_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_add_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    case P2P_DIR_UNKNOWN:
        col_clear(pinfo->cinfo, COL_INFO);
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
            pinfo->p2p_dir);
        break;
    }

    pi = proto_tree_add_item(tree, proto_btbnep, tvb, offset, -1, ENC_NA);
    btbnep_tree = proto_item_add_subtree(pi, ett_btbnep);

    proto_tree_add_item(btbnep_tree, hf_btbnep_extension_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(btbnep_tree, hf_btbnep_bnep_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    bnep_type = tvb_get_guint8(tvb, offset);
    extension_flag = bnep_type & 0x80;
    bnep_type = bnep_type & 0x7F;
    offset += 1;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(bnep_type, bnep_type_vals,  "Unknown type"));
    if (extension_flag)  col_append_fstr(pinfo->cinfo, COL_INFO, "+E");

    if (bnep_type == BNEP_TYPE_GENERAL_ETHERNET || bnep_type == BNEP_TYPE_COMPRESSED_ETHERNET_DESTINATION_ONLY) {
        dst_addr = tvb_get_ptr(tvb, offset, 6);
        SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dst_addr);
        SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dst_addr);

        addr_item = proto_tree_add_ether(btbnep_tree, hf_btbnep_dst, tvb, offset, 6, dst_addr);
        if (addr_item) addr_tree = proto_item_add_subtree(addr_item, ett_addr);
        proto_tree_add_ether(addr_tree, hf_btbnep_addr, tvb, offset, 6, dst_addr);
        proto_tree_add_item(addr_tree, hf_btbnep_lg, tvb, offset, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(addr_tree, hf_btbnep_ig, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 6;
    }

    if (bnep_type == BNEP_TYPE_GENERAL_ETHERNET || bnep_type == BNEP_TYPE_COMPRESSED_ETHERNET_SOURCE_ONLY) {
        src_addr = tvb_get_ptr(tvb, offset, 6);
        SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, src_addr);
        SET_ADDRESS(&pinfo->src, AT_ETHER, 6, src_addr);


        addr_item = proto_tree_add_ether(btbnep_tree, hf_btbnep_src, tvb, offset, 6, src_addr);
        if (addr_item) {
            addr_tree = proto_item_add_subtree(addr_item, ett_addr);
            if (tvb_get_guint8(tvb, offset) & 0x01) {
                expert_add_info_format(pinfo, addr_item, PI_PROTOCOL, PI_WARN,
                    "Source MAC must not be a group address: IEEE 802.3-2002, Section 3.2.3(b)");
            }
        }
        proto_tree_add_ether(addr_tree, hf_btbnep_addr, tvb, offset, 6, src_addr);
        proto_tree_add_item(addr_tree, hf_btbnep_lg, tvb, offset, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(addr_tree, hf_btbnep_ig, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 6;
    }

    if (bnep_type != BNEP_TYPE_CONTROL) {
        type = tvb_get_ntohs(tvb, offset);
        if (!top_dissect) {
               proto_tree_add_item(btbnep_tree, hf_btbnep_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	       col_append_fstr(pinfo->cinfo, COL_INFO, " - Type: %s", val_to_str(type, etype_vals, "unknown"));
        }
        offset += 2;
    } else {
        offset = dissect_control(tvb, pinfo, btbnep_tree, offset);
    }

    if (extension_flag) {
        offset = dissect_extension(tvb, pinfo, btbnep_tree, offset);
    }

    if (bnep_type != BNEP_TYPE_CONTROL) {
        /* dissect normal network */
       if (top_dissect) {
            ethertype(type, tvb, offset, pinfo, tree, btbnep_tree, hf_btbnep_type,
            0, 0);
       } else {
            next_tvb = tvb_new_subset(tvb, offset,
                tvb_length_remaining(tvb, offset),
                tvb_length_remaining(tvb, offset));
            call_dissector(data_handle, next_tvb, pinfo, tree);
       }
    }
}

void
proto_register_btbnep(void)
{
    module_t *module;

    static hf_register_info hf[] = {
        { &hf_btbnep_bnep_type,
            { "BNEP Type",                         "btbnep.bnep_type",
            FT_UINT8, BASE_HEX, VALS(bnep_type_vals), 0x7F,
            NULL, HFILL }
        },
        { &hf_btbnep_extension_flag,
            { "Extension Flag",                    "btbnep.extension_flag",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btbnep_control_type,
            { "Control Type",                      "btbnep.control_type",
            FT_UINT8, BASE_HEX, VALS(control_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_extension_type,
            { "Extension Type",                    "btbnep.extension_type",
            FT_UINT8, BASE_HEX, VALS(extension_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_extension_length,
            { "Extension Length",                  "btbnep.extension_length",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_unknown_control_type,
            { "Unknown Control Type",              "btbnep.uknown_control_type",
            FT_UINT8, BASE_HEX, VALS(control_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_uuid_size,
            { "UIDD Size",                         "btbnep.uuid_size",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_destination_service_uuid,
            { "Destination Service UUID",          "btbnep.destination_service_uuid",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_source_service_uuid,
            { "Source Service UUID",               "btbnep.source_service_uuid",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_setup_connection_response_message,
            { "Response Message",                  "btbnep.setup_connection_response_message",
            FT_UINT16, BASE_HEX, VALS(setup_connection_response_message_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_filter_net_type_response_message,
            { "Response Message",                  "btbnep.filter_net_type_response_message",
            FT_UINT16, BASE_HEX, VALS(filter_net_type_response_message_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_filter_multi_addr_response_message,
            { "Response Message",                  "btbnep.filter_multi_addr_response_message",
            FT_UINT16, BASE_HEX, VALS(filter_multi_addr_response_message_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_list_length,
            { "List Length",                       "btbnep.list_length",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* http://www.iana.org/assignments/ethernet-numbers */
        { &hf_btbnep_network_type_start,
            { "Network Protocol Type Range Start", "btbnep.network_type_start",
            FT_UINT16, BASE_HEX, VALS(etype_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_network_type_end,
            { "Network Protocol Type Range End",   "btbnep.network_type_end",
            FT_UINT16, BASE_HEX, VALS(etype_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_multicast_address_start,
            { "Multicast Address Start",           "btbnep.multicast_address_start",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_multicast_address_end,
            { "Multicast Address End",             "btbnep.multicast_address_end",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btbnep_dst,
            { "Destination",                       "btbnep.dst",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "Destination Hardware Address", HFILL }
        },
        { &hf_btbnep_src,
            { "Source",                            "btbnep.src",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "Source Hardware Address", HFILL }
        },
        { &hf_btbnep_type,
            { "Type",                              "btbnep.type",
            FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btbnep_addr,
            { "Address",                           "btbnep.addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "Source or Destination Hardware Address", HFILL }
        },
        { &hf_btbnep_lg,
            { "LG bit",                            "btbnep.lg",
            FT_BOOLEAN, 24, TFS(&lg_tfs), 0x020000,
            "Specifies if this is a locally administered or globally unique (IEEE assigned) address", HFILL }
        },
        { &hf_btbnep_ig,
            { "IG bit",                            "btbnep.ig",
            FT_BOOLEAN, 24, TFS(&ig_tfs), 0x010000,
            "Specifies if this is an individual (unicast) or group (broadcast/multicast) address", HFILL }
        },

        { &hf_btbnep_data,
            { "Data",                              "btbnep.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_btbnep,
        &ett_addr,
    };

    proto_btbnep = proto_register_protocol("Bluetooth BNEP Potocol", "BNEP", "btbnep");
    register_dissector("btbnep", dissect_btbnep, proto_btbnep);

    proto_register_field_array(proto_btbnep, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module = prefs_register_protocol(proto_btbnep, NULL);
    prefs_register_static_text_preference(module, "bnep.version",
            "Bluetooth Protocol BNEP version: 1.0",
            "Version of protocol supported by this dissector.");

    prefs_register_bool_preference(module, "bnep.top_dissect",
            "Dissecting the top protocols", "Dissecting the top protocols",
            &top_dissect);
}

void
proto_reg_handoff_btbnep(void)
{
    dissector_handle_t btbnep_handle;

    btbnep_handle = find_dissector("btbnep");
    eth_handle = find_dissector("eth");
    data_handle    = find_dissector("data");

    dissector_add_uint("btl2cap.service", BTSDP_PAN_GN_SERVICE_UUID, btbnep_handle);
    dissector_add_uint("btl2cap.service", BTSDP_PAN_NAP_SERVICE_UUID, btbnep_handle);
    dissector_add_uint("btl2cap.service", BTSDP_PAN_GN_SERVICE_UUID, btbnep_handle);

    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_BNEP, btbnep_handle);
    dissector_add_handle("btl2cap.cid", btbnep_handle);
}
