/* packet-usb-com.c
 * Routines for USB Communications and CDC Control dissection
 * Copyright 2013, Pascal Quantin <pascal.quantin@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-usb.h"

/* protocols and header fields */
static int proto_usb_com = -1;
static int hf_usb_com_descriptor_subtype = -1;
static int hf_usb_com_descriptor_cdc = -1;
static int hf_usb_com_descriptor_payload = -1;
static int hf_usb_com_control_subclass = -1;
static int hf_usb_com_capabilities = -1;
static int hf_usb_com_descriptor_acm_capabilities_reserved = -1;
static int hf_usb_com_descriptor_acm_capabilities_network_connection = -1;
static int hf_usb_com_descriptor_acm_capabilities_send_break = -1;
static int hf_usb_com_descriptor_acm_capabilities_line_and_state = -1;
static int hf_usb_com_descriptor_acm_capabilities_comm_features = -1;
static int hf_usb_com_control_interface = -1;
static int hf_usb_com_subordinate_interface = -1;
static int hf_usb_com_descriptor_cm_capabilities_reserved = -1;
static int hf_usb_com_descriptor_cm_capabilities_call_managment_over_data_class_interface = -1;
static int hf_usb_com_descriptor_cm_capabilities_call_managment = -1;
static int hf_usb_com_descriptor_cm_data_interface = -1;
static int hf_usb_com_control_payload = -1;

static gint ett_usb_com = -1;
static gint ett_usb_com_capabilities = -1;

static dissector_handle_t mbim_control_handle;
static dissector_handle_t mbim_descriptor_handle;
static dissector_handle_t mbim_bulk_handle;
static dissector_handle_t eth_withoutfcs_handle;

#define CS_INTERFACE 0x24
#define CS_ENDPOINT  0x25

static const value_string usb_com_descriptor_type_vals[] = {
    { CS_INTERFACE, "CS_INTERFACE"},
    { CS_ENDPOINT, "CS_ENDPOINT"},
    { 0, NULL}
};
static value_string_ext usb_com_descriptor_type_vals_ext = VALUE_STRING_EXT_INIT(usb_com_descriptor_type_vals);

static const value_string usb_com_descriptor_subtype_vals[] = {
    { 0x00, "Header Functional Descriptor"},
    { 0x01, "Call Management Functional Descriptor"},
    { 0x02, "Abstract Control Management Functional Descriptor"},
    { 0x03, "Direct Line Management Functional Descriptor"},
    { 0x04, "Telephone Ringer Functional Descriptor"},
    { 0x05, "Telephone Call and Line State Reporting Capabilities Functional Descriptor"},
    { 0x06, "Union Functional Descriptor"},
    { 0x07, "Country Selection Functional Descriptor"},
    { 0x08, "Telephone Operational Modes Functional Descriptor"},
    { 0x09, "USB Terminal Functional Descriptor"},
    { 0x0A, "Network Channel Terminal Descriptor"},
    { 0x0B, "Protocol Unit Functional Descriptor"},
    { 0x0C, "Extension Unit Functional Descriptor"},
    { 0x0D, "Multi-Channel Management Functional Descriptor"},
    { 0x0E, "CAPI Control Management Functional Descriptor"},
    { 0x0F, "Ethernet Networking Functional Descriptor"},
    { 0x10, "ATM Networking Functional Descriptor"},
    { 0x11, "Wireless Handset Control Model Functional Descriptor"},
    { 0x12, "Mobile Direct Line Model Functional Descriptor"},
    { 0x13, "MDLM Detail Functional Descriptor"},
    { 0x14, "Device Management Model Functional Descriptor"},
    { 0x15, "OBEX Functional Descriptor"},
    { 0x16, "Command Set Functional Descriptor"},
    { 0x17, "Command Set Detail Functional Descriptor"},
    { 0x18, "Telephone Control Model Functional Descriptor"},
    { 0x19, "OBEX Service Identifier Functional Descriptor"},
    { 0x1A, "NCM Functional Descriptor"},
    { 0x1B, "MBIM Functional Descriptor"},
    { 0x1C, "MBIM Extended Functional Descriptor"},
    { 0, NULL}
};
static value_string_ext usb_com_descriptor_subtype_vals_ext = VALUE_STRING_EXT_INIT(usb_com_descriptor_subtype_vals);

#define COM_SUBCLASS_RESERVED 0x00
#define COM_SUBCLASS_DLCM     0x01
#define COM_SUBCLASS_ACM      0x02
#define COM_SUBCLASS_TCM      0x03
#define COM_SUBCLASS_MCCM     0x04
#define COM_SUBCLASS_CCM      0x05
#define COM_SUBCLASS_ENCM     0x06
#define COM_SUBCLASS_ANCM     0x07
#define COM_SUBCLASS_WHCM     0x08
#define COM_SUBCLASS_DM       0x09
#define COM_SUBCLASS_MDLM     0x0a
#define COM_SUBCLASS_OBEX     0x0b
#define COM_SUBCLASS_EEM      0x0c
#define COM_SUBCLASS_NCM      0x0d
#define COM_SUBCLASS_MBIM     0x0e

static const value_string usb_com_subclass_vals[] = {
    {COM_SUBCLASS_RESERVED, "RESERVED"},
    {COM_SUBCLASS_DLCM, "Direct Line Control Model"},
    {COM_SUBCLASS_ACM, "Abstract Control Model"},
    {COM_SUBCLASS_TCM, "Telephone Control Model"},
    {COM_SUBCLASS_MCCM, "Multi-Channel Control Model"},
    {COM_SUBCLASS_CCM, "CAPI Control Model"},
    {COM_SUBCLASS_ENCM, "Ethernet Networking Control Model"},
    {COM_SUBCLASS_ANCM, "ATM Networking Control Model"},
    {COM_SUBCLASS_WHCM, "Wireless Handset Control Model"},
    {COM_SUBCLASS_DM, "Device Management"},
    {COM_SUBCLASS_MDLM, "Mobile Direct Line Model"},
    {COM_SUBCLASS_OBEX, "OBEX"},
    {COM_SUBCLASS_EEM, "Ethernet Emulation Model"},
    {COM_SUBCLASS_NCM, "Network Control Model"},
    {COM_SUBCLASS_MBIM, "Mobile Broadband Interface Model"},
    {0, NULL}
};
value_string_ext ext_usb_com_subclass_vals = VALUE_STRING_EXT_INIT(usb_com_subclass_vals);

void proto_register_usb_com(void);
void proto_reg_handoff_usb_com(void);

static int
dissect_usb_com_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 offset = 0, type, subtype;
    proto_tree *subtree;
    proto_tree *subtree_capabilities;
    proto_item *subitem_capabilities;
    proto_item *ti;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "COMMUNICATIONS DESCRIPTOR");
    subtree = proto_item_add_subtree(ti, ett_usb_com);

    dissect_usb_descriptor_header(subtree, tvb, offset, &usb_com_descriptor_type_vals_ext);
    offset += 2;

    type = tvb_get_guint8(tvb, 1);
    switch (type) {
        case CS_INTERFACE:
            subtype = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(subtree, hf_usb_com_descriptor_subtype, tvb, offset, 1, subtype);
            offset++;
            switch (subtype) {
                case 0x00:
                    proto_tree_add_item(subtree, hf_usb_com_descriptor_cdc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;
                case 0x01:
                    subitem_capabilities = proto_tree_add_item(subtree, hf_usb_com_capabilities, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    subtree_capabilities = proto_item_add_subtree(subitem_capabilities, ett_usb_com_capabilities);

                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_cm_capabilities_reserved, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_cm_capabilities_call_managment_over_data_class_interface, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_cm_capabilities_call_managment, tvb, 3, 1, ENC_LITTLE_ENDIAN);

                    proto_tree_add_item(subtree, hf_usb_com_descriptor_cm_data_interface, tvb, 4, 1, ENC_LITTLE_ENDIAN);
                    offset = 5;
                    break;
                case 0x02:
                    subitem_capabilities = proto_tree_add_item(subtree, hf_usb_com_capabilities, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    subtree_capabilities = proto_item_add_subtree(subitem_capabilities, ett_usb_com_capabilities);

                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_acm_capabilities_reserved, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_acm_capabilities_network_connection, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_acm_capabilities_send_break, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_acm_capabilities_line_and_state, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_acm_capabilities_comm_features, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    offset = 4;
                    break;
                case 0x06:
                    offset = 3;
                    proto_tree_add_item(subtree, hf_usb_com_control_interface, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    while (tvb_length_remaining(tvb,offset) > 0) {
                        proto_tree_add_item(subtree, hf_usb_com_subordinate_interface, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;
                    }
                    break;
                case 0x1b:
                case 0x1c:
                    offset = call_dissector_only(mbim_descriptor_handle, tvb, pinfo, subtree, NULL);
                    break;
                default:
                    break;
            }
            break;
        case CS_ENDPOINT:
        default:
            break;
    }

    if (tvb_reported_length_remaining(tvb, offset) != 0) {
        proto_tree_add_item(subtree, hf_usb_com_descriptor_payload, tvb, offset, -1, ENC_NA);
    }
    return tvb_length(tvb);
}

static int
dissect_usb_com_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    usb_conv_info_t *usb_conv_info;
    proto_tree *subtree;
    proto_item *ti;
    gint offset = 0;

    usb_conv_info = (usb_conv_info_t *)pinfo->usb_conv_info;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBCOM");

    ti = proto_tree_add_item(tree, proto_usb_com, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_usb_com);

    if (usb_conv_info) {
        ti = proto_tree_add_uint(subtree, hf_usb_com_control_subclass, tvb, 0, 0,
                                 usb_conv_info->interfaceSubclass);
        PROTO_ITEM_SET_GENERATED(ti);

        switch (usb_conv_info->interfaceSubclass)
        {
            case COM_SUBCLASS_MBIM:
                offset = call_dissector_only(mbim_control_handle, tvb, pinfo, tree, NULL);
                break;
            default:
                break;
        }
    }

    if (tvb_reported_length_remaining(tvb, offset) != 0) {
        proto_tree_add_item(subtree, hf_usb_com_control_payload, tvb, offset, -1, ENC_NA);
    }
    return tvb_length(tvb);
}

static int
dissect_usb_com_bulk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    usb_conv_info_t *usb_conv_info;

    usb_conv_info = (usb_conv_info_t *)pinfo->usb_conv_info;

    if (usb_conv_info) {
        switch (usb_conv_info->interfaceProtocol)
        {
            case 0x01: /* Network Transfer Block */
            case 0x02: /* Network Transfer Block (IP + DSS) */
                return call_dissector_only(mbim_bulk_handle, tvb, pinfo, tree, NULL);
                break;
            default:
                break;
        }
    }

    /* By default, assume it is ethernet without FCS */
    return call_dissector_only(eth_withoutfcs_handle, tvb, pinfo, tree, NULL);
}

void
proto_register_usb_com(void)
{
    static hf_register_info hf[] = {
        { &hf_usb_com_descriptor_subtype,
            { "bDescriptorSubtype", "usbcom.descriptor.subtype", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
              &usb_com_descriptor_subtype_vals_ext, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_cdc,
            { "bcdCDC", "usbcom.descriptor.cdc", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_payload,
            { "Payload", "usbcom.descriptor.payload", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_control_subclass,
            { "Subclass", "usbcom.control.subclass", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
              &ext_usb_com_subclass_vals, 0, NULL, HFILL }},
        { &hf_usb_com_capabilities,
            { "bmCapabilities", "usbcom.descriptor.capabilities", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_acm_capabilities_reserved,
            { "Reserved", "usbcom.descriptor.acm.capabilities.reserved", FT_UINT8, BASE_HEX,
              NULL, 0xF0, NULL, HFILL }},
        { &hf_usb_com_descriptor_acm_capabilities_network_connection,
            { "Network_Connection", "usbcom.descriptor.acm.capabilities.network_connection", FT_BOOLEAN, 8,
              &tfs_supported_not_supported, 0x08, NULL, HFILL }},
        { &hf_usb_com_descriptor_acm_capabilities_send_break,
            { "Send_Break", "usbcom.descriptor.acm.capabilities.network_connection", FT_BOOLEAN, 8,
              &tfs_supported_not_supported, 0x04, NULL, HFILL }},
        { &hf_usb_com_descriptor_acm_capabilities_line_and_state,
            { "Line Requests and State Notification", "usbcom.descriptor.acm.capabilities.line_and_state", FT_BOOLEAN, 8,
              &tfs_supported_not_supported, 0x02, NULL, HFILL }},
        { &hf_usb_com_descriptor_acm_capabilities_comm_features,
            { "Comm Features Combinations", "usbcom.descriptor.acm.capabilities.comm_features", FT_BOOLEAN, 8,
              &tfs_supported_not_supported, 0x01, NULL, HFILL }},
        { &hf_usb_com_control_interface,
            { "bControlInterface", "usbcom.descriptor.control_interface", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_subordinate_interface,
            { "bSubordinateInterface", "usbcom.descriptor.subordinate_interface", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_cm_capabilities_reserved,
            { "Reserved", "usbcom.descriptor.cm.capabilities.reserved", FT_UINT8, BASE_HEX,
              NULL, 0xFC, NULL, HFILL }},
        { &hf_usb_com_descriptor_cm_capabilities_call_managment_over_data_class_interface,
            { "Call Managment over Data Class Interface", "usbcom.descriptor.cm.capabilities.call_managment_over_data_class_interface", FT_BOOLEAN, 8,
              &tfs_supported_not_supported, 0x02, NULL, HFILL }},
        { &hf_usb_com_descriptor_cm_capabilities_call_managment,
            { "Call Managment", "usbcom.descriptor.cm.capabilities.call_managment", FT_BOOLEAN, 8,
              &tfs_supported_not_supported, 0x01, NULL, HFILL }},
        { &hf_usb_com_descriptor_cm_data_interface,
            { "bDataInterface", "usbcom.descriptor.cm.data_interface", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_control_payload,
            { "Payload", "usbcom.control.payload", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }}
    };

    static gint *usb_com_subtrees[] = {
        &ett_usb_com,
        &ett_usb_com_capabilities
    };

    proto_usb_com = proto_register_protocol("USB Communications and CDC Control", "USBCOM", "usbcom");
    proto_register_field_array(proto_usb_com, hf, array_length(hf));
    proto_register_subtree_array(usb_com_subtrees, array_length(usb_com_subtrees));
}

void
proto_reg_handoff_usb_com(void)
{
    dissector_handle_t usb_com_descriptor_handle, usb_com_control_handle, usb_com_bulk_handle;

    usb_com_descriptor_handle = new_create_dissector_handle(dissect_usb_com_descriptor, proto_usb_com);
    dissector_add_uint("usb.descriptor", IF_CLASS_COMMUNICATIONS, usb_com_descriptor_handle);
    usb_com_control_handle = new_create_dissector_handle(dissect_usb_com_control, proto_usb_com);
    dissector_add_uint("usb.control", IF_CLASS_COMMUNICATIONS, usb_com_control_handle);
    usb_com_bulk_handle = new_create_dissector_handle(dissect_usb_com_bulk, proto_usb_com);
    dissector_add_uint("usb.bulk", IF_CLASS_CDC_DATA, usb_com_bulk_handle);
    mbim_control_handle = find_dissector("mbim.control");
    mbim_descriptor_handle = find_dissector("mbim.descriptor");
    mbim_bulk_handle = find_dissector("mbim.bulk");
    eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
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
