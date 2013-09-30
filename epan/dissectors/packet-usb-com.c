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
static int hf_usb_com_subclass = -1;
static int hf_usb_com_payload = -1;

static gint ett_usb_com = -1;

static dissector_handle_t mbim_handle = NULL;

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

static int
dissect_usb_com_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    usb_conv_info_t *usb_conv_info;
    proto_tree *subtree;
    proto_item *ti;

    usb_conv_info = (usb_conv_info_t *)pinfo->usb_conv_info;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBCOM");

    ti = proto_tree_add_item(tree, proto_usb_com, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_usb_com);

    if (usb_conv_info) {
        ti = proto_tree_add_uint(subtree, hf_usb_com_subclass, tvb, 0, 0, usb_conv_info->interfaceSubclass);
        PROTO_ITEM_SET_GENERATED(ti);

        switch (usb_conv_info->interfaceSubclass)
        {
            case COM_SUBCLASS_MBIM:
                if (mbim_handle) {
                    return call_dissector(mbim_handle, tvb, pinfo, tree);
                }
                break;
            default:
                break;
        }
    }

    proto_tree_add_item(subtree, hf_usb_com_payload, tvb, 0, -1, ENC_NA);
    return tvb_length(tvb);
}

void
proto_register_usb_com(void)
{
    static hf_register_info hf[] = {
        { &hf_usb_com_subclass,
            { "Subclass", "usbcom.subclass", FT_UINT8, BASE_HEX,
              VALS(usb_com_subclass_vals), 0, NULL, HFILL }},
        { &hf_usb_com_payload,
            { "Payload", "usbcom.payload", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }}
    };

    static gint *usb_com_subtrees[] = {
        &ett_usb_com
    };

    proto_usb_com = proto_register_protocol("USB Communications and CDC Control", "USBCOM", "usbcom");
    proto_register_field_array(proto_usb_com, hf, array_length(hf));
    proto_register_subtree_array(usb_com_subtrees, array_length(usb_com_subtrees));
}

void
proto_reg_handoff_usb_com(void)
{
    dissector_handle_t usb_com_descriptor_handle;

    usb_com_descriptor_handle = new_create_dissector_handle(dissect_usb_com_descriptor, proto_usb_com);
    dissector_add_uint("usb.control", IF_CLASS_COMMUNICATIONS, usb_com_descriptor_handle);
    mbim_handle = find_dissector("mbim");
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
