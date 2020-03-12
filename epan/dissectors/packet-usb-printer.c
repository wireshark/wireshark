/* packet-usb-printer.c
 *
 * Copyright 2020, Martin Kaiser <martin@kaiser.cx>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * References:
 *
 * USB printer class specification
 * https://www.usb.org/sites/default/files/usbprint11a021811.pdf
 *
 * IEEE 1284 (parallel peripheral interface for personal computers)
 * http://kazus.ru/nuke/modules/Downloads/pub/148/0/IEEE%201284-2000.pdf
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/dissectors/packet-usb.h>
#include <epan/value_string.h>

static int proto_usb_printer = -1;

static int hf_usb_printer_req = -1;
static int hf_usb_printer_cfg_idx = -1;
static int hf_usb_printer_intf = -1;
static int hf_usb_printer_alt_set = -1;
static int hf_usb_printer_max_len = -1;
static int hf_usb_printer_dev_id_len = -1;
static int hf_usb_printer_dev_id = -1;

static gint ett_usb_printer   = -1;

void proto_register_usb_printer(void);
void proto_reg_handoff_usb_printer(void);

#define REQ_GET_DEV_ID    0
#define REQ_GET_PORT_STAT 1
#define REQ_GET_SOFT_RST  2

static const value_string usb_printer_req[] = {
    { REQ_GET_DEV_ID,    "GET_DEVICE_ID" },
    { REQ_GET_PORT_STAT, "GET_PORT_STATUS" },
    { REQ_GET_SOFT_RST,  "SOFT_RESET" },
    { 0, NULL }
};

static gint dissect_usb_printer_ctl(
        tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gboolean is_request = (pinfo->srcport == NO_ENDPOINT);
    usb_conv_info_t *usb_conv_info = (usb_conv_info_t *)data;
    usb_trans_info_t *usb_trans_info;
    gint offset = 0;
    guint8 bReq;
    guint32 dev_id_len;

    if (!usb_conv_info)
        return 0;

    usb_trans_info = usb_conv_info->usb_trans_info;
    if (!usb_trans_info)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBPRINTER");
    col_set_str(pinfo->cinfo, COL_INFO,
            val_to_str_const(usb_trans_info->setup.request,
                usb_printer_req, "Invalid"));

    if (is_request) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " request");

        bReq = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_usb_printer_req,
                tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        if (bReq == REQ_GET_DEV_ID) {
            /* Generally, fields in USB messages are little endian. */
            proto_tree_add_item(tree, hf_usb_printer_cfg_idx,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_printer_intf,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_printer_alt_set,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_printer_max_len,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
    }
    else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " response");

        if (usb_trans_info->setup.request == REQ_GET_DEV_ID) {
            /*
             * A printer's Device ID is defined in IEEE 1284, section 7.6.
             * It starts with a 16-bit length field in big endian encoding.
             * The length field includes the two bytes for itself. Therefore,
             * we can't use an FT_UINT_STRING for the entire Device ID.
             * The actual Device ID string consists of ASCII characters.
             */
            proto_tree_add_item_ret_uint(tree, hf_usb_printer_dev_id_len,
                    tvb, offset, 2, ENC_BIG_ENDIAN, &dev_id_len);
            offset += 2;
            if (dev_id_len > 2) {
                proto_tree_add_item(tree, hf_usb_printer_dev_id,
                        tvb, offset, dev_id_len-2, ENC_ASCII|ENC_NA);
                offset += dev_id_len-2;
            }
            /* XXX - expert info for invalid dev_id_len */
        }
    }

    return offset;
}

void proto_register_usb_printer(void)
{
    static hf_register_info hf[] = {
        { &hf_usb_printer_req,
            { "bRequest", "usbprinter.bRequest", FT_UINT8, BASE_HEX,
                VALS(usb_printer_req), 0x0, NULL, HFILL }
        },
        { &hf_usb_printer_cfg_idx,
            { "Config index", "usbprinter.config_index", FT_UINT16, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_usb_printer_intf,
            { "Interface", "usbprinter.interface", FT_UINT16, BASE_HEX,
                NULL, 0xFF00, NULL, HFILL }
        },
        { &hf_usb_printer_alt_set,
            { "Alternate setting", "usbprinter.alt_set", FT_UINT16, BASE_HEX,
                NULL, 0x00FF, NULL, HFILL }
        },
        { &hf_usb_printer_max_len,
            { "Maximum length", "usbprinter.max_len", FT_UINT16, BASE_HEX,
                NULL, 0, NULL, HFILL }
        },
        { &hf_usb_printer_dev_id_len,
            { "Device ID length", "usbprinter.device_id_len", FT_UINT16,
                BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_usb_printer_dev_id,
            { "Device ID", "usbprinter.device_id", FT_STRING, BASE_NONE,
                NULL, 0, NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_usb_printer
    };

    proto_usb_printer = proto_register_protocol(
            "USB Printer", "USBPRINTER", "usbprinter");
    proto_register_field_array(proto_usb_printer, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_usb_printer(void)
{
    dissector_handle_t usb_printer_ctl_handle;

    usb_printer_ctl_handle = create_dissector_handle(
            dissect_usb_printer_ctl, proto_usb_printer);

    dissector_add_uint("usb.control", IF_CLASS_PRINTER, usb_printer_ctl_handle);
}

/*
* Editor modelines - https://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
