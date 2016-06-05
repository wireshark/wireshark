/* packet-usbip.c
 * Routines for USB/IP dissection
 * Copyright 2016, Christian Lamparter <chunkeey@googlemail.com>
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

/*
 * The USB/IP protocol follows a server/client architecture. It runs
 * on top of TCP/IP. The server exports the USB devices and the
 * clients imports them. The device driver for the exported USB
 * device runs on the client machine.
 *
 * See
 *
 *    https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain/Documentation/usb/usbip_protocol.txt
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/etypes.h>
#include <epan/conversation.h>

#include "packet-usbip.h"
#include "packet-usb.h"
#include "packet-tcp.h"

void proto_register_usbip(void);
void proto_reg_handoff_usbip(void);

/* Initialize the protocol and registered fields
 */
static int proto_usbip = -1;

static int hf_usbip_version = -1;
static int hf_usbip_operation = -1;
static int hf_usbip_command = -1;
static int hf_usbip_status = -1;
static int hf_usbip_number_devices = -1;
static int hf_usbip_path = -1;
static int hf_usbip_devid = -1;
static int hf_usbip_busid = -1;
static int hf_usbip_busnum = -1;
static int hf_usbip_devnum = -1;
static int hf_usbip_speed = -1;
static int hf_usbip_idVendor = -1;
static int hf_usbip_idProduct = -1;
static int hf_usbip_bcdDevice = -1;
static int hf_usbip_bDeviceClass = -1;
static int hf_usbip_bDeviceSubClass = -1;
static int hf_usbip_bDeviceProtocol = -1;
static int hf_usbip_bConfigurationValue = -1;
static int hf_usbip_bNumConfigurations = -1;
static int hf_usbip_bNumInterfaces = -1;
static int hf_usbip_bInterfaceClass = -1;
static int hf_usbip_bInterfaceSubClass = -1;
static int hf_usbip_bInterfaceProtocol = -1;
static int hf_usbip_padding = -1;

static int hf_usbip_device = -1;
static int hf_usbip_interface = -1;
static int hf_usbip_interval = -1;

static int hf_usbip_actual_length = -1;
static int hf_usbip_error_count = -1;

static int hf_usbip_seqnum = -1;
static int hf_usbip_cmd_frame = -1;
static int hf_usbip_ret_frame = -1;
static int hf_usbip_vic_frame = -1;
static int hf_usbip_direction = -1;
static int hf_usbip_ep = -1;
static int hf_usbip_transfer_flags = -1;
static int hf_usbip_transfer_buffer_length = -1;
static int hf_usbip_start_frame = -1;
static int hf_usbip_number_of_packets = -1;
static int hf_usbip_setup = -1;
static int hf_usbip_urb_data = -1;

/* Initialize the subtree pointers */
static gint ett_usbip = -1;
static gint ett_usbip_dev = -1;
static gint ett_usbip_intf = -1;

enum usb_device_speed {
        USB_SPEED_UNKNOWN = 0,                  /* enumerating */
        USB_SPEED_LOW,                          /* usb 1.0 */
        USB_SPEED_FULL,                         /* usb 1.1 */
        USB_SPEED_HIGH,                         /* usb 2.0 */
        USB_SPEED_WIRELESS,                     /* wireless (usb 2.5) */
        USB_SPEED_SUPER,                        /* usb 3.0 */
};

#define USBIP_SUPPORTED_VERSION 0x111

#define OP_REQUEST (0x80 << 8)
#define OP_REPLY (0x00 << 8)

/* ----------------------------------------------------------------------
 * Import a remote USB device. */
#define OP_IMPORT 0x03
#define OP_REQ_IMPORT (OP_REQUEST | OP_IMPORT)
#define OP_REP_IMPORT (OP_REPLY | OP_IMPORT)

/* ----------------------------------------------------------------------
 * Retrieve the list of exported USB devices. */
#define OP_DEVLIST 0x05
#define OP_REQ_DEVLIST (OP_REQUEST | OP_DEVLIST)
#define OP_REP_DEVLIST (OP_REPLY | OP_DEVLIST)

#define OP_CMD_SUBMIT 0x0001
#define OP_CMD_UNLINK 0x0002
#define OP_RET_SUBMIT 0x0003
#define OP_RET_UNLINK 0x0004

static const value_string usbip_operation_vals[] = {
    {OP_REP_IMPORT,   "OP_REP_IMPORT"                              },
    {OP_REP_DEVLIST,  "OP_REP_DEVLIST"                             },

    {OP_REQ_IMPORT,   "OP_REQ_IMPORT"                              },
    {OP_REQ_DEVLIST,  "OP_REQ_DEVLIST"                             },
    {0,               NULL                                         }
};

static const value_string usbip_urb_vals[] = {
    {OP_CMD_SUBMIT, "OP_CMD_SUBMIT"                        },
    {OP_CMD_UNLINK, "OP_CMD_UNLINK"                        },
    {OP_RET_SUBMIT, "OP_RET_SUBMIT"                        },
    {OP_RET_UNLINK, "OP_RET_UNLINK"                        },
    {0,             NULL                                   }
};

static const value_string usbip_speed_vals[] = {
    {USB_SPEED_UNKNOWN,  "Speed Unknown"                                   },
    {USB_SPEED_LOW,      "Low Speed"                                       },
    {USB_SPEED_FULL,     "Full Speed"                                      },
    {USB_SPEED_HIGH,     "High Speed"                                      },
    {USB_SPEED_WIRELESS, "Wireless Speed"                                  },
    {USB_SPEED_SUPER,    "Super Speed"                                     },
    {0,                  NULL                                              }
};

static value_string_ext usbip_speed_vals_ext = VALUE_STRING_EXT_INIT(usbip_speed_vals);
static value_string_ext usbip_operation_vals_ext = VALUE_STRING_EXT_INIT(usbip_operation_vals);
static value_string_ext usbip_urb_vals_ext = VALUE_STRING_EXT_INIT(usbip_urb_vals);

extern value_string_ext ext_usb_vendors_vals;
extern value_string_ext ext_usb_products_vals;

static const value_string usb_endpoint_direction_vals[] = {
    {USBIP_DIR_OUT, "OUT"                        },
    {USBIP_DIR_IN,  "IN"                         },
    {0,             NULL                         }
};

static expert_field ei_usbip = EI_INIT;

typedef struct _usbip_transaction_t
{
    guint32 seqnum;
    guint32 devid;
    guint32 ep;
    guint32 dir;
    guint32 cmd_frame;
    guint32 ret_frame;
    guint32 unlink_seqnum;
} usbip_transaction_t;

typedef struct _usbip_conv_info_t
{
    /* holds OP_{CMD|RET}_{SUBMIT|UNLINK} */
    wmem_tree_t *pdus;
} usbip_conv_info_t;

static int
dissect_device_list_request(packet_info *pinfo)
{
    col_set_str(pinfo->cinfo, COL_INFO, "Device List Request");
    return 0;
}

static int
dissect_device(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    guint32 product;
    guint32 vendor_id;
    guint32 product_id;

    /* Device path on host (usually /sys/devices/usb/... */
    proto_tree_add_item(tree, hf_usbip_path, tvb, offset, 256, ENC_ASCII | ENC_NA);
    offset += 256;

    /* Bus id string - Id of the bus the device is connected to */
    proto_tree_add_item(tree, hf_usbip_busid, tvb, offset, 32, ENC_ASCII | ENC_NA);
    offset += 32;

    /* bus number */
    proto_tree_add_item(tree, hf_usbip_busnum, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* device number */
    proto_tree_add_item(tree, hf_usbip_devnum, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* USB Speed */
    proto_tree_add_item(tree, hf_usbip_speed, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* idVendor */
    proto_tree_add_item_ret_uint(tree, hf_usbip_idVendor, tvb, offset, 2, ENC_BIG_ENDIAN, &vendor_id);
    offset += 2;

    /* idProduct */
    product_id = tvb_get_ntohs(tvb, offset);
    product = vendor_id << 16 | product_id;

    proto_tree_add_uint_format_value(tree, hf_usbip_idProduct, tvb, offset, 2,
        product_id, "%s (0x%04x)", val_to_str_ext_const(product, &ext_usb_products_vals,
                                                        "Unknown"), product_id);
    offset += 2;

    /* bcdDevice */
    proto_tree_add_item(tree, hf_usbip_bcdDevice, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Device Class */
    proto_tree_add_item(tree, hf_usbip_bDeviceClass, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Device Sub Class */
    proto_tree_add_item(tree, hf_usbip_bDeviceSubClass, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Device Protocol */
    proto_tree_add_item(tree, hf_usbip_bDeviceProtocol, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Current Configuration */
    proto_tree_add_item(tree, hf_usbip_bConfigurationValue, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Number of Configurations */
    proto_tree_add_item(tree, hf_usbip_bNumConfigurations, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Number of Interfaces */
    proto_tree_add_item(tree, hf_usbip_bNumInterfaces, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    return offset;
}

static int
dissect_device_list_response(packet_info *pinfo, proto_tree *tree,
                             tvbuff_t *tvb,
                             int offset)
{
    proto_item *ti_intf;
    proto_item *ti_dev;
    proto_tree *intf_tree = NULL;
    proto_tree *dev_tree = NULL;
    guint32 num_of_devs;
    guint32 i;
    guint8 num_of_intf;
    guint8 j;

    col_set_str(pinfo->cinfo, COL_INFO, "Device List Response");

    proto_tree_add_item_ret_uint(tree, hf_usbip_number_devices, tvb, offset, 4,
                        ENC_BIG_ENDIAN, &num_of_devs);
    offset += 4;

    for (i = 0; i < num_of_devs; i++) {
        num_of_intf = tvb_get_guint8(tvb, offset + 0x137);
        ti_dev = proto_tree_add_uint(tree, hf_usbip_device, tvb, offset,
                                     0x138 + 4 * num_of_intf, i + 1);
        PROTO_ITEM_SET_GENERATED(ti_dev);

        dev_tree = proto_item_add_subtree(ti_dev, ett_usbip_dev);
        offset = dissect_device(dev_tree, tvb, offset);

        for (j = 0; j < num_of_intf; j++) {
            ti_intf = proto_tree_add_uint(dev_tree, hf_usbip_interface, tvb,
                                          offset, 3, j + 1);
            intf_tree = proto_item_add_subtree(ti_intf, ett_usbip_intf);

            proto_tree_add_item(intf_tree, hf_usbip_bInterfaceClass, tvb,
                                offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(intf_tree, hf_usbip_bInterfaceSubClass, tvb,
                                offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(intf_tree, hf_usbip_bInterfaceProtocol, tvb,
                                offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(intf_tree, hf_usbip_padding, tvb,
                                offset, 1, ENC_NA);
            offset += 1;
        }
    }
    return offset;
}

static int
dissect_import_request(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                       int offset)
{
    col_set_str(pinfo->cinfo, COL_INFO, "Import Request");
    proto_tree_add_item(tree, hf_usbip_busid, tvb, offset, 32, ENC_ASCII | ENC_NA);
    return offset + 32;
}

static int
dissect_import_response(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                        int offset, guint32 status)
{
    col_set_str(pinfo->cinfo, COL_INFO, "Import Response");
    if (status == 0)
        offset = dissect_device(tree, tvb, offset);
    return offset;
}

static int
dissect_cmd_submit(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                   int offset)
{
    col_set_str(pinfo->cinfo, COL_INFO, "URB Submit");

    proto_tree_add_item(tree, hf_usbip_transfer_flags, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_usbip_transfer_buffer_length, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_usbip_start_frame, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_usbip_number_of_packets, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_usbip_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_usbip_setup, tvb, offset, 8, ENC_NA);
    offset += 8;
    return offset;
}

static int
dissect_ret_submit(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                   int offset)
{
    col_set_str(pinfo->cinfo, COL_INFO, "URB Response");

    proto_tree_add_item(tree, hf_usbip_status, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_usbip_actual_length, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_usbip_start_frame, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_usbip_number_of_packets, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_usbip_error_count, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_usbip_setup, tvb, offset, 8, ENC_NA);
    offset += 8;
    return offset;
}

static int
dissect_cmd_unlink(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                   int offset, usbip_conv_info_t *usbip_info,
                   usbip_transaction_t *trans)
{
    usbip_transaction_t *victim;
    guint32 seqnum;

    col_set_str(pinfo->cinfo, COL_INFO, "URB Unlink");

    proto_tree_add_item_ret_uint(tree, hf_usbip_seqnum, tvb, offset, 4, ENC_BIG_ENDIAN, &seqnum);
    trans->unlink_seqnum = seqnum;
    offset += 4;

    victim = (usbip_transaction_t *) wmem_tree_lookup32(usbip_info->pdus, seqnum);
    if (victim) {
        proto_item *ti;

        ti = proto_tree_add_uint(tree, hf_usbip_vic_frame, NULL, 0, 0,
                                 victim->cmd_frame);
        PROTO_ITEM_SET_GENERATED(ti);
    }
    return offset;
}

static int
dissect_ret_unlink(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                   int offset, usbip_conv_info_t *usbip_info,
                   guint32 seqnum)
{
    usbip_transaction_t *victim;

    col_set_str(pinfo->cinfo, COL_INFO, "URB Unlink Response");

    victim = (usbip_transaction_t *) wmem_tree_lookup32(usbip_info->pdus, seqnum);
    if (victim) {
        proto_item *ti;

        victim->ret_frame = pinfo->num;
        ti = proto_tree_add_uint(tree, hf_usbip_vic_frame, NULL, 0, 0,
                                 victim->cmd_frame);
        PROTO_ITEM_SET_GENERATED(ti);
    }
    proto_tree_add_item(tree, hf_usbip_status, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    return offset;
}

static usbip_conv_info_t *
usbip_get_usbip_conv(packet_info *pinfo)
{
    conversation_t *conversation;
    usbip_conv_info_t *usbip_info;

    conversation = find_or_create_conversation(pinfo);
    usbip_info = (usbip_conv_info_t *) conversation_get_proto_data(conversation,
                                                                   proto_usbip);
    if (!usbip_info) {
        usbip_info = wmem_new(wmem_file_scope(), usbip_conv_info_t);
        usbip_info->pdus = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_usbip, usbip_info);
    }
    return usbip_info;
}

static int
usbip_dissect_op(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
                 int offset)
{
    proto_item *ti = NULL;
    guint32 operation;
    gint32 status;

    proto_tree_add_item(tree, hf_usbip_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_usbip_operation, tvb, offset, 2,
                        ENC_BIG_ENDIAN, &operation);
    offset += 2;
    proto_tree_add_item_ret_int(tree, hf_usbip_status, tvb, offset, 4, ENC_BIG_ENDIAN, &status);
    offset += 4;

    switch (operation) {

    case OP_REQ_IMPORT:
        offset = dissect_import_request(pinfo, tree, tvb, offset);
        break;

    case OP_REP_IMPORT:
        offset = dissect_import_response(pinfo, tree, tvb, offset, status);
        break;

    case OP_REQ_DEVLIST:
        offset = dissect_device_list_request(pinfo);
        break;

    case OP_REP_DEVLIST:
        offset = dissect_device_list_response(pinfo, tree, tvb, offset);
        break;

    default:
        proto_tree_add_item(tree, hf_usbip_urb_data, tvb, offset, -1, ENC_NA);
        offset = tvb_reported_length_remaining(tvb, offset);
        expert_add_info_format(
            pinfo, ti, &ei_usbip,
            "Dissector for USBIP Operation"
            " (%x) code not implemented, Contact"
            " Wireshark developers if you want this supported",
            operation);
        proto_item_append_text(ti, ": Undecoded");
        break;
    }
    return offset;
}

static int
usbip_dissect_urb(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
                  proto_tree *orig, int offset,
                  usbip_conv_info_t *usbip_info)
{
    proto_item *ti = NULL;
    usbip_transaction_t *usbip_trans;
    guint32 command;
    guint32 devid;
    guint32 seqnum;
    guint32 dir;
    guint32 ep;
    struct usbip_header header;

    proto_tree_add_item_ret_uint(tree, hf_usbip_command, tvb, offset, 4, ENC_BIG_ENDIAN, &command);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_usbip_seqnum, tvb, offset, 4, ENC_BIG_ENDIAN, &seqnum);
    offset += 4;

    dir = tvb_get_ntohl(tvb, offset + 4);
    ep = tvb_get_ntohl(tvb, offset + 8);
    devid = tvb_get_ntohl(tvb, offset);

    if (!PINFO_FD_VISITED(pinfo)) {
        if (command == OP_CMD_SUBMIT || command == OP_CMD_UNLINK) {
            usbip_trans = wmem_new(wmem_file_scope(), usbip_transaction_t);
            usbip_trans->devid = devid;
            usbip_trans->dir = dir;
            usbip_trans->ep = ep;
            usbip_trans->seqnum = seqnum;
            usbip_trans->cmd_frame = pinfo->num;
            usbip_trans->ret_frame = 0;
            usbip_trans->unlink_seqnum = 0;
            wmem_tree_insert32(usbip_info->pdus, seqnum, (void *) usbip_trans);
        } else {
            usbip_trans = (usbip_transaction_t *) wmem_tree_lookup32(usbip_info->pdus, seqnum);
            if (usbip_trans)
                usbip_trans->ret_frame = pinfo->num;
        }
    } else {
        usbip_trans = (usbip_transaction_t *) wmem_tree_lookup32(usbip_info->pdus, seqnum);
    }

    if (!usbip_trans) {
        usbip_trans = wmem_new(wmem_packet_scope(), usbip_transaction_t);
        usbip_trans->cmd_frame = 0;
        usbip_trans->ret_frame = 0;
        usbip_trans->devid = 0;
        usbip_trans->unlink_seqnum = 0;
        usbip_trans->seqnum = seqnum;
    }

    /* only the OP_CMD_SUBMIT has a valid devid - in all other case we have to restore it from the transaction */
    if (command == OP_RET_SUBMIT || command == OP_RET_UNLINK) {
        devid = usbip_trans->devid;
        ep = usbip_trans->ep;
        dir = usbip_trans->dir;
    }

    ti = proto_tree_add_uint(tree, hf_usbip_cmd_frame, NULL, 0, 0,
                             usbip_trans->cmd_frame);
    PROTO_ITEM_SET_GENERATED(ti);
    ti = proto_tree_add_uint(tree, hf_usbip_ret_frame, NULL, 0, 0,
                             usbip_trans->ret_frame);
    PROTO_ITEM_SET_GENERATED(ti);
    ti = proto_tree_add_uint(tree, hf_usbip_devid, NULL, 0, 0, devid);
    PROTO_ITEM_SET_GENERATED(ti);
    ti = proto_tree_add_uint(tree, hf_usbip_direction, NULL, 0, 0, dir);
    PROTO_ITEM_SET_GENERATED(ti);
    ti = proto_tree_add_uint(tree, hf_usbip_ep, NULL, 0, 0, ep);
    PROTO_ITEM_SET_GENERATED(ti);

    proto_tree_add_item(tree, hf_usbip_devid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_usbip_direction, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_usbip_ep, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    header.ep = ep;
    header.dir = dir;
    header.devid = devid & 0x00ff;
    header.busid = devid >> 16;

    switch (command) {

    case OP_CMD_SUBMIT:
        offset = dissect_cmd_submit(pinfo, tree, tvb, offset);
        dissect_usb_common(tvb, pinfo, orig, USB_HEADER_USBIP, &header);
        break;

    case OP_CMD_UNLINK:
        offset = dissect_cmd_unlink(pinfo, tree, tvb, offset, usbip_info,
                                    usbip_trans);
        break;

    case OP_RET_SUBMIT: {
        guint32 status;

        status = tvb_get_ntohl(tvb, offset);
        offset = dissect_ret_submit(pinfo, tree, tvb, offset);
        if (status == 0)
            dissect_usb_common(tvb, pinfo, orig, USB_HEADER_USBIP, &header);
        break;
    }

    case OP_RET_UNLINK:
        offset = dissect_ret_unlink(pinfo, tree, tvb, offset, usbip_info,
                                    usbip_trans->unlink_seqnum);
        break;

    default:
        proto_tree_add_item(tree, hf_usbip_urb_data, tvb, offset, -1, ENC_NA);
        offset = tvb_reported_length_remaining(tvb, offset);
        expert_add_info_format(
            pinfo, ti, &ei_usbip,
            "Dissector for USBIP Command"
            " (%x) code not implemented, Contact"
            " Wireshark developers if you want this supported",
            command);
        proto_item_append_text(ti, ": Undecoded");
        break;
    }
    return offset;
}

static int
dissect_usbip_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     void *data _U_)
{
    guint16 version;
    int offset = 0;

    proto_item *ti = NULL;
    proto_tree *usbip_tree = NULL;

    usbip_conv_info_t *usbip_info;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBIP");
    col_clear(pinfo->cinfo, COL_INFO);

    usbip_info = usbip_get_usbip_conv(pinfo);

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_usbip, tvb, 0, -1, ENC_NA);
    usbip_tree = proto_item_add_subtree(ti, ett_usbip);

    /* Get some values from the packet header */
    version = tvb_get_ntohs(tvb, 0);

    /* check if this is a operation code by checking the version. */
    if (version == USBIP_SUPPORTED_VERSION) {
        offset = usbip_dissect_op(pinfo, tvb, usbip_tree, offset);
    } else if (version == 0x0000) {
        offset = usbip_dissect_urb(pinfo, tvb, usbip_tree, tree, offset,
                                   usbip_info);
    } else {
        proto_tree_add_item(usbip_tree, hf_usbip_urb_data, tvb, offset, -1,
                            ENC_NA);
        offset = tvb_reported_length_remaining(tvb, offset);
        expert_add_info_format(
            pinfo, ti, &ei_usbip,
            "Dissector for USBIP Version"
            " (%d.%d) not implemented, Contact"
            " Wireshark developers if you want this supported",
            version >> 8, version & 0xff);
        proto_item_append_text(ti, ": Undecoded");
    }
    return offset;
}

#define FRAME_HEADER_LEN 8

static unsigned int
get_usbip_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
                      void *data _U_)
{
    guint16 version;

    /* Get some values from the packet header */
    version = tvb_get_ntohs(tvb, offset);

    /* The USBIP's is split in two parts.
     * There's an userspace portion which consists of the usbipd daemon
     * and usbip tool.
     * The kernel part is done by two modules usbip-host.ko and vhci-hcd.ko (client).
     *
     * The userspace programs are generating and parsing the OP_REQ_* and OP_REP_*
     * data packets. They have all have a proper protocol version field. But data
     * can be split up in multiple packages, so reassembly is required. There's no
     * session id or sequence number to track packages.
     *
     * The kernel modules are handling the OP_CMD_* and OP_RET_* data packets.
     * There's no protocol version (The version is simply always 0x0000, because
     * the OP_CMD|RET are 4-Bytes long, whereas OP_REQ/OP_REP are only 2-Bytes).
     * data frames can be split into multiple packages. But it also can happen that
     * multiple data frames are aggregated into a single package. The OP_CMD_* and
     * OP_RET_* frames have a 4-Byte sequence number to track individual URBs. The
     * sequence counter will wrap around eventually.
     */

    if (version == USBIP_SUPPORTED_VERSION) {
        guint16 op = tvb_get_ntohs(tvb, offset + 2);

        switch (op) {

        case OP_REQ_IMPORT:
            return 40;

        case OP_REP_IMPORT:
            if (tvb_get_ntohl(tvb, offset + 4) == 0) {
                /* Status: OK */
                return 0x140;
            } else {
                /* Status: Error */
                return 0x8;
            }

        case OP_REQ_DEVLIST:
            return 8;

        case OP_REP_DEVLIST: {
            unsigned int expected_size = 0xc;
            unsigned int num_of_devs;
            unsigned int i;

            if (tvb_captured_length(tvb) < 0xc) {
                /* not enough segments to calculate the size */
                return 0x0;
            }

            offset += 8;

            num_of_devs = tvb_get_ntohl(tvb, offset);
            offset += 4;

            if (num_of_devs == 0)
                return expected_size;

            if (tvb_captured_length_remaining(tvb, offset) < (gint) (0x138 * num_of_devs))
                return 0;

            for (i = 0; i < num_of_devs; i++) {
                guint8 num_of_intf = tvb_get_guint8(tvb, offset + 0x137);
                int skip = num_of_intf * 4;

                expected_size += 0x138 + skip;
                offset += 0x138 + skip;
            }
            return expected_size;
        }
        }
    } else if (version == 0x0000) {
        guint32 cmd = tvb_get_ntohl(tvb, offset);

        if (tvb_captured_length_remaining(tvb, offset) < USBIP_HEADER_LEN)
            return 0;

        switch (cmd) {

        case OP_RET_UNLINK:
            return USBIP_HEADER_LEN;

        case OP_CMD_UNLINK:
            return USBIP_HEADER_LEN;

        case OP_CMD_SUBMIT: {
            int expected_size = USBIP_HEADER_LEN;

            if (tvb_get_ntohl(tvb, offset + 0xc) == USBIP_DIR_OUT)
                expected_size += tvb_get_ntohl(tvb, offset + 0x18);

            expected_size += tvb_get_ntohl(tvb, offset + 0x20) * 4 * 4;
            return expected_size;
        }

        case OP_RET_SUBMIT: {
            int expected_size = USBIP_HEADER_LEN;
            usbip_transaction_t *usbip_trans = NULL;
            usbip_conv_info_t *usbip_info = usbip_get_usbip_conv(pinfo);
            guint32 status = tvb_get_ntohl(tvb, offset + 0x14);

            if (usbip_info) {
                usbip_trans = (usbip_transaction_t *) wmem_tree_lookup32(
                    usbip_info->pdus, tvb_get_ntohl(tvb, offset + 4));

                if (usbip_trans && usbip_trans->dir == USBIP_DIR_IN && status == 0)
                    expected_size += tvb_get_ntohl(tvb, offset + 0x18);
            }

            if (status == 0)
                expected_size += tvb_get_ntohl(tvb, offset + 0x20) * 4 * 4;
            else
                expected_size = tvb_captured_length(tvb);

            return expected_size;
        }
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_usbip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* Check that there's enough data */
    if (tvb_reported_length(tvb) < 4) {
        /* usbip's smallest packet size is 4 */
        return 0;
    }

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                     get_usbip_message_len, dissect_usbip_common, data);

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */

void
proto_register_usbip(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        {&hf_usbip_version,
            {"Version",                       "usbip.version",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Version of the protocol", HFILL}},

        {&hf_usbip_operation,
            {"Operation",                     "usbip.operation",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &usbip_operation_vals_ext,
            0x0,
            "USBIP Operation", HFILL}},

        {&hf_usbip_command,
         {"Command",                       "usbip.urb",
            FT_UINT32, BASE_HEX | BASE_EXT_STRING, &usbip_urb_vals_ext, 0x0,
            "USBIP URB Transaction", HFILL}},

        {&hf_usbip_status,
         {"Status",                        "usbip.status",
            FT_INT32, BASE_DEC | BASE_EXT_STRING, &usb_urb_status_vals_ext, 0,
            "USBIP Status", HFILL}},

        {&hf_usbip_number_devices,
         {"Number of exported Devices",    "usbip.number_of_devices",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},

        {&hf_usbip_path,
         {"System Path",                   "usbip.system_path",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},

        {&hf_usbip_devid,
         {"Devid",                         "usbip.devid",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}},

        {&hf_usbip_busid,
         {"Busid",                         "usbip.busid",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},

        {&hf_usbip_busnum,
         {"Bus number",                    "usbip.bus_num",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}},

        {&hf_usbip_devnum,
         {"Device Number",                 "usbip.dev_num",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}},

        {&hf_usbip_speed,
         {"Connected Speed",               "usbip.speed",
            FT_UINT32, BASE_DEC | BASE_EXT_STRING, &usbip_speed_vals_ext, 0,
            NULL, HFILL}},

        {&hf_usbip_idVendor,
         {"idVendor",                      "usbip.idVendor",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &ext_usb_vendors_vals, 0x0,
            NULL, HFILL}},

        {&hf_usbip_idProduct,
         {"idProduct",                     "usbip.idProduct",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}},

        {&hf_usbip_bcdDevice,
         {"bcdDevice",                     "usbip.bcdDevice",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}},

        {&hf_usbip_bDeviceClass,
         {"bDeviceClass",                  "usbip.bDeviceClass",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &usb_class_vals_ext, 0x0,
            NULL, HFILL}},

        {&hf_usbip_bDeviceSubClass,
         {"bDeviceSubClass",               "usbip.bDeviceSubClass",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},

        {&hf_usbip_bDeviceProtocol,
         {"bDeviceProtocol",               "usbip.bDeviceProtocol",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},

        {&hf_usbip_bConfigurationValue,
         {"bConfigurationValue",           "usbip.bConfigurationValue",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},

        {&hf_usbip_bNumConfigurations,
         {"bNumConfigurations",            "usbip.bNumConfigurations",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},

        {&hf_usbip_bNumInterfaces,
         {"bNumInterfaces",                "usbip.bNumInterfaces",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},

        {&hf_usbip_bInterfaceClass,
         {"bInterfaceClass",               "usbip.bInterfaceClass",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &usb_class_vals_ext, 0x0,
            NULL, HFILL}},

        {&hf_usbip_bInterfaceSubClass,
         {"bInterfaceSubClass",            "usbip.bInterfaceSubClass",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}},

        {&hf_usbip_bInterfaceProtocol,
         {"bInterfaceProtocol",            "usbip.bInterfaceProtocol",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}},

        {&hf_usbip_padding,
         {"Padding",                       "usbip.padding",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}},

        {&hf_usbip_device,
         {"Device",                        "usbip.device",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},

        {&hf_usbip_interface,
         {"Interface",                     "usbip.interface",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},

        {&hf_usbip_interval,
         {"Interval",                      "usbip.interval",
            FT_UINT32, BASE_DEC, NULL, 0,
            "maximum time for the request on the server-side host controller",
            HFILL}},

        {&hf_usbip_actual_length,
         {"Actual length",                 "usbip.actual_length",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL}},

        {&hf_usbip_error_count,
         {"ISO error count",               "usbip.iso.error_count",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL}},

        {&hf_usbip_seqnum,
         {"Sequence",                      "usbip.sequence_no",
          FT_UINT32, BASE_DEC, NULL, 0,
          "Sequence number", HFILL}},

        {&hf_usbip_cmd_frame,
         {"Command frame",                 "usbip.cmd_frame",
          FT_FRAMENUM, BASE_NONE, NULL, 0,
          NULL, HFILL}},

        {&hf_usbip_ret_frame,
         {"Return frame",                  "usbip.ret_frame",
          FT_FRAMENUM, BASE_NONE, NULL, 0,
          NULL, HFILL}},

        {&hf_usbip_vic_frame,
         {"Victim frame",                  "usbip.vic_frame",
          FT_FRAMENUM, BASE_NONE, NULL, 0,
          "Frame which was forcefully cancelled", HFILL}},

        {&hf_usbip_direction,
         {"Direction",                     "usbip.endpoint_number.direction",
          FT_UINT8, BASE_HEX, VALS(usb_endpoint_direction_vals), 0x1,
          "USB endpoint direction", HFILL}},

        {&hf_usbip_ep,
         {"Endpoint",                      "usbip.endpoint_number",
          FT_UINT8, BASE_HEX, NULL, 0xf,
          "USB endpoint number", HFILL}},

        {&hf_usbip_transfer_flags,
         {"Transfer flags",                "usbip.transfer_flags",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          "USBIP Transferflag", HFILL}},

        {&hf_usbip_transfer_buffer_length,
         {"Transfer buffer length [bytes]", "usbip.transfer_buffer_length",
          FT_UINT32, BASE_DEC, NULL, 0,
          "Data length in bytes", HFILL}},

        {&hf_usbip_start_frame,
         {"ISO Start frame",               "usbip.iso.start_frame",
          FT_INT32, BASE_DEC, NULL, 0,
          "For an ISO frame the actually selected frame to transmit", HFILL}},

        {&hf_usbip_number_of_packets,
         {"Number of ISO descriptors",     "usbip.iso.num_of_packets",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL}},

        {&hf_usbip_setup,
         {"Setup Data",                    "usbip.setup",
          FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL}},

        {&hf_usbip_urb_data,
         {"Data",                          "usbip.data",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Raw Data", HFILL}},
    };

    static gint *ett[] = {
        &ett_usbip,
        &ett_usbip_dev,
        &ett_usbip_intf,
    };

    static ei_register_info ei[] = {
        {&ei_usbip,
         { "usbip.unsupported_version", PI_MALFORMED, PI_ERROR,
          "Unsupported element", EXPFILL}},
    };

    expert_module_t *expert_usbip;

    expert_usbip = expert_register_protocol(proto_usbip);
    expert_register_field_array(expert_usbip, ei, array_length(ei));
    proto_usbip = proto_register_protocol("USBIP Protocol", "USBIP", "usbip");
    proto_register_field_array(proto_usbip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_usbip(void)
{
    dissector_handle_t usbip_handle;

    usbip_handle = create_dissector_handle(dissect_usbip, proto_usbip);
    dissector_add_for_decode_as("tcp.port", usbip_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
