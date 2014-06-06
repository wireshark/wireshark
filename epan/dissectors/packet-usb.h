/* packet-usb.h
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

#ifndef __PACKET_USB_H__
#define __PACKET_USB_H__

#include <epan/value_string.h>
#include <epan/wmem/wmem.h>
#include <epan/conversation.h>

typedef struct _usb_address_t {
    guint32 device;
    guint32 endpoint;
} usb_address_t;
#define USB_ADDR_LEN (sizeof(usb_address_t))

/* Flag used to mark usb_address_t.endpoint as an interface
 * address instead of the normal endpoint address.
 */
#define INTERFACE_PORT	0x80000000


typedef struct _usb_conv_info_t usb_conv_info_t;

/* header flags */
#define USB_HEADER_IS_LINUX    (1 << 0)
#define USB_HEADER_IS_64_BYTES (1 << 1)
#define USB_HEADER_IS_USBPCAP  (1 << 2)

/* there is one such structure for each request/response */
typedef struct _usb_trans_info_t {
    guint32 request_in;
    guint32 response_in;
    nstime_t req_time;
    guint8 header_info;

    /* Valid only for SETUP transactions */
    struct _usb_setup {
        guint8 requesttype;
        guint8 request;
        guint16 wValue;
        guint16 wIndex;
        guint16 wLength;
    } setup;

    /* Valid only during GET DESCRIPTOR transactions */
    union {
        struct {
            guint8 type;
            guint8 index;
        } get_descriptor;
    } u;


    /* used to pass the interface class from the
     * interface descriptor onto the endpoint
     * descriptors so that we can create a
     * conversation with the appropriate class
     * once we know the endpoint.
     * Valid only during GET CONFIGURATION response.
     */
    usb_conv_info_t *interface_info;
} usb_trans_info_t;

/* Conversation Structure
 * there is one such structure for each device/endpoint conversation */
struct _usb_conv_info_t {
    guint16  bus_id;
    guint16  device_address;
    guint8   endpoint;
    gint     direction;
    guint8   transfer_type;
    guint32  device_protocol;
    gboolean is_request;
    gboolean is_setup;
    guint8   setup_requesttype;

    guint16 interfaceClass;     /* Interface Descriptor - class          */
    guint16 interfaceSubclass;  /* Interface Descriptor - subclass       */
    guint16 interfaceProtocol;  /* Interface Descriptor - protocol       */
    guint8  interfaceNum;       /* Most recent interface number          */

    guint16 deviceVendor;       /* Device    Descriptor - USB Vendor  ID */
    guint32 deviceProduct;      /* Device    Descriptor - USB Product ID - MSBs only for encoding unknown */
    wmem_tree_t *transactions;
    usb_trans_info_t *usb_trans_info; /* pointer to the current transaction */

    void *class_data;	/* private class/id decode data */
};

/* This is what a tap will tap */
typedef struct _usb_tap_data_t {
    guint8 urb_type;
    guint8 transfer_type;
    usb_conv_info_t *conv_info;
    usb_trans_info_t *trans_info;
} usb_tap_data_t;


/* This is the endpoint number used for "no endpoint" or the fake endpoint
 * for the host side since we need two endpoints to manage conversations
 * properly.
 */
#define NO_ENDPOINT 0xffffffff

/*
 * Values from the Linux USB pseudo-header.
 */

/*
 * event_type values
 */
#define URB_SUBMIT        'S'
#define URB_COMPLETE      'C'
#define URB_ERROR         'E'

/*
 * transfer_type values
 */
#define URB_ISOCHRONOUS   0x0
#define URB_INTERRUPT     0x1
#define URB_CONTROL       0x2
#define URB_BULK          0x3

#define URB_TRANSFER_IN   0x80		/* to host */


/* http://www.usb.org/developers/defined_class */
#define IF_CLASS_DEVICE               0x00
#define IF_CLASS_AUDIO                0x01
#define IF_CLASS_COMMUNICATIONS       0x02
#define IF_CLASS_HID                  0x03
#define IF_CLASS_PHYSICAL             0x05
#define IF_CLASS_IMAGE                0x06
#define IF_CLASS_PRINTER              0x07
#define IF_CLASS_MASS_STORAGE         0x08
#define IF_CLASS_HUB                  0x09
#define IF_CLASS_CDC_DATA             0x0a
#define IF_CLASS_SMART_CARD           0x0b
#define IF_CLASS_CONTENT_SECURITY     0x0d
#define IF_CLASS_VIDEO                0x0e
#define IF_CLASS_PERSONAL_HEALTHCARE  0x0f
#define IF_CLASS_AUDIO_VIDEO          0x10
#define IF_CLASS_DIAGNOSTIC_DEVICE    0xdc
#define IF_CLASS_WIRELESS_CONTROLLER  0xe0
#define IF_CLASS_MISCELLANEOUS        0xef
#define IF_CLASS_APPLICATION_SPECIFIC 0xfe
#define IF_CLASS_VENDOR_SPECIFIC      0xff

#define IF_CLASS_UNKNOWN              0xffff
#define IF_SUBCLASS_UNKNOWN           0xffff
#define IF_PROTOCOL_UNKNOWN           0xffff
#define DEV_VENDOR_UNKNOWN            0x0000  /* this id is unassigned */
#define DEV_PRODUCT_UNKNOWN           0xfffffff /* 0x0000 and 0xffff are used values by vendors, so MSBs encode unknown */

/* bmRequestType values */
#define USB_DIR_OUT                     0               /* to device */
#define USB_DIR_IN                      0x80            /* to host */

#define USB_TYPE_MASK                   (0x03 << 5)
#define USB_TYPE(type)                  (((type) & USB_TYPE_MASK) >> 5)
#define RQT_SETUP_TYPE_STANDARD	0
#define RQT_SETUP_TYPE_CLASS	1
#define RQT_SETUP_TYPE_VENDOR	2

#define USB_RECIPIENT_MASK              0x1F
#define USB_RECIPIENT(type)             ((type) & USB_RECIPIENT_MASK)
#define RQT_SETUP_RECIPIENT_DEVICE      0
#define RQT_SETUP_RECIPIENT_INTERFACE   1
#define RQT_SETUP_RECIPIENT_ENDPOINT    2
#define RQT_SETUP_RECIPIENT_OTHER       3

/* Endpoint descriptor bmAttributes  */
#define ENDPOINT_TYPE(ep_attrib)        ((ep_attrib) & 0x03)
#define ENDPOINT_TYPE_CONTROL           0
#define ENDPOINT_TYPE_ISOCHRONOUS       1
#define ENDPOINT_TYPE_BULK              2
#define ENDPOINT_TYPE_INTERRUPT         3

usb_conv_info_t *
get_usb_conv_info(conversation_t *conversation);

conversation_t *
get_usb_conversation(packet_info *pinfo,
                     address *src_addr, address *dst_addr,
                     guint32 src_endpoint, guint32 dst_endpoint);

usb_conv_info_t *get_usb_iface_conv_info(packet_info *pinfo, guint8 interface_num);

proto_item * dissect_usb_descriptor_header(proto_tree *tree,
                                           tvbuff_t *tvb, int offset,
                                           value_string_ext *type_val_str);
void dissect_usb_endpoint_address(proto_tree *tree, tvbuff_t *tvb, int offset);

int
dissect_usb_endpoint_descriptor(packet_info *pinfo, proto_tree *parent_tree,
                                tvbuff_t *tvb, int offset,
                                usb_trans_info_t *usb_trans_info,
                                usb_conv_info_t  *usb_conv_info _U_);

int
dissect_usb_unknown_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree,
                               tvbuff_t *tvb, int offset,
                               usb_trans_info_t *usb_trans_info _U_,
                               usb_conv_info_t  *usb_conv_info _U_);

int
dissect_usb_setup_request(packet_info *pinfo, proto_tree *parent, tvbuff_t *tvb,
                          int offset, usb_conv_info_t *usb_conv_info, proto_tree **setup_tree);

void
usb_set_addr(packet_info *pinfo, usb_address_t *src_addr,
             usb_address_t *dst_addr, guint16 device_address, int endpoint,
             gboolean req);

usb_trans_info_t
*usb_get_trans_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    guint8 header_info, usb_conv_info_t *usb_conv_info);


#endif
