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
    guint16 bus_id;
} usb_address_t;
#define USB_ADDR_LEN (sizeof(usb_address_t))

/* Flag used to mark usb_address_t.endpoint as an interface
 * address instead of the normal endpoint address.
 */
#define INTERFACE_PORT	0x80000000


typedef struct _usb_conv_info_t usb_conv_info_t;

/* header type */
typedef enum {
    USB_HEADER_LINUX_48_BYTES,
    USB_HEADER_LINUX_64_BYTES,
    USB_HEADER_USBPCAP,
    USB_HEADER_MAUSB,
    USB_HEADER_USBIP
} usb_header_t;

#define USB_HEADER_IS_LINUX(type) \
    ((type) == USB_HEADER_LINUX_48_BYTES || (type) == USB_HEADER_LINUX_64_BYTES)

/* there is one such structure for each request/response */
typedef struct _usb_trans_info_t {
    guint32 request_in;
    guint32 response_in;
    nstime_t req_time;
    usb_header_t header_type;

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
            guint8 usb_index;
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

    guint64 usb_id;
} usb_trans_info_t;

enum usb_conv_class_data_type {USB_CONV_UNKNOWN = 0, USB_CONV_U3V, USB_CONV_AUDIO, USB_CONV_VIDEO, USB_CONV_MASS_STORAGE};

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

    void *class_data;           /* private class/id decode data */
    enum usb_conv_class_data_type class_data_type;

    wmem_array_t *alt_settings;
};

/* This is what a tap will tap */
typedef struct _usb_tap_data_t {
    guint8 urb_type;
    guint8 transfer_type;
    usb_conv_info_t *conv_info;
    usb_trans_info_t *trans_info;
} usb_tap_data_t;


/* the value for "no endpoint" that's used usb_addr_t, e.g. for the address of the host */
#define NO_ENDPOINT  0xffffffff
/* the 8bit version of NO_ENDPOINT, it's used in usb_conv_info_t
   0xff would be an invalid endpoint number (reserved bits are 1) */
#define NO_ENDPOINT8 ((guint8)(NO_ENDPOINT& G_MAXUINT8))

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
 * URB transfer_type values
 */
#define URB_ISOCHRONOUS   0x0
#define URB_INTERRUPT     0x1
#define URB_CONTROL       0x2
#define URB_BULK          0x3
#define URB_UNKNOWN       0xFF

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

#define IF_SUBCLASS_MISC_U3V          0x05

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


#define USB_SETUP_GET_STATUS             0
#define USB_SETUP_CLEAR_FEATURE          1
#define USB_SETUP_SET_FEATURE            3
#define USB_SETUP_SET_ADDRESS            5
#define USB_SETUP_GET_DESCRIPTOR         6
#define USB_SETUP_SET_DESCRIPTOR         7
#define USB_SETUP_GET_CONFIGURATION      8
#define USB_SETUP_SET_CONFIGURATION      9
#define USB_SETUP_GET_INTERFACE         10
#define USB_SETUP_SET_INTERFACE         11
#define USB_SETUP_SYNCH_FRAME           12
#define USB_SETUP_SET_SEL               48
#define USB_SETUP_SET_ISOCH_DELAY       49


/* 9.6.6 */
extern const true_false_string tfs_endpoint_direction;

extern value_string_ext usb_class_vals_ext;

extern value_string_ext usb_urb_status_vals_ext;

usb_conv_info_t *get_usb_iface_conv_info(packet_info *pinfo, guint8 interface_num);

proto_item * dissect_usb_descriptor_header(proto_tree *tree,
                                           tvbuff_t *tvb, int offset,
                                           value_string_ext *type_val_str);

void dissect_usb_endpoint_address(proto_tree *tree, tvbuff_t *tvb, int offset);

int
dissect_usb_endpoint_descriptor(packet_info *pinfo, proto_tree *parent_tree,
                                tvbuff_t *tvb, int offset,
                                usb_conv_info_t  *usb_conv_info);

int
dissect_usb_unknown_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree,
                               tvbuff_t *tvb, int offset,
                               usb_conv_info_t  *usb_conv_info _U_);

struct mausb_header;

void
dissect_usb_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent,
                   usb_header_t header_type, void *extra_data);

#endif

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
