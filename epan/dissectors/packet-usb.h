/* packet-usb.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_USB_H__
#define __PACKET_USB_H__

#include <epan/packet_info.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/value_string.h>
#include <epan/tfs.h>
#include <wsutil/nstime.h>

typedef struct _usb_address_t {
    uint32_t device;
    uint32_t endpoint;
    uint16_t bus_id;
} usb_address_t;
#define USB_ADDR_LEN (sizeof(usb_address_t))

/* Flag used to mark usb_address_t.endpoint as an interface
 * address instead of the normal endpoint address.
 */
#define INTERFACE_PORT	0x80000000


typedef struct _usb_conv_info_t usb_conv_info_t;
typedef struct _urb_info_t urb_info_t;

/* Wireshark specific (i.e. numeric values are arbitrary) enum representing
 * USB device speed.
 */
typedef enum {
    USB_SPEED_UNKNOWN,  /* Unknown, skip speed specific processing */
    USB_SPEED_LOW,
    USB_SPEED_FULL,
    USB_SPEED_HIGH,
} usb_speed_t;

/* header type */
typedef enum {
    USB_HEADER_LINUX_48_BYTES,
    USB_HEADER_LINUX_64_BYTES,
    USB_HEADER_USBPCAP,
    USB_HEADER_MAUSB,
    USB_HEADER_USBIP,
    USB_HEADER_DARWIN,
    USB_HEADER_PSEUDO_URB,
} usb_header_t;

#define USB_HEADER_IS_LINUX(type) \
    ((type) == USB_HEADER_LINUX_48_BYTES || (type) == USB_HEADER_LINUX_64_BYTES)

typedef struct _usb_pseudo_urb_t {
    bool from_host;
    uint8_t transfer_type;
    uint8_t device_address;
    uint8_t endpoint;
    uint16_t bus_id;
    usb_speed_t speed;
} usb_pseudo_urb_t;

/* there is one such structure for each request/response */
typedef struct _usb_trans_info_t {
    uint32_t request_in;
    uint32_t response_in;
    nstime_t req_time;
    usb_header_t header_type;

    /* Valid only for SETUP transactions */
    struct _usb_setup {
        uint8_t requesttype;
        uint8_t request;
        uint16_t wValue;
        uint16_t wIndex;
        uint16_t wLength;
    } setup;

    /* Valid only during GET DESCRIPTOR transactions */
    union {
        struct {
            uint8_t type;
            uint8_t usb_index;
        } get_descriptor;
    } u;


    /* used to pass the interface class from the
     * interface descriptor onto the endpoint
     * descriptors so that we can create a
     * conversation with the appropriate class
     * once we know the endpoint.
     * Valid only during GET CONFIGURATION response.
     */
    uint8_t interface_endpoint;
    usb_conv_info_t *interface_info;

    uint64_t usb_id;
} usb_trans_info_t;

enum usb_conv_class_data_type {
    USB_CONV_UNKNOWN = 0,
    USB_CONV_U3V,
    USB_CONV_AUDIO,
    USB_CONV_VIDEO,
    USB_CONV_MASS_STORAGE_BOT,
    USB_CONV_MASS_STORAGE_UASP,
    USB_CONV_CDC_DATA,
};

/* Conversation Structure
 * there is one such structure for each device/endpoint conversation */
struct _usb_conv_info_t {
    uint8_t  descriptor_transfer_type; /* transfer type lifted from the configuration descriptor */
    uint16_t max_packet_size; /* max packet size from configuration descriptor */

    uint16_t interfaceClass;     /* Interface Descriptor - class          */
    uint16_t interfaceSubclass;  /* Interface Descriptor - subclass       */
    uint16_t interfaceProtocol;  /* Interface Descriptor - protocol       */
    uint8_t interfaceNum;       /* Most recent interface number          */

    uint16_t deviceVendor;       /* Device    Descriptor - USB Vendor  ID */
    uint32_t deviceProduct;      /* Device    Descriptor - USB Product ID - MSBs only for encoding unknown */
    uint16_t deviceVersion;      /* Device    Descriptor - USB device version number BCD */
    uint8_t iSerialNumber;      /* Device    Descriptor - iSerialNumber (0 if no serial number available) */
    wmem_tree_t *transactions;

    void *class_data;           /* private class/id decode data */
    enum usb_conv_class_data_type class_data_type;

    wmem_array_t *alt_settings;
};

/* URB data lifetime is limited to packet scope */
struct _urb_info_t {
    uint16_t bus_id;
    uint16_t device_address;
    uint8_t  endpoint;
    int      direction;
    uint8_t  transfer_type; /* transfer type from URB */
    uint32_t device_protocol;
    bool is_request;
    bool is_setup;
    uint8_t  setup_requesttype;
    usb_speed_t speed;

    usb_trans_info_t *usb_trans_info; /* pointer to the current transaction */

    usb_conv_info_t *conv;
};

/* This is what a tap will tap */
typedef struct _usb_tap_data_t {
    uint8_t urb_type;
    uint8_t transfer_type;
    urb_info_t *urb;
    usb_trans_info_t *trans_info;
} usb_tap_data_t;


/* the value for "no endpoint" that's used usb_addr_t, e.g. for the address of the host */
#define NO_ENDPOINT  0xffffffff
/* the 8bit version of NO_ENDPOINT, it's used in usb_conv_info_t
   0xff would be an invalid endpoint number (reserved bits are 1) */
#define NO_ENDPOINT8 ((uint8_t)(NO_ENDPOINT& UINT8_MAX))

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
#define IF_CLASS_BILLBOARD            0x11
#define IF_CLASS_USB_C_BRIDGE         0x12
#define IF_CLASS_BULK_DISPLAY_PROTO   0x13
#define IF_CLASS_MCTP_USB_EP          0x14
#define IF_CLASS_I3C                  0x3c
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
#define DEV_VERSION_UNKNOWN           0xffff

#define IF_SUBCLASS_MISC_U3V          0x05

#define IF_SUBCLASS_APP_DFU           0x01

#define IF_PROTOCOL_DFU_RUNTIME       0x01
#define IF_PROTOCOL_DFU_MODE          0x02

/* Key to be used with "usb.control", "usb.bulk" and/or "usb.interrupt"
 * dissector tables when the dissector only applies to specific triple.
 * Use class code directly if the code is not shared with other specifications.
 *
 * MSB (bit 31) is arbitrarily chosen to ensure class registered dissectors
 * won't clash with protocol key.
 */
#define USB_PROTOCOL_KEY(class, subclass, protocol) \
    (1u << 31 | (class & 0xff) << 16 | (subclass & 0xff) << 8 | (protocol & 0xff))

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
#define ENDPOINT_TYPE_NOT_SET         255

/* wMaxPacketSize */
#define USB_MPS_EP_SIZE(max_packet_size) ((max_packet_size) & 0x07FF)
#define USB_MPS_ADDNL(max_packet_size)   (((max_packet_size) & 0x1800) >> 11)
#define USB_MPS(ep_size, addnl)          (((addnl) << 11) | (ep_size))
#define USB_MPS_TPL(max_packet_size) \
    ((USB_MPS_ADDNL(max_packet_size) + 1) * USB_MPS_EP_SIZE(max_packet_size))

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

/* transfer_flags */
#define URB_SHORT_NOT_OK	0x00000001	/* report short reads as errors */
#define URB_ISO_ASAP		0x00000002	/* iso-only; use the first unexpired
					 * slot in the schedule */
#define URB_NO_TRANSFER_DMA_MAP	0x00000004	/* urb->transfer_dma valid on submit */
#define URB_NO_FSBR		0x00000020	/* UHCI-specific */
#define URB_ZERO_PACKET		0x00000040	/* Finish bulk OUT with short packet */
#define URB_NO_INTERRUPT	0x00000080	/* HINT: no non-error interrupt
					 * needed */
#define URB_FREE_BUFFER		0x00000100	/* Free transfer buffer with the URB */

/* The following flags are used internally by usbcore and HCDs */
#define URB_DIR_IN		0x00000200	/* Transfer from device to host */
#define URB_DIR_OUT		0
#define URB_DIR_MASK		URB_DIR_IN

#define URB_DMA_MAP_SINGLE	0x00010000	/* Non-scatter-gather mapping */
#define URB_DMA_MAP_PAGE	0x00020000	/* HCD-unsupported S-G */
#define URB_DMA_MAP_SG		0x00040000	/* HCD-supported S-G */
#define URB_MAP_LOCAL		0x00080000	/* HCD-local-memory mapping */
#define URB_SETUP_MAP_SINGLE	0x00100000	/* Setup packet DMA mapped */
#define URB_SETUP_MAP_LOCAL	0x00200000	/* HCD-local setup packet */
#define URB_DMA_SG_COMBINED	0x00400000	/* S-G entries were combined */
#define URB_ALIGNED_TEMP_BUFFER	0x00800000	/* Temp buffer was alloc'd */


/* 9.6.6 */
extern const true_false_string tfs_endpoint_direction;

extern value_string_ext usb_class_vals_ext;

usb_conv_info_t *get_usb_iface_conv_info(packet_info *pinfo, uint8_t interface_num);
usb_conv_info_t *get_existing_usb_ep_conv_info(packet_info *pinfo, uint16_t bus_id,
                                               uint16_t device_address, int endpoint);

proto_item * dissect_usb_descriptor_header(proto_tree *tree,
                                           tvbuff_t *tvb, int offset,
                                           value_string_ext *type_val_str);

void dissect_usb_endpoint_address(proto_tree *tree, tvbuff_t *tvb, int offset);

unsigned int
sanitize_usb_max_packet_size(uint8_t ep_type, usb_speed_t speed,
                             unsigned int max_packet_size);

int
dissect_usb_endpoint_descriptor(packet_info *pinfo, proto_tree *parent_tree,
                                tvbuff_t *tvb, int offset,
                                urb_info_t *urb,
                                uint8_t *out_ep_type, usb_speed_t speed);

int
dissect_usb_unknown_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree,
                               tvbuff_t *tvb, int offset,
                               urb_info_t *urb _U_);

int
dissect_urb_transfer_flags(tvbuff_t *tvb, int offset, proto_tree* tree, int hf, int endian);

struct mausb_header;

void
dissect_usb_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent,
                   usb_header_t header_type, void *extra_data);

void usb_lpm_besl_str(char *buf, uint32_t value);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
