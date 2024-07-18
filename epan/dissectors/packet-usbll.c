/* packet-usbll.c
 *
 * 2019 Tomasz Mon <desowin@gmail.com>
 *
 * USB link layer dissector
 *
 * This code is separated from packet-usb.c on purpose.
 * It is important to note that packet-usb.c operates on the USB URB level.
 * The idea behind this file is to transform low level link layer data
 * (captured by hardware sniffers) into structures that resemble URB and pass
 * such URB to the URB common dissection code.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/crc16-tvb.h>
#include <wsutil/crc5.h>
#include <epan/address_types.h>
#include <epan/to_str.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>
#include <wiretap/wtap.h>
#include "packet-usb.h"

void proto_register_usbll(void);
void proto_reg_handoff_usbll(void);

static dissector_handle_t unknown_speed_handle;
static dissector_handle_t low_speed_handle;
static dissector_handle_t full_speed_handle;
static dissector_handle_t high_speed_handle;

static int proto_usbll;

/* Fields defined by USB 2.0 standard */
static int hf_usbll_pid;
static int hf_usbll_device_addr;
static int hf_usbll_endp;
static int hf_usbll_crc5;
static int hf_usbll_crc5_status;
static int hf_usbll_data;
static int hf_usbll_data_crc;
static int hf_usbll_data_crc_status;
static int hf_usbll_sof_framenum;
static int hf_usbll_split_hub_addr;
static int hf_usbll_split_sc;
static int hf_usbll_split_port;
static int hf_usbll_split_s;
static int hf_usbll_split_e;
static int hf_usbll_split_u;
static int hf_usbll_split_iso_se;
static int hf_usbll_split_et;
static int hf_usbll_split_crc5;
static int hf_usbll_split_crc5_status;
static int hf_usbll_src;
static int hf_usbll_dst;
static int hf_usbll_addr;
static int hf_usbll_transfer_fragments;
static int hf_usbll_transfer_fragment;
static int hf_usbll_transfer_fragment_overlap;
static int hf_usbll_transfer_fragment_overlap_conflicts;
static int hf_usbll_transfer_fragment_multiple_tails;
static int hf_usbll_transfer_fragment_too_long_fragment;
static int hf_usbll_transfer_fragment_error;
static int hf_usbll_transfer_fragment_count;
static int hf_usbll_transfer_reassembled_in;
static int hf_usbll_transfer_reassembled_length;
/* Fields defined by USB 2.0 ECN: Link Power Management (LPM) and
 * USB 2.0 ECN Errata for Link Power Management 9/28/2011
 */
static int hf_usbll_subpid;
static int hf_usbll_lpm_link_state;
static int hf_usbll_lpm_besl;
static int hf_usbll_lpm_remote_wake;
static int hf_usbll_lpm_reserved;

static int ett_usbll;
static int ett_usbll_transfer_fragment;
static int ett_usbll_transfer_fragments;

static const fragment_items usbll_frag_items = {
    /* Fragment subtrees */
    &ett_usbll_transfer_fragment,
    &ett_usbll_transfer_fragments,
    /* Fragment Fields */
    &hf_usbll_transfer_fragments,
    &hf_usbll_transfer_fragment,
    &hf_usbll_transfer_fragment_overlap,
    &hf_usbll_transfer_fragment_overlap_conflicts,
    &hf_usbll_transfer_fragment_multiple_tails,
    &hf_usbll_transfer_fragment_too_long_fragment,
    &hf_usbll_transfer_fragment_error,
    &hf_usbll_transfer_fragment_count,
    /* Reassembled in field */
    &hf_usbll_transfer_reassembled_in,
    /* Reassembled length field */
    &hf_usbll_transfer_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "USB transfer fragments"
};

static expert_field ei_invalid_pid;
static expert_field ei_invalid_subpid;
static expert_field ei_conflicting_subpid;
static expert_field ei_undecoded;
static expert_field ei_wrong_crc5;
static expert_field ei_wrong_split_crc5;
static expert_field ei_wrong_crc16;
static expert_field ei_invalid_s;
static expert_field ei_invalid_e_u;
static expert_field ei_invalid_pid_sequence;
static expert_field ei_invalid_setup_data;

static int usbll_address_type = -1;

static reassembly_table usbll_reassembly_table;

static wmem_map_t *transfer_info;

static const enum_val_t dissect_unknown_speed_as[] = {
    { "unk",  "Unknown",    USB_SPEED_UNKNOWN },
    { "low",  "Low-Speed",  USB_SPEED_LOW },
    { "full", "Full-Speed", USB_SPEED_FULL },
    { "high", "High-Speed", USB_SPEED_HIGH },
    { NULL, NULL, 0 }
};

static int global_dissect_unknown_speed_as = USB_SPEED_UNKNOWN;

/* USB packet ID is 4-bit. It is send in octet alongside complemented form.
 * The list of PIDs is available in Universal Serial Bus Specification Revision 2.0,
 * Table 8-1. PID Types
 * Packets here are sorted by the complemented form (high nibble).
 */
#define USB_PID_DATA_MDATA         0x0F
#define USB_PID_HANDSHAKE_STALL    0x1E
#define USB_PID_TOKEN_SETUP        0x2D
#define USB_PID_SPECIAL_PRE_OR_ERR 0x3C
#define USB_PID_DATA_DATA1         0x4B
#define USB_PID_HANDSHAKE_NAK      0x5A
#define USB_PID_TOKEN_IN           0x69
#define USB_PID_SPECIAL_SPLIT      0x78
#define USB_PID_DATA_DATA2         0x87
#define USB_PID_HANDSHAKE_NYET     0x96
#define USB_PID_TOKEN_SOF          0xA5
#define USB_PID_SPECIAL_PING       0xB4
#define USB_PID_DATA_DATA0         0xC3
#define USB_PID_HANDSHAKE_ACK      0xD2
#define USB_PID_TOKEN_OUT          0xE1
#define USB_PID_SPECIAL_EXT        0xF0
static const value_string usb_packetid_vals[] = {
    {USB_PID_DATA_MDATA,         "MDATA"},
    {USB_PID_HANDSHAKE_STALL,    "STALL"},
    {USB_PID_TOKEN_SETUP,        "SETUP"},
    {USB_PID_SPECIAL_PRE_OR_ERR, "PRE/ERR"},
    {USB_PID_DATA_DATA1,         "DATA1"},
    {USB_PID_HANDSHAKE_NAK,      "NAK"},
    {USB_PID_TOKEN_IN,           "IN"},
    {USB_PID_SPECIAL_SPLIT,      "SPLIT"},
    {USB_PID_DATA_DATA2,         "DATA2"},
    {USB_PID_HANDSHAKE_NYET,     "NYET"},
    {USB_PID_TOKEN_SOF,          "SOF"},
    {USB_PID_SPECIAL_PING,       "PING"},
    {USB_PID_DATA_DATA0,         "DATA0"},
    {USB_PID_HANDSHAKE_ACK,      "ACK"},
    {USB_PID_TOKEN_OUT,          "OUT"},
    {USB_PID_SPECIAL_EXT,        "EXT"},
    {0, NULL}
};
static value_string_ext usb_packetid_vals_ext =
    VALUE_STRING_EXT_INIT(usb_packetid_vals);

/* EXT PID and SubPIDs are defined in USB 2.0 ECN: Link Power Management (LPM)
 * Currently only LPM SubPID is defined, all other are reserved. The reserved
 * PIDs are either conflicting with USB 2.0 Token PIDs (and can not be reused
 * as SubPID in order to maintain backwards compatibility) or not yet defined
 * (reserved for future use, because old devices will simply reject them).
 */
#define USB_SUBPID_RESERVED_MDATA     0x0F
#define USB_SUBPID_RESERVED_STALL     0x1E
#define USB_SUBPID_CONFLICT_SETUP     0x2D
#define USB_SUBPID_CONFLICT_PRE       0x3C
#define USB_SUBPID_RESERVED_DATA1     0x4B
#define USB_SUBPID_RESERVED_NAK       0x5A
#define USB_SUBPID_CONFLICT_IN        0x69
#define USB_SUBPID_CONFLICT_SPLIT     0x78
#define USB_SUBPID_RESERVED_DATA2     0x87
#define USB_SUBPID_RESERVED_NYET      0x96
#define USB_SUBPID_CONFLICT_SOF       0xA5
#define USB_SUBPID_CONFLICT_PING      0xB4
#define USB_SUBPID_LPM                0xC3
#define USB_SUBPID_RESERVED_ACK       0xD2
#define USB_SUBPID_CONFLICT_OUT       0xE1
#define USB_SUBPID_RESERVED_EXT       0xF0
static const value_string usb_subpid_vals[] = {
    {USB_SUBPID_RESERVED_MDATA,  "Reserved (MDATA)"},
    {USB_SUBPID_RESERVED_STALL,  "Reserved (STALL)"},
    {USB_SUBPID_CONFLICT_SETUP,  "Reserved (conflict with SETUP)"},
    {USB_SUBPID_CONFLICT_PRE,    "Reserved (conflict with PRE)"},
    {USB_SUBPID_RESERVED_DATA1,  "Reserved (DATA1)"},
    {USB_SUBPID_RESERVED_NAK,    "Reserved (NAK)"},
    {USB_SUBPID_CONFLICT_IN,     "Reserved (conflict with IN)"},
    {USB_SUBPID_CONFLICT_SPLIT,  "Reserved (conflict with SPLIT)"},
    {USB_SUBPID_RESERVED_DATA2,  "Reserved (DATA2)"},
    {USB_SUBPID_RESERVED_NYET,   "Reserved (NYET)"},
    {USB_SUBPID_CONFLICT_SOF,    "Reserved (conflict with SOF)"},
    {USB_SUBPID_CONFLICT_PING,   "Reserved (conflict with PING)"},
    {USB_SUBPID_LPM,             "LPM"},
    {USB_SUBPID_RESERVED_ACK,    "Reserved (ACK)"},
    {USB_SUBPID_CONFLICT_OUT,    "Reserved (conflict with OUT)"},
    {USB_SUBPID_RESERVED_EXT,    "Reserved (EXT)"},
    {0, NULL}
};
static value_string_ext usb_subpid_vals_ext =
    VALUE_STRING_EXT_INIT(usb_subpid_vals);

static void lpm_link_state_str(char *buf, uint32_t value)
{
    if (value == 0x01) {
        snprintf(buf, ITEM_LABEL_LENGTH, "L1 (Sleep)");
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "Reserved for future use");
    }
}

static unsigned besl_to_us(uint8_t besl)
{
    unsigned int us;
    if (besl == 0) {
        us = 125;
    } else if (besl == 1) {
        us = 150;
    } else if (besl <= 5) {
        us = 100 * besl;
    } else {
        us = 1000 * (besl - 5);
    }
    return us;
}

void usb_lpm_besl_str(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%d us (%d)", besl_to_us(value), value);
}

static const value_string usb_lpm_remote_wake_vals[] = {
    {0, "Disable"},
    {1, "Enable"},
    {0, NULL},
};

static const value_string usb_start_complete_vals[] = {
    {0, "Start"},
    {1, "Complete"},
    {0, NULL}
};

static const value_string usb_split_speed_vals[] = {
    {0, "Full"},
    {1, "Low"},
    {0, NULL}
};

static const value_string usb_split_iso_se_vals[] = {
    {0, "High-speed data is the middle of the fullspeed data payload"},
    {1, "High-speed data is the beginning of the full-speed data payload"},
    {2, "High-speed data is the end of the full-speed data payload"},
    {3, "High-speed data is all of the full-speed data payload"},
    {0, NULL}
};

#define USB_EP_TYPE_CONTROL     0
#define USB_EP_TYPE_ISOCHRONOUS 1
#define USB_EP_TYPE_BULK        2
#define USB_EP_TYPE_INTERRUPT   3
static const value_string usb_endpoint_type_vals[] = {
    {USB_EP_TYPE_CONTROL,     "Control"},
    {USB_EP_TYPE_ISOCHRONOUS, "Isochronous"},
    {USB_EP_TYPE_BULK,        "Bulk"},
    {USB_EP_TYPE_INTERRUPT,   "Interrupt"},
    {0, NULL}
};

/* Macros for Token Packets. */
#define TOKEN_BITS_GET_ADDRESS(bits) (bits & 0x007F)
#define TOKEN_BITS_GET_ENDPOINT(bits) ((bits & 0x0780) >> 7)

/* Macros for Split Packets. */
#define SPLIT_BITS_GET_HUB_ADDRESS(bits) (uint8_t)(bits & 0x007F)
#define SPLIT_BITS_GET_HUB_PORT(bits) (uint8_t)((bits & 0x7F00) >> 8)
#define SPLIT_BITS_GET_ENDPOINT_TYPE(bits) ((bits & 0x060000) >> 17)
#define SPLIT_BIT_SPEED 0x8000
#define SPLIT_BIT_E_U 0x10000
#define SPLIT_BIT_START_COMPLETE 0x0080

/* Bitmasks definitions for usbll_address_t flags
 * and 'flags' parameter of usbll_set_address function.
 */
#define USBLL_ADDRESS_STANDARD 0
#define USBLL_ADDRESS_HOST 0x01
#define USBLL_ADDRESS_HUB_PORT 0x02
#define USBLL_ADDRESS_BROADCAST 0x04
#define USBLL_ADDRESS_HOST_TO_DEV 0
#define USBLL_ADDRESS_DEV_TO_HOST 0x08

#define USBLL_ADDRESS_IS_DEV_TO_HOST(flags) \
    (flags & USBLL_ADDRESS_DEV_TO_HOST)

#define USBLL_ADDRESS_IS_HOST_TO_DEV(flags) \
    (!USBLL_ADDRESS_IS_DEV_TO_HOST(flags))

typedef enum usbll_state {
    STATE_IDLE,      /* No transaction, e.g. after SOF */
    STATE_INVALID,   /* Invalid PID sequence, e.g. ACK without transaction  */
    STATE_IN,
    STATE_IN_DATA0,
    STATE_IN_DATA1,
    STATE_IN_HS_ISOCHRONOUS_DATA2,
    STATE_IN_ACK,
    STATE_IN_NAK,
    STATE_IN_STALL,
    STATE_OUT,
    STATE_OUT_DATA0,
    STATE_OUT_DATA1,
    STATE_OUT_HS_ISOCHRONOUS_DATA2,
    STATE_OUT_HS_ISOCHRONOUS_MDATA,
    STATE_OUT_ACK,
    STATE_OUT_NAK,
    STATE_OUT_STALL,
    STATE_OUT_NYET,
    STATE_PING,
    STATE_PING_ACK,
    STATE_PING_NAK,
    STATE_PING_STALL,
    STATE_SETUP,
    STATE_SETUP_DATA0,
    STATE_SETUP_ACK,
    /* LS/FS Control transactions via HS hub */
    STATE_SSPLIT_CONTROL,
    STATE_SSPLIT_CONTROL_SETUP,
    STATE_SSPLIT_CONTROL_SETUP_DATA0,
    STATE_SSPLIT_CONTROL_SETUP_ACK,
    STATE_SSPLIT_CONTROL_SETUP_NAK,
    STATE_SSPLIT_CONTROL_OUT,
    STATE_SSPLIT_CONTROL_OUT_DATA0,
    STATE_SSPLIT_CONTROL_OUT_DATA1,
    STATE_SSPLIT_CONTROL_OUT_ACK,
    STATE_SSPLIT_CONTROL_OUT_NAK,
    STATE_SSPLIT_CONTROL_IN,
    STATE_SSPLIT_CONTROL_IN_ACK,
    STATE_SSPLIT_CONTROL_IN_NAK,
    STATE_CSPLIT_CONTROL,
    STATE_CSPLIT_CONTROL_SETUP,
    STATE_CSPLIT_CONTROL_SETUP_ACK,
    STATE_CSPLIT_CONTROL_SETUP_NYET,
    STATE_CSPLIT_CONTROL_OUT,
    STATE_CSPLIT_CONTROL_OUT_ACK,
    STATE_CSPLIT_CONTROL_OUT_NAK,
    STATE_CSPLIT_CONTROL_OUT_STALL,
    STATE_CSPLIT_CONTROL_OUT_NYET,
    STATE_CSPLIT_CONTROL_IN,
    STATE_CSPLIT_CONTROL_IN_DATA0,
    STATE_CSPLIT_CONTROL_IN_DATA1,
    STATE_CSPLIT_CONTROL_IN_NAK,
    STATE_CSPLIT_CONTROL_IN_STALL,
    STATE_CSPLIT_CONTROL_IN_NYET,
    /* LS/FS Bulk transactions via HS hub */
    STATE_SSPLIT_BULK,
    STATE_SSPLIT_BULK_OUT,
    STATE_SSPLIT_BULK_OUT_DATA0,
    STATE_SSPLIT_BULK_OUT_DATA1,
    STATE_SSPLIT_BULK_OUT_ACK,
    STATE_SSPLIT_BULK_OUT_NAK,
    STATE_SSPLIT_BULK_IN,
    STATE_SSPLIT_BULK_IN_ACK,
    STATE_SSPLIT_BULK_IN_NAK,
    STATE_CSPLIT_BULK,
    STATE_CSPLIT_BULK_OUT,
    STATE_CSPLIT_BULK_OUT_ACK,
    STATE_CSPLIT_BULK_OUT_NAK,
    STATE_CSPLIT_BULK_OUT_STALL,
    STATE_CSPLIT_BULK_OUT_NYET,
    STATE_CSPLIT_BULK_IN,
    STATE_CSPLIT_BULK_IN_DATA0,
    STATE_CSPLIT_BULK_IN_DATA1,
    STATE_CSPLIT_BULK_IN_NAK,
    STATE_CSPLIT_BULK_IN_STALL,
    STATE_CSPLIT_BULK_IN_NYET,
    /* LS/FS Interrupt transactions via HS hub */
    STATE_SSPLIT_INTERRUPT,
    STATE_SSPLIT_INTERRUPT_OUT,
    STATE_SSPLIT_INTERRUPT_OUT_DATA0,
    STATE_SSPLIT_INTERRUPT_OUT_DATA1,
    STATE_SSPLIT_INTERRUPT_IN,
    STATE_CSPLIT_INTERRUPT,
    STATE_CSPLIT_INTERRUPT_OUT,
    STATE_CSPLIT_INTERRUPT_OUT_ACK,
    STATE_CSPLIT_INTERRUPT_OUT_NAK,
    STATE_CSPLIT_INTERRUPT_OUT_STALL,
    STATE_CSPLIT_INTERRUPT_OUT_ERR,
    STATE_CSPLIT_INTERRUPT_OUT_NYET,
    STATE_CSPLIT_INTERRUPT_IN,
    STATE_CSPLIT_INTERRUPT_IN_MDATA,
    STATE_CSPLIT_INTERRUPT_IN_DATA0,
    STATE_CSPLIT_INTERRUPT_IN_DATA1,
    STATE_CSPLIT_INTERRUPT_IN_NAK,
    STATE_CSPLIT_INTERRUPT_IN_STALL,
    STATE_CSPLIT_INTERRUPT_IN_ERR,
    STATE_CSPLIT_INTERRUPT_IN_NYET,
    /* FS Isochronous transactions via HS hub */
    STATE_SSPLIT_ISOCHRONOUS,
    STATE_SSPLIT_ISOCHRONOUS_OUT,
    STATE_SSPLIT_ISOCHRONOUS_OUT_DATA0,
    STATE_SSPLIT_ISOCHRONOUS_IN,
    STATE_CSPLIT_ISOCHRONOUS,
    STATE_CSPLIT_ISOCHRONOUS_IN,
    STATE_CSPLIT_ISOCHRONOUS_IN_DATA0,
    STATE_CSPLIT_ISOCHRONOUS_IN_MDATA,
    STATE_CSPLIT_ISOCHRONOUS_IN_ERR,
    STATE_CSPLIT_ISOCHRONOUS_IN_NYET,
    /* USB 2.0 ECN: Link Power Management (LPM) */
    STATE_EXT,
    STATE_SUBPID_INVALID,
    STATE_SUBPID_NOT_REUSABLE,
    STATE_SUBPID_LPM,
    STATE_SUBPID_LPM_ACK,
    STATE_SUBPID_LPM_NYET,
    STATE_SUBPID_LPM_STALL,
    STATE_SUBPID_RESERVED,
} usbll_state_t;

typedef enum usbll_ep_type {
    USBLL_EP_UNKNOWN,
    USBLL_EP_CONTROL,
    USBLL_EP_BULK,
    USBLL_EP_INTERRUPT,
    USBLL_EP_ISOCHRONOUS,
} usbll_ep_type_t;

/* usbll_address_t represents the address
 * of Host, Hub and Devices.
 */
typedef struct {
    uint8_t flags;       /* flags    - Contains information if address is
                         *            Host, Hub, Device or Broadcast.
                         */
    uint8_t device;      /* device   - Device or Hub Address */
    uint8_t endpoint;    /* endpoint - It represents endpoint number for
                         *            Device and port number for Hub.
                         */
} usbll_address_t;

typedef struct usbll_transaction_info {
    uint32_t starts_in;
    uint8_t pid;
    uint8_t address;
    uint8_t endpoint;
    usb_speed_t speed;
    struct usbll_transaction_info *split_start;
    struct usbll_transaction_info *split_complete;
} usbll_transaction_info_t;

typedef struct usbll_transfer_info {
    /* First data packet number, used as reassembly key */
    uint32_t first_packet;
    /* Offset this packet starts at */
    uint32_t offset;
    usbll_ep_type_t type;
    /* true if data from host to device, false when from device to host */
    bool from_host;
    /* false if this is the last packet */
    bool more_frags;
} usbll_transfer_info_t;

/* USB is a stateful protocol. The addresses of Data Packets
 * and Handshake Packets depend on the packets before them.
 *
 * We maintain a static global pointer of the type usbll_data_t.
 * Maintaining a pointer instead of a conversation helps in reducing
 * memory usage, taking the following advantages:
 * 1. Packets are always ordered.
 * 2. Addresses of packets only up to last 3 packets are required.
 *
 * Previous pointer is used in the initial pass to link packets
 * into transactions.
 */
typedef struct usbll_data {
    usbll_state_t transaction_state;
    usbll_transaction_info_t *transaction;
    struct usbll_data *prev;
    struct usbll_data *next;
} usbll_data_t;

static usbll_data_t *usbll_data_ptr;

/* Transaction Translator arrays used only during first pass. */
static usbll_transaction_info_t ***tt_non_periodic;
static usbll_transaction_info_t ***tt_periodic;

typedef enum usbll_transfer_data {
    USBLL_TRANSFER_NORMAL,
    USBLL_TRANSFER_GET_DEVICE_DESCRIPTOR,
} usbll_transfer_data_t;

typedef struct usbll_endpoint_info {
    usbll_ep_type_t type;
    usbll_transfer_data_t data;
    /* Maximum packet size, 0 if not known */
    uint16_t max_packet_size;
    /* DATA0/DATA1 tracking to detect retransmissions */
    uint8_t last_data_pid;
    /* true if last data packet was acknowledged */
    bool last_data_acked;
    /* Current transfer key, 0 if no transfer in progress */
    uint32_t active_transfer_key;
    /* Offset where next packet should start at */
    uint32_t transfer_offset;
    /* Last data packet length that was part of transfer */
    uint32_t last_data_len;
    /* Transfer length if known, 0 if unknown */
    uint32_t requested_transfer_length;
} usbll_endpoint_info_t;

/* Endpoint info arrays used only during first pass. */
static usbll_endpoint_info_t **ep_info_in;
static usbll_endpoint_info_t **ep_info_out;

static unsigned usbll_fragment_key_hash(const void *k)
{
    return GPOINTER_TO_UINT(k);
}

static int usbll_fragment_key_equal(const void *k1, const void *k2)
{
    return GPOINTER_TO_UINT(k1) == GPOINTER_TO_UINT(k2);
}

static void *usbll_fragment_key(const packet_info *pinfo _U_, const uint32_t id, const void *data _U_)
{
    return GUINT_TO_POINTER(id);
}

static void usbll_fragment_free_key(void *ptr _U_)
{
    /* there's nothing to be freed */
}

static const reassembly_table_functions usbll_reassembly_table_functions = {
    .hash_func = usbll_fragment_key_hash,
    .equal_func = usbll_fragment_key_equal,
    .temporary_key_func = usbll_fragment_key,
    .persistent_key_func = usbll_fragment_key,
    .free_temporary_key_func = usbll_fragment_free_key,
    .free_persistent_key_func = usbll_fragment_free_key,
};

static usbll_state_t
usbll_next_state(usbll_state_t state, uint8_t pid)
{
    if (state == STATE_EXT)
    {
        switch (pid)
        {
            case USB_SUBPID_RESERVED_MDATA:        return STATE_SUBPID_RESERVED;
            case USB_SUBPID_RESERVED_STALL:        return STATE_SUBPID_RESERVED;
            case USB_SUBPID_CONFLICT_SETUP:        return STATE_SUBPID_NOT_REUSABLE;
            case USB_SUBPID_CONFLICT_PRE:          return STATE_SUBPID_NOT_REUSABLE;
            case USB_SUBPID_RESERVED_DATA1:        return STATE_SUBPID_RESERVED;
            case USB_SUBPID_RESERVED_NAK:          return STATE_SUBPID_RESERVED;
            case USB_SUBPID_CONFLICT_IN:           return STATE_SUBPID_NOT_REUSABLE;
            case USB_SUBPID_CONFLICT_SPLIT:        return STATE_SUBPID_NOT_REUSABLE;
            case USB_SUBPID_RESERVED_DATA2:        return STATE_SUBPID_RESERVED;
            case USB_SUBPID_RESERVED_NYET:         return STATE_SUBPID_RESERVED;
            case USB_SUBPID_CONFLICT_SOF:          return STATE_SUBPID_NOT_REUSABLE;
            case USB_SUBPID_CONFLICT_PING:         return STATE_SUBPID_NOT_REUSABLE;
            case USB_SUBPID_LPM:                   return STATE_SUBPID_LPM;
            case USB_SUBPID_RESERVED_ACK:          return STATE_SUBPID_RESERVED;
            case USB_SUBPID_CONFLICT_OUT:          return STATE_SUBPID_NOT_REUSABLE;
            case USB_SUBPID_RESERVED_EXT:          return STATE_SUBPID_RESERVED;
            default:                               return STATE_SUBPID_INVALID;
        }
    }
    else if (pid == USB_PID_SPECIAL_EXT)
    {
        return STATE_EXT;
    }
    else if (pid == USB_PID_TOKEN_SOF)
    {
        return STATE_IDLE;
    }
    else if (pid == USB_PID_SPECIAL_PING)
    {
        return STATE_PING;
    }
    else if (pid == USB_PID_TOKEN_SETUP)
    {
        switch (state)
        {
            case STATE_SSPLIT_CONTROL:             return STATE_SSPLIT_CONTROL_SETUP;
            case STATE_CSPLIT_CONTROL:             return STATE_CSPLIT_CONTROL_SETUP;
            default:                               return STATE_SETUP;
        }
    }
    else if (pid == USB_PID_TOKEN_OUT)
    {
        switch (state)
        {
            case STATE_SSPLIT_CONTROL:             return STATE_SSPLIT_CONTROL_OUT;
            case STATE_CSPLIT_CONTROL:             return STATE_CSPLIT_CONTROL_OUT;
            case STATE_SSPLIT_BULK:                return STATE_SSPLIT_BULK_OUT;
            case STATE_CSPLIT_BULK:                return STATE_CSPLIT_BULK_OUT;
            case STATE_SSPLIT_INTERRUPT:           return STATE_SSPLIT_INTERRUPT_OUT;
            case STATE_CSPLIT_INTERRUPT:           return STATE_CSPLIT_INTERRUPT_OUT;
            case STATE_SSPLIT_ISOCHRONOUS:         return STATE_SSPLIT_ISOCHRONOUS_OUT;
            default:                               return STATE_OUT;
        }
    }
    else if (pid == USB_PID_TOKEN_IN)
    {
        switch (state)
        {
            case STATE_SSPLIT_CONTROL:             return STATE_SSPLIT_CONTROL_IN;
            case STATE_CSPLIT_CONTROL:             return STATE_CSPLIT_CONTROL_IN;
            case STATE_SSPLIT_BULK:                return STATE_SSPLIT_BULK_IN;
            case STATE_CSPLIT_BULK:                return STATE_CSPLIT_BULK_IN;
            case STATE_SSPLIT_INTERRUPT:           return STATE_SSPLIT_INTERRUPT_IN;
            case STATE_CSPLIT_INTERRUPT:           return STATE_CSPLIT_INTERRUPT_IN;
            case STATE_SSPLIT_ISOCHRONOUS:         return STATE_SSPLIT_ISOCHRONOUS_IN;
            case STATE_CSPLIT_ISOCHRONOUS:         return STATE_CSPLIT_ISOCHRONOUS_IN;
            default:                               return STATE_IN;
        }
    }
    else if (pid == USB_PID_DATA_DATA0)
    {
        switch (state)
        {
            case STATE_IN:                         return STATE_IN_DATA0;
            case STATE_OUT:                        return STATE_OUT_DATA0;
            case STATE_SETUP:                      return STATE_SETUP_DATA0;
            case STATE_SSPLIT_CONTROL_SETUP:       return STATE_SSPLIT_CONTROL_SETUP_DATA0;
            case STATE_SSPLIT_CONTROL_OUT:         return STATE_SSPLIT_CONTROL_OUT_DATA0;
            case STATE_CSPLIT_CONTROL_IN:          return STATE_CSPLIT_CONTROL_IN_DATA0;
            case STATE_SSPLIT_BULK_OUT:            return STATE_SSPLIT_BULK_OUT_DATA0;
            case STATE_CSPLIT_BULK_IN:             return STATE_CSPLIT_BULK_IN_DATA0;
            case STATE_SSPLIT_INTERRUPT_OUT:       return STATE_SSPLIT_INTERRUPT_OUT_DATA0;
            case STATE_CSPLIT_INTERRUPT_IN:        return STATE_CSPLIT_INTERRUPT_IN_DATA0;
            case STATE_SSPLIT_ISOCHRONOUS_OUT:     return STATE_SSPLIT_ISOCHRONOUS_OUT_DATA0;
            case STATE_CSPLIT_ISOCHRONOUS_IN:      return STATE_CSPLIT_ISOCHRONOUS_IN_DATA0;
            default:                               return STATE_INVALID;
        }
    }
    else if (pid == USB_PID_DATA_DATA1)
    {
        switch (state)
        {
            case STATE_IN:                         return STATE_IN_DATA1;
            case STATE_OUT:                        return STATE_OUT_DATA1;
            case STATE_SSPLIT_CONTROL_OUT:         return STATE_SSPLIT_CONTROL_OUT_DATA1;
            case STATE_CSPLIT_CONTROL_IN:          return STATE_CSPLIT_CONTROL_IN_DATA1;
            case STATE_SSPLIT_BULK_OUT:            return STATE_SSPLIT_BULK_OUT_DATA1;
            case STATE_CSPLIT_BULK_IN:             return STATE_CSPLIT_BULK_IN_DATA1;
            case STATE_SSPLIT_INTERRUPT_OUT:       return STATE_SSPLIT_INTERRUPT_OUT_DATA1;
            case STATE_CSPLIT_INTERRUPT_IN:        return STATE_CSPLIT_INTERRUPT_IN_DATA1;
            default:                               return STATE_INVALID;
        }
    }
    else if (pid == USB_PID_DATA_DATA2)
    {
        switch (state)
        {
            case STATE_IN:                         return STATE_IN_HS_ISOCHRONOUS_DATA2;
            default:                               return STATE_INVALID;
        }
    }
    else if (pid == USB_PID_DATA_MDATA)
    {
        switch (state)
        {
            case STATE_OUT:                        return STATE_OUT_HS_ISOCHRONOUS_MDATA;
            case STATE_CSPLIT_INTERRUPT_IN:        return STATE_CSPLIT_INTERRUPT_IN_MDATA;
            case STATE_CSPLIT_ISOCHRONOUS_IN:      return STATE_CSPLIT_ISOCHRONOUS_IN_MDATA;
            default:                               return STATE_INVALID;
        }
    }
    else if (pid == USB_PID_HANDSHAKE_ACK)
    {
        switch (state)
        {
            case STATE_IN_DATA0:                   return STATE_IN_ACK;
            case STATE_IN_DATA1:                   return STATE_IN_ACK;
            case STATE_OUT_DATA0:                  return STATE_OUT_ACK;
            case STATE_OUT_DATA1:                  return STATE_OUT_ACK;
            case STATE_PING:                       return STATE_PING_ACK;
            case STATE_SETUP_DATA0:                return STATE_SETUP_ACK;
            case STATE_SSPLIT_CONTROL_SETUP_DATA0: return STATE_SSPLIT_CONTROL_SETUP_ACK;
            case STATE_CSPLIT_CONTROL_SETUP:       return STATE_CSPLIT_CONTROL_SETUP_ACK;
            case STATE_SSPLIT_CONTROL_OUT_DATA0:   return STATE_SSPLIT_CONTROL_OUT_ACK;
            case STATE_SSPLIT_CONTROL_OUT_DATA1:   return STATE_SSPLIT_CONTROL_OUT_ACK;
            case STATE_CSPLIT_CONTROL_OUT:         return STATE_CSPLIT_CONTROL_OUT_ACK;
            case STATE_SSPLIT_CONTROL_IN:          return STATE_SSPLIT_CONTROL_IN_ACK;
            case STATE_SSPLIT_BULK_OUT_DATA0:      return STATE_SSPLIT_BULK_OUT_ACK;
            case STATE_SSPLIT_BULK_OUT_DATA1:      return STATE_SSPLIT_BULK_OUT_ACK;
            case STATE_SSPLIT_BULK_IN:             return STATE_SSPLIT_BULK_IN_ACK;
            case STATE_CSPLIT_BULK_OUT:            return STATE_CSPLIT_BULK_OUT_ACK;
            case STATE_CSPLIT_INTERRUPT_OUT:       return STATE_CSPLIT_INTERRUPT_OUT_ACK;
            case STATE_SUBPID_LPM:                 return STATE_SUBPID_LPM_ACK;
            default:                               return STATE_INVALID;
        }
    }
    else if (pid == USB_PID_HANDSHAKE_NAK)
    {
        switch (state)
        {
            case STATE_IN:                         return STATE_IN_NAK;
            case STATE_OUT_DATA0:                  return STATE_OUT_NAK;
            case STATE_OUT_DATA1:                  return STATE_OUT_NAK;
            case STATE_PING:                       return STATE_PING_NAK;
            case STATE_SSPLIT_CONTROL_SETUP_DATA0: return STATE_SSPLIT_CONTROL_SETUP_NAK;
            case STATE_SSPLIT_CONTROL_OUT_DATA0:   return STATE_SSPLIT_CONTROL_OUT_NAK;
            case STATE_SSPLIT_CONTROL_OUT_DATA1:   return STATE_SSPLIT_CONTROL_OUT_NAK;
            case STATE_SSPLIT_CONTROL_IN:          return STATE_SSPLIT_CONTROL_IN_NAK;
            case STATE_CSPLIT_CONTROL_OUT:         return STATE_CSPLIT_CONTROL_OUT_NAK;
            case STATE_CSPLIT_CONTROL_IN:          return STATE_CSPLIT_CONTROL_IN_NAK;
            case STATE_SSPLIT_BULK_OUT_DATA0:      return STATE_SSPLIT_BULK_OUT_NAK;
            case STATE_SSPLIT_BULK_OUT_DATA1:      return STATE_SSPLIT_BULK_OUT_NAK;
            case STATE_SSPLIT_BULK_IN:             return STATE_SSPLIT_BULK_IN_NAK;
            case STATE_CSPLIT_BULK_OUT:            return STATE_CSPLIT_BULK_OUT_NAK;
            case STATE_CSPLIT_BULK_IN:             return STATE_CSPLIT_BULK_IN_NAK;
            case STATE_CSPLIT_INTERRUPT_OUT:       return STATE_CSPLIT_INTERRUPT_OUT_NAK;
            case STATE_CSPLIT_INTERRUPT_IN:        return STATE_CSPLIT_INTERRUPT_IN_NAK;
            default:                               return STATE_INVALID;
        }
    }
    else if (pid == USB_PID_HANDSHAKE_STALL)
    {
        switch (state)
        {
            case STATE_IN:                         return STATE_IN_STALL;
            case STATE_OUT_DATA0:                  return STATE_OUT_STALL;
            case STATE_OUT_DATA1:                  return STATE_OUT_STALL;
            case STATE_PING:                       return STATE_PING_STALL;
            case STATE_CSPLIT_CONTROL_OUT:         return STATE_CSPLIT_CONTROL_OUT_STALL;
            case STATE_CSPLIT_CONTROL_IN:          return STATE_CSPLIT_CONTROL_IN_STALL;
            case STATE_CSPLIT_BULK_OUT:            return STATE_CSPLIT_BULK_OUT_STALL;
            case STATE_CSPLIT_BULK_IN:             return STATE_CSPLIT_BULK_IN_STALL;
            case STATE_CSPLIT_INTERRUPT_OUT:       return STATE_CSPLIT_INTERRUPT_OUT_STALL;
            case STATE_CSPLIT_INTERRUPT_IN:        return STATE_CSPLIT_INTERRUPT_IN_STALL;
            case STATE_SUBPID_LPM:                 return STATE_SUBPID_LPM_STALL;
            default:                               return STATE_INVALID;
        }
    }
    else if (pid == USB_PID_HANDSHAKE_NYET)
    {
        /* Allowed only in High-Speed */
        switch (state)
        {
            case STATE_OUT_DATA0:                return STATE_OUT_NYET;
            case STATE_OUT_DATA1:                return STATE_OUT_NYET;
            case STATE_CSPLIT_CONTROL_SETUP:     return STATE_CSPLIT_CONTROL_SETUP_NYET;
            case STATE_CSPLIT_CONTROL_OUT:       return STATE_CSPLIT_CONTROL_OUT_NYET;
            case STATE_CSPLIT_CONTROL_IN:        return STATE_CSPLIT_CONTROL_IN_NYET;
            case STATE_CSPLIT_BULK_OUT:          return STATE_CSPLIT_BULK_OUT_NYET;
            case STATE_CSPLIT_BULK_IN:           return STATE_CSPLIT_BULK_IN_NYET;
            case STATE_CSPLIT_INTERRUPT_OUT:     return STATE_CSPLIT_INTERRUPT_OUT_NYET;
            case STATE_CSPLIT_INTERRUPT_IN:      return STATE_CSPLIT_INTERRUPT_IN_NYET;
            case STATE_CSPLIT_ISOCHRONOUS_IN:    return STATE_CSPLIT_ISOCHRONOUS_IN_NYET;
            case STATE_SUBPID_LPM:               return STATE_SUBPID_LPM_NYET;
            default:                             return STATE_INVALID;
        }
    }
    else if (pid == USB_PID_SPECIAL_PRE_OR_ERR)
    {
        switch (state)
        {
            case STATE_CSPLIT_INTERRUPT_OUT:     return STATE_CSPLIT_INTERRUPT_OUT_ERR;
            case STATE_CSPLIT_INTERRUPT_IN:      return STATE_CSPLIT_INTERRUPT_IN_ERR;
            case STATE_CSPLIT_ISOCHRONOUS_IN:    return STATE_CSPLIT_ISOCHRONOUS_IN_ERR;
            default:                             return STATE_IDLE;
        }
    }

    /* SPLIT is not suitable for this function as the state cannot be
     * determined by looking solely at PID.
     */
    DISSECTOR_ASSERT(pid != USB_PID_SPECIAL_SPLIT);

    return STATE_IDLE;
}

static bool usbll_is_non_periodic_split_start_token(usbll_state_t state)
{
    switch (state)
    {
        case STATE_SSPLIT_CONTROL_SETUP:
        case STATE_SSPLIT_CONTROL_OUT:
        case STATE_SSPLIT_CONTROL_IN:
        case STATE_SSPLIT_BULK_OUT:
        case STATE_SSPLIT_BULK_IN:
            return true;
        default:
            return false;
    }

}
static bool usbll_is_periodic_split_start_token(usbll_state_t state)
{
    switch (state)
    {
        case STATE_SSPLIT_INTERRUPT_OUT:
        case STATE_SSPLIT_INTERRUPT_IN:
        case STATE_SSPLIT_ISOCHRONOUS_OUT:
        case STATE_SSPLIT_ISOCHRONOUS_IN:
            return true;
        default:
            return false;
    }

}
static bool usbll_is_split_start_token(usbll_state_t state)
{
    return usbll_is_non_periodic_split_start_token(state) || usbll_is_periodic_split_start_token(state);
}

static bool usbll_is_non_periodic_split_complete_token(usbll_state_t state)
{
    switch (state)
    {
        case STATE_CSPLIT_CONTROL_SETUP:
        case STATE_CSPLIT_CONTROL_OUT:
        case STATE_CSPLIT_CONTROL_IN:
        case STATE_CSPLIT_BULK_OUT:
        case STATE_CSPLIT_BULK_IN:
            return true;
        default:
            return false;
    }
}

static bool usbll_is_periodic_split_complete_token(usbll_state_t state)
{
    switch (state)
    {
        case STATE_CSPLIT_INTERRUPT_OUT:
        case STATE_CSPLIT_INTERRUPT_IN:
        case STATE_CSPLIT_ISOCHRONOUS_IN:
            return true;
        default:
            return false;
    }
}

static bool usbll_is_split_complete_token(usbll_state_t state)
{
    return usbll_is_non_periodic_split_complete_token(state) || usbll_is_periodic_split_complete_token(state);
}

static bool usbll_is_split_token(usbll_state_t state)
{
    return usbll_is_split_start_token(state) || usbll_is_split_complete_token(state);
}

static bool usbll_is_non_split_token(usbll_state_t state)
{
    switch (state)
    {
        case STATE_IN:
        case STATE_OUT:
        case STATE_PING:
        case STATE_SETUP:
        case STATE_EXT:
            return true;
        default:
            return false;
    }
}

static bool usbll_is_extended_subpid(usbll_state_t state)
{
    switch (state)
    {
        case STATE_SUBPID_INVALID:
        case STATE_SUBPID_NOT_REUSABLE:
        case STATE_SUBPID_LPM:
        case STATE_SUBPID_RESERVED:
            return true;
        default:
            return false;
    }
}

static bool usbll_is_setup_data(usbll_state_t state)
{
    switch (state)
    {
        case STATE_SETUP_DATA0:
        case STATE_SSPLIT_CONTROL_SETUP_DATA0:
            return true;
        default:
            return false;
    }
}

static bool usbll_is_data_from_host(usbll_state_t state)
{
    switch (state)
    {
        case STATE_OUT_DATA0:
        case STATE_OUT_DATA1:
        case STATE_OUT_HS_ISOCHRONOUS_DATA2:
        case STATE_OUT_HS_ISOCHRONOUS_MDATA:
        case STATE_SETUP_DATA0:
        case STATE_SSPLIT_CONTROL_SETUP_DATA0:
        case STATE_SSPLIT_CONTROL_OUT_DATA0:
        case STATE_SSPLIT_CONTROL_OUT_DATA1:
        case STATE_SSPLIT_BULK_OUT_DATA0:
        case STATE_SSPLIT_BULK_OUT_DATA1:
        case STATE_SSPLIT_INTERRUPT_OUT_DATA0:
        case STATE_SSPLIT_INTERRUPT_OUT_DATA1:
        case STATE_SSPLIT_ISOCHRONOUS_OUT_DATA0:
            return true;
        case STATE_IN_DATA0:
        case STATE_IN_DATA1:
        case STATE_IN_HS_ISOCHRONOUS_DATA2:
        case STATE_CSPLIT_CONTROL_IN_DATA0:
        case STATE_CSPLIT_CONTROL_IN_DATA1:
        case STATE_CSPLIT_BULK_IN_DATA0:
        case STATE_CSPLIT_BULK_IN_DATA1:
        case STATE_CSPLIT_INTERRUPT_IN_MDATA:
        case STATE_CSPLIT_INTERRUPT_IN_DATA0:
        case STATE_CSPLIT_INTERRUPT_IN_DATA1:
        case STATE_CSPLIT_ISOCHRONOUS_IN_DATA0:
        case STATE_CSPLIT_ISOCHRONOUS_IN_MDATA:
            return false;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }
}

static bool usbll_is_split_data_from_device(usbll_state_t state)
{
    switch (state)
    {
        case STATE_CSPLIT_CONTROL_IN_DATA0:
        case STATE_CSPLIT_CONTROL_IN_DATA1:
        case STATE_CSPLIT_BULK_IN_DATA0:
        case STATE_CSPLIT_BULK_IN_DATA1:
        case STATE_CSPLIT_INTERRUPT_IN_MDATA:
        case STATE_CSPLIT_INTERRUPT_IN_DATA0:
        case STATE_CSPLIT_INTERRUPT_IN_DATA1:
        case STATE_CSPLIT_ISOCHRONOUS_IN_DATA0:
        case STATE_CSPLIT_ISOCHRONOUS_IN_MDATA:
            return true;
        default:
            return false;
    }
}

static bool usbll_is_setup_ack(usbll_state_t state)
{
    switch (state)
    {
        case STATE_SETUP_ACK:
        case STATE_CSPLIT_CONTROL_SETUP_ACK:
            return true;
        default:
            return false;
    }
}

static bool usbll_is_data_ack(usbll_state_t state)
{
    switch (state)
    {
        case STATE_IN_ACK:
        case STATE_OUT_ACK:
        case STATE_OUT_NYET:
        case STATE_CSPLIT_CONTROL_OUT_ACK:
        case STATE_CSPLIT_BULK_OUT_ACK:
        case STATE_CSPLIT_INTERRUPT_OUT_ACK:
            return true;
        default:
            return false;
    }
}

static bool usbll_is_acked_data_from_host(usbll_state_t state)
{
    switch (state)
    {
        case STATE_OUT_ACK:
        case STATE_OUT_NYET:
        case STATE_CSPLIT_CONTROL_OUT_ACK:
        case STATE_CSPLIT_BULK_OUT_ACK:
        case STATE_CSPLIT_INTERRUPT_OUT_ACK:
            return true;
        case STATE_IN_ACK:
            return false;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }
}

static bool usbll_is_endpoint_stall(usbll_state_t state)
{
    switch (state)
    {
        case STATE_IN_STALL:
        case STATE_OUT_STALL:
        case STATE_PING_STALL:
        case STATE_CSPLIT_CONTROL_OUT_STALL:
        case STATE_CSPLIT_CONTROL_IN_STALL:
        case STATE_CSPLIT_BULK_OUT_STALL:
        case STATE_CSPLIT_BULK_IN_STALL:
        case STATE_CSPLIT_INTERRUPT_OUT_STALL:
        case STATE_CSPLIT_INTERRUPT_IN_STALL:
            return true;
        default:
            return false;
    }
}

static bool usbll_is_stalled_data_from_host(usbll_state_t state)
{
    switch (state)
    {
        case STATE_OUT_STALL:
        case STATE_PING_STALL:
        case STATE_CSPLIT_CONTROL_OUT_STALL:
        case STATE_CSPLIT_BULK_OUT_STALL:
        case STATE_CSPLIT_INTERRUPT_OUT_STALL:
            return true;
        case STATE_IN_STALL:
        case STATE_CSPLIT_CONTROL_IN_STALL:
        case STATE_CSPLIT_BULK_IN_STALL:
        case STATE_CSPLIT_INTERRUPT_IN_STALL:
            return false;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }
}

static usb_speed_t usbll_get_data_transaction_speed(usbll_data_t *data)
{
    switch (data->transaction_state)
    {
        case STATE_IN_DATA0:
        case STATE_IN_DATA1:
        case STATE_IN_HS_ISOCHRONOUS_DATA2:
        case STATE_IN_STALL:
        case STATE_OUT_DATA0:
        case STATE_OUT_DATA1:
        case STATE_OUT_HS_ISOCHRONOUS_DATA2:
        case STATE_OUT_HS_ISOCHRONOUS_MDATA:
        case STATE_OUT_STALL:
        case STATE_PING_STALL:
        case STATE_SETUP_DATA0:
            DISSECTOR_ASSERT(data->transaction != NULL);
            return data->transaction->speed;
        case STATE_SSPLIT_CONTROL_SETUP_DATA0:
        case STATE_SSPLIT_CONTROL_OUT_DATA0:
        case STATE_SSPLIT_CONTROL_OUT_DATA1:
        case STATE_SSPLIT_BULK_OUT_DATA0:
        case STATE_SSPLIT_BULK_OUT_DATA1:
        case STATE_SSPLIT_INTERRUPT_OUT_DATA0:
        case STATE_SSPLIT_INTERRUPT_OUT_DATA1:
        case STATE_SSPLIT_ISOCHRONOUS_OUT_DATA0:
            DISSECTOR_ASSERT(data->transaction != NULL);
            DISSECTOR_ASSERT(data->transaction->split_start != NULL);
            return data->transaction->split_start->speed;
        case STATE_CSPLIT_CONTROL_OUT_STALL:
        case STATE_CSPLIT_CONTROL_IN_DATA0:
        case STATE_CSPLIT_CONTROL_IN_DATA1:
        case STATE_CSPLIT_CONTROL_IN_STALL:
        case STATE_CSPLIT_BULK_OUT_STALL:
        case STATE_CSPLIT_BULK_IN_DATA0:
        case STATE_CSPLIT_BULK_IN_DATA1:
        case STATE_CSPLIT_BULK_IN_STALL:
        case STATE_CSPLIT_INTERRUPT_OUT_STALL:
        case STATE_CSPLIT_INTERRUPT_IN_MDATA:
        case STATE_CSPLIT_INTERRUPT_IN_DATA0:
        case STATE_CSPLIT_INTERRUPT_IN_DATA1:
        case STATE_CSPLIT_INTERRUPT_IN_STALL:
        case STATE_CSPLIT_ISOCHRONOUS_IN_DATA0:
        case STATE_CSPLIT_ISOCHRONOUS_IN_MDATA:
            DISSECTOR_ASSERT(data->transaction != NULL);
            DISSECTOR_ASSERT(data->transaction->split_complete != NULL);
            return data->transaction->split_complete->speed;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }
}

static int usbll_addr_to_str(const address* addr, char *buf, int buf_len)
{
    const usbll_address_t *addrp = (const usbll_address_t *)addr->data;

    if (addrp->flags & USBLL_ADDRESS_HOST) {
        (void) g_strlcpy(buf, "host", buf_len);
    } else if (addrp->flags & USBLL_ADDRESS_BROADCAST) {
        (void) g_strlcpy(buf, "broadcast", buf_len);
    } else if (addrp->flags & USBLL_ADDRESS_HUB_PORT) {
        /*
         * In split transaction we use : to mark that the last part is port not
         * endpoint.
         */
        snprintf(buf, buf_len, "%d:%d", addrp->device,
                       addrp->endpoint);
    } else {
        /* Just a standard address.endpoint notation. */
        snprintf(buf, buf_len, "%d.%d", addrp->device,
                       addrp->endpoint);
    }

    return (int)(strlen(buf)+1);
}

static int usbll_addr_str_len(const address* addr _U_)
{
    return 50; /* The same as for usb. */
}

static void
usbll_set_address(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
                  uint8_t device, uint8_t endpoint, uint8_t flags)
{
    proto_item     *sub_item;
    usbll_address_t *src_addr, *dst_addr;
    uint8_t *str_src_addr, *str_dst_addr;

    src_addr = wmem_new0(pinfo->pool, usbll_address_t);
    dst_addr = wmem_new0(pinfo->pool, usbll_address_t);

    if (USBLL_ADDRESS_IS_HOST_TO_DEV(flags)) {
        src_addr->flags = USBLL_ADDRESS_HOST;

        if (flags & USBLL_ADDRESS_BROADCAST) {
            dst_addr->flags = USBLL_ADDRESS_BROADCAST;
            pinfo->ptype = PT_NONE;
        } else {
            dst_addr->device = device;
            dst_addr->endpoint = endpoint;
            if (flags & USBLL_ADDRESS_HUB_PORT) {
                dst_addr->flags = USBLL_ADDRESS_HUB_PORT;
                pinfo->ptype = PT_NONE;
            } else {
                pinfo->ptype = PT_USB;
                pinfo->destport = dst_addr->endpoint;
            }
        }
    } else {
        dst_addr->flags = USBLL_ADDRESS_HOST;
        src_addr->device = device;
        src_addr->endpoint = endpoint;
        if (flags & USBLL_ADDRESS_HUB_PORT) {
            src_addr->flags = USBLL_ADDRESS_HUB_PORT;
            pinfo->ptype = PT_NONE;
        } else {
            pinfo->ptype = PT_USB;
            pinfo->srcport = src_addr->endpoint;
            pinfo->destport = NO_ENDPOINT;
        }
    }

    pinfo->p2p_dir = USBLL_ADDRESS_IS_HOST_TO_DEV(flags) ? P2P_DIR_SENT : P2P_DIR_RECV;

    set_address(&pinfo->net_src, usbll_address_type, sizeof(usbll_address_t), (char *)src_addr);
    copy_address_shallow(&pinfo->src, &pinfo->net_src);

    set_address(&pinfo->net_dst, usbll_address_type, sizeof(usbll_address_t), (char *)dst_addr);
    copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

    str_src_addr = address_to_str(pinfo->pool, &pinfo->src);
    str_dst_addr = address_to_str(pinfo->pool, &pinfo->dst);

    sub_item = proto_tree_add_string(tree, hf_usbll_src, tvb, 0, 0, str_src_addr);
    proto_item_set_generated(sub_item);

    sub_item = proto_tree_add_string(tree, hf_usbll_addr, tvb, 0, 0, str_src_addr);
    proto_item_set_hidden(sub_item);

    sub_item = proto_tree_add_string(tree, hf_usbll_dst, tvb, 0, 0, str_dst_addr);
    proto_item_set_generated(sub_item);

    sub_item = proto_tree_add_string(tree, hf_usbll_addr, tvb, 0, 0, str_dst_addr);
    proto_item_set_hidden(sub_item);
}

static void
usbll_generate_address(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, usbll_data_t *data)
{
    switch (data->transaction_state)
    {
        case STATE_IDLE:
        case STATE_INVALID:
            /* Do not set address if we are not sure about it */
            break;
        case STATE_IN:
        case STATE_IN_ACK:
        case STATE_OUT:
        case STATE_OUT_DATA0:
        case STATE_OUT_DATA1:
        case STATE_OUT_HS_ISOCHRONOUS_DATA2:
        case STATE_OUT_HS_ISOCHRONOUS_MDATA:
        case STATE_PING:
        case STATE_SETUP:
        case STATE_SETUP_DATA0:
        case STATE_EXT:
        case STATE_SUBPID_INVALID:
        case STATE_SUBPID_NOT_REUSABLE:
        case STATE_SUBPID_LPM:
        case STATE_SUBPID_RESERVED:
            DISSECTOR_ASSERT(data->transaction != NULL);
            usbll_set_address(tree, tvb, pinfo,
                              data->transaction->address, data->transaction->endpoint,
                              USBLL_ADDRESS_HOST_TO_DEV);
            break;
        case STATE_IN_DATA0:
        case STATE_IN_DATA1:
        case STATE_IN_HS_ISOCHRONOUS_DATA2:
        case STATE_IN_NAK:
        case STATE_IN_STALL:
        case STATE_OUT_ACK:
        case STATE_OUT_NAK:
        case STATE_OUT_STALL:
        case STATE_OUT_NYET:
        case STATE_PING_ACK:
        case STATE_PING_NAK:
        case STATE_PING_STALL:
        case STATE_SETUP_ACK:
        case STATE_SUBPID_LPM_ACK:
        case STATE_SUBPID_LPM_NYET:
        case STATE_SUBPID_LPM_STALL:
            DISSECTOR_ASSERT(data->transaction != NULL);
            usbll_set_address(tree, tvb, pinfo,
                              data->transaction->address, data->transaction->endpoint,
                              USBLL_ADDRESS_DEV_TO_HOST);
            break;
        case STATE_SSPLIT_CONTROL:
        case STATE_CSPLIT_CONTROL:
        case STATE_SSPLIT_BULK:
        case STATE_CSPLIT_BULK:
        case STATE_SSPLIT_INTERRUPT:
        case STATE_CSPLIT_INTERRUPT:
        case STATE_SSPLIT_ISOCHRONOUS:
        case STATE_CSPLIT_ISOCHRONOUS:
            DISSECTOR_ASSERT(data->transaction != NULL);
            usbll_set_address(tree, tvb, pinfo,
                              data->transaction->address, data->transaction->endpoint,
                              USBLL_ADDRESS_HOST_TO_DEV | USBLL_ADDRESS_HUB_PORT);
            break;
        case STATE_SSPLIT_CONTROL_SETUP:
        case STATE_SSPLIT_CONTROL_SETUP_DATA0:
        case STATE_SSPLIT_CONTROL_OUT:
        case STATE_SSPLIT_CONTROL_OUT_DATA0:
        case STATE_SSPLIT_CONTROL_OUT_DATA1:
        case STATE_SSPLIT_CONTROL_IN:
        case STATE_SSPLIT_BULK_OUT:
        case STATE_SSPLIT_BULK_OUT_DATA0:
        case STATE_SSPLIT_BULK_OUT_DATA1:
        case STATE_SSPLIT_BULK_IN:
        case STATE_SSPLIT_INTERRUPT_OUT:
        case STATE_SSPLIT_INTERRUPT_OUT_DATA0:
        case STATE_SSPLIT_INTERRUPT_OUT_DATA1:
        case STATE_SSPLIT_INTERRUPT_IN:
        case STATE_SSPLIT_ISOCHRONOUS_OUT:
        case STATE_SSPLIT_ISOCHRONOUS_OUT_DATA0:
        case STATE_SSPLIT_ISOCHRONOUS_IN:
            DISSECTOR_ASSERT(data->transaction != NULL);
            DISSECTOR_ASSERT(data->transaction->split_start != NULL);
            usbll_set_address(tree, tvb, pinfo,
                              data->transaction->address, data->transaction->endpoint,
                              USBLL_ADDRESS_HOST_TO_DEV);
            break;
        case STATE_SSPLIT_CONTROL_SETUP_ACK:
        case STATE_SSPLIT_CONTROL_SETUP_NAK:
        case STATE_SSPLIT_CONTROL_OUT_ACK:
        case STATE_SSPLIT_CONTROL_OUT_NAK:
        case STATE_SSPLIT_CONTROL_IN_ACK:
        case STATE_SSPLIT_CONTROL_IN_NAK:
        case STATE_SSPLIT_BULK_OUT_ACK:
        case STATE_SSPLIT_BULK_OUT_NAK:
        case STATE_SSPLIT_BULK_IN_ACK:
        case STATE_SSPLIT_BULK_IN_NAK:
            DISSECTOR_ASSERT(data->transaction != NULL);
            DISSECTOR_ASSERT(data->transaction->split_start != NULL);
            usbll_set_address(tree, tvb, pinfo,
                              data->transaction->split_start->address, data->transaction->split_start->endpoint,
                              USBLL_ADDRESS_DEV_TO_HOST | USBLL_ADDRESS_HUB_PORT);
            break;
        case STATE_CSPLIT_CONTROL_SETUP:
        case STATE_CSPLIT_CONTROL_OUT:
        case STATE_CSPLIT_CONTROL_IN:
        case STATE_CSPLIT_BULK_OUT:
        case STATE_CSPLIT_BULK_IN:
        case STATE_CSPLIT_INTERRUPT_OUT:
        case STATE_CSPLIT_INTERRUPT_IN:
        case STATE_CSPLIT_ISOCHRONOUS_IN:
            DISSECTOR_ASSERT(data->transaction != NULL);
            DISSECTOR_ASSERT(data->transaction->split_complete != NULL);
            usbll_set_address(tree, tvb, pinfo,
                              data->transaction->address, data->transaction->endpoint,
                              USBLL_ADDRESS_HOST_TO_DEV);
            break;
        case STATE_CSPLIT_CONTROL_SETUP_ACK:
        case STATE_CSPLIT_CONTROL_OUT_ACK:
        case STATE_CSPLIT_CONTROL_OUT_NAK:
        case STATE_CSPLIT_CONTROL_OUT_STALL:
        case STATE_CSPLIT_CONTROL_IN_DATA0:
        case STATE_CSPLIT_CONTROL_IN_DATA1:
        case STATE_CSPLIT_CONTROL_IN_NAK:
        case STATE_CSPLIT_CONTROL_IN_STALL:
        case STATE_CSPLIT_BULK_OUT_ACK:
        case STATE_CSPLIT_BULK_OUT_NAK:
        case STATE_CSPLIT_BULK_OUT_STALL:
        case STATE_CSPLIT_BULK_IN_DATA0:
        case STATE_CSPLIT_BULK_IN_DATA1:
        case STATE_CSPLIT_BULK_IN_NAK:
        case STATE_CSPLIT_BULK_IN_STALL:
        case STATE_CSPLIT_INTERRUPT_OUT_ACK:
        case STATE_CSPLIT_INTERRUPT_OUT_NAK:
        case STATE_CSPLIT_INTERRUPT_OUT_STALL:
        case STATE_CSPLIT_INTERRUPT_IN_MDATA:
        case STATE_CSPLIT_INTERRUPT_IN_DATA0:
        case STATE_CSPLIT_INTERRUPT_IN_DATA1:
        case STATE_CSPLIT_INTERRUPT_IN_NAK:
        case STATE_CSPLIT_INTERRUPT_IN_STALL:
        case STATE_CSPLIT_ISOCHRONOUS_IN_DATA0:
        case STATE_CSPLIT_ISOCHRONOUS_IN_MDATA:
            DISSECTOR_ASSERT(data->transaction != NULL);
            DISSECTOR_ASSERT(data->transaction->split_complete != NULL);
            usbll_set_address(tree, tvb, pinfo,
                              data->transaction->address, data->transaction->endpoint,
                              USBLL_ADDRESS_DEV_TO_HOST);
            break;
        case STATE_CSPLIT_CONTROL_SETUP_NYET:
        case STATE_CSPLIT_CONTROL_OUT_NYET:
        case STATE_CSPLIT_CONTROL_IN_NYET:
        case STATE_CSPLIT_BULK_OUT_NYET:
        case STATE_CSPLIT_BULK_IN_NYET:
        case STATE_CSPLIT_INTERRUPT_OUT_ERR:
        case STATE_CSPLIT_INTERRUPT_OUT_NYET:
        case STATE_CSPLIT_INTERRUPT_IN_ERR:
        case STATE_CSPLIT_INTERRUPT_IN_NYET:
        case STATE_CSPLIT_ISOCHRONOUS_IN_ERR:
        case STATE_CSPLIT_ISOCHRONOUS_IN_NYET:
            DISSECTOR_ASSERT(data->transaction != NULL);
            usbll_set_address(tree, tvb, pinfo,
                              data->transaction->address, data->transaction->endpoint,
                              USBLL_ADDRESS_DEV_TO_HOST | USBLL_ADDRESS_HUB_PORT);
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }
}

static usbll_transaction_info_t *
tt_restore_transaction(packet_info *pinfo, usbll_state_t state, uint8_t hub_address, uint8_t port)
{
    /* The buffer is simply updated with each subsequent packet, this is fine
     * if and only if we access it only during first pass.
     */
    DISSECTOR_ASSERT(!PINFO_FD_VISITED(pinfo));
    DISSECTOR_ASSERT(usbll_is_split_complete_token(state));
    DISSECTOR_ASSERT(hub_address <= 127);
    DISSECTOR_ASSERT(port <= 127);

    if (!tt_periodic || !tt_non_periodic)
    {
        /* No transaction has been registered yet */
        return NULL;
    }

    if (usbll_is_periodic_split_complete_token(state))
    {
        return tt_periodic[hub_address][port];
    }
    else
    {
        DISSECTOR_ASSERT(usbll_is_non_periodic_split_complete_token(state));
        return tt_non_periodic[hub_address][port];
    }
}

static void
tt_store_transaction(packet_info *pinfo, usbll_state_t state, uint8_t hub_address, uint8_t port,
                     usbll_transaction_info_t *transaction)
{
    DISSECTOR_ASSERT(!PINFO_FD_VISITED(pinfo));
    DISSECTOR_ASSERT(usbll_is_split_start_token(state));
    DISSECTOR_ASSERT(hub_address <= 127);
    DISSECTOR_ASSERT(port <= 127);

    if (!tt_periodic || !tt_non_periodic)
    {
        /* Lazy allocate lookup table. Both address and port are 7 bit numbers,
         * so simply allocate buffers capable to hold all possible combinations.
         */
        int i;
        tt_periodic = wmem_alloc_array(wmem_file_scope(), usbll_transaction_info_t **, 128);
        for (i = 0; i < 128; i++)
        {
            tt_periodic[i] = wmem_alloc0_array(wmem_file_scope(), usbll_transaction_info_t *, 128);
        }
        tt_non_periodic = wmem_alloc_array(wmem_file_scope(), usbll_transaction_info_t **, 128);
        for (i = 0; i < 128; i++)
        {
            tt_non_periodic[i] = wmem_alloc0_array(wmem_file_scope(), usbll_transaction_info_t *, 128);
        }
    }

    if (usbll_is_periodic_split_start_token(state))
    {
        tt_periodic[hub_address][port] = transaction;
    }
    else
    {
        DISSECTOR_ASSERT(usbll_is_non_periodic_split_start_token(state));
        tt_non_periodic[hub_address][port] = transaction;
    }
}

static usbll_ep_type_t
usbll_ep_type_from_urb_type(uint8_t urb_type)
{
    switch (urb_type)
    {
        case URB_ISOCHRONOUS: return USBLL_EP_ISOCHRONOUS;
        case URB_INTERRUPT:   return USBLL_EP_INTERRUPT;
        case URB_CONTROL:     return USBLL_EP_CONTROL;
        case URB_BULK:        return USBLL_EP_BULK;
        default:              return USBLL_EP_UNKNOWN;
    }
}

static void
usbll_reset_endpoint_info(usbll_endpoint_info_t *info, usbll_ep_type_t type, uint16_t max_packet_size)
{
    info->type = type;
    info->data = USBLL_TRANSFER_NORMAL;
    info->max_packet_size = max_packet_size;
    info->last_data_pid = 0;
    info->last_data_acked = false;
    info->active_transfer_key = 0;
    info->transfer_offset = 0;
    info->last_data_len = 0;
    info->requested_transfer_length = 0;
}

static void usbll_reset_device_endpoints(int addr)
{
    int ep;
    DISSECTOR_ASSERT((addr >= 0) && (addr <= 127));

    /* Endpoint 0 is always control type */
    usbll_reset_endpoint_info(&ep_info_in[addr][0], USBLL_EP_CONTROL, 0);
    usbll_reset_endpoint_info(&ep_info_out[addr][0], USBLL_EP_CONTROL, 0);
    for (ep = 1; ep < 16; ep++)
    {
        usbll_reset_endpoint_info(&ep_info_in[addr][ep], USBLL_EP_UNKNOWN, 0);
        usbll_reset_endpoint_info(&ep_info_out[addr][ep], USBLL_EP_UNKNOWN, 0);
    }
}

static void usbll_init_endpoint_tables(void)
{
    /* Address is 7 bits (0 - 127), while endpoint is 4 bits (0 - 15) */
    int addr;
    ep_info_in = wmem_alloc_array(wmem_file_scope(), usbll_endpoint_info_t *, 128);
    for (addr = 0; addr < 128; addr++)
    {
        ep_info_in[addr] = wmem_alloc_array(wmem_file_scope(), usbll_endpoint_info_t, 16);
    }
    ep_info_out = wmem_alloc_array(wmem_file_scope(), usbll_endpoint_info_t *, 128);
    for (addr = 0; addr < 128; addr++)
    {
        ep_info_out[addr] = wmem_alloc_array(wmem_file_scope(), usbll_endpoint_info_t, 16);
    }

    for (addr = 0; addr < 128; addr++)
    {
        usbll_reset_device_endpoints(addr);
    }
}

static usbll_endpoint_info_t *
usbll_get_endpoint_info(packet_info *pinfo, uint8_t addr, uint8_t ep, bool from_host)
{
    usbll_endpoint_info_t *info;
    DISSECTOR_ASSERT(!PINFO_FD_VISITED(pinfo));
    DISSECTOR_ASSERT(addr <= 127);
    DISSECTOR_ASSERT(ep <= 15);

    if (!ep_info_in || !ep_info_out)
    {
        usbll_init_endpoint_tables();
        DISSECTOR_ASSERT(ep_info_in != NULL);
        DISSECTOR_ASSERT(ep_info_out != NULL);
    }

    if (from_host)
    {
        info = &ep_info_out[addr][ep];
    }
    else
    {
        info = &ep_info_in[addr][ep];
    }

    if (ep != 0)
    {
        /* Get endpoint type and max packet size from USB dissector
         * USB dissector gets the information from CONFIGURATION descriptor
         *
         * TODO: Reorganize USB dissector to call us whenever selected
         *       configuration and/or interface changes. USB dissector
         *       currently assumes only one configuration and that all
         *       alternate interface settings have matching endpoint
         *       information. This should be fixed but is good for now
         *       as most devices fullfills this (wrong) assumption.
         */
        usb_conv_info_t *usb_conv_info;
        usbll_ep_type_t  type = USBLL_EP_UNKNOWN;
        uint16_t         max_packet_size = 0;
        uint8_t          endpoint = ep | (from_host ? 0 : 0x80);
        usb_conv_info = get_existing_usb_ep_conv_info(pinfo, 0, addr, endpoint);
        if (usb_conv_info && usb_conv_info->max_packet_size)
        {
            type = usbll_ep_type_from_urb_type(usb_conv_info->descriptor_transfer_type);
            max_packet_size = usb_conv_info->max_packet_size;
        }
        /* Reset endpoint info if endpoint parameters changed */
        if ((info->type != type) || (info->max_packet_size != max_packet_size))
        {
            usbll_reset_endpoint_info(info, type, max_packet_size);
        }
    }

    return info;
}

static int
dissect_usbll_sof(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    uint32_t frame;
    /* SOF Packets are broadcasted from Host to all devices. */
    usbll_set_address(tree, tvb, pinfo, 0, 0, USBLL_ADDRESS_HOST_TO_DEV | USBLL_ADDRESS_BROADCAST);

    proto_tree_add_item_ret_uint(tree, hf_usbll_sof_framenum, tvb, offset, 2, ENC_LITTLE_ENDIAN, &frame);
    proto_tree_add_checksum(tree, tvb, offset,
                            hf_usbll_crc5, hf_usbll_crc5_status, &ei_wrong_crc5, pinfo,
                            crc5_usb_11bit_input(frame),
                            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
    offset += 2;

    return offset;
}

static int
dissect_usbll_token(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                    uint8_t pid, usbll_data_t *data, usb_speed_t speed)
{
    uint8_t          device_address;
    uint8_t          endpoint;
    uint16_t         address_bits;

    static int * const address_fields[] = {
        &hf_usbll_device_addr,
        &hf_usbll_endp,
        NULL
    };

    address_bits = tvb_get_letohs(tvb, offset);
    device_address = TOKEN_BITS_GET_ADDRESS(address_bits);
    endpoint = TOKEN_BITS_GET_ENDPOINT(address_bits);

    proto_tree_add_bitmask_list_value(tree, tvb, offset, 2, address_fields, address_bits);
    proto_tree_add_checksum(tree, tvb, offset,
                            hf_usbll_crc5, hf_usbll_crc5_status, &ei_wrong_crc5, pinfo,
                            crc5_usb_11bit_input(address_bits),
                            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
    offset += 2;

    if (!PINFO_FD_VISITED(pinfo))
    {
        usbll_state_t             prev_state;
        usbll_transaction_info_t *transaction = NULL;
        usbll_transaction_info_t *split_transaction = NULL;

        prev_state = data->prev ? data->prev->transaction_state : STATE_IDLE;
        data->transaction_state = usbll_next_state(prev_state, pid);

        DISSECTOR_ASSERT(usbll_is_non_split_token(data->transaction_state) ||
                         usbll_is_split_token(data->transaction_state));

        if (usbll_is_split_complete_token(data->transaction_state))
        {
            DISSECTOR_ASSERT(data->prev != NULL);
            DISSECTOR_ASSERT(data->prev->transaction != NULL);
            DISSECTOR_ASSERT(data->prev->transaction->pid == USB_PID_SPECIAL_SPLIT);
            split_transaction = data->prev->transaction;

            transaction = tt_restore_transaction(pinfo, data->transaction_state,
                                                 split_transaction->address, split_transaction->endpoint);

            if (transaction == NULL)
            {
                /* Most likely capture simply misses Split Start */
                transaction = wmem_new0(wmem_file_scope(), usbll_transaction_info_t);
                transaction->pid = pid;
                transaction->address = device_address;
                transaction->endpoint = endpoint;
                transaction->speed = speed;
            }

            transaction->split_complete = data->prev->transaction;
        }
        else
        {
            transaction = wmem_new0(wmem_file_scope(), usbll_transaction_info_t);
            transaction->starts_in = pinfo->num;
            transaction->pid = pid;
            transaction->address = device_address;
            transaction->endpoint = endpoint;
            transaction->speed = speed;
        }

        if (usbll_is_split_start_token(data->transaction_state))
        {
            DISSECTOR_ASSERT(data->prev != NULL);
            DISSECTOR_ASSERT(data->prev->transaction != NULL);
            DISSECTOR_ASSERT(data->prev->transaction->pid == USB_PID_SPECIAL_SPLIT);
            transaction->split_start = data->prev->transaction;

            tt_store_transaction(pinfo, data->transaction_state,
                                 transaction->split_start->address, transaction->split_start->endpoint,
                                 transaction);
        }

        data->transaction = transaction;
    }

    return offset;
}

static bool
packet_ends_transfer(usbll_endpoint_info_t *ep_info, uint32_t offset, int data_size)
{
    DISSECTOR_ASSERT(ep_info->type != USBLL_EP_UNKNOWN);

    if (ep_info->requested_transfer_length != 0)
    {
        /* We know requested transfer length */
        if (offset + data_size >= ep_info->requested_transfer_length)
        {
            /* No more data needed */
            return true;
        }
        /* else check max packet size as transfer can end prematurely */
    }
    else
    {
        DISSECTOR_ASSERT(ep_info->type != USBLL_EP_CONTROL);
        DISSECTOR_ASSERT(ep_info->max_packet_size != 0);
        /* We don't know requested transfer length, for bulk transfers
         * assume that transfer can be larger than max packet length,
         * for periodic transfers assume transfer is not larger than
         * max packet length.
         */
        if (ep_info->type != USBLL_EP_BULK)
        {
            return true;
        }
    }

    if (ep_info->max_packet_size)
    {
        return data_size < ep_info->max_packet_size;
    }

    DISSECTOR_ASSERT(ep_info->type == USBLL_EP_CONTROL);
    /* This code is valid only for high-speed control endpoints */
    if (data_size < 64)
    {
        return true;
    }

    return false;
}

static bool is_get_device_descriptor(uint8_t setup[8])
{
    uint16_t lang_id = setup[4] | (setup[5] << 8);
    uint16_t length = setup[6] | (setup[7] << 8);
    return (setup[0] == USB_DIR_IN) &&
           (setup[1] == USB_SETUP_GET_DESCRIPTOR) &&
           (setup[2] == 0x00) && /* Descriptor Index */
           (setup[3] == 0x01) && /* DEVICE descriptor */
           (lang_id == 0x00) && /* no language specified */
           (length >= 8); /* atleast 8 bytes needed to get bMaxPacketSize0 */
}

static bool is_set_address(uint8_t setup[8])
{
    uint16_t addr = setup[2] | (setup[3] << 8);
    uint16_t idx = setup[4] | (setup[5] << 8);
    uint16_t length = setup[6] | (setup[7] << 8);
    return (setup[0] == USB_DIR_OUT) &&
           (setup[1] == USB_SETUP_SET_ADDRESS) &&
           (addr <= 127) && (idx == 0x00) && (length == 0x00);
}

static void
usbll_construct_urb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    int data_offset, int data_size, usbll_data_t *data)
{
    usbll_transfer_info_t *transfer = NULL;

    transfer = (usbll_transfer_info_t *)wmem_map_lookup(transfer_info, GUINT_TO_POINTER(pinfo->num));
    if (transfer)
    {
        tvbuff_t *transfer_tvb;

        if ((transfer->first_packet == pinfo->num) && (!transfer->more_frags) &&
            (((transfer->type == USBLL_EP_CONTROL) && (transfer->from_host)) ||
             (transfer->type == USBLL_EP_ISOCHRONOUS)))
        {
            /* No multi-packet reassembly needed, simply construct tvb */
            transfer_tvb = tvb_new_subset_length(tvb, data_offset, data_size);
            add_new_data_source(pinfo, transfer_tvb, "USB transfer");
        }
        else
        {
            fragment_head *head;
            head = fragment_add_check_with_fallback(&usbll_reassembly_table,
                       tvb, data_offset,
                       pinfo, transfer->first_packet, NULL,
                       transfer->offset, data_size, transfer->more_frags, transfer->first_packet);
            transfer_tvb = process_reassembled_data(tvb, data_offset, pinfo,
                                                    "USB transfer", head, &usbll_frag_items,
                                                    NULL, tree);
        }

        if (transfer_tvb != NULL)
        {
            usb_pseudo_urb_t pseudo_urb;
            pseudo_urb.from_host = transfer->from_host;
            switch (transfer->type)
            {
                case USBLL_EP_UNKNOWN:
                    pseudo_urb.transfer_type = URB_UNKNOWN;
                    break;
                case USBLL_EP_CONTROL:
                    pseudo_urb.transfer_type = URB_CONTROL;
                    break;
                case USBLL_EP_BULK:
                    pseudo_urb.transfer_type = URB_BULK;
                    break;
                case USBLL_EP_INTERRUPT:
                    pseudo_urb.transfer_type = URB_INTERRUPT;
                    break;
                case USBLL_EP_ISOCHRONOUS:
                    pseudo_urb.transfer_type = URB_ISOCHRONOUS;
                    break;
                default:
                    DISSECTOR_ASSERT_NOT_REACHED();
            }
            pseudo_urb.device_address = data->transaction->address;
            pseudo_urb.endpoint = data->transaction->endpoint | (transfer->from_host ? 0 : 0x80);
            pseudo_urb.bus_id = 0;
            pseudo_urb.speed = usbll_get_data_transaction_speed(data);
            dissect_usb_common(transfer_tvb, pinfo, proto_tree_get_parent_tree(tree),
                               USB_HEADER_PSEUDO_URB, &pseudo_urb);
        }
    }
}

static int
dissect_usbll_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                   uint8_t pid, usbll_data_t *data, int *payload_size)
{
    /* TODO: How to determine the expected DATA size? */
    uint16_t               computed_crc, actual_crc;
    int                    data_offset = offset;
    int                    data_size = tvb_reported_length_remaining(tvb, offset) - 2;
    proto_item            *data_item = NULL;
    usbll_transfer_info_t *transfer = NULL;

    data_item = proto_tree_add_item(tree, hf_usbll_data, tvb, offset, data_size, ENC_NA);
    offset += data_size;

    actual_crc = tvb_get_letohs(tvb, offset);
    computed_crc = crc16_usb_tvb_offset(tvb, 1, offset - 1);
    proto_tree_add_checksum(tree, tvb, offset,
                            hf_usbll_data_crc, hf_usbll_data_crc_status, &ei_wrong_crc16, pinfo,
                            computed_crc, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
    offset += 2;

    if (!PINFO_FD_VISITED(pinfo))
    {
        usbll_state_t             prev_state;

        prev_state = data->prev ? data->prev->transaction_state : STATE_IDLE;
        data->transaction_state = usbll_next_state(prev_state, pid);
        if (data->transaction_state != STATE_INVALID)
        {
            DISSECTOR_ASSERT(data->prev != NULL);
            DISSECTOR_ASSERT(data->prev->transaction != NULL);
            data->transaction = data->prev->transaction;
        }
    }

    if (actual_crc != computed_crc)
    {
        /* Do not reassemble on CRC error */
        return offset;
    }

    if (usbll_is_setup_data(data->transaction_state))
    {
        if (data_size != 8)
        {
            expert_add_info(pinfo, data_item, &ei_invalid_setup_data);
        }
        else if (!PINFO_FD_VISITED(pinfo))
        {
            usbll_endpoint_info_t *ep_out, *ep_in;

            ep_out = usbll_get_endpoint_info(pinfo, data->transaction->address, data->transaction->endpoint, true);
            ep_in = usbll_get_endpoint_info(pinfo, data->transaction->address, data->transaction->endpoint, false);

            /* Check if SETUP data is indeed to control endpoint (discard if targtet endpoint is not control).
             * Practically all control transfers are to endpoint 0 which is always control endpoint.
             */
            if ((ep_out->type == USBLL_EP_CONTROL) && (ep_in->type == USBLL_EP_CONTROL))
            {
                uint8_t setup[8];
                bool data_stage_from_host;
                uint16_t requested_length;

                tvb_memcpy(tvb, setup, data_offset, 8);

                /* bmRequestType D7 0 = Host-to-device, 1 = Device-to-host */
                data_stage_from_host = (setup[0] & 0x80) ? false : true;
                /* wLength */
                requested_length = setup[6] | (setup[7] << 8);

                usbll_reset_endpoint_info(ep_out, USBLL_EP_CONTROL, ep_out->max_packet_size);
                usbll_reset_endpoint_info(ep_in, USBLL_EP_CONTROL, ep_in->max_packet_size);

                transfer = wmem_new0(wmem_file_scope(), usbll_transfer_info_t);
                transfer->first_packet = pinfo->num;
                transfer->offset = 0;
                transfer->type = USBLL_EP_CONTROL;
                transfer->from_host = true; /* SETUP is always from host to service */

                if (requested_length > 0)
                {
                    if (data_stage_from_host)
                    {
                        /* Merge SETUP data with OUT Data to pass to USB dissector */
                        transfer->more_frags = true;
                        ep_out->active_transfer_key = pinfo->num;
                        ep_out->requested_transfer_length = 8 + requested_length;
                        ep_out->transfer_offset = 8;
                        ep_out->last_data_pid = pid;
                        ep_out->last_data_acked = false;
                        /* If SETUP is sent again, it always starts a new transfer.
                         * If we receive DATA0 next then it is really a host failure.
                         * Do not "overwrite" the 8 SETUP bytes in such case.
                         */
                        ep_out->last_data_len = 0;
                    }
                    else
                    {
                        transfer->more_frags = false;
                        /* Expect requested_length when reading from control endpoint.
                         * The data should start with DATA1. If we receive DATA0 then
                         * this is really device failure.
                         */
                        ep_in->requested_transfer_length = requested_length;
                        ep_in->last_data_pid = pid;
                        ep_in->last_data_acked = false;
                        ep_in->last_data_len = 0;
                    }
                }

                if (is_get_device_descriptor(setup))
                {
                    ep_in->data = USBLL_TRANSFER_GET_DEVICE_DESCRIPTOR;
                }
                else if (is_set_address(setup))
                {
                    int addr = setup[2];
                    if (addr > 0)
                    {
                        /* Prevent transfer reassembly across reset boundary.
                         * Do not reset for default address (0) because there
                         * can only be control transfers to default address
                         * and we don't want to lose max packet size info.
                         */
                        usbll_reset_device_endpoints(addr);
                    }
                }

                wmem_map_insert(transfer_info, GUINT_TO_POINTER(pinfo->num), transfer);
            }
        }
    }
    else if ((!PINFO_FD_VISITED(pinfo)) && (data->transaction_state != STATE_INVALID))
    {
        usbll_endpoint_info_t *ep_info;
        bool                   from_host;

        from_host = usbll_is_data_from_host(data->transaction_state);
        ep_info = usbll_get_endpoint_info(pinfo, data->transaction->address, data->transaction->endpoint, from_host);

        if (ep_info->type == USBLL_EP_CONTROL)
        {
            if (ep_info->requested_transfer_length > 0)
            {
                if (pid == ep_info->last_data_pid)
                {
                    if (ep_info->last_data_len == 0)
                    {
                        /* We received DATA0 immediately after SETUP (as response to OUT or IN)
                         * Do not reassemble the data, instead mark it as unexpected PID.
                         */
                        data->transaction_state = STATE_INVALID;
                    }
                    else
                    {
                        /* Retransmission */
                        transfer = wmem_new0(wmem_file_scope(), usbll_transfer_info_t);
                        transfer->first_packet = ep_info->active_transfer_key;
                        transfer->offset = ep_info->transfer_offset - ep_info->last_data_len;
                        transfer->type = USBLL_EP_CONTROL;
                        transfer->from_host = from_host;
                        transfer->more_frags = !packet_ends_transfer(ep_info, transfer->offset, data_size);
                        wmem_map_insert(transfer_info, GUINT_TO_POINTER(pinfo->num), transfer);
                        /* Do not update endpoint info, previously transferred packet must have
                         * the same data length as retransmitted packet.
                         */
                    }
                }
                else if ((pid == USB_PID_DATA_DATA0) || (pid == USB_PID_DATA_DATA1))
                {
                    if (ep_info->active_transfer_key == 0)
                    {
                        /* This is allowed only when Data stage is from device to host */
                        DISSECTOR_ASSERT(!from_host);
                        DISSECTOR_ASSERT(ep_info->transfer_offset == 0);
                        DISSECTOR_ASSERT(ep_info->last_data_len == 0);
                        ep_info->active_transfer_key = pinfo->num;

                        if ((ep_info->data == USBLL_TRANSFER_GET_DEVICE_DESCRIPTOR) && (data_size >= 8))
                        {
                            usbll_endpoint_info_t *ep_out;
                            usb_speed_t            speed;
                            uint16_t               max_packet_size;
                            ep_out = usbll_get_endpoint_info(pinfo, data->transaction->address, data->transaction->endpoint, true);
                            max_packet_size = tvb_get_uint8(tvb, data_offset + 7);
                            speed = usbll_get_data_transaction_speed(data);
                            max_packet_size = sanitize_usb_max_packet_size(ENDPOINT_TYPE_CONTROL, speed, max_packet_size);
                            ep_info->max_packet_size = ep_out->max_packet_size = max_packet_size;
                        }
                    }
                    transfer = wmem_new0(wmem_file_scope(), usbll_transfer_info_t);
                    transfer->first_packet = ep_info->active_transfer_key;
                    transfer->offset = ep_info->transfer_offset;
                    transfer->type = USBLL_EP_CONTROL;
                    transfer->from_host = from_host;
                    transfer->more_frags = !packet_ends_transfer(ep_info, transfer->offset, data_size);
                    wmem_map_insert(transfer_info, GUINT_TO_POINTER(pinfo->num), transfer);

                    ep_info->last_data_pid = pid;
                    ep_info->last_data_acked = usbll_is_split_data_from_device(data->transaction_state);
                    ep_info->transfer_offset += data_size;
                    ep_info->last_data_len = data_size;
                }
                else
                {
                    /* Only DATA0 and DATA1 are allowed in Control transfers */
                    data->transaction_state = STATE_INVALID;
                }
            }
            else
            {
                /* We don't know anything about the control transfer.
                 * Most likely the capture is incomplete, there's nothing to be done here.
                 */
            }
        }
        else if ((ep_info->type == USBLL_EP_BULK) || (ep_info->type == USBLL_EP_INTERRUPT))
        {
            if (pid == ep_info->last_data_pid)
            {
                /* Retransmission */
                DISSECTOR_ASSERT(ep_info->active_transfer_key != 0);
                transfer = wmem_new0(wmem_file_scope(), usbll_transfer_info_t);
                transfer->first_packet = ep_info->active_transfer_key;
                transfer->offset = ep_info->transfer_offset - ep_info->last_data_len;
                transfer->type = ep_info->type;
                transfer->from_host = from_host;
                transfer->more_frags = !packet_ends_transfer(ep_info, transfer->offset, data_size);
                wmem_map_insert(transfer_info, GUINT_TO_POINTER(pinfo->num), transfer);
                /* Do not update endpoint info, previously transferred packet must have
                 * the same data length as retransmitted packet.
                 */
            }
            else if ((ep_info->active_transfer_key == 0) ||
                     packet_ends_transfer(ep_info, ep_info->transfer_offset, ep_info->last_data_len))
            {
                 /* Packet starts new transfer */
                 transfer = wmem_new0(wmem_file_scope(), usbll_transfer_info_t);
                 transfer->first_packet = pinfo->num;
                 transfer->offset = 0;
                 transfer->type = ep_info->type;
                 transfer->from_host = from_host;
                 transfer->more_frags = !packet_ends_transfer(ep_info, transfer->offset, data_size);
                 wmem_map_insert(transfer_info, GUINT_TO_POINTER(pinfo->num), transfer);

                 ep_info->last_data_pid = pid;
                 ep_info->last_data_acked = usbll_is_split_data_from_device(data->transaction_state);
                 ep_info->active_transfer_key = pinfo->num;
                 ep_info->transfer_offset = data_size;
                 ep_info->last_data_len = data_size;
            }
            else
            {
                transfer = wmem_new0(wmem_file_scope(), usbll_transfer_info_t);
                transfer->first_packet = ep_info->active_transfer_key;
                transfer->offset = ep_info->transfer_offset;
                transfer->type = ep_info->type;
                transfer->from_host = from_host;
                transfer->more_frags = !packet_ends_transfer(ep_info, transfer->offset, data_size);
                wmem_map_insert(transfer_info, GUINT_TO_POINTER(pinfo->num), transfer);

                ep_info->last_data_pid = pid;
                ep_info->last_data_acked = usbll_is_split_data_from_device(data->transaction_state);
                ep_info->transfer_offset += data_size;
                ep_info->last_data_len = data_size;
            }
        }
        else if (ep_info->type == USBLL_EP_ISOCHRONOUS)
        {
            /* TODO: Reassemble high-bandwidth endpoints data */
            transfer = wmem_new0(wmem_file_scope(), usbll_transfer_info_t);
            transfer->first_packet = pinfo->num;
            transfer->offset = 0;
            transfer->type = ep_info->type;
            transfer->from_host = from_host;
            transfer->more_frags = false;
            wmem_map_insert(transfer_info, GUINT_TO_POINTER(pinfo->num), transfer);
        }
    }

    *payload_size = data_size;

    return offset;
}

static int
dissect_usbll_split(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                    uint8_t pid, usbll_data_t *data)
{
    uint8_t          hub_address;
    uint8_t          hub_port;
    proto_item      *split_e_u;
    proto_item      *split_s;

    int32_t tmp = tvb_get_int24(tvb, offset, ENC_LITTLE_ENDIAN);

    hub_address = SPLIT_BITS_GET_HUB_ADDRESS(tmp);
    hub_port = SPLIT_BITS_GET_HUB_PORT(tmp);

    col_append_str(pinfo->cinfo, COL_INFO, (tmp & SPLIT_BIT_START_COMPLETE) ? " Complete" : " Start");

    proto_tree_add_uint(tree, hf_usbll_split_hub_addr, tvb, offset, 3, tmp);
    proto_tree_add_uint(tree, hf_usbll_split_sc, tvb, offset, 3, tmp);
    proto_tree_add_uint(tree, hf_usbll_split_port, tvb, offset, 3, tmp);

    if (tmp & SPLIT_BIT_START_COMPLETE) {
        proto_tree_add_uint(tree, hf_usbll_split_s, tvb, offset, 3, tmp);
        split_e_u = proto_tree_add_uint(tree, hf_usbll_split_u, tvb, offset, 3, tmp);

        if (tmp & SPLIT_BIT_E_U)
            expert_add_info(pinfo, split_e_u, &ei_invalid_e_u);
    } else {
        /* S/E fields have special meaning for Isochronous OUT transfers. */
        if (data->next && data->next->transaction_state == STATE_SSPLIT_ISOCHRONOUS_OUT) {
            DISSECTOR_ASSERT(SPLIT_BITS_GET_ENDPOINT_TYPE(tmp) == USB_EP_TYPE_ISOCHRONOUS);
            proto_tree_add_uint(tree, hf_usbll_split_iso_se, tvb, offset, 3, tmp);
        } else if (SPLIT_BITS_GET_ENDPOINT_TYPE(tmp) != USB_EP_TYPE_ISOCHRONOUS) {
            split_s = proto_tree_add_uint(tree, hf_usbll_split_s, tvb, offset, 3, tmp);
            split_e_u = proto_tree_add_uint(tree, hf_usbll_split_e, tvb, offset, 3, tmp);

            if ((SPLIT_BITS_GET_ENDPOINT_TYPE(tmp) == USB_EP_TYPE_BULK) && (tmp & SPLIT_BIT_SPEED))
                expert_add_info(pinfo, split_s, &ei_invalid_s);
            if (tmp & SPLIT_BIT_E_U)
                expert_add_info(pinfo, split_e_u, &ei_invalid_e_u);
        } else if (data->next &&
                   (data->next->transaction_state == STATE_SSPLIT_ISOCHRONOUS_IN ||
                    data->next->transaction_state == STATE_CSPLIT_ISOCHRONOUS_IN)) {
            DISSECTOR_ASSERT(SPLIT_BITS_GET_ENDPOINT_TYPE(tmp) == USB_EP_TYPE_ISOCHRONOUS);
            split_s = proto_tree_add_uint(tree, hf_usbll_split_s, tvb, offset, 3, tmp);
            split_e_u = proto_tree_add_uint(tree, hf_usbll_split_e, tvb, offset, 3, tmp);

            if (tmp & SPLIT_BIT_SPEED)
                expert_add_info(pinfo, split_s, &ei_invalid_s);
            if (tmp & SPLIT_BIT_E_U)
                expert_add_info(pinfo, split_e_u, &ei_invalid_e_u);
        }
    }
    proto_tree_add_uint(tree, hf_usbll_split_et, tvb, offset, 3, tmp);

    proto_tree_add_checksum(tree, tvb, offset,
                            hf_usbll_split_crc5, hf_usbll_split_crc5_status, &ei_wrong_split_crc5, pinfo,
                            crc5_usb_19bit_input(tmp),
                            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
    offset += 3;

    if (!PINFO_FD_VISITED(pinfo))
    {
        usbll_transaction_info_t *transaction;
        transaction = wmem_new0(wmem_file_scope(), usbll_transaction_info_t);
        transaction->starts_in = pinfo->num;
        transaction->pid = pid;
        transaction->address = hub_address;
        transaction->endpoint = hub_port;
        if (SPLIT_BITS_GET_ENDPOINT_TYPE(tmp) == USB_EP_TYPE_ISOCHRONOUS)
            transaction->speed = USB_SPEED_FULL;
        else
            transaction->speed = (tmp & SPLIT_BIT_SPEED) ? USB_SPEED_LOW : USB_SPEED_FULL;

        data->transaction = transaction;
        if (tmp & SPLIT_BIT_START_COMPLETE)
        {
            switch (SPLIT_BITS_GET_ENDPOINT_TYPE(tmp))
            {
                case USB_EP_TYPE_CONTROL:
                    data->transaction_state = STATE_CSPLIT_CONTROL;
                    break;
                case USB_EP_TYPE_ISOCHRONOUS:
                    data->transaction_state = STATE_CSPLIT_ISOCHRONOUS;
                    break;
                case USB_EP_TYPE_BULK:
                    data->transaction_state = STATE_CSPLIT_BULK;
                    break;
                case USB_EP_TYPE_INTERRUPT:
                    data->transaction_state = STATE_CSPLIT_INTERRUPT;
                    break;
            }
        }
        else
        {
            switch (SPLIT_BITS_GET_ENDPOINT_TYPE(tmp))
            {
                case USB_EP_TYPE_CONTROL:
                    data->transaction_state = STATE_SSPLIT_CONTROL;
                    break;
                case USB_EP_TYPE_ISOCHRONOUS:
                    data->transaction_state = STATE_SSPLIT_ISOCHRONOUS;
                    break;
                case USB_EP_TYPE_BULK:
                    data->transaction_state = STATE_SSPLIT_BULK;
                    break;
                case USB_EP_TYPE_INTERRUPT:
                    data->transaction_state = STATE_SSPLIT_INTERRUPT;
                    break;
            }
        }
    }

    return offset;
}

static int
dissect_usbll_handshake(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int offset,
                        uint8_t pid, usbll_data_t *data)
{
    if (!PINFO_FD_VISITED(pinfo))
    {
        usbll_state_t             prev_state;

        prev_state = data->prev ? data->prev->transaction_state : STATE_IDLE;
        data->transaction_state = usbll_next_state(prev_state, pid);

        if (data->transaction_state != STATE_INVALID)
        {
            DISSECTOR_ASSERT(data->prev != NULL);
            DISSECTOR_ASSERT(data->prev->transaction != NULL);
            data->transaction = data->prev->transaction;
        }

        if (usbll_is_setup_ack(data->transaction_state))
        {
            usbll_endpoint_info_t *ep_out, *ep_in;
            ep_out = usbll_get_endpoint_info(pinfo, data->transaction->address, data->transaction->endpoint, true);
            ep_in = usbll_get_endpoint_info(pinfo, data->transaction->address, data->transaction->endpoint, false);
            if ((ep_out->type == USBLL_EP_CONTROL) && (ep_in->type == USBLL_EP_CONTROL))
            {
                if (ep_out->active_transfer_key != 0)
                {
                    DISSECTOR_ASSERT(ep_in->active_transfer_key == 0);
                    ep_out->last_data_acked = true;
                }
                else if (ep_in->active_transfer_key != 0)
                {
                    DISSECTOR_ASSERT(ep_out->active_transfer_key == 0);
                    ep_in->last_data_acked = true;
                }
            }
        }

        if (usbll_is_data_ack(data->transaction_state))
        {
            usbll_endpoint_info_t *ep_info;
            bool                   from_host;

            from_host = usbll_is_acked_data_from_host(data->transaction_state);
            ep_info = usbll_get_endpoint_info(pinfo, data->transaction->address, data->transaction->endpoint, from_host);

            ep_info->last_data_acked = true;
        }

        if (usbll_is_endpoint_stall(data->transaction_state))
        {
            usbll_endpoint_info_t *ep_info;
            usbll_transfer_info_t *transfer;
            uint32_t               last_offset;
            bool                   from_host;

            from_host = usbll_is_stalled_data_from_host(data->transaction_state);
            ep_info = usbll_get_endpoint_info(pinfo, data->transaction->address, data->transaction->endpoint, from_host);

            last_offset = ep_info->transfer_offset - ep_info->last_data_len;

            if (ep_info->active_transfer_key &&
                !packet_ends_transfer(ep_info, last_offset, ep_info->last_data_len))
            {
                /* STALL terminates ongoing transfer. While the STALL packet is
                 * always sent by device, the transfer can be either IN or OUT.
                 * For IN usbll source and destination will match usb source
                 * and destination. For OUT the source and destination will be
                 * swapped in usb dissector.
                 */
                 transfer = wmem_new0(wmem_file_scope(), usbll_transfer_info_t);
                 transfer->first_packet = ep_info->active_transfer_key;
                 if (!from_host)
                 {
                    /* Data is from device, all reassembled data is in URB */
                    transfer->offset = ep_info->transfer_offset;
                 }
                 else if (data->transaction_state == STATE_PING_STALL)
                 {
                    if (ep_info->last_data_acked)
                    {
                        /* Last DATA packet was acknowledged with NYET */
                        transfer->offset = ep_info->transfer_offset;
                    }
                    else
                    {
                        /* Last DATA packet was NAKed. Drop it from URB. */
                        transfer->offset = last_offset;
                    }
                 }
                 else
                 {
                    /* Last DATA packet was not acknowledged by device because
                     * endpoint was STALLed. Drop last DATA packet from URB.
                     */
                    transfer->offset = last_offset;
                 }
                 transfer->type = ep_info->type;
                 transfer->from_host = from_host;
                 transfer->more_frags = false;
                 wmem_map_insert(transfer_info, GUINT_TO_POINTER(pinfo->num), transfer);
            }

            /* Transfers cannot span across STALL handshake */
            ep_info->last_data_pid = 0;
            ep_info->last_data_acked = false;
            ep_info->active_transfer_key = 0;
            ep_info->transfer_offset = 0;
            ep_info->last_data_len = 0;
            ep_info->requested_transfer_length = 0;
        }
    }

    return offset;
}

static void check_for_extended_subpid(uint8_t pid, usbll_data_t *data)
{
    if (data->prev && data->prev->transaction_state == STATE_EXT)
    {
        data->transaction_state = usbll_next_state(STATE_EXT, pid);

        if (data->transaction_state != STATE_SUBPID_INVALID)
        {
            DISSECTOR_ASSERT(data->prev != NULL);
            DISSECTOR_ASSERT(data->prev->transaction != NULL);
            data->transaction = data->prev->transaction;
        }
    }
}

static int
dissect_usbll_lpm_token(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    uint16_t         attributes_bits;

    static int * const attributes_fields[] = {
        &hf_usbll_lpm_link_state,
        &hf_usbll_lpm_besl,
        &hf_usbll_lpm_remote_wake,
        &hf_usbll_lpm_reserved,
        NULL
    };

    attributes_bits = tvb_get_letohs(tvb, offset);

    proto_tree_add_bitmask_list_value(tree, tvb, offset, 2, attributes_fields, attributes_bits);
    proto_tree_add_checksum(tree, tvb, offset,
                            hf_usbll_crc5, hf_usbll_crc5_status, &ei_wrong_crc5, pinfo,
                            crc5_usb_11bit_input(attributes_bits),
                            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
    offset += 2;

    return offset;
}

static usbll_data_t *
usbll_restore_data(packet_info *pinfo)
{
    return (usbll_data_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_usbll, pinfo->num);
}

static usbll_data_t *
usbll_create_data(packet_info *pinfo)
{
    /* allocate a data structure, as it is the first call on this frame. */
    usbll_data_t *n_data_ptr = wmem_new0(wmem_file_scope(), usbll_data_t);

    p_add_proto_data(wmem_file_scope(), pinfo, proto_usbll, pinfo->num, n_data_ptr);

    if (usbll_data_ptr)
        *n_data_ptr = *usbll_data_ptr;

    n_data_ptr->transaction_state = STATE_IDLE;
    n_data_ptr->prev = usbll_data_ptr;
    if (n_data_ptr->prev)
    {
        n_data_ptr->prev->next = n_data_ptr;
    }

    return n_data_ptr;
}

static void
usbll_cleanup_data(void)
{
    usbll_data_ptr = NULL;
    tt_non_periodic = NULL;
    tt_periodic = NULL;
    ep_info_in = NULL;
    ep_info_out = NULL;
}

static int
dissect_usbll_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, usb_speed_t speed)
{
    proto_item       *item;
    proto_tree       *tree;
    int               offset = 0;
    int               data_offset;
    int               data_size;
    uint8_t           pid;
    bool              is_subpid;
    const char       *str;
    usbll_data_t     *data;

    item = proto_tree_add_item(parent_tree, proto_usbll, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_usbll);

    pid = tvb_get_uint8(tvb, offset);

    if (PINFO_FD_VISITED(pinfo)) {
        data = usbll_restore_data(pinfo);
    } else {
        data = usbll_data_ptr = usbll_create_data(pinfo);
        check_for_extended_subpid(pid, data);
    }

    is_subpid = usbll_is_extended_subpid(data->transaction_state);
    if (is_subpid) {
        proto_tree_add_item(tree, hf_usbll_subpid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        str = try_val_to_str(pid, usb_subpid_vals);
    } else {
        proto_tree_add_item(tree, hf_usbll_pid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        str = try_val_to_str(pid, usb_packetid_vals);
    }
    offset++;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBLL");
    if (str) {
        col_set_str(pinfo->cinfo, COL_INFO, str);
    } else if (is_subpid) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid SubPID (0x%02x)", pid);
        expert_add_info(pinfo, item, &ei_invalid_subpid);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid Packet ID (0x%02x)", pid);
        expert_add_info(pinfo, item, &ei_invalid_pid);
    }

    /* If handler updates data size, then it means we should process with data
     * reassembly at data offset with the provided data size.
     */
    data_offset = offset;
    data_size = -1;

    if (is_subpid) {
        switch (pid)
        {
            case USB_SUBPID_LPM:
                offset = dissect_usbll_lpm_token(tvb, pinfo, tree, offset);
                break;

            default:
                break;
        }
    } else {
        switch (pid)
        {
            case USB_PID_TOKEN_SETUP:
            case USB_PID_TOKEN_OUT:
            case USB_PID_TOKEN_IN:
            case USB_PID_SPECIAL_PING:
            case USB_PID_SPECIAL_EXT:
                offset = dissect_usbll_token(tvb, pinfo, tree, offset, pid, data, speed);
                break;

            case USB_PID_DATA_DATA0:
            case USB_PID_DATA_DATA1:
            case USB_PID_DATA_DATA2:
            case USB_PID_DATA_MDATA:
                offset = dissect_usbll_data(tvb, pinfo, tree, offset, pid, data, &data_size);
                break;

            case USB_PID_HANDSHAKE_ACK:
            case USB_PID_HANDSHAKE_NAK:
            case USB_PID_HANDSHAKE_NYET:
            case USB_PID_HANDSHAKE_STALL:
                offset = dissect_usbll_handshake(tvb, pinfo, tree, offset, pid, data);
                data_size = 0;
                break;

            case USB_PID_TOKEN_SOF:
                offset = dissect_usbll_sof(tvb, pinfo, tree, offset);
                break;

            case USB_PID_SPECIAL_SPLIT:
                offset = dissect_usbll_split(tvb, pinfo, tree, offset, pid, data);
                break;
            case USB_PID_SPECIAL_PRE_OR_ERR:
                break;
            default:
                break;
        }
    }

    usbll_generate_address(tree, tvb, pinfo, data);
    if (data->transaction_state == STATE_INVALID) {
        expert_add_info(pinfo, item, &ei_invalid_pid_sequence);
    } else if (data->transaction_state == STATE_SUBPID_NOT_REUSABLE) {
        expert_add_info(pinfo, item, &ei_conflicting_subpid);
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert(tree, pinfo, &ei_undecoded, tvb, offset, -1);
        offset += tvb_captured_length_remaining(tvb, offset);
    }

    if (data_size >= 0) {
        usbll_construct_urb(tvb, pinfo, tree, data_offset, data_size, data);
    }

    return offset;
}

static int
dissect_usbll_unknown_speed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
    return dissect_usbll_packet(tvb, pinfo, parent_tree, global_dissect_unknown_speed_as);
}

static int
dissect_usbll_low_speed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
    return dissect_usbll_packet(tvb, pinfo, parent_tree, USB_SPEED_LOW);
}

static int
dissect_usbll_full_speed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
    return dissect_usbll_packet(tvb, pinfo, parent_tree, USB_SPEED_FULL);
}

static int
dissect_usbll_high_speed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
    return dissect_usbll_packet(tvb, pinfo, parent_tree, USB_SPEED_HIGH);
}

void
proto_register_usbll(void)
{
    module_t         *usbll_module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        /* Common header fields */
        { &hf_usbll_pid,
            { "PID", "usbll.pid",
              FT_UINT8, BASE_HEX|BASE_EXT_STRING, &usb_packetid_vals_ext, 0x00,
              "USB Packet ID", HFILL }},
        { &hf_usbll_src,
            { "Source", "usbll.src",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_usbll_dst,
            { "Destination", "usbll.dst",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_usbll_addr,
            { "Source or Destination", "usbll.addr",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        /* Token header fields */
        { &hf_usbll_device_addr,
            { "Address", "usbll.device_addr",
              FT_UINT16, BASE_DEC, NULL, 0x007F,
              NULL, HFILL }},
        { &hf_usbll_endp,
            { "Endpoint", "usbll.endp",
              FT_UINT16, BASE_DEC, NULL, 0x0780,
              NULL, HFILL }},

        /*SOF header field */
        { &hf_usbll_sof_framenum,
            { "Frame Number", "usbll.frame_num",
              FT_UINT16, BASE_DEC, NULL, 0x07FF,
              NULL, HFILL }},

        /* Token and SOF header fields */
        { &hf_usbll_crc5,
            { "CRC5", "usbll.crc5",
              FT_UINT16, BASE_HEX, NULL, 0xF800,
              NULL, HFILL }},
        { &hf_usbll_crc5_status,
            { "CRC5 Status", "usbll.crc5.status",
              FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0,
              NULL, HFILL }},

        /* Data header fields */
        { &hf_usbll_data,
            { "Data", "usbll.data",
              FT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0,
              NULL, HFILL }},
        { &hf_usbll_data_crc,
            { "CRC", "usbll.crc16",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              NULL, HFILL }},
        { &hf_usbll_data_crc_status,
            { "CRC Status", "usbll.crc16.status",
              FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0,
              NULL, HFILL }},

        /* Split header fields */
        { &hf_usbll_split_hub_addr,
            { "Hub Address", "usbll.split_hub_addr",
              FT_UINT24, BASE_DEC, NULL, 0x00007F,
              NULL, HFILL }},
        { &hf_usbll_split_sc,
            { "SC", "usbll.split_sc",
              FT_UINT24, BASE_DEC, VALS(usb_start_complete_vals), 0x000080,
              NULL, HFILL }},
        { &hf_usbll_split_port,
            { "Port", "usbll.split_port",
              FT_UINT24, BASE_DEC, NULL, 0x007F00,
              NULL, HFILL }},
        { &hf_usbll_split_s,
            { "Speed", "usbll.split_s",
              FT_UINT24, BASE_DEC, VALS(usb_split_speed_vals), 0x008000,
              NULL, HFILL }},
        { &hf_usbll_split_e,
            { "E", "usbll.split_e",
              FT_UINT24, BASE_DEC, NULL, 0x010000,
              "Unused. Must be 0.", HFILL }},
        { &hf_usbll_split_u,
            { "U", "usbll.split_u",
              FT_UINT24, BASE_DEC, NULL, 0x010000,
              "Unused. Must be 0.", HFILL }},
        { &hf_usbll_split_iso_se,
            { "Start and End", "usbll.split_se",
              FT_UINT24, BASE_DEC, VALS(usb_split_iso_se_vals), 0x018000,
              NULL, HFILL }},
        { &hf_usbll_split_et,
            { "Endpoint Type", "usbll.split_et",
              FT_UINT24, BASE_DEC, VALS(usb_endpoint_type_vals), 0x060000,
              NULL, HFILL }},
        { &hf_usbll_split_crc5,
            { "CRC5", "usbll.split_crc5",
              FT_UINT24, BASE_HEX, NULL, 0xF80000,
              NULL, HFILL }},
        { &hf_usbll_split_crc5_status,
            { "CRC5 Status", "usbll.split_crc5.status",
              FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0,
              NULL, HFILL }},
        { &hf_usbll_transfer_fragments,
            { "Transfer fragments", "usbll.fragments",
              FT_NONE, BASE_NONE, NULL, 0x00,
              NULL, HFILL }},
        { &hf_usbll_transfer_fragment,
            {"Transfer fragment", "usbll.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_usbll_transfer_fragment_overlap,
            {"Transfer fragment overlap", "usbll.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_usbll_transfer_fragment_overlap_conflicts,
            {"Transfer fragment overlapping with conflicting data",
            "usbll.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_usbll_transfer_fragment_multiple_tails,
            {"Transfer has multiple tail fragments",
            "usbll.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_usbll_transfer_fragment_too_long_fragment,
            {"Transfer fragment too long", "usbll.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_usbll_transfer_fragment_error,
            {"Transfer defragmentation error", "usbll.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_usbll_transfer_fragment_count,
            {"Transfer fragment count", "usbll.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_usbll_transfer_reassembled_in,
            {"Reassembled in", "usbll.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_usbll_transfer_reassembled_length,
            {"Reassembled length", "usbll.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},

        /* USB 2.0 Link Power Management Addendum */
        { &hf_usbll_subpid,
            { "SubPID", "usbll.subpid",
              FT_UINT8, BASE_HEX|BASE_EXT_STRING, &usb_subpid_vals_ext, 0x00,
              "Extended Token Packet SubPID", HFILL }},
        { &hf_usbll_lpm_link_state,
            { "bLinkState", "usbll.lpm_link_state",
              FT_UINT16, BASE_CUSTOM, CF_FUNC(lpm_link_state_str), 0x000F,
              NULL, HFILL }},
        { &hf_usbll_lpm_besl,
            { "BESL", "usbll.lpm_besl",
              FT_UINT16, BASE_CUSTOM, CF_FUNC(usb_lpm_besl_str), 0x00F0,
              "Best Effort Service Latency", HFILL}},
        { &hf_usbll_lpm_remote_wake,
            { "bRemoteWake", "usbll.lpm_remote_wake",
              FT_UINT16, BASE_DEC, VALS(usb_lpm_remote_wake_vals), 0x0100,
              NULL, HFILL }},
        { &hf_usbll_lpm_reserved,
            { "Reserved", "usbll.lpm_reserved",
              FT_UINT16, BASE_DEC, NULL, 0x0600,
              NULL, HFILL }},
    };

    static ei_register_info ei[] = {
        { &ei_invalid_pid, { "usbll.invalid_pid", PI_MALFORMED, PI_ERROR, "Invalid USB Packet ID", EXPFILL }},
        { &ei_invalid_subpid, { "usbll.invalid_subpid", PI_MALFORMED, PI_ERROR, "Invalid SubPID", EXPFILL }},
        { &ei_conflicting_subpid, { "usbll.conflicting_subpid", PI_MALFORMED, PI_ERROR, "Token PID cannot be reused as SubPID", EXPFILL }},
        { &ei_undecoded, { "usbll.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
        { &ei_wrong_crc5, { "usbll.crc5.wrong", PI_PROTOCOL, PI_WARN, "Wrong CRC", EXPFILL }},
        { &ei_wrong_split_crc5, { "usbll.split_crc5.wrong", PI_PROTOCOL, PI_WARN, "Wrong CRC", EXPFILL }},
        { &ei_wrong_crc16, { "usbll.crc16.wrong", PI_PROTOCOL, PI_WARN, "Wrong CRC", EXPFILL }},
        { &ei_invalid_s, { "usbll.invalid_s", PI_MALFORMED, PI_ERROR, "Invalid bit (Must be 0)", EXPFILL }},
        { &ei_invalid_e_u, { "usbll.invalid_e_u", PI_MALFORMED, PI_ERROR, "Invalid bit (Must be 0)", EXPFILL }},
        { &ei_invalid_pid_sequence, {"usbll.invalid_pid_sequence", PI_MALFORMED, PI_ERROR, "Invalid PID Sequence",EXPFILL }},
        { &ei_invalid_setup_data, {"usbll.invalid_setup_data", PI_MALFORMED, PI_ERROR, "Invalid data length (Must be 8 bytes)", EXPFILL }},
    };

    static int *ett[] = {
        &ett_usbll,
        &ett_usbll_transfer_fragment,
        &ett_usbll_transfer_fragments,
    };

    transfer_info = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
    proto_usbll = proto_register_protocol("USB Link Layer", "USBLL", "usbll");
    proto_register_field_array(proto_usbll, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module = expert_register_protocol(proto_usbll);
    expert_register_field_array(expert_module, ei, array_length(ei));

    usbll_module = prefs_register_protocol(proto_usbll, NULL);

    prefs_register_enum_preference(usbll_module, "global_pref_dissect_unknown_speed_as",
        "Decode unknown speed packets as",
        "Use specified speed if speed is not indicated in capture",
        &global_dissect_unknown_speed_as, dissect_unknown_speed_as, false);

    unknown_speed_handle = register_dissector("usbll", dissect_usbll_unknown_speed, proto_usbll);
    low_speed_handle = register_dissector("usbll.low_speed", dissect_usbll_low_speed, proto_usbll);
    full_speed_handle = register_dissector("usbll.full_speed", dissect_usbll_full_speed, proto_usbll);
    high_speed_handle = register_dissector("usbll.high_speed", dissect_usbll_high_speed, proto_usbll);
    register_cleanup_routine(usbll_cleanup_data);

    usbll_address_type = address_type_dissector_register("AT_USBLL", "USBLL Address",
                                                         usbll_addr_to_str, usbll_addr_str_len,
                                                         NULL, NULL, NULL, NULL, NULL);

    reassembly_table_register(&usbll_reassembly_table, &usbll_reassembly_table_functions);
}

void
proto_reg_handoff_usbll(void)
{
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USB_2_0, unknown_speed_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USB_2_0_LOW_SPEED, low_speed_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USB_2_0_FULL_SPEED, full_speed_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USB_2_0_HIGH_SPEED, high_speed_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
