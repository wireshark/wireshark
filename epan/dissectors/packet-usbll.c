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
#include "packet-usb.h"

void proto_register_usbll(void);
void proto_reg_handoff_usbll(void);

static int proto_usbll = -1;

/* Fields defined by USB 2.0 standard */
static int hf_usbll_pid = -1;
static int hf_usbll_device_addr = -1;
static int hf_usbll_endp = -1;
static int hf_usbll_crc5 = -1;
static int hf_usbll_crc5_status = -1;
static int hf_usbll_data = -1;
static int hf_usbll_data_crc = -1;
static int hf_usbll_data_crc_status = -1;
static int hf_usbll_sof_framenum = -1;
static int hf_usbll_split_hub_addr = -1;
static int hf_usbll_split_sc = -1;
static int hf_usbll_split_port = -1;
static int hf_usbll_split_s = -1;
static int hf_usbll_split_e = -1;
static int hf_usbll_split_u = -1;
static int hf_usbll_split_iso_se = -1;
static int hf_usbll_split_et = -1;
static int hf_usbll_split_crc5 = -1;
static int hf_usbll_split_crc5_status = -1;
static int hf_usbll_src = -1;
static int hf_usbll_dst = -1;
static int hf_usbll_addr = -1;


static int ett_usbll = -1;

static expert_field ei_invalid_pid = EI_INIT;
static expert_field ei_undecoded = EI_INIT;
static expert_field ei_wrong_crc5 = EI_INIT;
static expert_field ei_wrong_split_crc5 = EI_INIT;
static expert_field ei_wrong_crc16 = EI_INIT;
static expert_field ei_invalid_s = EI_INIT;
static expert_field ei_invalid_e_u = EI_INIT;
static expert_field ei_invalid_pid_sequence = EI_INIT;

static int usbll_address_type = -1;

static dissector_handle_t usbll_handle;

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
#define USB_PID_SPECIAL_RESERVED   0xF0
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
    {USB_PID_SPECIAL_RESERVED,   "Reserved"},
    {0, NULL}
};
static value_string_ext usb_packetid_vals_ext =
    VALUE_STRING_EXT_INIT(usb_packetid_vals);

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
#define SPLIT_BITS_GET_HUB_ADDRESS(bits) (guint8)(bits & 0x007F)
#define SPLIT_BITS_GET_HUB_PORT(bits) (guint8)((bits & 0x7F00) >> 8)
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
} usbll_state_t;

/* usbll_address_t represents the address
 * of Host, Hub and Devices.
 */
typedef struct {
    guint8 flags;       /* flags    - Contains information if address is
                         *            Host, Hub, Device or Broadcast.
                         */
    guint8 device;      /* device   - Device or Hub Address */
    guint8 endpoint;    /* endpoint - It represents endpoint number for
                         *            Device and port number for Hub.
                         */
} usbll_address_t;

typedef struct usbll_transaction_info {
    guint32 starts_in;
    guint8 pid;
    guint8 address;
    guint8 endpoint;
    struct usbll_transaction_info *split_start;
    struct usbll_transaction_info *split_complete;
} usbll_transaction_info_t;

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

static usbll_data_t *usbll_data_ptr = NULL;

/* Transaction Translator arrays used only during first pass. */
static usbll_transaction_info_t ***tt_non_periodic;
static usbll_transaction_info_t ***tt_periodic;

static usbll_state_t
usbll_next_state(usbll_state_t state, guint8 pid)
{
    if (pid == USB_PID_TOKEN_SOF)
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
    else if (pid == USB_PID_SPECIAL_RESERVED)
    {
        /* TODO: Link Power Management */
    }

    /* SPLIT is not suitable for this function as the state cannot be
     * determined by looking solely at PID.
     */
    DISSECTOR_ASSERT(pid != USB_PID_SPECIAL_SPLIT);

    return STATE_IDLE;
}

static gboolean usbll_is_non_periodic_split_start_token(usbll_state_t state)
{
    switch (state)
    {
        case STATE_SSPLIT_CONTROL_SETUP:
        case STATE_SSPLIT_CONTROL_OUT:
        case STATE_SSPLIT_CONTROL_IN:
        case STATE_SSPLIT_BULK_OUT:
        case STATE_SSPLIT_BULK_IN:
            return TRUE;
        default:
            return FALSE;
    }

}
static gboolean usbll_is_periodic_split_start_token(usbll_state_t state)
{
    switch (state)
    {
        case STATE_SSPLIT_INTERRUPT_OUT:
        case STATE_SSPLIT_INTERRUPT_IN:
        case STATE_SSPLIT_ISOCHRONOUS_OUT:
        case STATE_SSPLIT_ISOCHRONOUS_IN:
            return TRUE;
        default:
            return FALSE;
    }

}
static gboolean usbll_is_split_start_token(usbll_state_t state)
{
    return usbll_is_non_periodic_split_start_token(state) || usbll_is_periodic_split_start_token(state);
}

static gboolean usbll_is_non_periodic_split_complete_token(usbll_state_t state)
{
    switch (state)
    {
        case STATE_CSPLIT_CONTROL_SETUP:
        case STATE_CSPLIT_CONTROL_OUT:
        case STATE_CSPLIT_CONTROL_IN:
        case STATE_CSPLIT_BULK_OUT:
        case STATE_CSPLIT_BULK_IN:
            return TRUE;
        default:
            return FALSE;
    }
}

static gboolean usbll_is_periodic_split_complete_token(usbll_state_t state)
{
    switch (state)
    {
        case STATE_CSPLIT_INTERRUPT_OUT:
        case STATE_CSPLIT_INTERRUPT_IN:
        case STATE_CSPLIT_ISOCHRONOUS_IN:
            return TRUE;
        default:
            return FALSE;
    }
}

static gboolean usbll_is_split_complete_token(usbll_state_t state)
{
    return usbll_is_non_periodic_split_complete_token(state) || usbll_is_periodic_split_complete_token(state);
}

static gboolean usbll_is_split_token(usbll_state_t state)
{
    return usbll_is_split_start_token(state) || usbll_is_split_complete_token(state);
}

static gboolean usbll_is_non_split_token(usbll_state_t state)
{
    switch (state)
    {
        case STATE_IN:
        case STATE_OUT:
        case STATE_PING:
        case STATE_SETUP:
            return TRUE;
        default:
            return FALSE;
    }
}

static int usbll_addr_to_str(const address* addr, gchar *buf, int buf_len)
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
        g_snprintf(buf, buf_len, "%d:%d", addrp->device,
                       addrp->endpoint);
    } else {
        /* Just a standard address.endpoint notation. */
        g_snprintf(buf, buf_len, "%d.%d", addrp->device,
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
                  guint8 device, guint8 endpoint, guint8 flags)
{
    proto_item     *sub_item;
    usbll_address_t *src_addr, *dst_addr;
    guint8 *str_src_addr, *str_dst_addr;

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

    str_src_addr = address_to_str(wmem_packet_scope(), &pinfo->src);
    str_dst_addr = address_to_str(wmem_packet_scope(), &pinfo->dst);

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
tt_restore_transaction(packet_info *pinfo, usbll_state_t state, guint8 hub_address, guint8 port)
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
        /* No transaciton has been registered yet */
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
tt_store_transaction(packet_info *pinfo, usbll_state_t state, guint8 hub_address, guint8 port,
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

static gint
dissect_usbll_sof(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    guint32 frame;
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

static gint
dissect_usbll_token(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
                    guint8 pid, usbll_data_t *data)
{
    guint8           device_address;
    guint8           endpoint;
    guint16          address_bits;

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

static gint
dissect_usbll_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                   guint8 pid, usbll_data_t *data)
{
    /* TODO: How to determine the expected DATA size? */
    gint data_size = tvb_reported_length_remaining(tvb, offset) - 2;

    if (data_size > 0) {
        proto_tree_add_item(tree, hf_usbll_data, tvb, offset, data_size, ENC_NA);
        offset += data_size;
    }

    proto_tree_add_checksum(tree, tvb, offset,
                            hf_usbll_data_crc, hf_usbll_data_crc_status, &ei_wrong_crc16, pinfo,
                            crc16_usb_tvb_offset(tvb, 1, offset - 1),
                            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
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

    return offset;
}

static gint
dissect_usbll_split(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
                    guint8 pid, usbll_data_t *data)
{
    guint8           hub_address;
    guint8           hub_port;
    proto_item      *split_e_u;
    proto_item      *split_s;

    gint32 tmp = tvb_get_gint24(tvb, offset, ENC_LITTLE_ENDIAN);

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

static gint
dissect_usbll_handshake(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int offset,
                        guint8 pid, usbll_data_t *data)
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
    }

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
}

static int
dissect_usbll_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    proto_item       *item;
    proto_tree       *tree;
    gint              offset = 0;
    guint32           pid;
    const gchar      *str;

    tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_usbll, &item, "USB Packet");

    item = proto_tree_add_item_ret_uint(tree, hf_usbll_pid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &pid);
    offset++;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBLL");
    str = try_val_to_str(pid, usb_packetid_vals);
    if (str) {
        col_set_str(pinfo->cinfo, COL_INFO, str);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid Packet ID (0x%02x)", pid);
        expert_add_info(pinfo, item, &ei_invalid_pid);
    }

    if (PINFO_FD_VISITED(pinfo)) {
        usbll_data_ptr = usbll_restore_data(pinfo);
    } else {
        usbll_data_ptr = usbll_create_data(pinfo);
    }

    switch (pid)
    {
        case USB_PID_TOKEN_SETUP:
        case USB_PID_TOKEN_OUT:
        case USB_PID_TOKEN_IN:
        case USB_PID_SPECIAL_PING:
            offset = dissect_usbll_token(tvb, pinfo, tree, offset, pid, usbll_data_ptr);
            break;

        case USB_PID_DATA_DATA0:
        case USB_PID_DATA_DATA1:
        case USB_PID_DATA_DATA2:
        case USB_PID_DATA_MDATA:
            offset = dissect_usbll_data(tvb, pinfo, tree, offset, pid, usbll_data_ptr);
            break;

        case USB_PID_HANDSHAKE_ACK:
        case USB_PID_HANDSHAKE_NAK:
        case USB_PID_HANDSHAKE_NYET:
        case USB_PID_HANDSHAKE_STALL:
            offset = dissect_usbll_handshake(tvb, pinfo, tree, offset, pid, usbll_data_ptr);
            break;

        case USB_PID_TOKEN_SOF:
            offset = dissect_usbll_sof(tvb, pinfo, tree, offset);
            break;

        case USB_PID_SPECIAL_SPLIT:
            offset = dissect_usbll_split(tvb, pinfo, tree, offset, pid, usbll_data_ptr);
            break;
        case USB_PID_SPECIAL_PRE_OR_ERR:
            break;
        case USB_PID_SPECIAL_RESERVED:
            break;
        default:
            break;
    }

    usbll_generate_address(tree, tvb, pinfo, usbll_data_ptr);
    if (usbll_data_ptr->transaction_state == STATE_INVALID)
    {
        expert_add_info(pinfo, item, &ei_invalid_pid_sequence);
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert(tree, pinfo, &ei_undecoded, tvb, offset, -1);
        offset += tvb_captured_length_remaining(tvb, offset);
    }

    return offset;
}

void
proto_register_usbll(void)
{
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        /* Common header fields */
        { &hf_usbll_pid,
            { "PID", "usbll.pid",
              FT_UINT8, BASE_HEX|BASE_EXT_STRING, &usb_packetid_vals_ext, 0x00,
              "USB Packet ID", HFILL }},
        { &hf_usbll_src,
            { "Source", "usbll.src",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }},
        { &hf_usbll_dst,
            { "Destination", "usbll.dst",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }},
        { &hf_usbll_addr,
            { "Source or Destination", "usbll.addr",
            FT_STRING, STR_ASCII, NULL, 0x0,
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
              FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }},
        { &hf_usbll_data_crc,
            { "CRC", "usbll.crc16",
              FT_UINT16, BASE_HEX, NULL, 0x0000,
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
    };

    static ei_register_info ei[] = {
        { &ei_invalid_pid, { "usbll.invalid_pid", PI_MALFORMED, PI_ERROR, "Invalid USB Packet ID", EXPFILL }},
        { &ei_undecoded, { "usbll.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
        { &ei_wrong_crc5, { "usbll.crc5.wrong", PI_PROTOCOL, PI_WARN, "Wrong CRC", EXPFILL }},
        { &ei_wrong_split_crc5, { "usbll.split_crc5.wrong", PI_PROTOCOL, PI_WARN, "Wrong CRC", EXPFILL }},
        { &ei_wrong_crc16, { "usbll.crc16.wrong", PI_PROTOCOL, PI_WARN, "Wrong CRC", EXPFILL }},
        { &ei_invalid_s, { "usbll.invalid_s", PI_MALFORMED, PI_ERROR, "Invalid bit (Must be 0)", EXPFILL }},
        { &ei_invalid_e_u, { "usbll.invalid_e_u", PI_MALFORMED, PI_ERROR, "Invalid bit (Must be 0)", EXPFILL }},
        { &ei_invalid_pid_sequence, {"usbll.invalid_pid_sequence", PI_MALFORMED, PI_ERROR, "Invalid PID Sequence",EXPFILL }},
    };

    static gint *ett[] = {
        &ett_usbll,
    };

    proto_usbll = proto_register_protocol("USB Link Layer", "USBLL", "usbll");
    proto_register_field_array(proto_usbll, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module = expert_register_protocol(proto_usbll);
    expert_register_field_array(expert_module, ei, array_length(ei));

    register_dissector("usbll", dissect_usbll_packet, proto_usbll);
    register_cleanup_routine(usbll_cleanup_data);

    usbll_address_type = address_type_dissector_register("AT_USBLL", "USBLL Address",
                                                         usbll_addr_to_str, usbll_addr_str_len,
                                                         NULL, NULL, NULL, NULL, NULL);

}

void
proto_reg_handoff_usbll(void)
{
    usbll_handle = create_dissector_handle(dissect_usbll_packet, proto_usbll);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USB_2_0, usbll_handle);
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
