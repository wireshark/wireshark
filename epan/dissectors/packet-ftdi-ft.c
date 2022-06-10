/* packet-ftdi-ft.c
 * Routines for FTDI FTxxxx USB converters dissection
 *
 * Copyright 2019 Tomasz Mon
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include "packet-usb.h"
#include "packet-ftdi-ft.h"

static int proto_ftdi_ft = -1;

static gint hf_setup_brequest = -1;
static gint hf_setup_lvalue = -1;
static gint hf_setup_lvalue_purge = -1;
static gint hf_setup_lvalue_dtr = -1;
static gint hf_setup_lvalue_rts = -1;
static gint hf_setup_lvalue_xon_char = -1;
static gint hf_setup_lvalue_baud_low = -1;
static gint hf_setup_lvalue_data_size = -1;
static gint hf_setup_lvalue_event_char = -1;
static gint hf_setup_lvalue_error_char = -1;
static gint hf_setup_lvalue_latency_time = -1;
static gint hf_setup_lvalue_bitmask = -1;
static gint hf_setup_hvalue = -1;
static gint hf_setup_hvalue_dtr = -1;
static gint hf_setup_hvalue_rts = -1;
static gint hf_setup_hvalue_xoff_char = -1;
static gint hf_setup_hvalue_baud_mid = -1;
static gint hf_setup_hvalue_parity = -1;
static gint hf_setup_hvalue_stop_bits = -1;
static gint hf_setup_hvalue_break_bit = -1;
static gint hf_setup_hvalue_trigger = -1;
static gint hf_setup_hvalue_error_replacement = -1;
static gint hf_setup_hvalue_bitmode = -1;
static gint hf_setup_lindex = -1;
static gint hf_setup_lindex_port_ab = -1;
static gint hf_setup_lindex_port_abcd = -1;
static gint hf_setup_lindex_baud_high = -1;
static gint hf_setup_hindex = -1;
static gint hf_setup_hindex_rts_cts = -1;
static gint hf_setup_hindex_dtr_dsr = -1;
static gint hf_setup_hindex_xon_xoff = -1;
static gint hf_setup_hindex_baud_high = -1;
static gint hf_setup_hindex_baud_clock_divide = -1;
static gint hf_setup_wlength = -1;
static gint hf_response_lat_timer = -1;
static gint hf_modem_status = -1;
static gint hf_modem_status_fs_max_packet = -1;
static gint hf_modem_status_hs_max_packet = -1;
static gint hf_modem_status_cts = -1;
static gint hf_modem_status_dsr = -1;
static gint hf_modem_status_ri = -1;
static gint hf_modem_status_dcd = -1;
static gint hf_line_status = -1;
static gint hf_line_status_receive_overflow = -1;
static gint hf_line_status_parity_error = -1;
static gint hf_line_status_framing_error = -1;
static gint hf_line_status_break_received = -1;
static gint hf_line_status_tx_holding_reg_empty = -1;
static gint hf_line_status_tx_empty = -1;
static gint hf_if_a_rx_payload = -1;
static gint hf_if_a_tx_payload = -1;
static gint hf_if_b_rx_payload = -1;
static gint hf_if_b_tx_payload = -1;
static gint hf_if_c_rx_payload = -1;
static gint hf_if_c_tx_payload = -1;
static gint hf_if_d_rx_payload = -1;
static gint hf_if_d_tx_payload = -1;
static gint hf_ftdi_fragments = -1;
static gint hf_ftdi_fragment = -1;
static gint hf_ftdi_fragment_overlap = -1;
static gint hf_ftdi_fragment_overlap_conflicts = -1;
static gint hf_ftdi_fragment_multiple_tails = -1;
static gint hf_ftdi_fragment_too_long_fragment = -1;
static gint hf_ftdi_fragment_error = -1;
static gint hf_ftdi_fragment_count = -1;
static gint hf_ftdi_reassembled_in = -1;
static gint hf_ftdi_reassembled_length = -1;

static gint ett_ftdi_ft = -1;
static gint ett_modem_ctrl_lvalue = -1;
static gint ett_modem_ctrl_hvalue = -1;
static gint ett_flow_ctrl_hindex = -1;
static gint ett_baudrate_lindex = -1;
static gint ett_baudrate_hindex = -1;
static gint ett_setdata_hvalue = -1;
static gint ett_modem_status = -1;
static gint ett_line_status = -1;
static gint ett_ftdi_fragment = -1;
static gint ett_ftdi_fragments = -1;

static const fragment_items ftdi_frag_items = {
    /* Fragment subtrees */
    &ett_ftdi_fragment,
    &ett_ftdi_fragments,
    /* Fragment Fields */
    &hf_ftdi_fragments,
    &hf_ftdi_fragment,
    &hf_ftdi_fragment_overlap,
    &hf_ftdi_fragment_overlap_conflicts,
    &hf_ftdi_fragment_multiple_tails,
    &hf_ftdi_fragment_too_long_fragment,
    &hf_ftdi_fragment_error,
    &hf_ftdi_fragment_count,
    /* Reassembled in field */
    &hf_ftdi_reassembled_in,
    /* Reassembled length field */
    &hf_ftdi_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "FTDI FT fragments"
};

static dissector_handle_t ftdi_mpsse_handle;

static expert_field ei_undecoded = EI_INIT;

static dissector_handle_t ftdi_ft_handle;

static reassembly_table ftdi_reassembly_table;

static wmem_tree_t *request_info = NULL;
static wmem_tree_t *bitmode_info = NULL;
static wmem_tree_t *desegment_info = NULL;

typedef struct _request_data {
    guint32  bus_id;
    guint32  device_address;
    guint8   request;
    guint8   hvalue;
    guint8   lindex;
} request_data_t;

typedef struct _bitmode_data {
    guint32        bus_id;
    guint32        device_address;
    FTDI_INTERFACE interface;
    guint8         bitmode;
} bitmode_data_t;

typedef struct _desegment_data desegment_data_t;
struct _desegment_data {
    guint32           bus_id;
    guint32           device_address;
    FTDI_INTERFACE    interface;
    guint8            bitmode;
    gint              p2p_dir;
    /* First frame where the segmented data starts (reassembly key) */
    guint32           first_frame;
    guint32           last_frame;
    gint              first_frame_offset;
    /* Points to desegment data if the previous desegment data ends
     * in last_frame that is equal to this desegment data first_frame.
     */
    desegment_data_t *previous;
};

typedef struct _ftdi_fragment_key {
    guint32           bus_id;
    guint32           device_address;
    FTDI_INTERFACE    interface;
    guint8            bitmode;
    gint              p2p_dir;
    guint32           id;
} ftdi_fragment_key_t;

#define REQUEST_RESET           0x00
#define REQUEST_MODEM_CTRL      0x01
#define REQUEST_SET_FLOW_CTRL   0x02
#define REQUEST_SET_BAUD_RATE   0x03
#define REQUEST_SET_DATA        0x04
#define REQUEST_GET_MODEM_STAT  0x05
#define REQUEST_SET_EVENT_CHAR  0x06
#define REQUEST_SET_ERROR_CHAR  0x07
#define REQUEST_SET_LAT_TIMER   0x09
#define REQUEST_GET_LAT_TIMER   0x0A
#define REQUEST_SET_BITMODE     0x0B

static const value_string request_vals[] = {
    {REQUEST_RESET,           "Reset"},
    {REQUEST_MODEM_CTRL,      "ModemCtrl"},
    {REQUEST_SET_FLOW_CTRL,   "SetFlowCtrl"},
    {REQUEST_SET_BAUD_RATE,   "SetBaudRate"},
    {REQUEST_SET_DATA,        "SetData"},
    {REQUEST_GET_MODEM_STAT,  "GetModemStat"},
    {REQUEST_SET_EVENT_CHAR,  "SetEventChar"},
    {REQUEST_SET_ERROR_CHAR,  "SetErrorChar"},
    {REQUEST_SET_LAT_TIMER,   "SetLatTimer"},
    {REQUEST_GET_LAT_TIMER,   "GetLatTimer"},
    {REQUEST_SET_BITMODE,     "SetBitMode"},
    {0, NULL}
};
static value_string_ext request_vals_ext  = VALUE_STRING_EXT_INIT(request_vals);

static const value_string reset_purge_vals[] = {
    {0x00, "Purge RX and TX"},
    {0x01, "Purge RX"},
    {0x02, "Purge TX"},
    {0, NULL}
};

static const value_string index_port_ab_vals[] = {
    {0x00, "Port A"},
    {0x01, "Port A"},
    {0x02, "Port B"},
    {0, NULL}
};

static const value_string index_port_abcd_vals[] = {
    {0x00, "Port A"},
    {0x01, "Port A"},
    {0x02, "Port B"},
    {0x03, "Port C"},
    {0x04, "Port D"},
    {0, NULL}
};

static const value_string data_size_vals[] = {
    {0x07, "7 bit data"},
    {0x08, "8 bit data"},
    {0, NULL}
};

static const value_string parity_vals[] = {
    {0x0, "None"},
    {0x1, "Odd"},
    {0x2, "Even"},
    {0x3, "Mark"},
    {0x4, "Space"},
    {0, NULL}
};

static const value_string stop_bits_vals[] = {
    {0, "1 stop bit"},
    {1, "2 stop bits"},
    {0, NULL}
};

static const value_string break_bit_vals[] = {
    {0, "No Break"},
    {1, "Set Break"},
    {0, NULL}
};

static const value_string event_char_trigger_vals[] = {
    {0x00, "No trigger"},
    {0x01, "Trigger IN on Event Char"},
    {0, NULL}
};

static const value_string error_replacement_vals[] = {
    {0x00, "No Error Replacement"},
    {0x01, "Error Replacement On"},
    {0, NULL}
};

#define BITMODE_RESET   0x00
#define BITMODE_BITBANG 0x01
#define BITMODE_MPSSE   0x02
#define BITMODE_SYNCBB  0x04
#define BITMODE_MCU     0x08
#define BITMODE_OPTO    0x10
#define BITMODE_CBUS    0x20
#define BITMODE_SYNCFF  0x40
#define BITMODE_FT1284  0x80


static const value_string bitmode_vals[] = {
    {BITMODE_RESET,   "switch off bitbang mode, back to regular serial / FIFO"},
    {BITMODE_BITBANG, "classical asynchronous bitbang mode, introduced with B-type chips"},
    {BITMODE_MPSSE,   "MPSSE mode, available on 2232x chips"},
    {BITMODE_SYNCBB,  "synchronous bitbang mode, available on 2232x and R-type chips"},
    {BITMODE_MCU,     "MCU Host Bus Emulation mode, available on 2232x chips"},
    {BITMODE_OPTO,    "Fast Opto-Isolated Serial Interface Mode, available on 2232x chips"},
    {BITMODE_CBUS,    "Bitbang on CBUS pins of R-type chips, configure in EEPROM before"},
    {BITMODE_SYNCFF,  "Single Channel Synchronous FIFO mode, available on 2232H chips"},
    {BITMODE_FT1284,  "FT1284 mode, available on 232H chips"},
    {0, NULL}
};

#define MODEM_STATUS_BIT_FS_64_MAX_PACKET  (1 << 0)
#define MODEM_STATUS_BIT_HS_512_MAX_PACKET (1 << 1)

void proto_register_ftdi_ft(void);
void proto_reg_handoff_ftdi_ft(void);

/* It is assumed that this function is called only when the device is known
 * to be FTDI FT chip and thus the VID and PID is not checked here.
 * This function determines chip based on bcdDevice version which cannot be
 * altered by the hardware vendor.
 */
static FTDI_CHIP
identify_chip(usb_conv_info_t *usb_conv_info)
{
    switch (usb_conv_info->deviceVersion)
    {
    case 0x0200:
        if (usb_conv_info->iSerialNumber)
        {
            /* Serial number enabled - it is FT8U232AM */
            return FTDI_CHIP_FT8U232AM;
        }
        /* No serial number - FT232B without (or with blank) EEPROM fitted */
        return FTDI_CHIP_FT232B;
    case 0x0400:
        return FTDI_CHIP_FT232B;
    case 0x0500:
        return FTDI_CHIP_FT2232D;
    case 0x0600:
        return FTDI_CHIP_FT232R;
    case 0x0700:
        return FTDI_CHIP_FT2232H;
    case 0x0800:
        return FTDI_CHIP_FT4232H;
    case 0x0900:
        return FTDI_CHIP_FT232H;
    case 0x1000:
        return FTDI_CHIP_X_SERIES;
    default:
        return FTDI_CHIP_UNKNOWN;
    }
}

static FTDI_INTERFACE
endpoint_to_interface(usb_conv_info_t *usb_conv_info)
{
    switch (usb_conv_info->endpoint)
    {
    case 0x01: /* A OUT */
    case 0x02: /* A IN */
        return FTDI_INTERFACE_A;
    case 0x03: /* B OUT */
    case 0x04: /* B IN */
        return FTDI_INTERFACE_B;
    case 0x05: /* C OUT */
    case 0x06: /* C IN */
        return FTDI_INTERFACE_C;
    case 0x07: /* D OUT */
    case 0x08: /* D IN */
        return FTDI_INTERFACE_D;
    default:
        return FTDI_INTERFACE_UNKNOWN;
    }
}

static FTDI_INTERFACE
lindex_to_interface(guint8 lindex)
{
    switch (lindex)
    {
    case 0: /* ANY, default to A */
    case 1:
        return FTDI_INTERFACE_A;
    case 2:
        return FTDI_INTERFACE_B;
    case 3:
        return FTDI_INTERFACE_C;
    case 4:
        return FTDI_INTERFACE_D;
    default:
        return FTDI_INTERFACE_UNKNOWN;
    }
}

static gint
dissect_request_reset(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, proto_tree *tree)
{
    gint offset_start = offset;

    proto_tree_add_item(tree, hf_setup_lvalue_purge, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hvalue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_lindex_port_abcd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    return offset - offset_start;
}

static gint
dissect_request_modem_ctrl(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, proto_tree *tree)
{
    static int * const lvalue_bits[] = {
        &hf_setup_lvalue_dtr,
        &hf_setup_lvalue_rts,
        NULL
    };
    static int * const hvalue_bits[] = {
        &hf_setup_hvalue_dtr,
        &hf_setup_hvalue_rts,
        NULL
    };
    gint offset_start = offset;

    proto_tree_add_bitmask(tree, tvb, offset, hf_setup_lvalue,
        ett_modem_ctrl_lvalue, lvalue_bits, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_bitmask(tree, tvb, offset, hf_setup_hvalue,
        ett_modem_ctrl_hvalue, hvalue_bits, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_lindex_port_abcd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    return offset - offset_start;
}

static gint
dissect_request_set_flow_ctrl(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, proto_tree *tree)
{
    static int * const hindex_bits[] = {
        &hf_setup_hindex_rts_cts,
        &hf_setup_hindex_dtr_dsr,
        &hf_setup_hindex_xon_xoff,
        NULL
    };
    gint offset_start = offset;

    proto_tree_add_item(tree, hf_setup_lvalue_xon_char, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hvalue_xoff_char, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_lindex_port_abcd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_bitmask(tree, tvb, offset, hf_setup_hindex,
        ett_flow_ctrl_hindex, hindex_bits, ENC_LITTLE_ENDIAN);
    offset++;

    return offset - offset_start;
}

static gint
dissect_request_set_baud_rate(tvbuff_t *tvb, packet_info *pinfo, gint offset, proto_tree *tree, FTDI_CHIP chip)
{
    static int * const lindex_bits[] = {
        &hf_setup_lindex_baud_high,
        NULL
    };
    static int * const hindex_bits[] = {
        &hf_setup_hindex_baud_high,
        NULL
    };
    static int * const hindex_bits_hispeed[] = {
        &hf_setup_hindex_baud_high,
        &hf_setup_hindex_baud_clock_divide,
        NULL
    };

    gint offset_start = offset;

    proto_tree_add_item(tree, hf_setup_lvalue_baud_low, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hvalue_baud_mid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    switch (chip)
    {
    case FTDI_CHIP_FT8U232AM:
        proto_tree_add_item(tree, hf_setup_lindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        proto_tree_add_item(tree, hf_setup_hindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case FTDI_CHIP_FT232B:
    case FTDI_CHIP_FT232R:
        proto_tree_add_bitmask(tree, tvb, offset, hf_setup_lindex,
            ett_baudrate_lindex, lindex_bits, ENC_LITTLE_ENDIAN);
        offset++;

        proto_tree_add_item(tree, hf_setup_hindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case FTDI_CHIP_FT2232D:
    case FTDI_CHIP_X_SERIES:
        proto_tree_add_item(tree, hf_setup_lindex_port_ab, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        proto_tree_add_bitmask(tree, tvb, offset, hf_setup_hindex,
            ett_baudrate_hindex, hindex_bits, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case FTDI_CHIP_FT2232H:
    case FTDI_CHIP_FT4232H:
    case FTDI_CHIP_FT232H:
        proto_tree_add_item(tree, hf_setup_lindex_port_abcd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        proto_tree_add_bitmask(tree, tvb, offset, hf_setup_hindex,
            ett_baudrate_hindex, hindex_bits_hispeed, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case FTDI_CHIP_UNKNOWN:
    default:
        proto_tree_add_expert(tree, pinfo, &ei_undecoded, tvb, offset, 2);
        offset += 2;
        break;
    }
    return offset - offset_start;
}

static gint
dissect_request_set_data(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, proto_tree *tree)
{
    static int * const hvalue_bits[] = {
        &hf_setup_hvalue_parity,
        &hf_setup_hvalue_stop_bits,
        &hf_setup_hvalue_break_bit,
        NULL
    };
    gint offset_start = offset;

    proto_tree_add_item(tree, hf_setup_lvalue_data_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_bitmask(tree, tvb, offset, hf_setup_hvalue,
        ett_setdata_hvalue, hvalue_bits, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_lindex_port_abcd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    return offset - offset_start;
}

static gint
dissect_request_get_modem_stat(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, proto_tree *tree)
{
    gint offset_start = offset;

    proto_tree_add_item(tree, hf_setup_lvalue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hvalue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_lindex_port_abcd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    return offset - offset_start;
}

static gint
dissect_request_set_event_char(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, proto_tree *tree)
{
    gint offset_start = offset;

    proto_tree_add_item(tree, hf_setup_lvalue_event_char, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hvalue_trigger, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_lindex_port_abcd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    return offset - offset_start;
}

static gint
dissect_request_set_error_char(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, proto_tree *tree)
{
    gint offset_start = offset;

    proto_tree_add_item(tree, hf_setup_lvalue_error_char, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hvalue_error_replacement, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_lindex_port_abcd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;


    return offset - offset_start;
}

static gint
dissect_request_set_lat_timer(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, proto_tree *tree)
{
    gint offset_start = offset;

    proto_tree_add_item(tree, hf_setup_lvalue_latency_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hvalue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_lindex_port_abcd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    return offset - offset_start;
}

static gint
dissect_request_get_lat_timer(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, proto_tree *tree)
{
    gint offset_start = offset;

    proto_tree_add_item(tree, hf_setup_lvalue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hvalue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_lindex_port_abcd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    return offset - offset_start;
}

static gint
dissect_response_get_lat_timer(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, proto_tree *tree)
{
    gint offset_start = offset;

    proto_tree_add_item(tree, hf_response_lat_timer, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    return offset - offset_start;
}

static gint
dissect_request_set_bitmode(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, proto_tree *tree)
{
    gint offset_start = offset;

    proto_tree_add_item(tree, hf_setup_lvalue_bitmask, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hvalue_bitmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_lindex_port_abcd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_setup_hindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    return offset - offset_start;
}

static gint
dissect_modem_status_bytes(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, proto_tree *tree, gint *out_rx_len)
{
    static int * const modem_status_bits[] = {
        &hf_modem_status_fs_max_packet,
        &hf_modem_status_hs_max_packet,
        &hf_modem_status_cts,
        &hf_modem_status_dsr,
        &hf_modem_status_ri,
        &hf_modem_status_dcd,
        NULL
    };
    static int * const line_status_bits[] = {
        &hf_line_status_receive_overflow,
        &hf_line_status_parity_error,
        &hf_line_status_framing_error,
        &hf_line_status_break_received,
        &hf_line_status_tx_holding_reg_empty,
        &hf_line_status_tx_empty,
        NULL
    };
    guint64 modem_status;

    proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_modem_status,
        ett_modem_status, modem_status_bits, ENC_LITTLE_ENDIAN, &modem_status);
    offset++;

    proto_tree_add_bitmask(tree, tvb, offset, hf_line_status,
        ett_line_status, line_status_bits, ENC_LITTLE_ENDIAN);
    offset++;

    if (out_rx_len)
    {
        *out_rx_len = tvb_reported_length_remaining(tvb, offset);
        if (modem_status & MODEM_STATUS_BIT_FS_64_MAX_PACKET)
        {
            /* 2 bytes modem status, 62 bytes payload */
            *out_rx_len = MIN(*out_rx_len, 62);
        }
        else if (modem_status & MODEM_STATUS_BIT_HS_512_MAX_PACKET)
        {
            /* 2 bytes modem status, 510 bytes payload */
            *out_rx_len = MIN(*out_rx_len, 510);
        }
    }

    return 2;
}

static void
record_interface_mode(packet_info *pinfo, usb_conv_info_t *usb_conv_info, FTDI_INTERFACE interface, guint8 bitmode)
{
    guint32         k_bus_id = usb_conv_info->bus_id;
    guint32         k_device_address = usb_conv_info->device_address;
    guint32         k_interface = (guint32)interface;
    wmem_tree_key_t key[] = {
        {1, &k_bus_id},
        {1, &k_device_address},
        {1, &k_interface},
        {1, &pinfo->num},
        {0, NULL}
    };
    bitmode_data_t *bitmode_data = NULL;

    bitmode_data = wmem_new(wmem_file_scope(), bitmode_data_t);
    bitmode_data->bus_id = usb_conv_info->bus_id;
    bitmode_data->device_address = usb_conv_info->device_address;
    bitmode_data->interface = interface;
    bitmode_data->bitmode = bitmode;
    wmem_tree_insert32_array(bitmode_info, key, bitmode_data);
}

static guint8
get_recorded_interface_mode(packet_info *pinfo, usb_conv_info_t *usb_conv_info, FTDI_INTERFACE interface)
{
    guint32         k_bus_id = usb_conv_info->bus_id;
    guint32         k_device_address = usb_conv_info->device_address;
    guint32         k_interface = (guint32)interface;
    wmem_tree_key_t key[] = {
        {1, &k_bus_id},
        {1, &k_device_address},
        {1, &k_interface},
        {1, &pinfo->num},
        {0, NULL}
    };

    bitmode_data_t *bitmode_data = NULL;
    bitmode_data = (bitmode_data_t *)wmem_tree_lookup32_array_le(bitmode_info, key);
    if (bitmode_data && bitmode_data->bus_id == k_bus_id && bitmode_data->device_address == k_device_address &&
        bitmode_data->interface == interface)
    {
        return bitmode_data->bitmode;
    }

    return 0; /* Default to 0, which is plain serial data */
}

static desegment_data_t *
record_desegment_data(packet_info *pinfo, usb_conv_info_t *usb_conv_info,
                      FTDI_INTERFACE interface, guint8 bitmode)
{
    guint32         k_bus_id = usb_conv_info->bus_id;
    guint32         k_device_address = usb_conv_info->device_address;
    guint32         k_interface = (guint32)interface;
    guint32         k_p2p_dir = (guint32)pinfo->p2p_dir;
    wmem_tree_key_t key[] = {
        {1, &k_bus_id},
        {1, &k_device_address},
        {1, &k_interface},
        {1, &k_p2p_dir},
        {1, &pinfo->num},
        {0, NULL}
    };
    desegment_data_t *desegment_data = NULL;

    desegment_data = wmem_new(wmem_file_scope(), desegment_data_t);
    desegment_data->bus_id = usb_conv_info->bus_id;
    desegment_data->device_address = usb_conv_info->device_address;
    desegment_data->interface = interface;
    desegment_data->bitmode = bitmode;
    desegment_data->p2p_dir = pinfo->p2p_dir;
    desegment_data->first_frame = pinfo->num;
    /* Last frame is currently unknown */
    desegment_data->last_frame = 0;
    desegment_data->first_frame_offset = 0;
    desegment_data->previous = NULL;

    wmem_tree_insert32_array(desegment_info, key, desegment_data);
    return desegment_data;
}

static desegment_data_t *
get_recorded_desegment_data(packet_info *pinfo, usb_conv_info_t *usb_conv_info,
                            FTDI_INTERFACE interface, guint8 bitmode)
{
    guint32         k_bus_id = usb_conv_info->bus_id;
    guint32         k_device_address = usb_conv_info->device_address;
    guint32         k_interface = (guint32)interface;
    guint32         k_p2p_dir = (guint32)pinfo->p2p_dir;
    wmem_tree_key_t key[] = {
        {1, &k_bus_id},
        {1, &k_device_address},
        {1, &k_interface},
        {1, &k_p2p_dir},
        {1, &pinfo->num},
        {0, NULL}
    };

    desegment_data_t *desegment_data = NULL;
    desegment_data = (desegment_data_t*)wmem_tree_lookup32_array_le(desegment_info, key);
    if (desegment_data && desegment_data->bus_id == k_bus_id && desegment_data->device_address == k_device_address &&
        desegment_data->interface == interface && desegment_data->bitmode == bitmode &&
        desegment_data->p2p_dir == pinfo->p2p_dir)
    {
        /* Return desegment data only if it is relevant to current packet */
        if ((desegment_data->last_frame == 0) || (desegment_data->last_frame >= pinfo->num))
        {
            return desegment_data;
        }
    }

    return NULL;
}

static guint ftdi_fragment_key_hash(gconstpointer k)
{
    const ftdi_fragment_key_t *key = (const ftdi_fragment_key_t *)k;
    return key->id;
}

static gint ftdi_fragment_key_equal(gconstpointer k1, gconstpointer k2)
{
    const ftdi_fragment_key_t *key1 = (const ftdi_fragment_key_t *)k1;
    const ftdi_fragment_key_t *key2 = (const ftdi_fragment_key_t *)k2;

    /* id is most likely to differ and thus should be checked first */
    return (key1->id == key2->id) &&
           (key1->bus_id == key2->bus_id) &&
           (key1->device_address == key2->device_address) &&
           (key1->interface == key2->interface) &&
           (key1->bitmode == key2->bitmode) &&
           (key1->p2p_dir == key2->p2p_dir);
}

static gpointer ftdi_fragment_key(const packet_info *pinfo _U_, const guint32 id, const void *data)
{
    desegment_data_t *desegment_data = (desegment_data_t *)data;
    ftdi_fragment_key_t *key = g_slice_new(ftdi_fragment_key_t);

    key->bus_id = desegment_data->bus_id;
    key->device_address = desegment_data->device_address;
    key->interface = desegment_data->interface;
    key->bitmode = desegment_data->bitmode;
    key->p2p_dir = desegment_data->p2p_dir;
    key->id = id;

    return (gpointer)key;
}

static void ftdi_fragment_free_key(gpointer ptr)
{
    ftdi_fragment_key_t *key = (ftdi_fragment_key_t *)ptr;
    g_slice_free(ftdi_fragment_key_t, key);
}

static const reassembly_table_functions ftdi_reassembly_table_functions = {
    .hash_func = ftdi_fragment_key_hash,
    .equal_func = ftdi_fragment_key_equal,
    .temporary_key_func = ftdi_fragment_key,
    .persistent_key_func = ftdi_fragment_key,
    .free_temporary_key_func = ftdi_fragment_free_key,
    .free_persistent_key_func = ftdi_fragment_free_key,
};

static void
dissect_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, usb_conv_info_t *usb_conv_info,
                FTDI_INTERFACE interface, guint8 bitmode)
{
    guint32           k_bus_id;
    guint32           k_device_address;

    k_bus_id = usb_conv_info->bus_id;
    k_device_address = usb_conv_info->device_address;

    if (tvb && ((bitmode == BITMODE_MPSSE) || (bitmode == BITMODE_MCU)))
    {
        ftdi_mpsse_info_t mpsse_info = {
            .bus_id = k_bus_id,
            .device_address = k_device_address,
            .chip = identify_chip(usb_conv_info),
            .iface = interface,
            .mcu_mode = (bitmode == BITMODE_MCU),
        };
        call_dissector_with_data(ftdi_mpsse_handle, tvb, pinfo, tree, &mpsse_info);
    }
}

static gint
dissect_serial_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *ftdi_tree,
                       usb_conv_info_t *usb_conv_info, FTDI_INTERFACE interface)
{
    guint16           save_can_desegment;
    int               save_desegment_offset;
    guint32           save_desegment_len;
    desegment_data_t *desegment_data;
    guint32           bytes;

    save_can_desegment = pinfo->can_desegment;
    save_desegment_offset = pinfo->desegment_offset;
    save_desegment_len = pinfo->desegment_len;

    bytes = tvb_reported_length(tvb);
    if (bytes > 0)
    {
        tvbuff_t *payload_tvb = NULL;
        guint32   reassembled_bytes = 0;
        guint8    bitmode;
        guint8    curr_layer_num = pinfo->curr_layer_num;

        bitmode = get_recorded_interface_mode(pinfo, usb_conv_info, interface);

        pinfo->can_desegment = 2;
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = 0;

        desegment_data = get_recorded_desegment_data(pinfo, usb_conv_info, interface, bitmode);
        if (desegment_data)
        {
            fragment_head    *fd_head;
            desegment_data_t *next_desegment_data = NULL;

            if ((desegment_data->previous) && (desegment_data->first_frame == pinfo->num))
            {
                DISSECTOR_ASSERT(desegment_data->previous->last_frame == pinfo->num);

                next_desegment_data = desegment_data;
                desegment_data = desegment_data->previous;
            }

            if (!PINFO_FD_VISITED(pinfo))
            {
                /* Combine data reassembled so far with current tvb and check if this is last fragment or not */
                fragment_item *item;
                fd_head = fragment_get(&ftdi_reassembly_table, pinfo, desegment_data->first_frame, desegment_data);
                DISSECTOR_ASSERT(fd_head && !(fd_head->flags & FD_DEFRAGMENTED) && fd_head->next);
                payload_tvb = tvb_new_composite();
                for (item = fd_head->next; item; item = item->next)
                {
                    DISSECTOR_ASSERT(reassembled_bytes == item->offset);
                    tvb_composite_append(payload_tvb, item->tvb_data);
                    reassembled_bytes += item->len;
                }
                tvb_composite_append(payload_tvb, tvb);
                tvb_composite_finalize(payload_tvb);
            }
            else
            {
                fd_head = fragment_get_reassembled_id(&ftdi_reassembly_table, pinfo, desegment_data->first_frame);
                payload_tvb = process_reassembled_data(tvb, 0, pinfo, "Reassembled", fd_head,
                                                       &ftdi_frag_items, NULL, ftdi_tree);
            }

            if (next_desegment_data)
            {
                fragment_head *next_head;
                next_head = fragment_get_reassembled_id(&ftdi_reassembly_table, pinfo, next_desegment_data->first_frame);
                process_reassembled_data(tvb, 0, pinfo, "Reassembled", next_head, &ftdi_frag_items, NULL, ftdi_tree);
            }

            if ((desegment_data->first_frame == pinfo->num) && (desegment_data->first_frame_offset > 0))
            {
                payload_tvb = tvb_new_subset_length(tvb, 0, desegment_data->first_frame_offset);
            }
        }
        else
        {
            /* Packet is not part of reassembly sequence, simply use it without modifications */
            payload_tvb = tvb;
        }

        dissect_payload(payload_tvb, pinfo, tree, usb_conv_info, interface, bitmode);

        if (!PINFO_FD_VISITED(pinfo))
        {
            /* FTDI FT dissector doesn't know if the last fragment is really the last one unless it passes
             * the data to the next dissector. There is absolutely no metadata that could help with it as
             * FTDI FT is pretty much a direct replacement to UART (COM port) and is pretty much transparent
             * to the actual serial protocol used.
             *
             * Passing the data to next dissector results in curr_layer_num being increased if it dissected
             * the data (when it is the last fragment). This would prevent the process_reassembled_data()
             * (after the first pass) from returning the reassembled tvb in FTFI FT which in turn prevents
             * the data from being passed to the next dissector.
             *
             * Override pinfo->curr_layer_num value when the fragments are being added to reassembly table.
             * This is ugly hack. Is there any better approach?
             *
             * There doesn't seem to be a mechanism to "back-track" just added fragments to reassembly table,
             * or any way to "shorten" the last added fragment. The most problematic case is when current
             * packet is both last packet for previous reassembly and a first packet for next reassembly.
             */
            guint8 save_curr_layer_num = pinfo->curr_layer_num;
            pinfo->curr_layer_num = curr_layer_num;

            if (!pinfo->desegment_len)
            {
                if (desegment_data)
                {
                    /* Current tvb is really the last fragment */
                    fragment_add_check(&ftdi_reassembly_table, tvb, 0, pinfo, desegment_data->first_frame,
                                       desegment_data, reassembled_bytes, bytes, FALSE);
                    desegment_data->last_frame = pinfo->num;
                }
            }
            else
            {
                DISSECTOR_ASSERT_HINT(pinfo->desegment_len == DESEGMENT_ONE_MORE_SEGMENT,
                                      "FTDI FT supports only DESEGMENT_ONE_MORE_SEGMENT");
                if (!desegment_data)
                {
                    /* Start desegmenting */
                    gint fragment_length = tvb_reported_length_remaining(tvb, pinfo->desegment_offset);
                    desegment_data = record_desegment_data(pinfo, usb_conv_info, interface, bitmode);
                    desegment_data->first_frame_offset = pinfo->desegment_offset;
                    fragment_add_check(&ftdi_reassembly_table, tvb, pinfo->desegment_offset, pinfo,
                                       desegment_data->first_frame, desegment_data, 0, fragment_length, TRUE);
                }
                else if (pinfo->desegment_offset == 0)
                {
                    /* Continue reassembling */
                    fragment_add_check(&ftdi_reassembly_table, tvb, 0, pinfo, desegment_data->first_frame,
                                       desegment_data, reassembled_bytes, bytes, TRUE);
                }
                else
                {
                    gint fragment_length;
                    gint previous_bytes;
                    desegment_data_t *previous_desegment_data;

                    /* This packet contains both an end from a previous reassembly and start of a new one */
                    DISSECTOR_ASSERT((guint32)pinfo->desegment_offset > reassembled_bytes);
                    previous_bytes = pinfo->desegment_offset - reassembled_bytes;
                    fragment_add_check(&ftdi_reassembly_table, tvb, 0, pinfo, desegment_data->first_frame,
                                       desegment_data, reassembled_bytes, previous_bytes, FALSE);
                    desegment_data->last_frame = pinfo->num;

                    previous_desegment_data = desegment_data;
                    fragment_length = bytes - previous_bytes;
                    desegment_data = record_desegment_data(pinfo, usb_conv_info, interface, bitmode);
                    desegment_data->first_frame_offset = previous_bytes;
                    desegment_data->previous = previous_desegment_data;
                    fragment_add_check(&ftdi_reassembly_table, tvb, previous_bytes, pinfo, desegment_data->first_frame,
                                       desegment_data, 0, fragment_length, TRUE);
                }
            }

            pinfo->curr_layer_num = save_curr_layer_num;
        }
    }

    pinfo->can_desegment = save_can_desegment;
    pinfo->desegment_offset = save_desegment_offset;
    pinfo->desegment_len = save_desegment_len;

    return bytes;
}

static gint
dissect_ftdi_ft(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item       *main_item;
    proto_tree       *main_tree;
    gint              offset = 0;
    usb_conv_info_t  *usb_conv_info = (usb_conv_info_t *)data;
    request_data_t   *request_data = NULL;
    wmem_tree_key_t   key[4];
    guint32           k_bus_id;
    guint32           k_device_address;

    if (!usb_conv_info)
    {
        return offset;
    }

    if (usb_conv_info->is_setup)
    {
        /* This dissector can only process device Vendor specific setup data */
        if ((USB_TYPE(usb_conv_info->setup_requesttype) != RQT_SETUP_TYPE_VENDOR) ||
            (USB_RECIPIENT(usb_conv_info->setup_requesttype) != RQT_SETUP_RECIPIENT_DEVICE))
        {
            return offset;
        }
    }

    k_bus_id = usb_conv_info->bus_id;
    k_device_address = usb_conv_info->device_address;

    key[0].length = 1;
    key[0].key = &k_bus_id;
    key[1].length = 1;
    key[1].key = &k_device_address;
    key[2].length = 1;
    key[2].key = &pinfo->num;
    key[3].length = 0;
    key[3].key = NULL;

    main_item = proto_tree_add_item(tree, proto_ftdi_ft, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_ftdi_ft);

    if (usb_conv_info->transfer_type == URB_CONTROL)
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "FTDI FT");
        col_set_str(pinfo->cinfo, COL_INFO, "FTDI FT ");
        col_append_str(pinfo->cinfo, COL_INFO, usb_conv_info->is_request ? "Request" : "Response");

        if (usb_conv_info->is_setup)
        {
            gint         bytes_dissected;
            guint8       brequest;
            guint8       hvalue;
            guint8       lindex;

            brequest = tvb_get_guint8(tvb, offset);
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
                val_to_str_ext_const(brequest, &request_vals_ext, "Unknown"));
            proto_tree_add_item(main_tree, hf_setup_brequest, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            hvalue = tvb_get_guint8(tvb, offset + 1);
            lindex = tvb_get_guint8(tvb, offset + 2);

            switch (brequest)
            {
            case REQUEST_RESET:
                bytes_dissected = dissect_request_reset(tvb, pinfo, offset, main_tree);
                break;
            case REQUEST_MODEM_CTRL:
                bytes_dissected = dissect_request_modem_ctrl(tvb, pinfo, offset, main_tree);
                break;
            case REQUEST_SET_FLOW_CTRL:
                bytes_dissected = dissect_request_set_flow_ctrl(tvb, pinfo, offset, main_tree);
                break;
            case REQUEST_SET_BAUD_RATE:
            {
                FTDI_CHIP chip = identify_chip(usb_conv_info);
                bytes_dissected = dissect_request_set_baud_rate(tvb, pinfo, offset, main_tree, chip);
                break;
            }
            case REQUEST_SET_DATA:
                bytes_dissected = dissect_request_set_data(tvb, pinfo, offset, main_tree);
                break;
            case REQUEST_GET_MODEM_STAT:
                bytes_dissected = dissect_request_get_modem_stat(tvb, pinfo, offset, main_tree);
                break;
            case REQUEST_SET_EVENT_CHAR:
                bytes_dissected = dissect_request_set_event_char(tvb, pinfo, offset, main_tree);
                break;
            case REQUEST_SET_ERROR_CHAR:
                bytes_dissected = dissect_request_set_error_char(tvb, pinfo, offset, main_tree);
                break;
            case REQUEST_SET_LAT_TIMER:
                bytes_dissected = dissect_request_set_lat_timer(tvb, pinfo, offset, main_tree);
                break;
            case REQUEST_GET_LAT_TIMER:
                bytes_dissected = dissect_request_get_lat_timer(tvb, pinfo, offset, main_tree);
                break;
            case REQUEST_SET_BITMODE:
                bytes_dissected = dissect_request_set_bitmode(tvb, pinfo, offset, main_tree);
                break;
            default:
                bytes_dissected = 0;
                break;
            }

            offset += bytes_dissected;
            if (bytes_dissected < 4)
            {
                proto_tree_add_expert(main_tree, pinfo, &ei_undecoded, tvb, offset, 4 - bytes_dissected);
                offset += 4 - bytes_dissected;
            }

            proto_tree_add_item(main_tree, hf_setup_wlength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            /* Record the request type so we can find it when dissecting response */
            request_data = wmem_new(wmem_file_scope(), request_data_t);
            request_data->bus_id = usb_conv_info->bus_id;
            request_data->device_address = usb_conv_info->device_address;
            request_data->request = brequest;
            request_data->hvalue = hvalue;
            request_data->lindex = lindex;
            wmem_tree_insert32_array(request_info, key, request_data);
        }
        else
        {
            /* Retrieve request type */
            request_data = (request_data_t *)wmem_tree_lookup32_array_le(request_info, key);
            if (request_data && request_data->bus_id == k_bus_id && request_data->device_address == k_device_address)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
                    val_to_str_ext_const(request_data->request, &request_vals_ext, "Unknown"));

                switch (request_data->request)
                {
                case REQUEST_GET_MODEM_STAT:
                    offset += dissect_modem_status_bytes(tvb, pinfo, offset, main_tree, NULL);
                    break;
                case REQUEST_GET_LAT_TIMER:
                    offset += dissect_response_get_lat_timer(tvb, pinfo, offset, main_tree);
                    break;
                case REQUEST_SET_BITMODE:
                    /* TODO: Record interface mode only if the control request has succeeded */
                    record_interface_mode(pinfo, usb_conv_info, lindex_to_interface(request_data->lindex), request_data->hvalue);
                    break;
                default:
                    break;
                }
            }
            else
            {
                col_append_str(pinfo->cinfo, COL_INFO, ": Unknown");
            }

            /* Report any potentially undissected response data */
            if (tvb_reported_length_remaining(tvb, offset) > 0)
            {
                proto_tree_add_expert(main_tree, pinfo, &ei_undecoded, tvb, offset, -1);
            }
        }
    }
    else
    {
        const char *interface_str;
        FTDI_INTERFACE interface;
        gint rx_hf, tx_hf;

        interface = endpoint_to_interface(usb_conv_info);
        switch (interface)
        {
        case FTDI_INTERFACE_A:
            interface_str = "A";
            rx_hf = hf_if_a_rx_payload;
            tx_hf = hf_if_a_tx_payload;
            break;
        case FTDI_INTERFACE_B:
            interface_str = "B";
            rx_hf = hf_if_b_rx_payload;
            tx_hf = hf_if_b_tx_payload;
            break;
        case FTDI_INTERFACE_C:
            interface_str = "C";
            rx_hf = hf_if_c_rx_payload;
            tx_hf = hf_if_c_tx_payload;
            break;
        case FTDI_INTERFACE_D:
            interface_str = "D";
            rx_hf = hf_if_d_rx_payload;
            tx_hf = hf_if_d_tx_payload;
            break;
        default:
            return offset;
        }

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "FTDI FT");
        if (pinfo->p2p_dir == P2P_DIR_RECV)
        {
            gint total_rx_len = 0;
            gint rx_len;
            tvbuff_t *rx_tvb = tvb_new_composite();

            col_add_fstr(pinfo->cinfo, COL_INFO, "INTERFACE %s RX", interface_str);

            do
            {
                /* First two bytes are status */
                offset += dissect_modem_status_bytes(tvb, pinfo, offset, main_tree, &rx_len);
                total_rx_len += rx_len;

                if (rx_len > 0)
                {
                    tvbuff_t *rx_tvb_fragment = tvb_new_subset_length(tvb, offset, rx_len);
                    tvb_composite_append(rx_tvb, rx_tvb_fragment);
                    proto_tree_add_item(main_tree, rx_hf, tvb, offset, rx_len, ENC_NA);
                    offset += rx_len;
                }
            }
            while (tvb_reported_length_remaining(tvb, offset) > 0);

            if (total_rx_len > 0)
            {
                tvb_composite_finalize(rx_tvb);
                col_append_fstr(pinfo->cinfo, COL_INFO, " %d bytes", total_rx_len);
                add_new_data_source(pinfo, rx_tvb, "RX Payload");
                dissect_serial_payload(rx_tvb, pinfo, tree, main_tree, usb_conv_info, interface);
            }
            else
            {
                tvb_free_chain(rx_tvb);
            }
        }
        else
        {
            gint bytes;

            col_add_fstr(pinfo->cinfo, COL_INFO, "INTERFACE %s TX", interface_str);
            bytes = tvb_reported_length_remaining(tvb, offset);

            if (bytes > 0)
            {
                tvbuff_t *tx_tvb;

                col_append_fstr(pinfo->cinfo, COL_INFO, " %d bytes", bytes);
                proto_tree_add_item(main_tree, tx_hf, tvb, offset, bytes, ENC_NA);

                tx_tvb = tvb_new_subset_length(tvb, offset, bytes);
                add_new_data_source(pinfo, tx_tvb, "TX Payload");
                dissect_serial_payload(tx_tvb, pinfo, tree, main_tree, usb_conv_info, interface);
                offset += bytes;
            }
        }
    }

    return offset;
}

void
proto_register_ftdi_ft(void)
{
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_setup_brequest,
          { "Request", "ftdi-ft.bRequest",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &request_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue,
          { "lValue", "ftdi-ft.lValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_purge,
          { "lValue", "ftdi-ft.lValue",
            FT_UINT8, BASE_HEX, VALS(reset_purge_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_dtr,
          { "DTR Active", "ftdi-ft.lValue.b0",
            FT_BOOLEAN, 8, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_setup_lvalue_rts,
          { "RTS Active", "ftdi-ft.lValue.b1",
            FT_BOOLEAN, 8, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_setup_lvalue_xon_char,
          { "XON Char", "ftdi-ft.lValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_baud_low,
          { "Baud low", "ftdi-ft.lValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_data_size,
          { "Data Size", "ftdi-ft.lValue",
            FT_UINT8, BASE_HEX, VALS(data_size_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_event_char,
          { "Event Char", "ftdi-ft.lValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_error_char,
          { "Parity Error Char", "ftdi-ft.lValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_latency_time,
          { "Latency Time", "ftdi-ft.lValue",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Latency time in milliseconds", HFILL }
        },
        { &hf_setup_lvalue_bitmask,
          { "Bit Mask", "ftdi-ft.lValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hvalue,
          { "hValue", "ftdi-ft.hValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hvalue_dtr,
          { "en DTR for writing", "ftdi-ft.hValue.b0",
            FT_BOOLEAN, 8, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_setup_hvalue_rts,
          { "en RTS for writing", "ftdi-ft.hValue.b1",
            FT_BOOLEAN, 8, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_setup_hvalue_xoff_char,
          { "XOFF Char", "ftdi-ft.hValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hvalue_baud_mid,
          { "Baud mid", "ftdi-ft.hValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hvalue_parity,
          { "Parity", "ftdi-ft.hValue.parity",
            FT_UINT8, BASE_HEX, VALS(parity_vals), (0x7 << 0),
            NULL, HFILL }
        },
        { &hf_setup_hvalue_stop_bits,
          { "Stop Bits", "ftdi-ft.hValue.b4",
            FT_UINT8, BASE_HEX, VALS(stop_bits_vals), (1 << 4),
            NULL, HFILL }
        },
        { &hf_setup_hvalue_break_bit,
          { "Break Bit", "ftdi-ft.hValue.b6",
            FT_UINT8, BASE_HEX, VALS(break_bit_vals), (1 << 6),
            NULL, HFILL }
        },
        { &hf_setup_hvalue_trigger,
          { "hValue", "ftdi-ft.hValue",
            FT_UINT8, BASE_HEX, VALS(event_char_trigger_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hvalue_error_replacement,
          { "hValue", "ftdi-ft.hValue",
            FT_UINT8, BASE_HEX, VALS(error_replacement_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hvalue_bitmode,
          { "Bit Mode", "ftdi-ft.hValue",
            FT_UINT8, BASE_HEX, VALS(bitmode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lindex,
          { "lIndex", "ftdi-ft.lIndex",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lindex_port_ab,
          { "lIndex", "ftdi-ft.lIndex",
            FT_UINT8, BASE_HEX, VALS(index_port_ab_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lindex_port_abcd,
          { "lIndex", "ftdi-ft.lIndex",
            FT_UINT8, BASE_HEX, VALS(index_port_abcd_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lindex_baud_high,
          { "Baud High", "ftdi-ft.lIndex.b0",
            FT_UINT8, BASE_HEX, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_setup_hindex,
          { "hIndex", "ftdi-ft.hIndex",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hindex_rts_cts,
          { "RTS/CTS Flow Control", "ftdi-ft.hIndex.b0",
            FT_BOOLEAN, 8, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_setup_hindex_dtr_dsr,
          { "DTR/DSR Flow Control", "ftdi-ft.hIndex.b1",
            FT_BOOLEAN, 8, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_setup_hindex_xon_xoff,
          { "XON/XOFF Flow Control", "ftdi-ft.hIndex.b2",
            FT_BOOLEAN, 8, NULL, (1 << 2),
            NULL, HFILL }
        },
        { &hf_setup_hindex_baud_high,
          { "Baud High", "ftdi-ft.baud_high.b0",
            FT_UINT8, BASE_HEX, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_setup_hindex_baud_clock_divide,
          { "Baud Clock Divide off", "ftdi-ft.baud_clock_divide.b1",
            FT_BOOLEAN, 8, NULL, (1 << 1),
            "When active 120 MHz is max frequency instead of 48 MHz", HFILL }
        },
        { &hf_setup_wlength,
          { "wLength", "ftdi-ft.wLength",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_response_lat_timer,
          { "Latency Time", "ftdi-ft.latency_time",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Latency time in milliseconds", HFILL }
        },
        { &hf_modem_status,
          { "Modem Status", "ftdi-ft.modem_status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_modem_status_fs_max_packet,
          { "Full Speed 64 byte MAX packet", "ftdi-ft.modem_status.b0",
            FT_BOOLEAN, 8, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_modem_status_hs_max_packet,
          { "High Speed 512 byte MAX packet", "ftdi-ft.modem_status.b1",
            FT_BOOLEAN, 8, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_modem_status_cts,
          { "CTS", "ftdi-ft.modem_status.b4",
            FT_BOOLEAN, 8, NULL, (1 << 4),
            NULL, HFILL }
        },
        { &hf_modem_status_dsr,
          { "DSR", "ftdi-ft.modem_status.b5",
            FT_BOOLEAN, 8, NULL, (1 << 5),
            NULL, HFILL }
        },
        { &hf_modem_status_ri,
          { "RI", "ftdi-ft.modem_status.b6",
            FT_BOOLEAN, 8, NULL, (1 << 6),
            NULL, HFILL }
        },
        { &hf_modem_status_dcd,
          { "DCD", "ftdi-ft.modem_status.b7",
            FT_BOOLEAN, 8, NULL, (1 << 7),
            NULL, HFILL }
        },
        { &hf_line_status,
          { "Line Status", "ftdi-ft.line_status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_line_status_receive_overflow,
          { "Receive Overflow Error", "ftdi-ft.line_status.b1",
            FT_BOOLEAN, 8, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_line_status_parity_error,
          { "Parity Error", "ftdi-ft.line_status.b2",
            FT_BOOLEAN, 8, NULL, (1 << 2),
            NULL, HFILL }
        },
        { &hf_line_status_framing_error,
          { "Framing Error", "ftdi-ft.line_status.b3",
            FT_BOOLEAN, 8, NULL, (1 << 3),
            NULL, HFILL }
        },
        { &hf_line_status_break_received,
          { "Break Received", "ftdi-ft.line_status.b4",
            FT_BOOLEAN, 8, NULL, (1 << 4),
            NULL, HFILL }
        },
        { &hf_line_status_tx_holding_reg_empty,
          { "Transmitter Holding Register Empty", "ftdi-ft.line_status.b5",
            FT_BOOLEAN, 8, NULL, (1 << 5),
            NULL, HFILL }
        },
        { &hf_line_status_tx_empty,
          { "Transmitter Empty", "ftdi-ft.line_status.b6",
            FT_BOOLEAN, 8, NULL, (1 << 6),
            NULL, HFILL }
        },
        { &hf_if_a_rx_payload,
          { "A RX payload", "ftdi-ft.if_a_rx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data received on interface A", HFILL }
        },
        { &hf_if_a_tx_payload,
          { "A TX payload", "ftdi-ft.if_a_tx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data to transmit on interface A", HFILL }
        },
        { &hf_if_b_rx_payload,
          { "B RX payload", "ftdi-ft.if_b_rx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data received on interface B", HFILL }
        },
        { &hf_if_b_tx_payload,
          { "B TX payload", "ftdi-ft.if_b_tx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data to transmit on interface B", HFILL }
        },
        { &hf_if_c_rx_payload,
          { "C RX payload", "ftdi-ft.if_c_rx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data received on interface C", HFILL }
        },
        { &hf_if_c_tx_payload,
          { "C TX payload", "ftdi-ft.if_c_tx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data to transmit on interface C", HFILL }
        },
        { &hf_if_d_rx_payload,
          { "D RX payload", "ftdi-ft.if_d_rx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data received on interface D", HFILL }
        },
        { &hf_if_d_tx_payload,
          { "D TX payload", "ftdi-ft.if_d_tx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data to transmit on interface D", HFILL }
        },
        { &hf_ftdi_fragments,
          { "Payload fragments", "ftdi-ft.fragments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ftdi_fragment,
          { "Payload fragment", "ftdi-ft.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ftdi_fragment_overlap,
          { "Payload fragment overlap", "ftdi-ft.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ftdi_fragment_overlap_conflicts,
          { "Payload fragment overlapping with conflicting data", "ftdi-ft.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ftdi_fragment_multiple_tails,
          { "Payload has multiple tails", "ftdi-ft.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_ftdi_fragment_too_long_fragment,
          { "Payload fragment too long", "ftdi-ft.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ftdi_fragment_error,
          { "Payload defragmentation error", "ftdi-ft.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ftdi_fragment_count,
          { "Payload fragment count", "ftdi-ft.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ftdi_reassembled_in,
          { "Payload reassembled in", "ftdi-ft.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ftdi_reassembled_length,
          { "Payload reassembled length", "ftdi-ft.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_undecoded, { "ftdi-ft.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_ftdi_ft,
        &ett_modem_ctrl_lvalue,
        &ett_modem_ctrl_hvalue,
        &ett_flow_ctrl_hindex,
        &ett_baudrate_lindex,
        &ett_baudrate_hindex,
        &ett_setdata_hvalue,
        &ett_modem_status,
        &ett_line_status,
        &ett_ftdi_fragment,
        &ett_ftdi_fragments,
    };

    request_info = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    bitmode_info = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    desegment_info = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_ftdi_ft = proto_register_protocol("FTDI FT USB", "FTDI FT", "ftdi-ft");
    proto_register_field_array(proto_ftdi_ft, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    ftdi_ft_handle = register_dissector("ftdi-ft", dissect_ftdi_ft, proto_ftdi_ft);

    expert_module = expert_register_protocol(proto_ftdi_ft);
    expert_register_field_array(expert_module, ei, array_length(ei));

    reassembly_table_register(&ftdi_reassembly_table, &ftdi_reassembly_table_functions);
}

void
proto_reg_handoff_ftdi_ft(void)
{
    /* TODO: Add configuration option to specify VID and PID.
     * The values below denote default VID/PID of FT converters (as of 2019)
     * The VID and PID can be changed by hardware vendor.
     */
    dissector_add_uint("usb.product", (0x0403 << 16) | 0x6001, ftdi_ft_handle);
    dissector_add_uint("usb.product", (0x0403 << 16) | 0x6010, ftdi_ft_handle);
    dissector_add_uint("usb.product", (0x0403 << 16) | 0x6011, ftdi_ft_handle);
    dissector_add_uint("usb.product", (0x0403 << 16) | 0x6014, ftdi_ft_handle);
    dissector_add_uint("usb.product", (0x0403 << 16) | 0x6015, ftdi_ft_handle);

    /* Devices that use FTDI FT converter with changed Vendor ID and/or Product ID */
    dissector_add_uint("usb.product", (0x0403 << 16) | 0xcff8, ftdi_ft_handle); /* Amontec JTAGkey */
    dissector_add_uint("usb.product", (0x15ba << 16) | 0x0003, ftdi_ft_handle); /* Olimex ARM-USB-OCD */
    dissector_add_uint("usb.product", (0x15ba << 16) | 0x0004, ftdi_ft_handle); /* Olimex ARM-USB-TINY */
    dissector_add_uint("usb.product", (0x15ba << 16) | 0x002a, ftdi_ft_handle); /* Olimex ARM-USB-TINY-H */
    dissector_add_uint("usb.product", (0x15ba << 16) | 0x002b, ftdi_ft_handle); /* Olimex ARM-USB-OCD-H */
    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x607c, ftdi_ft_handle); /* OpenVizsla USB sniffer/analyzer */

    dissector_add_for_decode_as("usb.device", ftdi_ft_handle);

    ftdi_mpsse_handle = find_dissector_add_dependency("ftdi-mpsse", proto_ftdi_ft);
}

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
