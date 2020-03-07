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

static gint ett_ftdi_ft = -1;
static gint ett_modem_ctrl_lvalue = -1;
static gint ett_modem_ctrl_hvalue = -1;
static gint ett_flow_ctrl_hindex = -1;
static gint ett_baudrate_lindex = -1;
static gint ett_baudrate_hindex = -1;
static gint ett_setdata_hvalue = -1;
static gint ett_modem_status = -1;
static gint ett_line_status = -1;

static dissector_handle_t ftdi_mpsse_handle;

static expert_field ei_undecoded = EI_INIT;

static dissector_handle_t ftdi_ft_handle;

static wmem_tree_t *request_info = NULL;
static wmem_tree_t *bitmode_info = NULL;

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
    static const int *lvalue_bits[] = {
        &hf_setup_lvalue_dtr,
        &hf_setup_lvalue_rts,
        NULL
    };
    static const int *hvalue_bits[] = {
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
    static const int *hindex_bits[] = {
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
    static const int *lindex_bits[] = {
        &hf_setup_lindex_baud_high,
        NULL
    };
    static const int *hindex_bits[] = {
        &hf_setup_hindex_baud_high,
        NULL
    };
    static const int *hindex_bits_hispeed[] = {
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
    static const int *hvalue_bits[] = {
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
dissect_modem_status_bytes(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, proto_tree *tree)
{
    static const int *modem_status_bits[] = {
        &hf_modem_status_fs_max_packet,
        &hf_modem_status_hs_max_packet,
        &hf_modem_status_cts,
        &hf_modem_status_dsr,
        &hf_modem_status_ri,
        &hf_modem_status_dcd,
        NULL
    };
    static const int *line_status_bits[] = {
        &hf_line_status_receive_overflow,
        &hf_line_status_parity_error,
        &hf_line_status_framing_error,
        &hf_line_status_break_received,
        &hf_line_status_tx_holding_reg_empty,
        &hf_line_status_tx_empty,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_modem_status,
        ett_modem_status, modem_status_bits, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_bitmask(tree, tvb, offset, hf_line_status,
        ett_line_status, line_status_bits, ENC_LITTLE_ENDIAN);
    offset++;

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
                    offset += dissect_modem_status_bytes(tvb, pinfo, offset, main_tree);
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
        gint payload_hf, rx_hf, tx_hf;
        gint bytes;

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
        if (usb_conv_info->direction == P2P_DIR_RECV)
        {
            col_add_fstr(pinfo->cinfo, COL_INFO, "INTERFACE %s RX", interface_str);
            /* First two bytes are status */
            offset += dissect_modem_status_bytes(tvb, pinfo, offset, main_tree);
            payload_hf = rx_hf;
        }
        else
        {
            col_add_fstr(pinfo->cinfo, COL_INFO, "INTERFACE %s TX", interface_str);
            payload_hf = tx_hf;
        }
        bytes = tvb_reported_length_remaining(tvb, offset);
        if (bytes > 0)
        {
            guint8 bitmode;

            col_append_fstr(pinfo->cinfo, COL_INFO, " %d bytes", bytes);
            proto_tree_add_item(main_tree, payload_hf, tvb, offset, bytes, ENC_NA);

            bitmode = get_recorded_interface_mode(pinfo, usb_conv_info, interface);
            if (bitmode == BITMODE_MPSSE)
            {
                ftdi_mpsse_info_t mpsse_info = {
                    .bus_id         = k_bus_id,
                    .device_address = k_device_address,
                    .chip           = identify_chip(usb_conv_info),
                    .iface          = interface,
                };
                tvbuff_t *mpsse_payload_tvb = tvb_new_subset_remaining(tvb, offset);
                call_dissector_with_data(ftdi_mpsse_handle, mpsse_payload_tvb, pinfo, tree, &mpsse_info);
            }

            offset += bytes;
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
          { "Request", "ftdift.bRequest",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &request_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue,
          { "lValue", "ftdift.lValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_purge,
          { "lValue", "ftdift.lValue",
            FT_UINT8, BASE_HEX, VALS(reset_purge_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_dtr,
          { "DTR Active", "ftdift.lValue.b0",
            FT_BOOLEAN, 8, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_setup_lvalue_rts,
          { "RTS Active", "ftdift.lValue.b1",
            FT_BOOLEAN, 8, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_setup_lvalue_xon_char,
          { "XON Char", "ftdift.lValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_baud_low,
          { "Baud low", "ftdift.lValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_data_size,
          { "Data Size", "ftdift.lValue",
            FT_UINT8, BASE_HEX, VALS(data_size_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_event_char,
          { "Event Char", "ftdift.lValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_error_char,
          { "Parity Error Char", "ftdift.lValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lvalue_latency_time,
          { "Latency Time", "ftdift.lValue",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Latency time in milliseconds", HFILL }
        },
        { &hf_setup_lvalue_bitmask,
          { "Bit Mask", "ftdift.lValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hvalue,
          { "hValue", "ftdift.hValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hvalue_dtr,
          { "en DTR for writing", "ftdift.hValue.b0",
            FT_BOOLEAN, 8, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_setup_hvalue_rts,
          { "en RTS for writing", "ftdift.hValue.b1",
            FT_BOOLEAN, 8, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_setup_hvalue_xoff_char,
          { "XOFF Char", "ftdift.hValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hvalue_baud_mid,
          { "Baud mid", "ftdift.hValue",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hvalue_parity,
          { "Parity", "ftdift.hValue.parity",
            FT_UINT8, BASE_HEX, VALS(parity_vals), (0x7 << 0),
            NULL, HFILL }
        },
        { &hf_setup_hvalue_stop_bits,
          { "Stop Bits", "ftdift.hValue.b4",
            FT_UINT8, BASE_HEX, VALS(stop_bits_vals), (1 << 4),
            NULL, HFILL }
        },
        { &hf_setup_hvalue_break_bit,
          { "Break Bit", "ftdift.hValue.b6",
            FT_UINT8, BASE_HEX, VALS(break_bit_vals), (1 << 6),
            NULL, HFILL }
        },
        { &hf_setup_hvalue_trigger,
          { "hValue", "ftdift.hValue",
            FT_UINT8, BASE_HEX, VALS(event_char_trigger_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hvalue_error_replacement,
          { "hValue", "ftdift.hValue",
            FT_UINT8, BASE_HEX, VALS(error_replacement_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hvalue_bitmode,
          { "Bit Mode", "ftdift.hValue",
            FT_UINT8, BASE_HEX, VALS(bitmode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lindex,
          { "lIndex", "ftdift.lIndex",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lindex_port_ab,
          { "lIndex", "ftdift.lIndex",
            FT_UINT8, BASE_HEX, VALS(index_port_ab_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lindex_port_abcd,
          { "lIndex", "ftdift.lIndex",
            FT_UINT8, BASE_HEX, VALS(index_port_abcd_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_setup_lindex_baud_high,
          { "Baud High", "ftdift.lIndex.b0",
            FT_UINT8, BASE_HEX, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_setup_hindex,
          { "hIndex", "ftdift.hIndex",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_hindex_rts_cts,
          { "RTS/CTS Flow Control", "ftdift.hIndex.b0",
            FT_BOOLEAN, 8, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_setup_hindex_dtr_dsr,
          { "DTR/DSR Flow Control", "ftdift.hIndex.b1",
            FT_BOOLEAN, 8, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_setup_hindex_xon_xoff,
          { "XON/XOFF Flow Control", "ftdift.hIndex.b2",
            FT_BOOLEAN, 8, NULL, (1 << 2),
            NULL, HFILL }
        },
        { &hf_setup_hindex_baud_high,
          { "Baud High", "ftdift.hIndex.b0",
            FT_UINT8, BASE_HEX, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_setup_hindex_baud_clock_divide,
          { "Baud Clock Divide off", "ftdift.hIndex.b1",
            FT_BOOLEAN, 8, NULL, (1 << 1),
            "When active 120 MHz is max frequency instead of 48 MHz", HFILL }
        },
        { &hf_setup_wlength,
          { "wLength", "ftdift.wLength",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_response_lat_timer,
          { "Latency Time", "ftdift.latency_time",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Latency time in milliseconds", HFILL }
        },
        { &hf_modem_status,
          { "Modem Status", "ftdift.modem_status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_modem_status_fs_max_packet,
          { "Full Speed 64 byte MAX packet", "ftdift.modem_status.b0",
            FT_BOOLEAN, 8, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_modem_status_hs_max_packet,
          { "High Speed 512 byte MAX packet", "ftdift.modem_status.b1",
            FT_BOOLEAN, 8, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_modem_status_cts,
          { "CTS", "ftdift.modem_status.b4",
            FT_BOOLEAN, 8, NULL, (1 << 4),
            NULL, HFILL }
        },
        { &hf_modem_status_dsr,
          { "DSR", "ftdift.modem_status.b5",
            FT_BOOLEAN, 8, NULL, (1 << 5),
            NULL, HFILL }
        },
        { &hf_modem_status_ri,
          { "RI", "ftdift.modem_status.b6",
            FT_BOOLEAN, 8, NULL, (1 << 6),
            NULL, HFILL }
        },
        { &hf_modem_status_dcd,
          { "DCD", "ftdift.modem_status.b7",
            FT_BOOLEAN, 8, NULL, (1 << 7),
            NULL, HFILL }
        },
        { &hf_line_status,
          { "Line Status", "ftdift.line_status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_line_status_receive_overflow,
          { "Receive Overflow Error", "ftdift.line_status.b1",
            FT_BOOLEAN, 8, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_line_status_parity_error,
          { "Parity Error", "ftdift.line_status.b2",
            FT_BOOLEAN, 8, NULL, (1 << 2),
            NULL, HFILL }
        },
        { &hf_line_status_framing_error,
          { "Framing Error", "ftdift.line_status.b3",
            FT_BOOLEAN, 8, NULL, (1 << 3),
            NULL, HFILL }
        },
        { &hf_line_status_break_received,
          { "Break Received", "ftdift.line_status.b4",
            FT_BOOLEAN, 8, NULL, (1 << 4),
            NULL, HFILL }
        },
        { &hf_line_status_tx_holding_reg_empty,
          { "Transmitter Holding Register Empty", "ftdift.line_status.b5",
            FT_BOOLEAN, 8, NULL, (1 << 5),
            NULL, HFILL }
        },
        { &hf_line_status_tx_empty,
          { "Transmitter Empty", "ftdift.line_status.b6",
            FT_BOOLEAN, 8, NULL, (1 << 6),
            NULL, HFILL }
        },
        { &hf_if_a_rx_payload,
          { "A RX payload", "ftdift.if_a_rx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data received on interface A", HFILL }
        },
        { &hf_if_a_tx_payload,
          { "A TX payload", "ftdift.if_a_tx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data to transmit on interface A", HFILL }
        },
        { &hf_if_b_rx_payload,
          { "B RX payload", "ftdift.if_b_rx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data received on interface B", HFILL }
        },
        { &hf_if_b_tx_payload,
          { "B TX payload", "ftdift.if_b_tx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data to transmit on interface B", HFILL }
        },
        { &hf_if_c_rx_payload,
          { "C RX payload", "ftdift.if_c_rx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data received on interface C", HFILL }
        },
        { &hf_if_c_tx_payload,
          { "C TX payload", "ftdift.if_c_tx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data to transmit on interface C", HFILL }
        },
        { &hf_if_d_rx_payload,
          { "D RX payload", "ftdift.if_d_rx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data received on interface D", HFILL }
        },
        { &hf_if_d_tx_payload,
          { "D TX payload", "ftdift.if_d_tx_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Data to transmit on interface D", HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_undecoded, { "ftdift.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
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
    };

    request_info = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    bitmode_info = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_ftdi_ft = proto_register_protocol("FTDI FT USB", "FTDI FT", "ftdift");
    proto_register_field_array(proto_ftdi_ft, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    ftdi_ft_handle = register_dissector("ftdift", dissect_ftdi_ft, proto_ftdi_ft);

    expert_module = expert_register_protocol(proto_ftdi_ft);
    expert_register_field_array(expert_module, ei, array_length(ei));
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
