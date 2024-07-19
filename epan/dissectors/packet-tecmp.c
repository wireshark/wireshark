/* packet-tecmp.c
 * Technically Enhanced Capture Module Protocol (TECMP) dissector.
 * By <lars.voelker@technica-engineering.de>
 * Copyright 2019-2023 Dr. Lars Voelker
 * Copyright 2020      Ayoub Kaanich
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*
  * This is a dissector for the Technically Enhanced Capture Module Protocol (TECMP).
  * A new automotive protocol to carry data from a so called Capture Module (CM),
  * which is somewhat similar to active network tap, towards a logger or PC to
  * record or analyze the captured data.
  * Capture Modules capture data of LIN, CAN, FlexRay, Ethernet, RS232, or other sources.
  */

#include <config.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/proto_data.h>
#include <wsutil/utf8_entities.h>

#include "packet-tecmp.h"
#include "packet-socketcan.h"
#include "packet-flexray.h"
#include "packet-lin.h"


void proto_register_tecmp(void);
void proto_reg_handoff_tecmp(void);
void proto_register_tecmp_payload(void);
void proto_reg_handoff_tecmp_payload(void);

static dissector_handle_t tecmp_handle;

static int proto_tecmp;
static int proto_tecmp_payload;

static dissector_handle_t eth_handle;
static int proto_vlan;

static bool heuristic_first;
static bool analog_samples_are_signed_int = true;
static bool show_ethernet_in_tecmp_tree;
static bool detect_asam_cmp = true;
static bool detect_asam_cmp_ignore_user_defined = true;

static dissector_table_t lin_subdissector_table;
static dissector_table_t data_subdissector_table;
static dissector_handle_t text_lines_handle;

/* Header fields */
/* TECMP */
static int hf_tecmp_device_id;
static int hf_tecmp_counter;
static int hf_tecmp_version;
static int hf_tecmp_msgtype;
static int hf_tecmp_data_type;
static int hf_tecmp_res;

static int hf_tecmp_flags;
static int hf_tecmp_flags_eos;
static int hf_tecmp_flags_sos;
static int hf_tecmp_flags_spy;
static int hf_tecmp_flags_multi_frame;
static int hf_tecmp_flags_dev_overflow;

/* TECMP Payload */
static int hf_tecmp_payload_interface_id;
static int hf_tecmp_payload_interface_name;
static int hf_tecmp_payload_timestamp;
static int hf_tecmp_payload_timestamp_ns;
static int hf_tecmp_payload_timestamp_async;
static int hf_tecmp_payload_timestamp_res;
static int hf_tecmp_payload_length;
static int hf_tecmp_payload_data;
static int hf_tecmp_payload_data_length;

/* TECMP Payload flags */
/* Generic */
static int hf_tecmp_payload_data_flags;
static int hf_tecmp_payload_data_flags_crc;
static int hf_tecmp_payload_data_flags_checksum;
static int hf_tecmp_payload_data_flags_tx;
static int hf_tecmp_payload_data_flags_overflow;

/* ILaS*/
static int hf_tecmp_payload_data_flags_crc_enabled;
static int hf_tecmp_payload_data_flags_direction;

/* Ethernet 10BASE-T1S */
static int hf_tecmp_payload_data_flags_phy_event_error;

/* LIN */
static int hf_tecmp_payload_data_flags_coll;
static int hf_tecmp_payload_data_flags_parity;
static int hf_tecmp_payload_data_flags_no_resp;
static int hf_tecmp_payload_data_flags_wup;
static int hf_tecmp_payload_data_flags_short_wup;
static int hf_tecmp_payload_data_flags_sleep;

/* CAN and CAN-FD DATA */
static int hf_tecmp_payload_data_flags_ack;
static int hf_tecmp_payload_data_flags_rtr;  /* CAN DATA only */
static int hf_tecmp_payload_data_flags_esi;  /* CAN-FD DATA only */
static int hf_tecmp_payload_data_flags_ide;
static int hf_tecmp_payload_data_flags_err;
static int hf_tecmp_payload_data_flags_brs;  /* CAN-FD DATA only */

static int hf_tecmp_payload_data_flags_can_bit_stuff_err;
static int hf_tecmp_payload_data_flags_can_crc_del_err;
static int hf_tecmp_payload_data_flags_can_ack_del_err;
static int hf_tecmp_payload_data_flags_can_eof_err;
static int hf_tecmp_payload_data_flags_canfd_bit_stuff_err;
static int hf_tecmp_payload_data_flags_canfd_crc_del_err;
static int hf_tecmp_payload_data_flags_canfd_ack_del_err;
static int hf_tecmp_payload_data_flags_canfd_eof_err;

/* FlexRay */
static int hf_tecmp_payload_data_flags_nf;
static int hf_tecmp_payload_data_flags_sf;
static int hf_tecmp_payload_data_flags_sync;
static int hf_tecmp_payload_data_flags_wus;
static int hf_tecmp_payload_data_flags_ppi;
static int hf_tecmp_payload_data_flags_cas;
static int hf_tecmp_payload_data_flags_header_crc_err;
static int hf_tecmp_payload_data_flags_frame_crc_err;

/* UART/RS232 ASCII*/
static int hf_tecmp_payload_data_flags_dl;
static int hf_tecmp_payload_data_flags_parity_error;

/* Analog */
static int hf_tecmp_payload_data_flags_sample_time;
static int hf_tecmp_payload_data_flags_factor;
static int hf_tecmp_payload_data_flags_unit;
static int hf_tecmp_payload_data_flags_threshold_u;
static int hf_tecmp_payload_data_flags_threshold_o;

/* Special TX Data Flags */
static int hf_tecmp_payload_data_flags_use_crc_value;
static int hf_tecmp_payload_data_flags_use_header_crc_value;
static int hf_tecmp_payload_data_flags_use_checksum_value;
static int hf_tecmp_payload_data_flags_use_parity_bits;
static int hf_tecmp_payload_data_flags_tx_mode;

static const unit_name_string tecmp_units_amp_hour = { "Ah", NULL };

#define TECMP_DATAFLAGS_FACTOR_MASK         0x0180
#define TECMP_DATAFLAGS_FACTOR_SHIFT        7
#define TECMP_DATAFLAGS_UNIT_MASK           0x001c
#define TECMP_DATAFLAGS_UNIT_SHIFT          2

/* TECMP Payload Fields */
/* Ethernet 10BASE-T1S */
static int hf_tecmp_payload_data_beacon_timestamp;
static int hf_tecmp_payload_data_beacon_timestamp_ns;
static int hf_tecmp_payload_data_beacon_to_timestamp_ns;

/* LIN */
static int hf_tecmp_payload_data_id_field_8bit;
static int hf_tecmp_payload_data_id_field_6bit;
static int hf_tecmp_payload_data_parity_bits;
static int hf_tecmp_payload_data_checksum_8bit;

/* CAN DATA / CAN-FD DATA */
static int hf_tecmp_payload_data_id_field_32bit;
static int hf_tecmp_payload_data_id_type;
static int hf_tecmp_payload_data_id_11;
static int hf_tecmp_payload_data_id_29;
static int hf_tecmp_payload_data_crc15;
static int hf_tecmp_payload_data_crc17;
static int hf_tecmp_payload_data_crc21;

/* FlexRay DATA */
static int hf_tecmp_payload_data_cycle;
static int hf_tecmp_payload_data_frame_id;
static int hf_tecmp_payload_data_header_crc;
static int hf_tecmp_payload_data_frame_crc;

/* Analog */
static int hf_tecmp_payload_data_analog_value_raw;
static int hf_tecmp_payload_data_analog_value_raw_signed;
static int hf_tecmp_payload_data_analog_value_volt;
static int hf_tecmp_payload_data_analog_value_amp;
static int hf_tecmp_payload_data_analog_value_watt;
static int hf_tecmp_payload_data_analog_value_amp_hour;
static int hf_tecmp_payload_data_analog_value_celsius;

/* ILaS */
static int hf_tecmp_payload_data_ilas_decoded_command;
static int hf_tecmp_payload_data_ilas_decoded_address;
static int hf_tecmp_payload_data_ilas_decoded_data;
static int hf_tecmp_payload_data_ilas_raw_sdu;
static int hf_tecmp_payload_data_ilas_raw_crc;

/* TECMP Status Messages */
/* Status Device */
static int hf_tecmp_payload_status_vendor_id;
static int hf_tecmp_payload_status_dev_version;
static int hf_tecmp_payload_status_dev_type;
static int hf_tecmp_payload_status_res;
static int hf_tecmp_payload_status_length_vendor_data;
static int hf_tecmp_payload_status_device_id;
static int hf_tecmp_payload_status_sn;
static int hf_tecmp_payload_status_vendor_data;

/* Status Bus */
static int hf_tecmp_payload_status_bus_data;
static int hf_tecmp_payload_status_bus_data_entry;
static int hf_tecmp_payload_status_bus_interface_id;
static int hf_tecmp_payload_status_bus_total;
static int hf_tecmp_payload_status_bus_errors;

/* Status Device Vendor Data Technica Engineering */
static int hf_tecmp_payload_status_dev_vendor_technica_res;
static int hf_tecmp_payload_status_dev_vendor_technica_sw;
static int hf_tecmp_payload_status_dev_vendor_technica_hw;
static int hf_tecmp_payload_status_dev_vendor_technica_buffer_fill_level;
static int hf_tecmp_payload_status_dev_vendor_technica_buffer_overflow;
static int hf_tecmp_payload_status_dev_vendor_technica_buffer_size;
static int hf_tecmp_payload_status_dev_vendor_technica_lifecycle;
static int hf_tecmp_payload_status_dev_vendor_technica_lifecycle_start;
static int hf_tecmp_payload_status_dev_vendor_technica_voltage;
static int hf_tecmp_payload_status_dev_vendor_technica_temperature;
static int hf_tecmp_payload_status_dev_vendor_technica_temperature_chassis;
static int hf_tecmp_payload_status_dev_vendor_technica_temperature_silicon;

#define VENDOR_TECHNICA_TEMP_MAX 127
#define VENDOR_TECHNICA_TEMP_NA  -128

/* Status Bus Vendor Data Technica Engineering */
static int hf_tecmp_payload_status_bus_vendor_technica_link_status;
static int hf_tecmp_payload_status_bus_vendor_technica_link_quality;
static int hf_tecmp_payload_status_bus_vendor_technica_linkup_time;

static int hf_tecmp_payload_status_bus_vendor_technica_10m_flags;
static int hf_tecmp_payload_status_bus_vendor_technica_10m_flags_beacons_received;
static int hf_tecmp_payload_status_bus_vendor_technica_10m_flags_plca_enabled;
static int hf_tecmp_payload_status_bus_vendor_technica_res0;
static int hf_tecmp_payload_status_bus_vendor_technica_beacon_counter;
static int hf_tecmp_payload_status_bus_vendor_technica_res1;
static int hf_tecmp_payload_status_bus_vendor_technica_res2;
static int hf_tecmp_payload_status_bus_vendor_technica_5b_decode_err_cnt;
static int hf_tecmp_payload_status_bus_vendor_technica_eos_delim_err_cnt;
static int hf_tecmp_payload_status_bus_vendor_technica_plca_symbols_detected_cnt;
static int hf_tecmp_payload_status_bus_vendor_technica_plca_symbols_missing_cnt;
static int hf_tecmp_payload_status_bus_vendor_technica_plca_symbols_empty_cycle_cnt;


/* Status Configuration Data Technica Engineering */
static int hf_tecmp_payload_status_cfg_vendor_technica_version;
static int hf_tecmp_payload_status_cfg_vendor_technica_reserved;
static int hf_tecmp_payload_status_cfg_vendor_technica_msg_id;
static int hf_tecmp_payload_status_cfg_vendor_technica_total_length;
static int hf_tecmp_payload_status_cfg_vendor_technica_total_num_seg;
static int hf_tecmp_payload_status_cfg_vendor_technica_segment_num;
static int hf_tecmp_payload_status_cfg_vendor_technica_segment_length;
static int hf_tecmp_payload_status_cfg_vendor_technica_segment_data;

/* TECMP Control Message */
static int hf_tecmp_payload_ctrl_msg_device_id;
static int hf_tecmp_payload_ctrl_msg_id;
static int hf_tecmp_payload_ctrl_msg_unparsed_bytes;
static int hf_tecmp_payload_ctrl_msg_can_replay_fill_level_fill_level;
static int hf_tecmp_payload_ctrl_msg_can_replay_fill_level_buffer_overflow;
static int hf_tecmp_payload_ctrl_msg_can_replay_fill_level_queue_size;
static int hf_tecmp_payload_ctrl_msg_can_replay_fill_level_queue_length;
static int hf_tecmp_payload_ctrl_msg_flexray_poc_interface_id;
static int hf_tecmp_payload_ctrl_msg_flexray_poc_state;
static int hf_tecmp_payload_ctrl_msg_10baset1s_interface_id;
static int hf_tecmp_payload_ctrl_msg_10baset1s_10m_flags;
static int hf_tecmp_payload_ctrl_msg_10baset1s_10m_flags_beacons_received;
static int hf_tecmp_payload_ctrl_msg_10baset1s_10m_flags_plca_enabled;
static int hf_tecmp_payload_ctrl_msg_10baset1s_10m_reserved;
static int hf_tecmp_payload_ctrl_msg_10baset1s_10m_events;
static int hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_5b_decode_error;
static int hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_eos_delim_error;
static int hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_plca_symb_detected;
static int hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_plca_symb_missing;
static int hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_plca_empty_cycle;

/* Counter Event */
static int hf_tecmp_payload_counter_event_device_id;
static int hf_tecmp_payload_counter_event_interface_id;
static int hf_tecmp_payload_counter_event_counter_last;
static int hf_tecmp_payload_counter_event_counter_cur;

/* TimeSync Event */
static int hf_tecmp_payload_timesync_event_device_id;
static int hf_tecmp_payload_timesync_event_interface_id;
static int hf_tecmp_payload_timesync_event_reserved;
static int hf_tecmp_payload_timesync_event_async;
static int hf_tecmp_payload_timesync_event_time_delta;


/* protocol tree items */
static int ett_tecmp;
static int ett_tecmp_flags;

static int ett_tecmp_payload;
static int ett_tecmp_payload_interface_id;
static int ett_tecmp_payload_data;
static int ett_tecmp_payload_timestamp;
static int ett_tecmp_payload_dataflags;
static int ett_tecmp_payload_instruction_address;
static int ett_tecmp_payload_data_id;
static int ett_tecmp_payload_lin_id;
static int ett_tecmp_status_bus_data;
static int ett_tecmp_status_bus_data_entry;
static int ett_tecmp_status_dev_vendor_data;
static int ett_tecmp_status_bus_vendor_data;
static int ett_tecmp_status_bus_vendor_data_flags;
static int ett_tecmp_ctrl_message_10baset1s_flags;
static int ett_tecmp_ctrl_message_10baset1s_events_errors;

/* dissector handle to hand off to ASAM CMP (successor protocol) */
static dissector_handle_t asam_cmp_handle;

/*** expert info items ***/
static expert_field ei_tecmp_payload_length_mismatch;
static expert_field ei_tecmp_payload_header_crc_overflow;

/* TECMP Type Names */

#define TECMP_MSG_TYPE_CTRL_MSG            0x00
#define TECMP_MSG_TYPE_STATUS_DEV          0x01
#define TECMP_MSG_TYPE_STATUS_BUS          0x02
#define TECMP_MSG_TYPE_LOG_STREAM          0x03
#define TECMP_MSG_TYPE_CFG_CM              0x04
#define TECMP_MSG_TYPE_REPLAY_DATA         0x0A
#define TECMP_MSG_TYPE_COUNTER_EVENT       0x0B
#define TECMP_MSG_TYPE_TIMESYNC_EVENT      0x0C


/* TECMP Type Names */
/* Updated by ID Registry */
static const value_string msg_type_names[] = {
    {TECMP_MSG_TYPE_CTRL_MSG,              "Control Message"},
    {TECMP_MSG_TYPE_STATUS_DEV,            "Status Device"},
    {TECMP_MSG_TYPE_STATUS_BUS,            "Status Bus"},
    {TECMP_MSG_TYPE_LOG_STREAM,            "Logging Stream"},
    {TECMP_MSG_TYPE_CFG_CM,                "Status Configuration"},
    {TECMP_MSG_TYPE_REPLAY_DATA,           "Replay Data"},
    {TECMP_MSG_TYPE_COUNTER_EVENT,         "Counter Event"},
    {TECMP_MSG_TYPE_TIMESYNC_EVENT,        "TimeSync Event"},
    {0, NULL}
};

/* TECMP Message Type Names */
/* Updated by ID Registry */
#define TECMP_DATA_TYPE_NONE               0x0000
#define TECMP_DATA_TYPE_CAN_RAW            0x0001
#define TECMP_DATA_TYPE_CAN_DATA           0x0002
#define TECMP_DATA_TYPE_CAN_FD_DATA        0x0003
#define TECMP_DATA_TYPE_LIN                0x0004
#define TECMP_DATA_TYPE_FR_RAW             0x0007
#define TECMP_DATA_TYPE_FR_DATA            0x0008
#define TECMP_DATA_TYPE_GPIO               0x000A
#define TECMP_DATA_TYPE_ILAS               0x000E
#define TECMP_DATA_TYPE_RS232_ASCII        0x0010
#define TECMP_DATA_TYPE_RS232_RAW          0x0011
#define TECMP_DATA_TYPE_RS232_SLA          0x0012
#define TECMP_DATA_TYPE_ANALOG             0x0020
#define TECMP_DATA_TYPE_ANALOG_SLA         0x0021
#define TECMP_DATA_TYPE_ETH                0x0080
#define TECMP_DATA_TYPE_ETH_10BASE_T1S     0x0082
#define TECMP_DATA_TYPE_XCP_DATA           0x00A0
#define TECMP_DATA_TYPE_MIPI_CSI2_V        0x0101
#define TECMP_DATA_TYPE_MIPI_CSI2_L        0x0102
#define TECMP_DATA_TYPE_SPI                0x0103
#define TECMP_DATA_TYPE_I2C_7BIT           0x0104
#define TECMP_DATA_TYPE_TAPI               0x0200
#define TECMP_DATA_TYPE_TAPI_INIT_STATE    0x0201
#define TECMP_DATA_TYPE_TAPI_CORE_DUMP     0x0202
#define TECMP_DATA_TYPE_R                  0x0400
#define TECMP_DATA_TYPE_TECMP_RAW          0xA000
#define TECMP_DATA_TYPE_PRE_LABEL          0xB000

static const value_string tecmp_msgtype_names[] = {
    {TECMP_DATA_TYPE_NONE,                 "None (Undefined)"},
    {TECMP_DATA_TYPE_CAN_RAW,              "CAN(-FD) Raw"},
    {TECMP_DATA_TYPE_CAN_DATA,             "CAN Data"},
    {TECMP_DATA_TYPE_CAN_FD_DATA,          "CAN-FD Data"},
    {TECMP_DATA_TYPE_LIN,                  "LIN"},
    {TECMP_DATA_TYPE_FR_RAW,               "Flexray Raw"},
    {TECMP_DATA_TYPE_FR_DATA,              "Flexray Data"},
    {TECMP_DATA_TYPE_GPIO,                 "GPIO"},
    {TECMP_DATA_TYPE_ILAS,                 "ILaS"},
    {TECMP_DATA_TYPE_RS232_ASCII,          "UART/RS232_ASCII"},
    {TECMP_DATA_TYPE_RS232_RAW,            "UART/RS232_RAW"},
    {TECMP_DATA_TYPE_RS232_SLA,            "UART/RS232_SLA"},
    {TECMP_DATA_TYPE_ANALOG,               "Analog"},
    {TECMP_DATA_TYPE_ANALOG_SLA,           "Analog_SLA"},
    {TECMP_DATA_TYPE_ETH,                  "Ethernet II"},
    {TECMP_DATA_TYPE_ETH_10BASE_T1S,       "Ethernet 10BASE-T1S"},
    {TECMP_DATA_TYPE_XCP_DATA,             "XCP-Data"},
    {TECMP_DATA_TYPE_MIPI_CSI2_V,          "MIPI-CSI2 V"},
    {TECMP_DATA_TYPE_MIPI_CSI2_L,          "MIPI-CSI2 L"},
    {TECMP_DATA_TYPE_SPI,                  "SPI"},
    {TECMP_DATA_TYPE_I2C_7BIT,             "I2C 7 Bit"},
    {TECMP_DATA_TYPE_TAPI,                 "TAPI"},
    {TECMP_DATA_TYPE_TAPI_INIT_STATE,      "TAPI Initial State"},
    {TECMP_DATA_TYPE_TAPI_CORE_DUMP,       "TAPI Core Dump"},
    {TECMP_DATA_TYPE_R,                    "R"},
    {TECMP_DATA_TYPE_TECMP_RAW,            "TECMP_Raw"},
    {TECMP_DATA_TYPE_PRE_LABEL,            "PreLabel"},
    {0, NULL}
};

/* Vendor IDs */
/* Updated by ID Registry */
#define TECMP_VENDOR_ID_TECHNICA           0x0c
static const value_string tecmp_vendor_ids[] = {
    {TECMP_VENDOR_ID_TECHNICA,             "Technica Engineering"},
    {0, NULL}
};

/* Device IDs */
/* Can be overwritten/extended by config */
static const value_string tecmp_device_id_prefixes[] = {
    {0x0030, "CM LIN Combo"},
    {0x0040, "CM CAN Combo"},
    {0x0060, "CM 100 High"},
    {0x0070, "CM 10BASE-T1S 0"},
    {0x0071, "CM 10BASE-T1S 1"},
    {0x0072, "CM 10BASE-T1S 2"},
    {0x0073, "CM 10BASE-T1S 3"},
    {0x0074, "CM 10BASE-T1S 4"},
    {0x0075, "CM 10BASE-T1S 5"},
    {0x0076, "CM 10BASE-T1S 6"},
    {0x0077, "CM 10BASE-T1S 7"},
    {0x0078, "CM 10BASE-T1S 8"},
    {0x0079, "CM 10BASE-T1S 9"},
    {0x007a, "CM ILaS Combo 0"},
    {0x007b, "CM ILaS Combo 1"},
    {0x007c, "CM ILaS Combo 2"},
    {0x007d, "CM ILaS Combo 3"},
    {0x007e, "CM ILaS Combo 4"},
    {0x007f, "CM ILaS Combo 5"},
    {0x0080, "CM Eth Combo"},
    {0x0090, "CM 1000 High"},
    {0, NULL}
};

#define TECMP_DEVICE_TYPE_CM_10BASE_T1S 0x0c
#define TECMP_DEVICE_TYPE_CM_ILAS_COMBO 0x0e

/* Device Types */
/* Updated by ID Registry */
static const value_string tecmp_device_types[] = {
    {0x02, "CM LIN Combo"},
    {0x04, "CM CAN Combo"},
    {0x06, "CM 100 High"},
    {0x08, "CM Eth Combo"},
    {0x0a, "CM 1000 High"},
    {TECMP_DEVICE_TYPE_CM_10BASE_T1S, "CM 10BASE-T1S"},
    {TECMP_DEVICE_TYPE_CM_ILAS_COMBO, "CM ILaS Combo"},
    {0x10, "Sensor specific"},
    {0x20, "Logger"},
    {0, NULL}
};

/* Control Message IDs */
/* Updated by ID Registry */
#define TECMP_CTRL_MSG_LOGGER_READY        0x0002
#define TECMP_CTRL_MSG_CAN_REPLAY_FILL_LVL 0x00E0
#define TECMP_CTRL_MSG_FR_POC_STATE        0x00E1
#define TECMP_CTRL_MSG_10BASE_T1S          0x00E2

static const value_string tecmp_ctrl_msg_ids_types[] = {
    {TECMP_CTRL_MSG_LOGGER_READY,          "Logger Ready"},
    {TECMP_CTRL_MSG_CAN_REPLAY_FILL_LVL,   "CAN Replay Fill Level"},
    {TECMP_CTRL_MSG_FR_POC_STATE,          "FlexRay POC State"},
    {TECMP_CTRL_MSG_10BASE_T1S,            "10BASE-T1S"},
    {0, NULL}
};

static const value_string tecmp_ctrl_msg_fr_poc_state[] = {
    {0, "Config"},
    {1, "Default Config"},
    {2, "Halt"},
    {3, "Normal Active"},
    {4, "Normal Passive"},
    {5, "Ready"},
    {6, "Startup"},
    {7, "Wakeup"},
    {0, NULL}
};

static const true_false_string tfs_tecmp_payload_timestamp_async_type = {
    "Not synchronized",
    "Synchronized or Master"
};

static const true_false_string tfs_tecmp_technica_bufferoverflow = {
    "Buffer Overflow occurred",
    "No Buffer Overflow occurred"
};

static const true_false_string tfs_tecmp_payload_data_crc_received = {
    "CRC present in received message",
    "CRC not present in received message"
};

static const true_false_string tfs_tecmp_payload_data_direction = {
    "Upstream (response)",
    "Downstream (command)"
};

static const true_false_string tfs_tecmp_payload_data_id_type = {
    "29bit CAN Identifier",
    "11bit CAN Identifier"
};

static const value_string tecmp_payload_rs232_uart_dl_types[] = {
    {0x2, "RS232 with 7 bit"},
    {0x3, "RS232 with 8 bit"},
    {0, NULL}
};

static const value_string tecmp_payload_analog_sample_time_types[] = {
    {0x0, "Reserved"},
    {0x1, "2500 ms"},
    {0x2, "1000 ms"},
    {0x3, "500 ms"},
    {0x4, "250 ms"},
    {0x5, "100 ms"},
    {0x6, "50 ms"},
    {0x7, "25 ms"},
    {0x8, "10 ms"},
    {0x9, "5 ms"},
    {0xa, "2.5 ms"},
    {0xb, "1 ms"},
    {0xc, "0.5 ms"},
    {0xd, "0.25 ms"},
    {0xe, "0.1 ms"},
    {0xf, "0.05 ms"},
    {0, NULL}
};

static const double tecmp_payload_analog_scale_factor_values[] = {
    0.1,
    0.01,
    0.001,
    0.0001,
};

static const value_string tecmp_payload_analog_scale_factor_types[] = {
    {0x0, "0.1"},
    {0x1, "0.01"},
    {0x2, "0.001"},
    {0x3, "0.0001"},
    {0, NULL}
};

static const value_string tecmp_payload_analog_unit_types[] = {
    {0x0, "V"},
    {0x1, "A"},
    {0x2, "W"},
    {0x3, "Ah"},
    {0x4, UTF8_DEGREE_SIGN "C"},
    {0x5, "undefined value"},
    {0x6, "undefined value"},
    {0x7, "undefined value"},
    {0, NULL}
};

static const value_string tecmp_ilas_command_types[] = {
    {0, "Unknown Command"},
    {1, "ILas_Reset"},
    {2, "ILaS_Set_Config"},
    {3, "ILaS_Set_PWM_Max_High_Ch2"},
    {4, "ILaS_Set_PWM_Max_High_Ch1"},
    {5, "ILaS_Set_PWM_Max_High_Ch0"},
    {6, "ILaS_Set_Cur_Ch1"},
    {7, "ILaS_Set_Cur_Ch0"},
    {8, "ILaS_Set_Temp_Offset"},
    {9, "ILaS_Trig_ADC_Cal"},
    {11, "ILaS_Set_Bias"},
    {12, "ILaS_Set_TC_Base"},
    {13, "ILaS_Set_TC_Offset"},
    {14, "ILaS_Set_Sig_High"},
    {15, "ILaS_Set_ADC_DAC"},
    {16, "ILaS_Burn_Item (part 1)"},
    {17, "ILaS_Burn_Sig"},
    {18, "ILaS_Burn_Item (part 2)"},
    {19, "ILaS_Set_TC_LUT"},
    {20, "ILaS_Define_Mcast"},
    {21, "ILaS_Set_PWM_Max_Low_Ch2"},
    {22, "ILaS_Set_PWM_Max_Low_Ch1"},
    {23, "ILaS_Set_PWM_Max_Low_Ch0"},
    {24, "ILaS_Set_Cur_Ch3"},
    {25, "ILaS_Burn_Item (part 3)"},
    {26, "ILaS_Set_Port"},
    {27, "ILaS_Branch_Read_Temp"},
    {28, "ILaS_Branch_Read_Status"},
    {29, "ILaS_Branch_Read_ADC"},
    {30, "ILaS_Branch_Read_Item (part 1)"},
    {31, "ILaS_Branch_Read_PWM"},
    {32, "ILaS_Branch_Read_Item (part 2)"},
    {33, "ILaS_Network_Init"},
    {34, "ILaS_Branch_Init"},
    {35, "ILaS_Network_Ping"},
    {36, "ILaS_Branch_Ping"},
    {37, "ILaS_Read_Register"},
    {38, "ILaS_BranchDevices_Read"},
    {39, "ILaS_Read_Event"},
    {40, "ILaS_Set_Fw_Mode"},
    {41, "ILaS_Set_Ps_Mode"},
    {42, "ILaS_Burn_Sniff_Mode"},
    {43, "ILaS_NOP"},
    {44, "ILaS_Trg_ADC_Meas"},
    {45, "ILaS_Set_3PWM_Low"},
    {46, "ILaS_Set_3PWM_High"},
    {47, "ILaS_Set_DIM"},
    {48, "ILaS_Set_PWM_Ch3"},
    {49, "ILaS_Write_Register"},
    {50, "ILaS_Burn_Register"},
    {0, NULL}
};

static const value_string tecmp_payload_flexray_tx_mode[] = {
    {0x0, "Reserved"},
    {0x1, "Single Shot Transmission"},
    {0x2, "Continuous Transmission"},
    {0x3, "TX None"},
    {0, NULL}
};

static const value_string tecmp_bus_status_link_status[] = {
    {0x0, "Down"},
    {0x1, "Up"},
    {0, NULL}
};

static const value_string tecmp_bus_status_link_quality[] = {
    {0x0, "Unacceptable or Down (0/5)"},
    {0x1, "Poor (1/5)"},
    {0x2, "Marginal (2/5)"},
    {0x3, "Good (3/5)"},
    {0x4, "Very good (4/5)"},
    {0x5, "Excellent (5/5)"},
    {0, NULL}
};

static const value_string tecmp_timesync_event_flags[] = {
    {0x0, "No error occurred"},
    {0x1, "Error occurred"},
    {0, NULL}
};


#define DATA_FLAG_CAN_ACK               0x0001
#define DATA_FLAG_CAN_RTR               0x0002
#define DATA_FLAG_CANFD_ESI             0x0002
#define DATA_FLAG_CAN_IDE               0x0004
#define DATA_FLAG_CAN_ERR               0x0008
#define DATA_FLAG_CAN_BIT_STUFF_ERR     0x0010
#define DATA_FLAG_CAN_CRC_DEL_ERR       0x0020
#define DATA_FLAG_CAN_ACK_DEL_ERR       0x0040
#define DATA_FLAG_CAN_EOF_ERR           0x0080
#define DATA_FLAG_CANFD_BRS             0x0010
#define DATA_FLAG_CANFD_BIT_STUFF_ERR   0x0020
#define DATA_FLAG_CANFD_CRC_DEL_ERR     0x0040
#define DATA_FLAG_CANFD_ACK_DEL_ERR     0x0080
#define DATA_FLAG_CANFD_EOF_ERR         0x0100

#define DATA_FLAG_FR_NF                 0x0001
#define DATA_FLAG_FR_ST                 0x0002
#define DATA_FLAG_FR_SYNC               0x0004
#define DATA_FLAG_FR_WUS                0x0008
#define DATA_FLAG_FR_PPI                0x0010
#define DATA_FLAG_FR_CAS                0x0020
#define DATA_FLAG_FR_HDR_CRC_ERR        0x1000
#define DATA_FLAG_FR_FRAME_CRC_ERR      0x2000

#define DATA_LIN_ID_MASK                0x3F
#define DATA_FR_HEADER_CRC_MAX          0x07FF

/********* UATs *********/

typedef struct _generic_one_id_string {
    unsigned   id;
    char   *name;
} generic_one_id_string_t;

/* Interface UAT */
typedef struct _interface_config {
    unsigned  id;
    unsigned  bus_id;
    char     *name;
} interface_config_t;

#define DATAFILE_TECMP_DEVICE_IDS "TECMP_device_identifiers"
#define DATAFILE_TECMP_INTERFACE_IDS "TECMP_interface_identifiers"
#define DATAFILE_TECMP_CONTROL_MSG_IDS "TECMP_control_message_identifiers"

static GHashTable *data_tecmp_devices;
static generic_one_id_string_t* tecmp_devices;
static unsigned tecmp_devices_num;

UAT_HEX_CB_DEF(tecmp_devices, id, generic_one_id_string_t)
UAT_CSTRING_CB_DEF(tecmp_devices, name, generic_one_id_string_t)

static GHashTable *data_tecmp_interfaces;
static interface_config_t* tecmp_interfaces;
static unsigned tecmp_interfaces_num;

UAT_HEX_CB_DEF(tecmp_interfaces, id, interface_config_t)
UAT_CSTRING_CB_DEF(tecmp_interfaces, name, interface_config_t)
UAT_HEX_CB_DEF(tecmp_interfaces, bus_id, interface_config_t)

static GHashTable *data_tecmp_ctrlmsgids;
static generic_one_id_string_t* tecmp_ctrl_msgs;
static unsigned tecmp_ctrl_msg_num;

UAT_HEX_CB_DEF(tecmp_ctrl_msgs, id, generic_one_id_string_t)
UAT_CSTRING_CB_DEF(tecmp_ctrl_msgs, name, generic_one_id_string_t)

/* generic UAT */
static void
tecmp_free_key(void *key) {
    wmem_free(wmem_epan_scope(), key);
}

static void
simple_free(void *data) {
    /* we need to free because of the g_strdup in post_update*/
    g_free(data);
}

/* ID -> Name */
static void *
copy_generic_one_id_string_cb(void *n, const void *o, size_t size _U_) {
    generic_one_id_string_t *new_rec = (generic_one_id_string_t *)n;
    const generic_one_id_string_t *old_rec = (const generic_one_id_string_t *)o;

    new_rec->name = g_strdup(old_rec->name);
    new_rec->id = old_rec->id;
    return new_rec;
}

static bool
update_generic_one_identifier_16bit(void *r, char **err) {
    generic_one_id_string_t *rec = (generic_one_id_string_t *)r;

    if (rec->id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit identifiers (ID: %i  Name: %s)", rec->id, rec->name);
        return false;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return false;
    }

    return true;
}

static void
free_generic_one_id_string_cb(void* r) {
    generic_one_id_string_t *rec = (generic_one_id_string_t *)r;
    /* freeing result of g_strdup */
    g_free(rec->name);
    rec->name = NULL;
}

static void
post_update_one_id_string_template_cb(generic_one_id_string_t *data, unsigned data_num, GHashTable *ht) {
    unsigned   i;
    int    *key = NULL;

    for (i = 0; i < data_num; i++) {
        key = wmem_new(wmem_epan_scope(), int);
        *key = data[i].id;

        g_hash_table_insert(ht, key, g_strdup(data[i].name));
    }
}

static char *
ht_lookup_name(GHashTable *ht, unsigned int identifier) {
    char           *tmp = NULL;
    unsigned int   *id = NULL;

    if (ht == NULL) {
        return NULL;
    }

    id = wmem_new(wmem_epan_scope(), unsigned int);
    *id = (unsigned int)identifier;
    tmp = (char *)g_hash_table_lookup(ht, id);
    wmem_free(wmem_epan_scope(), id);

    return tmp;
}

/* ID -> ID, Name */
static void *
copy_interface_config_cb(void *n, const void *o, size_t size _U_) {
    interface_config_t *new_rec = (interface_config_t *)n;
    const interface_config_t *old_rec = (const interface_config_t *)o;

    new_rec->id = old_rec->id;
    new_rec->name = g_strdup(old_rec->name);
    new_rec->bus_id = old_rec->bus_id;
    return new_rec;
}

static bool
update_interface_config(void *r, char **err) {
    interface_config_t *rec = (interface_config_t *)r;

    if (rec->id > 0xffffffff) {
        *err = ws_strdup_printf("We currently only support 32 bit identifiers (ID: %i  Name: %s)", rec->id, rec->name);
        return false;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return false;
    }

    if (rec->bus_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit bus identifiers (ID: %i  Name: %s  Bus-ID: %i)", rec->id, rec->name, rec->bus_id);
        return false;
    }

    return true;
}

static void
free_interface_config_cb(void *r) {
    interface_config_t *rec = (interface_config_t *)r;
    /* freeing result of g_strdup */
    g_free(rec->name);
    rec->name = NULL;
}

static interface_config_t *
ht_lookup_interface_config(unsigned int identifier) {
    interface_config_t   *tmp = NULL;
    unsigned int       *id = NULL;

    if (data_tecmp_interfaces == NULL) {
        return NULL;
    }

    id = wmem_new(wmem_epan_scope(), unsigned int);
    *id = (unsigned int)identifier;
    tmp = (interface_config_t *)g_hash_table_lookup(data_tecmp_interfaces, id);
    wmem_free(wmem_epan_scope(), id);

    return tmp;
}

static char *
ht_interface_config_to_string(unsigned int identifier) {
    interface_config_t   *tmp = ht_lookup_interface_config(identifier);
    if (tmp == NULL) {
        return NULL;
    }

    return tmp->name;
}

static uint16_t
ht_interface_config_to_bus_id(unsigned int identifier) {
    interface_config_t   *tmp = ht_lookup_interface_config(identifier);
    if (tmp == NULL) {
        /* 0 means basically any or none */
        return 0;
    }

    return tmp->bus_id;
}

/*** UAT TECMP_DEVICE_IDs ***/

static void
post_update_tecmp_devices_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_tecmp_devices) {
        g_hash_table_destroy(data_tecmp_devices);
        data_tecmp_devices = NULL;
    }

    /* create new hash table */
    data_tecmp_devices = g_hash_table_new_full(g_int_hash, g_int_equal, &tecmp_free_key, &simple_free);
    post_update_one_id_string_template_cb(tecmp_devices, tecmp_devices_num, data_tecmp_devices);
}

static void
add_device_id_text(proto_item *ti, uint16_t device_id) {
    const char *descr = ht_lookup_name(data_tecmp_devices, device_id);

    if (descr != NULL) {
        proto_item_append_text(ti, " (%s)", descr);
    } else if (device_id >= 0x0070 && device_id <= 0x007f) {
        descr = val_to_str_const((device_id), tecmp_device_id_prefixes, "Unknown/Unconfigured CM");
        proto_item_append_text(ti, " (%s)", descr);
    } else {
        /* try to pick a default */
        descr = val_to_str_const((device_id & 0xfff0), tecmp_device_id_prefixes, "Unknown/Unconfigured CM");

        if (descr != NULL) {
            if ((device_id & 0x000f) == 0) {
                proto_item_append_text(ti, " (%s %d (Default))", descr, (device_id & 0x000f));
            } else {
                proto_item_append_text(ti, " (%s %d)", descr, (device_id & 0x000f));
            }
        }
    }
}

/*** UAT TECMP_INTERFACE_IDs ***/

static void
post_update_tecmp_interfaces_cb(void) {
    unsigned  i;
    int   *key = NULL;

    /* destroy old hash table, if it exists */
    if (data_tecmp_interfaces) {
        g_hash_table_destroy(data_tecmp_interfaces);
        data_tecmp_interfaces = NULL;
    }

    /* create new hash table */
    data_tecmp_interfaces = g_hash_table_new_full(g_int_hash, g_int_equal, &tecmp_free_key, NULL);

    if (data_tecmp_interfaces == NULL || tecmp_interfaces == NULL || tecmp_interfaces_num == 0) {
        return;
    }

    for (i = 0; i < tecmp_interfaces_num; i++) {
        key = wmem_new(wmem_epan_scope(), int);
        *key = tecmp_interfaces[i].id;
        g_hash_table_insert(data_tecmp_interfaces, key, &tecmp_interfaces[i]);
    }
}

static void
add_interface_id_text_and_name(proto_item *ti, uint32_t interface_id, tvbuff_t *tvb, int offset) {
    const char *descr = ht_interface_config_to_string(interface_id);

    if (descr != NULL) {
        proto_item_append_text(ti, " (%s)", descr);
        proto_tree *subtree = proto_item_add_subtree(ti, ett_tecmp_payload_interface_id);
        proto_tree_add_string(subtree, hf_tecmp_payload_interface_name, tvb, offset, 4, descr);
    }
}

/*** UAT TECMP_CONTROL_MESSAGE_IDs ***/

static void
post_update_tecmp_control_messages_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_tecmp_ctrlmsgids) {
        g_hash_table_destroy(data_tecmp_ctrlmsgids);
        data_tecmp_ctrlmsgids = NULL;
    }

    /* create new hash table */
    data_tecmp_ctrlmsgids = g_hash_table_new_full(g_int_hash, g_int_equal, &tecmp_free_key, &simple_free);
    post_update_one_id_string_template_cb(tecmp_ctrl_msgs, tecmp_ctrl_msg_num, data_tecmp_ctrlmsgids);
}

static const char*
resolve_control_message_id(uint16_t control_message_id)
{
    const char *tmp = ht_lookup_name(data_tecmp_ctrlmsgids, control_message_id);

    /* lets look at the static values, if nothing is configured */
    if (tmp == NULL) {
        tmp = try_val_to_str(control_message_id, tecmp_ctrl_msg_ids_types);
    }

    /* no configured or standardized name known */
    if (tmp != NULL) {
        return wmem_strdup_printf(wmem_packet_scope(), "%s (0x%04x)", tmp, control_message_id);
    }

    /* just give back unknown */
    return wmem_strdup_printf(wmem_packet_scope(), "Unknown (0x%04x)", control_message_id);
}



static bool
tecmp_entry_header_present(tvbuff_t *tvb, unsigned offset) {
    uint32_t chan_id = 0;
    uint64_t tstamp  = 0;
    uint16_t length  = 0;

    chan_id = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    tstamp  = tvb_get_uint64(tvb, offset + 4, ENC_BIG_ENDIAN);
    length  = tvb_get_uint16(tvb, offset + 12, ENC_BIG_ENDIAN);

    if (chan_id == 0 && tstamp == 0 && length == 0) {
        /* 0 is not valid and therefore we assume padding. */
        return false;
    }
    return true;
}

static unsigned
dissect_tecmp_entry_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset_orig, unsigned tecmp_msg_type, uint16_t data_type,
                           bool first, uint16_t *dataflags, uint32_t *interface_id, uint64_t *timestamp_ns) {
    proto_item *ti;
    proto_tree *subtree = NULL;
    unsigned offset = offset_orig;

    nstime_t timestamp;
    uint64_t ns = 0;
    bool async = false;
    unsigned tmp;

    static int * const dataflags_generic[] = {
        &hf_tecmp_payload_data_flags_overflow,
        &hf_tecmp_payload_data_flags_tx,
        &hf_tecmp_payload_data_flags_crc,
        NULL
    };

    static int * const dataflags_ethernet_10base_t1s[] = {
        &hf_tecmp_payload_data_flags_overflow,
        &hf_tecmp_payload_data_flags_tx,
        &hf_tecmp_payload_data_flags_crc,
        &hf_tecmp_payload_data_flags_phy_event_error,
        NULL
    };

    static int * const dataflags_lin[] = {
        &hf_tecmp_payload_data_flags_overflow,
        &hf_tecmp_payload_data_flags_tx,
        &hf_tecmp_payload_data_flags_checksum,

        &hf_tecmp_payload_data_flags_sleep,
        &hf_tecmp_payload_data_flags_short_wup,
        &hf_tecmp_payload_data_flags_wup,
        &hf_tecmp_payload_data_flags_no_resp,
        &hf_tecmp_payload_data_flags_parity,
        &hf_tecmp_payload_data_flags_coll,
        NULL
    };

    static int * const dataflags_lin_tx[] = {
        &hf_tecmp_payload_data_flags_use_checksum_value,

        &hf_tecmp_payload_data_flags_short_wup,
        &hf_tecmp_payload_data_flags_wup,
        &hf_tecmp_payload_data_flags_use_parity_bits,
        NULL
    };

    static int * const dataflags_can_data[] = {
        &hf_tecmp_payload_data_flags_overflow,
        &hf_tecmp_payload_data_flags_tx,
        &hf_tecmp_payload_data_flags_crc,

        &hf_tecmp_payload_data_flags_can_eof_err,
        &hf_tecmp_payload_data_flags_can_ack_del_err,
        &hf_tecmp_payload_data_flags_can_crc_del_err,
        &hf_tecmp_payload_data_flags_can_bit_stuff_err,
        &hf_tecmp_payload_data_flags_err,
        &hf_tecmp_payload_data_flags_ide,
        &hf_tecmp_payload_data_flags_rtr,
        &hf_tecmp_payload_data_flags_ack,
        NULL
    };

    static int * const dataflags_can_tx_data[] = {
        &hf_tecmp_payload_data_flags_use_crc_value,

        &hf_tecmp_payload_data_flags_can_eof_err,
        &hf_tecmp_payload_data_flags_can_ack_del_err,
        &hf_tecmp_payload_data_flags_can_crc_del_err,
        &hf_tecmp_payload_data_flags_can_bit_stuff_err,
        NULL
    };

    static int * const dataflags_can_fd_data[] = {
        &hf_tecmp_payload_data_flags_overflow,
        &hf_tecmp_payload_data_flags_tx,
        &hf_tecmp_payload_data_flags_crc,

        &hf_tecmp_payload_data_flags_canfd_eof_err,
        &hf_tecmp_payload_data_flags_canfd_ack_del_err,
        &hf_tecmp_payload_data_flags_canfd_crc_del_err,
        &hf_tecmp_payload_data_flags_canfd_bit_stuff_err,
        &hf_tecmp_payload_data_flags_brs,
        &hf_tecmp_payload_data_flags_err,
        &hf_tecmp_payload_data_flags_ide,
        &hf_tecmp_payload_data_flags_esi,
        &hf_tecmp_payload_data_flags_ack,
        NULL
    };

    static int * const dataflags_can_fd_tx_data[] = {
        &hf_tecmp_payload_data_flags_use_crc_value,

        &hf_tecmp_payload_data_flags_canfd_eof_err,
        &hf_tecmp_payload_data_flags_canfd_ack_del_err,
        &hf_tecmp_payload_data_flags_canfd_crc_del_err,
        &hf_tecmp_payload_data_flags_canfd_bit_stuff_err,
        &hf_tecmp_payload_data_flags_brs,
        NULL
    };

    static int * const dataflags_flexray_data[] = {
        &hf_tecmp_payload_data_flags_overflow,
        &hf_tecmp_payload_data_flags_tx,

        &hf_tecmp_payload_data_flags_frame_crc_err,
        &hf_tecmp_payload_data_flags_header_crc_err,
        &hf_tecmp_payload_data_flags_cas,
        &hf_tecmp_payload_data_flags_ppi,
        &hf_tecmp_payload_data_flags_wus,
        &hf_tecmp_payload_data_flags_sync,
        &hf_tecmp_payload_data_flags_sf,
        &hf_tecmp_payload_data_flags_nf,
        NULL
    };

    static int * const dataflags_flexray_tx_data[] = {

        &hf_tecmp_payload_data_flags_use_header_crc_value,
        &hf_tecmp_payload_data_flags_tx_mode,
        NULL
    };

    static int * const dataflags_ilas[] = {
        &hf_tecmp_payload_data_flags_crc,

        &hf_tecmp_payload_data_flags_direction,
        &hf_tecmp_payload_data_flags_crc_enabled,
        NULL
    };

    static int * const dataflags_rs232_uart_ascii[] = {
        &hf_tecmp_payload_data_flags_tx,

        &hf_tecmp_payload_data_flags_dl,
        &hf_tecmp_payload_data_flags_parity_error,
        NULL
    };

    static int * const dataflags_analog[] = {
        &hf_tecmp_payload_data_flags_overflow,

        &hf_tecmp_payload_data_flags_sample_time,
        &hf_tecmp_payload_data_flags_factor,
        &hf_tecmp_payload_data_flags_unit,
        &hf_tecmp_payload_data_flags_threshold_u,
        &hf_tecmp_payload_data_flags_threshold_o,
        NULL
    };

    /* Can't use col_append_sep_str because we already set something before. */
    if (!first) {
        col_append_str(pinfo->cinfo, COL_INFO, ", ");
    }
    col_append_str(pinfo->cinfo, COL_INFO, val_to_str(data_type, tecmp_msgtype_names, "Unknown (%d)"));

    ti = proto_tree_add_item_ret_uint(tree, hf_tecmp_payload_interface_id, tvb, offset, 4, ENC_BIG_ENDIAN, &tmp);
    add_interface_id_text_and_name(ti, tmp, tvb, offset);
    if (interface_id != NULL) {
        *interface_id = tmp;
    }

    ns = tvb_get_uint64(tvb, offset + 4, ENC_BIG_ENDIAN) & 0x3fffffffffffffff;

    if (timestamp_ns != NULL) {
        *timestamp_ns = ns;
    }

    timestamp.secs = (time_t)(ns / 1000000000);
    timestamp.nsecs = (int)(ns % 1000000000);
    ti = proto_tree_add_time(tree, hf_tecmp_payload_timestamp, tvb, offset + 4, 8, &timestamp);
    subtree = proto_item_add_subtree(ti, ett_tecmp_payload_timestamp);
    proto_tree_add_item_ret_boolean(subtree, hf_tecmp_payload_timestamp_async, tvb, offset + 4, 1, ENC_NA, &async);
    proto_tree_add_item(subtree, hf_tecmp_payload_timestamp_res, tvb, offset + 4, 1, ENC_NA);

    if (async) {
        proto_item_append_text(ti, " (not synchronized)");
    } else {
        proto_item_append_text(ti, " (synchronized or master)");
    }
    ti = proto_tree_add_uint64(tree, hf_tecmp_payload_timestamp_ns, tvb, offset + 4, 8, ns);
    proto_item_set_hidden(ti);

    proto_tree_add_item(tree, hf_tecmp_payload_length, tvb, offset+12, 2, ENC_BIG_ENDIAN);
    offset += 14;

    if (dataflags != NULL) {
        *dataflags = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    }

    switch (tecmp_msg_type) {
    case TECMP_MSG_TYPE_LOG_STREAM:
        switch (data_type) {
        case TECMP_DATA_TYPE_LIN:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_lin, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_CAN_DATA:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_can_data, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_CAN_FD_DATA:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_can_fd_data, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_FR_DATA:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_flexray_data, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_ILAS:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_ilas, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_RS232_ASCII:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_rs232_uart_ascii, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_ANALOG:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_analog, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_ETH_10BASE_T1S:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_ethernet_10base_t1s, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_ETH:
        default:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_generic, ENC_BIG_ENDIAN);
        }
        break;

    case TECMP_MSG_TYPE_REPLAY_DATA:
        switch (data_type) {
        case TECMP_DATA_TYPE_LIN:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_lin_tx, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_CAN_DATA:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_can_tx_data, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_CAN_FD_DATA:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_can_fd_tx_data, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_FR_DATA:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_flexray_tx_data, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_RS232_ASCII:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_rs232_uart_ascii, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_ANALOG:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_analog, ENC_BIG_ENDIAN);
            break;

        case TECMP_DATA_TYPE_ETH:
        default:
            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_data_flags, ett_tecmp_payload_dataflags, dataflags_generic, ENC_BIG_ENDIAN);
        }
        break;

    case TECMP_MSG_TYPE_CTRL_MSG:
    case TECMP_MSG_TYPE_STATUS_DEV:
    case TECMP_MSG_TYPE_STATUS_BUS:
    case TECMP_MSG_TYPE_CFG_CM:
    case TECMP_MSG_TYPE_COUNTER_EVENT:
    case TECMP_MSG_TYPE_TIMESYNC_EVENT:
    default:
        proto_tree_add_item(tree, hf_tecmp_payload_data_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    }

    offset += 2;

    return offset - offset_orig;
}

static void
dissect_tecmp_status_config_vendor_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *ti_root, uint8_t device_type _U_,
                                        uint8_t vendor_id) {
    proto_tree *tree = NULL;
    int offset = 0;
    unsigned data_length = 0;

    proto_item_append_text(ti_root, " (%s)", val_to_str(vendor_id, tecmp_vendor_ids, "(Unknown Vendor: %d)"));
    tree = proto_item_add_subtree(ti_root, ett_tecmp_status_bus_vendor_data);

    switch (vendor_id) {
    case TECMP_VENDOR_ID_TECHNICA:
        proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_version, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_reserved, tvb, offset + 1, 1, ENC_NA);
        proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_msg_id, tvb, offset + 2, 2,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_total_length, tvb, offset + 4, 4,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_total_num_seg, tvb, offset + 8, 2,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_segment_num, tvb, offset + 10, 2,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_uint(tree, hf_tecmp_payload_status_cfg_vendor_technica_segment_length, tvb,
                                     offset + 12, 2, ENC_BIG_ENDIAN, &data_length);
        offset += 14;
        if (tvb_captured_length_remaining(tvb, offset) >= (int)data_length) {
            proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_segment_data, tvb, offset,
                                data_length, ENC_NA);
        } else {
            proto_tree_add_item(tree, hf_tecmp_payload_status_cfg_vendor_technica_segment_data, tvb, offset,
                                tvb_captured_length_remaining(tvb, offset), ENC_NA);
        }

        break;
    }
}

static void
dissect_tecmp_status_bus_vendor_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *ti_root,
                                     uint8_t entry_number, uint8_t device_type, uint8_t vendor_id) {
    proto_tree *tree = NULL;
    proto_item *ti = NULL;
    int offset = 0;
    int bytes_remaining = 0;
    unsigned tmp = 0;

    proto_item_append_text(ti_root, " (%s)", val_to_str(vendor_id, tecmp_vendor_ids, "(Unknown Vendor: %d)"));
    tree = proto_item_add_subtree(ti_root, ett_tecmp_status_bus_vendor_data);

    switch (vendor_id) {
    case TECMP_VENDOR_ID_TECHNICA:
        bytes_remaining = tvb_captured_length_remaining(tvb, offset);

        if (device_type == TECMP_DEVICE_TYPE_CM_ILAS_COMBO && entry_number < 5) {
            /* Currently no parameters for this format but might be specified in a later specification. */
        } else if ((device_type == TECMP_DEVICE_TYPE_CM_ILAS_COMBO && entry_number == 5) || device_type == TECMP_DEVICE_TYPE_CM_10BASE_T1S) {
            static int * const vendor_data_flags_10BASE_T1S[] = {
                &hf_tecmp_payload_status_bus_vendor_technica_10m_flags_plca_enabled,
                &hf_tecmp_payload_status_bus_vendor_technica_10m_flags_beacons_received,
                NULL
            };

            proto_tree_add_bitmask(tree, tvb, offset, hf_tecmp_payload_status_bus_vendor_technica_10m_flags, ett_tecmp_status_bus_vendor_data_flags, vendor_data_flags_10BASE_T1S, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_res0, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_beacon_counter, tvb, offset, 4, ENC_NA);
            offset += 4;

            proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_link_quality, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_res1, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_res2, tvb, offset, 2, ENC_NA);
            offset += 2;

            proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_5b_decode_err_cnt, tvb, offset, 2, ENC_NA);
            offset += 2;

            proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_eos_delim_err_cnt, tvb, offset, 2, ENC_NA);
            offset += 2;

            proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_plca_symbols_detected_cnt, tvb, offset, 2, ENC_NA);
            offset += 2;

            proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_plca_symbols_missing_cnt, tvb, offset, 2, ENC_NA);
            offset += 2;

            proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_plca_symbols_empty_cycle_cnt, tvb, offset, 2, ENC_NA);
        } else {
            if (bytes_remaining >= 1) {
                proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_link_status, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            if (bytes_remaining >= 2) {
                proto_tree_add_item(tree, hf_tecmp_payload_status_bus_vendor_technica_link_quality, tvb, offset, 1,
                    ENC_NA);
                offset += 1;
            }
            if (bytes_remaining >= 4) {
                ti = proto_tree_add_item_ret_uint(tree, hf_tecmp_payload_status_bus_vendor_technica_linkup_time, tvb,
                    offset, 2, ENC_NA, &tmp);
                if (tmp == 0) {
                    proto_item_append_text(ti, " %s", "(no linkup detected yet)");
                } else if (tmp == 0xffff) {
                    proto_item_append_text(ti, " %s", "(no linkup detected and timeout occurred)");
                }
            }
        }
        break;
    }
}

static void
dissect_tecmp_status_device_vendor_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *ti_root, uint8_t device_type _U_, uint8_t vendor_id, uint64_t timestamp_ns) {
    proto_tree *tree = NULL;
    proto_item *ti = NULL;
    int offset = 0;
    unsigned tmp = 0;
    uint64_t tmp64 = 0;
    nstime_t timestamp;
    int temperature = 0;

    proto_item_append_text(ti_root, " (%s)", val_to_str(vendor_id, tecmp_vendor_ids, "(Unknown Vendor: %d)"));
    tree = proto_item_add_subtree(ti_root, ett_tecmp_status_dev_vendor_data);

    switch (vendor_id) {
    case TECMP_VENDOR_ID_TECHNICA:
        proto_tree_add_item(tree, hf_tecmp_payload_status_dev_vendor_technica_res, tvb, offset, 1, ENC_NA);
        offset += 1;
        tmp = tvb_get_uint24(tvb, offset, ENC_BIG_ENDIAN);
        proto_tree_add_string_format(tree, hf_tecmp_payload_status_dev_vendor_technica_sw, tvb, offset, 3, NULL,
                                     "Software Version: v%d.%d.%d", (tmp&0x00ff0000)>>16, (tmp&0x0000ff00)>>8, tmp&0x000000ff);
        offset += 3;

        tmp = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
        proto_tree_add_string_format(tree, hf_tecmp_payload_status_dev_vendor_technica_hw, tvb, offset, 2, NULL,
                                     "Hardware Version: v%d.%x", (tmp & 0x0000ff00) >> 8, tmp & 0x000000ff);
        offset += 2;

        ti = proto_tree_add_item(tree, hf_tecmp_payload_status_dev_vendor_technica_buffer_fill_level, tvb, offset, 1, ENC_NA);
        proto_item_append_text(ti, "%s", "%");
        offset += 1;

        proto_tree_add_item(tree, hf_tecmp_payload_status_dev_vendor_technica_buffer_overflow, tvb, offset, 1, ENC_NA);
        offset += 1;

        tmp = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
        proto_tree_add_uint_format_value(tree, hf_tecmp_payload_status_dev_vendor_technica_buffer_size, tvb, offset,
                                         4, tmp * 128, "%d MB", tmp * 128);
        offset += 4;

        ti = proto_tree_add_item_ret_uint64(tree, hf_tecmp_payload_status_dev_vendor_technica_lifecycle, tvb, offset, 8, ENC_BIG_ENDIAN, &tmp64);

        uint64_t nanos = tmp64 % 1000000000;
        uint64_t secs = tmp64 / 1000000000;
        uint64_t mins = secs / 60;
        secs -= mins * 60;
        uint64_t hours = mins / 24;
        mins -= hours * 24;
        proto_item_append_text(ti, " ns (%d:%02d:%02d.%09d)", (uint32_t)hours, (uint32_t)mins, (uint32_t)secs, (uint32_t)nanos);

        if (tmp64 < timestamp_ns) {
            timestamp_ns -= tmp64;
            timestamp.secs = (time_t)(timestamp_ns / 1000000000);
            timestamp.nsecs = (int)(timestamp_ns % 1000000000);
            ti = proto_tree_add_time(tree, hf_tecmp_payload_status_dev_vendor_technica_lifecycle_start, tvb, offset, 8, &timestamp);
            proto_item_set_generated(ti);
        }
        offset += 8;

        tmp = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);

        double voltage_value = (double)((tmp & 0x0000ff00) >> 8) + (tmp & 0x000000ff) / 100.0;
        proto_tree_add_double(tree, hf_tecmp_payload_status_dev_vendor_technica_voltage, tvb, offset, 2, voltage_value);
        offset += 2;

        if (tvb_captured_length_remaining(tvb, offset) == 1) {
            proto_tree_add_item(tree, hf_tecmp_payload_status_dev_vendor_technica_temperature, tvb, offset, 1, ENC_NA);
        } else if (tvb_captured_length_remaining(tvb, offset) > 1) {
            /* TECMP 1.5 and later */
            temperature = tvb_get_int8(tvb, offset);
            if (temperature == VENDOR_TECHNICA_TEMP_NA) {
                proto_tree_add_int_format_value(tree, hf_tecmp_payload_status_dev_vendor_technica_temperature_chassis, tvb, offset, 1, temperature, "%s", "Not Available");
            } else {
                ti = proto_tree_add_item(tree, hf_tecmp_payload_status_dev_vendor_technica_temperature_chassis, tvb, offset, 1, ENC_NA);
                if (temperature == VENDOR_TECHNICA_TEMP_MAX) {
                    proto_item_append_text(ti, " %s", "or more");
                }
            }
            offset += 1;

            temperature = tvb_get_int8(tvb, offset);
            if ( temperature == VENDOR_TECHNICA_TEMP_NA) {
                proto_tree_add_int_format_value(tree, hf_tecmp_payload_status_dev_vendor_technica_temperature_silicon, tvb, offset, 1, temperature, "%s", "Not Available");
            } else {
                ti = proto_tree_add_item(tree, hf_tecmp_payload_status_dev_vendor_technica_temperature_silicon, tvb, offset, 1, ENC_NA);
                if (temperature == VENDOR_TECHNICA_TEMP_MAX) {
                    proto_item_append_text(ti, " %s", "or more");
                }
            }
        }

        break;
    }
}

static int
dissect_tecmp_control_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset_orig, uint16_t msg_type, unsigned tecmp_msg_type) {
    proto_item *root_ti = NULL;
    proto_item *ti = NULL;
    proto_tree *tecmp_tree = NULL;
    uint16_t length = 0;
    unsigned offset = offset_orig;
    unsigned device_id = 0;
    unsigned interface_id = 0;
    unsigned ctrl_msg_id = 0;

    if (tvb_captured_length_remaining(tvb, offset) >= (16 + 4)) {
        length = tvb_get_uint16(tvb, offset + 12, ENC_BIG_ENDIAN);
        root_ti = proto_tree_add_item(tree, proto_tecmp_payload, tvb, offset, (int)length + 16, ENC_NA);
        proto_item_append_text(root_ti, " Control Message");
        tecmp_tree = proto_item_add_subtree(root_ti, ett_tecmp_payload);

        offset += dissect_tecmp_entry_header(tvb, pinfo, tecmp_tree, offset, tecmp_msg_type, msg_type, true, NULL, NULL, NULL);

        col_set_str(pinfo->cinfo, COL_INFO, "TECMP Control Message");

        ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_ctrl_msg_device_id, tvb, offset, 2, ENC_BIG_ENDIAN, &device_id);
        add_device_id_text(ti, (uint16_t)device_id);
        ctrl_msg_id = tvb_get_uint16(tvb, offset + 2, ENC_BIG_ENDIAN);
        proto_tree_add_uint_format(tecmp_tree, hf_tecmp_payload_ctrl_msg_id, tvb, offset + 2, 2, ctrl_msg_id, "Type: %s", resolve_control_message_id(ctrl_msg_id));
        offset += 4;

        proto_item_append_text(root_ti, ", %s", resolve_control_message_id(ctrl_msg_id));
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", resolve_control_message_id(ctrl_msg_id));

        /* offset includes 16 byte header, while length is only for payload */
        int bytes_left = length + (unsigned)16 - (offset - offset_orig);
        if (bytes_left > 0) {
            int i;

            switch (ctrl_msg_id) {
            case TECMP_CTRL_MSG_CAN_REPLAY_FILL_LVL:
                ti = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_ctrl_msg_can_replay_fill_level_fill_level, tvb, offset, 1, ENC_NA);
                proto_item_append_text(ti, "%%");
                offset += 1;

                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_ctrl_msg_can_replay_fill_level_buffer_overflow, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_ctrl_msg_can_replay_fill_level_queue_size, tvb, offset, 1, ENC_NA);
                offset += 1;

                for (i = 0; i < bytes_left - 3; i++) {
                    uint8_t queue_level = tvb_get_uint8(tvb, offset);
                    proto_tree_add_uint_format(tecmp_tree, hf_tecmp_payload_ctrl_msg_can_replay_fill_level_queue_length, tvb, offset, 1, queue_level, "Queue %d Fill Level: %d", i, queue_level);
                    offset += 1;
                }
                offset += 1;

                break;

            case TECMP_CTRL_MSG_FR_POC_STATE:
                ti = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_ctrl_msg_flexray_poc_interface_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                add_interface_id_text_and_name(ti, interface_id, tvb, offset);
                offset += 4;

                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_ctrl_msg_flexray_poc_state, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;

            case TECMP_CTRL_MSG_10BASE_T1S:
                ti = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_ctrl_msg_10baset1s_interface_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                add_interface_id_text_and_name(ti, interface_id, tvb, offset);
                offset += 4;

                static int * const data_flags_10BASE_T1S[] = {
                    &hf_tecmp_payload_ctrl_msg_10baset1s_10m_flags_plca_enabled,
                    &hf_tecmp_payload_ctrl_msg_10baset1s_10m_flags_beacons_received,
                    NULL
                };

                proto_tree_add_bitmask(tecmp_tree, tvb, offset, hf_tecmp_payload_ctrl_msg_10baset1s_10m_flags, ett_tecmp_ctrl_message_10baset1s_flags, data_flags_10BASE_T1S, ENC_BIG_ENDIAN);
                offset += 1;

                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_ctrl_msg_10baset1s_10m_reserved, tvb, offset, 1, ENC_NA);
                offset += 1;

                static int * const events_10BASE_T1S[] = {
                    &hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_plca_empty_cycle,
                    &hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_plca_symb_missing,
                    &hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_plca_symb_detected,
                    &hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_eos_delim_error,
                    &hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_5b_decode_error,
                    NULL
                };

                proto_tree_add_bitmask(tecmp_tree, tvb, offset, hf_tecmp_payload_ctrl_msg_10baset1s_10m_events, ett_tecmp_ctrl_message_10baset1s_events_errors, events_10BASE_T1S, ENC_BIG_ENDIAN);
                offset += 2;

                break;
            }

            if (length + (unsigned)16 - (offset - offset_orig) > 0) {
                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_ctrl_msg_unparsed_bytes, tvb, offset, length + (unsigned)16 - (offset - offset_orig), ENC_NA);
            }
        }
    }

    return offset - offset_orig;
}

static int
dissect_tecmp_status_device(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset_orig, uint16_t msg_type, unsigned tecmp_msg_type) {
    proto_item *ti = NULL;
    proto_item *ti_tecmp_payload = NULL;
    proto_item *ti_tecmp_vendor_data = NULL;
    proto_item *ti_tecmp_bus = NULL;
    proto_tree *tecmp_tree = NULL;
    proto_tree *tecmp_tree_bus = NULL;
    tvbuff_t *sub_tvb = NULL;
    uint16_t length = 0;
    uint16_t vendor_data_len = 0;
    unsigned vendor_id = 0;
    unsigned device_type = 0;
    unsigned offset = offset_orig;
    unsigned i = 0;
    unsigned tmp = 0;
    const char *descr;
    uint64_t timestamp_ns;

    if (tvb_captured_length_remaining(tvb, offset) >= 12) {
        length = tvb_get_uint16(tvb, offset + 12, ENC_BIG_ENDIAN);
        ti_tecmp_payload = proto_tree_add_item(tree, proto_tecmp_payload, tvb, offset, (int)length + 16, ENC_NA);
        tecmp_tree = proto_item_add_subtree(ti_tecmp_payload, ett_tecmp_payload);

        offset += dissect_tecmp_entry_header(tvb, pinfo, tecmp_tree, offset, tecmp_msg_type, msg_type, true, NULL, NULL, &timestamp_ns);

        proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_status_vendor_id, tvb, offset, 1, ENC_NA, &vendor_id);
        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_dev_version, tvb, offset + 1, 1, ENC_NA);
        proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_status_dev_type, tvb, offset + 2, 1, ENC_NA, &device_type);
        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_res, tvb, offset + 3, 1, ENC_NA);
        offset += 4;

        proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_status_length_vendor_data, tvb, offset, 2, ENC_BIG_ENDIAN, &tmp);
        vendor_data_len = (uint16_t)tmp;
        ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_status_device_id, tvb, offset + 2, 2, ENC_BIG_ENDIAN, &tmp);
        add_device_id_text(ti, (uint16_t)tmp);
        offset += 4;

        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_sn, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        switch (tecmp_msg_type) {
        case TECMP_MSG_TYPE_STATUS_DEV:
            col_set_str(pinfo->cinfo, COL_INFO, "TECMP Status Device");
            proto_item_append_text(ti_tecmp_payload, " Status Device");

            if (vendor_data_len > 0) {
                sub_tvb = tvb_new_subset_length(tvb, offset, (int)vendor_data_len);
                ti_tecmp_vendor_data = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_vendor_data, tvb, offset, (int)vendor_data_len, ENC_NA);

                dissect_tecmp_status_device_vendor_data(sub_tvb, pinfo, ti_tecmp_vendor_data, (uint8_t)device_type, (uint8_t)vendor_id, timestamp_ns);
                offset += vendor_data_len;
            }
            break;

        case TECMP_MSG_TYPE_STATUS_BUS:
            col_set_str(pinfo->cinfo, COL_INFO, "TECMP Status Bus");
            proto_item_append_text(ti_tecmp_payload, " Status Bus");

            /* bytes left - entry header (16 bytes) */
            length = length - (uint16_t)(offset - offset_orig - 16);

            ti_tecmp_bus = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_bus_data, tvb, offset, length, ENC_NA);
            tecmp_tree = proto_item_add_subtree(ti_tecmp_bus, ett_tecmp_status_bus_data);
            i = 1; /* we start the numbering of the entries with 1. */
            while (length >= (12 + vendor_data_len)) {
                ti_tecmp_bus = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_bus_data_entry, tvb, offset, 12 + vendor_data_len, ENC_NA);
                proto_item_append_text(ti_tecmp_bus, " %d", i);
                tecmp_tree_bus = proto_item_add_subtree(ti_tecmp_bus, ett_tecmp_status_bus_data_entry);

                ti = proto_tree_add_item_ret_uint(tecmp_tree_bus, hf_tecmp_payload_status_bus_interface_id, tvb, offset, 4, ENC_NA, &tmp);
                descr = ht_interface_config_to_string(tmp);
                if (descr != NULL) {
                    proto_item_append_text(ti, " (%s)", descr);
                    proto_item_append_text(ti_tecmp_bus, ": (Interface ID: 0x%08x, %s)", tmp, descr);
                } else {
                    proto_item_append_text(ti_tecmp_bus, ": (Interface ID: 0x%08x)", tmp);
                }

                proto_tree_add_item(tecmp_tree_bus, hf_tecmp_payload_status_bus_total, tvb, offset + 4, 4, ENC_NA);
                proto_tree_add_item(tecmp_tree_bus, hf_tecmp_payload_status_bus_errors, tvb, offset + 8, 4, ENC_NA);
                offset += 12;

                if (vendor_data_len > 0) {
                    sub_tvb = tvb_new_subset_length(tvb, offset, (int)vendor_data_len);
                    ti_tecmp_vendor_data = proto_tree_add_item(tecmp_tree_bus, hf_tecmp_payload_status_vendor_data,
                                                               tvb, offset, (int)vendor_data_len, ENC_NA);

                    dissect_tecmp_status_bus_vendor_data(sub_tvb, pinfo, ti_tecmp_vendor_data, i, (uint8_t)device_type, (uint8_t)vendor_id);
                    offset += vendor_data_len;
                }

                i++;
                length -= (12 + vendor_data_len);
            }
            break;

        case TECMP_MSG_TYPE_CFG_CM:
            col_set_str(pinfo->cinfo, COL_INFO, "TECMP Status Configuration");
            proto_item_append_text(ti_tecmp_payload, " Status Configuration");

            if (vendor_data_len > 0) {
                sub_tvb = tvb_new_subset_length(tvb, offset, (int)vendor_data_len);
                ti_tecmp_vendor_data = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_status_vendor_data, tvb,
                                                           offset, (int)vendor_data_len, ENC_NA);

                dissect_tecmp_status_config_vendor_data(sub_tvb, pinfo, ti_tecmp_vendor_data, (uint8_t)device_type, (uint8_t)vendor_id);
                offset += vendor_data_len;
            }
            break;

        default:
            proto_item_append_text(ti_tecmp_payload, " Status Device");
        }

    } else {
        return tvb_captured_length_remaining(tvb, offset);
    }

    return offset - offset_orig;
}

static int
dissect_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint16_t device_id, uint8_t msg_type, uint16_t data_type, uint32_t interface_id) {
    tecmp_info_t tecmp_info;
    int          dissected_bytes;

    tecmp_info.interface_id = interface_id;
    tecmp_info.device_id = device_id;
    tecmp_info.data_type = data_type;
    tecmp_info.msg_type = msg_type;


    dissector_handle_t handle = dissector_get_uint_handle(data_subdissector_table, interface_id);
    if (handle != NULL) {
        dissected_bytes = call_dissector_only(handle, tvb, pinfo, tree, &tecmp_info);
        if (dissected_bytes > 0) {
            return dissected_bytes;
        }
    }

    if (tecmp_info.data_type == TECMP_DATA_TYPE_RS232_ASCII) {
        return call_dissector(text_lines_handle, tvb, pinfo, tree);
    } else {
        return call_data_dissector(tvb, pinfo, tree);
    }
}

static int
dissect_tecmp_log_or_replay_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset_orig,
                                   uint16_t data_type, uint8_t tecmp_msg_type, uint16_t device_id) {
    proto_item *ti = NULL;
    proto_item *ti_tecmp = NULL;
    proto_tree *tecmp_tree = NULL;
    uint16_t length = 0;
    uint32_t length2 = 0;
    unsigned offset = offset_orig;
    unsigned offset2 = 0;
    uint16_t dataflags = 0;
    uint32_t tmp = 0;
    tvbuff_t *sub_tvb;
    tvbuff_t *payload_tvb;
    bool first = true;
    uint32_t interface_id = 0;
    uint64_t timestamp_ns = 0;

    double analog_value_scale_factor;

    struct can_info can_info;
    flexray_info_t fr_info;
    lin_info_t lin_info;

    static int * const tecmp_payload_id_flags_can_11[] = {
        &hf_tecmp_payload_data_id_type,
        &hf_tecmp_payload_data_id_11,
        NULL
    };

    static int * const tecmp_payload_id_flags_can_29[] = {
        &hf_tecmp_payload_data_id_type,
        &hf_tecmp_payload_data_id_29,
        NULL
    };

    static int * const tecmp_payload_id_flags_lin[] = {
        &hf_tecmp_payload_data_parity_bits,
        &hf_tecmp_payload_data_id_field_6bit,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_INFO, "TECMP Payload: ");

    while (tvb_captured_length_remaining(tvb, offset) >= 16) {

        if (!tecmp_entry_header_present(tvb, offset)) {
            /* header not valid, we leave */
            break;
        }

        length = tvb_get_uint16(tvb, offset+12, ENC_BIG_ENDIAN);
        ti_tecmp = proto_tree_add_item(tree, proto_tecmp_payload, tvb, offset, (int)length + 16, ENC_NA);
        proto_item_append_text(ti_tecmp, " (%s)", val_to_str(data_type, tecmp_msgtype_names, "Unknown (%d)"));
        tecmp_tree = proto_item_add_subtree(ti_tecmp, ett_tecmp_payload);

        offset += dissect_tecmp_entry_header(tvb, pinfo, tecmp_tree, offset, tecmp_msg_type, data_type, first, &dataflags, &interface_id, &timestamp_ns);

        first = false;

        if (length > 0) {
            sub_tvb = tvb_new_subset_length(tvb, offset, (int)length);
            offset2 = 0;

            switch (data_type) {
            case TECMP_DATA_TYPE_LIN:
                lin_info.id = tvb_get_uint8(sub_tvb, offset2) & DATA_LIN_ID_MASK;

                proto_tree_add_bitmask(tecmp_tree, sub_tvb, offset2, hf_tecmp_payload_data_id_field_8bit, ett_tecmp_payload_lin_id, tecmp_payload_id_flags_lin, ENC_BIG_ENDIAN);
                lin_info.bus_id = ht_interface_config_to_bus_id(interface_id);
                ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_data_length, sub_tvb, offset2 + 1, 1, ENC_NA, &length2);
                offset2 += 2;

                lin_set_source_and_destination_columns(pinfo, &lin_info);

                if (length2 > 0 && tvb_captured_length_remaining(sub_tvb, offset2) < (int)(length2 + 1)) {
                    expert_add_info(pinfo, ti, &ei_tecmp_payload_length_mismatch);
                    length2 = MAX(0, MIN((int)length2, tvb_captured_length_remaining(sub_tvb, offset2) - 1));
                }

                if (length2 > 0) {
                    lin_info.len = tvb_captured_length_remaining(sub_tvb, offset2);
                    payload_tvb = tvb_new_subset_length(sub_tvb, offset2, length2);
                    uint32_t bus_frame_id = lin_info.id | (lin_info.bus_id << 16);
                    if (!dissector_try_uint_new(lin_subdissector_table, bus_frame_id, payload_tvb, pinfo, tree, false, &lin_info)) {
                        if (!dissector_try_uint_new(lin_subdissector_table, lin_info.id, payload_tvb, pinfo, tree, false, &lin_info)) {
                            dissect_data(payload_tvb, pinfo, tree, device_id, tecmp_msg_type, data_type, interface_id);
                        }
                    }
                    offset2 += (int)length2;
                    proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_checksum_8bit, sub_tvb, offset2, 1, ENC_NA);
                }

                break;

            case TECMP_DATA_TYPE_CAN_DATA:
            case TECMP_DATA_TYPE_CAN_FD_DATA:
                tmp = tvb_get_uint32(sub_tvb, offset2, ENC_BIG_ENDIAN);
                if ((tmp & 0x80000000) == 0x80000000) {
                    proto_tree_add_bitmask_with_flags(tecmp_tree, sub_tvb, offset2, hf_tecmp_payload_data_id_field_32bit,
                        ett_tecmp_payload_data_id, tecmp_payload_id_flags_can_29, ENC_BIG_ENDIAN, BMT_NO_APPEND);
                } else {
                    proto_tree_add_bitmask_with_flags(tecmp_tree, sub_tvb, offset2, hf_tecmp_payload_data_id_field_32bit,
                        ett_tecmp_payload_data_id, tecmp_payload_id_flags_can_11, ENC_BIG_ENDIAN, BMT_NO_APPEND);
                }
                ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_data_length, sub_tvb, offset2 + 4, 1, ENC_NA,
                                                  &length2);
                offset2 += 5;

                if (tvb_captured_length_remaining(sub_tvb, offset2) < (int)length2) {
                    expert_add_info(pinfo, ti, &ei_tecmp_payload_length_mismatch);
                    length2 = MAX(0, MIN((int)length2, tvb_captured_length_remaining(sub_tvb, offset2)));
                }

                if (length2 > 0) {
                    payload_tvb = tvb_new_subset_length(sub_tvb, offset2, length2);
                    offset2 += length2;

                    can_info.fd = (data_type == TECMP_DATA_TYPE_CAN_FD_DATA) ? CAN_TYPE_CAN_FD : CAN_TYPE_CAN_CLASSIC;
                    can_info.len = length2;
                    can_info.bus_id = ht_interface_config_to_bus_id(interface_id);

                    /* luckily TECMP and SocketCAN share the first bit as indicator for 11 vs 29bit Identifiers */
                    can_info.id = tmp;

                    if (data_type == TECMP_DATA_TYPE_CAN_DATA && (dataflags & DATA_FLAG_CAN_RTR) == DATA_FLAG_CAN_RTR) {
                        can_info.id |= CAN_RTR_FLAG;
                    }

                    if ((dataflags & DATA_FLAG_CAN_ERR) == DATA_FLAG_CAN_ERR) {
                        can_info.id |= CAN_ERR_FLAG;
                    }

                    socketcan_set_source_and_destination_columns(pinfo, &can_info);

                    if (!socketcan_call_subdissectors(payload_tvb, pinfo, tree, &can_info, heuristic_first)) {
                        dissect_data(payload_tvb, pinfo, tree, device_id, tecmp_msg_type, data_type, interface_id);
                    }
                }

                /* new for TECMP 1.6 */
                if (data_type == TECMP_DATA_TYPE_CAN_DATA && tvb_captured_length_remaining(sub_tvb, offset2) >= 2) {
                    proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_crc15, sub_tvb, offset2, 2, ENC_BIG_ENDIAN);
                } else if (data_type == TECMP_DATA_TYPE_CAN_FD_DATA && tvb_captured_length_remaining(sub_tvb, offset2) >= 3) {
                    if (length2 <= 16) {
                        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_crc17, sub_tvb, offset2, 3, ENC_BIG_ENDIAN);
                    } else {
                        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_crc21, sub_tvb, offset2, 3, ENC_BIG_ENDIAN);
                    }
                }
                break;

            case TECMP_DATA_TYPE_FR_DATA:
                /* lets set it based on config */
                fr_info.bus_id = ht_interface_config_to_bus_id(interface_id);

                /* we assume "FlexRay Channel A" since we cannot know */
                fr_info.ch = 0;

                proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_data_cycle, sub_tvb, offset2, 1, ENC_NA, &tmp);
                fr_info.cc = (uint8_t)tmp;

                proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_data_frame_id, sub_tvb, offset2 + 1, 2, ENC_NA, &tmp);
                fr_info.id = (uint16_t)tmp;

                ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_data_length, sub_tvb, offset2 + 3, 1, ENC_NA, &length2);
                offset2 += 4;

                flexray_set_source_and_destination_columns(pinfo, &fr_info);

                if (tvb_captured_length_remaining(sub_tvb, offset2) < (int)length2) {
                    expert_add_info(pinfo, ti, &ei_tecmp_payload_length_mismatch);
                    length2 = MAX(0, MIN((int)length2, tvb_captured_length_remaining(sub_tvb, offset2)));
                }

                if (length2 > 0) {
                    payload_tvb = tvb_new_subset_length(sub_tvb, offset2, length2);
                    offset2 += length2;

                    if ((dataflags & DATA_FLAG_FR_NF) != 0 || !flexray_call_subdissectors(payload_tvb, pinfo, tree, &fr_info, heuristic_first)) {
                        dissect_data(payload_tvb, pinfo, tree, device_id, tecmp_msg_type, data_type, interface_id);
                    }
                }

                /* new for TECMP 1.6 */
                if (tvb_captured_length_remaining(sub_tvb, offset2) >= 5) {
                    uint32_t header_crc = 0;
                    ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_data_header_crc, sub_tvb, offset2, 2, ENC_BIG_ENDIAN, &header_crc);
                    if (header_crc > DATA_FR_HEADER_CRC_MAX) {
                        expert_add_info(pinfo, ti, &ei_tecmp_payload_header_crc_overflow);
                    }
                    offset2 += 2;
                    proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_frame_crc, sub_tvb, offset2, 3, ENC_BIG_ENDIAN);
                }
                break;

            case TECMP_DATA_TYPE_ILAS:
                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_ilas_decoded_command, sub_tvb, offset2, 1, ENC_NA);
                offset2 += 1;
                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_ilas_decoded_address, sub_tvb, offset2, 2, ENC_BIG_ENDIAN);
                offset2 += 2;
                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_ilas_decoded_data, sub_tvb, offset2, 3, ENC_NA);
                offset2 += 3;
                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_ilas_raw_sdu, sub_tvb, offset2, 7, ENC_NA);
                offset2 += 7;
                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_ilas_raw_crc, sub_tvb, offset2, 2, ENC_BIG_ENDIAN);
                break;

            case TECMP_DATA_TYPE_RS232_ASCII:
                dissect_data(sub_tvb, pinfo, tree, device_id, tecmp_msg_type, data_type, interface_id);
                break;

            case TECMP_DATA_TYPE_ANALOG:
                ti_tecmp = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data, sub_tvb, offset2, length, ENC_NA);
                tecmp_tree = proto_item_add_subtree(ti_tecmp, ett_tecmp_payload_data);

                analog_value_scale_factor = tecmp_payload_analog_scale_factor_values[((dataflags & TECMP_DATAFLAGS_FACTOR_MASK) >> TECMP_DATAFLAGS_FACTOR_SHIFT)];

                tmp = offset2 + length;
                while (offset2 + 2 <= tmp) {
                    double scaled_value;

                    if (analog_samples_are_signed_int) {
                        scaled_value = analog_value_scale_factor * tvb_get_int16(sub_tvb, offset2, ENC_BIG_ENDIAN);
                    } else {
                        scaled_value = analog_value_scale_factor * tvb_get_uint16(sub_tvb, offset2, ENC_BIG_ENDIAN);
                    }

                    switch ((dataflags & TECMP_DATAFLAGS_UNIT_MASK) >> TECMP_DATAFLAGS_UNIT_SHIFT) {
                    case 0x0:
                        proto_tree_add_double(tecmp_tree, hf_tecmp_payload_data_analog_value_volt, sub_tvb, offset2, 2, scaled_value);
                        break;
                    case 0x01:
                        proto_tree_add_double(tecmp_tree, hf_tecmp_payload_data_analog_value_amp, sub_tvb, offset2, 2, scaled_value);
                        break;
                    case 0x02:
                        proto_tree_add_double(tecmp_tree, hf_tecmp_payload_data_analog_value_watt, sub_tvb, offset2, 2, scaled_value);
                        break;
                    case 0x03:
                        proto_tree_add_double(tecmp_tree, hf_tecmp_payload_data_analog_value_amp_hour, sub_tvb, offset2, 2, scaled_value);
                        break;
                    case 0x04:
                        proto_tree_add_double(tecmp_tree, hf_tecmp_payload_data_analog_value_celsius, sub_tvb, offset2, 2, scaled_value);
                        break;
                    default:
                        if (analog_samples_are_signed_int) {
                            ti = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_analog_value_raw_signed, sub_tvb, offset2, 2, ENC_BIG_ENDIAN);
                        } else {
                            ti = proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data_analog_value_raw, sub_tvb, offset2, 2, ENC_BIG_ENDIAN);
                        }
                        proto_item_append_text(ti, "%s", " (raw)");
                    }
                    offset2 += 2;
                }
                break;

            case TECMP_DATA_TYPE_ETH_10BASE_T1S:
            case TECMP_DATA_TYPE_ETH:
            {
                length2 = length;

                if (data_type == TECMP_DATA_TYPE_ETH_10BASE_T1S) {
                    uint64_t ns = tvb_get_uint64(sub_tvb, offset2, ENC_BIG_ENDIAN);

                    nstime_t timestamp;
                    timestamp.secs = (time_t)(ns / 1000000000);
                    timestamp.nsecs = (int)(ns % 1000000000);
                    proto_tree_add_time(tecmp_tree, hf_tecmp_payload_data_beacon_timestamp, sub_tvb, offset2, 8, &timestamp);
                    ti = proto_tree_add_uint64(tecmp_tree, hf_tecmp_payload_data_beacon_timestamp_ns, sub_tvb, offset2, 8, ns);
                    proto_item_set_hidden(ti);

                    ti = proto_tree_add_int64(tecmp_tree, hf_tecmp_payload_data_beacon_to_timestamp_ns, sub_tvb, offset2, 8, (int64_t)timestamp_ns - (int64_t)ns);
                    proto_item_set_generated(ti);
                    proto_item_set_hidden(ti);

                    offset2 += 8;
                    length2 -= 8;
                }

                payload_tvb = tvb_new_subset_length(sub_tvb, offset2, length2);

                /* resetting VLAN count since this is another embedded Ethernet packet. */
                p_set_proto_depth(pinfo, proto_vlan, 0);

                int len_saved = pinfo->fd->pkt_len;
                pinfo->fd->pkt_len = length2;

                if (show_ethernet_in_tecmp_tree) {
                    call_dissector(eth_handle, payload_tvb, pinfo, tecmp_tree);
                } else {
                    call_dissector(eth_handle, payload_tvb, pinfo, tree);
                }

                pinfo->fd->pkt_len = len_saved;
            }
                break;

            default:
                proto_tree_add_item(tecmp_tree, hf_tecmp_payload_data, sub_tvb, 0, length, ENC_NA);
            }

            offset += length;
        }
    }

    return offset - offset_orig;
}

static int
dissect_tecmp_counter_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset_orig, uint16_t data_type, unsigned tecmp_msg_type) {
    proto_item *ti = NULL;
    proto_tree *tecmp_tree = NULL;
    uint16_t length = 0;
    unsigned offset = offset_orig;
    unsigned tmp = 0;

    if (tvb_captured_length_remaining(tvb, offset) >= (16 + 8)) {
        length = tvb_get_uint16(tvb, offset + 12, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(tree, proto_tecmp_payload, tvb, offset, (int)length + 16, ENC_NA);
        proto_item_append_text(ti, " Counter Event");
        tecmp_tree = proto_item_add_subtree(ti, ett_tecmp_payload);

        offset += dissect_tecmp_entry_header(tvb, pinfo, tecmp_tree, offset, tecmp_msg_type, data_type, true, NULL, NULL, NULL);

        col_set_str(pinfo->cinfo, COL_INFO, "TECMP Counter Event");

        ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_counter_event_device_id, tvb, offset, 2, ENC_BIG_ENDIAN, &tmp);
        add_device_id_text(ti, (uint16_t)tmp);
        offset += 2;

        ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_counter_event_interface_id, tvb, offset, 2, ENC_BIG_ENDIAN, &tmp);
        add_interface_id_text_and_name(ti, tmp, tvb, offset);
        offset += 2;

        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_counter_event_counter_last, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_counter_event_counter_cur, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    return offset - offset_orig;
}

static int
dissect_tecmp_timesync_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset_orig, uint16_t data_type, unsigned tecmp_msg_type) {
    proto_item *ti = NULL;
    proto_tree *tecmp_tree = NULL;
    uint16_t length = 0;
    unsigned offset = offset_orig;
    unsigned tmp = 0;

    if (tvb_captured_length_remaining(tvb, offset) >= (16 + 8)) {
        length = tvb_get_uint16(tvb, offset + 12, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(tree, proto_tecmp_payload, tvb, offset, (int)length + 16, ENC_NA);
        proto_item_append_text(ti, " TimeSync Event");
        tecmp_tree = proto_item_add_subtree(ti, ett_tecmp_payload);

        offset += dissect_tecmp_entry_header(tvb, pinfo, tecmp_tree, offset, tecmp_msg_type, data_type, true, NULL, NULL, NULL);

        col_set_str(pinfo->cinfo, COL_INFO, "TECMP TimeSync Event");

        ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_timesync_event_device_id, tvb, offset, 2, ENC_BIG_ENDIAN, &tmp);
        add_device_id_text(ti, (uint16_t)tmp);
        offset += 2;

        ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_payload_timesync_event_interface_id, tvb, offset, 2, ENC_BIG_ENDIAN, &tmp);
        add_interface_id_text_and_name(ti, tmp, tvb, offset);
        offset += 2;

        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_timesync_event_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_timesync_event_async, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tecmp_tree, hf_tecmp_payload_timesync_event_time_delta, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    return offset - offset_orig;
}

static int
dissect_tecmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_item *ti = NULL;
    proto_item *ti_root = NULL;
    proto_tree *tecmp_tree = NULL;
    unsigned offset = 0;
    unsigned tecmp_type = 0;
    unsigned data_type = 0;
    unsigned device_id = 0;

    static int * const tecmp_flags[] = {
        &hf_tecmp_flags_eos,
        &hf_tecmp_flags_sos,
        &hf_tecmp_flags_spy,
        &hf_tecmp_flags_multi_frame,
        &hf_tecmp_flags_dev_overflow,
        NULL
    };

    /* ASAM CMP is the successor of TECMP and uses the same EtherType.
     *
     * How to detect what the message is:
     * The first byte in TECMP 1.7 and later is always 0.
     * The first byte in TECMP 1.6 and older allowed 0xff for user-defined IDs.
     * The first byte in ASAM CMP is defined as version and is required to be > 0.
     * If the first byte is not 0, we pass it be ASAM CMP.
     * For backward compatibility: If 0xff allow as TECMP.
     */
    if ( (detect_asam_cmp && asam_cmp_handle != 0 && tvb_get_uint8(tvb, offset) != 0) &&
         (!detect_asam_cmp_ignore_user_defined || tvb_get_uint8(tvb, offset) != 0xff) ) {
        return call_dissector_with_data(asam_cmp_handle, tvb, pinfo, tree, data);
    }

    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TECMP");
    ti_root = proto_tree_add_item(tree, proto_tecmp, tvb, 0, -1, ENC_NA);
    tecmp_tree = proto_item_add_subtree(ti_root, ett_tecmp);

    if (!proto_field_is_referenced(tree, proto_tecmp)) {
        tecmp_tree = NULL;
    }

    ti = proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_device_id, tvb, offset, 2, ENC_BIG_ENDIAN, &device_id);
    add_device_id_text(ti, (uint16_t)device_id);
    offset += 2;

    proto_tree_add_item(tecmp_tree, hf_tecmp_counter, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tecmp_tree, hf_tecmp_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_msgtype, tvb, offset, 1, ENC_NA, &tecmp_type);
    offset += 1;

    proto_tree_add_item_ret_uint(tecmp_tree, hf_tecmp_data_type, tvb, offset, 2, ENC_BIG_ENDIAN, &data_type);
    offset += 2;

    proto_tree_add_item(tecmp_tree, hf_tecmp_res, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask(tecmp_tree, tvb, offset, hf_tecmp_flags, ett_tecmp_flags, tecmp_flags,
                           ENC_BIG_ENDIAN);
    offset += 2;

    switch (tecmp_type) {
    case TECMP_MSG_TYPE_CTRL_MSG:
        offset += dissect_tecmp_control_msg(tvb, pinfo, tree, offset, (uint16_t)data_type, (uint8_t)tecmp_type);
        break;

    case TECMP_MSG_TYPE_STATUS_BUS:
    case TECMP_MSG_TYPE_CFG_CM:
    case TECMP_MSG_TYPE_STATUS_DEV:
        offset += dissect_tecmp_status_device(tvb, pinfo, tree, offset, (uint16_t)data_type, (uint8_t)tecmp_type);
        break;

    case TECMP_MSG_TYPE_LOG_STREAM:
    case TECMP_MSG_TYPE_REPLAY_DATA:
        offset += dissect_tecmp_log_or_replay_stream(tvb, pinfo, tree, offset, (uint16_t)data_type, (uint8_t)tecmp_type, (uint16_t)device_id);
        break;

    case TECMP_MSG_TYPE_COUNTER_EVENT:
        offset += dissect_tecmp_counter_event(tvb, pinfo, tree, offset, (uint16_t)data_type, (uint8_t)tecmp_type);
        break;

    case TECMP_MSG_TYPE_TIMESYNC_EVENT:
        offset += dissect_tecmp_timesync_event(tvb, pinfo, tree, offset, (uint16_t)data_type, (uint8_t)tecmp_type);
        break;

    }

    proto_item_set_end(ti_root, tvb, offset);
    return offset;
}

void
proto_register_tecmp_payload(void) {
    expert_module_t *expert_module_tecmp_payload;

    static hf_register_info hf[] = {
        { &hf_tecmp_payload_interface_id,
            { "Interface ID", "tecmp.payload.interface_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_interface_name,
            { "Interface Name", "tecmp.payload.interface_name",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_timestamp,
            { "Timestamp", "tecmp.payload.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_timestamp_async,
            { "Timestamp Synchronisation Status", "tecmp.payload.timestamp_synch_status",
            FT_BOOLEAN, 8, TFS(&tfs_tecmp_payload_timestamp_async_type), 0x80, NULL, HFILL }},
        { &hf_tecmp_payload_timestamp_res,
            { "Timestamp Synchronisation reserved", "tecmp.payload.timestamp_reserved",
            FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
        { &hf_tecmp_payload_timestamp_ns,
            { "Timestamp ns", "tecmp.payload.timestamp_ns",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tecmp_payload_length,
            { "Length", "tecmp.payload.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data,
            { "Data", "tecmp.payload.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tecmp_payload_data_beacon_timestamp,
            { "Beacon Timestamp", "tecmp.payload.beacon_timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_beacon_timestamp_ns,
            { "Beacon Timestamp ns", "tecmp.payload.beacon_timestamp_ns",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_beacon_to_timestamp_ns,
            { "Beacon to Timestamp ns", "tecmp.payload.beacon_to_timestamp_ns",
            FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_id_field_8bit,
            { "ID", "tecmp.payload.data.lin_id_with_parity",
            FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_id_field_6bit,
            { "LIN ID", "tecmp.payload.data.lin_id",
            FT_UINT8, BASE_HEX_DEC, NULL, DATA_LIN_ID_MASK, NULL, HFILL }},
        { &hf_tecmp_payload_data_parity_bits,
            { "Parity Bits", "tecmp.payload.data.lin_parity_bits",
            FT_UINT8, BASE_HEX_DEC, NULL, 0xc0, NULL, HFILL }},
        { &hf_tecmp_payload_data_checksum_8bit,
            { "Checksum", "tecmp.payload.data.checksum",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_tecmp_payload_data_id_field_32bit,
            { "ID Field", "tecmp.payload.data.can_id_field",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_id_type,
            { "CAN ID Type", "tecmp.payload.data.can_id_type",
            FT_BOOLEAN, 32, TFS(&tfs_tecmp_payload_data_id_type), 0x80000000, NULL, HFILL }},
        { &hf_tecmp_payload_data_id_11,
            { "ID (11bit)", "tecmp.payload.data.can_id_11",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x000007FF, NULL, HFILL }},
        { &hf_tecmp_payload_data_id_29,
            { "ID (29bit)", "tecmp.payload.data.can_id_29",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x1FFFFFFF, NULL, HFILL }},
        { &hf_tecmp_payload_data_crc15,
            { "CRC15", "tecmp.payload.data.crc15",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_crc17,
            { "CRC17", "tecmp.payload.data.crc17",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_crc21,
            { "CRC21", "tecmp.payload.data.crc21",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_tecmp_payload_data_cycle,
            { "Cycle", "tecmp.payload.data.cycle",
            FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_frame_id,
            { "Frame ID", "tecmp.payload.data.frame_id",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_header_crc,
            { "Header CRC", "tecmp.payload.data.header_crc",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_frame_crc,
            { "Frame CRC", "tecmp.payload.data.frame_crc",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_tecmp_payload_data_length,
            { "Payload Length", "tecmp.payload.data.payload_length",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tecmp_payload_data_flags,
            { "Data Flags", "tecmp.payload.data_flags",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_crc,
            { "CRC Error", "tecmp.payload.data_flags.crc_error",
            FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_checksum,
            { "Checksum Error", "tecmp.payload.data_flags.checksum_error",
            FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_tx,
            { "TX (sent by Device)", "tecmp.payload.data_flags.tx",
            FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_overflow,
            { "Overflow (lost data)", "tecmp.payload.data_flags.Overflow",
            FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL }},

        /* Control Message */
        { &hf_tecmp_payload_ctrl_msg_device_id,
            { "Device ID", "tecmp.payload.ctrl_msg.device_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_ctrl_msg_id,
            { "Control Message ID", "tecmp.payload.ctrl_msg.id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_ctrl_msg_unparsed_bytes,
            { "Unparsed Bytes", "tecmp.payload.ctrl_msg.unparsed",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        /* Control Message: CAN Replay Fill Level */
        { &hf_tecmp_payload_ctrl_msg_can_replay_fill_level_fill_level,
            { "Fill Level RAM", "tecmp.payload.ctrl_msg.can_replay_fill_level.fill_level_ram",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_ctrl_msg_can_replay_fill_level_buffer_overflow,
            { "Buffer Overflow RAM", "tecmp.payload.ctrl_msg.can_replay_fill_level.buffer_overflow_ram",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_ctrl_msg_can_replay_fill_level_queue_size,
            { "Queue Size", "tecmp.payload.ctrl_msg.can_replay_fill_level.queue_size",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_ctrl_msg_can_replay_fill_level_queue_length,
            { "Queue Fill Level", "tecmp.payload.ctrl_msg.can_replay_fill_level.queue_fill_level",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* Control Message: FlexRay POC State */
        { &hf_tecmp_payload_ctrl_msg_flexray_poc_interface_id,
            { "Interface ID", "tecmp.payload.ctrl_msg.flexray_poc.interface_id",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_ctrl_msg_flexray_poc_state,
            { "Protocol Operation Control State", "tecmp.payload.ctrl_msg.flexray_poc.state",
            FT_UINT8, BASE_DEC, VALS(tecmp_ctrl_msg_fr_poc_state), 0x0, NULL, HFILL } },

        /* Control Message: 10BASE-T1S */
        { &hf_tecmp_payload_ctrl_msg_10baset1s_interface_id,
            { "Interface ID", "tecmp.payload.ctrl_msg.10baset1s.interface_id",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_ctrl_msg_10baset1s_10m_flags,
            { "Flags", "tecmp.payload.ctrl_msg.10baset1s.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_ctrl_msg_10baset1s_10m_flags_beacons_received,
            { "Beacons Received", "tecmp.payload.ctrl_msg.10baset1s.flags.beacons_received",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL } },
        { &hf_tecmp_payload_ctrl_msg_10baset1s_10m_flags_plca_enabled,
            { "PLCA Enabled", "tecmp.payload.ctrl_msg.10baset1s.flags.plca_enabled",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL } },
        { &hf_tecmp_payload_ctrl_msg_10baset1s_10m_reserved,
            { "Reserved", "tecmp.payload.ctrl_msg.10baset1s.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
            { &hf_tecmp_payload_ctrl_msg_10baset1s_10m_events,
            { "Events/Errors", "tecmp.payload.ctrl_msg.10baset1s.events",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_5b_decode_error,
            { "5B Decode Error", "tecmp.payload.ctrl_msg.10baset1s.events.5b_decode_error",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0001, NULL, HFILL } },
        { &hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_eos_delim_error,
            { "End of Stream Delimiter Error", "tecmp.payload.ctrl_msg.10baset1s.events.end_of_stream_delimiter_error",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0002, NULL, HFILL } },
        { &hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_plca_symb_detected,
            { "PLCA Symbols Detected", "tecmp.payload.ctrl_msg.10baset1s.events.plca_symbols_detected",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0004, NULL, HFILL } },
        { &hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_plca_symb_missing,
            { "PLCA Symbols Missing", "tecmp.payload.ctrl_msg.10baset1s.events.plca_symbols_missing",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0008, NULL, HFILL } },
        { &hf_tecmp_payload_ctrl_msg_10baset1s_10m_events_plca_empty_cycle,
            { "PLCA Empty Cycle", "tecmp.payload.ctrl_msg.10baset1s.events.plca_empty_cycle",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0010, NULL, HFILL } },

        /* Status Device / Status Bus / Status Configuration */
        { &hf_tecmp_payload_status_vendor_id,
            { "Vendor ID", "tecmp.payload.status.vendor_id",
            FT_UINT8, BASE_HEX, VALS(tecmp_vendor_ids), 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_dev_version,
            { "Device Version", "tecmp.payload.status.device_version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_dev_type,
            { "Device Type", "tecmp.payload.status.device_type",
            FT_UINT8, BASE_HEX, VALS(tecmp_device_types), 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_res,
            { "Reserved", "tecmp.payload.status.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_length_vendor_data,
            { "Length of Vendor Data", "tecmp.payload.status.vdata_len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_device_id,
            { "Device ID", "tecmp.payload.status.device_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_sn,
            { "Serial Number", "tecmp.payload.status.sn",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_vendor_data,
            { "Vendor Data", "tecmp.payload.status.vendor_data",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_data,
            { "Bus Data", "tecmp.payload.status.bus_data",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_data_entry,
            { "Bus Data Entry", "tecmp.payload.status.bus_data_entry",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_interface_id,
            { "Interface ID", "tecmp.payload.status.bus.interface_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_total,
            { "Messages Total", "tecmp.payload.status.bus.total",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_errors,
            { "Errors Total", "tecmp.payload.status.bus.errors",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* Status Device Vendor Data */
        { &hf_tecmp_payload_status_dev_vendor_technica_res,
            { "Reserved", "tecmp.payload.status_dev.vendor_technica.res",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_dev_vendor_technica_sw,
            { "Software Version", "tecmp.payload.status_dev.vendor_technica.sw_version",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_dev_vendor_technica_hw,
            { "Hardware Version", "tecmp.payload.status_dev.vendor_technica.hw_version",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_dev_vendor_technica_buffer_fill_level,
            { "Buffer Fill Level", "tecmp.payload.status_dev.vendor_technica.buffer_fill_level",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_dev_vendor_technica_buffer_overflow,
            { "Buffer Overflow", "tecmp.payload.status_dev.vendor_technica.buffer_overflow",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_tecmp_technica_bufferoverflow), 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_dev_vendor_technica_buffer_size,
            { "Buffer Size", "tecmp.payload.status_dev.vendor_technica.buffer_size",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_dev_vendor_technica_lifecycle,
            { "Lifecycle", "tecmp.payload.status_dev.vendor_technica.lifecycle",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_dev_vendor_technica_lifecycle_start,
            { "Lifecycle Start", "tecmp.payload.status_dev.vendor_technica.lifecycle.start",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_status_dev_vendor_technica_voltage,
            { "Voltage", "tecmp.payload.status_dev.vendor_technica.voltage",
            FT_DOUBLE, BASE_NONE | BASE_UNIT_STRING, &units_volt, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_status_dev_vendor_technica_temperature,
            { "Temperature", "tecmp.payload.status_dev.vendor_technica.temperature",
            FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_degree_celsius, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_dev_vendor_technica_temperature_chassis,
            { "Temperature Chassis", "tecmp.payload.status_dev.vendor_technica.temperature_chassis",
            FT_INT8, BASE_DEC | BASE_UNIT_STRING, &units_degree_celsius, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_dev_vendor_technica_temperature_silicon,
            { "Temperature Silicon", "tecmp.payload.status_dev.vendor_technica.temperature_silicon",
            FT_INT8, BASE_DEC | BASE_UNIT_STRING, &units_degree_celsius, 0x0, NULL, HFILL }},

        /* Status Bus Vendor Data */
        { &hf_tecmp_payload_status_bus_vendor_technica_link_status,
            { "Link Status", "tecmp.payload.status.bus.vendor_technica.link_status",
            FT_UINT8, BASE_DEC, VALS(tecmp_bus_status_link_status), 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_vendor_technica_link_quality,
            { "Link Quality", "tecmp.payload.status.bus.vendor_technica.link_quality",
            FT_UINT8, BASE_DEC, VALS(tecmp_bus_status_link_quality), 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_bus_vendor_technica_linkup_time,
            { "Linkup Time", "tecmp.payload.status.bus.vendor_technica.linkup_time",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tecmp_payload_status_bus_vendor_technica_10m_flags,
            { "Flags", "tecmp.payload.status.bus.vendor_technica.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_status_bus_vendor_technica_10m_flags_beacons_received,
            { "Beacons Received", "tecmp.payload.status.bus.vendor_technica.flags.beacons_received",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL } },
        { &hf_tecmp_payload_status_bus_vendor_technica_10m_flags_plca_enabled,
            { "PLCA Enabled", "tecmp.payload.status.bus.vendor_technica.flags.plca_enabled",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL } },
        { &hf_tecmp_payload_status_bus_vendor_technica_res0,
            { "Reserved", "tecmp.payload.status.bus.vendor_technica.reserved_0",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_status_bus_vendor_technica_beacon_counter,
            { "Beacon Counter", "tecmp.payload.status.bus.vendor_technica.beacon_counter",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_status_bus_vendor_technica_res1,
            { "Reserved", "tecmp.payload.status.bus.vendor_technica.reserved_1",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_status_bus_vendor_technica_res2,
            { "Reserved", "tecmp.payload.status.bus.vendor_technica.reserved_2",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_status_bus_vendor_technica_5b_decode_err_cnt,
            { "5B Decode Error Count", "tecmp.payload.status.bus.vendor_technica.5b_decode_err_count",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_status_bus_vendor_technica_eos_delim_err_cnt,
            { "End of Stream Delimiter Error Count", "tecmp.payload.status.bus.vendor_technica.eos_delim_err_count",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_status_bus_vendor_technica_plca_symbols_detected_cnt,
            { "PLCA Symbols Detected Count", "tecmp.payload.status.bus.vendor_technica.plca_symbols_detected_count",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_status_bus_vendor_technica_plca_symbols_missing_cnt,
            { "PLCA Symbols Missing Count", "tecmp.payload.status.bus.vendor_technica.plca_symbols_missing_count",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_status_bus_vendor_technica_plca_symbols_empty_cycle_cnt,
            { "PLCA Empty Cycle Count", "tecmp.payload.status.bus.vendor_technica.plca_empty_cycle_count",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* Status Config Vendor Data */
        { &hf_tecmp_payload_status_cfg_vendor_technica_version,
            { "Version", "tecmp.payload.status.config.vendor_technica.version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_reserved,
            { "Reserved", "tecmp.payload.status.config.vendor_technica.res",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_msg_id,
            { "Message ID", "tecmp.payload.status.config.vendor_technica.message_id",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_total_length,
            { "Total Length", "tecmp.payload.status.config.vendor_technica.total_length",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_total_num_seg,
            { "Total Number of Segments", "tecmp.payload.status.config.vendor_technica.total_number_segments",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_segment_num,
            { "Segment Number", "tecmp.payload.status.config.vendor_technica.segment_number",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_segment_length,
            { "Segment Length", "tecmp.payload.status.config.vendor_technica.segment_length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_status_cfg_vendor_technica_segment_data,
            { "Segment Data", "tecmp.payload.status.config.vendor_technica.segment_data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        /* ILaS */
        { &hf_tecmp_payload_data_flags_crc_enabled,
            { "CRC Received", "tecmp.payload.data_flags.crc_received",
            FT_BOOLEAN, 16, TFS(&tfs_tecmp_payload_data_crc_received), 0x0001, NULL, HFILL } },
        { &hf_tecmp_payload_data_flags_direction,
            { "Direction", "tecmp.payload.data_flags.direction",
            FT_BOOLEAN, 16, TFS(&tfs_tecmp_payload_data_direction), 0x0002, NULL, HFILL } },

        /* Ethernet 10BASE-T1S */
        { &hf_tecmp_payload_data_flags_phy_event_error,
            { "PHY Event/Error", "tecmp.payload.data_flags.phy_event_error",
            FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL } },

        /* LIN */
        { &hf_tecmp_payload_data_flags_coll,
            { "Collision", "tecmp.payload.data_flags.collision",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_parity,
            { "Parity Error", "tecmp.payload.data_flags.parity_error",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_no_resp,
            { "No Slave Response", "tecmp.payload.data_flags.no_resp",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_wup,
            { "Wake Up Signal", "tecmp.payload.data_flags.wup",
            FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_short_wup,
            { "Short Wake Up Signal", "tecmp.payload.data_flags.short_wup",
            FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_sleep,
            { "Sleep Signal", "tecmp.payload.data_flags.sleep",
            FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL }},

        /* CAN DATA, CAN-FD Data */
        { &hf_tecmp_payload_data_flags_ack,
            { "Ack'ed", "tecmp.payload.data_flags.ack",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_ACK, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_rtr,
            { "Remote Frame", "tecmp.payload.data_flags.rtr",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_RTR, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_esi,
            { "Error Node Active", "tecmp.payload.data_flags.esi",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CANFD_ESI, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_ide,
            { "Extended CAN-ID", "tecmp.payload.data_flags.ext_can_id",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_IDE, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_err,
            { "Error Frame", "tecmp.payload.data_flags.error_frame",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_ERR, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_brs,
            { "Bit Rate Switch", "tecmp.payload.data_flags.bit_rate_switch",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CANFD_BRS, NULL, HFILL }},

        { &hf_tecmp_payload_data_flags_can_bit_stuff_err,
            { "Bit Stuff Error", "tecmp.payload.data_flags.bit_stuff_error",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_BIT_STUFF_ERR, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_can_crc_del_err,
            { "CRC Delimiter Error", "tecmp.payload.data_flags.crc_del_error",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_CRC_DEL_ERR, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_can_ack_del_err,
            { "Ack Delimiter Error", "tecmp.payload.data_flags.ack_del_error",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_ACK_DEL_ERR, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_can_eof_err,
            { "End of Frame Field Error", "tecmp.payload.data_flags.eof_error",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CAN_EOF_ERR, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_canfd_bit_stuff_err,
            { "Bit Stuff Error", "tecmp.payload.data_flags.bit_stuff_error",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CANFD_BIT_STUFF_ERR, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_canfd_crc_del_err,
            { "CRC Delimiter Error", "tecmp.payload.data_flags.crc_del_error",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CANFD_CRC_DEL_ERR, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_canfd_ack_del_err,
            { "Ack Delimiter Error", "tecmp.payload.data_flags.ack_del_error",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CANFD_ACK_DEL_ERR, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_canfd_eof_err,
            { "End of Frame Field Error", "tecmp.payload.data_flags.eof_error",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_CANFD_EOF_ERR, NULL, HFILL }},

        /* FlexRay Data */
        { &hf_tecmp_payload_data_flags_nf,
            { "Null Frame", "tecmp.payload.data_flags.null_frame",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_FR_NF, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_sf,
            { "Startup Frame", "tecmp.payload.data_flags.startup_frame",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_FR_ST, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_sync,
            { "Sync Frame", "tecmp.payload.data_flags.sync_frame",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_FR_SYNC, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_wus,
            { "Wakeup Symbol", "tecmp.payload.data_flags.wakeup_symbol",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_FR_WUS, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_ppi,
            { "Payload Preamble Indicator", "tecmp.payload.data_flags.payload_preamble_indicator",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_FR_PPI, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_cas,
            { "Collision Avoidance Symbol", "tecmp.payload.data_flags.collision_avoidance_symbol",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_FR_CAS, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_header_crc_err,
            { "Header CRC Error", "tecmp.payload.data_flags.header_crc_error",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_FR_HDR_CRC_ERR, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_frame_crc_err,
            { "Frame CRC Error", "tecmp.payload.data_flags.frame_crc_error",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_FR_FRAME_CRC_ERR, NULL, HFILL }},

        /* UART/RS232 ASCII */
        { &hf_tecmp_payload_data_flags_dl,
            { "DL", "tecmp.payload.data_flags.dl",
            FT_UINT16, BASE_DEC, VALS(tecmp_payload_rs232_uart_dl_types), 0x000e, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_parity_error,
            { "Parity Error", "tecmp.payload.data_flags.parity_error",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }},

        /* Analog  */
        { &hf_tecmp_payload_data_flags_sample_time,
            { "Sample Time", "tecmp.payload.data_flags.sample_time",
            FT_UINT16, BASE_DEC, VALS(tecmp_payload_analog_sample_time_types), 0x7800, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_factor,
            { "Factor", "tecmp.payload.data_flags.factor",
            FT_UINT16, BASE_DEC, VALS(tecmp_payload_analog_scale_factor_types), TECMP_DATAFLAGS_FACTOR_MASK, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_unit,
            { "Unit", "tecmp.payload.data_flags.unit",
            FT_UINT16, BASE_DEC, VALS(tecmp_payload_analog_unit_types), TECMP_DATAFLAGS_UNIT_MASK, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_threshold_u,
            { "Threshold Undershot (deprecated)", "tecmp.payload.data_flags.threshold_undershot",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_threshold_o,
            { "Threshold Exceeded (deprecated)", "tecmp.payload.data_flags.threshold_exceeded",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }},
        { &hf_tecmp_payload_data_analog_value_raw,
            { "Analog Value", "tecmp.payload.data.analog_value",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_analog_value_raw_signed,
            { "Analog Value", "tecmp.payload.data.analog_value_signed",
            FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_analog_value_volt,
            { "Analog Value", "tecmp.payload.data.analog_value_volt",
            FT_DOUBLE, BASE_NONE | BASE_UNIT_STRING, &units_volt, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_analog_value_amp,
            { "Analog Value", "tecmp.payload.data.analog_value_amp",
            FT_DOUBLE, BASE_NONE | BASE_UNIT_STRING, &units_amp, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_analog_value_watt,
            { "Analog Value", "tecmp.payload.data.analog_value_watt",
            FT_DOUBLE, BASE_NONE | BASE_UNIT_STRING, &units_watt, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_analog_value_amp_hour,
            { "Analog Value", "tecmp.payload.data.analog_value_amp_hour",
            FT_DOUBLE, BASE_NONE | BASE_UNIT_STRING, &tecmp_units_amp_hour, 0x0, NULL, HFILL }},
        { &hf_tecmp_payload_data_analog_value_celsius,
            { "Analog Value", "tecmp.payload.data.analog_value_celsius",
            FT_DOUBLE, BASE_NONE | BASE_UNIT_STRING, &units_degree_celsius, 0x0, NULL, HFILL }},

        /* ILaS */
        { &hf_tecmp_payload_data_ilas_decoded_command,
            { "Decoded API Command", "tecmp.payload.ilas_decoded_command",
            FT_UINT8, BASE_DEC, VALS(tecmp_ilas_command_types), 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_data_ilas_decoded_address,
            { "Decoded Address", "tecmp.payload.ilas_decoded_address",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_data_ilas_decoded_data,
            { "Decoded Data", "tecmp.payload.ilas_decoded_data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_data_ilas_raw_sdu,
            { "Raw SDU", "tecmp.payload.ilas_raw_sdu",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_data_ilas_raw_crc,
            { "Raw CRC", "tecmp.payload.ilas_raw_crc",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        /* TX Data Flags */
        { &hf_tecmp_payload_data_flags_use_crc_value,
            { "Use CRC Value", "tecmp.payload.data_flags.use_crc_value",
            FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_use_header_crc_value,
            { "Use Header CRC Value", "tecmp.payload.data_flags.use_header_crc_value",
            FT_BOOLEAN, 16, NULL, DATA_FLAG_FR_HDR_CRC_ERR, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_use_checksum_value,
            { "Use Checksum Value", "tecmp.payload.data_flags.use_checksum_value",
            FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_use_parity_bits,
            { "Use Parity Bits", "tecmp.payload.data_flags.use_parity_bits",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }},
        { &hf_tecmp_payload_data_flags_tx_mode,
            { "TX Mode", "tecmp.payload.data_flags.set_tx_mode",
            FT_UINT16, BASE_DEC, VALS(tecmp_payload_flexray_tx_mode), 0x0380, NULL, HFILL }},

        /* Counter Event */
        { &hf_tecmp_payload_counter_event_device_id,
            { "Device ID", "tecmp.payload.counter_event.device_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_counter_event_interface_id,
            { "Interface ID", "tecmp.payload.counter_event.interface_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_counter_event_counter_last,
            { "Last Counter", "tecmp.payload.counter_event.counter_last",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_counter_event_counter_cur,
            { "Current Counter", "tecmp.payload.counter_event.counter_current",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* TimeSync Event */
        { &hf_tecmp_payload_timesync_event_device_id,
            { "Device ID", "tecmp.payload.timesync_event.device_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_timesync_event_interface_id,
            { "Interface ID", "tecmp.payload.timesync_event.interface_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_timesync_event_reserved,
            { "Reserved", "tecmp.payload.timesync_event.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_timesync_event_async,
            { "Async", "tecmp.payload.timesync_event.async",
            FT_UINT16, BASE_HEX, VALS(tecmp_timesync_event_flags), 0x0, NULL, HFILL } },
        { &hf_tecmp_payload_timesync_event_time_delta,
            { "TimeDelta", "tecmp.payload.timesync_event.time_delta",
            FT_UINT16, BASE_HEX, VALS(tecmp_timesync_event_flags), 0x0, NULL, HFILL } },
    };

    static int *ett[] = {
        &ett_tecmp_payload,
        &ett_tecmp_payload_interface_id,
        &ett_tecmp_payload_data,
        &ett_tecmp_payload_timestamp,
        &ett_tecmp_payload_dataflags,
        &ett_tecmp_payload_instruction_address,
        &ett_tecmp_payload_data_id,
        &ett_tecmp_payload_lin_id,
        &ett_tecmp_status_dev_vendor_data,
        &ett_tecmp_status_bus_data,
        &ett_tecmp_status_bus_data_entry,
        &ett_tecmp_status_bus_vendor_data,
        &ett_tecmp_status_bus_vendor_data_flags,
        &ett_tecmp_ctrl_message_10baset1s_flags,
        &ett_tecmp_ctrl_message_10baset1s_events_errors,
    };

    static ei_register_info ei[] = {
         { &ei_tecmp_payload_length_mismatch, { "tecmp.payload.payload_length_mismatch",
           PI_PROTOCOL, PI_WARN, "Payload Length and the length of Payload present in packet do not match!", EXPFILL }},
         { &ei_tecmp_payload_header_crc_overflow, { "tecmp.payload.header_crc_overflow",
           PI_PROTOCOL, PI_WARN, "Header CRC may only be up to 0x07ff!", EXPFILL }},
    };

    proto_tecmp_payload = proto_register_protocol("Technically Enhanced Capture Module Protocol Payload",
        "TECMP Payload", "tecmp.payload");
    proto_register_field_array(proto_tecmp_payload, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_tecmp_payload = expert_register_protocol(proto_tecmp_payload);
    expert_register_field_array(expert_module_tecmp_payload, ei, array_length(ei));


    /*
     * Dissectors can register themselves in this table.
     */
    data_subdissector_table = register_dissector_table(TECMP_PAYLOAD_INTERFACE_ID, "TECMP Interface ID", proto_tecmp_payload, FT_UINT32, BASE_HEX);

}

void
proto_reg_handoff_tecmp_payload(void) {
    eth_handle = find_dissector("eth_withfcs");
    proto_vlan = proto_get_id_by_filter_name("vlan");
}

void
proto_register_tecmp(void) {
    module_t *tecmp_module = NULL;
    uat_t *tecmp_device_id_uat = NULL;
    uat_t *tecmp_interface_id_uat = NULL;
    uat_t *tecmp_control_message_id_uat = NULL;

    static hf_register_info hf[] = {
        { &hf_tecmp_device_id,
            { "Device ID", "tecmp.device_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_counter,
            { "Counter", "tecmp.counter",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_version,
            { "Version", "tecmp.version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_msgtype,
            { "Message Type", "tecmp.message_type",
            FT_UINT8, BASE_HEX, VALS(msg_type_names), 0x0, NULL, HFILL }},
        { &hf_tecmp_data_type,
            { "Data Type", "tecmp.data_type",
            FT_UINT16, BASE_HEX, VALS(tecmp_msgtype_names), 0x0, NULL, HFILL }},
        { &hf_tecmp_res,
            { "Reserved", "tecmp.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_flags,
            { "Device Flags", "tecmp.dev_flags",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_tecmp_flags_eos,
            { "End of Segment", "tecmp.dev_flags.eos",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }},
        { &hf_tecmp_flags_sos,
            { "Start of Segment", "tecmp.dev_flags.sos",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }},
        { &hf_tecmp_flags_spy,
            { "Spy", "tecmp.dev_flags.spy",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL }},
        { &hf_tecmp_flags_multi_frame,
            { "Multi Frame", "tecmp.dev_flags.multi_frame",
            FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL }},
        { &hf_tecmp_flags_dev_overflow,
            { "Device Overflow", "tecmp.dev_flags.device_overflow",
            FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_tecmp,
        &ett_tecmp_flags,
    };

    /* UATs for user_data fields */
    static uat_field_t tecmp_device_id_uat_fields[] = {
        UAT_FLD_HEX(tecmp_devices, id, "ID", "ID of the Device (hex uint16 without leading 0x)"),
        UAT_FLD_CSTRING(tecmp_devices, name, "Device Name", "Name of the Device (string)"),
        UAT_END_FIELDS
    };

    static uat_field_t tecmp_interface_id_uat_fields[] = {
        UAT_FLD_HEX(tecmp_interfaces, id, "ID", "ID of the Interface (hex uint32 without leading 0x)"),
        UAT_FLD_CSTRING(tecmp_interfaces, name, "Interface Name", "Name of the Interface (string)"),
        UAT_FLD_HEX(tecmp_interfaces, bus_id, "Bus ID", "Bus ID of the Interface (hex uint16 without leading 0x)"),
        UAT_END_FIELDS
    };

    static uat_field_t tecmp_control_message_id_uat_fields[] = {
        UAT_FLD_HEX(tecmp_ctrl_msgs, id, "ID", "ID of the Control Message"),
        UAT_FLD_CSTRING(tecmp_ctrl_msgs, name, "Control Message Name", "Name of the Control Message"),
        UAT_END_FIELDS
    };

    proto_tecmp = proto_register_protocol("Technically Enhanced Capture Module Protocol", "TECMP", "tecmp");
    proto_register_field_array(proto_tecmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    tecmp_handle = register_dissector("tecmp", dissect_tecmp, proto_tecmp);
    tecmp_module = prefs_register_protocol(proto_tecmp, NULL);

    /* UATs */
    tecmp_device_id_uat = uat_new("TECMP Devices",
        sizeof(generic_one_id_string_t),        /* record size           */
        DATAFILE_TECMP_DEVICE_IDS,              /* filename              */
        true,                                   /* from profile          */
        (void**)&tecmp_devices,                 /* data_ptr              */
        &tecmp_devices_num,                     /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                 /* but not fields        */
        NULL,                                   /* help                  */
        copy_generic_one_id_string_cb,          /* copy callback         */
        update_generic_one_identifier_16bit,    /* update callback       */
        free_generic_one_id_string_cb,          /* free callback         */
        post_update_tecmp_devices_cb,           /* post update callback  */
        NULL,                                   /* reset callback        */
        tecmp_device_id_uat_fields              /* UAT field definitions */
    );

    prefs_register_uat_preference(tecmp_module, "_udf_tecmp_devicess", "Devices",
        "A table to define names of Devices, which override default names.", tecmp_device_id_uat);

    tecmp_interface_id_uat = uat_new("TECMP Interfaces",
        sizeof(interface_config_t),             /* record size           */
        DATAFILE_TECMP_INTERFACE_IDS,           /* filename              */
        true,                                   /* from profile          */
        (void**)&tecmp_interfaces,              /* data_ptr              */
        &tecmp_interfaces_num,                  /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                 /* but not fields        */
        NULL,                                   /* help                  */
        copy_interface_config_cb,               /* copy callback         */
        update_interface_config,                /* update callback       */
        free_interface_config_cb,               /* free callback         */
        post_update_tecmp_interfaces_cb,        /* post update callback  */
        NULL,                                   /* reset callback        */
        tecmp_interface_id_uat_fields           /* UAT field definitions */
    );

    prefs_register_uat_preference(tecmp_module, "_udf_tecmp_interfaces", "Interfaces",
        "A table to define names of Interfaces.", tecmp_interface_id_uat);

    tecmp_control_message_id_uat = uat_new("TECMP Control Messages",
        sizeof(generic_one_id_string_t),        /* record size           */
        DATAFILE_TECMP_CONTROL_MSG_IDS,         /* filename              */
        true,                                   /* from profile          */
        (void**)&tecmp_ctrl_msgs,               /* data_ptr              */
        &tecmp_ctrl_msg_num,                    /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                 /* but not fields        */
        NULL,                                   /* help                  */
        copy_generic_one_id_string_cb,          /* copy callback         */
        update_generic_one_identifier_16bit,    /* update callback       */
        free_generic_one_id_string_cb,          /* free callback         */
        post_update_tecmp_control_messages_cb,  /* post update callback  */
        NULL,                                   /* reset callback        */
        tecmp_control_message_id_uat_fields     /* UAT field definitions */
    );

    prefs_register_uat_preference(tecmp_module, "_udf_tecmp_control_msg_id", "Control Messages",
        "A table to define names of Control Messages.", tecmp_control_message_id_uat);

    prefs_register_bool_preference(tecmp_module, "try_heuristic_first",
        "Try heuristic sub-dissectors first",
        "Try to decode a packet using an heuristic sub-dissector"
        " before using a sub-dissector registered to \"decode as\"",
        &heuristic_first);

    prefs_register_bool_preference(tecmp_module, "analog_samples_sint",
        "Decode Analog Samples as Signed Integer",
        "Treat the analog samples as signed integers and decode them accordingly.",
        &analog_samples_are_signed_int);

    prefs_register_bool_preference(tecmp_module, "move_ethernet_in_tecmp_tree",
        "More compact Ethernet representation (move into TECMP Tree)",
        "Move Ethernet into the TECMP Tree to be more space efficient.",
        &show_ethernet_in_tecmp_tree);

    prefs_register_bool_preference(tecmp_module, "detect_asam_cmp",
        "Detect ASAM CMP",
        "Detect ASAM CMP messages and the ASAM CMP dissector handle them.",
        &detect_asam_cmp);

    prefs_register_bool_preference(tecmp_module, "detect_asam_cmp_ignore_user_defined",
        "Ignore Device IDs 0xff00-0xffff for ASAM CMP Detection",
        "Ignore Device IDs 0xff00-0xffff (user-defined range) for ASAM CMP Detection",
        &detect_asam_cmp_ignore_user_defined);
}

void
proto_reg_handoff_tecmp(void) {
    dissector_add_uint("ethertype", ETHERTYPE_TECMP, tecmp_handle);

    lin_subdissector_table = find_dissector_table("lin.frame_id");

    text_lines_handle = find_dissector_add_dependency("data-text-lines", proto_tecmp);
    asam_cmp_handle = find_dissector("asam-cmp");
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
