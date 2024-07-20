/* packet-z21.c
 * Routines for Z21 LAN protocol dissection
 * Copyright 2023, Markku Leiniö <markku.leinio@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Z21 LAN protocol specification can be found at:
 * https://www.z21.eu/en/downloads/manuals
 */

#include "config.h"
#define WS_LOG_DOMAIN "Z21"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include "packet-udp.h"

void proto_register_z21(void);
void proto_reg_handoff_z21(void);

/* Initialize the protocol and registered fields */
static int proto_z21;
static int hf_z21_datalen;
static int hf_z21_command;
static int hf_z21_x_bus;
static int hf_z21_serial_number;
static int hf_z21_checksum;
static int hf_z21_main_current;
static int hf_z21_prog_current;
static int hf_z21_filtered_main_current;
static int hf_z21_temperature;
static int hf_z21_supply_voltage;
static int hf_z21_track_voltage;
static int hf_z21_broadcast_flags;
static int hf_z21_central_state;
static int hf_z21_central_state_ex;
static int hf_z21_systemstate_reserved;
static int hf_z21_capabilities;
static int hf_z21_status;
static int hf_z21_loco_mode;
static int hf_z21_loco_address;
static int hf_z21_loco_direction_and_speed;
static int hf_z21_loco_direction;
static int hf_z21_loco_speed;
static int hf_z21_loco_info_mm;
static int hf_z21_loco_info_busy;
static int hf_z21_loco_info_speed_steps;
static int hf_z21_loco_info_direction;
static int hf_z21_loco_info_speed;
static int hf_z21_loco_info_double_traction;
static int hf_z21_loco_info_smartsearch;
static int hf_z21_loco_info_f0;
static int hf_z21_loco_info_f1;
static int hf_z21_loco_info_f2;
static int hf_z21_loco_info_f3;
static int hf_z21_loco_info_f4;
static int hf_z21_loco_info_f5;
static int hf_z21_loco_info_f6;
static int hf_z21_loco_info_f7;
static int hf_z21_loco_info_f8;
static int hf_z21_loco_info_f9;
static int hf_z21_loco_info_f10;
static int hf_z21_loco_info_f11;
static int hf_z21_loco_info_f12;
static int hf_z21_loco_info_f13;
static int hf_z21_loco_info_f14;
static int hf_z21_loco_info_f15;
static int hf_z21_loco_info_f16;
static int hf_z21_loco_info_f17;
static int hf_z21_loco_info_f18;
static int hf_z21_loco_info_f19;
static int hf_z21_loco_info_f20;
static int hf_z21_loco_info_f21;
static int hf_z21_loco_info_f22;
static int hf_z21_loco_info_f23;
static int hf_z21_loco_info_f24;
static int hf_z21_loco_info_f25;
static int hf_z21_loco_info_f26;
static int hf_z21_loco_info_f27;
static int hf_z21_loco_info_f28;
static int hf_z21_loco_info_f29;
static int hf_z21_loco_info_f30;
static int hf_z21_loco_info_f31;
static int hf_z21_loco_info_extensions;
static int hf_z21_loco_func_switch_type;
static int hf_z21_loco_func_index;
static int hf_z21_speed_steps;
static int hf_z21_hw_type;
static int hf_z21_firmware_version;
static int hf_z21_broadcast_flags_driving_switching;
static int hf_z21_broadcast_flags_rmbus;
static int hf_z21_broadcast_flags_railcom_subscribed;
static int hf_z21_broadcast_flags_system_status;
static int hf_z21_broadcast_flags_driving_switching_ex;
static int hf_z21_broadcast_flags_loconet;
static int hf_z21_broadcast_flags_loconet_driving;
static int hf_z21_broadcast_flags_loconet_switching;
static int hf_z21_broadcast_flags_loconet_detector;
static int hf_z21_broadcast_flags_railcom;
static int hf_z21_broadcast_flags_can_detector;
static int hf_z21_broadcast_flags_can_booster;
static int hf_z21_broadcast_flags_fast_clock;
static int hf_z21_state_emergency_stop;
static int hf_z21_state_track_voltage_off;
static int hf_z21_state_short_circuit;
static int hf_z21_state_programming_mode;
static int hf_z21_state_high_temperature;
static int hf_z21_state_power_lost;
static int hf_z21_state_short_circuit_external;
static int hf_z21_state_short_circuit_internal;
static int hf_z21_state_rcn_213;
static int hf_z21_capability_dcc;
static int hf_z21_capability_mm;
static int hf_z21_capability_reserved;
static int hf_z21_capability_railcom;
static int hf_z21_capability_loco_cmds;
static int hf_z21_capability_accessory_cmds;
static int hf_z21_capability_detector_cmds;
static int hf_z21_capability_needs_unlock_code;
static int hf_z21_function_address;
static int hf_z21_turnout_state;
static int hf_z21_turnout_activate_bit;
static int hf_z21_turnout_output_bit;
static int hf_z21_turnout_queue_bit;
static int hf_z21_accessory_address;
static int hf_z21_accessory_state;
static int hf_z21_accessory_status;
static int hf_z21_cv_address;
static int hf_z21_cv_value;
static int hf_z21_register;
static int hf_z21_register_value;
static int hf_z21_pom_operation;
static int hf_z21_cv_bit_position;
static int hf_z21_cv_bit_value;
static int hf_z21_rmbus_group;
static int hf_z21_rmbus_feedbacks;
static int hf_z21_rmbus_address;
static int hf_z21_railcom_receive_counter;
static int hf_z21_railcom_error_counter;
static int hf_z21_railcom_reserved1;
static int hf_z21_railcom_options;
static int hf_z21_railcom_speed;
static int hf_z21_railcom_qos;
static int hf_z21_railcom_reserved2;
static int hf_z21_railcom_type;
static int hf_z21_loconet_message;
static int hf_z21_loconet_result;
static int hf_z21_loconet_type;
static int hf_z21_loconet_report_address;
static int hf_z21_loconet_feedback_address;
static int hf_z21_loconet_info;
static int hf_z21_can_type;
static int hf_z21_can_network_id;
static int hf_z21_can_module_address;
static int hf_z21_can_port;
static int hf_z21_can_value1;
static int hf_z21_can_value2;
static int hf_z21_can_booster_name;
static int hf_z21_can_booster_output_port;
static int hf_z21_can_booster_state;
static int hf_z21_can_booster_state_bg_active;
static int hf_z21_can_booster_state_short_circuit;
static int hf_z21_can_booster_state_track_voltage_off;
static int hf_z21_can_booster_state_railcom_active;
static int hf_z21_can_booster_state_output_disabled;
static int hf_z21_can_booster_vcc;
static int hf_z21_can_booster_current;
static int hf_z21_can_booster_power;
static int hf_z21_zlink_message_type;
static int hf_z21_zlink_hwid;
static int hf_z21_zlink_fw_major;
static int hf_z21_zlink_fw_minor;
static int hf_z21_zlink_fw_build;
static int hf_z21_zlink_mac;
static int hf_z21_zlink_name;
static int hf_z21_zlink_reserved;
static int hf_z21_booster_name;
static int hf_z21_booster_port;
static int hf_z21_booster_port_state;
static int hf_z21_booster_state_data;
static int hf_z21_decoder_name;
static int hf_z21_decoder_state_data;
static int hf_z21_data;

static dissector_handle_t z21_handle;

/* Not IANA registered */
#define Z21_UDP_PORTS "21105,21106"
static range_t *udp_port_range;

/* Initialize the subtree pointers */
static int ett_z21;

/* Initialize expert fields */
static expert_field ei_z21_invalid_checksum;

#define Z21_MIN_LENGTH 4

/* All commands are here defined as big-endian even though the
 * specifications are all little-endian. That's fine as we are
 * not comparing the values numerically, just matching them
 * in the packets. */
#define Z21_LAN_GET_SERIAL_NUMBER               0x1000
#define Z21_LAN_GET_HWINFO                      0x1A00
#define Z21_LAN_LOGOFF                          0x3000
/* Responses and requests based on the X-BUS protocol are transmitted
 * with the Z21-LAN-Header 0x40 and the specific command is indicated
 * with additional bytes inside the data field. */
#define Z21_LAN_X_BC                            0x4000
#define Z21_LAN_SET_BROADCASTFLAGS              0x5000
#define Z21_LAN_GET_BROADCASTFLAGS              0x5100
#define Z21_LAN_GET_LOCOMODE                    0x6000
#define Z21_LAN_SET_LOCOMODE                    0x6100
#define Z21_LAN_RMBUS_DATACHANGED               0x8000
#define Z21_LAN_RMBUS_GETDATA                   0x8100
#define Z21_LAN_RMBUS_PROGRAMMODULE             0x8200
#define Z21_LAN_SYSTEMSTATE_DATACHANGED         0x8400
#define Z21_LAN_SYSTEMSTATE_GETDATA             0x8500
#define Z21_LAN_RAILCOM_DATACHANGED             0x8800
#define Z21_LAN_RAILCOM_GETDATA                 0x8900
#define Z21_LAN_LOCONET_Z21_RX                  0xA000
#define Z21_LAN_LOCONET_Z21_TX                  0xA100
#define Z21_LAN_LOCONET_FROM_LAN                0xA200
#define Z21_LAN_LOCONET_DISPATCH_ADDR           0xA300
#define Z21_LAN_LOCONET_DETECTOR                0xA400
#define Z21_LAN_BOOSTER_SET_POWER               0xB200
#define Z21_LAN_BOOSTER_GET_DESCRIPTION         0xB800
#define Z21_LAN_BOOSTER_SET_DESCRIPTION         0xB900
#define Z21_LAN_BOOSTER_SYSTEMSTATE_DATACHANGED 0xBA00
#define Z21_LAN_BOOSTER_SYSTEMSTATE_GETDATA     0xBB00
#define Z21_LAN_CAN_DETECTOR                    0xC400
#define Z21_LAN_CAN_DEVICE_GET_DESCRIPTION      0xC800
#define Z21_LAN_CAN_DEVICE_SET_DESCRIPTION      0xC900
#define Z21_LAN_CAN_BOOSTER_SYSTEMSTATE_CHGD    0xCA00
#define Z21_LAN_CAN_BOOSTER_SET_TRACKPOWER      0xCB00
#define Z21_LAN_FAST_CLOCK_CONTROL              0xCC00
#define Z21_LAN_FAST_CLOCK_DATA                 0xCD00
#define Z21_LAN_FAST_CLOCK_SETTINGS_GET         0xCE00
#define Z21_LAN_FAST_CLOCK_SETTINGS_SET         0xCF00
#define Z21_LAN_DECODER_GET_DESCRIPTION         0xD800
#define Z21_LAN_DECODER_SET_DESCRIPTION         0xD900
#define Z21_LAN_DECODER_SYSTEMSTATE_DATACHANGED 0xDA00
#define Z21_LAN_DECODER_SYSTEMSTATE_GETDATA     0xDB00
#define Z21_LAN_ZLINK_GET_HWINFO                0xE800
/* X-BUS commands are listed as 32-bit big-endian */
#define Z21_LAN_X_GET_VERSION_REQUEST           0x40002121
#define Z21_LAN_X_GET_VERSION_REPLY             0x40006321
#define Z21_LAN_X_GET_STATUS_REQUEST            0x40002124
#define Z21_LAN_X_SET_TRACK_POWER_OFF           0x40002180
#define Z21_LAN_X_SET_TRACK_POWER_ON            0x40002181
#define Z21_LAN_X_DCC_READ_REGISTER             0x40002211
#define Z21_LAN_X_CV_READ                       0x40002311
#define Z21_LAN_X_DCC_WRITE_REGISTER            0x40002312
#define Z21_LAN_X_CV_WRITE                      0x40002412
#define Z21_LAN_X_MM_WRITE_BYTE                 0x400024FF
#define Z21_LAN_X_GET_TURNOUT_INFO              0x400043
#define Z21_LAN_X_TURNOUT_INFO                  0x40FF43    /* To be set manually */
#define Z21_LAN_X_GET_EXT_ACCESSORY_INFO        0x400044
#define Z21_LAN_X_EXT_ACCESSORY_INFO            0x40FF44    /* To be set manually */
#define Z21_LAN_X_SET_TURNOUT                   0x400053
#define Z21_LAN_X_SET_EXT_ACCESSORY             0x400054
#define Z21_LAN_X_BC_TRACK_POWER_OFF            0x40006100
#define Z21_LAN_X_BC_TRACK_POWER_ON             0x40006101
#define Z21_LAN_X_BC_PROGRAMMING_MODE           0x40006102
#define Z21_LAN_X_BC_TRACK_SHORT_CIRCUIT        0x40006108
#define Z21_LAN_X_CV_NACK_SC                    0x40006112
#define Z21_LAN_X_CV_NACK                       0x40006113
#define Z21_LAN_X_UNKNOWN_COMMAND               0x40006182
#define Z21_LAN_X_STATUS_CHANGED                0x40006222
#define Z21_LAN_X_CV_RESULT                     0x40006414
#define Z21_LAN_X_SET_STOP                      0x400080
#define Z21_LAN_X_BC_STOPPED                    0x40008100
#define Z21_LAN_X_SET_LOCO_E_STOP               0x400092
#define Z21_LAN_X_PURGE_LOCO                    0x4000E344
#define Z21_LAN_X_GET_LOCO_INFO                 0x4000E3F0
#define Z21_LAN_X_SET_LOCO_DRIVE_DCC14          0x4000E410
#define Z21_LAN_X_SET_LOCO_DRIVE_DCC28          0x4000E412
#define Z21_LAN_X_SET_LOCO_DRIVE_DCC128         0x4000E413
#define Z21_LAN_X_SET_LOCO_FUNCTION             0x4000E4F8
#define Z21_LAN_X_SET_LOCO_BINARY_STATE         0x4000E55F
#define Z21_LAN_X_CV_POM_COMMANDS               0x4000E630
#define Z21_LAN_X_CV_POM_WRITE_BYTE             0x40FFE630      /* To be set manually */
#define Z21_LAN_X_CV_POM_WRITE_BIT              0x40FEE630      /* To be set manually */
#define Z21_LAN_X_CV_POM_READ_BYTE              0x40FDE630      /* To be set manually */
#define Z21_LAN_X_CV_POM_ACCESSORY_COMMANDS     0x4000E631
#define Z21_LAN_X_CV_POM_ACCESSORY_WRITE_BYTE   0x40FFE631      /* To be set manually */
#define Z21_LAN_X_CV_POM_ACCESSORY_WRITE_BIT    0x40FEE631      /* To be set manually */
#define Z21_LAN_X_CV_POM_ACCESSORY_READ_BYTE    0x40FDE631      /* To be set manually */
#define Z21_LAN_X_LOCO_INFO                     0x4000EF
#define Z21_LAN_X_GET_FIRMWARE_VERSION_REQUEST  0x4000F10A
#define Z21_LAN_X_GET_FIRMWARE_VERSION_REPLY    0x4000F30A

/* This should be put in numerical order, not alphabetical order,
 * if it is ever converted to a value_string_ext, to allow binary search.
 */
static const value_string z21_command_vals[] = {
    { Z21_LAN_CAN_BOOSTER_SET_TRACKPOWER,       "LAN_CAN_BOOSTER_SET_TRACKPOWER" },
    { Z21_LAN_CAN_BOOSTER_SYSTEMSTATE_CHGD,     "LAN_CAN_BOOSTER_SYSTEMSTATE_CHGD" },
    { Z21_LAN_CAN_DETECTOR,                     "LAN_CAN_DETECTOR" },
    { Z21_LAN_CAN_DEVICE_GET_DESCRIPTION,       "LAN_CAN_DEVICE_GET_DESCRIPTION" },
    { Z21_LAN_CAN_DEVICE_SET_DESCRIPTION,       "LAN_CAN_DEVICE_SET_DESCRIPTION" },
    { Z21_LAN_BOOSTER_GET_DESCRIPTION,          "LAN_BOOSTER_GET_DESCRIPTION" },
    { Z21_LAN_BOOSTER_SET_DESCRIPTION,          "LAN_BOOSTER_SET_DESCRIPTION" },
    { Z21_LAN_BOOSTER_SET_POWER,                "LAN_BOOSTER_SET_POWER" },
    { Z21_LAN_BOOSTER_SYSTEMSTATE_DATACHANGED,  "LAN_BOOSTER_SYSTEMSTATE_DATACHANGED" },
    { Z21_LAN_BOOSTER_SYSTEMSTATE_GETDATA,      "LAN_BOOSTER_SYSTEMSTATE_GETDATA" },
    { Z21_LAN_DECODER_GET_DESCRIPTION,          "LAN_DECODER_GET_DESCRIPTION" },
    { Z21_LAN_DECODER_SET_DESCRIPTION,          "LAN_DECODER_SET_DESCRIPTION" },
    { Z21_LAN_DECODER_SYSTEMSTATE_DATACHANGED,  "LAN_DECODER_SYSTEMSTATE_DATACHANGED" },
    { Z21_LAN_DECODER_SYSTEMSTATE_GETDATA,      "LAN_DECODER_SYSTEMSTATE_GETDATA" },
    { Z21_LAN_FAST_CLOCK_CONTROL,               "LAN_FAST_CLOCK_CONTROL" },
    { Z21_LAN_FAST_CLOCK_DATA,                  "LAN_FAST_CLOCK_DATA" },
    { Z21_LAN_FAST_CLOCK_SETTINGS_GET,          "LAN_FAST_CLOCK_SETTINGS_GET" },
    { Z21_LAN_FAST_CLOCK_SETTINGS_SET,          "LAN_FAST_CLOCK_SETTINGS_SET" },
    { Z21_LAN_GET_BROADCASTFLAGS,               "LAN_GET_BROADCASTFLAGS" },
    { Z21_LAN_GET_HWINFO,                       "LAN_GET_HWINFO" },
    { Z21_LAN_GET_LOCOMODE,                     "LAN_GET_LOCOMODE" },
    { Z21_LAN_GET_SERIAL_NUMBER,                "LAN_GET_SERIAL_NUMBER" },
    { Z21_LAN_LOCONET_DETECTOR,                 "LAN_LOCONET_DETECTOR" },
    { Z21_LAN_LOCONET_DISPATCH_ADDR,            "LAN_LOCONET_DISPATCH_ADDR" },
    { Z21_LAN_LOCONET_FROM_LAN,                 "LAN_LOCONET_FROM_LAN" },
    { Z21_LAN_LOCONET_Z21_RX,                   "LAN_LOCONET_Z21_RX" },
    { Z21_LAN_LOCONET_Z21_TX,                   "LAN_LOCONET_Z21_TX" },
    { Z21_LAN_LOGOFF,                           "LAN_LOGOFF" },
    { Z21_LAN_RAILCOM_GETDATA,                  "LAN_RAILCOM_GETDATA" },
    { Z21_LAN_RAILCOM_DATACHANGED,              "LAN_RAILCOM_DATACHANGED" },
    { Z21_LAN_RMBUS_DATACHANGED,                "LAN_RMBUS_DATACHANGED" },
    { Z21_LAN_RMBUS_GETDATA,                    "LAN_RMBUS_GETDATA" },
    { Z21_LAN_RMBUS_PROGRAMMODULE,              "LAN_RMBUS_PROGRAMMODULE" },
    { Z21_LAN_SET_BROADCASTFLAGS,               "LAN_SET_BROADCASTFLAGS" },
    { Z21_LAN_SET_LOCOMODE,                     "LAN_SET_LOCOMODE" },
    { Z21_LAN_SYSTEMSTATE_DATACHANGED,          "LAN_SYSTEMSTATE_DATACHANGED" },
    { Z21_LAN_SYSTEMSTATE_GETDATA,              "LAN_SYSTEMSTATE_GETDATA" },
    { Z21_LAN_X_BC,                             "LAN_X_xxx" }, /* Unspecified X-Bus command */
    { Z21_LAN_X_BC_PROGRAMMING_MODE,            "LAN_X_BC_PROGRAMMING_MODE" },
    { Z21_LAN_X_BC_STOPPED,                     "LAN_X_BC_STOPPED" },
    { Z21_LAN_X_BC_TRACK_POWER_OFF,             "LAN_X_BC_TRACK_POWER_OFF" },
    { Z21_LAN_X_BC_TRACK_POWER_ON,              "LAN_X_BC_TRACK_POWER_ON" },
    { Z21_LAN_X_BC_TRACK_SHORT_CIRCUIT,         "LAN_X_BC_TRACK_SHORT_CIRCUIT" },
    { Z21_LAN_X_CV_NACK,                        "LAN_X_CV_NACK" },
    { Z21_LAN_X_CV_NACK_SC,                     "LAN_X_CV_NACK_SC" },
    { Z21_LAN_X_CV_POM_ACCESSORY_READ_BYTE,     "LAN_X_CV_POM_ACCESSORY_READ_BYTE" },
    { Z21_LAN_X_CV_POM_ACCESSORY_WRITE_BIT,     "LAN_X_CV_POM_ACCESSORY_WRITE_BIT" },
    { Z21_LAN_X_CV_POM_ACCESSORY_WRITE_BYTE,    "LAN_X_CV_POM_ACCESSORY_WRITE_BYTE" },
    { Z21_LAN_X_CV_POM_READ_BYTE,               "LAN_X_CV_POM_READ_BYTE" },
    { Z21_LAN_X_CV_POM_WRITE_BIT,               "LAN_X_CV_POM_WRITE_BIT" },
    { Z21_LAN_X_CV_POM_WRITE_BYTE,              "LAN_X_CV_POM_WRITE_BYTE" },
    { Z21_LAN_X_CV_READ,                        "LAN_X_CV_READ" },
    { Z21_LAN_X_CV_RESULT,                      "LAN_X_CV_RESULT" },
    { Z21_LAN_X_CV_WRITE,                       "LAN_X_CV_WRITE" },
    { Z21_LAN_X_DCC_READ_REGISTER,              "LAN_X_DCC_READ_REGISTER" },
    { Z21_LAN_X_DCC_WRITE_REGISTER,             "LAN_X_DCC_WRITE_REGISTER" },
    { Z21_LAN_X_EXT_ACCESSORY_INFO,             "LAN_X_EXT_ACCESSORY_INFO" },
    { Z21_LAN_X_GET_EXT_ACCESSORY_INFO,         "LAN_X_GET_EXT_ACCESSORY_INFO" },
    { Z21_LAN_X_GET_FIRMWARE_VERSION_REQUEST,   "LAN_X_GET_FIRMWARE_VERSION" },
    { Z21_LAN_X_GET_FIRMWARE_VERSION_REPLY,     "LAN_X_GET_FIRMWARE_VERSION" },
    { Z21_LAN_X_GET_LOCO_INFO,                  "LAN_X_GET_LOCO_INFO" },
    { Z21_LAN_X_GET_TURNOUT_INFO,               "LAN_X_GET_TURNOUT_INFO" },
    { Z21_LAN_X_GET_VERSION_REQUEST,            "LAN_X_GET_VERSION" },
    { Z21_LAN_X_GET_VERSION_REPLY,              "LAN_X_GET_VERSION" },
    { Z21_LAN_X_GET_STATUS_REQUEST,             "LAN_X_GET_STATUS" },
    { Z21_LAN_X_LOCO_INFO,                      "LAN_X_LOCO_INFO" },
    { Z21_LAN_X_MM_WRITE_BYTE,                  "LAN_X_MM_WRITE_BYTE" },
    { Z21_LAN_X_PURGE_LOCO,                     "LAN_X_PURGE_LOCO" },
    { Z21_LAN_X_SET_EXT_ACCESSORY,              "LAN_X_SET_EXT_ACCESSORY" },
    { Z21_LAN_X_SET_LOCO_BINARY_STATE,          "LAN_X_SET_LOCO_BINARY_STATE" },
    { Z21_LAN_X_SET_LOCO_DRIVE_DCC14,           "LAN_X_SET_LOCO_DRIVE" },
    { Z21_LAN_X_SET_LOCO_DRIVE_DCC28,           "LAN_X_SET_LOCO_DRIVE" },
    { Z21_LAN_X_SET_LOCO_DRIVE_DCC128,          "LAN_X_SET_LOCO_DRIVE" },
    { Z21_LAN_X_SET_LOCO_E_STOP,                "LAN_X_SET_LOCO_E_STOP" },
    { Z21_LAN_X_SET_LOCO_FUNCTION,              "LAN_X_SET_LOCO_FUNCTION" },
    { Z21_LAN_X_SET_STOP,                       "LAN_X_SET_STOP" },
    { Z21_LAN_X_SET_TRACK_POWER_OFF,            "LAN_X_SET_TRACK_POWER_OFF" },
    { Z21_LAN_X_SET_TRACK_POWER_ON,             "LAN_X_SET_TRACK_POWER_ON" },
    { Z21_LAN_X_SET_TURNOUT,                    "LAN_X_SET_TURNOUT" },
    { Z21_LAN_X_STATUS_CHANGED,                 "LAN_X_STATUS_CHANGED" },
    { Z21_LAN_X_TURNOUT_INFO,                   "LAN_X_TURNOUT_INFO" },
    { Z21_LAN_X_UNKNOWN_COMMAND,                "LAN_X_UNKNOWN_COMMAND" },
    { Z21_LAN_ZLINK_GET_HWINFO,                 "LAN_ZLINK_GET_HWINFO" },
    { 0, NULL },
};

static const value_string z21_loco_mode_vals[] = {
    { 0, "DCC Format" },
    { 1, "MM Format" },
    { 0, NULL },
};

static const value_string z21_hw_type_vals[] = {
    { 0x00000200, "Z21a" },
    { 0x00000201, "Z21b" },
    { 0x00000202, "SmartRail" },
    { 0x00000203, "z21small" },
    { 0x00000204, "z21start" },
    { 0x00000205, "Z21 Single Booster" },
    { 0x00000206, "Z21 Dual Booster" },
    { 0x00000211, "Z21 XL Series" },
    { 0x00000212, "Z21 XL Booster" },
    { 0x00000301, "Z21 Switch Decoder" },
    { 0x00000302, "Z21 Signal Decoder" },
    { 0, NULL },
};

static const value_string z21_loco_info_speed_steps_vals[] = {
    { 0, "14 speed steps" },
    { 2, "28 speed steps" },
    { 4, "128 speed steps" },
    { 0, NULL },
};

static const value_string z21_loco_func_vals[] = {
    { 0, "Off" },
    { 1, "On" },
    { 2, "Toggle" },
    { 3, "Not allowed" },
    { 0, NULL },
};

static const value_string z21_turnout_state_vals[] = {
    { 0, "Not switched yet" },
    { 1, "Turnout is in position \"P=0\"" },
    { 2, "Turnout is in position \"P=1\"" },
    { 3, "Invalid combination" },
    { 0, NULL },
};

static const value_string z21_pom_operation_vals[] = {
    { 0x39, "Read byte" },  /* 111001 */
    { 0x3a, "Write bit" },  /* 111010 */
    { 0x3b, "Write byte" }, /* 111011 */
    { 0, NULL },
};

static const value_string z21_zlink_message_type_vals[] = {
    { 0x06, "ZLINK_MSG_TYPE_HW_INFO" },
    { 0, NULL },
};

static const true_false_string tfs_forward_reverse = { "Forward", "Reverse" };
static const true_false_string tfs_turnout_command = { "Activate", "Deactivate" };
static const true_false_string tfs_turnout_output = { "Output 2", "Output 1" };


static void
update_command_field(proto_item *ti, unsigned command)
{
    int width = 8;
    if (command <= 0xff)
        width = 2;
    else if (command <= 0xffff)
        width = 4;
    else if (command <= 0xffffff)
        width = 6;
    proto_item_append_text(ti, ": %s (0x%0*x)",
        val_to_str_const(command, z21_command_vals, "unknown"),
        width, command);
}


/* Code to actually dissect the packets */

static int
dissect_z21_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *temp_ti, *command_ti;
    proto_tree *z21_tree;
    unsigned offset = 0, datalen, command;
    unsigned checksum, calculated_checksum, one_byte, version, temp_uint;
    unsigned address_bytes, addr, speed_steps = 0, cv_addr;
    uint64_t status, direction_and_speed, temp_guint64;
    int32_t main_current, temp_gint32;
    char *buffer;
    float temp_float;
    static int * const broadcast_flags_bits[] = {
        &hf_z21_broadcast_flags_loconet_detector,
        &hf_z21_broadcast_flags_loconet_switching,
        &hf_z21_broadcast_flags_loconet_driving,
        &hf_z21_broadcast_flags_loconet,
        &hf_z21_broadcast_flags_can_detector,
        &hf_z21_broadcast_flags_railcom,
        &hf_z21_broadcast_flags_can_booster,
        &hf_z21_broadcast_flags_driving_switching_ex,
        &hf_z21_broadcast_flags_system_status,
        &hf_z21_broadcast_flags_fast_clock,
        &hf_z21_broadcast_flags_railcom_subscribed,
        &hf_z21_broadcast_flags_rmbus,
        &hf_z21_broadcast_flags_driving_switching,
        NULL
    };
    static int * const state_bits_byte1[] = {
        &hf_z21_state_programming_mode,
        &hf_z21_state_short_circuit,
        &hf_z21_state_track_voltage_off,
        &hf_z21_state_emergency_stop,
        NULL
    };
    static int * const state_bits_byte2[] = {
        &hf_z21_state_rcn_213,
        &hf_z21_state_short_circuit_internal,
        &hf_z21_state_short_circuit_external,
        &hf_z21_state_power_lost,
        &hf_z21_state_high_temperature,
        NULL
    };
    static int * const capability_bits[] = {
        &hf_z21_capability_needs_unlock_code,
        &hf_z21_capability_detector_cmds,
        &hf_z21_capability_accessory_cmds,
        &hf_z21_capability_loco_cmds,
        &hf_z21_capability_railcom,
        &hf_z21_capability_reserved,
        &hf_z21_capability_mm,
        &hf_z21_capability_dcc,
        NULL
    };
    static int * const speed_bits[] = {
        &hf_z21_loco_direction,
        &hf_z21_loco_speed,
        NULL
    };
    static int * const loco_info_bits1[] = {
        &hf_z21_loco_info_mm,
        &hf_z21_loco_info_busy,
        &hf_z21_loco_info_speed_steps,
        NULL
    };
    static int * const loco_info_bits2[] = {
        &hf_z21_loco_info_direction,
        &hf_z21_loco_info_speed,
        NULL
    };
    static int * const loco_info_bits3[] = {
        &hf_z21_loco_info_double_traction,
        &hf_z21_loco_info_smartsearch,
        &hf_z21_loco_info_f0,
        &hf_z21_loco_info_f4,
        &hf_z21_loco_info_f3,
        &hf_z21_loco_info_f2,
        &hf_z21_loco_info_f1,
        NULL
    };
    static int * const loco_info_bits4[] = {
        &hf_z21_loco_info_f12,
        &hf_z21_loco_info_f11,
        &hf_z21_loco_info_f10,
        &hf_z21_loco_info_f9,
        &hf_z21_loco_info_f8,
        &hf_z21_loco_info_f7,
        &hf_z21_loco_info_f6,
        &hf_z21_loco_info_f5,
        NULL
    };
    static int * const loco_info_bits5[] = {
        &hf_z21_loco_info_f20,
        &hf_z21_loco_info_f19,
        &hf_z21_loco_info_f18,
        &hf_z21_loco_info_f17,
        &hf_z21_loco_info_f16,
        &hf_z21_loco_info_f15,
        &hf_z21_loco_info_f14,
        &hf_z21_loco_info_f13,
        NULL
    };
    static int * const loco_info_bits6[] = {
        &hf_z21_loco_info_f28,
        &hf_z21_loco_info_f27,
        &hf_z21_loco_info_f26,
        &hf_z21_loco_info_f25,
        &hf_z21_loco_info_f24,
        &hf_z21_loco_info_f23,
        &hf_z21_loco_info_f22,
        &hf_z21_loco_info_f21,
        NULL
    };
    static int * const loco_info_bits7[] = {
        &hf_z21_loco_info_f31,
        &hf_z21_loco_info_f30,
        &hf_z21_loco_info_f29,
        NULL
    };
    static int * const loco_func_bits[] = {
        &hf_z21_loco_func_switch_type,
        &hf_z21_loco_func_index,
        NULL
    };
    static int * const turnout_state_bits[] = {
        &hf_z21_turnout_state,
        NULL
    };
    static int * const turnout_set_bits[] = {
        &hf_z21_turnout_queue_bit,
        &hf_z21_turnout_activate_bit,
        &hf_z21_turnout_output_bit,
        NULL
    };
    static int * const cv_bits[] = {
        &hf_z21_cv_bit_value,
        &hf_z21_cv_bit_position,
        NULL
    };
    static int * const booster_state_bits[] = {
        &hf_z21_can_booster_state_railcom_active,
        &hf_z21_can_booster_state_output_disabled,
        &hf_z21_can_booster_state_track_voltage_off,
        &hf_z21_can_booster_state_short_circuit,
        &hf_z21_can_booster_state_bg_active,
        NULL
    };

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < Z21_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Z21");

    ti = proto_tree_add_item(tree, proto_z21, tvb, 0, -1, ENC_NA);
    z21_tree = proto_item_add_subtree(ti, ett_z21);
    proto_tree_add_item_ret_uint(z21_tree, hf_z21_datalen,
        tvb, offset, 2, ENC_LITTLE_ENDIAN, &datalen);
    offset += 2;
    command = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    if (command == Z21_LAN_X_BC) {
        proto_tree_add_boolean(z21_tree, hf_z21_x_bus, tvb, offset, 2, true);
        /* Note that we do not increment the offset yet */

        /* Strategy:
         * 1. Read two bytes of the data (as big-endian)
         * 2. Prepend it with 0x4000 (the header bytes for X-BUS)
         * 3. If the three MSBs are one of the "one-byte commands",
         *    set x_bus_command accordingly and run with that
         * 4. Otherwise run with "two-byte commands"...
         * 5. ... except that there are some commands that need more data to
         *    determine the exact command (as their two "command bytes" are the
         *    same), so check for those and set x_bus_command manually for them.
         */
        temp_uint = 0x40000000 + tvb_get_uint16(tvb, offset+2, ENC_BIG_ENDIAN);
        unsigned x_bus_command = temp_uint >> 8;
        /* Check for all the "one-byte" commands */
        if (x_bus_command == Z21_LAN_X_SET_STOP ||
            x_bus_command == Z21_LAN_X_SET_LOCO_E_STOP ||
            x_bus_command == Z21_LAN_X_GET_EXT_ACCESSORY_INFO ||
            x_bus_command == Z21_LAN_X_SET_EXT_ACCESSORY ||
            x_bus_command == Z21_LAN_X_GET_TURNOUT_INFO ||
            x_bus_command == Z21_LAN_X_SET_TURNOUT ||
            x_bus_command == Z21_LAN_X_LOCO_INFO) {
            /* Initialize the checksum without the 0x4000 prefix */
            calculated_checksum = x_bus_command & 0xff;
            /* Check for these that are actually another command */
            if (x_bus_command == Z21_LAN_X_GET_TURNOUT_INFO && datalen == 9) {
                x_bus_command = Z21_LAN_X_TURNOUT_INFO;
            } else if (x_bus_command == Z21_LAN_X_GET_EXT_ACCESSORY_INFO && datalen == 10) {
                x_bus_command = Z21_LAN_X_EXT_ACCESSORY_INFO;
            }
            command_ti = proto_tree_add_uint(z21_tree, hf_z21_command, tvb, offset, 3, x_bus_command);
            offset += 3;
        }
        else {
            /* First assume "two-byte command", then check for exceptions */
            x_bus_command = temp_uint;
            if (x_bus_command == Z21_LAN_X_CV_POM_COMMANDS ||
                x_bus_command == Z21_LAN_X_CV_POM_ACCESSORY_COMMANDS) {
                /* Read DB3 from data, get the two interesting bits */
                temp_uint = tvb_get_uint8(tvb, offset + 6) >> 2 & 0x3;
                switch (x_bus_command) {
                case Z21_LAN_X_CV_POM_COMMANDS:
                    if (temp_uint == 0x1)
                        x_bus_command = Z21_LAN_X_CV_POM_READ_BYTE;
                    else if (temp_uint == 0x2)
                        x_bus_command = Z21_LAN_X_CV_POM_WRITE_BIT;
                    else if (temp_uint == 0x3)
                        x_bus_command = Z21_LAN_X_CV_POM_WRITE_BYTE;
                    break;
                case Z21_LAN_X_CV_POM_ACCESSORY_COMMANDS:
                    if (temp_uint == 0x1)
                        x_bus_command = Z21_LAN_X_CV_POM_ACCESSORY_READ_BYTE;
                    else if (temp_uint == 0x2)
                        x_bus_command = Z21_LAN_X_CV_POM_ACCESSORY_WRITE_BIT;
                    else if (temp_uint == 0x3)
                        x_bus_command = Z21_LAN_X_CV_POM_ACCESSORY_WRITE_BYTE;
                    break;
                }
            }
            command_ti = proto_tree_add_uint(z21_tree, hf_z21_command,
                tvb, offset, 4, x_bus_command);
            offset += 4;
            /* Initialize the checksum with the two LSBs */
            calculated_checksum = ((x_bus_command & 0xff00) >> 8) ^ (x_bus_command & 0x00ff);
        }
        update_command_field(command_ti, x_bus_command);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Command=%s",
            val_to_str_const(x_bus_command, z21_command_vals, "unknown"));
        proto_item_append_text(z21_tree, ", Command: %s",
            val_to_str_const(x_bus_command, z21_command_vals, "unknown"));
        switch (x_bus_command) {
        case Z21_LAN_X_STATUS_CHANGED:
            proto_tree_add_bitmask_ret_uint64(z21_tree, tvb, offset, hf_z21_status,
                ett_z21, state_bits_byte1, ENC_NA, &status);
            offset += 1;
            calculated_checksum ^= (unsigned)status;
            break;
        case Z21_LAN_X_SET_LOCO_DRIVE_DCC14:
        case Z21_LAN_X_SET_LOCO_DRIVE_DCC28:
        case Z21_LAN_X_SET_LOCO_DRIVE_DCC128:
            address_bytes = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            addr = address_bytes & 0x3FFF;
            proto_tree_add_uint(z21_tree, hf_z21_loco_address, tvb, offset, 2, addr);
            switch (x_bus_command) {
            case Z21_LAN_X_SET_LOCO_DRIVE_DCC14: speed_steps = 14; break;
            case Z21_LAN_X_SET_LOCO_DRIVE_DCC28: speed_steps = 28; break;
            case Z21_LAN_X_SET_LOCO_DRIVE_DCC128: speed_steps = 128; break;
            }
            proto_tree_add_uint(z21_tree, hf_z21_speed_steps, tvb, offset-1, 1, speed_steps);
            offset += 2;
            calculated_checksum ^= address_bytes >> 8;
            calculated_checksum ^= address_bytes & 0xFF;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Loco=%d (%d SS)",
                addr, speed_steps);
            temp_ti = proto_tree_add_bitmask_ret_uint64(z21_tree, tvb, offset, hf_z21_loco_direction_and_speed,
                ett_z21, speed_bits, ENC_NA, &direction_and_speed);
            offset += 1;
            calculated_checksum ^= (unsigned)direction_and_speed;
            if (direction_and_speed & 0x80) {
                proto_item_set_text(temp_ti,
                    "Locomotive direction and speed: Forward, 0x%02" PRIx64,
                    direction_and_speed & 0x7F);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Forward");
            }
            else {
                proto_item_set_text(temp_ti,
                    "Locomotive direction and speed: Reverse, 0x%02" PRIx64,
                    direction_and_speed & 0x7F);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Reverse");
            }
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Speed=0x%02" PRIx64,
                direction_and_speed & 0x7F);
            break;
        case Z21_LAN_X_GET_LOCO_INFO:
            address_bytes = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            addr = address_bytes & 0x3FFF;
            proto_tree_add_uint(z21_tree, hf_z21_loco_address, tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= address_bytes >> 8;
            calculated_checksum ^= address_bytes & 0xFF;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Loco=%d", addr);
            break;
        case Z21_LAN_X_LOCO_INFO:
            address_bytes = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            addr = address_bytes & 0x3FFF;
            proto_tree_add_uint(z21_tree, hf_z21_loco_address, tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= address_bytes >> 8;
            calculated_checksum ^= address_bytes & 0xFF;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Loco=%d", addr);
            proto_item_append_text(z21_tree, ", Loco: %d", addr);

            proto_tree_add_bitmask_list_ret_uint64(z21_tree, tvb, offset, 1,
                loco_info_bits1, ENC_NA, &temp_guint64);
            offset += 1;
            calculated_checksum ^= temp_guint64;
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                val_to_str_const((uint32_t)temp_guint64 & 0x07,
                    z21_loco_info_speed_steps_vals, "unknown"));

            proto_tree_add_bitmask_list_ret_uint64(z21_tree, tvb, offset, 1,
                loco_info_bits2, ENC_NA, &temp_guint64);
            offset += 1;
            calculated_checksum ^= temp_guint64;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                tfs_get_string((bool)(temp_guint64 >> 7), &tfs_forward_reverse));
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Speed=0x%02" PRIx64,
                temp_guint64 & 0x7f);

            proto_tree_add_bitmask_list_ret_uint64(z21_tree, tvb, offset, 1,
                loco_info_bits3, ENC_NA, &temp_guint64);
            offset += 1;
            calculated_checksum ^= temp_guint64;
            if (temp_guint64 & 0x40) {
                col_append_str(pinfo->cinfo, COL_INFO, ", in double traction");
            }

            proto_tree_add_bitmask_list_ret_uint64(z21_tree, tvb, offset, 1,
                loco_info_bits4, ENC_NA, &temp_guint64);
            offset += 1;
            calculated_checksum ^= temp_guint64;

            proto_tree_add_bitmask_list_ret_uint64(z21_tree, tvb, offset, 1,
                loco_info_bits5, ENC_NA, &temp_guint64);
            offset += 1;
            calculated_checksum ^= temp_guint64;

            /* The following bytes are not always there it seems */
            if (offset < datalen-1) {
                proto_tree_add_bitmask_list_ret_uint64(z21_tree, tvb, offset, 1,
                    loco_info_bits6, ENC_NA, &temp_guint64);
                offset += 1;
                calculated_checksum ^= temp_guint64;
            }
            if (offset < datalen-1) {
                proto_tree_add_bitmask_list_ret_uint64(z21_tree, tvb, offset, 1,
                    loco_info_bits7, ENC_NA, &temp_guint64);
                offset += 1;
                calculated_checksum ^= temp_guint64;
            }
            /* If still something, dissect as bytes */
            if (offset < datalen-1) {
                proto_tree_add_item(z21_tree, hf_z21_loco_info_extensions,
                    tvb, offset, datalen-1-offset, ENC_NA);
                /* Note: Do not increment offset because the checksum
                 * will be calculated below! */
            }
            break;
        case Z21_LAN_X_PURGE_LOCO:
            address_bytes = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            addr = address_bytes & 0x3FFF;
            proto_tree_add_uint(z21_tree, hf_z21_loco_address, tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= address_bytes >> 8;
            calculated_checksum ^= address_bytes & 0xFF;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Loco=%d", addr);
            proto_item_append_text(z21_tree, ", Loco: %d", addr);
            break;
        case Z21_LAN_X_SET_LOCO_E_STOP:
            address_bytes = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            addr = address_bytes & 0x3FFF;
            proto_tree_add_uint(z21_tree, hf_z21_loco_address, tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= address_bytes >> 8;
            calculated_checksum ^= address_bytes & 0xFF;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Loco=%d", addr);
            proto_item_append_text(z21_tree, ", Loco: %d", addr);
            break;
        case Z21_LAN_X_SET_LOCO_BINARY_STATE:
            col_append_str(pinfo->cinfo, COL_INFO, ", TO BE COMPLETED");
            break;
        case Z21_LAN_X_SET_LOCO_FUNCTION:
            address_bytes = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            addr = address_bytes & 0x3FFF;
            proto_tree_add_uint(z21_tree, hf_z21_loco_address, tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= address_bytes >> 8;
            calculated_checksum ^= address_bytes & 0xFF;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Loco=%d", addr);
            proto_item_append_text(z21_tree, ", Loco: %d", addr);
            proto_tree_add_bitmask_list_ret_uint64(z21_tree, tvb, offset, 1,
                loco_func_bits, ENC_NA, &temp_guint64);
            offset += 1;
            calculated_checksum ^= temp_guint64;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Function=%" PRIu64 ", State=%s",
                temp_guint64 & 0x3f,
                val_to_str_const((uint32_t)temp_guint64 >> 6, z21_loco_func_vals, "unknown"));
            proto_item_append_text(z21_tree, ", Function: %" PRIu64 ", State: %s",
                temp_guint64 & 0x3f,
                val_to_str_const((uint32_t)temp_guint64 >> 6, z21_loco_func_vals, "unknown"));
            break;
        case Z21_LAN_X_GET_TURNOUT_INFO:
            addr = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(z21_tree, hf_z21_function_address,
                tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= addr >> 8;
            calculated_checksum ^= addr & 0xFF;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Function=%d", addr);
            proto_item_append_text(z21_tree, ", Function: %d", addr);
            break;
        case Z21_LAN_X_TURNOUT_INFO:
            addr = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(z21_tree, hf_z21_function_address,
                tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= addr >> 8;
            calculated_checksum ^= addr & 0xFF;
            proto_tree_add_bitmask_list_ret_uint64(z21_tree, tvb, offset, 1,
                turnout_state_bits, ENC_NA, &temp_guint64);
            offset += 1;
            calculated_checksum ^= temp_guint64;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Address=%d, State=%s",
                addr,
                val_to_str_const((uint32_t)temp_guint64 & 0x03, z21_turnout_state_vals, "unknown"));
            proto_item_append_text(z21_tree, ", Address: %d, State: %s",
                addr,
                val_to_str_const((uint32_t)temp_guint64 & 0x03, z21_turnout_state_vals, "unknown"));
            break;
        case Z21_LAN_X_SET_TURNOUT:
            addr = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(z21_tree, hf_z21_function_address,
                tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= addr >> 8;
            calculated_checksum ^= addr & 0xFF;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Address=%d", addr);
            proto_item_append_text(z21_tree, ", Address: %d", addr);
            proto_tree_add_bitmask_list_ret_uint64(z21_tree, tvb, offset, 1,
                turnout_set_bits, ENC_NA, &temp_guint64);
            offset += 1;
            calculated_checksum ^= temp_guint64;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Address=%d, %s, Output=%s",
                addr,
                tfs_get_string((bool)(temp_guint64 & 0x08), &tfs_turnout_command),
                tfs_get_string((bool)(temp_guint64 & 0x01), &tfs_turnout_output));
            proto_item_append_text(z21_tree, ", Address: %d, %s, Output: %s",
                addr,
                tfs_get_string((bool)(temp_guint64 & 0x08), &tfs_turnout_command),
                tfs_get_string((bool)(temp_guint64 & 0x01), &tfs_turnout_output));
            break;
        case Z21_LAN_X_GET_EXT_ACCESSORY_INFO:
            addr = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(z21_tree, hf_z21_accessory_address,
                tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= addr >> 8;
            calculated_checksum ^= addr & 0xFF;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Address=%d", addr);
            proto_item_append_text(z21_tree, ", Address: %d", addr);
            break;
        case Z21_LAN_X_EXT_ACCESSORY_INFO:
            addr = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(z21_tree, hf_z21_accessory_address,
                tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= addr >> 8;
            calculated_checksum ^= addr & 0xFF;
            temp_uint = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(z21_tree, hf_z21_accessory_state,
                tvb, offset, 1, temp_uint >> 8);
            offset += 1;
            calculated_checksum ^= temp_uint >> 8;
            proto_tree_add_uint(z21_tree, hf_z21_accessory_status,
                tvb, offset, 1, temp_uint & 0xff);
            offset += 1;
            calculated_checksum ^= temp_uint & 0xff;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Address=%d, State=%d, Status=0x%02x",
                addr, temp_uint >> 8, temp_uint & 0xff);
            proto_item_append_text(z21_tree, ", Address: %d, State: %d, Status: 0x%02x",
                addr, temp_uint >> 8, temp_uint & 0xff);
            break;
        case Z21_LAN_X_SET_EXT_ACCESSORY:
            addr = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(z21_tree, hf_z21_accessory_address,
                tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= addr >> 8;
            calculated_checksum ^= addr & 0xFF;
            temp_uint = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint(z21_tree, hf_z21_accessory_state,
                tvb, offset, 1, temp_uint);
            offset += 1;
            calculated_checksum ^= temp_uint;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Address=%d, State=%d",
                addr, temp_uint);
            proto_item_append_text(z21_tree, ", Address: %d, State: %d",
                addr, temp_uint);
            break;
        case Z21_LAN_X_CV_READ:
            cv_addr = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            /* CV addresses are 1-based, update checksum first */
            calculated_checksum ^= cv_addr >> 8;
            calculated_checksum ^= cv_addr & 0xFF;
            cv_addr += 1;
            proto_tree_add_uint(z21_tree, hf_z21_cv_address,
                tvb, offset, 2, cv_addr);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", CV%d", cv_addr);
            proto_item_append_text(z21_tree, ", CV%d", cv_addr);
            break;
        case Z21_LAN_X_CV_WRITE:
            cv_addr = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            /* CV addresses are 1-based, update checksum first */
            calculated_checksum ^= cv_addr >> 8;
            calculated_checksum ^= cv_addr & 0xFF;
            cv_addr += 1;
            proto_tree_add_uint(z21_tree, hf_z21_cv_address,
                tvb, offset, 2, cv_addr);
            offset += 2;
            temp_uint = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint(z21_tree, hf_z21_cv_value,
                tvb, offset, 1, temp_uint);
            offset += 1;
            calculated_checksum ^= temp_uint;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", CV%d, Value=%d",
                cv_addr, temp_uint);
            proto_item_append_text(z21_tree, ", CV%d, Value: %d",
                cv_addr, temp_uint);
            break;
        case Z21_LAN_X_CV_RESULT:
            cv_addr = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            /* CV addresses are 1-based, update checksum first */
            calculated_checksum ^= cv_addr >> 8;
            calculated_checksum ^= cv_addr & 0xFF;
            cv_addr += 1;
            proto_tree_add_uint(z21_tree, hf_z21_cv_address,
                tvb, offset, 2, cv_addr);
            offset += 2;
            temp_uint = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint(z21_tree, hf_z21_cv_value,
                tvb, offset, 1, temp_uint);
            offset += 1;
            calculated_checksum ^= temp_uint;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", CV%d, Value=%d",
                cv_addr, temp_uint);
            proto_item_append_text(z21_tree, ", CV%d, Value: %d",
                cv_addr, temp_uint);
            break;
        case Z21_LAN_X_CV_POM_WRITE_BYTE:
            address_bytes = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            addr = address_bytes & 0x3FFF;
            proto_tree_add_uint(z21_tree, hf_z21_loco_address, tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= address_bytes >> 8;
            calculated_checksum ^= address_bytes & 0xFF;
            temp_uint = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            calculated_checksum ^= temp_uint >> 8;
            calculated_checksum ^= temp_uint & 0xff;
            proto_tree_add_uint(z21_tree, hf_z21_pom_operation,
                tvb, offset, 1, temp_uint >> 2);
            cv_addr = (temp_uint & 0x03ff) + 1;
            proto_tree_add_uint(z21_tree, hf_z21_cv_address,
                tvb, offset, 2, cv_addr);
            offset += 2;
            proto_tree_add_item_ret_uint(z21_tree, hf_z21_cv_value,
                tvb, offset, 1, ENC_NA, &temp_uint);
            offset += 1;
            calculated_checksum ^= temp_uint;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Loco=%d, CV%d, Value=%d",
                addr, cv_addr, temp_uint);
            proto_item_append_text(z21_tree, ", Loco: %d, CV%d, Value: %d",
                addr, cv_addr, temp_uint);
            break;
        case Z21_LAN_X_CV_POM_WRITE_BIT:
            address_bytes = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            addr = address_bytes & 0x3FFF;
            proto_tree_add_uint(z21_tree, hf_z21_loco_address, tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= address_bytes >> 8;
            calculated_checksum ^= address_bytes & 0xFF;
            temp_uint = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            calculated_checksum ^= temp_uint >> 8;
            calculated_checksum ^= temp_uint & 0xff;
            proto_tree_add_uint(z21_tree, hf_z21_pom_operation,
                tvb, offset, 1, temp_uint >> 2);
            cv_addr = (temp_uint & 0x03ff) + 1;
            proto_tree_add_uint(z21_tree, hf_z21_cv_address,
                tvb, offset, 2, cv_addr);
            offset += 2;
            proto_tree_add_bitmask_list_ret_uint64(z21_tree, tvb, offset, 1,
                cv_bits, ENC_NA, &temp_guint64);
            offset += 1;
            calculated_checksum ^= (unsigned)temp_guint64;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Loco=%d, CV%d, Bit position=%" PRIu64 ", Value=%" PRIu64,
                addr, cv_addr, temp_guint64 & 0x07, temp_guint64 >> 3 & 0x01);
            proto_item_append_text(z21_tree, ", Loco: %d, CV%d, Bit position: %" PRIu64 ", Value: %" PRIu64,
                addr, cv_addr, temp_guint64 & 0x07, temp_guint64 >> 3 & 0x01);
            break;
        case Z21_LAN_X_CV_POM_READ_BYTE:
            address_bytes = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            addr = address_bytes & 0x3FFF;
            proto_tree_add_uint(z21_tree, hf_z21_loco_address, tvb, offset, 2, addr);
            offset += 2;
            calculated_checksum ^= address_bytes >> 8;
            calculated_checksum ^= address_bytes & 0xFF;
            temp_uint = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            calculated_checksum ^= temp_uint >> 8;
            calculated_checksum ^= temp_uint & 0xff;
            proto_tree_add_uint(z21_tree, hf_z21_pom_operation,
                tvb, offset, 1, temp_uint >> 2);
            cv_addr = (temp_uint & 0x03ff) + 1;
            proto_tree_add_uint(z21_tree, hf_z21_cv_address,
                tvb, offset, 2, cv_addr);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Loco=%d, CV%d",
                addr, cv_addr);
            proto_item_append_text(z21_tree, ", Loco: %d, CV%d",
                addr, cv_addr);
            break;
        case Z21_LAN_X_CV_POM_ACCESSORY_WRITE_BYTE:
        case Z21_LAN_X_CV_POM_ACCESSORY_WRITE_BIT:
        case Z21_LAN_X_CV_POM_ACCESSORY_READ_BYTE:
            col_append_fstr(pinfo->cinfo, COL_INFO, ", *** TO BE COMPLETED ***");
            break;
        case Z21_LAN_X_DCC_READ_REGISTER:
            temp_uint = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint(z21_tree, hf_z21_register,
                tvb, offset, 1, temp_uint);
            offset += 1;
            calculated_checksum ^= temp_uint;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Register%d",
                temp_uint);
            proto_item_append_text(z21_tree, ", Register%d",
                temp_uint);
            break;
        case Z21_LAN_X_DCC_WRITE_REGISTER:
            temp_uint = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(z21_tree, hf_z21_register,
                tvb, offset, 1, temp_uint >> 8);
            offset += 1;
            calculated_checksum ^= temp_uint >> 8;
            proto_tree_add_uint(z21_tree, hf_z21_register_value,
                tvb, offset, 1, temp_uint & 0xff);
            offset += 1;
            calculated_checksum ^= temp_uint & 0xff;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Register%d, Value=%d",
                temp_uint >> 8, temp_uint & 0xff);
            proto_item_append_text(z21_tree, ", Register%d, Value: %d",
                temp_uint >> 8, temp_uint & 0xff);
            break;
        case Z21_LAN_X_MM_WRITE_BYTE:
            /* Skip one zero byte */
            offset += 1;
            temp_uint = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(z21_tree, hf_z21_register,
                tvb, offset, 1, temp_uint >> 8);
            offset += 1;
            calculated_checksum ^= temp_uint >> 8;
            proto_tree_add_uint(z21_tree, hf_z21_register_value,
                tvb, offset, 1, temp_uint & 0xff);
            offset += 1;
            calculated_checksum ^= temp_uint & 0xff;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Register%d, Value=%d",
                temp_uint >> 8, temp_uint & 0xff);
            proto_item_append_text(z21_tree, ", Register%d, Value: %d",
                temp_uint >> 8, temp_uint & 0xff);
            break;
        case Z21_LAN_X_GET_FIRMWARE_VERSION_REPLY:
            version = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            buffer = wmem_strdup_printf(pinfo->pool, "%x.%02x",
                version >> 8, version & 0xff);
            proto_tree_add_string(z21_tree, hf_z21_firmware_version,
                tvb, offset, 2, buffer);
            offset += 2;
            calculated_checksum ^= version >> 8;
            calculated_checksum ^= version & 0xFF;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Version=%s",
                buffer);
        }

        /* Calculate checksum for the rest of the bytes (if any) for now */
        while (offset < datalen-1) {
            one_byte = tvb_get_uint8(tvb, offset);
            offset += 1;
            calculated_checksum ^= one_byte;
        }
        /* No more data in the X-BUS command, read the checksum */
        temp_ti = proto_tree_add_item_ret_uint(z21_tree, hf_z21_checksum,
            tvb, offset, 1, ENC_NA, &checksum);
        if (checksum != calculated_checksum) {
            expert_add_info_format(pinfo, temp_ti, &ei_z21_invalid_checksum,
                "Invalid checksum, calculated: 0x%02x", calculated_checksum);
        }
    }
    else {
        /* Not X-BUS */
        command_ti = proto_tree_add_uint(z21_tree, hf_z21_command,
            tvb, offset, 2, command);
        offset += 2;
        update_command_field(command_ti, command);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Command=%s",
            val_to_str_const(command, z21_command_vals, "unknown"));
        proto_item_append_text(z21_tree, ", Command: %s",
            val_to_str_const(command, z21_command_vals, "unknown"));
        switch (command) {
        case Z21_LAN_GET_SERIAL_NUMBER:
            if (datalen == 8) {
                unsigned serial;
                proto_tree_add_item_ret_uint(z21_tree, hf_z21_serial_number,
                    tvb, offset, 4, ENC_LITTLE_ENDIAN, &serial);
                offset += 4;
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Serial number: %d",
                    serial);
            }
            break;
        case Z21_LAN_SYSTEMSTATE_DATACHANGED:
            main_current = tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_int_format_value(z21_tree, hf_z21_main_current,
                tvb, offset, 2, main_current, "%d mA", main_current);
            offset += 2;

            temp_gint32 = tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_int_format_value(z21_tree, hf_z21_prog_current,
                tvb, offset, 2, temp_gint32, "%d mA", temp_gint32);
            offset += 2;

            temp_gint32 = tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_int_format_value(z21_tree, hf_z21_filtered_main_current,
                tvb, offset, 2, temp_gint32, "%d mA", temp_gint32);
            offset += 2;

            temp_gint32 = tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_int_format_value(z21_tree, hf_z21_temperature,
                tvb, offset, 2, temp_gint32, "%d°C", temp_gint32);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO,
                ", Temperature=%d°C", temp_gint32);

            temp_uint = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
            temp_float = (float)temp_uint / 1000;
            proto_tree_add_float_format_value(z21_tree, hf_z21_supply_voltage,
                tvb, offset, 2, temp_float, "%.3f V", temp_float);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO,
                ", Track=%.3f V/%d mA", temp_float, main_current);

            temp_uint = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
            temp_float = (float)temp_uint / 1000;
            proto_tree_add_float_format_value(z21_tree, hf_z21_track_voltage,
                tvb, offset, 2, temp_float, "%.3f V", temp_float);
            offset += 2;

            proto_tree_add_bitmask(z21_tree, tvb, offset, hf_z21_central_state,
                ett_z21, state_bits_byte1, ENC_NA);
            offset += 1;
            proto_tree_add_bitmask(z21_tree, tvb, offset, hf_z21_central_state_ex,
                ett_z21, state_bits_byte2, ENC_NA);
            offset += 1;
            proto_tree_add_item(z21_tree, hf_z21_systemstate_reserved,
                tvb, offset, 1, ENC_NA);
            offset += 1;
            temp_uint = tvb_get_uint8(tvb, offset);
            if (temp_uint == 0) {
                /* Don't interpret the flags */
                proto_tree_add_uint_format_value(z21_tree, hf_z21_capabilities,
                tvb, offset, 1, 0, "0x00 (Capability flags not supported)");
            }
            else {
                proto_tree_add_bitmask(z21_tree, tvb, offset, hf_z21_capabilities,
                    ett_z21, capability_bits, ENC_NA);
            }
            offset += 1;
            break;
        case Z21_LAN_RMBUS_GETDATA:
            proto_tree_add_item_ret_uint(z21_tree, hf_z21_rmbus_group,
                tvb, offset, 1, ENC_NA, &temp_uint);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Group=%d", temp_uint);
            proto_item_append_text(z21_tree, ", Group: %d", temp_uint);
            break;
        case Z21_LAN_RMBUS_DATACHANGED:
            proto_tree_add_item_ret_uint(z21_tree, hf_z21_rmbus_group,
                tvb, offset, 1, ENC_NA, &temp_uint);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Group=%d", temp_uint);
            proto_item_append_text(z21_tree, ", Group: %d", temp_uint);
            proto_tree_add_item(z21_tree, hf_z21_rmbus_feedbacks, tvb, offset, 10, ENC_NA);
            offset += 10;
            break;
        case Z21_LAN_RMBUS_PROGRAMMODULE:
            proto_tree_add_item_ret_uint(z21_tree, hf_z21_rmbus_address,
                tvb, offset, 1, ENC_NA, &temp_uint);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Address=%d", temp_uint);
            proto_item_append_text(z21_tree, ", Address: %d", temp_uint);
            offset += 1;
            break;
        case Z21_LAN_RAILCOM_DATACHANGED:
            proto_tree_add_item_ret_uint(z21_tree, hf_z21_loco_address,
                tvb, offset, 2, ENC_LITTLE_ENDIAN, &temp_uint);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Loco=%d", temp_uint);
            proto_item_append_text(z21_tree, ", Loco: %d", temp_uint);
            proto_tree_add_item(z21_tree, hf_z21_railcom_receive_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(z21_tree, hf_z21_railcom_error_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(z21_tree, hf_z21_railcom_reserved1, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(z21_tree, hf_z21_railcom_options, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(z21_tree, hf_z21_railcom_speed, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(z21_tree, hf_z21_railcom_qos, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(z21_tree, hf_z21_railcom_reserved2, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case Z21_LAN_RAILCOM_GETDATA:
            proto_tree_add_item(z21_tree, hf_z21_railcom_type, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(z21_tree, hf_z21_loco_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case Z21_LAN_LOCONET_FROM_LAN:
        case Z21_LAN_LOCONET_Z21_RX:
        case Z21_LAN_LOCONET_Z21_TX:
            proto_tree_add_item(z21_tree, hf_z21_loconet_message,
                tvb, offset, datalen-4, ENC_NA);
            offset += datalen-4;
            break;
        case Z21_LAN_LOCONET_DISPATCH_ADDR:
            proto_tree_add_item_ret_uint(z21_tree, hf_z21_loco_address,
                tvb, offset, 2, ENC_LITTLE_ENDIAN, &temp_uint);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Loco=%d", temp_uint);
            proto_item_append_text(z21_tree, ", Loco: %d", temp_uint);
            if (datalen > 6) {
                /* Response from Z21 */
                proto_tree_add_item(z21_tree, hf_z21_loconet_result, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            break;
        case Z21_LAN_LOCONET_DETECTOR:
            proto_tree_add_item(z21_tree, hf_z21_loconet_type, tvb, offset, 1, ENC_NA);
            offset += 1;
            if (datalen == 7) {
                /* This is request */
                proto_tree_add_item(z21_tree, hf_z21_loconet_report_address,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
            else {
                /* This is reply */
                proto_tree_add_item(z21_tree, hf_z21_loconet_feedback_address,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(z21_tree, hf_z21_loconet_info,
                    tvb, offset, datalen-7, ENC_NA);
                offset += datalen-7;
            }
            break;
        case Z21_LAN_CAN_DETECTOR:
            if (datalen == 7) {
                /* This is request */
                proto_tree_add_item(z21_tree, hf_z21_can_type, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item_ret_uint(z21_tree, hf_z21_can_network_id,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN, &temp_uint);
                offset += 2;
                col_append_fstr(pinfo->cinfo, COL_INFO, ", NetworkID=%d", temp_uint);
                proto_item_append_text(z21_tree, ", NetworkID: %d", temp_uint);
            }
            else {
                /* This is reply */
                proto_tree_add_item_ret_uint(z21_tree, hf_z21_can_network_id,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN, &temp_uint);
                offset += 2;
                col_append_fstr(pinfo->cinfo, COL_INFO, ", NetworkID=%d", temp_uint);
                proto_item_append_text(z21_tree, ", NetworkID: %d", temp_uint);
                proto_tree_add_item(z21_tree, hf_z21_can_module_address,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(z21_tree, hf_z21_can_port, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(z21_tree, hf_z21_can_type, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(z21_tree, hf_z21_can_value1,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(z21_tree, hf_z21_can_value2,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
            break;
        case Z21_LAN_CAN_DEVICE_GET_DESCRIPTION:
        case Z21_LAN_CAN_DEVICE_SET_DESCRIPTION:
            proto_tree_add_item_ret_uint(z21_tree, hf_z21_can_network_id,
                tvb, offset, 2, ENC_LITTLE_ENDIAN, &temp_uint);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", NetworkID=%d", temp_uint);
            proto_item_append_text(z21_tree, ", NetworkID: %d", temp_uint);
            if (datalen > 6) {
                proto_tree_add_item(z21_tree, hf_z21_can_booster_name,
                    tvb, offset, 16, ENC_ISO_8859_1);
                offset += 16;
            }
            break;
        case Z21_LAN_CAN_BOOSTER_SYSTEMSTATE_CHGD:
            proto_tree_add_item_ret_uint(z21_tree, hf_z21_can_network_id,
                tvb, offset, 2, ENC_LITTLE_ENDIAN, &temp_uint);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", NetworkID=%d", temp_uint);
            proto_item_append_text(z21_tree, ", NetworkID: %d", temp_uint);
            proto_tree_add_item(z21_tree, hf_z21_can_booster_output_port,
                tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_bitmask(z21_tree, tvb, offset,
                hf_z21_can_booster_state, ett_z21, booster_state_bits, ENC_LITTLE_ENDIAN);
            offset += 2;
            temp_uint = tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_uint_format_value(z21_tree, hf_z21_can_booster_vcc,
                tvb, offset, 2, temp_uint, "%d mV", temp_uint);
            offset += 2;
            temp_uint = tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN);
            proto_tree_add_uint_format_value(z21_tree, hf_z21_can_booster_current,
                tvb, offset, 2, temp_uint, "%d mA", temp_uint);
            offset += 2;
            break;
        case Z21_LAN_CAN_BOOSTER_SET_TRACKPOWER:
            proto_tree_add_item_ret_uint(z21_tree, hf_z21_can_network_id,
                tvb, offset, 2, ENC_LITTLE_ENDIAN, &temp_uint);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", NetworkID=%d", temp_uint);
            proto_item_append_text(z21_tree, ", NetworkID: %d", temp_uint);
            proto_tree_add_item(z21_tree, hf_z21_can_booster_power, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case Z21_LAN_ZLINK_GET_HWINFO:
            proto_tree_add_item(z21_tree, hf_z21_zlink_message_type, tvb, offset, 1, ENC_NA);
            offset += 1;
            if (datalen > 5) {
                proto_tree_add_item(z21_tree, hf_z21_zlink_hwid,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(z21_tree, hf_z21_zlink_fw_major, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(z21_tree, hf_z21_zlink_fw_minor, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(z21_tree, hf_z21_zlink_fw_build, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(z21_tree, hf_z21_zlink_mac, tvb, offset, 18, ENC_ASCII);
                offset += 18;
                proto_tree_add_item(z21_tree, hf_z21_zlink_name, tvb, offset, 33, ENC_ISO_8859_1);
                offset += 18;
                proto_tree_add_item(z21_tree, hf_z21_zlink_reserved, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            break;
        case Z21_LAN_BOOSTER_GET_DESCRIPTION:
        case Z21_LAN_BOOSTER_SET_DESCRIPTION:
            if (datalen > 4) {
                /* SET_DESCRIPTION or reply to GET_DESCRIPTION */
                uint8_t *buf = tvb_get_stringz_enc(pinfo->pool, tvb, offset, NULL, ENC_ISO_8859_1);
                if (buf[0] == 0xff) {
                    /* Interpreted as an empty name */
                    proto_tree_add_string(z21_tree, hf_z21_booster_name, tvb, offset, 32, "");
                }
                else {
                    proto_tree_add_string(z21_tree, hf_z21_booster_name, tvb, offset, 32, buf);
                }
                offset += 32;
            }
            break;
        case Z21_LAN_BOOSTER_SYSTEMSTATE_GETDATA:
        case Z21_LAN_DECODER_SYSTEMSTATE_GETDATA:
            break;
        case Z21_LAN_DECODER_GET_DESCRIPTION:
        case Z21_LAN_DECODER_SET_DESCRIPTION:
            if (datalen > 4) {
                /* SET_DESCRIPTION or reply to GET_DESCRIPTION */
                uint8_t *buf = tvb_get_stringz_enc(pinfo->pool, tvb, offset, NULL, ENC_ISO_8859_1);
                if (buf[0] == 0xff) {
                    /* Interpreted as an empty name */
                    proto_tree_add_string(z21_tree, hf_z21_decoder_name, tvb, offset, 32, "");
                }
                else {
                    proto_tree_add_string(z21_tree, hf_z21_decoder_name, tvb, offset, 32, buf);
                }
                offset += 32;
            }
            break;
        case Z21_LAN_BOOSTER_SET_POWER:
            proto_tree_add_item_ret_uint(z21_tree, hf_z21_booster_port,
                tvb, offset, 1, ENC_NA, &temp_uint);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Port=%d", temp_uint);
            proto_item_append_text(z21_tree, ", Port: %d", temp_uint);
            proto_tree_add_item_ret_uint(z21_tree, hf_z21_booster_port_state,
                tvb, offset, 1, ENC_NA, &temp_uint);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", State=%d", temp_uint);
            proto_item_append_text(z21_tree, ", State: %d", temp_uint);
            break;
        case Z21_LAN_BOOSTER_SYSTEMSTATE_DATACHANGED:
            /* To be expanded later... */
            proto_tree_add_item(z21_tree, hf_z21_booster_state_data,
                tvb, offset, 24, ENC_NA);
            offset += 24;
            break;
        case Z21_LAN_DECODER_SYSTEMSTATE_DATACHANGED:
            /* To be expanded later... */
            /* Data is variable length */
            proto_tree_add_item(z21_tree, hf_z21_decoder_state_data,
                tvb, offset, datalen-4, ENC_NA);
            offset += datalen-4;
            break;
        case Z21_LAN_GET_LOCOMODE:
        case Z21_LAN_SET_LOCOMODE:
            address_bytes = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            addr = address_bytes & 0x3FFF;
            proto_tree_add_uint(z21_tree, hf_z21_loco_address, tvb, offset, 2, addr);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Loco=%d", addr);
            if (datalen > 6) {
                unsigned mode = tvb_get_uint8(tvb, offset);
                proto_tree_add_uint(z21_tree, hf_z21_loco_mode, tvb, offset, 1, mode);
                offset += 1;
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Mode: %d", mode);
            }
            break;
        case Z21_LAN_GET_BROADCASTFLAGS:
        case Z21_LAN_SET_BROADCASTFLAGS:
            if (datalen == 8) {
                proto_tree_add_bitmask_with_flags(z21_tree, tvb, offset, hf_z21_broadcast_flags,
                    ett_z21, broadcast_flags_bits, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
                offset += 4;
            }
            break;
        case Z21_LAN_GET_HWINFO:
            if (datalen == 12) {
                unsigned hwtype = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(z21_tree, hf_z21_hw_type, tvb, offset, 1, hwtype);
                offset += 4;
                version = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
                buffer = wmem_strdup_printf(pinfo->pool, "%x.%02x",
                    version >> 8, version & 0xff);
                proto_tree_add_string(z21_tree, hf_z21_firmware_version,
                    tvb, offset, 2, buffer);
                offset += 4;
            }
            break;
        }
        if (offset < datalen) {
            /* Just dump all the rest, if any */
            proto_tree_add_item(z21_tree, hf_z21_data, tvb, offset, datalen-offset, ENC_NA);
            offset += datalen-offset;
        }
    }
    return offset;
}

static unsigned
get_z21_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
}

static bool
check_z21_header(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    int remaining_length = tvb_reported_length_remaining(tvb, offset);
    if (remaining_length < Z21_MIN_LENGTH) {
        return false;
    }
    int pdu_len = get_z21_pdu_len(pinfo, tvb, offset, data);
    if (pdu_len < Z21_MIN_LENGTH || pdu_len > remaining_length) {
        return false;
    }
    uint16_t command = tvb_get_uint16(tvb, offset + 2, ENC_BIG_ENDIAN);
    if (!try_val_to_str(command, z21_command_vals)) {
        return false;
    }
    return true;
}

static int
dissect_z21(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return udp_dissect_pdus(tvb, pinfo, tree, Z21_MIN_LENGTH,
        check_z21_header, get_z21_pdu_len, dissect_z21_pdu, data);
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_z21(void)
{
    expert_module_t *expert_z21;

    static hf_register_info hf[] = {
        { &hf_z21_datalen,
          { "Data length", "z21.datalen",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_command,
          { "Command", "z21.command",
            FT_UINT32, BASE_HEX|BASE_NO_DISPLAY_VALUE, VALS(z21_command_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_z21_x_bus,
          { "X-BUS", "z21.xbus",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_serial_number,
          { "Serial number", "z21.serialnumber",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_checksum,
          { "Checksum", "z21.checksum",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_main_current,
          { "Main track current", "z21.maincurrent",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_prog_current,
          { "Programming track current", "z21.progcurrent",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_filtered_main_current,
          { "Filtered main track current", "z21.filteredmaincurrent",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_temperature,
          { "Command station temperature", "z21.temperature",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_supply_voltage,
          { "Supply voltage", "z21.supplyvoltage",
            FT_FLOAT, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_track_voltage,
          { "Track voltage", "z21.trackvoltage",
            FT_FLOAT, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags,
          { "Broadcast flags", "z21.broadcastflags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_central_state,
          { "Central state, first byte", "z21.centralstate1",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_central_state_ex,
          { "Central state, second byte", "z21.centralstate2",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_systemstate_reserved,
          { "Reserved", "z21.systemstatereserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_capabilities,
          { "Capabilities", "z21.capabilities",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_status,
          { "Status", "z21.status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags_driving_switching,
          { "Broadcasts messages concerning driving and switching", "z21.broadcastflags.driving_switching",
            FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000001,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags_rmbus,
          { "Changes of the feedback devices on the R-Bus", "z21.broadcastflags.rmbus",
            FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000002,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags_railcom_subscribed,
          { "Changes of RailCom data of subscribed locomotives", "z21.broadcastflags.railcom_subscribed",
            FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000004,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags_system_status,
          { "Changes of the Z21 system status", "z21.broadcastflags.system_status",
            FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000100,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags_driving_switching_ex,
          { "Extends flag 0x00000001, LAN_X_LOCO_INFO is sent for all modified locomotives", "z21.broadcastflags.driving_switching_ex",
            FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00010000,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags_loconet,
          { "Forward messages from LocoNet without locos and switches", "z21.broadcastflags.loconet",
            FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x01000000,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags_loconet_driving,
          { "Forward locomotive-specific LocoNet", "z21.broadcastflags.loconet_driving",
            FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x02000000,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags_loconet_switching,
          { "Forward switch-specific LocoNet", "z21.broadcastflags.loconet_switching",
            FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x04000000,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags_loconet_detector,
          { "Changes of LocoNet track occupancy detectors", "z21.broadcastflags.emergencystop",
            FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x08000000,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags_railcom,
          { "Changes of RailCom data", "z21.broadcastflags.railcom",
            FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00040000,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags_can_detector,
          { "Changes of CAN-Bus track occupancy detectors", "z21.broadcastflags.can_detector",
            FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00080000,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags_can_booster,
          { "Forward CAN-Bus booster status messages", "z21.broadcastflags.can_booster",
            FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00020000,
            NULL, HFILL }
        },
        { &hf_z21_broadcast_flags_fast_clock,
          { "Fast clock time messages", "z21.broadcastflags.fast_clock",
            FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000010,
            NULL, HFILL }
        },
        { &hf_z21_state_emergency_stop,
          { "Emergency stop", "z21.state.emergencystop",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_z21_state_track_voltage_off,
          { "Track voltage off", "z21.state.trackvoltageoff",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_z21_state_short_circuit,
          { "Short circuit", "z21.state.shortcircuit",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_z21_state_programming_mode,
          { "Programming mode", "z21.state.programmingmode",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_z21_state_high_temperature,
          { "High temperature", "z21.state.hightemperature",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_z21_state_power_lost,
          { "Power lost", "z21.state.powerlost",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_z21_state_short_circuit_external,
          { "External short circuit", "z21.state.externalshortcircuit",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_z21_state_short_circuit_internal,
          { "Internal short circuit", "z21.state.internalshortcircuit",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_z21_state_rcn_213,
          { "RCN-213 turnout addressing", "z21.state.rcn213addressing",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_z21_capability_dcc,
          { "DCC capability", "z21.capability.dcc",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_z21_capability_mm,
          { "MM capability", "z21.capability.mm",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_z21_capability_reserved,
          { "Reserved capability", "z21.capability.reserved",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_z21_capability_railcom,
          { "RailCom capability", "z21.capability.railcom",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_z21_capability_loco_cmds,
          { "Accepts LAN commands for locomotive decoders", "z21.capability.lococmds",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_z21_capability_accessory_cmds,
          { "Accepts LAN commands for accessory decoders", "z21.capability.accessorycmds",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_z21_capability_detector_cmds,
          { "Accepts LAN commands for detectors", "z21.capability.detectorcmds",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_z21_capability_needs_unlock_code,
          { "Needs unlock code", "z21.capability.needsunlockcode",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_z21_loco_mode,
          { "Locomotive mode", "z21.locomode",
            FT_UINT8, BASE_DEC, VALS(z21_loco_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_z21_loco_address,
          { "Locomotive address", "z21.locoaddress",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_loco_direction_and_speed,
          { "Locomotive direction and speed", "z21.locodirectionandspeed",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_loco_direction,
          { "Locomotive direction", "z21.locodirection",
            FT_BOOLEAN, 8, TFS(&tfs_forward_reverse), 0x80,
            NULL, HFILL }
        },
        { &hf_z21_loco_speed,
          { "Locomotive speed", "z21.locospeed",
            FT_UINT8, BASE_HEX, NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_mm,
          { "Locomotive is MM (Märklin-Motorola)", "z21.locomm",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_busy,
          { "Locomotive is busy", "z21.locoinfobusy",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            "Locomotive is controlled by another X-BUS handset controller", HFILL }
        },
        { &hf_z21_loco_info_speed_steps,
          { "Locomotive speed steps", "z21.locoinfospeedsteps",
            FT_UINT8, BASE_DEC, VALS(z21_loco_info_speed_steps_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_direction,
          { "Locomotive direction", "z21.locoinfodirection",
            FT_BOOLEAN, 8, TFS(&tfs_forward_reverse), 0x80,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_speed,
          { "Locomotive speed", "z21.locoinfospeed",
            FT_UINT8, BASE_HEX, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_double_traction,
          { "Double traction", "z21.locoinfodoubletraction",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_smartsearch,
          { "Smartsearch", "z21.locoinfosmartsearch",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f0,
          { "Function F0 (lights)", "z21.locoinfof0",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f4,
          { "Function F4", "z21.locoinfof4",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f3,
          { "Function F3", "z21.locoinfof3",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f2,
          { "Function F2", "z21.locoinfof2",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f1,
          { "Function F1", "z21.locoinfof1",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f12,
          { "Function F12", "z21.locoinfof12",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f11,
          { "Function F11", "z21.locoinfof11",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f10,
          { "Function F10", "z21.locoinfof10",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f9,
          { "Function F9", "z21.locoinfof9",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f8,
          { "Function F8", "z21.locoinfof8",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f7,
          { "Function F7", "z21.locoinfof7",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f6,
          { "Function F6", "z21.locoinfof6",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f5,
          { "Function F5", "z21.locoinfof5",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f20,
          { "Function F20", "z21.locoinfof20",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f19,
          { "Function F19", "z21.locoinfof19",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f18,
          { "Function F18", "z21.locoinfof18",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f17,
          { "Function F17", "z21.locoinfof17",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f16,
          { "Function F16", "z21.locoinfof16",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f15,
          { "Function F15", "z21.locoinfof15",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f14,
          { "Function F14", "z21.locoinfof14",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f13,
          { "Function F13", "z21.locoinfof13",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f28,
          { "Function F28", "z21.locoinfof28",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f27,
          { "Function F27", "z21.locoinfof27",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f26,
          { "Function F26", "z21.locoinfof26",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f25,
          { "Function F25", "z21.locoinfof25",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f24,
          { "Function F24", "z21.locoinfof24",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f23,
          { "Function F23", "z21.locoinfof23",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f22,
          { "Function F22", "z21.locoinfof22",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f21,
          { "Function F21", "z21.locoinfof21",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f31,
          { "Function F31", "z21.locoinfof31",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f30,
          { "Function F30", "z21.locoinfof30",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_f29,
          { "Function F29", "z21.locoinfof29",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_z21_loco_info_extensions,
          { "Extensions", "z21.locoinfoextensions",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_speed_steps,
          { "Speed steps", "z21.speedsteps",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_hw_type,
          { "Hardware type", "z21.hwtype",
            FT_UINT32, BASE_HEX, VALS(z21_hw_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_z21_firmware_version,
          { "Firmware version", "z21.firmwareversion",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_loco_func_switch_type,
          { "Locomotive function switch type", "z21.locofunctionswitchtype",
            FT_UINT8, BASE_DEC, VALS(z21_loco_func_vals), 0xc0,
            NULL, HFILL }
        },
        { &hf_z21_loco_func_index,
          { "Locomotive function index", "z21.locofunctionindex",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_z21_function_address,
          { "Function address", "z21.functionaddress",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_turnout_state,
          { "Turnout state", "z21.turnoutstate",
            FT_UINT8, BASE_DEC, VALS(z21_turnout_state_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_z21_turnout_queue_bit,
          { "Queue the turnout command", "z21.turnoutqueue",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_z21_turnout_activate_bit,
          { "Turnout command", "z21.turnoutcommand",
            FT_BOOLEAN, 8, TFS(&tfs_turnout_command), 0x08,
            NULL, HFILL }
        },
        { &hf_z21_turnout_output_bit,
          { "Select turnout output", "z21.turnoutoutput",
            FT_BOOLEAN, 8, TFS(&tfs_turnout_output), 0x01,
            NULL, HFILL }
        },
        { &hf_z21_accessory_address,
          { "Accessory address", "z21.accessoryaddress",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_accessory_state,
          { "Accessory state", "z21.accessorystate",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_accessory_status,
          { "Accessory status", "z21.accessorystatus",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_cv_address,
          { "CV address", "z21.cvaddress",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_cv_value,
          { "CV value", "z21.cvvalue",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_register,
          { "Register", "z21.register",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_register_value,
          { "Register value", "z21.registervalue",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_pom_operation,
          { "POM operation", "z21.pomoperation",
            FT_UINT16, BASE_HEX, VALS(z21_pom_operation_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_z21_cv_bit_position,
          { "CV bit position", "z21.cvbitposition",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_z21_cv_bit_value,
          { "CV bit value", "z21.cvbitvalue",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
            NULL, HFILL }
        },
        { &hf_z21_rmbus_group,
          { "R-BUS group index", "z21.rbusgroup",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_rmbus_feedbacks,
          { "R-BUS feedbacks", "z21.rbusfeedbacks",
            FT_BYTES, BASE_NONE|SEP_SPACE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_rmbus_address,
          { "R-BUS feedback module address", "z21.rbusaddress",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_railcom_receive_counter,
          { "RailCom receive counter", "z21.railcomreceives",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_railcom_error_counter,
          { "RailCom error counter", "z21.railcomerrors",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_railcom_reserved1,
          { "RailCom reserved 1", "z21.railcomreserved1",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_railcom_reserved2,
          { "RailCom reserved 2", "z21.railcomreserved2",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_railcom_options,
          { "RailCom options", "z21.railcomoptions",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_railcom_speed,
          { "RailCom speed", "z21.railcomspeed",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_railcom_qos,
          { "RailCom QoS", "z21.railcomqos",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_railcom_type,
          { "RailCom type", "z21.railcomtype",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_loconet_message,
          { "LocoNet message", "z21.loconetmessage",
            FT_BYTES, BASE_NONE|SEP_SPACE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_loconet_result,
          { "LocoNet result", "z21.loconetresult",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_loconet_type,
          { "LocoNet type", "z21.loconettype",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_loconet_report_address,
          { "LocoNet report address", "z21.loconetreportaddress",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_loconet_feedback_address,
          { "LocoNet feedback address", "z21.loconetfeedbackaddress",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_loconet_info,
          { "LocoNet info", "z21.loconetinfo",
            FT_BYTES, BASE_NONE|SEP_SPACE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_can_type,
          { "CAN type", "z21.cantype",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_can_network_id,
          { "CAN network ID", "z21.cannetworkid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_can_module_address,
          { "CAN module address", "z21.canmoduleaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_can_port,
          { "CAN input port (pin)", "z21.canport",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_can_value1,
          { "CAN value 1", "z21.canvalue1",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_can_value2,
          { "CAN value 2", "z21.canvalue2",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_can_booster_name,
          { "CAN booster name", "z21.canboostername",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_can_booster_output_port,
          { "CAN booster output port", "z21.canboosteroutputport",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_can_booster_state,
          { "CAN booster state", "z21.canboosterstate",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_can_booster_state_bg_active,
          { "CAN booster brake generator active", "z21.canboosterbrakegenerator",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_z21_can_booster_state_short_circuit,
          { "CAN booster short circuit", "z21.canboostershortcircuit",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_z21_can_booster_state_track_voltage_off,
          { "CAN booster track voltage off", "z21.canboostertrackvoltageoff",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_z21_can_booster_state_railcom_active,
          { "CAN booster RailCom cutout active", "z21.canboosterrailcomactive",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_z21_can_booster_state_output_disabled,
          { "CAN booster output disabled", "z21.canboosteroutputdisabled",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_z21_can_booster_vcc,
          { "CAN booster VCC voltage", "z21.canboostervoltage",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_can_booster_current,
          { "CAN booster current", "z21.canboostercurrent",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_can_booster_power,
          { "CAN booster power", "z21.canboosterpower",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_zlink_message_type,
          { "zLink message type", "z21.zlinkmessagetype",
            FT_UINT8, BASE_HEX, VALS(z21_zlink_message_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_z21_zlink_hwid,
          { "zLink hardware ID", "z21.zlinkhwid",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_zlink_fw_major,
          { "zLink firmware major version", "z21.zlinkmajorversion",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_zlink_fw_minor,
          { "zLink firmware minor version", "z21.zlinkminorversion",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_zlink_fw_build,
          { "zLink firmware build version", "z21.zlinkbuildversion",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_zlink_mac,
          { "zLink MAC address", "z21.zlinkmac",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_zlink_name,
          { "zLink name", "z21.zlinkname",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_zlink_reserved,
          { "zLink reserved", "z21.zlinkreserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_booster_name,
          { "Booster name", "z21.boostername",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_booster_port,
          { "Booster port", "z21.boosterport",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_booster_port_state,
          { "Booster port state", "z21.boosterportstate",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_booster_state_data,
          { "Booster state data", "z21.boosterstatedata",
            FT_BYTES, BASE_NONE|SEP_SPACE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_decoder_name,
          { "Decoder name", "z21.decodername",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_decoder_state_data,
          { "Decoder state data", "z21.decoderstatedata",
            FT_BYTES, BASE_NONE|SEP_SPACE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_z21_data,
          { "Undecoded data", "z21.data",
            FT_BYTES, BASE_NONE|SEP_SPACE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_z21,
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_z21_invalid_checksum,
            { "z21.invalidchecksum", PI_CHECKSUM, PI_WARN,
            "Invalid XOR checksum", EXPFILL }
        },
    };

    /* Register the protocol name and description */
    proto_z21 = proto_register_protocol("Z21 LAN Protocol", "Z21", "z21");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_z21, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_z21 = expert_register_protocol(proto_z21);
    expert_register_field_array(expert_z21, ei, array_length(ei));

    z21_handle = register_dissector("z21", dissect_z21, proto_z21);

    /* Register a preferences module (see section 2.6 of README.dissector
     * for more details). Registration of a prefs callback is not required
     * if there are no preferences that affect protocol registration (an example
     * of a preference that would affect registration is a port preference).
     * If the prefs callback is not needed, use NULL instead of
     * proto_reg_handoff_z21 in the following.
     */
    prefs_register_protocol(proto_z21, proto_reg_handoff_z21);
}

void
proto_reg_handoff_z21(void)
{
    static bool initialized = false;

    if (!initialized) {
        dissector_add_uint_range_with_preference("udp.port", Z21_UDP_PORTS, z21_handle);
        initialized = true;
    }
    udp_port_range = prefs_get_range_value("Z21", "udp.port");
}
