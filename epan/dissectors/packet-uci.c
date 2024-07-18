/*
 * Author: Henri Chataing <henrichataing@google.com>
 * Copyright 2022 Google LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Specification: Fira Consortium UWB Command Interface Generic Technical
 *                Specification v1.1.0
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include "packet-tcp.h"
#include <wiretap/wtap.h>

void proto_reg_handoff_uci(void);
void proto_register_uci(void);

#define UCI_PACKET_HEADER_LEN 4

#define UCI_MT_COMMAND 0x01
#define UCI_MT_RESPONSE 0x02
#define UCI_MT_NOTIFICATION 0x03

#define UCI_GID_CORE 0x00
#define UCI_GID_SESSION_CONFIG 0x01
#define UCI_GID_RANGING_SESSION_CONTROL 0x02
#define UCI_GID_DATA_CONTROL 0x03
#define UCI_GID_TEST 0x0d
#define UCI_GID_VENDOR_PICA 0x09
#define UCI_GID_VENDOR_RESERVED_A 0x0a
#define UCI_GID_VENDOR_RESERVED_B 0x0b
#define UCI_GID_VENDOR_RESERVED_C 0x0c
#define UCI_GID_VENDOR_ANDROID 0x0e
#define UCI_GID_VENDOR_RESERVED_F 0x0f

#define UCI_OID_CORE_DEVICE_RESET 0x00
#define UCI_OID_CORE_DEVICE_STATUS_NTF 0x01
#define UCI_OID_CORE_GET_DEVICE_INFO 0x02
#define UCI_OID_CORE_GET_CAPS_INFO 0x03
#define UCI_OID_CORE_SET_CONFIG 0x04
#define UCI_OID_CORE_GET_CONFIG 0x05
#define UCI_OID_CORE_GENERIC_ERROR_NTF 0x07
#define UCI_OID_SESSION_INIT 0x00
#define UCI_OID_SESSION_DEINIT 0x01
#define UCI_OID_SESSION_STATUS_NTF 0x02
#define UCI_OID_SESSION_SET_APP_CONFIG 0x03
#define UCI_OID_SESSION_GET_APP_CONFIG 0x04
#define UCI_OID_SESSION_GET_COUNT 0x05
#define UCI_OID_SESSION_GET_STATE 0x06
#define UCI_OID_SESSION_UPDATE_CONTROLLER_MULTICAST_LIST 0x07
#define UCI_OID_RANGE_START 0x00
#define UCI_OID_RANGE_DATA 0x00
#define UCI_OID_RANGE_STOP 0x01
#define UCI_OID_RANGE_GET_RANGING_COUNT 0x03

#define UCI_STATUS_OK 0x00
#define UCI_STATUS_REJECTED 0x01
#define UCI_STATUS_FAILED 0x02
#define UCI_STATUS_SYNTAX_ERROR 0x03
#define UCI_STATUS_INVALID_PARAM 0x04
#define UCI_STATUS_INVALID_RANGE 0x05
#define UCI_STATUS_INVALID_MSG_SIZE 0x06
#define UCI_STATUS_UNKNOWN_GID 0x07
#define UCI_STATUS_UNKNOWN_OID 0x08
#define UCI_STATUS_READ_ONLY 0x09
#define UCI_STATUS_COMMAND_RETRY 0x0A
#define UCI_STATUS_SESSSION_NOT_EXIST 0x11
#define UCI_STATUS_SESSSION_DUPLICATE 0x12
#define UCI_STATUS_SESSSION_ACTIVE 0x13
#define UCI_STATUS_MAX_SESSSIONS_EXCEEDED 0x14
#define UCI_STATUS_SESSION_NOT_CONFIGURED 0x15
#define UCI_STATUS_ERROR_ACTIVE_SESSIONS_ONGOING 0x16
#define UCI_STATUS_ERROR_MULTICAST_LIST_FULL 0x17
#define UCI_STATUS_ERROR_ADDRESS_NOT_FOUND 0x18
#define UCI_STATUS_ERROR_ADDRESS_ALREADY_PRESENT 0x19
#define UCI_STATUS_RANGING_TX_FAILED 0x20
#define UCI_STATUS_RANGING_RX_TIMEOUT 0x21
#define UCI_STATUS_RANGING_RX_PHY_DEC_FAILED 0x22
#define UCI_STATUS_RANGING_RX_PHY_TOA_FAILED 0x23
#define UCI_STATUS_RANGING_RX_PHY_STS_FAILED 0x24
#define UCI_STATUS_RANGING_RX_MAC_DEC_FAILED 0x25
#define UCI_STATUS_RANGING_RX_MAC_IE_DEC_FAILED 0x26
#define UCI_STATUS_RANGING_RX_MAC_IE_MISSING 0x27

#define UCI_CAP_SUPPORTED_FIRA_PHY_VERSION_RANGE 0x0
#define UCI_CAP_SUPPORTED_FIRA_MAC_VERSION_RANGE 0x1
#define UCI_CAP_SUPPORTED_DEVICE_ROLES 0x2
#define UCI_CAP_SUPPORTED_RANGING_METHOD 0x3
#define UCI_CAP_SUPPORTED_STS_CONFIG 0x4
#define UCI_CAP_SUPPORTED_MULTI_NODE_MODES 0x5
#define UCI_CAP_SUPPORTED_RANGING_TIME_STRUCT 0x6
#define UCI_CAP_SUPPORTED_SCHEDULED_MODE 0x7
#define UCI_CAP_SUPPORTED_HOPPING_MODE 0x8
#define UCI_CAP_SUPPORTED_BLOCK_STRIDING 0x9
#define UCI_CAP_SUPPORTED_UWB_INITIATION_TIME 0x0A
#define UCI_CAP_SUPPORTED_CHANNELS 0x0B
#define UCI_CAP_SUPPORTED_RFRAME_CONFIG 0x0C
#define UCI_CAP_SUPPORTED_CC_CONSTRAINT_LENGTH 0x0D
#define UCI_CAP_SUPPORTED_BPRF_PARAMETER_SETS 0x0E
#define UCI_CAP_SUPPORTED_HPRF_PARAMETER_SETS 0x0F
#define UCI_CAP_SUPPORTED_AOA 0x10
#define UCI_CAP_SUPPORTED_EXTENDED_MAC_ADDRESS 0x11
#define UCI_CAP_SUPPORTED_AOA_RESULT_REQ_ANTENNA_INTERLEAVING 0xE3
#define UCI_CAP_CCC_SUPPORTED_CHAPS_PER_SLOT 0xA0
#define UCI_CAP_CCC_SUPPORTED_SYNC_CODES 0xA1
#define UCI_CAP_CCC_SUPPORTED_HOPPING_CONFIG_MODES_AND_SEQUENCES 0xA2
#define UCI_CAP_CCC_SUPPORTED_CHANNELS 0xA3
#define UCI_CAP_CCC_SUPPORTED_VERSIONS 0xA4
#define UCI_CAP_CCC_SUPPORTED_UWB_CONFIGS 0xA5
#define UCI_CAP_CCC_SUPPORTED_PULSE_SHAPE_COMBOS 0xA6
#define UCI_CAP_CCC_SUPPORTED_RAN_MULTIPLIER 0xA7

#define UCI_APP_CONFIG_DEVICE_TYPE 0x00
#define UCI_APP_CONFIG_RANGING_ROUND_USAGE 0x01
#define UCI_APP_CONFIG_STS_CONFIG 0x02
#define UCI_APP_CONFIG_MULTI_NODE_MODE 0x03
#define UCI_APP_CONFIG_CHANNEL_NUMBER 0x04
#define UCI_APP_CONFIG_NO_OF_CONTROLEE 0x05
#define UCI_APP_CONFIG_DEVICE_MAC_ADDRESS 0x06
#define UCI_APP_CONFIG_DST_MAC_ADDRESS 0x07
#define UCI_APP_CONFIG_SLOT_DURATION 0x08
#define UCI_APP_CONFIG_RANGING_INTERVAL 0x09
#define UCI_APP_CONFIG_STS_INDEX 0x0A
#define UCI_APP_CONFIG_MAC_FCS_TYPE 0x0B
#define UCI_APP_CONFIG_RANGING_ROUND_CONTROL 0x0C
#define UCI_APP_CONFIG_AOA_RESULT_REQ 0x0D
#define UCI_APP_CONFIG_RNG_DATA_NTF 0x0E
#define UCI_APP_CONFIG_RNG_DATA_NTF_PROXIMITY_NEAR 0x0F
#define UCI_APP_CONFIG_RNG_DATA_NTF_PROXIMITY_FAR 0x10
#define UCI_APP_CONFIG_DEVICE_ROLE 0x11
#define UCI_APP_CONFIG_RFRAME_CONFIG 0x12
#define UCI_APP_CONFIG_PREAMBLE_CODE_INDEX 0x14
#define UCI_APP_CONFIG_SFD_ID 0x15
#define UCI_APP_CONFIG_PSDU_DATA_RATE 0x16
#define UCI_APP_CONFIG_PREAMBLE_DURATION 0x17
#define UCI_APP_CONFIG_RANGING_TIME_STRUCT 0x1A
#define UCI_APP_CONFIG_SLOTS_PER_RR 0x1B
#define UCI_APP_CONFIG_TX_ADAPTIVE_PAYLOAD_POWER 0x1C
#define UCI_APP_CONFIG_RESPONDER_SLOT_INDEX 0x1E
#define UCI_APP_CONFIG_PRF_MODE 0x1F
#define UCI_APP_CONFIG_SCHEDULED_MODE 0x22
#define UCI_APP_CONFIG_KEY_ROTATION 0x23
#define UCI_APP_CONFIG_KEY_ROTATION_RATE 0x24
#define UCI_APP_CONFIG_SESSION_PRIORITY 0x25
#define UCI_APP_CONFIG_MAC_ADDRESS_MODE 0x26
#define UCI_APP_CONFIG_VENDOR_ID 0x27
#define UCI_APP_CONFIG_STATIC_STS_IV 0x28
#define UCI_APP_CONFIG_NUMBER_OF_STS_SEGMENTS 0x29
#define UCI_APP_CONFIG_MAX_RR_RETRY 0x2A
#define UCI_APP_CONFIG_UWB_INITIATION_TIME 0x2B
#define UCI_APP_CONFIG_HOPPING_MODE 0x2C
#define UCI_APP_CONFIG_BLOCK_STRIDE_LENGTH 0x2D
#define UCI_APP_CONFIG_RESULT_REPORT_CONFIG 0x2E
#define UCI_APP_CONFIG_IN_BAND_TERMINATION_ATTEMPT_COUNT 0x2F
#define UCI_APP_CONFIG_SUB_SESSION_ID 0x30
#define UCI_APP_CONFIG_BPRF_PHR_DATA_RATE 0x31
#define UCI_APP_CONFIG_MAX_NUMBER_OF_MEASUREMENTS 0x32
#define UCI_APP_CONFIG_STS_LENGTH 0x35
#define UCI_APP_CONFIG_CCC_HOP_MODE_KEY 0xA0
#define UCI_APP_CONFIG_CCC_UWB_TIME0 0xA1
#define UCI_APP_CONFIG_CCC_RANGING_PROTOCOL_VER 0xA3
#define UCI_APP_CONFIG_CCC_UWB_CONFIG_ID 0xA4
#define UCI_APP_CONFIG_CCC_PULSESHAPE_COMBO 0xA5
#define UCI_APP_CONFIG_CCC_URSK_TTL 0xA6
#define UCI_APP_CONFIG_NB_OF_RANGE_MEASUREMENTS 0xE3
#define UCI_APP_CONFIG_NB_OF_AZIMUTH_MEASUREMENTS 0xE4
#define UCI_APP_CONFIG_NB_OF_ELEVATION_MEASUREMENTS 0xE5

static bool gPREF_TCP_DESEGMENT = true;
static unsigned gPREF_TCP_PORT = 7000;

static int proto_uci;
static dissector_handle_t handle_uci;

static int hf_uci_message_type;
static int hf_uci_packet_boundary_flag;
static int hf_uci_group_id;
static int hf_uci_opcode_id;
static int hf_uci_payload_length;
static int hf_uci_status;
static int hf_uci_reset_config;
static int hf_uci_device_state;
static int hf_uci_generic_version;
static int hf_uci_version_major;
static int hf_uci_version_minor;
static int hf_uci_maintenance_number;
static int hf_uci_mac_version;
static int hf_uci_phy_version;
static int hf_uci_test_version;
static int hf_uci_vendor_specific_information_length;
static int hf_uci_vendor_specific_information;
static int hf_uci_capability_parameters_count;
static int hf_uci_capability_parameter_type;
static int hf_uci_capability_parameter_len;
static int hf_uci_capability_parameter_value;
static int hf_uci_parameters_count;
static int hf_uci_parameter_type;
static int hf_uci_parameter_len;
static int hf_uci_parameter_value;
static int hf_uci_parameter_status;
static int hf_uci_session_id;
static int hf_uci_session_type;
static int hf_uci_session_state;
static int hf_uci_session_count;
static int hf_uci_app_config_parameters_count;
static int hf_uci_app_config_parameter_type;
static int hf_uci_app_config_parameter_len;
static int hf_uci_app_config_parameter_value;
static int hf_uci_app_config_parameter_status;
static int hf_uci_update_controller_multicast_list_action;
static int hf_uci_controlees_count;
static int hf_uci_controlee_short_address;
static int hf_uci_controlee_subsession_id;
static int hf_uci_controlee_status;
static int hf_uci_remaining_multicast_list_size;
static int hf_uci_ranging_count;
static int hf_uci_sequence_number;
static int hf_uci_current_ranging_interval;
static int hf_uci_ranging_measurement_type;
static int hf_uci_mac_addressing_mode_indicator;
static int hf_uci_ranging_measurement_count;
static int hf_uci_mac_address;
static int hf_uci_nlos;
static int hf_uci_distance;
static int hf_uci_aoa_azimuth;
static int hf_uci_aoa_azimuth_fom;
static int hf_uci_aoa_elevation;
static int hf_uci_aoa_elevation_fom;
static int hf_uci_aoa_destination_azimuth;
static int hf_uci_aoa_destination_azimuth_fom;
static int hf_uci_aoa_destination_elevation;
static int hf_uci_aoa_destination_elevation_fom;
static int hf_uci_slot_index;

static int ett_uci;
static int ett_uci_header;
static int ett_uci_payload;
static int ett_uci_capability_parameters;
static int ett_uci_capability_parameter;
static int ett_uci_parameters;
static int ett_uci_parameter;
static int ett_uci_app_config_parameters;
static int ett_uci_app_config_parameter;
static int ett_uci_controlee_list;
static int ett_uci_controlee;
static int ett_uci_ranging_measurements;
static int ett_uci_ranging_measurement;

static const value_string message_type_vals[] = {
    { UCI_MT_COMMAND, "Command" },
    { UCI_MT_RESPONSE, "Response" },
    { UCI_MT_NOTIFICATION, "Notification" },
    { 0, NULL },
};

static const value_string packet_boundary_flag_vals[] = {
    { 0, "The packet contains a complete message, or the Packet contains the "
         "last segment of the segmented message" },
    { 1, "The Packet contains a segment of a Message that is not the last segment" },
    { 0, NULL },
};

static const value_string group_id_vals[] = {
    { UCI_GID_CORE, "Core" },
    { UCI_GID_SESSION_CONFIG, "Session Config" },
    { UCI_GID_RANGING_SESSION_CONTROL, "Ranging Session Control" },
    { UCI_GID_DATA_CONTROL, "Data Control" },
    { UCI_GID_VENDOR_PICA, "Vendor Pica" },
    { UCI_GID_VENDOR_RESERVED_A, "Vendor Reserved A" },
    { UCI_GID_VENDOR_RESERVED_B, "Vendor Reserved B" },
    { UCI_GID_VENDOR_RESERVED_C, "Vendor Reserved C" },
    { UCI_GID_TEST, "Test" },
    { UCI_GID_VENDOR_ANDROID, "Vendor Android" },
    { UCI_GID_VENDOR_RESERVED_F, "Vendor Reserved F" },
    { 0, NULL },
};

static const value_string status_vals[] = {
    { UCI_STATUS_OK, "OK Success" },
    { UCI_STATUS_REJECTED, "Intended operation is not supported in the current state" },
    { UCI_STATUS_FAILED, "Intended operation failed to complete" },
    { UCI_STATUS_SYNTAX_ERROR, "UCI packet structure is not per spec" },
    { UCI_STATUS_INVALID_PARAM, "Config ID is not correct, and it is not present in UWBS" },
    { UCI_STATUS_INVALID_RANGE, "Config ID is correct, and value is not in proper range" },
    { UCI_STATUS_INVALID_MSG_SIZE, "UCI packet payload size is not as per spec" },
    { UCI_STATUS_UNKNOWN_GID, "UCI Group ID is not per spec" },
    { UCI_STATUS_UNKNOWN_OID, "UCI Opcode ID is not per spec" },
    { UCI_STATUS_READ_ONLY, "Config ID is read-only" },
    { UCI_STATUS_COMMAND_RETRY, "UWBS request retransmission from Host" },
    { UCI_STATUS_SESSSION_NOT_EXIST, "Session is not existing or not created" },
    { UCI_STATUS_SESSSION_DUPLICATE, "Session is already created/exist" },
    { UCI_STATUS_SESSSION_ACTIVE, "Session is active" },
    { UCI_STATUS_MAX_SESSSIONS_EXCEEDED, "Max. number of sessions already created" },
    { UCI_STATUS_SESSION_NOT_CONFIGURED, "Session is not configured with required app configurations" },
    { UCI_STATUS_ERROR_ACTIVE_SESSIONS_ONGOING, "Sessions are actively running in UWBS" },
    { UCI_STATUS_ERROR_MULTICAST_LIST_FULL, "Indicates when multicast list is full during one to many ranging" },
    { UCI_STATUS_ERROR_ADDRESS_NOT_FOUND, "Indicates when short address is not available multicast list" },
    { UCI_STATUS_ERROR_ADDRESS_ALREADY_PRESENT, "Indicates when short address is already present" },
    { UCI_STATUS_RANGING_TX_FAILED, "Failed to transmit UWB packet" },
    { UCI_STATUS_RANGING_RX_TIMEOUT, "No UWB packet detected by the receiver" },
    { UCI_STATUS_RANGING_RX_PHY_DEC_FAILED, "UWB packet channel decoding error" },
    { UCI_STATUS_RANGING_RX_PHY_TOA_FAILED, "Failed to detect time of arrival of the UWB packet from CIR samples" },
    { UCI_STATUS_RANGING_RX_PHY_STS_FAILED, "UWB packet STS segment mismatch" },
    { UCI_STATUS_RANGING_RX_MAC_DEC_FAILED, "MAC CRC or syntax error" },
    { UCI_STATUS_RANGING_RX_MAC_IE_DEC_FAILED, "IE syntax error" },
    { UCI_STATUS_RANGING_RX_MAC_IE_MISSING, "Expected IE missing in the packet" },
    { 0, NULL },
};

static const value_string reset_config_vals[] = {
    { 0, "UWBS reset" },
    { 0, NULL },
};

static const value_string device_state_vals[] = {
    { 1, "UWBS is initialized and ready for UWB session" },
    { 2, "UWBS is busy with UWB session" },
    { 0xff, "Error occurred within the UWBS" },
    { 0, NULL },
};

static const value_string capability_parameter_type_vals[] = {
    { UCI_CAP_SUPPORTED_FIRA_PHY_VERSION_RANGE, "Supported Fira PHY version range" },
    { UCI_CAP_SUPPORTED_FIRA_MAC_VERSION_RANGE, "Supported Fira MAC version range" },
    { UCI_CAP_SUPPORTED_DEVICE_ROLES, "Supported device roles" },
    { UCI_CAP_SUPPORTED_RANGING_METHOD, "Supported ranging method" },
    { UCI_CAP_SUPPORTED_STS_CONFIG, "Supported STS config" },
    { UCI_CAP_SUPPORTED_MULTI_NODE_MODES, "Supported multi node modes" },
    { UCI_CAP_SUPPORTED_RANGING_TIME_STRUCT, "Supported ranging time struct" },
    { UCI_CAP_SUPPORTED_SCHEDULED_MODE, "Supported scheduled mode" },
    { UCI_CAP_SUPPORTED_HOPPING_MODE, "Supported hopping mode" },
    { UCI_CAP_SUPPORTED_BLOCK_STRIDING, "Supported block striding" },
    { UCI_CAP_SUPPORTED_UWB_INITIATION_TIME, "Supported UWB initiation time" },
    { UCI_CAP_SUPPORTED_CHANNELS, "Supported channels" },
    { UCI_CAP_SUPPORTED_RFRAME_CONFIG, "Supported rframe config" },
    { UCI_CAP_SUPPORTED_CC_CONSTRAINT_LENGTH, "Supported CC constraint length" },
    { UCI_CAP_SUPPORTED_BPRF_PARAMETER_SETS, "Supported BPRF parameter sets" },
    { UCI_CAP_SUPPORTED_HPRF_PARAMETER_SETS, "Supported HPRF parameter sets" },
    { UCI_CAP_SUPPORTED_AOA, "Supported AOA" },
    { UCI_CAP_SUPPORTED_EXTENDED_MAC_ADDRESS, "Supported extended MAC address" },
    { UCI_CAP_SUPPORTED_AOA_RESULT_REQ_ANTENNA_INTERLEAVING, "Supported AOA result req antenna interleaving" },
    { UCI_CAP_CCC_SUPPORTED_CHAPS_PER_SLOT, "Supported CCC chaps per slot" },
    { UCI_CAP_CCC_SUPPORTED_SYNC_CODES, "Supported CCC sync codes" },
    { UCI_CAP_CCC_SUPPORTED_HOPPING_CONFIG_MODES_AND_SEQUENCES, "Supported CCC hopping config modes and sequences" },
    { UCI_CAP_CCC_SUPPORTED_CHANNELS, "Supported CCC channels" },
    { UCI_CAP_CCC_SUPPORTED_VERSIONS, "Supported CCC versions" },
    { UCI_CAP_CCC_SUPPORTED_UWB_CONFIGS, "Supported CCC UWB configs" },
    { UCI_CAP_CCC_SUPPORTED_PULSE_SHAPE_COMBOS, "Supported CCC pulse shape combos" },
    { UCI_CAP_CCC_SUPPORTED_RAN_MULTIPLIER, "Supported CCC ran multiplier" },
    { 0, NULL },
};

static const value_string parameter_type_vals[] = {
    { 0, "Device State" },
    { 1, "Low Power Mode" },
    { 0, NULL },
};

static const value_string session_type_vals[] = {
    { 0x00, "Fira Ranging Session" },
    { 0xD0, "Device Test Mode" },
    { 0, NULL },
};

static const value_string session_state_vals[] = {
    { 0, "Session State Init" },
    { 1, "Session State Deinit" },
    { 2, "Session State Active" },
    { 3, "Session State Idle" },
    { 0, NULL },
};

static const value_string app_config_parameter_type_vals[] = {
    { UCI_APP_CONFIG_DEVICE_TYPE, "Device type" },
    { UCI_APP_CONFIG_RANGING_ROUND_USAGE, "Ranging round usage" },
    { UCI_APP_CONFIG_STS_CONFIG, "STS config" },
    { UCI_APP_CONFIG_MULTI_NODE_MODE, "Multi-node mode" },
    { UCI_APP_CONFIG_CHANNEL_NUMBER, "Channel number" },
    { UCI_APP_CONFIG_NO_OF_CONTROLEE, "No of controlee" },
    { UCI_APP_CONFIG_DEVICE_MAC_ADDRESS, "Device mac address" },
    { UCI_APP_CONFIG_DST_MAC_ADDRESS, "Dst mac address" },
    { UCI_APP_CONFIG_SLOT_DURATION, "Slot duration" },
    { UCI_APP_CONFIG_RANGING_INTERVAL, "Ranging interval" },
    { UCI_APP_CONFIG_STS_INDEX, "STS index" },
    { UCI_APP_CONFIG_MAC_FCS_TYPE, "Mac FCS type" },
    { UCI_APP_CONFIG_RANGING_ROUND_CONTROL, "Ranging round control" },
    { UCI_APP_CONFIG_AOA_RESULT_REQ, "AOA result req" },
    { UCI_APP_CONFIG_RNG_DATA_NTF, "Rng data ntf" },
    { UCI_APP_CONFIG_RNG_DATA_NTF_PROXIMITY_NEAR, "Rng data ntf proximity near" },
    { UCI_APP_CONFIG_RNG_DATA_NTF_PROXIMITY_FAR, "Rng data ntf proximity far" },
    { UCI_APP_CONFIG_DEVICE_ROLE, "Device role" },
    { UCI_APP_CONFIG_RFRAME_CONFIG, "Rframe config" },
    { UCI_APP_CONFIG_PREAMBLE_CODE_INDEX, "Preamble code index" },
    { UCI_APP_CONFIG_SFD_ID, "SFD ID" },
    { UCI_APP_CONFIG_PSDU_DATA_RATE, "PSDU data rate" },
    { UCI_APP_CONFIG_PREAMBLE_DURATION, "Preamble duration" },
    { UCI_APP_CONFIG_RANGING_TIME_STRUCT, "Ranging time struct" },
    { UCI_APP_CONFIG_SLOTS_PER_RR, "Slots per ranging round" },
    { UCI_APP_CONFIG_TX_ADAPTIVE_PAYLOAD_POWER, "Tx adaptive payload power" },
    { UCI_APP_CONFIG_RESPONDER_SLOT_INDEX, "Responder slot index" },
    { UCI_APP_CONFIG_PRF_MODE, "PRF mode" },
    { UCI_APP_CONFIG_SCHEDULED_MODE, "Scheduled mode" },
    { UCI_APP_CONFIG_KEY_ROTATION, "Key rotation" },
    { UCI_APP_CONFIG_KEY_ROTATION_RATE, "Key rotation rate" },
    { UCI_APP_CONFIG_SESSION_PRIORITY, "Session priority" },
    { UCI_APP_CONFIG_MAC_ADDRESS_MODE, "Mac address mode" },
    { UCI_APP_CONFIG_VENDOR_ID, "Vendor ID" },
    { UCI_APP_CONFIG_STATIC_STS_IV, "Static STS IV" },
    { UCI_APP_CONFIG_NUMBER_OF_STS_SEGMENTS, "Number of STS segments" },
    { UCI_APP_CONFIG_MAX_RR_RETRY, "Max ranging round retry" },
    { UCI_APP_CONFIG_UWB_INITIATION_TIME, "UWB initiation time" },
    { UCI_APP_CONFIG_HOPPING_MODE, "Hopping mode" },
    { UCI_APP_CONFIG_BLOCK_STRIDE_LENGTH, "Block stride length" },
    { UCI_APP_CONFIG_RESULT_REPORT_CONFIG, "Result report config" },
    { UCI_APP_CONFIG_IN_BAND_TERMINATION_ATTEMPT_COUNT, "In band termination attempt count" },
    { UCI_APP_CONFIG_SUB_SESSION_ID, "Sub session ID" },
    { UCI_APP_CONFIG_BPRF_PHR_DATA_RATE, "BPRF PHR data rate" },
    { UCI_APP_CONFIG_MAX_NUMBER_OF_MEASUREMENTS, "Max number of measurements" },
    { UCI_APP_CONFIG_STS_LENGTH, "STS length" },
    { UCI_APP_CONFIG_CCC_HOP_MODE_KEY, "CCC hop mode key" },
    { UCI_APP_CONFIG_CCC_UWB_TIME0, "CCC UWB time0" },
    { UCI_APP_CONFIG_CCC_RANGING_PROTOCOL_VER, "CCC ranging protocol ver" },
    { UCI_APP_CONFIG_CCC_UWB_CONFIG_ID, "CCC UWB config ID" },
    { UCI_APP_CONFIG_CCC_PULSESHAPE_COMBO, "CCC pulseshape combo" },
    { UCI_APP_CONFIG_CCC_URSK_TTL, "CCC URSK TTL" },
    { UCI_APP_CONFIG_NB_OF_RANGE_MEASUREMENTS, "Nb of range measurements" },
    { UCI_APP_CONFIG_NB_OF_AZIMUTH_MEASUREMENTS, "Nb of azimuth measurements" },
    { UCI_APP_CONFIG_NB_OF_ELEVATION_MEASUREMENTS, "Nb of elevation measurements" },
    { 0, NULL },
};

static const value_string update_controller_multicast_list_action_vals[] = {
    { 0, "Update the multicast list by adding requested controlee short address" },
    { 1, "Delete the requested short address from multicast list" },
    { 0, NULL },
};

static const value_string multicast_update_status_vals[] = {
    { 0, "OK - Multicast list updated" },
    { 1, "Multicast list full" },
    { 2, "Key fecth fail" },
    { 3, "Sub-session ID not found" },
    { 0, NULL },
};

static const value_string ranging_measurement_type_vals[] = {
    { 1, "Two Way Ranging Measurement (SS-TWR, DSTWR)" },
    { 0, NULL },
};

static const value_string mac_addressing_mode_indicator_vals[] = {
    { 0, "2 Octets short MAC address" },
    { 1, "8 Octets extended MAC Address" },
    { 0, NULL },
};

static const value_string nlos_vals[] = {
    { 0, "Line of sight" },
    { 1, "Non-line of sigt" },
    { 0xff, "Unable to determine" },
    { 0, NULL },
};

static unsigned get_uci_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    /* Return the payload length added to the packet header length. */
    return tvb_get_uint8(tvb, offset + 3) + UCI_PACKET_HEADER_LEN;
}

static void dissect_core_device_reset_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                         proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Core Device Reset Cmd");
    proto_tree_add_item(payload_tree, hf_uci_reset_config, tvb, offset, 1, ENC_NA);
}

static void dissect_core_device_reset_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                         proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Core Device Reset Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
}

static void dissect_core_device_status_ntf(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                          proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Core Device Status Ntf");
    proto_tree_add_item(payload_tree, hf_uci_device_state, tvb, offset, 1, ENC_NA);
}

static void dissect_core_get_device_info_cmd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo,
                                            proto_tree *payload_tree _U_)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Core Get Device Info Cmd");
}

static void dissect_core_get_device_info_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                            proto_tree *payload_tree)
{
    static int * const version_fields[] = {
        &hf_uci_version_major,
        &hf_uci_version_minor,
        &hf_uci_maintenance_number,
        NULL
    };

    col_add_fstr(pinfo->cinfo, COL_INFO, "Core Get Device Info Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_bitmask(payload_tree, tvb, offset,
        hf_uci_generic_version, ett_uci_payload, version_fields, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(payload_tree, tvb, offset,
        hf_uci_mac_version, ett_uci_payload, version_fields, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(payload_tree, tvb, offset,
        hf_uci_phy_version, ett_uci_payload, version_fields, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(payload_tree, tvb, offset,
        hf_uci_test_version, ett_uci_payload, version_fields, ENC_LITTLE_ENDIAN);
    offset += 2;

    int vendor_specific_information_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(payload_tree, hf_uci_vendor_specific_information_length,
        tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(payload_tree, hf_uci_vendor_specific_information,
        tvb, offset, vendor_specific_information_len, ENC_NA);
}

static void dissect_core_get_caps_info_cmd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo,
                                          proto_tree *payload_tree _U_)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Core Get Caps Info Cmd");
}

static void dissect_core_get_caps_info_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                          proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Core Get Caps Info Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
    offset += 1;

    int capability_parameters_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(payload_tree, hf_uci_capability_parameters_count,
        tvb, offset, 1, ENC_NA);
    offset += 1;

    if (capability_parameters_count == 0) {
        return;
    }

    proto_tree *capability_parameters_tree =
        proto_tree_add_subtree(payload_tree, tvb, offset, -1,
            ett_uci_capability_parameters, NULL, "Capability Parameters");

    for (int idx = 0; idx < capability_parameters_count; idx++) {
        int parameter_type = tvb_get_uint8(tvb, offset + 0);
        int parameter_len = tvb_get_uint8(tvb, offset + 1);
        proto_tree *parameter_tree =
            proto_tree_add_subtree(capability_parameters_tree, tvb, offset, 2 + parameter_len,
                ett_uci_capability_parameter, NULL,
                val_to_str(parameter_type, capability_parameter_type_vals, "Unknown (0x%02x)"));

        proto_tree_add_item(parameter_tree, hf_uci_capability_parameter_type, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(parameter_tree, hf_uci_capability_parameter_len, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(parameter_tree, hf_uci_capability_parameter_value, tvb, offset, parameter_len, ENC_NA);
        offset += parameter_len;
    }
}

static void dissect_core_get_config_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                       proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Core Get Config Cmd");

    int parameters_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(payload_tree, hf_uci_parameters_count, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (parameters_count == 0) {
        return;
    }

    proto_tree *parameters_tree =
        proto_tree_add_subtree(payload_tree, tvb, offset, -1,
            ett_uci_parameters, NULL, "Parameter IDs");

    for (int idx = 0; idx < parameters_count; idx++) {
        int parameter_id = tvb_get_uint8(tvb, offset);

        proto_tree *parameter_tree =
            proto_tree_add_subtree(parameters_tree, tvb, offset, 1,
                ett_uci_parameter, NULL,
                val_to_str(parameter_id, parameter_type_vals, "Unknown (0x%02x)"));

        proto_tree_add_item(parameter_tree, hf_uci_parameter_type,
            tvb, offset, 1, ENC_NA);

        offset += 1;
    }
}

static void dissect_parameters(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                               proto_tree *payload_tree)
{
    int parameters_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(payload_tree, hf_uci_parameters_count, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (parameters_count == 0) {
        return;
    }

    proto_tree *parameters_tree =
        proto_tree_add_subtree(payload_tree, tvb, offset, -1,
            ett_uci_parameters, NULL, "Parameters");

    for (int idx = 0; idx < parameters_count; idx++) {
        int parameter_id = tvb_get_uint8(tvb, offset + 0);
        int parameter_len = tvb_get_uint8(tvb, offset + 1);
        proto_tree *parameter_tree =
            proto_tree_add_subtree(parameters_tree, tvb, offset, 2 + parameter_len,
                ett_uci_parameter, NULL,
                val_to_str(parameter_id, parameter_type_vals, "Unknown (0x%02x)"));

        proto_tree_add_item(parameter_tree, hf_uci_parameter_type, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(parameter_tree, hf_uci_parameter_len, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(parameter_tree, hf_uci_parameter_value, tvb, offset, parameter_len, ENC_NA);
        offset += parameter_len;
    }
}

static void dissect_core_get_config_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                       proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Core Get Config Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
    offset += 1;

    dissect_parameters(tvb, offset, pinfo, payload_tree);
}

static void dissect_core_set_config_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                       proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Core Set Config Cmd");
    dissect_parameters(tvb, offset, pinfo, payload_tree);
}

static void dissect_core_set_config_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                       proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Core Set Config Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
    offset += 1;

    int parameters_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(payload_tree, hf_uci_parameters_count,
        tvb, offset, 1, ENC_NA);
    offset += 1;

    if (parameters_count == 0) {
        return;
    }

    proto_tree *parameters_tree =
        proto_tree_add_subtree(payload_tree, tvb, offset, -1,
            ett_uci_parameters, NULL, "Parameters");

    for (int idx = 0; idx < parameters_count; idx++) {
        int parameter_type = tvb_get_uint8(tvb, offset + 0);

        proto_tree *parameter_tree =
            proto_tree_add_subtree(parameters_tree, tvb, offset, 2,
                ett_uci_parameter, NULL,
                val_to_str(parameter_type, parameter_type_vals, "Unknown (0x%02x)"));

        proto_tree_add_item(parameter_tree, hf_uci_parameter_type, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(parameter_tree, hf_uci_parameter_status, tvb, offset, 1, ENC_NA);
        offset += 1;
    }
}

static void dissect_core_generic_error_ntf(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                          proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Core Generic Error Ntf");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
}

static void dissect_uci_core_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                proto_tree *payload_tree, int message_type, int opcode_id)
{
    if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_CORE_DEVICE_RESET) {
        dissect_core_device_reset_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_CORE_DEVICE_RESET) {
        dissect_core_device_reset_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_NOTIFICATION &&
        opcode_id == UCI_OID_CORE_DEVICE_STATUS_NTF) {
        dissect_core_device_status_ntf(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_CORE_GET_DEVICE_INFO) {
        dissect_core_get_device_info_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_CORE_GET_DEVICE_INFO) {
        dissect_core_get_device_info_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_CORE_GET_CAPS_INFO) {
        dissect_core_get_caps_info_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_CORE_GET_CAPS_INFO) {
        dissect_core_get_caps_info_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_CORE_GET_CONFIG) {
        dissect_core_get_config_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_CORE_GET_CONFIG) {
        dissect_core_get_config_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_CORE_SET_CONFIG) {
        dissect_core_set_config_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_CORE_SET_CONFIG) {
        dissect_core_set_config_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_NOTIFICATION &&
        opcode_id == UCI_OID_CORE_GENERIC_ERROR_NTF) {
        dissect_core_generic_error_ntf(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Core Cmd (%02x)", opcode_id);
    }
    else if (message_type == UCI_MT_RESPONSE) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Core Rsp (%02x)", opcode_id);
    }
    else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Core Ntf (%02x)", opcode_id);
    }
}

static void dissect_session_init_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                    proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Init Cmd");
    proto_tree_add_item(payload_tree, hf_uci_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(payload_tree, hf_uci_session_type, tvb, offset, 1, ENC_NA);
}

static void dissect_session_init_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                    proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Init Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
}

static void dissect_session_deinit_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                      proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Deinit Cmd");
    proto_tree_add_item(payload_tree, hf_uci_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_session_deinit_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                      proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Deinit Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
}

static void dissect_session_status_ntf(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                      proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Status Ntf");
    proto_tree_add_item(payload_tree, hf_uci_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(payload_tree, hf_uci_session_state, tvb, offset, 1, ENC_NA);
}

static void dissect_app_config_parameters(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                               proto_tree *payload_tree)
{
    int app_config_parameters_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(payload_tree, hf_uci_app_config_parameters_count,
        tvb, offset, 1, ENC_NA);
    offset += 1;

    if (app_config_parameters_count == 0) {
        return;
    }

    proto_tree *app_config_parameters_tree =
        proto_tree_add_subtree(payload_tree, tvb, offset, -1,
            ett_uci_app_config_parameters, NULL, "App Configurations");

    for (int idx = 0; idx < app_config_parameters_count; idx++) {
        int app_config_parameter_id = tvb_get_uint8(tvb, offset + 0);
        int app_config_parameter_len = tvb_get_uint8(tvb, offset + 1);
        proto_tree *app_config_parameter_tree =
            proto_tree_add_subtree(app_config_parameters_tree, tvb, offset,
                2 + app_config_parameter_len, ett_uci_app_config_parameter, NULL,
                val_to_str(app_config_parameter_id, app_config_parameter_type_vals, "Unknown (0x%02x)"));

        proto_tree_add_item(app_config_parameter_tree,
            hf_uci_app_config_parameter_type, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(app_config_parameter_tree,
            hf_uci_app_config_parameter_len, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(app_config_parameter_tree,
            hf_uci_app_config_parameter_value, tvb, offset,
            app_config_parameter_len, ENC_NA);
        offset += app_config_parameter_len;
    }
}

static void dissect_session_set_app_config_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                              proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Set App Config Cmd");
    proto_tree_add_item(payload_tree, hf_uci_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    dissect_app_config_parameters(tvb, offset, pinfo, payload_tree);
}

static void dissect_session_set_app_config_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                              proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Set App Config Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
    offset += 1;

    int app_config_parameters_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(payload_tree, hf_uci_app_config_parameters_count,
        tvb, offset, 1, ENC_NA);
    offset += 1;

    if (app_config_parameters_count == 0) {
        return;
    }

    proto_tree *app_config_parameters_tree =
        proto_tree_add_subtree(payload_tree, tvb, offset, -1,
            ett_uci_app_config_parameters, NULL, "App Configurations");

    for (int idx = 0; idx < app_config_parameters_count; idx++) {
        int app_config_parameter_type = tvb_get_uint8(tvb, offset + 0);

        proto_tree *app_config_parameter_tree =
            proto_tree_add_subtree(app_config_parameters_tree, tvb, offset, 2,
                ett_uci_app_config_parameter, NULL,
                val_to_str(app_config_parameter_type, app_config_parameter_type_vals, "Unknown (0x%02x)"));

        proto_tree_add_item(app_config_parameter_tree, hf_uci_app_config_parameter_type, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(app_config_parameter_tree, hf_uci_app_config_parameter_status, tvb, offset, 1, ENC_NA);
        offset += 1;
    }
}

static void dissect_session_get_app_config_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                              proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Get App Config Cmd");
    proto_tree_add_item(payload_tree, hf_uci_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    int app_config_parameters_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(payload_tree, hf_uci_app_config_parameters_count, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (app_config_parameters_count == 0) {
        return;
    }

    proto_tree *app_config_parameters_tree =
        proto_tree_add_subtree(payload_tree, tvb, offset, -1,
            ett_uci_app_config_parameters, NULL, "App Configuration IDs");

    for (int idx = 0; idx < app_config_parameters_count; idx++) {
        int app_config_parameter_id = tvb_get_uint8(tvb, offset);

        proto_tree *app_config_parameter_tree =
            proto_tree_add_subtree(app_config_parameters_tree, tvb, offset, 1,
                ett_uci_app_config_parameter, NULL,
                val_to_str(app_config_parameter_id, app_config_parameter_type_vals, "Unknown (0x%02x)"));

        proto_tree_add_item(app_config_parameter_tree, hf_uci_app_config_parameter_type,
            tvb, offset, 1, ENC_NA);

        offset += 1;
    }
}

static void dissect_session_get_app_config_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                              proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Get App Config Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
    offset += 1;
    dissect_app_config_parameters(tvb, offset, pinfo, payload_tree);
}

static void dissect_session_get_count_cmd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo,
                                         proto_tree *payload_tree _U_)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Get Count Cmd");
}

static void dissect_session_get_count_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                         proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Get Count Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(payload_tree, hf_uci_session_count, tvb, offset, 1, ENC_NA);
}

static void dissect_session_get_state_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                         proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Get State Cmd");
    proto_tree_add_item(payload_tree, hf_uci_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_session_get_state_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                         proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Get State Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(payload_tree, hf_uci_session_state, tvb, offset, 1, ENC_NA);
}

static void dissect_session_update_controller_multicast_list_cmd(
    tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Update Controller Multicast List Cmd");
    proto_tree_add_item(payload_tree, hf_uci_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(payload_tree, hf_uci_update_controller_multicast_list_action,
        tvb, offset, 1, ENC_NA);
    offset += 1;

    int controlees_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(payload_tree, hf_uci_controlees_count,
        tvb, offset, 1, ENC_NA);
    offset += 1;

    if (controlees_count == 0) {
        return;
    }

    proto_tree *controlee_list_tree =
        proto_tree_add_subtree(payload_tree, tvb, offset, -1,
            ett_uci_controlee_list, NULL, "Controlee List");

    for (int idx = 0; idx < controlees_count; idx++) {
        proto_tree *controlee_tree =
            proto_tree_add_subtree(controlee_list_tree, tvb, offset, -1,
                ett_uci_controlee, NULL, "Controlee");

        proto_tree_add_item(controlee_tree, hf_uci_controlee_short_address,
            tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(controlee_tree, hf_uci_controlee_subsession_id,
            tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
}

static void dissect_session_update_controller_multicast_list_rsp(
    tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Update Controller Multicast List Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
}

static void dissect_session_update_controller_multicast_list_ntf(
    tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Session Update Controller Multicast List Ntf");
    proto_tree_add_item(payload_tree, hf_uci_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(payload_tree, hf_uci_remaining_multicast_list_size,
        tvb, offset, 1, ENC_NA);
    offset += 1;

    int controlees_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(payload_tree, hf_uci_controlees_count,
        tvb, offset, 1, ENC_NA);
    offset += 1;

    if (controlees_count == 0) {
        return;
    }

    proto_tree *controlee_list_tree =
        proto_tree_add_subtree(payload_tree, tvb, offset, -1,
            ett_uci_controlee_list, NULL, "Controlee List");

    for (int idx = 0; idx < controlees_count; idx++) {
        proto_tree *controlee_tree =
            proto_tree_add_subtree(controlee_list_tree, tvb, offset, -1,
                ett_uci_controlee, NULL, "Controlee");

        proto_tree_add_item(controlee_tree, hf_uci_controlee_short_address,
            tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(controlee_tree, hf_uci_controlee_subsession_id,
            tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(controlee_tree, hf_uci_controlee_status,
            tvb, offset, 1, ENC_NA);
        offset += 1;
    }
}

static void dissect_uci_session_config_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                          proto_tree *payload_tree, int message_type, int opcode_id)
{
    if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_SESSION_INIT) {
        dissect_session_init_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_SESSION_INIT) {
        dissect_session_init_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_SESSION_DEINIT) {
        dissect_session_deinit_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_SESSION_DEINIT) {
        dissect_session_deinit_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_NOTIFICATION &&
        opcode_id == UCI_OID_SESSION_STATUS_NTF) {
        dissect_session_status_ntf(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_SESSION_SET_APP_CONFIG) {
        dissect_session_set_app_config_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_SESSION_SET_APP_CONFIG) {
        dissect_session_set_app_config_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_SESSION_GET_APP_CONFIG) {
        dissect_session_get_app_config_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_SESSION_GET_APP_CONFIG) {
        dissect_session_get_app_config_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_SESSION_GET_COUNT) {
        dissect_session_get_count_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_SESSION_GET_COUNT) {
        dissect_session_get_count_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_SESSION_GET_STATE) {
        dissect_session_get_state_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_SESSION_GET_STATE) {
        dissect_session_get_state_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_SESSION_UPDATE_CONTROLLER_MULTICAST_LIST) {
        dissect_session_update_controller_multicast_list_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_SESSION_UPDATE_CONTROLLER_MULTICAST_LIST) {
        dissect_session_update_controller_multicast_list_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_NOTIFICATION &&
        opcode_id == UCI_OID_SESSION_UPDATE_CONTROLLER_MULTICAST_LIST) {
        dissect_session_update_controller_multicast_list_ntf(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Session Config Cmd (%02x)", opcode_id);
    }
    else if (message_type == UCI_MT_RESPONSE) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Session Config Rsp (%02x)", opcode_id);
    }
    else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Session Config Ntf (%02x)", opcode_id);
    }
}

static void dissect_range_start_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                   proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Range Start Cmd");
    proto_tree_add_item(payload_tree, hf_uci_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_range_start_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                   proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Range Start Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
}

static void dissect_range_data_ntf(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                  proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Range Data Ntf");
    proto_tree_add_item(payload_tree, hf_uci_sequence_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(payload_tree, hf_uci_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    offset += 1;
    proto_tree_add_item(payload_tree, hf_uci_current_ranging_interval, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(payload_tree, hf_uci_ranging_measurement_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    offset += 1;

    int mac_addressing_mode_indicator = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(payload_tree, hf_uci_mac_addressing_mode_indicator, tvb, offset, 1, ENC_NA);
    offset += 1;
    offset += 8;

    int ranging_measurement_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(payload_tree, hf_uci_ranging_measurement_count, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (ranging_measurement_count == 0) {
        return;
    }

    proto_tree *ranging_measurements_tree =
        proto_tree_add_subtree(payload_tree, tvb, offset, -1,
            ett_uci_ranging_measurements, NULL, "Ranging Measurements");

    for (int idx = 0; idx < ranging_measurement_count; idx++) {
        proto_tree *ranging_measurement_tree;
        int padding_len;

        if (mac_addressing_mode_indicator == 0) {
            ranging_measurement_tree = proto_tree_add_subtree_format(
                ranging_measurements_tree, tvb, offset, 31,
                ett_uci_ranging_measurement, NULL,
                "%02x:%02x",
                tvb_get_uint8(tvb, offset + 0),
                tvb_get_uint8(tvb, offset + 1));

            proto_tree_add_item(ranging_measurement_tree,
                hf_uci_mac_address, tvb, offset, 2, ENC_NA);

            offset += 2;
            padding_len = 12;
        } else {
            ranging_measurement_tree = proto_tree_add_subtree_format(
                ranging_measurements_tree, tvb, offset, 31,
                ett_uci_ranging_measurement, NULL,
                "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                tvb_get_uint8(tvb, offset + 0),
                tvb_get_uint8(tvb, offset + 1),
                tvb_get_uint8(tvb, offset + 2),
                tvb_get_uint8(tvb, offset + 3),
                tvb_get_uint8(tvb, offset + 4),
                tvb_get_uint8(tvb, offset + 5),
                tvb_get_uint8(tvb, offset + 6),
                tvb_get_uint8(tvb, offset + 7));

            proto_tree_add_item(ranging_measurement_tree,
                hf_uci_mac_address, tvb, offset, 8, ENC_NA);

            offset += 8;
            padding_len = 6;
        }

        proto_tree_add_item(ranging_measurement_tree,
            hf_uci_status, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(ranging_measurement_tree,
            hf_uci_nlos, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(ranging_measurement_tree,
            hf_uci_distance, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(ranging_measurement_tree,
            hf_uci_aoa_azimuth, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(ranging_measurement_tree,
            hf_uci_aoa_azimuth_fom, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(ranging_measurement_tree,
            hf_uci_aoa_elevation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(ranging_measurement_tree,
            hf_uci_aoa_elevation_fom, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(ranging_measurement_tree,
            hf_uci_aoa_destination_azimuth, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(ranging_measurement_tree,
            hf_uci_aoa_destination_azimuth_fom, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(ranging_measurement_tree,
            hf_uci_aoa_destination_elevation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(ranging_measurement_tree,
            hf_uci_aoa_destination_elevation_fom, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(ranging_measurement_tree,
            hf_uci_slot_index, tvb, offset, 1, ENC_NA);
        offset += 1;
        offset += padding_len;
    }
}

static void dissect_range_stop_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                  proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Range Stop Cmd");
    proto_tree_add_item(payload_tree, hf_uci_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_range_stop_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                  proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Range Stop Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
}

static void dissect_range_get_ranging_count_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                               proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Range Get Ranging Count Cmd");
    proto_tree_add_item(payload_tree, hf_uci_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_range_get_ranging_count_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                               proto_tree *payload_tree)
{
    col_add_fstr(pinfo->cinfo, COL_INFO, "Range Get Ranging Count Rsp");
    proto_tree_add_item(payload_tree, hf_uci_status, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(payload_tree, hf_uci_ranging_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_uci_ranging_session_control_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                                   proto_tree *payload_tree, int message_type, int opcode_id)
{
    if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_RANGE_START) {
        dissect_range_start_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_RANGE_START) {
        dissect_range_start_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_NOTIFICATION &&
        opcode_id == UCI_OID_RANGE_DATA) {
        dissect_range_data_ntf(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_RANGE_STOP) {
        dissect_range_stop_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_RANGE_STOP) {
        dissect_range_stop_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND &&
        opcode_id == UCI_OID_RANGE_GET_RANGING_COUNT) {
        dissect_range_get_ranging_count_cmd(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_RESPONSE &&
        opcode_id == UCI_OID_RANGE_GET_RANGING_COUNT) {
        dissect_range_get_ranging_count_rsp(tvb, offset, pinfo, payload_tree);
    }
    else if (message_type == UCI_MT_COMMAND) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Ranging Session Control Cmd (%02x)", opcode_id);
    }
    else if (message_type == UCI_MT_RESPONSE) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Ranging Session Control Rsp (%02x)", opcode_id);
    }
    else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Ranging Session Control Ntf (%02x)", opcode_id);
    }
}

static void dissect_uci_data_control_pdu(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo,
                                         proto_tree *payload_tree _U_, int message_type, int opcode_id)
{
    if (message_type == UCI_MT_COMMAND) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Data Control Cmd (%02x)", opcode_id);
    }
    else if (message_type == UCI_MT_RESPONSE) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Data Control Rsp (%02x)", opcode_id);
    }
    else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Data Control Ntf (%02x)", opcode_id);
    }
}

static void dissect_uci_test_pdu(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo,
                                 proto_tree *payload_tree _U_, int message_type, int opcode_id)
{
    if (message_type == UCI_MT_COMMAND) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Test Cmd (%02x)", opcode_id);
    }
    else if (message_type == UCI_MT_RESPONSE) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Test Rsp (%02x)", opcode_id);
    }
    else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Test Ntf (%02x)", opcode_id);
    }
}

static void dissect_uci_vendor_pdu(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo,
                                   proto_tree *payload_tree _U_, int message_type, int group_id, int opcode_id)
{
    if (message_type == UCI_MT_COMMAND) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Vendor_%02X Cmd (%02x)", group_id, opcode_id);
    }
    else if (message_type == UCI_MT_RESPONSE) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Vendor_%02X Rsp (%02x)", group_id, opcode_id);
    }
    else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Vendor_%02X Ntf (%02x)", group_id, opcode_id);
    }
}

static int dissect_uci_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *packet_tree;
    proto_tree *header_tree;
    proto_tree *payload_tree;
    int message_type;
    int group_id;
    int opcode_id;
    int payload_len;
    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UCI");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_uci, tvb, 0, -1, ENC_NA);
    packet_tree = proto_item_add_subtree(ti, ett_uci);
    header_tree = proto_tree_add_subtree(packet_tree, tvb, offset, UCI_PACKET_HEADER_LEN, ett_uci_header, NULL, "UCI Packet Header");

    proto_tree_add_item(header_tree, hf_uci_message_type, tvb, offset + 0, 1, ENC_NA);
    proto_tree_add_item(header_tree, hf_uci_packet_boundary_flag, tvb, offset + 0, 1, ENC_NA);
    proto_tree_add_item(header_tree, hf_uci_group_id, tvb, offset + 0, 1, ENC_NA);
    proto_tree_add_item(header_tree, hf_uci_opcode_id, tvb, offset + 1, 1, ENC_NA);
    proto_tree_add_item(header_tree, hf_uci_payload_length, tvb, offset + 3, 1, ENC_NA);

    message_type = (tvb_get_uint8(tvb, offset + 0) >> 5) & 0x07;
    group_id = (tvb_get_uint8(tvb, offset + 0) >> 0) & 0x0f;
    opcode_id = tvb_get_uint8(tvb, offset + 1) & 0x3f;
    payload_len = tvb_get_uint8(tvb, offset + 3);

    offset += UCI_PACKET_HEADER_LEN;
    payload_tree = proto_tree_add_subtree(packet_tree, tvb, offset, payload_len, ett_uci_payload, NULL, "UCI Packet Payload");

    switch (group_id) {
    case UCI_GID_CORE: dissect_uci_core_pdu(tvb, offset, pinfo, payload_tree, message_type, opcode_id); break;
    case UCI_GID_SESSION_CONFIG: dissect_uci_session_config_pdu(tvb, offset, pinfo, payload_tree, message_type, opcode_id); break;
    case UCI_GID_RANGING_SESSION_CONTROL: dissect_uci_ranging_session_control_pdu(tvb, offset, pinfo, payload_tree, message_type, opcode_id); break;
    case UCI_GID_DATA_CONTROL: dissect_uci_data_control_pdu(tvb, offset, pinfo, payload_tree, message_type, opcode_id); break;
    case UCI_GID_TEST: dissect_uci_test_pdu(tvb, offset, pinfo, payload_tree, message_type, opcode_id); break;
    default: dissect_uci_vendor_pdu(tvb, offset, pinfo, payload_tree, message_type, group_id, opcode_id); break;
    }

    return tvb_reported_length(tvb);
}

static int dissect_uci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, gPREF_TCP_DESEGMENT, UCI_PACKET_HEADER_LEN,
        get_uci_pdu_len, dissect_uci_pdu, data);
    return tvb_reported_length(tvb);
}

void proto_register_uci(void)
{
    static hf_register_info hf[] = {
        { &hf_uci_message_type,
            { "UCI Message Type", "uci.mt",
                FT_UINT8, BASE_DEC,
                VALS(message_type_vals), 0xe0,
                NULL, HFILL }
        },
        { &hf_uci_packet_boundary_flag,
            { "UCI Packet Boundary Flag", "uci.pbf",
                FT_UINT8, BASE_HEX,
                VALS(packet_boundary_flag_vals), 0x10,
                NULL, HFILL }
        },
        { &hf_uci_group_id,
            { "UCI Group Identifier", "uci.gid",
                FT_UINT8, BASE_HEX,
                VALS(group_id_vals), 0x0f,
                NULL, HFILL }
        },
        { &hf_uci_opcode_id,
            { "UCI Opcode Identifier", "uci.oid",
                FT_UINT8, BASE_HEX,
                NULL, 0x3f,
                NULL, HFILL }
        },
        { &hf_uci_payload_length,
            { "UCI Payload Length", "uci.len",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_status,
            { "Status", "uci.status",
                FT_UINT8, BASE_DEC,
                VALS(status_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_reset_config,
            { "Reset Config", "uci.reset_config",
                FT_UINT8, BASE_DEC,
                VALS(reset_config_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_device_state,
            { "Device State", "uci.device_state",
                FT_UINT8, BASE_DEC,
                VALS(device_state_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_version_major,
            { "Major Version", "uci.major_version",
                FT_UINT16, BASE_DEC,
                NULL, 0x00ff,
                NULL, HFILL }
        },
        { &hf_uci_version_minor,
            { "Minor Version", "uci.minor_version",
                FT_UINT16, BASE_DEC,
                NULL, 0xf000,
                NULL, HFILL }
        },
        { &hf_uci_maintenance_number,
            { "Maintenance Number", "uci.maintenance_number",
                FT_UINT16, BASE_DEC,
                NULL, 0x0f00,
                NULL, HFILL }
        },
        { &hf_uci_generic_version,
            { "UCI Generic Version", "uci.generic_version",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_mac_version,
            { "MAC Version", "uci.mac_version",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_phy_version,
            { "PHY Version", "uci.phy_version",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_test_version,
            { "UCI Test Version", "uci.test_version",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_vendor_specific_information_length,
            { "Vendor Specific Information Length", "uci.vendor_specific_information_len",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_vendor_specific_information,
            { "Vendor Specific Information", "uci.vendor_specific_information",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_capability_parameters_count,
            { "Number of Capability Parameters", "uci.capability_parameters_count",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_capability_parameter_type,
            { "Type", "uci.capability_parameter.type",
                FT_UINT8, BASE_HEX,
                VALS(capability_parameter_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_capability_parameter_len,
            { "Length", "uci.capability_parameter.len",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_capability_parameter_value,
            { "Value", "uci.capability_parameter.value",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_parameters_count,
            { "Number of Parameters", "uci.parameters_count",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_parameter_type,
            { "Type", "uci.parameter.type",
                FT_UINT8, BASE_DEC,
                VALS(parameter_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_parameter_len,
            { "Length", "uci.parameter.len",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_parameter_value,
            { "Value", "uci.parameter.value",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_parameter_status,
            { "Status", "uci.parameter.status",
                FT_UINT8, BASE_HEX,
                VALS(status_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_session_id,
            { "Session ID", "uci.session_id",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_session_type,
            { "Session Type", "uci.session_type",
                FT_UINT8, BASE_HEX,
                VALS(session_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_session_state,
            { "Session Type", "uci.session_state",
                FT_UINT8, BASE_HEX,
                VALS(session_state_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_session_count,
            { "Session Count", "uci.session_count",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_app_config_parameters_count,
            { "Number of App Configurations", "uci.app_config_parameters_count",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_app_config_parameter_type,
            { "Type", "uci.app_config_parameter.type",
                FT_UINT8, BASE_DEC,
                VALS(app_config_parameter_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_app_config_parameter_len,
            { "Length", "uci.app_config_parameter.len",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_app_config_parameter_value,
            { "Value", "uci.app_config_parameter.value",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_app_config_parameter_status,
            { "Status", "uci.app_config_parameter.status",
                FT_UINT8, BASE_HEX,
                VALS(status_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_update_controller_multicast_list_action,
            { "Action", "uci.update_controller_multicast_list_action",
                FT_UINT8, BASE_HEX,
                VALS(update_controller_multicast_list_action_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_controlees_count,
            { "Number of Controlees", "uci.controlees_count",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_controlee_short_address,
            { "Short Address", "uci.controlee.short_address",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_controlee_subsession_id,
            { "Sub-Session ID", "uci.controlee.subsession_id",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_controlee_status,
            { "Status", "uci.controlee.status",
                FT_UINT8, BASE_HEX,
                VALS(multicast_update_status_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_remaining_multicast_list_size,
            { "Remaining Multicast List Size", "uci.remaining_multicast_list_size",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }

        },
        { &hf_uci_ranging_count,
            { "Count", "uci.ranging_count",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_sequence_number,
            { "Sequence Number", "uci.sequence_number",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_current_ranging_interval,
            { "Current Ranging Interval", "uci.current_ranging_interval",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_ranging_measurement_type,
            { "Ranging Measurement Type", "uci.ranging_measurement_type",
                FT_UINT8, BASE_HEX,
                VALS(ranging_measurement_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_mac_addressing_mode_indicator,
            { "MAC Addressing Mode Indicator", "uci.mac_addressing_mode_indicator",
                FT_UINT8, BASE_HEX,
                VALS(mac_addressing_mode_indicator_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_ranging_measurement_count,
            { "Number of Ranging Measurements", "uci.ranging_measurement_count",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_mac_address,
            { "MAC Address", "uci.mac_address",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_nlos,
            { "NLoS", "uci.nlos",
                FT_UINT8, BASE_HEX,
                VALS(nlos_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_uci_distance,
            { "Distance", "uci.distance",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_aoa_azimuth,
            { "AoA Azimuth", "uci.aoa_azimuth",
                FT_INT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_aoa_azimuth_fom,
            { "AoA Azimuth FOM", "uci.aoa_azimuth_fom",
                FT_INT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_aoa_elevation,
            { "AoA Elevation", "uci.aoa_elevation",
                FT_INT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_aoa_elevation_fom,
            { "AoA Elevation FOM", "uci.aoa_elevation_fom",
                FT_INT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_aoa_destination_azimuth,
            { "AoA Destination Azimuth", "uci.aoa_destination_azimuth",
                FT_INT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_aoa_destination_azimuth_fom,
            { "AoA Destination Azimuth FOM", "uci.aoa_destination_azimuth_fom",
                FT_INT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_aoa_destination_elevation,
            { "AoA Destination Elevation", "uci.aoa_destination_elevation",
                FT_INT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_aoa_destination_elevation_fom,
            { "AoA Destination Elevation FOM", "uci.aoa_destination_elevation_fom",
                FT_INT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uci_slot_index,
            { "Slot Index", "uci.slot_index",
                FT_INT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_uci,
        &ett_uci_header,
        &ett_uci_payload,
        &ett_uci_capability_parameters,
        &ett_uci_capability_parameter,
        &ett_uci_parameters,
        &ett_uci_parameter,
        &ett_uci_app_config_parameters,
        &ett_uci_app_config_parameter,
        &ett_uci_controlee_list,
        &ett_uci_controlee,
        &ett_uci_ranging_measurements,
        &ett_uci_ranging_measurement,
    };

    module_t *module_uci;

    proto_uci = proto_register_protocol (
        "UWB UCI Protocol", /* name        */
        "UCI",          /* short name  */
        "uci"           /* filter_name */
        );

    proto_register_field_array(proto_uci, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module_uci = prefs_register_protocol(proto_uci,
                                  proto_reg_handoff_uci);
    prefs_register_uint_preference(module_uci, "tcp.port",
        "TCP port",
        "Select preferred TCP port",
        10,
        &gPREF_TCP_PORT);
    prefs_register_bool_preference(module_uci, "tcp.desegment",
        "TCP desegment",
        "Enable desegmentation of UCI packets over TCP",
        &gPREF_TCP_DESEGMENT);

    handle_uci = create_dissector_handle(dissect_uci, proto_uci);
}

void proto_reg_handoff_uci(void)
{
    dissector_add_uint("tcp.port", gPREF_TCP_PORT, handle_uci);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_FIRA_UCI, handle_uci);
}
