/* packet-rdm.c
 * RDM (Remote Device Management) packet disassembly.
 *
 * This dissector is written by
 *
 *  Erwin Rol <erwin@erwinrol.com>
 *  Copyright 2003, 2011, 2012 Erwin Rol
 *
 *  Shaun Jackman <sjackman@gmail.com>
 *  Copyright 2006 Pathway Connectivity
 *
 *  Matt Morris <mattm.dev.1[AT]gmail.com?
 *  Copyright (c) 2025
 *
 *  Wireshark - Network traffic analyzer
 *  Gerald Combs <gerald@wireshark.org>
 *  Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * ANSI E1.20-2006, Entertainment Technology
 * Remote Device Management over USITT DMX512, describes a method of
 * bi-directional communications over a USITT DMX512/1990 data link
 * between an entertainment lighting controller and one or more
 * remotely controlled lighting devices. The protocol also is intended
 * to work with the ANSI E1.11-2004 control protocol. It allows
 * discovery of devices on a DMX512/E1.11 network and the remote
 * setting of DMX starting addresses, as well as status and fault
 * reporting back to the control console.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/unit_strings.h>
#include <epan/expert.h>
#include <epan/crc16-tvb.h>
#include "packet-rdm.h"
#include "packet-arp.h"
#include "data-dmx-manfid.h"

void proto_register_rdm(void);
void proto_reg_handoff_rdm(void);

static dissector_handle_t rdm_handle;
static dissector_table_t rdm_manf_dissector_table;

#define RDM_SC_RDM          0xCC
#define RDM_SC_SUB_MESSAGE  0x01

#define RDM_CC_COMMAND_RESPONSE_FLAG    0x01

#define RDM_CC_DISCOVERY_COMMAND           0x10
#define RDM_CC_DISCOVERY_COMMAND_RESPONSE  0x11
#define RDM_CC_GET_COMMAND                 0x20
#define RDM_CC_GET_COMMAND_RESPONSE        0x21
#define RDM_CC_SET_COMMAND                 0x30
#define RDM_CC_SET_COMMAND_RESPONSE        0x31

static const value_string rdm_cc_vals[] = {
  { RDM_CC_DISCOVERY_COMMAND,           "Discovery Command" },
  { RDM_CC_DISCOVERY_COMMAND_RESPONSE,  "Discovery Command Response" },
  { RDM_CC_GET_COMMAND,                 "Get Command" },
  { RDM_CC_GET_COMMAND_RESPONSE,        "Get Command Response" },
  { RDM_CC_SET_COMMAND,                 "Set Command" },
  { RDM_CC_SET_COMMAND_RESPONSE,        "Set Command Response" },
  { 0, NULL },
};

#define RDM_RESPONSE_TYPE_ACK               0x00
#define RDM_RESPONSE_TYPE_ACK_TIMER         0x01
#define RDM_RESPONSE_TYPE_NACK_REASON       0x02
#define RDM_RESPONSE_TYPE_ACK_OVERFLOW      0x03
#define RDM_RESPONSE_TYPE_ACK_TIMER_HI_RES  0x04

static const value_string rdm_rt_vals[] = {
  { RDM_RESPONSE_TYPE_ACK,              "Ack" },
  { RDM_RESPONSE_TYPE_ACK_TIMER,        "Ack Timer" },
  { RDM_RESPONSE_TYPE_NACK_REASON,      "Nack Reason" },
  { RDM_RESPONSE_TYPE_ACK_OVERFLOW,     "Ack Overflow" },
  { RDM_RESPONSE_TYPE_ACK_TIMER_HI_RES, "Ack Timer High Res" },
  { 0, NULL },
};

#define RDM_NR_UNKNOWN_PID                      0x0000
#define RDM_NR_FORMAT_ERROR                     0x0001
#define RDM_NR_HARDWARE_FAULT                   0x0002
#define RDM_NR_PROXY_REJECT                     0x0003
#define RDM_NR_WRITE_PROTECT                    0x0004
#define RDM_NR_UNSUPPORTED_COMMAND_CLASS        0x0005
#define RDM_NR_DATA_OUT_OF_RANGE                0x0006
#define RDM_NR_BUFFER_FULL                      0x0007
#define RDM_NR_PACKET_SIZE_UNSUPPORTED          0x0008
#define RDM_NR_SUB_DEVICE_OUT_OF_RANGE          0x0009
#define RDM_NR_PROXY_BUFFER_FULL                0x000A
#define RDM_NR_ACTION_NOT_SUPPORTED             0x000B  /* E1.37-2 */
#define RDM_NR_ENDPOINT_NUMBER_INVALID          0x000C  /* E1.37-7 */
#define RDM_NR_INVALID_ENDPOINT_MODE            0x000D  /* E1.37-7 */
#define RDM_NR_UNKNOWN_UID                      0x000E  /* E1.37-7 */
#define RDM_NR_UNKNOWN_SCOPE                    0x000F  /* E1.33 */
#define RDM_NR_INVALID_STATIC_CONFIG_TYPE       0x0010  /* E1.33 */
#define RDM_NR_INVALID_IPV4_ADDRESS             0x0011  /* E1.33 */
#define RDM_NR_INVALID_IPV6_ADDRESS             0x0012  /* E1.33 */
#define RDM_NR_INVALID_PORT                     0x0013  /* E1.33 */
#define RDM_NR_DEVICE_ABSENT                    0x0014
#define RDM_NR_SENSOR_OUT_OF_RANGE              0x0015
#define RDM_NR_SENSOR_FAULT                     0x0016
#define RDM_NR_PACKING_NOT_SUPPORTED            0x0017
#define RDM_NR_ERROR_IN_PACKED_LIST_TRANSACTION 0x0018
#define RDM_NR_PROXY_DROP                       0x0019
#define RDM_NR_ALL_CALL_SET_FAIL                0x001A

static const value_string rdm_nr_vals[] = {
  { RDM_NR_UNKNOWN_PID,                       "Unknown PID" },
  { RDM_NR_FORMAT_ERROR,                      "Format Error" },
  { RDM_NR_HARDWARE_FAULT,                    "Hardware Fault" },
  { RDM_NR_PROXY_REJECT,                      "Proxy Reject" },
  { RDM_NR_WRITE_PROTECT,                     "Write Protect" },
  { RDM_NR_UNSUPPORTED_COMMAND_CLASS,         "Unsupported Command Class" },
  { RDM_NR_DATA_OUT_OF_RANGE,                 "Data Out Of Range" },
  { RDM_NR_BUFFER_FULL,                       "Buffer Full" },
  { RDM_NR_PACKET_SIZE_UNSUPPORTED,           "Packet Size Unsupported" },
  { RDM_NR_SUB_DEVICE_OUT_OF_RANGE,           "Sub-Device Out Of Range" },
  { RDM_NR_PROXY_BUFFER_FULL,                 "Proxy Buffer Full" },
  { RDM_NR_ACTION_NOT_SUPPORTED,              "Action Not Supported" },       /* E1.37-2 */
  { RDM_NR_ENDPOINT_NUMBER_INVALID,           "Endpoint Number Invalid" },    /* E1.37-7 */
  { RDM_NR_INVALID_ENDPOINT_MODE,             "Invalid Endpoint Mode" },      /* E1.37-7 */
  { RDM_NR_UNKNOWN_UID,                       "Unknown UID" },                /* E1.37-7 */
  { RDM_NR_UNKNOWN_SCOPE,                     "Unknown Scope" },              /* E1.33 */
  { RDM_NR_INVALID_STATIC_CONFIG_TYPE,        "Invalid Static Config Type" }, /* E1.33 */
  { RDM_NR_INVALID_IPV4_ADDRESS,              "Invalid IPv4 Address" },       /* E1.33 */
  { RDM_NR_INVALID_IPV6_ADDRESS,              "Invalid IPv6 Address" },       /* E1.33 */
  { RDM_NR_INVALID_PORT,                      "Invalid Port" },               /* E1.33 */
  { RDM_NR_DEVICE_ABSENT,                     "Device Absent" },
  { RDM_NR_SENSOR_OUT_OF_RANGE,               "Sensor Out Of Range" },
  { RDM_NR_SENSOR_FAULT,                      "Sensor Fault" },
  { RDM_NR_PACKING_NOT_SUPPORTED,             "Packing Not Supported" },
  { RDM_NR_ERROR_IN_PACKED_LIST_TRANSACTION,  "Error In Packed Transaction List" },
  { RDM_NR_PROXY_DROP,                        "Proxy Drop" },
  { RDM_NR_ALL_CALL_SET_FAIL,                 "All Call Set Fail" },
  { 0, NULL },
};

/* E1.20, E1.33, and E1.37 PIDs */
#define RDM_PARAM_ID_DISC_UNIQUE_BRANCH                           0x0001
#define RDM_PARAM_ID_DISC_MUTE                                    0x0002
#define RDM_PARAM_ID_DISC_UN_MUTE                                 0x0003
#define RDM_PARAM_ID_PROXIED_DEVICES                              0x0010
#define RDM_PARAM_ID_PROXIED_DEVICE_COUNT                         0x0011
#define RDM_PARAM_ID_COMMS_STATUS                                 0x0015
#define RDM_PARAM_ID_TEST_DATA                                    0x0016  /* E1.37-5 */
#define RDM_PARAM_ID_COMMS_STATUS_NSC                             0x0017  /* E1.37-5 */
#define RDM_PARAM_ID_QUEUED_MESSAGE                               0x0020
#define RDM_PARAM_ID_STATUS_MESSAGES                              0x0030
#define RDM_PARAM_ID_STATUS_ID_DESCRIPTION                        0x0031
#define RDM_PARAM_ID_CLEAR_STATUS_ID                              0x0032
#define RDM_PARAM_ID_SUB_DEVICE_STATUS_REPORT_THRESHOLD           0x0033
#define RDM_PARAM_ID_QUEUED_MESSAGE_SENSOR_SUBSCRIBE              0x0034
#define RDM_PARAM_ID_SUPPORTED_PARAMETERS                         0x0050
#define RDM_PARAM_ID_PARAMETER_DESCRIPTION                        0x0051
#define RDM_PARAM_ID_METADATA_PARAMETER_VERSION                   0x0052  /* E1.37-5 */
#define RDM_PARAM_ID_METADATA_JSON                                0x0053  /* E1.37-5 */
#define RDM_PARAM_ID_METADATA_JSON_URL                            0x0054  /* E1.37-5 */
#define RDM_PARAM_ID_SUPPORTED_PARAMETERS_ENHANCED                0x0055
#define RDM_PARAM_ID_CONTROLLER_FLAG_SUPPORT                      0x0056
#define RDM_PARAM_ID_NACK_DESCRIPTION                             0x0057
#define RDM_PARAM_ID_PACKED_PID_SUB                               0x0058
#define RDM_PARAM_ID_PACKED_PID_INDEX                             0x0059
#define RDM_PARAM_ID_ENUM_LABEL                                   0x005A
#define RDM_PARAM_ID_DEVICE_INFO                                  0x0060
#define RDM_PARAM_ID_PRODUCT_DETAIL_ID_LIST                       0x0070
#define RDM_PARAM_ID_DEVICE_MODEL_DESCRIPTION                     0x0080
#define RDM_PARAM_ID_MANUFACTURER_LABEL                           0x0081
#define RDM_PARAM_ID_DEVICE_LABEL                                 0x0082
#define RDM_PARAM_ID_FACTORY_DEFAULTS                             0x0090
#define RDM_PARAM_ID_LANGUAGE_CAPABILITIES                        0x00A0
#define RDM_PARAM_ID_LANGUAGE                                     0x00B0
#define RDM_PARAM_ID_SOFTWARE_VERSION_LABEL                       0x00C0
#define RDM_PARAM_ID_BOOT_SOFTWARE_VERSION_ID                     0x00C1
#define RDM_PARAM_ID_BOOT_SOFTWARE_VERSION_LABEL                  0x00C2
#define RDM_PARAM_ID_MANUFACTURER_URL                             0x00D0  /* E1.37-5 */
#define RDM_PARAM_ID_PRODUCT_URL                                  0x00D1  /* E1.37-5 */
#define RDM_PARAM_ID_FIRMWARE_URL                                 0x00D2  /* E1.37-5 */
#define RDM_PARAM_ID_SERIAL_NUMBER                                0x00D3  /* E1.37-5 */
#define RDM_PARAM_ID_DEVICE_INFO_OFFSTAGE                         0x00D4  /* E1.37-5 */
#define RDM_PARAM_ID_DMX_PERSONALITY                              0x00E0
#define RDM_PARAM_ID_DMX_PERSONALITY_DESCRIPTION                  0x00E1
#define RDM_PARAM_ID_DMX_PERSONALITY_ID                           0x00E2  /* E1.37-5 */
#define RDM_PARAM_ID_DMX_START_ADDRESS                            0x00F0
#define RDM_PARAM_ID_SLOT_INFO                                    0x0120
#define RDM_PARAM_ID_SLOT_DESCRIPTION                             0x0121
#define RDM_PARAM_ID_DEFAULT_SLOT_VALUE                           0x0122

#define RDM_PARAM_ID_DMX_BLOCK_ADDRESS                            0x0140  /* E1.37-1 */
#define RDM_PARAM_ID_DMX_FAIL_MODE                                0x0141
#define RDM_PARAM_ID_DMX_STARTUP_MODE                             0x0142

#define RDM_PARAM_ID_SENSOR_DEFINITION                            0x0200
#define RDM_PARAM_ID_SENSOR_VALUE                                 0x0201
#define RDM_PARAM_ID_RECORD_SENSORS                               0x0202

#define RDM_PARAM_ID_SENSOR_TYPE_CUSTOM                           0x0210  /* E1.37-5 */
#define RDM_PARAM_ID_SENSOR_UNIT_CUSTOM                           0x0211

#define RDM_PARAM_ID_DIMMER_INFO                                  0x0340  /* E1.37-1 */
#define RDM_PARAM_ID_MINIMUM_LEVEL                                0x0341
#define RDM_PARAM_ID_MAXIMUM_LEVEL                                0x0342
#define RDM_PARAM_ID_CURVE                                        0x0343
#define RDM_PARAM_ID_CURVE_DESCRIPTION                            0x0344
#define RDM_PARAM_ID_OUTPUT_RESPONSE_TIME                         0x0345
#define RDM_PARAM_ID_OUTPUT_RESPONSE_TIME_DESCRIPTION             0x0346
#define RDM_PARAM_ID_MODULATION_FREQUENCY                         0x0347
#define RDM_PARAM_ID_MODULATION_FREQUENCY_DESCRIPTION             0x0348

#define RDM_PARAM_ID_DEVICE_HOURS                                 0x0400
#define RDM_PARAM_ID_LAMP_HOURS                                   0x0401
#define RDM_PARAM_ID_LAMP_STRIKES                                 0x0402
#define RDM_PARAM_ID_LAMP_STATE                                   0x0403
#define RDM_PARAM_ID_LAMP_ON_MODE                                 0x0404
#define RDM_PARAM_ID_DEVICE_POWER_CYCLES                          0x0405

#define RDM_PARAM_ID_BURN_IN                                      0x0440  /* E1.37-1 */

#define RDM_PARAM_ID_DISPLAY_INVERT                               0x0500
#define RDM_PARAM_ID_DISPLAY_LEVEL                                0x0501
#define RDM_PARAM_ID_PAN_INVERT                                   0x0600
#define RDM_PARAM_ID_TILT_INVERT                                  0x0601
#define RDM_PARAM_ID_PAN_TILT_SWAP                                0x0602
#define RDM_PARAM_ID_REAL_TIME_CLOCK                              0x0603

#define RDM_PARAM_ID_LOCK_PIN                                     0x0640  /* E1.37-1 */
#define RDM_PARAM_ID_LOCK_STATE                                   0x0641
#define RDM_PARAM_ID_LOCK_STATE_DESCRIPTION                       0x0642

#define RDM_PARAM_ID_SHIPPING_LOCK                                0x0650  /* E1.37-5 */
#define RDM_PARAM_ID_LIST_TAGS                                    0x0651
#define RDM_PARAM_ID_ADD_TAG                                      0x0652
#define RDM_PARAM_ID_REMOVE_TAG                                   0x0653
#define RDM_PARAM_ID_CHECK_TAG                                    0x0654
#define RDM_PARAM_ID_CLEAR_TAGS                                   0x0655
#define RDM_PARAM_ID_DEVICE_UNIT_NUMBER                           0x0656

#define RDM_PARAM_ID_LIST_INTERFACES                              0x0700  /* E1.37-2 */
#define RDM_PARAM_ID_INTERFACE_LABEL                              0x0701
#define RDM_PARAM_ID_INTERFACE_HARDWARE_ADDRESS_TYPE1             0x0702
#define RDM_PARAM_ID_IPV4_DHCP_MODE                               0x0703
#define RDM_PARAM_ID_IPV4_ZEROCONF_MODE                           0x0704
#define RDM_PARAM_ID_IPV4_CURRENT_ADDRESS                         0x0705
#define RDM_PARAM_ID_IPV4_STATIC_ADDRESS                          0x0706
#define RDM_PARAM_ID_INTERFACE_RENEW_DHCP                         0x0707
#define RDM_PARAM_ID_INTERFACE_RELEASE_DHCP                       0x0708
#define RDM_PARAM_ID_INTERFACE_APPLY_CONFIGURATION                0x0709
#define RDM_PARAM_ID_IPV4_DEFAULT_ROUTE                           0x070A
#define RDM_PARAM_ID_DNS_IPV4_NAME_SERVER                         0x070B
#define RDM_PARAM_ID_DNS_HOSTNAME                                 0x070C
#define RDM_PARAM_ID_DNS_DOMAIN_NAME                              0x070D

#define RDM_PARAM_ID_COMPONENT_SCOPE                              0x0800  /* E1.33 */
#define RDM_PARAM_ID_SEARCH_DOMAIN                                0x0801
#define RDM_PARAM_ID_TCP_COMMS_STATUS                             0x0802
#define RDM_PARAM_ID_BROKER_STATUS                                0x0803

#define RDM_PARAM_ID_ENDPOINT_LIST                                0x0900  /* E1.37-7 */
#define RDM_PARAM_ID_ENDPOINT_LIST_CHANGE                         0x0901
#define RDM_PARAM_ID_IDENTIFY_ENDPOINT                            0x0902
#define RDM_PARAM_ID_ENDPOINT_TO_UNIVERSE                         0x0903
#define RDM_PARAM_ID_ENDPOINT_MODE                                0x0904
#define RDM_PARAM_ID_ENDPOINT_LABEL                               0x0905
#define RDM_PARAM_ID_RDM_TRAFFIC_ENABLE                           0x0906
#define RDM_PARAM_ID_DISCOVERY_STATE                              0x0907
#define RDM_PARAM_ID_BACKGROUND_DISCOVERY                         0x0908
#define RDM_PARAM_ID_ENDPOINT_TIMING                              0x0909
#define RDM_PARAM_ID_ENDPOINT_TIMING_DESCRIPTION                  0x090A
#define RDM_PARAM_ID_ENDPOINT_RESPONDERS                          0x090B
#define RDM_PARAM_ID_ENDPOINT_RESPONDER_LIST_CHANGE               0x090C
#define RDM_PARAM_ID_BINDING_CONTROL_FIELDS                       0x090D
#define RDM_PARAM_ID_BACKGROUND_QUEUED_STATUS_POLICY              0x090E
#define RDM_PARAM_ID_BACKGROUND_QUEUED_STATUS_POLICY_DESCRIPTION  0x090F

#define RDM_PARAM_ID_IDENTIFY_DEVICE                              0x1000
#define RDM_PARAM_ID_RESET_DEVICE                                 0x1001
#define RDM_PARAM_ID_POWER_STATE                                  0x1010
#define RDM_PARAM_ID_PERFORM_SELFTEST                             0x1020
#define RDM_PARAM_ID_SELF_TEST_DESCRIPTION                        0x1021
#define RDM_PARAM_ID_SELF_TEST_ENHANCED                           0x1022
#define RDM_PARAM_ID_CAPTURE_PRESET                               0x1030
#define RDM_PARAM_ID_PRESET_PLAYBACK                              0x1031

#define RDM_PARAM_ID_IDENTIFY_MODE                                0x1040  /* E1.37-1 */
#define RDM_PARAM_ID_PRESET_INFO                                  0x1041
#define RDM_PARAM_ID_PRESET_STATUS                                0x1042
#define RDM_PARAM_ID_PRESET_MERGEMODE                             0x1043
#define RDM_PARAM_ID_POWER_ON_SELF_TEST                           0x1044

#define RDM_PARAM_ID_IDENTIFY_TIMEOUT                             0x1050  /* E1.37-5 */
#define RDM_PARAM_ID_POWER_OFF_READY                              0x1051

#define RDM_PARAM_ID_FTC_INITIATE                                 0x1200  /* E1.37-4 */
#define RDM_PARAM_ID_FTC_TRANSFER_UPLOAD                          0x1201
#define RDM_PARAM_ID_FTC_COMMIT                                   0x1202
#define RDM_PARAM_ID_FTC_CANCEL                                   0x1203
#define RDM_PARAM_ID_FTC_FILELIST                                 0x1204
#define RDM_PARAM_ID_FTC_TRANSFER_DOWNLOAD                        0x1205

static const value_string rdm_param_id_vals[] = {
  { RDM_PARAM_ID_DISC_UNIQUE_BRANCH,                  "Discovery Unique Branch" },
  { RDM_PARAM_ID_DISC_MUTE,                           "Discovery Mute" },
  { RDM_PARAM_ID_DISC_UN_MUTE,                        "Discovery Un-Mute" },
  { RDM_PARAM_ID_PROXIED_DEVICES,                     "Proxied Devices" },
  { RDM_PARAM_ID_PROXIED_DEVICE_COUNT,                "Proxied Device Count" },
  { RDM_PARAM_ID_COMMS_STATUS,                        "Communication Status" },
  { RDM_PARAM_ID_TEST_DATA,                           "Test Data" },                             /* E1.37-5 */
  { RDM_PARAM_ID_COMMS_STATUS_NSC,                    "NULL START Code Communication Status" },  /* E1.37-5 */
  { RDM_PARAM_ID_QUEUED_MESSAGE,                      "Queued Messages" },
  { RDM_PARAM_ID_STATUS_MESSAGES,                     "Status Messages" },
  { RDM_PARAM_ID_STATUS_ID_DESCRIPTION,               "Status ID Description" },
  { RDM_PARAM_ID_CLEAR_STATUS_ID,                     "Clear Status ID" },
  { RDM_PARAM_ID_SUB_DEVICE_STATUS_REPORT_THRESHOLD,  "Device Status Reporting Threshold" },
  { RDM_PARAM_ID_QUEUED_MESSAGE_SENSOR_SUBSCRIBE,     "Queued Message Sensor Subscription" },
  { RDM_PARAM_ID_SUPPORTED_PARAMETERS,                "Supported Parameters" },
  { RDM_PARAM_ID_PARAMETER_DESCRIPTION,               "Parameter Description" },
  { RDM_PARAM_ID_METADATA_PARAMETER_VERSION,          "Metadata Parameter Version" },  /* E1.37-5 */
  { RDM_PARAM_ID_METADATA_JSON,                       "Metadata JSON" },               /* E1.37-5 */
  { RDM_PARAM_ID_METADATA_JSON_URL,                   "Metadata JSON URL" },           /* E1.37-5 */
  { RDM_PARAM_ID_SUPPORTED_PARAMETERS_ENHANCED,       "Supported Parameters Enhanced" },
  { RDM_PARAM_ID_CONTROLLER_FLAG_SUPPORT,             "Controller Flag Support" },
  { RDM_PARAM_ID_NACK_DESCRIPTION,                    "NACK Reason Description" },
  { RDM_PARAM_ID_PACKED_PID_SUB,                      "Packed PIDs for Sub-Devices" },
  { RDM_PARAM_ID_PACKED_PID_INDEX,                    "Packed PIDs by Index" },
  { RDM_PARAM_ID_ENUM_LABEL,                          "Enum Label" },
  { RDM_PARAM_ID_DEVICE_INFO,                         "Device Info" },
  { RDM_PARAM_ID_PRODUCT_DETAIL_ID_LIST,              "Product Detail ID List" },
  { RDM_PARAM_ID_DEVICE_MODEL_DESCRIPTION,            "Device Model Description" },
  { RDM_PARAM_ID_MANUFACTURER_LABEL,                  "Manufacturer Label" },
  { RDM_PARAM_ID_DEVICE_LABEL,                        "Device Label" },
  { RDM_PARAM_ID_FACTORY_DEFAULTS,                    "Factory Defaults" },
  { RDM_PARAM_ID_LANGUAGE_CAPABILITIES,               "Language Capabilities" },
  { RDM_PARAM_ID_LANGUAGE,                            "Language" },
  { RDM_PARAM_ID_SOFTWARE_VERSION_LABEL,              "Software Version Label" },
  { RDM_PARAM_ID_BOOT_SOFTWARE_VERSION_ID,            "Boot Software Version ID" },
  { RDM_PARAM_ID_BOOT_SOFTWARE_VERSION_LABEL,         "Boot Software Version Label" },
  { RDM_PARAM_ID_MANUFACTURER_URL,                    "Manufacturer URL" },             /* E1.37-5 */
  { RDM_PARAM_ID_PRODUCT_URL,                         "Product URL" },                  /* E1.37-5 */
  { RDM_PARAM_ID_FIRMWARE_URL,                        "Firmware URL" },                 /* E1.37-5 */
  { RDM_PARAM_ID_SERIAL_NUMBER,                       "Serial Number" },                /* E1.37-5 */
  { RDM_PARAM_ID_DEVICE_INFO_OFFSTAGE,                "Device Information Offstage" },  /* E1.37-5 */
  { RDM_PARAM_ID_DMX_PERSONALITY,                     "DMX Personality" },
  { RDM_PARAM_ID_DMX_PERSONALITY_DESCRIPTION,         "DMX Personality Description" },
  { RDM_PARAM_ID_DMX_PERSONALITY_ID,                  "DMX Personality Id" },           /* E1.37-5 */
  { RDM_PARAM_ID_DMX_START_ADDRESS,                   "DMX Start Address" },
  { RDM_PARAM_ID_SLOT_INFO,                           "Slot Info" },
  { RDM_PARAM_ID_SLOT_DESCRIPTION,                    "Slot Description" },
  { RDM_PARAM_ID_DEFAULT_SLOT_VALUE,                  "Default Slot Value" },

  { RDM_PARAM_ID_DMX_BLOCK_ADDRESS,                   "DMX Block Address" },  /* E1.37-1 */
  { RDM_PARAM_ID_DMX_FAIL_MODE,                       "DMX Fail Mode" },
  { RDM_PARAM_ID_DMX_STARTUP_MODE,                    "DMX Startup Mode" },

  { RDM_PARAM_ID_SENSOR_DEFINITION,                   "Sensor Definition" },
  { RDM_PARAM_ID_SENSOR_VALUE,                        "Sensor Value" },
  { RDM_PARAM_ID_RECORD_SENSORS,                      "Record Sensors" },

  { RDM_PARAM_ID_SENSOR_TYPE_CUSTOM,                  "Sensor Type Custom Defines" },  /* E1.37-5 */
  { RDM_PARAM_ID_SENSOR_UNIT_CUSTOM,                  "Sensor Unit Custom defines" },

  { RDM_PARAM_ID_DIMMER_INFO,                         "Dimmer Info" },  /* E1.37-1 */
  { RDM_PARAM_ID_MINIMUM_LEVEL,                       "Minimum Level" },
  { RDM_PARAM_ID_MAXIMUM_LEVEL,                       "Maximum Level" },
  { RDM_PARAM_ID_CURVE,                               "Curve" },
  { RDM_PARAM_ID_CURVE_DESCRIPTION,                   "Curve Description" },
  { RDM_PARAM_ID_OUTPUT_RESPONSE_TIME,                "Output Response Time" },
  { RDM_PARAM_ID_OUTPUT_RESPONSE_TIME_DESCRIPTION,    "Output Response Time Description" },
  { RDM_PARAM_ID_MODULATION_FREQUENCY,                "Modulation Frequency" },
  { RDM_PARAM_ID_MODULATION_FREQUENCY_DESCRIPTION,    "Modulation Frequency Description" },

  { RDM_PARAM_ID_DEVICE_HOURS,                        "Device Hours" },
  { RDM_PARAM_ID_LAMP_HOURS,                          "Lamp Hours" },
  { RDM_PARAM_ID_LAMP_STRIKES,                        "Lamp Strikes" },
  { RDM_PARAM_ID_LAMP_STATE,                          "Lamp State" },
  { RDM_PARAM_ID_LAMP_ON_MODE,                        "Lamp On Mode" },
  { RDM_PARAM_ID_DEVICE_POWER_CYCLES,                 "Device Power Cycles" },

  { RDM_PARAM_ID_BURN_IN,                             "Burn In" },  /* E1.37-1 */

  { RDM_PARAM_ID_DISPLAY_INVERT,                      "Display Invert" },
  { RDM_PARAM_ID_DISPLAY_LEVEL,                       "Display Level" },
  { RDM_PARAM_ID_PAN_INVERT,                          "Pan Invert" },
  { RDM_PARAM_ID_TILT_INVERT,                         "Tilt Invert" },
  { RDM_PARAM_ID_PAN_TILT_SWAP,                       "Pan Tilt Swap" },
  { RDM_PARAM_ID_REAL_TIME_CLOCK,                     "Real Time Clock" },

  { RDM_PARAM_ID_LOCK_PIN,                            "Lock PIN" },  /* E1.37-1 */
  { RDM_PARAM_ID_LOCK_STATE,                          "Lock State" },
  { RDM_PARAM_ID_LOCK_STATE_DESCRIPTION,              "Lock State Description" },

  { RDM_PARAM_ID_SHIPPING_LOCK,                       "Shipping Lock" },  /* E1.37-5 */
  { RDM_PARAM_ID_LIST_TAGS,                           "List Tags" },
  { RDM_PARAM_ID_ADD_TAG,                             "Add Tag" },
  { RDM_PARAM_ID_REMOVE_TAG,                          "Remove Tag" },
  { RDM_PARAM_ID_CHECK_TAG,                           "Check Tag" },
  { RDM_PARAM_ID_CLEAR_TAGS,                          "Clear Tags" },
  { RDM_PARAM_ID_DEVICE_UNIT_NUMBER,                  "Device Unit Number" },

  { RDM_PARAM_ID_LIST_INTERFACES,                     "List Interfaces" },  /* E1.37-2 */
  { RDM_PARAM_ID_INTERFACE_LABEL,                     "Interface Label" },
  { RDM_PARAM_ID_INTERFACE_HARDWARE_ADDRESS_TYPE1,    "Interface Hardware Address Type 1" },
  { RDM_PARAM_ID_IPV4_DHCP_MODE,                      "IPv4 DHCP Mode" },
  { RDM_PARAM_ID_IPV4_ZEROCONF_MODE,                  "IPv4 Zero Configuration Mode" },
  { RDM_PARAM_ID_IPV4_CURRENT_ADDRESS,                "IPv4 Current Address" },
  { RDM_PARAM_ID_IPV4_STATIC_ADDRESS,                 "IPv4 Static Address" },
  { RDM_PARAM_ID_INTERFACE_RENEW_DHCP,                "Interface Renew DHCP" },
  { RDM_PARAM_ID_INTERFACE_RELEASE_DHCP,              "Interface Release DHCP" },
  { RDM_PARAM_ID_INTERFACE_APPLY_CONFIGURATION,       "Interface Apply Configuration" },
  { RDM_PARAM_ID_IPV4_DEFAULT_ROUTE,                  "IPv4 Default Route" },
  { RDM_PARAM_ID_DNS_IPV4_NAME_SERVER,                "DNS IPv4 Name Server" },
  { RDM_PARAM_ID_DNS_HOSTNAME,                        "DNS Hostname" },
  { RDM_PARAM_ID_DNS_DOMAIN_NAME,                     "DNS Domain Name" },

  { RDM_PARAM_ID_COMPONENT_SCOPE,                     "Component Scope" },  /* E1.33 */
  { RDM_PARAM_ID_SEARCH_DOMAIN,                       "Search Domain" },
  { RDM_PARAM_ID_TCP_COMMS_STATUS,                    "TCP Communication Status" },
  { RDM_PARAM_ID_BROKER_STATUS,                       "Broker Status" },

  { RDM_PARAM_ID_ENDPOINT_LIST,                       "Endpoint List" },  /* E1.37-7 */
  { RDM_PARAM_ID_ENDPOINT_LIST_CHANGE,                "Endpoint List Change" },
  { RDM_PARAM_ID_IDENTIFY_ENDPOINT,                   "Identify Endpoint" },
  { RDM_PARAM_ID_ENDPOINT_TO_UNIVERSE,                "Endpoint To Universe" },
  { RDM_PARAM_ID_ENDPOINT_MODE,                       "Endpoint Mode" },
  { RDM_PARAM_ID_ENDPOINT_LABEL,                      "Endpoint Label" },
  { RDM_PARAM_ID_RDM_TRAFFIC_ENABLE,                  "RDM Traffic Enable" },
  { RDM_PARAM_ID_DISCOVERY_STATE,                     "Discovery State" },
  { RDM_PARAM_ID_BACKGROUND_DISCOVERY,                "Background Discovery" },
  { RDM_PARAM_ID_ENDPOINT_TIMING,                     "Endpoint Timing" },
  { RDM_PARAM_ID_ENDPOINT_TIMING_DESCRIPTION,         "Endpoint Timing Description" },
  { RDM_PARAM_ID_ENDPOINT_RESPONDERS,                 "Endpoint Responders" },
  { RDM_PARAM_ID_ENDPOINT_RESPONDER_LIST_CHANGE,      "Endpoint Responder List Change" },
  { RDM_PARAM_ID_BINDING_CONTROL_FIELDS,              "Binding Control Fields" },
  { RDM_PARAM_ID_BACKGROUND_QUEUED_STATUS_POLICY,     "Background Queued Status Policy" },
  { RDM_PARAM_ID_BACKGROUND_QUEUED_STATUS_POLICY_DESCRIPTION,  "Background Queued Status Policy Description" },

  { RDM_PARAM_ID_IDENTIFY_DEVICE,                     "Identify Device" },
  { RDM_PARAM_ID_RESET_DEVICE,                        "Reset Device" },
  { RDM_PARAM_ID_POWER_STATE,                         "Power State" },
  { RDM_PARAM_ID_PERFORM_SELFTEST,                    "Perform Self Test" },
  { RDM_PARAM_ID_SELF_TEST_DESCRIPTION,               "Self Test Description" },
  { RDM_PARAM_ID_SELF_TEST_ENHANCED,                  "Self Test Enhanced" },
  { RDM_PARAM_ID_CAPTURE_PRESET,                      "Capture Preset" },
  { RDM_PARAM_ID_PRESET_PLAYBACK,                     "Preset Playback" },

  { RDM_PARAM_ID_IDENTIFY_MODE,                       "Identify Mode" },  /* E1.37-1 */
  { RDM_PARAM_ID_PRESET_INFO,                         "Preset Info" },
  { RDM_PARAM_ID_PRESET_STATUS,                       "Preset Status" },
  { RDM_PARAM_ID_PRESET_MERGEMODE,                    "Preset Merge Mode" },
  { RDM_PARAM_ID_POWER_ON_SELF_TEST,                  "Power On Self Test" },

  { RDM_PARAM_ID_IDENTIFY_TIMEOUT,                    "Identify Timeout" },  /* E1.37-5 */
  { RDM_PARAM_ID_POWER_OFF_READY,                     "Power Off Ready" },

  { RDM_PARAM_ID_FTC_INITIATE,                        "FTC Initiate Transfer" },  /* E1.37- 4 */
  { RDM_PARAM_ID_FTC_TRANSFER_UPLOAD,                 "FTC Transfer Data Upload" },
  { RDM_PARAM_ID_FTC_COMMIT,                          "FTC Commit Data" },
  { RDM_PARAM_ID_FTC_CANCEL,                          "FTC Cancel Transfer" },
  { RDM_PARAM_ID_FTC_FILELIST,                        "FTC File List" },
  { RDM_PARAM_ID_FTC_TRANSFER_DOWNLOAD,               "FTC Transfer Data Download" },

  { 0, NULL },
};

value_string_ext rdm_param_id_vals_ext = VALUE_STRING_EXT_INIT(rdm_param_id_vals);

#define RDM_STATUS_NONE              0x00
#define RMD_STATUS_GET_LAST_MESSAGE  0x01
#define RDM_STATUS_ADVISORY          0x02
#define RDM_STATUS_WARNING           0x03
#define RDM_STATUS_ERROR             0x04
#define RDM_STATUS_ADVISORY_CLEARED  0x12
#define RDM_STATUS_WARNING_CLEARED   0x13
#define RDM_STATUS_ERROR_CLEARED     0x14

static const value_string rdm_status_vals[] = {
  { RDM_STATUS_NONE,              "None" },
  { RMD_STATUS_GET_LAST_MESSAGE,  "Get Last Message" },
  { RDM_STATUS_ADVISORY,          "Advisory" },
  { RDM_STATUS_WARNING,           "Warning" },
  { RDM_STATUS_ERROR,             "Error" },
  { RDM_STATUS_ADVISORY_CLEARED,  "Advisory Cleared" },
  { RDM_STATUS_WARNING_CLEARED,   "Warning Cleared" },
  { RDM_STATUS_ERROR_CLEARED,     "Error Cleared" },
  { 0, NULL },
};

#define RDM_PREFIX_NONE    0x00
#define RDM_PREFIX_DECI    0x01
#define RDM_PREFIX_CENTI   0x02
#define RDM_PREFIX_MILLI   0x03
#define RDM_PREFIX_MICRO   0x04
#define RDM_PREFIX_NANO    0x05
#define RDM_PREFIX_PICO    0x06
#define RDM_PREFIX_FEMPTO  0x07
#define RDM_PREFIX_ATTO    0x08
#define RDM_PREFIX_ZEPTO   0x09
#define RDM_PREFIX_YOCTO   0x0A
#define RDM_PREFIX_DECA    0x11
#define RDM_PREFIX_HECTO   0x12
#define RDM_PREFIX_KILO    0x13
#define RDM_PREFIX_MEGA    0x14
#define RDM_PREFIX_GIGA    0x15
#define RDM_PREFIX_TERRA   0x16
#define RDM_PREFIX_PETA    0x17
#define RDM_PREFIX_EXA     0x18
#define RDM_PREFIX_ZETTA   0x19
#define RDM_PREFIX_YOTTA   0x1A

static const value_string rdm_prefix_vals[] = {
  { RDM_PREFIX_NONE,    "NONE (x1)" },
  { RDM_PREFIX_DECI,    "deci (x10^-1)" },
  { RDM_PREFIX_CENTI,   "centi (x10^-2)" },
  { RDM_PREFIX_MILLI,   "milli (x10^-3)" },
  { RDM_PREFIX_MICRO,   "micro (x10^-6)" },
  { RDM_PREFIX_NANO,    "nano (x10^-9)" },
  { RDM_PREFIX_PICO,    "pico (x10^-12)" },
  { RDM_PREFIX_FEMPTO,  "fempto (x10^-15)" },
  { RDM_PREFIX_ATTO,    "atto (x10^-18)" },
  { RDM_PREFIX_ZEPTO,   "zepto (x10^-21)" },
  { RDM_PREFIX_YOCTO,   "yocto (x10^-24)" },
  { RDM_PREFIX_DECA,    "deca (x10^1)" },
  { RDM_PREFIX_HECTO,   "hecto (x10^2)" },
  { RDM_PREFIX_KILO,    "kilo (x10^3)" },
  { RDM_PREFIX_MEGA,    "mega (x10^6)" },
  { RDM_PREFIX_GIGA,    "giga (x10^9)" },
  { RDM_PREFIX_TERRA,   "terra (x10^12)" },
  { RDM_PREFIX_PETA,    "peta (x10^15)" },
  { RDM_PREFIX_EXA,     "exa (x10^18)" },
  { RDM_PREFIX_ZETTA,   "zetta (x10^21)" },
  { RDM_PREFIX_YOTTA,   "yotta (x10^24)" },
  { 0, NULL },
};
static value_string_ext rdm_prefix_vals_ext = VALUE_STRING_EXT_INIT(rdm_prefix_vals);

#define RDM_UNITS_NONE                         0x00
#define RDM_UNITS_CENTIGRADE                   0x01
#define RDM_UNITS_VOLTS_DC                     0x02
#define RDM_UNITS_VOLTS_AC_PEAK                0x03
#define RDM_UNITS_VOLTS_AC_RMS                 0x04
#define RDM_UNITS_AMPERE_DC                    0x05
#define RDM_UNITS_AMPERE_AC_PEAK               0x06
#define RDM_UNITS_AMPERE_AC_RMS                0x07
#define RDM_UNITS_HERTZ                        0x08
#define RDM_UNITS_OHM                          0x09
#define RDM_UNITS_WATT                         0x0A
#define RDM_UNITS_KILOGRAM                     0x0B
#define RDM_UNITS_METERS                       0x0C
#define RDM_UNITS_METERS_SQUARED               0x0D
#define RDM_UNITS_METERS_CUBED                 0x0E
#define RDM_UNITS_KILOGRAMMES_PER_METER_CUBED  0x0F
#define RDM_UNITS_METERS_PER_SECOND            0x10
#define RDM_UNITS_METERS_PER_SECOND_SQUARED    0x11
#define RDM_UNITS_NEWTON                       0x12
#define RDM_UNITS_JOULE                        0x13
#define RDM_UNITS_PASCAL                       0x14
#define RDM_UNITS_SECOND                       0x15
#define RDM_UNITS_DEGREE                       0x16
#define RDM_UNITS_STERADIAN                    0x17
#define RDM_UNITS_CANDELA                      0x18
#define RDM_UNITS_LUMEN                        0x19
#define RDM_UNITS_LUX                          0x1A
#define RDM_UNITS_IRE                          0x1B
#define RDM_UNITS_BYTE                         0x1C
#define RDM_UNITS_DECIBEL                      0x1D
#define RDM_UNITS_DECIBEL_VOLT                 0x1E
#define RDM_UNITS_DECIBEL_WATT                 0x1F
#define RDM_UNITS_DECIBEL_METER                0x20
#define RDM_UNITS_PERCENT                      0x21
#define RDM_UNITS_MOLES_PER_METER_CUBED        0x22
#define RDM_UNITS_RPM                          0x23
#define RDM_UNITS_BYTES_PER_SECOND             0x24

static const value_string rdm_unit_vals[] = {
  { RDM_UNITS_NONE,                         "NONE" },
  { RDM_UNITS_CENTIGRADE,                   "Centigrade" },
  { RDM_UNITS_VOLTS_DC,                     "Volts DC" },
  { RDM_UNITS_VOLTS_AC_PEAK,                "Volts AC Peak" },
  { RDM_UNITS_VOLTS_AC_RMS,                 "Volts AC RMS" },
  { RDM_UNITS_AMPERE_DC,                    "Ampere DC" },
  { RDM_UNITS_AMPERE_AC_PEAK,               "Ampere AC Peak" },
  { RDM_UNITS_AMPERE_AC_RMS,                "Ampere AC RMS" },
  { RDM_UNITS_HERTZ,                        "Hertz" },
  { RDM_UNITS_OHM,                          "Ohm" },
  { RDM_UNITS_WATT,                         "Watt" },
  { RDM_UNITS_KILOGRAM,                     "Kilogram" },
  { RDM_UNITS_METERS,                       "Meters" },
  { RDM_UNITS_METERS_SQUARED,               "Meters Squared" },
  { RDM_UNITS_METERS_CUBED,                 "Meters Cubed" },
  { RDM_UNITS_KILOGRAMMES_PER_METER_CUBED,  "Kilogrammes per Meter Cubed" },
  { RDM_UNITS_METERS_PER_SECOND,            "Meters per Second" },
  { RDM_UNITS_METERS_PER_SECOND_SQUARED,    "Meters per Second Squared" },
  { RDM_UNITS_NEWTON,                       "Newton" },
  { RDM_UNITS_JOULE,                        "Joule" },
  { RDM_UNITS_PASCAL,                       "Pascal" },
  { RDM_UNITS_SECOND,                       "Second" },
  { RDM_UNITS_DEGREE,                       "Degree" },
  { RDM_UNITS_STERADIAN,                    "Steradian" },
  { RDM_UNITS_CANDELA,                      "Candela" },
  { RDM_UNITS_LUMEN,                        "Lumen" },
  { RDM_UNITS_LUX,                          "Lux" },
  { RDM_UNITS_IRE,                          "Ire" },
  { RDM_UNITS_BYTE,                         "Byte" },
  { RDM_UNITS_DECIBEL,                      "Decibel" },
  { RDM_UNITS_DECIBEL_VOLT,                 "Decibel Volt" },
  { RDM_UNITS_DECIBEL_WATT,                 "Decibel Watt" },
  { RDM_UNITS_DECIBEL_METER,                "Decibel Meter" },
  { RDM_UNITS_PERCENT,                      "Percent" },
  { RDM_UNITS_MOLES_PER_METER_CUBED,        "Moles per Meter Cubed" },
  { RDM_UNITS_RPM,                          "RPM" },
  { RDM_UNITS_BYTES_PER_SECOND,             "Bytes per Second" },
  { 0, NULL },
};
static value_string_ext rdm_unit_vals_ext = VALUE_STRING_EXT_INIT(rdm_unit_vals);

#define RDM_SENS_TEMPERATURE          0x00
#define RDM_SENS_VOLTAGE              0x01
#define RDM_SENS_CURRENT              0x02
#define RDM_SENS_FREQUENCY            0x03
#define RDM_SENS_RESISTANCE           0x04
#define RDM_SENS_POWER                0x05
#define RDM_SENS_MASS                 0x06
#define RDM_SENS_LENGTH               0x07
#define RDM_SENS_AREA                 0x08
#define RDM_SENS_VOLUME               0x09
#define RDM_SENS_DENSITY              0x0A
#define RDM_SENS_VELOCITY             0x0B
#define RDM_SENS_ACCELERATION         0x0C
#define RDM_SENS_FORCE                0x0D
#define RDM_SENS_ENERGY               0x0E
#define RDM_SENS_PRESSURE             0x0F
#define RDM_SENS_TIME                 0x10
#define RDM_SENS_ANGLE                0x11
#define RDM_SENS_POSITION_X           0x12
#define RDM_SENS_POSITION_Y           0x13
#define RDM_SENS_POSITION_Z           0x14
#define RDM_SENS_ANGULAR_VELOCITY     0x15
#define RDM_SENS_LUMINOUS_INTENSITY   0x16
#define RDM_SENS_LUMINOUS_FLUX        0x17
#define RDM_SENS_ILLUMINANCE          0x18
#define RDM_SENS_CHROMINANCE_RED      0x19
#define RDM_SENS_CHROMINANCE_GREEN    0x1A
#define RDM_SENS_CHROMINANCE_BLUE     0x1B
#define RDM_SENS_CONTACTS             0x1C
#define RDM_SENS_MEMORY               0x1D
#define RDM_SENS_ITEMS                0x1E
#define RDM_SENS_HUMIDITY             0x1F
#define RDM_SENS_COUNTER_16BIT        0x20
#define RDM_SENS_CPU_LOAD             0x21
#define RDM_SENS_BANDWIDTH            0x22
#define RDM_SENS_CONCENTRATION        0x23
#define RDM_SENS_SOUND_PRESSURE_LEVEL 0x24
#define RDM_SENS_SOLID_ANGLE          0x25
#define RDM_SENS_LOG_RATIO            0x26
#define RDM_SENS_LOG_RATIO_VOLTS      0x27
#define RDM_SENS_LOG_RATIO_WATTS      0x28
#define RDM_SENS_OTHER                0x7F

static const value_string rdm_sensor_type_vals[] = {
  { RDM_SENS_TEMPERATURE,          "Temperature" },
  { RDM_SENS_VOLTAGE,             "Voltage" },
  { RDM_SENS_CURRENT,             "Current" },
  { RDM_SENS_FREQUENCY,           "Frequency" },
  { RDM_SENS_RESISTANCE,          "Resistance" },
  { RDM_SENS_POWER,               "Power" },
  { RDM_SENS_MASS,                "Mass" },
  { RDM_SENS_LENGTH,              "Length" },
  { RDM_SENS_AREA,                "Area" },
  { RDM_SENS_VOLUME,              "Volume" },
  { RDM_SENS_DENSITY,             "Density" },
  { RDM_SENS_VELOCITY,            "Velocity" },
  { RDM_SENS_ACCELERATION,        "Acceleration" },
  { RDM_SENS_FORCE,               "Force" },
  { RDM_SENS_ENERGY,              "Energy" },
  { RDM_SENS_PRESSURE,            "Pressure" },
  { RDM_SENS_TIME,                "Time" },
  { RDM_SENS_ANGLE,               "Angle" },
  { RDM_SENS_POSITION_X,          "Position X" },
  { RDM_SENS_POSITION_Y,          "Position Y" },
  { RDM_SENS_POSITION_Z,          "Position Z" },
  { RDM_SENS_ANGULAR_VELOCITY,    "Angular Velocity" },
  { RDM_SENS_LUMINOUS_INTENSITY,  "Luminous Intensity" },
  { RDM_SENS_LUMINOUS_FLUX,       "Luminous Flux" },
  { RDM_SENS_ILLUMINANCE,         "Illuminance" },
  { RDM_SENS_CHROMINANCE_RED,     "Chrominance Red" },
  { RDM_SENS_CHROMINANCE_GREEN,   "Chrominance Green" },
  { RDM_SENS_CHROMINANCE_BLUE,    "Chrominance Blue" },
  { RDM_SENS_CONTACTS,            "Contacts" },
  { RDM_SENS_MEMORY,              "Memory" },
  { RDM_SENS_ITEMS,               "Items" },
  { RDM_SENS_HUMIDITY,            "Humidity" },
  { RDM_SENS_COUNTER_16BIT,       "Counter 16bit" },
  { RDM_SENS_CPU_LOAD,            "CPU Load" },
  { RDM_SENS_BANDWIDTH,           "Bandwidth" },
  { RDM_SENS_CONCENTRATION,       "Concentration" },
  { RDM_SENS_SOUND_PRESSURE_LEVEL,"Sound Pressure Level" },
  { RDM_SENS_SOLID_ANGLE,         "Solid Angle" },
  { RDM_SENS_LOG_RATIO,           "Log Ratio" },
  { RDM_SENS_LOG_RATIO_VOLTS,     "Log Ratio Volts" },
  { RDM_SENS_LOG_RATIO_WATTS,     "Log Ratio Watts" },
  { RDM_SENS_OTHER,               "Other" },
  { 0, NULL} ,
};
static value_string_ext rdm_sensor_type_vals_ext = VALUE_STRING_EXT_INIT(rdm_sensor_type_vals);

#define RDM_DATA_TYPE_NOT_DEFINED 0x00
#define RDM_DATA_TYPE_BIT_FIELD   0x01
#define RDM_DATA_TYPE_STIRNG      0x02
#define RDM_DATA_TYPE_UINT8       0x03
#define RDM_DATA_TYPE_INT8        0x04
#define RDM_DATA_TYPE_UINT16      0x05
#define RDM_DATA_TYPE_INT16       0x06
#define RDM_DATA_TYPE_UINT32      0x07
#define RDM_DATA_TYPE_INT32       0x08
#define RDM_DATA_TYPE_UINT64      0x09
#define RDM_DATA_TYPE_INT64       0x0A
#define RDM_DATA_TYPE_GROUP       0x0B
#define RDM_DATA_TYPE_UID         0x0C
#define RDM_DATA_TYPE_BOOLEAN     0x0D
#define RDM_DATA_TYPE_URL         0x0E
#define RDM_DATA_TYPE_MAC         0x0F
#define RDM_DATA_TYPE_IPV4        0x10
#define RDM_DATA_TYPE_IPV6        0x11
#define RDM_DATA_TYPE_ENUMERATION 0x12

static const value_string rdm_data_type_vals[] = {
  { RDM_DATA_TYPE_NOT_DEFINED,  "Not Defined" },
  { RDM_DATA_TYPE_BIT_FIELD,    "BitField" },
  { RDM_DATA_TYPE_STIRNG,       "String" },
  { RDM_DATA_TYPE_UINT8,        "UInt8" },
  { RDM_DATA_TYPE_INT8,         "Int8" },
  { RDM_DATA_TYPE_UINT16,       "UInt16" },
  { RDM_DATA_TYPE_INT16,        "Int16" },
  { RDM_DATA_TYPE_UINT32,       "UInt32" },
  { RDM_DATA_TYPE_INT32,        "Int32" },
  { RDM_DATA_TYPE_UINT64,       "UInt64" },
  { RDM_DATA_TYPE_INT64,        "Int64" },
  { RDM_DATA_TYPE_GROUP,        "Group" },
  { RDM_DATA_TYPE_UID,          "UID" },
  { RDM_DATA_TYPE_BOOLEAN,      "Bool" },
  { RDM_DATA_TYPE_URL,          "URL" },
  { RDM_DATA_TYPE_MAC,          "MAC Address" },
  { RDM_DATA_TYPE_IPV4,         "IPv4 Address" },
  { RDM_DATA_TYPE_IPV6,         "IPv6 Address" },
  { RDM_DATA_TYPE_ENUMERATION,  "Enum" },
  { 0, NULL},
};

#define RDM_PRODUCT_CATEGORY_NOT_DECLARED              0x0000
#define RDM_PRODUCT_CATEGORY_FIXTURE                   0x0100
#define RDM_PRODUCT_CATEGORY_FIXTURE_FIXED             0x0101
#define RDM_PRODUCT_CATEGORY_FIXTURE_MOVING_YOKE       0x0102
#define RDM_PRODUCT_CATEGORY_FIXTURE_MOVING_MIRROR     0x0103
#define RDM_PRODUCT_CATEGORY_FIXTURE_OTHER             0x01FF
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY         0x0200
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_COLOR   0x0201
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_YOKE    0x0202
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_MIRROR  0x0203
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_EFFECT  0x0204
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_BEAM    0x0205
#define RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_OTHER   0x02FF
#define RDM_PRODUCT_CATEGORY_PROJECTOR                 0x0300
#define RDM_PRODUCT_CATEGORY_PROJECTOR_FIXED           0x0301
#define RDM_PRODUCT_CATEGORY_PROJECTOR_MOVING_YOKE     0x0302
#define RDM_PRODUCT_CATEGORY_PROJECTOR_MOVING_MIRROR   0x0303
#define RDM_PRODUCT_CATEGORY_PROJECTOR_OTHER           0x03FF
#define RDM_PRODUCT_CATEGORY_ATMOSPHERIC               0x0400
#define RDM_PRODUCT_CATEGORY_ATMOSPHERIC_EFFECT        0x0401
#define RDM_PRODUCT_CATEGORY_ATMOSPHERIC_PYRO          0x0402
#define RDM_PRODUCT_CATEGORY_ATMOSPHERIC_OTHER         0x04FF
#define RDM_PRODUCT_CATEGORY_DIMMER                    0x0500
#define RDM_PRODUCT_CATEGORY_DIMMER_AC_INCANDESCENT    0x0501
#define RDM_PRODUCT_CATEGORY_DIMMER_AC_FLUORESCENT     0x0502
#define RDM_PRODUCT_CATEGORY_DIMMER_AC_COLDCATHODE     0x0503
#define RDM_PRODUCT_CATEGORY_DIMMER_AC_NONDIM          0x0504
#define RDM_PRODUCT_CATEGORY_DIMMER_AC_ELV             0x0505
#define RDM_PRODUCT_CATEGORY_DIMMER_AC_OTHER           0x0506
#define RDM_PRODUCT_CATEGORY_DIMMER_DC_LEVEL           0x0507
#define RDM_PRODUCT_CATEGORY_DIMMER_DC_PWM             0x0508
#define RDM_PRODUCT_CATEGORY_DIMMER_CS_LED             0x0509
#define RDM_PRODUCT_CATEGORY_DIMMER_OTHER              0x05FF
#define RDM_PRODUCT_CATEGORY_POWER                     0x0600
#define RDM_PRODUCT_CATEGORY_POWER_CONTROL             0x0601
#define RDM_PRODUCT_CATEGORY_POWER_SOURCE              0x0602
#define RDM_PRODUCT_CATEGORY_POWER_OTHER               0x06FF
#define RDM_PRODUCT_CATEGORY_SCENIC                    0x0700
#define RDM_PRODUCT_CATEGORY_SCENIC_DRIVE              0x0701
#define RDM_PRODUCT_CATEGORY_SCENIC_OTHER              0x07FF
#define RDM_PRODUCT_CATEGORY_DATA                      0x0800
#define RDM_PRODUCT_CATEGORY_DATA_DISTRIBUTION         0x0801
#define RDM_PRODUCT_CATEGORY_DATA_CONVERSION           0x0802
#define RDM_PRODUCT_CATEGORY_DATA_OTHER                0x08FF
#define RDM_PRODUCT_CATEGORY_AV                        0x0900
#define RDM_PRODUCT_CATEGORY_AV_AUDIO                  0x0901
#define RDM_PRODUCT_CATEGORY_AV_VIDEO                  0x0902
#define RDM_PRODUCT_CATEGORY_AV_OTHER                  0x09FF
#define RDM_PRODUCT_CATEGORY_MONITOR                   0x0A00
#define RDM_PRODUCT_CATEGORY_MONITOR_ACLINEPOWER       0x0A01
#define RDM_PRODUCT_CATEGORY_MONITOR_DCPOWER           0x0A02
#define RDM_PRODUCT_CATEGORY_MONITOR_ENVIRONMENTAL     0x0A03
#define RDM_PRODUCT_CATEGORY_MONITOR_OTHER             0x0AFF
#define RDM_PRODUCT_CATEGORY_CONTROL                   0x7000
#define RDM_PRODUCT_CATEGORY_CONTROL_CONTROLLER        0x7001
#define RDM_PRODUCT_CATEGORY_CONTROL_BACKUPDEVICE      0x7002
#define RDM_PRODUCT_CATEGORY_CONTROL_OTHER             0x70FF
#define RDM_PRODUCT_CATEGORY_TEST                      0x7100
#define RDM_PRODUCT_CATEGORY_TEST_EQUIPMENT            0x7101
#define RDM_PRODUCT_CATEGORY_TEST_EQUIPMENT_OTHER      0x71FF
#define RDM_PRODUCT_CATEGORY_OTHER                     0x7FFF

static const value_string rdm_product_cat_vals[] = {
  { RDM_PRODUCT_CATEGORY_NOT_DECLARED,              "Not Declared" },
  { RDM_PRODUCT_CATEGORY_FIXTURE,                   "Fixture" },
  { RDM_PRODUCT_CATEGORY_FIXTURE_FIXED,             "Fixture Fixed" },
  { RDM_PRODUCT_CATEGORY_FIXTURE_MOVING_YOKE,       "Fixture Moving Yoke" },
  { RDM_PRODUCT_CATEGORY_FIXTURE_MOVING_MIRROR,     "Fixture Moving Mirror" },
  { RDM_PRODUCT_CATEGORY_FIXTURE_OTHER,             "Fixture Other" },
  { RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY,         "Fixture Accessory" },
  { RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_COLOR,   "Fixture Accessory Color" },
  { RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_YOKE,    "Fixture Accessory Yoke" },
  { RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_MIRROR,  "Fixture Accessory Mirror" },
  { RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_EFFECT,  "Fixture Accessory Effect" },
  { RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_BEAM,    "Fixture Accessory Beam" },
  { RDM_PRODUCT_CATEGORY_FIXTURE_ACCESSORY_OTHER,   "Fixture Accessory Other" },
  { RDM_PRODUCT_CATEGORY_PROJECTOR,                 "Projector" },
  { RDM_PRODUCT_CATEGORY_PROJECTOR_FIXED,           "Projector Fixed" },
  { RDM_PRODUCT_CATEGORY_PROJECTOR_MOVING_YOKE,     "Projector Moving Yoke" },
  { RDM_PRODUCT_CATEGORY_PROJECTOR_MOVING_MIRROR,   "Projector Moving Mirror" },
  { RDM_PRODUCT_CATEGORY_PROJECTOR_OTHER,           "Projector Other" },
  { RDM_PRODUCT_CATEGORY_ATMOSPHERIC,               "Atmospheric" },
  { RDM_PRODUCT_CATEGORY_ATMOSPHERIC_EFFECT,        "Atmospheric Effect" },
  { RDM_PRODUCT_CATEGORY_ATMOSPHERIC_PYRO,          "Atmospheric Pyro" },
  { RDM_PRODUCT_CATEGORY_ATMOSPHERIC_OTHER,         "Atmospheric Other" },
  { RDM_PRODUCT_CATEGORY_DIMMER,                    "Dimmer" },
  { RDM_PRODUCT_CATEGORY_DIMMER_AC_INCANDESCENT,    "Dimmer AC Incandescent" },
  { RDM_PRODUCT_CATEGORY_DIMMER_AC_FLUORESCENT,     "Dimmer AC Fluorescent" },
  { RDM_PRODUCT_CATEGORY_DIMMER_AC_COLDCATHODE,     "Dimmer AC Coldcathode" },
  { RDM_PRODUCT_CATEGORY_DIMMER_AC_NONDIM,          "Dimmer AC Nondim" },
  { RDM_PRODUCT_CATEGORY_DIMMER_AC_ELV,             "Dimmer AC ELV" },
  { RDM_PRODUCT_CATEGORY_DIMMER_AC_OTHER,           "Dimmer AC Other" },
  { RDM_PRODUCT_CATEGORY_DIMMER_DC_LEVEL,           "Dimmer DC Level" },
  { RDM_PRODUCT_CATEGORY_DIMMER_DC_PWM,             "Dimmer DC PWM" },
  { RDM_PRODUCT_CATEGORY_DIMMER_CS_LED,             "Dimmer CS LED" },
  { RDM_PRODUCT_CATEGORY_DIMMER_OTHER,              "Dimmer Other" },
  { RDM_PRODUCT_CATEGORY_POWER,                     "Power" },
  { RDM_PRODUCT_CATEGORY_POWER_CONTROL,             "Power Control" },
  { RDM_PRODUCT_CATEGORY_POWER_SOURCE,              "Power Source" },
  { RDM_PRODUCT_CATEGORY_POWER_OTHER,               "Power Other" },
  { RDM_PRODUCT_CATEGORY_SCENIC,                    "Scenic" },
  { RDM_PRODUCT_CATEGORY_SCENIC_DRIVE,              "Scenic Drive" },
  { RDM_PRODUCT_CATEGORY_SCENIC_OTHER,              "Scenic Other" },
  { RDM_PRODUCT_CATEGORY_DATA,                      "Data" },
  { RDM_PRODUCT_CATEGORY_DATA_DISTRIBUTION,         "Data Distribution" },
  { RDM_PRODUCT_CATEGORY_DATA_CONVERSION,           "Data Conversion" },
  { RDM_PRODUCT_CATEGORY_DATA_OTHER,                "Data Other" },
  { RDM_PRODUCT_CATEGORY_AV,                        "AV" },
  { RDM_PRODUCT_CATEGORY_AV_AUDIO,                  "AV Audio" },
  { RDM_PRODUCT_CATEGORY_AV_VIDEO,                  "AV Video" },
  { RDM_PRODUCT_CATEGORY_AV_OTHER,                  "AV Other" },
  { RDM_PRODUCT_CATEGORY_MONITOR,                   "Monitor" },
  { RDM_PRODUCT_CATEGORY_MONITOR_ACLINEPOWER,       "Monitor AC Line Power" },
  { RDM_PRODUCT_CATEGORY_MONITOR_DCPOWER,           "Monitor DC Power" },
  { RDM_PRODUCT_CATEGORY_MONITOR_ENVIRONMENTAL,     "Monitor Environmental" },
  { RDM_PRODUCT_CATEGORY_MONITOR_OTHER,             "Monitor Other" },
  { RDM_PRODUCT_CATEGORY_CONTROL,                   "Control" },
  { RDM_PRODUCT_CATEGORY_CONTROL_CONTROLLER,        "Control Controller" },
  { RDM_PRODUCT_CATEGORY_CONTROL_BACKUPDEVICE,      "Control Backup Device" },
  { RDM_PRODUCT_CATEGORY_CONTROL_OTHER,             "Control Other" },
  { RDM_PRODUCT_CATEGORY_TEST,                      "Test" },
  { RDM_PRODUCT_CATEGORY_TEST_EQUIPMENT,            "Test Equipment" },
  { RDM_PRODUCT_CATEGORY_TEST_EQUIPMENT_OTHER,      "Test Equipment Other" },
  { RDM_PRODUCT_CATEGORY_OTHER,                     "Other" },
  { 0, NULL },
};
static value_string_ext rdm_product_cat_vals_ext = VALUE_STRING_EXT_INIT(rdm_product_cat_vals);

/* E1.20 Table A-6 */
#define RDM_PRODUCT_DETAIL_NOT_DECLARED           0x0000
/* Generally applied to fixtures */
#define RDM_PRODUCT_DETAIL_ARC                    0x0001
#define RDM_PRODUCT_DETAIL_METAL_HALIDE           0x0002
#define RDM_PRODUCT_DETAIL_INCANDESCENT           0x0003
#define RDM_PRODUCT_DETAIL_LED                    0x0004
#define RDM_PRODUCT_DETAIL_FLUORESCENT            0x0005
#define RDM_PRODUCT_DETAIL_COLDCATHODE            0x0006
#define RDM_PRODUCT_DETAIL_ELECTROLUMINESCENT     0x0007
#define RDM_PRODUCT_DETAIL_LASER                  0x0008
#define RDM_PRODUCT_DETAIL_FLASHTUBE              0x0009
/* Generally applied to fixture accessories */
#define RDM_PRODUCT_DETAIL_COLORSCROLLER          0x0100
#define RDM_PRODUCT_DETAIL_COLORWHEEL             0x0101
#define RDM_PRODUCT_DETAIL_COLORCHANGE            0x0102
#define RDM_PRODUCT_DETAIL_IRIS_DOUSER            0x0103
#define RDM_PRODUCT_DETAIL_DIMMING_SHUTTER        0x0104
#define RDM_PRODUCT_DETAIL_PROFILE_SHUTTER        0x0105
#define RDM_PRODUCT_DETAIL_BARNDOOR_SHUTTER       0x0106
#define RDM_PRODUCT_DETAIL_EFFECTS_DISC           0x0107
#define RDM_PRODUCT_DETAIL_GOBO_ROTATOR           0x0108
/* Generally applied to Projectors */
#define RDM_PRODUCT_DETAIL_VIDEO                  0x0200
#define RDM_PRODUCT_DETAIL_SLIDE                  0x0201
#define RDM_PRODUCT_DETAIL_FILM                   0x0202
#define RDM_PRODUCT_DETAIL_OILWHEEL               0x0203
#define RDM_PRODUCT_DETAIL_LCDGATE                0x0204
/* Generally applied to Atmospheric Effects */
#define RDM_PRODUCT_DETAIL_FOGGER_GLYCOL          0x0300
#define RDM_PRODUCT_DETAIL_FOGGER_MINERALOIL      0x0301
#define RDM_PRODUCT_DETAIL_FOGGER_WATER           0x0302
#define RDM_PRODUCT_DETAIL_CO2                    0x0303
#define RDM_PRODUCT_DETAIL_LN2                    0x0304
#define RDM_PRODUCT_DETAIL_BUBBLE                 0x0305
#define RDM_PRODUCT_DETAIL_FLAME_PROPANE          0x0306
#define RDM_PRODUCT_DETAIL_FLAME_OTHER            0x0307
#define RDM_PRODUCT_DETAIL_OLEFACTORY_STIMULATOR  0x0308
#define RDM_PRODUCT_DETAIL_SNOW                   0x0309
#define RDM_PRODUCT_DETAIL_WATER_JET              0x030A
#define RDM_PRODUCT_DETAIL_WIND                   0x030B
#define RDM_PRODUCT_DETAIL_CONFETTI               0x030C
#define RDM_PRODUCT_DETAIL_HAZARD                 0x030D
/* Generally applied to Dimmers/Power controllers */
#define RDM_PRODUCT_DETAIL_PHASE_CONTROL          0x0400
#define RDM_PRODUCT_DETAIL_REVERSE_PHASE_CONTROL  0x0401
#define RDM_PRODUCT_DETAIL_SINE                   0x0402
#define RDM_PRODUCT_DETAIL_PWM                    0x0403
#define RDM_PRODUCT_DETAIL_DC                     0x0404
#define RDM_PRODUCT_DETAIL_HFBALLAST              0x0405
#define RDM_PRODUCT_DETAIL_HFHV_NEONBALLAST       0x0406
#define RDM_PRODUCT_DETAIL_HFHV_EL                0x0407
#define RDM_PRODUCT_DETAIL_MHR_BALLAST            0x0408
#define RDM_PRODUCT_DETAIL_BITANGLE_MODULATION    0x0409
#define RDM_PRODUCT_DETAIL_FREQUENCY_MODULATION   0x040A
#define RDM_PRODUCT_DETAIL_HIGHFREQUENCY_12V      0x040B
#define RDM_PRODUCT_DETAIL_RELAY_MECHANICAL       0x040C
#define RDM_PRODUCT_DETAIL_RELAY_ELECTRONIC       0x040D
#define RDM_PRODUCT_DETAIL_SWITCH_ELECTRONIC      0x040E
#define RDM_PRODUCT_DETAIL_CONTACTOR              0x040F
/* Generally applied to Scenic drive */
#define RDM_PRODUCT_DETAIL_MIRRORBALL_ROTATOR     0x0500
#define RDM_PRODUCT_DETAIL_OTHER_ROTATOR          0x0501
#define RDM_PRODUCT_DETAIL_KABUKI_DROP            0x0502
#define RDM_PRODUCT_DETAIL_CURTAIN                0x0503
#define RDM_PRODUCT_DETAIL_LINESET                0x0504
#define RDM_PRODUCT_DETAIL_MOTOR_CONTROL          0x0505
#define RDM_PRODUCT_DETAIL_DAMPER_CONTROL         0x0506
/* Generally applied to Data Distribution */
#define RDM_PRODUCT_DETAIL_SPLITTER               0x0600
#define RDM_PRODUCT_DETAIL_ETHERNET_NODE          0x0601
#define RDM_PRODUCT_DETAIL_MERGE                  0x0602
#define RDM_PRODUCT_DETAIL_DATAPATCH              0x0603
#define RDM_PRODUCT_DETAIL_WIRELESS_LINK          0x0604
/* Generally applied to Data Conversion and Interfaces */
#define RDM_PRODUCT_DETAIL_PROTOCOL_CONVERTOR     0x0701
#define RDM_PRODUCT_DETAIL_ANALOG_DEMULTIPLEX     0x0702
#define RDM_PRODUCT_DETAIL_ANALOG_MULTIPLEX       0x0703
#define RDM_PRODUCT_DETAIL_SWITCH_PANEL           0x0704
/* Generally applied to Audio or Video (AV) devices */
#define RDM_PRODUCT_DETAIL_ROUTER                 0x0800
#define RDM_PRODUCT_DETAIL_FADER                  0x0801
#define RDM_PRODUCT_DETAIL_MIXER                  0x0802
/* Generally applied to Controllers, Backup devices, and Test Equipment */
#define RDM_PRODUCT_DETAIL_CHANGEOVER_MANUAL      0x0900
#define RDM_PRODUCT_DETAIL_CHANGEOVER_AUTO        0x0901
#define RDM_PRODUCT_DETAIL_TEST                   0x0902
/* Could be applied to any category */
#define RDM_PRODUCT_DETAIL_GFI_RCD                0x0A00
#define RDM_PRODUCT_DETAIL_BATTERY                0x0A01
#define RDM_PRODUCT_DETAIL_CONTROLLABLE_BREAKER   0x0A02
/* Input Devices E1.20-2025 */
#define RDM_PRODUCT_DETAIL_INPUT                  0x0B00
#define RDM_PRODUCT_DETAIL_SENSOR                 0x0B01
#define RDM_PRODUCT_DETAIL_OTHER                  0x7FFF

static const value_string rdm_product_detail_vals[] = {
  { RDM_PRODUCT_DETAIL_NOT_DECLARED,            "Not Declared" },
  /* Generally applied to fixtures */
  { RDM_PRODUCT_DETAIL_ARC,                     "Arc Lamp" },
  { RDM_PRODUCT_DETAIL_METAL_HALIDE,            "Metal Halide" },
  { RDM_PRODUCT_DETAIL_INCANDESCENT,            "Incandescent" },
  { RDM_PRODUCT_DETAIL_LED,                     "LED" },
  /* ANSI-ESTA E1.20-2010 misspells this FLUROESCENT */
  { RDM_PRODUCT_DETAIL_FLUORESCENT,             "Fluorescent" },
  { RDM_PRODUCT_DETAIL_COLDCATHODE,             "Cold Cathode" },
  { RDM_PRODUCT_DETAIL_ELECTROLUMINESCENT,      "Electroluminescent" },
  { RDM_PRODUCT_DETAIL_LASER,                   "Laser" },
  { RDM_PRODUCT_DETAIL_FLASHTUBE,               "Flashtube" },
  /* Generally applied to fixture accessories */
  { RDM_PRODUCT_DETAIL_COLORSCROLLER,           "Color Scroller" },
  { RDM_PRODUCT_DETAIL_COLORWHEEL,              "Color Wheel" },
  { RDM_PRODUCT_DETAIL_COLORCHANGE,             "Color Change" },
  { RDM_PRODUCT_DETAIL_IRIS_DOUSER,             "Iris / Douser" },
  { RDM_PRODUCT_DETAIL_DIMMING_SHUTTER,         "Dimming Shutter" },
  { RDM_PRODUCT_DETAIL_PROFILE_SHUTTER,         "Profile Shutter" },
  { RDM_PRODUCT_DETAIL_BARNDOOR_SHUTTER,        "Barn Door Shutter" },
  { RDM_PRODUCT_DETAIL_EFFECTS_DISC,            "Effects Disc" },
  { RDM_PRODUCT_DETAIL_GOBO_ROTATOR,            "Gobo Rotator" },
  /* Generally applied to Projectors */
  { RDM_PRODUCT_DETAIL_VIDEO,                   "Video" },
  { RDM_PRODUCT_DETAIL_SLIDE,                   "Slide" },
  { RDM_PRODUCT_DETAIL_FILM,                    "Film" },
  { RDM_PRODUCT_DETAIL_OILWHEEL,                "Oil Wheel" },
  { RDM_PRODUCT_DETAIL_LCDGATE,                 "LCD Gate" },
  /* Generally applied to Atmospheric Effects */
  { RDM_PRODUCT_DETAIL_FOGGER_GLYCOL,           "Fogger, Glycol" },
  { RDM_PRODUCT_DETAIL_FOGGER_MINERALOIL,       "Fogger, Mineral Oil" },
  { RDM_PRODUCT_DETAIL_FOGGER_WATER,            "Fogger, Water" },
  /* ANSI E1.20-2010 has a '0' instead of 'O' in CO2 */
  { RDM_PRODUCT_DETAIL_CO2,                     "Dry Ice / CO2 based" },
  { RDM_PRODUCT_DETAIL_LN2,                     "Liquid Nitrogen based" },
  { RDM_PRODUCT_DETAIL_BUBBLE,                  "Bubble or Foam" },
  { RDM_PRODUCT_DETAIL_FLAME_PROPANE,           "Propane Flame" },
  { RDM_PRODUCT_DETAIL_FLAME_OTHER,             "Other Flame" },
  { RDM_PRODUCT_DETAIL_OLEFACTORY_STIMULATOR,   "Scents" },
  { RDM_PRODUCT_DETAIL_SNOW,                    "Snow" },
  { RDM_PRODUCT_DETAIL_WATER_JET,               "Water Jet" },
  { RDM_PRODUCT_DETAIL_WIND,                    "Wind" },
  { RDM_PRODUCT_DETAIL_CONFETTI,                "Confetti" },
  { RDM_PRODUCT_DETAIL_HAZARD,                  "Hazard (any pyrotechnic)" },
  /* Generally applied to Dimmers/Power controllers */
  { RDM_PRODUCT_DETAIL_PHASE_CONTROL,           "Phase Control" },
  { RDM_PRODUCT_DETAIL_REVERSE_PHASE_CONTROL,   "Reverse Phase Control" },
  { RDM_PRODUCT_DETAIL_SINE,                    "Sine" },
  { RDM_PRODUCT_DETAIL_PWM,                     "Pulse Width Modulation" },
  { RDM_PRODUCT_DETAIL_DC,                      "DC" },
  { RDM_PRODUCT_DETAIL_HFBALLAST,               "HF Ballast" },
  { RDM_PRODUCT_DETAIL_HFHV_NEONBALLAST,        "HF Neon Ballast" },
  { RDM_PRODUCT_DETAIL_HFHV_EL,                 "HFHV Electroluminescent" },
  { RDM_PRODUCT_DETAIL_MHR_BALLAST,             "Metal Halide Ballast" },
  { RDM_PRODUCT_DETAIL_BITANGLE_MODULATION,     "Bit Angle Modulation" },
  { RDM_PRODUCT_DETAIL_FREQUENCY_MODULATION,    "Frequency Modulation" },
  { RDM_PRODUCT_DETAIL_HIGHFREQUENCY_12V,       "High Frequency 12V" },
  { RDM_PRODUCT_DETAIL_RELAY_MECHANICAL,        "Mechanical Relay" },
  { RDM_PRODUCT_DETAIL_RELAY_ELECTRONIC,        "Electronic Relay" },
  { RDM_PRODUCT_DETAIL_SWITCH_ELECTRONIC,       "Electronic Switch" },
  { RDM_PRODUCT_DETAIL_CONTACTOR,               "Contactor" },
  /* Generally applied to Scenic driver */
  { RDM_PRODUCT_DETAIL_MIRRORBALL_ROTATOR,      "Mirror Ball Rotator" },
  { RDM_PRODUCT_DETAIL_OTHER_ROTATOR,           "Other Rotator" },
  { RDM_PRODUCT_DETAIL_KABUKI_DROP,             "Kabuki Drop" },
  { RDM_PRODUCT_DETAIL_CURTAIN,                 "Curtain" },
  { RDM_PRODUCT_DETAIL_LINESET,                 "Line Set" },
  { RDM_PRODUCT_DETAIL_MOTOR_CONTROL,           "Motor Control" },
  { RDM_PRODUCT_DETAIL_DAMPER_CONTROL,          "Damper Control" },
  /* Generally applied to Data Distribution */
  { RDM_PRODUCT_DETAIL_SPLITTER,                "Splitter" },
  { RDM_PRODUCT_DETAIL_ETHERNET_NODE,           "DMX512 to/from Ethernet" },
  { RDM_PRODUCT_DETAIL_MERGE,                   "DMX512 Combiner" },
  { RDM_PRODUCT_DETAIL_DATAPATCH,               "Datapatch" },
  { RDM_PRODUCT_DETAIL_WIRELESS_LINK,           "Wireless Link" },
  /* Generally applied to Data Conversion and Interfaces */
  { RDM_PRODUCT_DETAIL_PROTOCOL_CONVERTOR,      "Protocol Converter" },
  { RDM_PRODUCT_DETAIL_ANALOG_DEMULTIPLEX,      "DMX512 to DC Voltage" },
  { RDM_PRODUCT_DETAIL_ANALOG_MULTIPLEX,        "DC Voltage to DMX512" },
  { RDM_PRODUCT_DETAIL_SWITCH_PANEL,            "Switch Panel" },
  /* Generally applied to Audio or Video (AV) devices */
  { RDM_PRODUCT_DETAIL_ROUTER,                  "Router" },
  { RDM_PRODUCT_DETAIL_FADER,                   "Fader" },
  { RDM_PRODUCT_DETAIL_MIXER,                   "Mixer" },
  /* Generally applied to Controllers, Backup devices, and Test Equipment */
  { RDM_PRODUCT_DETAIL_CHANGEOVER_MANUAL,       "Manual Changeover" },
  { RDM_PRODUCT_DETAIL_CHANGEOVER_AUTO,         "Auto Changeover" },
  { RDM_PRODUCT_DETAIL_TEST,                    "Test Equipment" },
  /* Could be applied to any category */
  { RDM_PRODUCT_DETAIL_GFI_RCD,                 "Includes GFI/RCD Trip" },
  { RDM_PRODUCT_DETAIL_BATTERY,                 "Battery Operated" },
  { RDM_PRODUCT_DETAIL_CONTROLLABLE_BREAKER,    "Controllable Breaker" },
  /* Input Devices E1.20-2025 */
  { RDM_PRODUCT_DETAIL_INPUT,                   "Generic Input" },
  { RDM_PRODUCT_DETAIL_SENSOR,                  "Sensor Input" },
  { RDM_PRODUCT_DETAIL_OTHER,                   "Other" },
  { 0, NULL },
};
static value_string_ext rdm_product_detail_vals_ext = VALUE_STRING_EXT_INIT(rdm_product_detail_vals);

#define RDM_SUPPORT_CC_GET      0x01
#define RDM_SUPPORT_CC_SET      0x02
#define RDM_SUPPORT_CC_GET_SET  0x03

static const value_string rdm_supported_command_class_vals[] = {
  { RDM_SUPPORT_CC_GET,     "GET only" },
  { RDM_SUPPORT_CC_SET,     "SET only" },
  { RDM_SUPPORT_CC_GET_SET, "GET and SET" },
  { 0, NULL },
};

#define RDM_LAMP_STATE_OFF          0x00
#define RDM_LAMP_STATE_ON           0x01
#define RDM_LAMP_STATE_STRIKE       0x02
#define RDM_LAMP_STATE_STANDBY      0x03
#define RDM_LAMP_STATE_NOT_PRESENT  0x04
#define RDM_LAMP_STATE_ERROR        0x7F

static const value_string rdm_lamp_state_vals[] = {
  { RDM_LAMP_STATE_OFF,         "Off" },
  { RDM_LAMP_STATE_ON,          "On" },
  { RDM_LAMP_STATE_STRIKE,      "Strike" },
  { RDM_LAMP_STATE_STANDBY,     "Standby" },
  { RDM_LAMP_STATE_NOT_PRESENT, "Not Present" },
  { RDM_LAMP_STATE_ERROR,       "Error" },
  { 0, NULL },
};

#define RDM_LAMP_ON_MODE_OFF        0x00
#define RDM_LAMP_ON_MODE_DMX        0x01
#define RDM_LAMP_ON_MODE_ON         0x02
#define RDM_LAMP_ON_MODE_AFTER_CAL  0x03

static const value_string rdm_lamp_on_mode_vals[] = {
  { RDM_LAMP_ON_MODE_OFF,       "When Instructed" },
  { RDM_LAMP_ON_MODE_DMX,       "On DMX Received" },
  { RDM_LAMP_ON_MODE_ON,        "On Power Up" },
  { RDM_LAMP_ON_MODE_AFTER_CAL, "After Calibration" },
  { 0, NULL },
};

#define RDM_DISPLAY_INVERT_OFF  0x00
#define RDM_DISPLAY_INVERT_ON   0x01
#define RDM_DISPLAY_INVERT_AUTO 0x02

static const value_string rdm_display_invert_vals[] = {
  { RDM_DISPLAY_INVERT_OFF,  "Off" },
  { RDM_DISPLAY_INVERT_ON,   "On" },
  { RDM_DISPLAY_INVERT_AUTO, "Auto" },
  { 0, NULL },
};

#define RDM_RESET_TYPE_WARM 0x01
#define RDM_RESET_TYPE_COLD 0x02

static const value_string rdm_reset_type_vals[] = {
  { RDM_RESET_TYPE_WARM, "Warm Reset" },
  { RDM_RESET_TYPE_COLD, "Cold Reset" },
  { 0, NULL },
};

#define RDM_POWER_STATE_FULL_OFF  0x00
#define RDM_POWER_STATE_SHUTDOWN  0x01
#define RDM_POWER_STATE_STANDBY   0x02
#define RDM_POWER_STATE_NORMAL    0xFF

static const value_string rdm_power_state_vals[] = {
  { RDM_POWER_STATE_FULL_OFF, "Full Off" },
  { RDM_POWER_STATE_SHUTDOWN, "Shutdown" },
  { RDM_POWER_STATE_STANDBY,  "Standby" },
  { RDM_POWER_STATE_NORMAL,   "Normal" },
  { 0, NULL },
};

#define RDM_PRESET_PLAYBACK_OFF 0x0000
#define RDM_PRESET_PLAYBACK_ALL 0xFFFF

static const value_string rdm_preset_playback_vals[] = {
  { RDM_PRESET_PLAYBACK_OFF, "Off" },
  { RDM_PRESET_PLAYBACK_ALL, "All" },
  { 0, NULL },
};

/* E1.20 */
static const value_string rdm_sensor_subscribe_vals[] = {
  { 0, "Unsubscribe" },
  { 1, "Subscribe" },
  { 0, NULL },
};

#define RDM_SELF_TEST_NR_OFF 0x00
#define RDM_SELF_TEST_NR_ALL 0xFF

static const value_string rdm_self_test_nr_vals[] = {
  { RDM_SELF_TEST_NR_OFF, "Off" },
  { RDM_SELF_TEST_NR_ALL, "All" },
  { 0, NULL },
};

/* E1.20 */
#define RDM_STS_NOT_SUPPORTTED  0x00
#define RDM_STS_NOT_RUN         0x01
#define RDM_STS_ABORTED         0x02
#define RDM_STS_ACTIVE          0x03
#define RDM_STS_PASS            0x04
#define RDM_STS_FAIL            0x05
#define RDM_STS_NO_ANALYSIS     0x06
#define RDM_STS_RESULT_CODE     0x07
#define RDM_STS_OTHER           0xFF

static const value_string rdm_self_test_status_vals[] = {
  { RDM_STS_NOT_SUPPORTTED, "Not Supported" },
  { RDM_STS_NOT_RUN,        "Test Not Run" },
  { RDM_STS_ABORTED,        "Aborted/Reset" },
  { RDM_STS_ACTIVE,         "Active/Running" },
  { RDM_STS_PASS,           "PASS" },
  { RDM_STS_FAIL,           "FAIL" },
  { RDM_STS_NO_ANALYSIS,    "Complete - No Analysis" },
  { RDM_STS_RESULT_CODE,    "Complete - Result Code Available" },
  { RDM_STS_OTHER,          "Other" },
  { 0, NULL },
};

/* E1.20 */
static const value_string rdm_self_test_result_code_vals[] = {
  { 0, "Not Available" },
  { 0, NULL },
};

/* E1.20 */
#define RDM_SLOT_TYPE_PRIMARY             0x00
#define RDM_SLOT_TYPE_SEC_FINE            0x01
#define RDM_SLOT_TYPE_SEC_TIMING          0x02
#define RDM_SLOT_TYPE_SEC_SPEED           0x03
#define RDM_SLOT_TYPE_SEC_CONTROL         0x04
#define RDM_SLOT_TYPE_SEC_QUANTUM         0x05
#define RDM_SLOT_TYPE_SEC_ROTATION        0x06
#define RDM_SLOT_TYPE_SEC_QUANTUM_ROTATE  0x07
#define RDM_SLOT_TYPE_SEC_UNDEFINED       0xFF

static const value_string rdm_slot_types[] = {
  { RDM_SLOT_TYPE_PRIMARY,             "Primary" },
  { RDM_SLOT_TYPE_SEC_FINE,            "Fine" },
  { RDM_SLOT_TYPE_SEC_TIMING,          "Timing value" },
  { RDM_SLOT_TYPE_SEC_SPEED,           "Speed/velocity" },
  { RDM_SLOT_TYPE_SEC_CONTROL,         "Control/mode info" },
  { RDM_SLOT_TYPE_SEC_QUANTUM,         "Index position" },
  { RDM_SLOT_TYPE_SEC_ROTATION,        "Rotation speed" },
  { RDM_SLOT_TYPE_SEC_QUANTUM_ROTATE,  "Combined index/rotation" },
  { RDM_SLOT_TYPE_SEC_UNDEFINED,       "Undefined secondary" },
  { 0, NULL },
};

/* E1.20 */
#define RDM_SD_INTENSITY            0x0001
#define RDM_SD_INTENSITY_MASTER     0x0002
#define RDM_SD_PAN                  0x0101
#define RDM_SD_TILT                 0x0102
#define RDM_SD_COLOR_WHEEL          0x0201
#define RDM_SD_COLOR_SUB_CYAN       0x0202
#define RDM_SD_COLOR_SUB_YELLOW     0x0203
#define RDM_SD_COLOR_SUB_MAGENTA    0x0204
#define RDM_SD_COLOR_ADD_RED        0x0205
#define RDM_SD_COLOR_ADD_GREEN      0x0206
#define RDM_SD_COLOR_ADD_BLUE       0x0207
#define RDM_SD_COLOR_CORRECTION     0x0208
#define RDM_SD_COLOR_SCROLL         0x0209
#define RDM_SD_COLOR_ADD_LIME       0x020A
#define RDM_SD_COLOR_ADD_INDIGO     0x020B
#define RDM_SD_COLOR_ADD_CYAN       0x020C
#define RDM_SD_COLOR_ADD_DEEP_RED   0x020D
#define RDM_SD_COLOR_ADD_DEEP_BLUE  0x020E
#define RDM_SD_COLOR_ADD_NAT_WHITE  0x020F
#define RDM_SD_COLOR_SEMAPHORE      0x0210
#define RDM_SD_COLOR_ADD_AMBER      0x0211
#define RDM_SD_COLOR_ADD_WHITE      0x0212
#define RDM_SD_COLOR_ADD_WARM_WHITE 0x0213
#define RDM_SD_COLOR_ADD_COOL_WHITE 0x0214
#define RDM_SD_COLOR_SUB_UV         0x0215
#define RDM_SD_COLOR_HUE            0x0216
#define RDM_SD_COLOR_SATURATION     0x0217
#define RDM_SD_COLOR_ADD_UV         0x0218
#define RDM_SD_STATIC_GOBO_WHEEL    0x0301
#define RDM_SD_ROTO_GOBO_WHEEL      0x0302
#define RDM_SD_PRISM_WHEEL          0x0303
#define RDM_SD_EFFECTS_WHEEL        0x0304
#define RDM_SD_BEAM_SIZE_IRIS       0x0401
#define RDM_SD_EDGE                 0x0402
#define RDM_SD_FROST                0x0403
#define RDM_SD_STROBE               0x0404
#define RDM_SD_ZOOM                 0x0405
#define RDM_SD_FRAMING_SHUTTER      0x0406
#define RDM_SD_SHUTTER_ROTATE       0x0407
#define RDM_SD_DOUSER               0x0408
#define RDM_SD_BARN_DOOR            0x0409
#define RDM_SD_LAMP_CONTROL         0x0501
#define RDM_SD_FIXTURE_CONTROL      0x0502
#define RDM_SD_FIXTURE_SPEED        0x0503
#define RDM_SD_MACRO                0x0504
#define RDM_SD_POWER_CONTROL        0x0505
#define RDM_SD_FAN_CONTROL          0x0506
#define RDM_SD_HEATER_CONTROL       0x0507
#define RDM_SD_FOUNTAIN_CONTROL     0x0508
#define RDM_SD_UNDEFINED            0xFFFF

static const value_string rdm_slot_label_definitions[] = {
  { RDM_SD_INTENSITY,            "Intensity" },
  { RDM_SD_INTENSITY_MASTER,     "Intensity Master" },
  { RDM_SD_PAN,                  "Pan" },
  { RDM_SD_TILT,                 "Tilt" },
  { RDM_SD_COLOR_WHEEL,          "Color Wheel" },
  { RDM_SD_COLOR_SUB_CYAN,       "Sub Cyan/Blue" },
  { RDM_SD_COLOR_SUB_YELLOW,     "Sub Yellow/Amber" },
  { RDM_SD_COLOR_SUB_MAGENTA,    "Sub Magenta" },
  { RDM_SD_COLOR_ADD_RED,        "Add Red" },
  { RDM_SD_COLOR_ADD_GREEN,      "Add Green" },
  { RDM_SD_COLOR_ADD_BLUE,       "Add Blue" },
  { RDM_SD_COLOR_CORRECTION,     "Color Temperature Correction" },
  { RDM_SD_COLOR_SCROLL,         "Color Scroll" },
  { RDM_SD_COLOR_ADD_LIME,       "Add Lime" },
  { RDM_SD_COLOR_ADD_INDIGO,     "Add Indigo" },
  { RDM_SD_COLOR_ADD_CYAN,       "Add Cyan" },
  { RDM_SD_COLOR_ADD_DEEP_RED,   "Add Deep Red" },
  { RDM_SD_COLOR_ADD_DEEP_BLUE,  "Add Deep Blue" },
  { RDM_SD_COLOR_ADD_NAT_WHITE,  "Add Natural White" },
  { RDM_SD_COLOR_SEMAPHORE,      "Color Semaphore" },
  { RDM_SD_COLOR_ADD_AMBER,      "Add Amber" },
  { RDM_SD_COLOR_ADD_WHITE,      "Add White" },
  { RDM_SD_COLOR_ADD_WARM_WHITE, "Add Warm White" },
  { RDM_SD_COLOR_ADD_COOL_WHITE, "Add Cool White" },
  { RDM_SD_COLOR_SUB_UV,         "Sub UV" },
  { RDM_SD_COLOR_HUE,            "Hue" },
  { RDM_SD_COLOR_SATURATION,     "Saturation" },
  { RDM_SD_COLOR_ADD_UV,         "Add UV" },
  { RDM_SD_STATIC_GOBO_WHEEL,    "Static gobo wheel" },
  { RDM_SD_ROTO_GOBO_WHEEL,      "Rotating gobo wheel" },
  { RDM_SD_PRISM_WHEEL,          "Prism wheel" },
  { RDM_SD_EFFECTS_WHEEL,        "Effects wheel" },
  { RDM_SD_BEAM_SIZE_IRIS,       "Beam size iris" },
  { RDM_SD_EDGE,                 "Edge/Lens focus" },
  { RDM_SD_FROST,                "Frost/Diffusion" },
  { RDM_SD_STROBE,               "Strobe/Shutter" },
  { RDM_SD_ZOOM,                 "Zoom lens" },
  { RDM_SD_FRAMING_SHUTTER,      "Framing shutter" },
  { RDM_SD_SHUTTER_ROTATE,       "Framing shutter rotation" },
  { RDM_SD_DOUSER,               "Douser" },
  { RDM_SD_BARN_DOOR,            "Barn Door" },
  { RDM_SD_LAMP_CONTROL,         "Lamp control functions" },
  { RDM_SD_FIXTURE_CONTROL,      "Fixture control channel" },
  { RDM_SD_FIXTURE_SPEED,        "Overall speed" },
  { RDM_SD_MACRO,                "Macro control" },
  { RDM_SD_POWER_CONTROL,        "Relay or power control" },
  { RDM_SD_FAN_CONTROL,          "Fan control" },
  { RDM_SD_HEATER_CONTROL,       "Heater control" },
  { RDM_SD_FOUNTAIN_CONTROL,     "Fountain water pump control" },
  { RDM_SD_UNDEFINED,            "Undefined" },
  { 0, NULL },
};

/* E1.37-1 */
#define RDM_PRESET_NOT_PROGRAMMED        0x00
#define RDM_PRESET_PROGRAMMED            0x01
#define RDM_PRESET_PROGRAMMED_READ_ONLY  0x02

static const value_string rdm_preset_programmed_vals[] = {
  { RDM_PRESET_NOT_PROGRAMMED,        "Preset Not Programmed" },
  { RDM_PRESET_PROGRAMMED,            "Preset Programmed" },
  { RDM_PRESET_PROGRAMMED_READ_ONLY,  "Preset Programmed Read Only" },
  { 0, NULL },
};

/* E1.37-1 */
#define RDM_MERGEMODE_DEFAULT   0x00
#define RDM_MERGEMODE_HTP       0x01
#define RDM_MERGEMODE_LTP       0x02
#define RDM_MERGEMODE_DMX_ONLY  0x03
#define RDM_MERGEMODE_OTHER     0xFF

static const value_string rdm_mergemode_vals[] = {
  { RDM_MERGEMODE_DEFAULT,   "Mergemode Default" },
  { RDM_MERGEMODE_HTP,       "Mergemode Highest Takes Precedence" },
  { RDM_MERGEMODE_LTP,       "Mergemode Last Takes Precedence" },
  { RDM_MERGEMODE_DMX_ONLY,  "Mergemode DMX Only" },
  { RDM_MERGEMODE_OTHER,     "Mergemode Other" },
  { 0, NULL },
};

/* E1.37-1 */
#define RDM_LOCK_STATE_UNLOCKED 0x00

static const value_string rdm_lock_state_vals[] = {
  { RDM_LOCK_STATE_UNLOCKED, "Unlocked" },
  { 0, NULL },
};

/* E1.37-1 */
#define RDM_IDENTIFY_MODE_QUIET 0x00
#define RDM_IDENTIFY_MODE_LOUD  0xFF

static const value_string rdm_identify_mode_vals[] = {
  { RDM_IDENTIFY_MODE_QUIET, "Quiet Identify" },
  { RDM_IDENTIFY_MODE_LOUD,  "Loud Identify" },
  { 0, NULL },
};

/* E1.37-2 */
#define RDM_DHCP_STATUS_INACTIVE  0x00
#define RDM_DHCP_STATUS_ACTIVE    0x01
#define RDM_DHCP_STATUS_UNKNOWN   0x02

static const value_string rdm_dhcp_status_vals[] = {
  { RDM_DHCP_STATUS_INACTIVE,  "DHCP Status Inactive" },
  { RDM_DHCP_STATUS_ACTIVE,    "DHCP Status Active" },
  { RDM_DHCP_STATUS_UNKNOWN,   "DHCP Status Unknown" },
  { 0, NULL },
};

/* E1.37-4 */
#define RDM_FTC_RS_STATUS_OK              0x00
#define RDM_FTC_RS_INITOK_UL              0x01
#define RDM_FTC_RS_INITOK_DL              0x02
#define RDM_FTC_RS_STATUS_IN_PROGRESS     0x03
#define RDM_FTC_RS_TRANSFER_COMPLETE      0x04
#define RDM_FTC_RS_MODAL_ERROR            0x05
#define RDM_FTC_RS_SWITCH_TO_BOOTLOADER   0x06
#define RDM_FTC_RS_SESSIONID_MISMATCH     0x07
#define RDM_FTC_RS_UNSUPPORTED_FILEID     0x08
#define RDM_FTC_RS_FILE_NOT_COMPATIBLE    0x09
#define RDM_FTC_RS_FILE_NOT_AVAILABLE     0x0A
#define RDM_FTC_RS_PACKET_CRC_ERROR       0x0B
#define RDM_FTC_RS_FILE_CRC_ERROR         0x0C
#define RDM_FTC_RS_VALIDATION_ERROR       0x0D
#define RDM_FTC_RS_E137_LOCKACTIVE        0x10
#define RDM_FTC_RS_OTHER_LOCKACTIVE       0x11
#define RDM_FTC_RS_WRITE_PROTECT          0x12
#define RDM_FTC_RS_INVALID_DIRECTION      0x13
#define RDM_FTC_RS_OFFSET_ERROR           0x14
#define RDM_FTC_RS_FILESIZE_ERROR         0x15
#define RDM_FTC_RS_FTCVERSION_ERROR       0x16
#define RDM_FTC_RS_FILE_CRC_NOT_SUPPORTED 0x17
#define RDM_FTC_RS_DOWNLOAD_KEY_REQUIRED  0x18
#define RDM_FTC_RS_DOWNLOAD_FILE_CRC      0x19
#define RDM_FTC_RS_DOWNLOAD_COMMAND_ERROR 0x1A
#define RDM_FTC_RS_UNRESOLVED_ERROR       0x7F

static const value_string rdm_ftc_response_status_vals[] = {
  { RDM_FTC_RS_STATUS_OK,              "Ok" },
  { RDM_FTC_RS_INITOK_UL,              "Upload Init Ok" },
  { RDM_FTC_RS_INITOK_DL,              "Download Init Ok" },
  { RDM_FTC_RS_STATUS_IN_PROGRESS,     "In Progress" },
  { RDM_FTC_RS_TRANSFER_COMPLETE,      "Transfer Complete" },
  { RDM_FTC_RS_MODAL_ERROR,            "Modal Error" },
  { RDM_FTC_RS_SWITCH_TO_BOOTLOADER,   "Switching to Bootloader" },
  { RDM_FTC_RS_SESSIONID_MISMATCH,     "Session ID Mismatch" },
  { RDM_FTC_RS_UNSUPPORTED_FILEID,     "Unsupported File ID" },
  { RDM_FTC_RS_FILE_NOT_COMPATIBLE,    "File Not Compatible" },
  { RDM_FTC_RS_FILE_NOT_AVAILABLE,     "File Not Available" },
  { RDM_FTC_RS_PACKET_CRC_ERROR,       "Packet CRC Error" },
  { RDM_FTC_RS_FILE_CRC_ERROR,         "File CRC Error" },
  { RDM_FTC_RS_VALIDATION_ERROR,       "Validation Error" },
  { RDM_FTC_RS_E137_LOCKACTIVE,        "E1.37 Lock Active" },
  { RDM_FTC_RS_OTHER_LOCKACTIVE,       "Other Lock Active" },
  { RDM_FTC_RS_WRITE_PROTECT,          "Write Protect" },
  { RDM_FTC_RS_INVALID_DIRECTION,      "Invalid Direction" },
  { RDM_FTC_RS_OFFSET_ERROR,           "Offset Error" },
  { RDM_FTC_RS_FILESIZE_ERROR,         "File Size Error" },
  { RDM_FTC_RS_FTCVERSION_ERROR,       "FTC Version Error" },
  { RDM_FTC_RS_FILE_CRC_NOT_SUPPORTED, "File CRC Not Supported" },
  { RDM_FTC_RS_DOWNLOAD_KEY_REQUIRED,  "Download Key Required" },
  { RDM_FTC_RS_DOWNLOAD_FILE_CRC,      "Download File CRC" },
  { RDM_FTC_RS_DOWNLOAD_COMMAND_ERROR, "Download Command Error" },
  { RDM_FTC_RS_UNRESOLVED_ERROR,       "Unresolved Error" },
  { 0, NULL }
};

/* E1.37-4 */
#define FTC_TD_GET_NEXT_PACKET    0x01
#define FTC_TD_RESEND_LAST_PACKET 0x02
#define FTC_TD_GET_FILE_CRC       0x03

static const value_string rdm_ftc_download_command_vals[] = {
  { FTC_TD_GET_NEXT_PACKET,    "Get Next Packet" },
  { FTC_TD_RESEND_LAST_PACKET, "Resend Last Packet" },
  { FTC_TD_GET_FILE_CRC,       "Get File CRC" },
  { 0, NULL }
};

/* E1.37-4 */
static const value_string rdm_ftc_session_id_vals[] = {
  { 0x00, "No Session ID" },
  { 0xFF, "All Sessions" },
  { 0, NULL }
};

/* E1.37-4 */
static const value_string rdm_ftc_file_id_vals[] = {
  { 0x00, "No FileID offered" },
  { 0xFF, "Multiple FileIDs" },
  { 0, NULL }
};

/* E1.37-5 */
static const value_string rdm_identify_timeout_vals[] = {
  { 0, "Timeout Disabled" },
  { 0, NULL },
};

/* E1.37-5 */
#define RDM_SHIPPING_LOCK_STATE_UNLOCKED          0x00
#define RDM_SHIPPING_LOCK_STATE_LOCKED            0x01
#define RDM_SHIPPING_LOCK_STATE_PARTIALLY_LOCKED  0x02

static const value_string rdm_shipping_lock_state_vals[] = {
  { RDM_SHIPPING_LOCK_STATE_UNLOCKED,         "Unlocked" },
  { RDM_SHIPPING_LOCK_STATE_LOCKED,           "Locked" },
  { RDM_SHIPPING_LOCK_STATE_PARTIALLY_LOCKED, "Partially Locked" },
  { 0, NULL },
};

/* E1.37-7 */
#define RDM_DISCOVERY_STATE_INCOMPLETE   0x00
#define RDM_DISCOVERY_STATE_INCREMENTAL  0x01
#define RDM_DISCOVERY_STATE_FULL         0x02
                                 /* skip 0x03 */
#define RDM_DISCOVERY_STATE_NOT_ACTIVE   0x04

static const value_string rdm_discovery_state_vals[] = {
  { RDM_DISCOVERY_STATE_INCOMPLETE,   "Incomplete" },
  { RDM_DISCOVERY_STATE_INCREMENTAL,  "Incremental" },
  { RDM_DISCOVERY_STATE_FULL,         "Full" },
  { RDM_DISCOVERY_STATE_NOT_ACTIVE,   "Not Active" },
  { 0, NULL },
};

/* E1.37-7 */
#define RDM_ENDPOINT_MODE_DISABLED  0x00
#define RDM_ENDPOINT_MODE_INPUT     0x01
#define RDM_ENDPOINT_MODE_OUTPUT    0x02

static const value_string rdm_endpoint_mode_vals[] = {
  { RDM_ENDPOINT_MODE_DISABLED,  "Disabled" },
  { RDM_ENDPOINT_MODE_INPUT,     "Input" },
  { RDM_ENDPOINT_MODE_OUTPUT,    "Output" },
  { 0, NULL },
};

/* E1.37-7 */
#define RDM_ENDPOINT_TYPE_VIRTUAL   0x00
#define RDM_ENDPOINT_TYPE_PHYSICAL  0x01

static const value_string rdm_endpoint_type_vals[] = {
  { RDM_ENDPOINT_TYPE_VIRTUAL,   "Virtual" },
  { RDM_ENDPOINT_TYPE_PHYSICAL,  "Physical" },
  { 0, NULL },
};

/* E1.37-7 */
#define RDM_DISCOVERY_COUNT_INCOMPLETE 0x0000
#define RDM_DISCOVERY_COUNT_UNKNOWN    0xFFFF

static const value_string rdm_discovery_count_vals[] = {
  { RDM_DISCOVERY_COUNT_INCOMPLETE, "Incomplete" },
  { RDM_DISCOVERY_COUNT_UNKNOWN,    "Unknown" },
  { 0, NULL },
};

/* E1.33 Table A-17 Static Config Types for Component Scope Messages */
#define RDMNET_COMPONENT_SCOPE_NO_STATIC_CONFIG    0x00
#define RDMNET_COMPONENT_SCOPE_STATIC_CONFIG_IPV4  0x01
#define RDMNET_COMPONENT_SCOPE_STATIC_CONFIG_IPV6  0x02

static const value_string rdmnet_component_scope_static_config_type_vals[] = {
  { RDMNET_COMPONENT_SCOPE_NO_STATIC_CONFIG,   "No Static Config" },
  { RDMNET_COMPONENT_SCOPE_STATIC_CONFIG_IPV4, "Static Config IPv4" },
  { RDMNET_COMPONENT_SCOPE_STATIC_CONFIG_IPV6, "Static Config IPv6" },
  { 0, NULL }
};
/* E1.33 Table A-18 Broker States for Broker Status Messages */
#define RDMNET_BROKER_STATE_DISABLED  0x00
#define RDMNET_BROKER_STATE_ACTIVE    0x01
#define RDMNET_BROKER_STATE_STANDBY   0x02

static const value_string rdmnet_broker_status_states_vals[] = {
  { RDMNET_BROKER_STATE_DISABLED, "Broker State Disabled" },
  { RDMNET_BROKER_STATE_ACTIVE,   "Broker State Active" },
  { RDMNET_BROKER_STATE_STANDBY,  "Broker State Standby" },
  { 0, NULL }
};

static const value_string true_false_vals[] = {
  { 0x00,  "False" },
  { 0x01,  "True" },
  { 0, NULL },
};

static const value_string enabled_disabled_vals[] = {
  { 0x00,  "Disabled" },
  { 0x01,  "Enabled" },
  { 0, NULL },
};

static const value_string on_off_vals[] = {
  { 0x00,  "Off" },
  { 0x01,  "On" },
  { 0, NULL },
};

static int proto_rdm;

static int hf_rdm_sub_start_code;
static int hf_rdm_message_length;
static int hf_rdm_dest_uid;
static int hf_rdm_dest_uid_dyn;
static int hf_rdm_dest_uid_manf;
static int hf_rdm_dest_uid_dev;
static int hf_rdm_src_uid;
static int hf_rdm_src_uid_dyn;
static int hf_rdm_src_uid_manf;
static int hf_rdm_src_uid_dev;
static int hf_rdm_transaction_number;
static int hf_rdm_port_id;
static int hf_rdm_response_type;
static int hf_rdm_message_count;
static int hf_rdm_controller_flags;
static int hf_rdm_controller_flags_unicode;
static int hf_rdm_controller_flags_hi_res_ack_timer;
static int hf_rdm_sub_device;
static int hf_rdm_mdb;
static int hf_rdm_command_class;
static int hf_rdm_parameter_id;
static int hf_rdm_parameter_data_length;
static int hf_rdm_parameter_data;
static int hf_rdm_parameter_data_raw;
static int hf_rdm_intron;
static int hf_rdm_checksum;
static int hf_rdm_checksum_status;
static int hf_rdm_trailer;

static int hf_rdm_pd_ack_timer_estimated_response_time;
static int hf_rdm_pd_ack_timer_hi_res_estimated_response_time;
static int hf_rdm_pd_ack_overflow_raw_data;
static int hf_rdm_pd_nack_reason_code;

static int hf_rdm_pd_device_label;

static int hf_rdm_pd_manu_label;

static int hf_rdm_pd_dmx_start_address;

static int hf_rdm_pd_queued_message_status;

static int hf_rdm_pd_sensor_nr;
static int hf_rdm_pd_sensor_type;
static int hf_rdm_pd_sensor_unit;
static int hf_rdm_pd_sensor_prefix;
static int hf_rdm_pd_sensor_value_pres;
static int hf_rdm_pd_sensor_value_low;
static int hf_rdm_pd_sensor_value_high;
static int hf_rdm_pd_sensor_value_rec;

static int hf_rdm_pd_sensor_range_min_value;
static int hf_rdm_pd_sensor_range_max_value;
static int hf_rdm_pd_sensor_normal_min_value;
static int hf_rdm_pd_sensor_normal_max_value;
static int hf_rdm_pd_sensor_recorded_value_support;
static int hf_rdm_pd_sensor_recorded_value_support_recorded;
static int hf_rdm_pd_sensor_recorded_value_support_low_high;
static int hf_rdm_pd_sensor_description;
static int hf_rdm_pd_sensor_subscribe_action;
static int hf_rdm_pd_sensor_type_label;
static int hf_rdm_pd_sensor_unit_label;

static int hf_rdm_pd_device_hours;
static int hf_rdm_pd_lamp_hours;
static int hf_rdm_pd_lamp_strikes;


static int hf_rdm_pd_proto_vers;
static int hf_rdm_pd_device_model_id;
static int hf_rdm_pd_product_cat;
static int hf_rdm_pd_software_vers_id;
static int hf_rdm_pd_dmx_footprint;
static int hf_rdm_pd_dmx_pers_current;
static int hf_rdm_pd_dmx_pers_total;
static int hf_rdm_pd_sub_device_count;
static int hf_rdm_pd_sensor_count;

static int hf_rdm_pd_device_model_description;

static int hf_rdm_pd_disc_unique_branch_lb_uid;
static int hf_rdm_pd_disc_unique_branch_ub_uid;
static int hf_rdm_pd_disc_mute_control_field;
static int hf_rdm_pd_disc_mute_control_field_managed;
static int hf_rdm_pd_disc_mute_control_field_sub_device;
static int hf_rdm_pd_disc_mute_control_field_bootloader;
static int hf_rdm_pd_disc_mute_control_field_proxied;
static int hf_rdm_pd_disc_mute_binding_uid;
static int hf_rdm_pd_disc_mute_binding_uid_dyn;
static int hf_rdm_pd_disc_mute_binding_uid_manf;
static int hf_rdm_pd_disc_mute_binding_uid_dev;
static int hf_rdm_pd_disc_unmute_control_field;
static int hf_rdm_pd_disc_unmute_control_field_managed;
static int hf_rdm_pd_disc_unmute_control_field_sub_device;
static int hf_rdm_pd_disc_unmute_control_field_bootloader;
static int hf_rdm_pd_disc_unmute_control_field_proxied;
static int hf_rdm_pd_disc_unmute_binding_uid;
static int hf_rdm_pd_disc_unmute_binding_uid_dyn;
static int hf_rdm_pd_disc_unmute_binding_uid_manf;
static int hf_rdm_pd_disc_unmute_binding_uid_dev;
static int hf_rdm_pd_proxied_devices_uid;
static int hf_rdm_pd_proxied_devices_uid_dyn;
static int hf_rdm_pd_proxied_devices_uid_manf;
static int hf_rdm_pd_proxied_devices_uid_dev;
static int hf_rdm_pd_proxied_device_count;
static int hf_rdm_pd_proxied_device_list_change;
static int hf_rdm_pd_real_time_clock_year;
static int hf_rdm_pd_real_time_clock_month;
static int hf_rdm_pd_real_time_clock_day;
static int hf_rdm_pd_real_time_clock_hour;
static int hf_rdm_pd_real_time_clock_minute;
static int hf_rdm_pd_real_time_clock_second;
static int hf_rdm_pd_lamp_state;
static int hf_rdm_pd_lamp_on_mode;
static int hf_rdm_pd_device_power_cycles;
static int hf_rdm_pd_display_invert;
static int hf_rdm_pd_display_level;
static int hf_rdm_pd_pan_invert;
static int hf_rdm_pd_tilt_invert;
static int hf_rdm_pd_tilt_swap;
static int hf_rdm_pd_selftest_nr;
static int hf_rdm_pd_selftest_state;
static int hf_rdm_pd_selftest_description;
static int hf_rdm_pd_selftest_status;
static int hf_rdm_pd_selftest_capability;
static int hf_rdm_pd_selftest_capability_auto_terminates;
static int hf_rdm_pd_selftest_capability_restricts_dmx;
static int hf_rdm_pd_selftest_capability_restricts_rdm;
static int hf_rdm_pd_selftest_capability_ignores_auto_terminate;
static int hf_rdm_pd_selftest_capability_result_codes_available;
static int hf_rdm_pd_selftest_capability_generates_status_messages;
static int hf_rdm_pd_selftest_result_code;
static int hf_rdm_pd_language_code;
static int hf_rdm_pd_identify_device;
static int hf_rdm_pd_identify_device_state;
static int hf_rdm_pd_reset_device;
static int hf_rdm_pd_power_state;
static int hf_rdm_pd_capture_preset_scene_nr;
static int hf_rdm_pd_capture_preset_up_fade_time;
static int hf_rdm_pd_capture_preset_down_fade_time;
static int hf_rdm_pd_capture_preset_wait_time;
static int hf_rdm_pd_preset_playback_mode;
static int hf_rdm_pd_preset_playback_level;
static int hf_rdm_pd_parameter_id;
static int hf_rdm_pd_parameter_pdl_size;
static int hf_rdm_pd_parameter_data_type;
static int hf_rdm_pd_parameter_cmd_class;
static int hf_rdm_pd_parameter_type;
static int hf_rdm_pd_parameter_unit;
static int hf_rdm_pd_parameter_prefix;
static int hf_rdm_pd_parameter_min_value;
static int hf_rdm_pd_parameter_max_value;
static int hf_rdm_pd_parameter_default_value;
static int hf_rdm_pd_parameter_description;
static int hf_rdm_pd_software_version_label;
static int hf_rdm_pd_boot_software_version_id;
static int hf_rdm_pd_boot_software_version_label;
static int hf_rdm_pd_manufacturer_url;
static int hf_rdm_pd_product_url;
static int hf_rdm_pd_firmware_url;
static int hf_rdm_pd_serial_number;
static int hf_rdm_pd_info_offstage_root_personality;
static int hf_rdm_pd_info_offstage_sub_device;
static int hf_rdm_pd_info_offstage_sub_device_personality;
static int hf_rdm_pd_comms_status_short_msg;
static int hf_rdm_pd_comms_status_len_mismatch;
static int hf_rdm_pd_comms_status_csum_fail;
static int hf_rdm_pd_test_data_pattern_length;
static int hf_rdm_pd_test_data_pattern_data;
static int hf_rdm_pd_comms_status_nsc_supported_fields;
static int hf_rdm_pd_comms_status_nsc_supported_fields_csum;
static int hf_rdm_pd_comms_status_nsc_supported_fields_packet_count;
static int hf_rdm_pd_comms_status_nsc_supported_fields_slot_count;
static int hf_rdm_pd_comms_status_nsc_supported_fields_slot_min;
static int hf_rdm_pd_comms_status_nsc_supported_fields_slot_max;
static int hf_rdm_pd_comms_status_nsc_supported_fields_error_count;
static int hf_rdm_pd_comms_status_nsc_csum;
static int hf_rdm_pd_comms_status_nsc_packet_count;
static int hf_rdm_pd_comms_status_nsc_slot_count;
static int hf_rdm_pd_comms_status_nsc_slot_min;
static int hf_rdm_pd_comms_status_nsc_slot_max;
static int hf_rdm_pd_comms_status_nsc_error_count;
static int hf_rdm_pd_status_messages_type;
static int hf_rdm_pd_status_messages_sub_device_id;
static int hf_rdm_pd_status_messages_id;
static int hf_rdm_pd_status_messages_data_value_1;
static int hf_rdm_pd_status_messages_data_value_2;
static int hf_rdm_pd_status_id;
static int hf_rdm_pd_status_id_description;
static int hf_rdm_pd_sub_device_status_report_threshold_status_type;
static int hf_rdm_pd_metadata_parameter_version;
static int hf_rdm_pd_metadata_json;
static int hf_rdm_pd_metadata_json_url;
static int hf_rdm_pd_supported_parameters_pid_support;
static int hf_rdm_pd_supported_parameters_pid_support_get;
static int hf_rdm_pd_supported_parameters_pid_support_set;
static int hf_rdm_pd_supported_parameters_pid_support_packed_sub_get;
static int hf_rdm_pd_supported_parameters_pid_support_packed_sub_set;
static int hf_rdm_pd_supported_parameters_pid_support_packed_index_get;
static int hf_rdm_pd_supported_parameters_pid_support_packed_index_set;
static int hf_rdm_pd_supported_parameters_pid_support_non_identical_sub;
static int hf_rdm_pd_supported_parameters_pid_support_json_metadata;
static int hf_rdm_pd_controller_flag_support_flags;
static int hf_rdm_pd_controller_flag_support_flags_unicode;
static int hf_rdm_pd_controller_flag_support_flags_hi_res_ack_timer;
static int hf_rdm_pd_nack_description_reason_code;
static int hf_rdm_pd_nack_description_text;
static int hf_rdm_pd_packed_pid_index;
static int hf_rdm_pd_packed_pid_index_count;
static int hf_rdm_pd_packed_pid_sub_device;
static int hf_rdm_pd_packed_pid_sub_device_count;
static int hf_rdm_pd_packed_pid_data;
static int hf_rdm_pd_packed_pid_data_none;
static int hf_rdm_pd_packed_pid_data_len;
static int hf_rdm_pd_enum_label_index;
static int hf_rdm_pd_enum_label_max_index;
static int hf_rdm_pd_enum_label_label;
static int hf_rdm_pd_product_detail_id;
static int hf_rdm_pd_factory_defaults;
static int hf_rdm_pd_background_discovery_endpoint_id;
static int hf_rdm_pd_background_discovery_enabled;
static int hf_rdm_pd_background_queued_status_policy_current_policy;
static int hf_rdm_pd_background_queued_status_policy_number_of_policies;
static int hf_rdm_pd_background_queued_status_policy_description_policy;
static int hf_rdm_pd_background_queued_status_policy_description_description;
static int hf_rdm_pd_binding_control_fields_endpoint_id;
static int hf_rdm_pd_binding_control_fields_uid;
static int hf_rdm_pd_binding_control_fields_uid_dyn;
static int hf_rdm_pd_binding_control_fields_uid_manf;
static int hf_rdm_pd_binding_control_fields_uid_dev;
static int hf_rdm_pd_binding_control_fields_control_field;
static int hf_rdm_pd_binding_control_fields_binding_uid;
static int hf_rdm_pd_binding_control_fields_binding_uid_dyn;
static int hf_rdm_pd_binding_control_fields_binding_uid_manf;
static int hf_rdm_pd_binding_control_fields_binding_uid_dev;
static int hf_rem_pd_broker_status_set_allowed;
static int hf_rem_pd_broker_status_state;
static int hf_rdm_pd_burn_in;
static int hf_rdm_pd_component_scope_scope_slot;
static int hf_rdm_pd_component_scope_scope_string;
static int hf_rdm_pd_component_scope_scope_static_config_type;
static int hf_rdm_pd_component_scope_scope_static_ipv4_address;
static int hf_rdm_pd_component_scope_scope_static_ipv6_address;
static int hf_rdm_pd_component_scope_scope_static_port;
static int hf_rdm_pd_current_address_interface_identifier;
static int hf_rdm_pd_current_address_ipv4_address;
static int hf_rdm_pd_current_address_netmask;
static int hf_rdm_pd_current_address_dhcp_status;
static int hf_rdm_pd_curve_curve;
static int hf_rdm_pd_curve_number_of_curves;
static int hf_rdm_pd_curve_description_curve;
static int hf_rdm_pd_curve_description_text;
static int hf_rdm_pd_device_unit_number;
static int hf_rdm_pd_dhcp_mode_interface_identifier;
static int hf_rdm_pd_dhcp_mode_enabled;
static int hf_rdm_pd_dimmer_info_minimum_level_lower_limit;
static int hf_rdm_pd_dimmer_info_minimum_level_upper_limit;
static int hf_rdm_pd_dimmer_info_maximum_level_lower_limit;
static int hf_rdm_pd_dimmer_info_maximum_level_upper_limit;
static int hf_rdm_pd_dimmer_info_number_of_supported_curves;
static int hf_rdm_pd_dimmer_info_levels_resolution;
static int hf_rdm_pd_dimmer_info_minimum_level_split_levels_supported;
static int hf_rdm_pd_discovery_state_endpoint_id;
static int hf_rdm_pd_discovery_state_device_count;
static int hf_rdm_pd_discovery_state_discovery_state;
static int hf_rdm_pd_dmx_block_address_base_dmx_address;
static int hf_rdm_pd_dmx_block_address_subdevice_footprint;
static int hf_rdm_pd_dmx_fail_mode_scene_number;
static int hf_rdm_pd_dmx_fail_mode_loss_of_signal_delay;
static int hf_rdm_pd_dmx_fail_mode_hold_time;
static int hf_rdm_pd_dmx_fail_mode_level;
static int hf_rdm_pd_dmx_pers_nr;
static int hf_rdm_pd_dmx_pers_count;
static int hf_rdm_pd_dmx_pers_requested;
static int hf_rdm_pd_dmx_pers_slots;
static int hf_rdm_pd_dmx_pers_text;
static int hf_rdm_pd_dmx_pers_id_major;
static int hf_rdm_pd_dmx_pers_id_minor;
static int hf_rdm_pd_dmx_startup_mode_scene_number;
static int hf_rdm_pd_dmx_startup_mode_loss_of_signal_delay;
static int hf_rdm_pd_dmx_startup_mode_hold_time;
static int hf_rdm_pd_dmx_startup_mode_level;
static int hf_rdm_pd_dns_domain_name;
static int hf_rdm_pd_dns_hostname;
static int hf_rdm_pd_dns_ipv4_name_server_index;
static int hf_rdm_pd_dns_ipv4_name_server_address;
static int hf_rdm_pd_endpoint_label_endpoint_id;
static int hf_rdm_pd_endpoint_label_label;
static int hf_rdm_pd_endpoint_list_change_number;
static int hf_rdm_pd_endpoint_list_endpoint_id;
static int hf_rdm_pd_endpoint_list_endpoint_type;
static int hf_rdm_pd_endpoint_list_change_change_number;
static int hf_rdm_pd_endpoint_mode_endpoint_id;
static int hf_rdm_pd_endpoint_mode_endpoint_mode;
static int hf_rdm_pd_endpoint_responder_list_change_endpoint_id;
static int hf_rdm_pd_endpoint_responder_list_change_change_number;
static int hf_rdm_pd_endpoint_responders_endpoint_id;
static int hf_rdm_pd_endpoint_responders_change_number;
static int hf_rdm_pd_endpoint_responders_uid;
static int hf_rdm_pd_endpoint_responders_uid_dyn;
static int hf_rdm_pd_endpoint_responders_uid_manf;
static int hf_rdm_pd_endpoint_responders_uid_dev;
static int hf_rdm_pd_endpoint_timing_endpoint_id;
static int hf_rdm_pd_endpoint_timing_setting;
static int hf_rdm_pd_endpoint_timing_number_of_settings;
static int hf_rdm_pd_endpoint_timing_description_setting;
static int hf_rdm_pd_endpoint_timing_description_description;
static int hf_rdm_pd_endpoint_to_universe_endpoint_id;
static int hf_rdm_pd_endpoint_to_universe_universe_number;
static int hf_rdm_pd_hardware_address_type1_interface_identifier;
static int hf_rdm_pd_hardware_address_type1_hardware_address;
static int hf_rdm_pd_identify_endpoint_endpoint_id;
static int hf_rdm_pd_identify_endpoint_identify_state;
static int hf_rdm_pd_identify_mode;
static int hf_rdm_pd_identify_timeout;
static int hf_rdm_pd_interface_apply_configuration_interface_identifier;
static int hf_rdm_pd_interface_label_interface_identifier;
static int hf_rdm_pd_interface_label_label;
static int hf_rdm_pd_interface_release_dhcp_interface_identifier;
static int hf_rdm_pd_interface_renew_dhcp_interface_identifier;
static int hf_rdm_pd_ipv4_default_route_interface_identifier;
static int hf_rdm_pd_ipv4_default_route_ipv4_default_route;
static int hf_rdm_pd_list_interfaces_interface_identifier;
static int hf_rdm_pd_list_interfaces_interface_hardware_type;
static int hf_rdm_pd_lock_pin_pin_code;
static int hf_rdm_pd_lock_pin_new_pin_code;
static int hf_rdm_pd_lock_state_lock_state;
static int hf_rdm_pd_lock_state_number_of_lock_states;
static int hf_rdm_pd_lock_state_pin_code;
static int hf_rdm_pd_lock_state_description_lock_state;
static int hf_rdm_pd_lock_state_description_text;
static int hf_rdm_pd_maximum_level_level;
static int hf_rdm_pd_preset_mergemode;
static int hf_rdm_pd_power_on_self_test;
static int hf_rdm_pd_minimum_level_increasing;
static int hf_rdm_pd_minimum_level_decreasing;
static int hf_rdm_pd_minimum_level_on_below_minimum;
static int hf_rdm_pd_modulation_frequency_modulation_frequency;
static int hf_rdm_pd_modulation_frequency_number_of_modulation_frequencies;
static int hf_rdm_pd_modulation_frequency_description_modulation_frequency;
static int hf_rdm_pd_modulation_frequency_description_hertz;
static int hf_rdm_pd_modulation_frequency_description_text;
static int hf_rdm_pd_output_response_time_response_time;
static int hf_rdm_pd_output_response_time_number_of_response_times;
static int hf_rdm_pd_output_response_time_description_output_response_time;
static int hf_rdm_pd_output_response_time_description_text;
static int hf_rdm_pd_power_off_ready;
static int hf_rdm_pd_preset_info_level_field_supported;
static int hf_rdm_pd_preset_info_preset_sequence_supported;
static int hf_rdm_pd_preset_info_split_times_supported;
static int hf_rdm_pd_preset_info_dmx_fail_infinite_delay_time_supported;
static int hf_rdm_pd_preset_info_dmx_fail_infinite_hold_time_supported;
static int hf_rdm_pd_preset_info_start_up_infinite_hold_time_supported;
static int hf_rdm_pd_preset_info_maximum_scene_number;
static int hf_rdm_pd_preset_info_minimum_preset_fade_time_supported;
static int hf_rdm_pd_preset_info_maximum_preset_fade_time_supported;
static int hf_rdm_pd_preset_info_minimum_preset_wait_time_supported;
static int hf_rdm_pd_preset_info_maximum_preset_wait_time_supported;
static int hf_rdm_pd_preset_info_minimum_dmx_fail_delay_time_supported;
static int hf_rdm_pd_preset_info_maximum_dmx_fail_delay_time_supported;
static int hf_rdm_pd_preset_info_minimum_dmx_fail_hold_time_supported;
static int hf_rdm_pd_preset_info_maximum_dmx_fail_hold_time_supported;
static int hf_rdm_pd_preset_info_minimum_start_up_delay_time_supported;
static int hf_rdm_pd_preset_info_maximum_start_up_delay_time_supported;
static int hf_rdm_pd_preset_info_minimum_start_up_hold_time_supported;
static int hf_rdm_pd_preset_info_maximum_start_up_hold_time_supported;
static int hf_rdm_pd_preset_status_scene_number;
static int hf_rdm_pd_preset_status_up_fade_time;
static int hf_rdm_pd_preset_status_down_fade_time;
static int hf_rdm_pd_preset_status_wait_time;
static int hf_rdm_pd_preset_status_programmed;
static int hf_rdm_pd_preset_status_clear_preset;
static int hf_rdm_pd_rdm_traffic_enable_endpoint_id;
static int hf_rdm_pd_rdm_traffic_enable_rdm_enabled;
static int hf_rdm_pd_search_domain_dns_domain_name;
static int hf_rdm_pd_shipping_lock_state;
static int hf_rdm_pd_slot_offset;
static int hf_rdm_pd_slot_type;
static int hf_rdm_pd_slot_label_id;
static int hf_rdm_pd_slot_primary_offset;
static int hf_rdm_pd_slot_nr;
static int hf_rdm_pd_slot_description;
static int hf_rdm_pd_slot_value;
static int hf_rdm_pd_static_address_interface_identifier;
static int hf_rdm_pd_static_address_ipv4_address;
static int hf_rdm_pd_static_address_netmask;
static int hf_rdm_pd_tag;
static int hf_rdm_pd_tag_null;
static int hf_rdm_pd_tag_status;
static int hf_rdm_pd_tag_list;
static int hf_rdm_pd_tcp_comms_status_scope_string;
static int hf_rdm_pd_tcp_comms_status_broker_ipv4_address;
static int hf_rdm_pd_tcp_comms_status_broker_ipv6_address;
static int hf_rdm_pd_tcp_comms_status_broker_port;
static int hf_rdm_pd_tcp_comms_status_unhealthy_tcp_events;
static int hf_rdm_pd_zeroconf_mode_interface_identifier;
static int hf_rdm_pd_zeroconf_mode_enabled;
static int hf_rdm_pd_rec_value_support;

static int hf_rdm_pd_ftc_session_id;
static int hf_rdm_pd_ftc_file_id;
static int hf_rdm_pd_ftc_version_major;
static int hf_rdm_pd_ftc_version_minor;
static int hf_rdm_pd_ftc_transfer_flags;
static int hf_rdm_pd_ftc_transfer_flags_test_mode;
static int hf_rdm_pd_ftc_transfer_flags_download;
static int hf_rdm_pd_ftc_response_status;
static int hf_rdm_pd_ftc_response_data;
static int hf_rdm_pd_ftc_response_data_commit_time;
static int hf_rdm_pd_ftc_response_data_time_to_wait;
static int hf_rdm_pd_ftc_response_data_received_crc;
static int hf_rdm_pd_ftc_response_data_calculated_crc;
static int hf_rdm_pd_ftc_response_data_offered_fileid;
static int hf_rdm_pd_ftc_response_data_supported_fileid;
static int hf_rdm_pd_ftc_response_data_received_sessionid;
static int hf_rdm_pd_ftc_response_data_expected_sessionid;
static int hf_rdm_pd_ftc_response_data_expected_offset;
static int hf_rdm_pd_ftc_response_data_expected_file_size;
static int hf_rdm_pd_ftc_response_data_supported_major_ver;
static int hf_rdm_pd_ftc_response_data_supported_minor_ver;
static int hf_rdm_pd_ftc_response_data_received_command;
static int hf_rdm_pd_ftc_file_size;
static int hf_rdm_pd_ftc_data;
static int hf_rdm_pd_ftc_file_crc;
static int hf_rdm_pd_ftc_packet_crc;
static int hf_rdm_pd_ftc_packet_crc_status;
static int hf_rdm_pd_ftc_capabilities;
static int hf_rdm_pd_ftc_capabilities_accept_upload;
static int hf_rdm_pd_ftc_capabilities_accept_download;
static int hf_rdm_pd_ftc_capabilities_process_file_crc;
static int hf_rdm_pd_ftc_capabilities_process_packet_crc;
static int hf_rdm_pd_ftc_capabilities_generate_file_crc;
static int hf_rdm_pd_ftc_capabilities_generate_packet_crc;
static int hf_rdm_pd_ftc_capabilities_download_key;
static int hf_rdm_pd_ftc_capabilities_bootloader_switch;
static int hf_rdm_pd_ftc_capabilities_nsc_no_iterleave;
static int hf_rdm_pd_ftc_capabilities_nsc_ignored;
static int hf_rdm_pd_ftc_capabilities_function_limit;
static int hf_rdm_pd_ftc_capabilities_e137_lock;
static int hf_rdm_pd_ftc_capabilities_other_lock;
static int hf_rdm_pd_ftc_capabilities_accept_broadcasts;
static int hf_rdm_pd_ftc_capabilities_fail_may_brick;
static int hf_rdm_pd_ftc_capabilities_alternate_error_recovery;
static int hf_rdm_pd_ftc_capabilities_test_mode_supported;
static int hf_rdm_pd_ftc_data_offset;
static int hf_rdm_pd_ftc_transfer_block_size;
static int hf_rdm_pd_ftc_initial_delay;
static int hf_rdm_pd_ftc_inter_packet_delay;
static int hf_rdm_pd_ftc_accumulated_byte_count;
static int hf_rdm_pd_ftc_accumulated_byte_delay;
static int hf_rdm_pd_ftc_validation_delay;
static int hf_rdm_pd_ftc_max_inter_packet_delay;
static int hf_rdm_pd_ftc_commit_flags;
static int hf_rdm_pd_ftc_commit_flags_test_mode;
static int hf_rdm_pd_ftc_commit_flags_download;
static int hf_rdm_pd_ftc_calculated_file_crc;
static int hf_rdm_pd_ftc_expected_uid;
static int hf_rdm_pd_ftc_expected_uid_manf;
static int hf_rdm_pd_ftc_expected_uid_dev;
static int hf_rdm_pd_ftc_expected_uid_dyn;
static int hf_rdm_pd_ftc_file_description;
static int hf_rdm_pd_ftc_file_suffix;
static int hf_rdm_pd_ftc_command;

static int * const rdm_pd_disc_mute_control_field[] = {
  &hf_rdm_pd_disc_mute_control_field_managed,
  &hf_rdm_pd_disc_mute_control_field_sub_device,
  &hf_rdm_pd_disc_mute_control_field_bootloader,
  &hf_rdm_pd_disc_mute_control_field_proxied,
  NULL
};

static int * const rdm_pd_disc_unmute_control_field[] = {
  &hf_rdm_pd_disc_unmute_control_field_managed,
  &hf_rdm_pd_disc_unmute_control_field_sub_device,
  &hf_rdm_pd_disc_unmute_control_field_bootloader,
  &hf_rdm_pd_disc_unmute_control_field_proxied,
  NULL
};

static int * const rdm_controller_flags[] = {
  &hf_rdm_controller_flags_unicode,
  &hf_rdm_controller_flags_hi_res_ack_timer,
  NULL
};

static int * const rdm_pd_sensor_recorded_value_support[] = {
  &hf_rdm_pd_sensor_recorded_value_support_recorded,
  &hf_rdm_pd_sensor_recorded_value_support_low_high,
  NULL
};

static int * const rdm_pd_comms_status_nsc_supported_fields[] = {
  &hf_rdm_pd_comms_status_nsc_supported_fields_csum,
  &hf_rdm_pd_comms_status_nsc_supported_fields_packet_count,
  &hf_rdm_pd_comms_status_nsc_supported_fields_slot_count,
  &hf_rdm_pd_comms_status_nsc_supported_fields_slot_min,
  &hf_rdm_pd_comms_status_nsc_supported_fields_slot_max,
  &hf_rdm_pd_comms_status_nsc_supported_fields_error_count,
  NULL
};

static int * const rdm_pd_supported_parameters_pid_support[] = {
  &hf_rdm_pd_supported_parameters_pid_support_get,
  &hf_rdm_pd_supported_parameters_pid_support_set,
  &hf_rdm_pd_supported_parameters_pid_support_packed_sub_get,
  &hf_rdm_pd_supported_parameters_pid_support_packed_sub_set,
  &hf_rdm_pd_supported_parameters_pid_support_packed_index_get,
  &hf_rdm_pd_supported_parameters_pid_support_packed_index_set,
  &hf_rdm_pd_supported_parameters_pid_support_non_identical_sub,
  &hf_rdm_pd_supported_parameters_pid_support_json_metadata,
  NULL
};

static int * const rdm_pd_controller_flag_support_flags[] = {
  &hf_rdm_pd_controller_flag_support_flags_unicode,
  &hf_rdm_pd_controller_flag_support_flags_hi_res_ack_timer,
  NULL
};

static int * const rdm_pd_selftest_capability[] = {
  &hf_rdm_pd_selftest_capability_auto_terminates,
  &hf_rdm_pd_selftest_capability_restricts_dmx,
  &hf_rdm_pd_selftest_capability_restricts_rdm,
  &hf_rdm_pd_selftest_capability_ignores_auto_terminate,
  &hf_rdm_pd_selftest_capability_result_codes_available,
  &hf_rdm_pd_selftest_capability_generates_status_messages,
  NULL
};

static int * const rdm_pd_ftc_transfer_flags[] = {
  &hf_rdm_pd_ftc_transfer_flags_test_mode,
  &hf_rdm_pd_ftc_transfer_flags_download,
  NULL
};

static int * const rdm_pd_ftc_capabilities[] = {
  &hf_rdm_pd_ftc_capabilities_accept_upload,
  &hf_rdm_pd_ftc_capabilities_accept_download,
  &hf_rdm_pd_ftc_capabilities_process_file_crc,
  &hf_rdm_pd_ftc_capabilities_process_packet_crc,
  &hf_rdm_pd_ftc_capabilities_generate_file_crc,
  &hf_rdm_pd_ftc_capabilities_generate_packet_crc,
  &hf_rdm_pd_ftc_capabilities_download_key,
  &hf_rdm_pd_ftc_capabilities_bootloader_switch,
  &hf_rdm_pd_ftc_capabilities_nsc_no_iterleave,
  &hf_rdm_pd_ftc_capabilities_nsc_ignored,
  &hf_rdm_pd_ftc_capabilities_function_limit,
  &hf_rdm_pd_ftc_capabilities_e137_lock,
  &hf_rdm_pd_ftc_capabilities_other_lock,
  &hf_rdm_pd_ftc_capabilities_accept_broadcasts,
  &hf_rdm_pd_ftc_capabilities_fail_may_brick,
  &hf_rdm_pd_ftc_capabilities_alternate_error_recovery,
  &hf_rdm_pd_ftc_capabilities_test_mode_supported,
  NULL
};

static int * const rdm_pd_ftc_commit_flags[] = {
  &hf_rdm_pd_ftc_commit_flags_test_mode,
  &hf_rdm_pd_ftc_commit_flags_download,
  NULL
};

static int ett_rdm;
static int ett_rdm_mdb;
static int ett_rdm_pd;
static int ett_rdm_uid;
static int ett_rdm_controller_flags;
static int ett_rdm_packed_pid_data;
static int ett_rdm_pd_sensor_recorded_value_support;
static int ett_rdm_pd_disc_mute_control_field;
static int ett_rdm_pd_disc_unmute_control_field;
static int ett_rdm_pd_comms_status_nsc_supported_fields;
static int ett_rdm_pd_supported_parameters_pid_support;
static int ett_rdm_pd_controller_flag_support_flags;
static int ett_rdm_pd_selftest_capability;
static int ett_rdm_pd_ftc_transfer_flags;
static int ett_rdm_pd_ftc_response_data;
static int ett_rdm_pd_ftc_capabilities;
static int ett_rdm_pd_ftc_commit_flags;

static expert_field ei_rdm_checksum;
static expert_field ei_rdm_parameter_data_length;
static expert_field ei_rdm_ftc_crc;

static int hf_rdm_etc_parameter_id;
static int hf_rdm_etc_pd_parameter_id;
static int hf_rdm_etc_pd_device_model_id;

static unsigned
dissect_rdm_mdb_param_data_no_packed(tvbuff_t *tvb, unsigned offset, packet_info* pinfo, proto_tree *tree, uint8_t cc, uint16_t param_id, uint8_t pdl, uint16_t device_manufacturer_id);

static uint16_t
rdm_checksum(tvbuff_t *tvb, unsigned length)
{
  uint16_t sum = RDM_SC_RDM;
  unsigned  i;
  for (i = 0; i < length; i++)
    sum += tvb_get_uint8(tvb, i);
  return sum;
}

static uint16_t
crc16_rdm_tvb_offset(tvbuff_t *tvb, unsigned offset, unsigned len) {
  uint16_t modbus_crc = crc16_usb_tvb_offset(tvb, offset, len) ^ 0xFFFF;
  // we undo the out XOR
  // then do a byte swap, because the RDM version uses it's high and low bytes in the opposite
  // way to the Modbus (and USB) version
  return (modbus_crc >> 8) | (modbus_crc << 8);
}

static void
rdm_add_uid_item(proto_tree *tree, int hfindex, tvbuff_t *tvb, unsigned *offset_ptr, int hfindex_manf, int hfindex_dev, int hfindex_dyn)
{
  unsigned offset = *offset_ptr;
  proto_item* uid_item = proto_tree_add_item(tree, hfindex, tvb, offset, 6, ENC_NA);
  proto_tree* uid_tree = proto_item_add_subtree(uid_item, ett_rdm_uid);
  uint16_t uid_manf = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
  /* if it's a dynamic UID we add en extra flag and change the manf ID so it is still correct */
  if ((uid_manf & 0x8000) != 0 && uid_manf < 0xFFF0) {
    proto_tree_add_item(uid_tree, hfindex_dyn, tvb, offset, 1, ENC_NA);
    proto_tree_add_uint(uid_tree, hfindex_manf, tvb, offset, 2, uid_manf&0x7FFF);
  } else {
    proto_tree_add_item(uid_tree, hfindex_manf, tvb, offset, 2, ENC_BIG_ENDIAN);
  }
  proto_tree_add_item(uid_tree, hfindex_dev, tvb, offset+2, 4, ENC_BIG_ENDIAN);
  *offset_ptr += 6;
}

static uint16_t
rdm_add_param_id(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t device_manufacturer_id)
{
  uint16_t param_id = tvb_get_uint16(tvb, *offset, ENC_BIG_ENDIAN);
  if (param_id < 0x8000) {
    proto_tree_add_item(tree, hf_rdm_pd_parameter_id, tvb, *offset, 2, ENC_BIG_ENDIAN);
    *offset += 2;
  } else {
    switch(device_manufacturer_id) {
    case RDM_MANUFACTURER_ID_ETC:
      proto_tree_add_item(tree, hf_rdm_etc_pd_parameter_id, tvb, *offset, 2, ENC_BIG_ENDIAN);
      *offset += 2;
      break;
    default:
      proto_tree_add_item(tree, hf_rdm_pd_parameter_id, tvb, *offset, 2, ENC_BIG_ENDIAN);
      *offset += 2;
      break;
    }
  }
  return param_id;
}

static void
rdm_add_ftc_response_status_data(proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t param_id) {
  uint8_t response_status;
  proto_tree_add_item_ret_uint8(tree, hf_rdm_pd_ftc_response_status, tvb, *offset, 1, ENC_BIG_ENDIAN, &response_status);
  *offset += 1;
  proto_item* ti = proto_tree_add_item(tree, hf_rdm_pd_ftc_response_data, tvb, *offset, 4, ENC_BIG_ENDIAN);
  proto_tree* status_tree = proto_item_add_subtree(ti, ett_rdm_pd_ftc_response_data);
  switch (response_status) {
  case RDM_FTC_RS_STATUS_OK:
    if (param_id == RDM_PARAM_ID_FTC_COMMIT) {
      proto_tree_add_item(status_tree, hf_rdm_pd_ftc_response_data_commit_time, tvb, *offset, 4, ENC_BIG_ENDIAN);
    }
    break;
  case RDM_FTC_RS_STATUS_IN_PROGRESS:
  case RDM_FTC_RS_SWITCH_TO_BOOTLOADER:
    proto_tree_add_item(status_tree, hf_rdm_pd_ftc_response_data_time_to_wait, tvb, *offset, 4, ENC_BIG_ENDIAN);
    break;
  case RDM_FTC_RS_PACKET_CRC_ERROR:
  case RDM_FTC_RS_FILE_CRC_ERROR:
    proto_tree_add_item(status_tree, hf_rdm_pd_ftc_response_data_received_crc, tvb, *offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(status_tree, hf_rdm_pd_ftc_response_data_calculated_crc, tvb, *offset + 2, 2, ENC_BIG_ENDIAN);
    break;
  case RDM_FTC_RS_UNSUPPORTED_FILEID:
    proto_tree_add_item(status_tree, hf_rdm_pd_ftc_response_data_offered_fileid, tvb, *offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(status_tree, hf_rdm_pd_ftc_response_data_supported_fileid, tvb, *offset + 3, 1, ENC_BIG_ENDIAN);
    break;
  case RDM_FTC_RS_SESSIONID_MISMATCH:
    proto_tree_add_item(status_tree, hf_rdm_pd_ftc_response_data_received_sessionid, tvb, *offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(status_tree, hf_rdm_pd_ftc_response_data_expected_sessionid, tvb, *offset + 2, 2, ENC_BIG_ENDIAN);
    break;
  case RDM_FTC_RS_OFFSET_ERROR:
    proto_tree_add_item(status_tree, hf_rdm_pd_ftc_response_data_expected_offset, tvb, *offset, 4, ENC_BIG_ENDIAN);
    break;
  case RDM_FTC_RS_FILESIZE_ERROR:
    proto_tree_add_item(status_tree, hf_rdm_pd_ftc_response_data_expected_file_size, tvb, *offset, 4, ENC_BIG_ENDIAN);
    break;
  case RDM_FTC_RS_FTCVERSION_ERROR:
    proto_tree_add_item(status_tree, hf_rdm_pd_ftc_response_data_supported_major_ver, tvb, *offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(status_tree, hf_rdm_pd_ftc_response_data_supported_minor_ver, tvb, *offset + 2, 2, ENC_BIG_ENDIAN);
    break;
  case RDM_FTC_RS_DOWNLOAD_COMMAND_ERROR:
    proto_tree_add_item(status_tree, hf_rdm_pd_ftc_response_data_received_command, tvb, *offset, 4, ENC_BIG_ENDIAN);
    break;
  }
  *offset += 4;
}

/**
 * Heuristic:
 * Check if the sequence of bytes starting at offset could be the body section of a PACKED_PID message
 *
 * Checks for a repeating structure:
 * - u16
 * - u8: data_len
 * - data_len bytes
 */
static bool
check_packed_format(tvbuff_t *tvb, unsigned offset, uint8_t initial_len)
{
  if (tvb_captured_length_remaining(tvb, offset) < initial_len) {
    return false;
  }

  int32_t len = initial_len;
  while (len >= 3) {
    /* skip u16 (item or sub-device number) */
    len -= 2; offset += 2;
    /* read data len */
    uint8_t data_len = tvb_get_uint8(tvb, offset);
    len -= 1; offset += 1;
    /* skip data */
    len -= data_len; offset += data_len;
  }

  return len == 0;
}

/**
 * Heuristic:
 * Check if parameter data could be the first packet of a metadata string
 *
 * Check that the first 2 bytes are a manufacturer-specific PID
 * And that they are followed by the target_string
 */
static bool
check_metadata_has_param(tvbuff_t *tvb, unsigned offset, const uint8_t* target_str, size_t target_str_len)
{
  if (tvb_captured_length_remaining(tvb, offset) < 2) {
    return false;
  }

  uint16_t param_id = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
  if ((param_id & 0x8000) == 0) {
    return false;
  }

  return tvb_memeql(tvb, offset, target_str, target_str_len);
}


static unsigned
dissect_rdm_pd_queued_message(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_queued_message_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dmx_start_address(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_dmx_start_address, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_device_info(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_, uint16_t device_manufacturer_id)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_proto_vers, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    switch(device_manufacturer_id) {
    case RDM_MANUFACTURER_ID_ETC:
      proto_tree_add_item(tree, hf_rdm_etc_pd_device_model_id, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      break;
    default:
      proto_tree_add_item(tree, hf_rdm_pd_device_model_id, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      break;
    }
    proto_tree_add_item(tree, hf_rdm_pd_product_cat, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_software_vers_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_footprint, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_current, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_total, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_start_address, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_sub_device_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_count, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}


static unsigned
dissect_rdm_pd_device_model_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_device_model_description, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}


static unsigned
dissect_rdm_pd_device_label(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_device_label, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}


static unsigned
dissect_rdm_pd_device_hours(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_device_hours, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}


static unsigned
dissect_rdm_pd_lamp_hours(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_lamp_hours, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}


static unsigned
dissect_rdm_pd_lamp_strikes(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_lamp_strikes, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}


static unsigned
dissect_rdm_pd_sensor_definition(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_sensor_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_sensor_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_prefix, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_range_min_value, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_range_max_value, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_normal_min_value, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_normal_max_value, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_pd_sensor_recorded_value_support,
      ett_rdm_pd_sensor_recorded_value_support, rdm_pd_sensor_recorded_value_support, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_description, tvb, offset, len-13, ENC_UTF_8);
    offset += len-13;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_sensor_value(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_sensor_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_sensor_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_value_pres, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_value_low, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_value_high, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_value_rec, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_manufacturer_label(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_manu_label, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_disc_unique_branch(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_DISCOVERY_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_disc_unique_branch_lb_uid, tvb, offset, 6, ENC_NA);
    offset += 6;
    proto_tree_add_item(tree, hf_rdm_pd_disc_unique_branch_ub_uid, tvb, offset, 6, ENC_NA);
    offset += 6;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_disc_mute(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_DISCOVERY_COMMAND_RESPONSE:
    proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_pd_disc_mute_control_field,
      ett_rdm_pd_disc_mute_control_field, rdm_pd_disc_mute_control_field, ENC_BIG_ENDIAN);
    offset += 2;
    if (len > 2) {
      rdm_add_uid_item(tree, hf_rdm_pd_disc_mute_binding_uid, tvb, &offset,
        hf_rdm_pd_disc_mute_binding_uid_manf, hf_rdm_pd_disc_mute_binding_uid_dev,
        hf_rdm_pd_disc_mute_binding_uid_dyn);
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_disc_un_mute(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_DISCOVERY_COMMAND_RESPONSE:
    proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_pd_disc_unmute_control_field,
      ett_rdm_pd_disc_unmute_control_field, rdm_pd_disc_unmute_control_field, ENC_BIG_ENDIAN);
    offset += 2;
    if (len > 2) {
      rdm_add_uid_item(tree, hf_rdm_pd_disc_unmute_binding_uid, tvb, &offset,
        hf_rdm_pd_disc_unmute_binding_uid_manf, hf_rdm_pd_disc_unmute_binding_uid_dev,
        hf_rdm_pd_disc_unmute_binding_uid_dyn);
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_proxied_devices(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 6) {
      rdm_add_uid_item(tree, hf_rdm_pd_proxied_devices_uid, tvb, &offset,
        hf_rdm_pd_proxied_devices_uid_manf, hf_rdm_pd_proxied_devices_uid_dev,
        hf_rdm_pd_proxied_devices_uid_dyn);
      len -= 6;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_proxied_device_count(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_proxied_device_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_proxied_device_list_change, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_comms_status(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_comms_status_short_msg, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_comms_status_len_mismatch, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_comms_status_csum_fail, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_test_data(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_test_data_pattern_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
  case RDM_CC_SET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_test_data_pattern_data, tvb, offset, len, ENC_NA);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_comms_status_nsc(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_pd_comms_status_nsc_supported_fields,
      ett_rdm_pd_comms_status_nsc_supported_fields, rdm_pd_comms_status_nsc_supported_fields, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_comms_status_nsc_csum, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_comms_status_nsc_packet_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_comms_status_nsc_slot_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_comms_status_nsc_slot_min, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_comms_status_nsc_slot_max, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_comms_status_nsc_error_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_status_messages(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_status_messages_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 9) {
      proto_tree_add_item(tree, hf_rdm_pd_status_messages_sub_device_id, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tree, hf_rdm_pd_status_messages_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(tree, hf_rdm_pd_status_messages_id, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tree, hf_rdm_pd_status_messages_data_value_1, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tree, hf_rdm_pd_status_messages_data_value_2, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      len -= 9;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_status_id_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_status_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_status_id_description, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_clear_status_id(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_, uint8_t cc _U_, uint8_t len _U_)
{
  return offset;
}

static unsigned
dissect_rdm_pd_sub_device_status_report_threshold(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_sub_device_status_report_threshold_status_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_queued_message_sensor_subscribe(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_sensor_subscribe_action, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    len -= 1;
    /* FALLTHROUGH */
  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 1) {
      proto_tree_add_item(tree, hf_rdm_pd_sensor_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      len -= 1;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_supported_parameters(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len, uint16_t device_manufacturer_id)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 2) {
      rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
      len -= 2;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_parameter_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len, uint16_t device_manufacturer_id)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
    proto_tree_add_item(tree, hf_rdm_pd_parameter_pdl_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_parameter_data_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_parameter_cmd_class, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_parameter_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_parameter_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_parameter_prefix, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_parameter_min_value, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_parameter_max_value, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_parameter_default_value, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_parameter_description, tvb, offset, len-20, ENC_UTF_8);
    offset += len-20;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_metadata_parameter_version(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_, uint16_t device_manufacturer_id)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
    proto_tree_add_item(tree, hf_rdm_pd_metadata_parameter_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_metadata_json(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len, uint16_t device_manufacturer_id)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    if (check_metadata_has_param(tvb, offset, (const uint8_t*)"{", 1)) {
      rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
      len -= 2;
    }
    proto_tree_add_item(tree, hf_rdm_pd_metadata_json, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_metadata_json_url(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len, uint16_t device_manufacturer_id)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_metadata_json_url, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_supported_parameters_enhanced(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len, uint16_t device_manufacturer_id)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 4) {
      rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
      proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_pd_supported_parameters_pid_support,
        ett_rdm_pd_supported_parameters_pid_support, rdm_pd_supported_parameters_pid_support, ENC_BIG_ENDIAN);
      offset += 2;
      len -= 4;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_controller_flag_support(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_pd_controller_flag_support_flags,
      ett_rdm_pd_controller_flag_support_flags, rdm_pd_controller_flag_support_flags, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_nack_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_nack_description_reason_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_nack_description_reason_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_nack_description_text, tvb, offset, len-2, ENC_UTF_8);
    offset += len-2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_packed_pid_sub(tvbuff_t *tvb, unsigned offset, packet_info* pinfo, proto_tree *tree, uint8_t cc, uint8_t len, uint16_t device_manufacturer_id)
{
  uint16_t param_id = 0;

  switch(cc) {
  case RDM_CC_GET_COMMAND:
    param_id = rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
    proto_tree_add_item(tree, hf_rdm_pd_packed_pid_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_packed_pid_sub_device, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_packed_pid_sub_device_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    if (len >= 4 && check_packed_format(tvb, offset+4, len-4)) {
      param_id = rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
      proto_tree_add_item(tree, hf_rdm_pd_packed_pid_index, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      len -= 4;
    }
    break;
  case RDM_CC_SET_COMMAND:
    param_id = rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
    proto_tree_add_item(tree, hf_rdm_pd_packed_pid_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    len -= 4;
    break;
  }

  if (cc == RDM_CC_GET_COMMAND_RESPONSE || cc == RDM_CC_SET_COMMAND) {
    while (len >= 3) {
      proto_tree_add_item(tree, hf_rdm_pd_packed_pid_sub_device, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      uint8_t param_len;
      proto_tree_add_item_ret_uint8(tree, hf_rdm_pd_packed_pid_data_len, tvb, offset, 1, ENC_BIG_ENDIAN, &param_len);
      offset += 1;
      len -= 3;

      /* Prevent recursion by disallowing nested packed messages (not actually a valid message)*/
      if (param_id == 0 || param_id == RDM_PARAM_ID_PACKED_PID_SUB || param_id == RDM_PARAM_ID_PACKED_PID_INDEX) {
        proto_tree_add_item(tree, hf_rdm_pd_packed_pid_data, tvb, offset, param_len, ENC_NA);
        offset += param_len;
      } else {
        proto_item* ti = proto_tree_add_item(tree, hf_rdm_pd_packed_pid_data_none, tvb, offset, param_len, ENC_NA);
        proto_tree* ti_tree = proto_item_add_subtree(ti, ett_rdm_packed_pid_data);

        dissect_rdm_mdb_param_data_no_packed(tvb, offset, pinfo, ti_tree, cc, param_id, param_len, device_manufacturer_id);
        offset += param_len;
      }
      len -= param_len;
    }
  }

  return offset;
}

static unsigned
dissect_rdm_pd_packed_pid_index(tvbuff_t *tvb, unsigned offset, packet_info* pinfo, proto_tree *tree, uint8_t cc, uint8_t len, uint16_t device_manufacturer_id)
{
  uint16_t param_id = 0;

  switch(cc) {
  case RDM_CC_GET_COMMAND:
    param_id = rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
    proto_tree_add_item(tree, hf_rdm_pd_packed_pid_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_packed_pid_index_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    if (len >= 2 && check_packed_format(tvb, offset+2, len-2)) {
      param_id = rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
      len -= 2;
    }
    break;
  case RDM_CC_SET_COMMAND:
    param_id = rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
    len -= 2;
    break;
  }

  if (cc == RDM_CC_GET_COMMAND_RESPONSE || cc == RDM_CC_SET_COMMAND) {
    while (len >= 3) {
      proto_tree_add_item(tree, hf_rdm_pd_packed_pid_index, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      uint8_t param_len;
      proto_tree_add_item_ret_uint8(tree, hf_rdm_pd_packed_pid_data_len, tvb, offset, 1, ENC_BIG_ENDIAN, &param_len);
      offset += 1;
      len -= 3;

      /* Prevent recursion by disallowing nested packed messages (not actually a valid message)*/
      if (param_id == 0 || param_id == RDM_PARAM_ID_PACKED_PID_SUB || param_id == RDM_PARAM_ID_PACKED_PID_INDEX) {
        proto_tree_add_item(tree, hf_rdm_pd_packed_pid_data, tvb, offset, param_len, ENC_NA);
        offset += param_len;
      } else {
        proto_item* ti = proto_tree_add_item(tree, hf_rdm_pd_packed_pid_data_none, tvb, offset, param_len, ENC_NA);
        proto_tree* ti_tree = proto_item_add_subtree(ti, ett_rdm_packed_pid_data);

        dissect_rdm_mdb_param_data_no_packed(tvb, offset, pinfo, ti_tree, cc, param_id, param_len, device_manufacturer_id);
        offset += param_len;
      }
      len -= param_len;
    }
  }

  return offset;
}

static unsigned
dissect_rdm_pd_enum_label(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len, uint16_t device_manufacturer_id)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
    proto_tree_add_item(tree, hf_rdm_pd_enum_label_index, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
    proto_tree_add_item(tree, hf_rdm_pd_enum_label_index, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_enum_label_max_index, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_enum_label_label, tvb, offset, len-10, ENC_UTF_8);
    offset += len-10;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_product_detail_id_list(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 2) {
      proto_tree_add_item(tree, hf_rdm_pd_product_detail_id, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      len -= 2;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_factory_defaults(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_factory_defaults, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_language_capabilities(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 2) {
      proto_tree_add_item(tree, hf_rdm_pd_language_code, tvb, offset, 2, ENC_UTF_8);
      offset += 2;
      len -= 2;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_language(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_language_code, tvb, offset, 2, ENC_UTF_8);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_software_version_label(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_software_version_label, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_boot_software_version_id(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_boot_software_version_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_boot_software_version_label(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_boot_software_version_label, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_manufacturer_url(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_manufacturer_url, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_product_url(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_product_url, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_firmware_url(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_firmware_url, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_serial_number(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_serial_number, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_device_info_offstage(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len, uint16_t device_manufacturer_id)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_info_offstage_root_personality, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_info_offstage_sub_device, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_info_offstage_sub_device_personality, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_info_offstage_root_personality, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_info_offstage_sub_device, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_info_offstage_sub_device_personality, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    offset = dissect_rdm_pd_device_info(tvb, offset, tree, cc, len, device_manufacturer_id);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dmx_personality(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_current, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_count, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dmx_personality_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_requested, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_requested, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_slots, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_text, tvb, offset, len-3, ENC_UTF_8);
    offset += len-3;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dmx_personality_id(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_requested, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_requested, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_id_major, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_pers_id_minor, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_slot_info(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  uint8_t slot_type;
  uint16_t slot_label_id;
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 5) {
      proto_tree_add_item(tree, hf_rdm_pd_slot_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item_ret_uint8(tree, hf_rdm_pd_slot_type, tvb, offset, 1, ENC_BIG_ENDIAN, &slot_type);
      offset += 1;
      slot_label_id = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
      /* Per the spec all secondary slots should use an offset, but in reality many don't so we only use as an offset
       *   if the value is lower then 512 (given devices generally have fewer than 512 dmx slots)
      */
      if (((RDM_SLOT_TYPE_SEC_FINE <= slot_type && slot_type <= RDM_SLOT_TYPE_SEC_QUANTUM_ROTATE) || slot_type == RDM_SLOT_TYPE_SEC_UNDEFINED) && slot_label_id <= 0x0100) {
        proto_tree_add_item(tree, hf_rdm_pd_slot_primary_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
      } else {
        proto_tree_add_item(tree, hf_rdm_pd_slot_label_id, tvb, offset, 2, ENC_BIG_ENDIAN);
      }
      offset += 2;
      len -= 5;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_slot_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_slot_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_slot_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_slot_description, tvb, offset, len-2, ENC_UTF_8);
    offset += len-2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_slot_value(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 3) {
      proto_tree_add_item(tree, hf_rdm_pd_slot_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tree, hf_rdm_pd_slot_value, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      len -= 3;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dmx_block_address(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_dmx_block_address_subdevice_footprint, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_block_address_base_dmx_address, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;

  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_dmx_block_address_base_dmx_address, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dmx_fail_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_dmx_fail_mode_scene_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_fail_mode_loss_of_signal_delay, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_fail_mode_hold_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_fail_mode_level, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dmx_startup_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_dmx_startup_mode_scene_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_startup_mode_loss_of_signal_delay, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_startup_mode_hold_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dmx_startup_mode_level, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_record_sensors(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_sensor_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_sensor_type_custom(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_sensor_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_sensor_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_type_label, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_sensor_unit_custom(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_sensor_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_sensor_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_sensor_unit_label, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dimmer_info(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_dimmer_info_minimum_level_lower_limit, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dimmer_info_minimum_level_upper_limit, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dimmer_info_maximum_level_lower_limit, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dimmer_info_maximum_level_upper_limit, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_dimmer_info_number_of_supported_curves, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_dimmer_info_levels_resolution, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_dimmer_info_minimum_level_split_levels_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_minimum_level(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_minimum_level_increasing, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_minimum_level_decreasing, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_minimum_level_on_below_minimum, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_maximum_level(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_maximum_level_level, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_curve(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_curve_curve, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_curve_number_of_curves, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_curve_curve, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_curve_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_curve_description_curve, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_curve_description_curve, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_curve_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_output_response_time(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_output_response_time_response_time, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_output_response_time_number_of_response_times, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_output_response_time_response_time, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_output_response_time_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_output_response_time_description_output_response_time, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_output_response_time_description_output_response_time, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_output_response_time_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_modulation_frequency(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_modulation_frequency_modulation_frequency, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_modulation_frequency_number_of_modulation_frequencies, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_modulation_frequency_modulation_frequency, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_modulation_frequency_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_modulation_frequency_description_modulation_frequency, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_modulation_frequency_description_modulation_frequency, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_modulation_frequency_description_hertz, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_modulation_frequency_description_text, tvb, offset, len-5, ENC_UTF_8);
    offset += len-5;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_lamp_state(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_lamp_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_lamp_on_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_lamp_on_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_device_power_cycles(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_device_power_cycles, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_burn_in(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_burn_in, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_display_invert(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_display_invert, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_display_level(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_display_level, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_pan_invert(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_pan_invert, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_tilt_invert(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_tilt_invert, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_pan_tilt_swap(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_tilt_swap, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_real_time_clock(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_real_time_clock_year, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_real_time_clock_month, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_real_time_clock_day, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_real_time_clock_hour, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_real_time_clock_minute, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_real_time_clock_second, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_lock_pin(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_lock_pin_pin_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;

  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_lock_pin_new_pin_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_lock_pin_pin_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_lock_state(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_lock_state_lock_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_lock_state_number_of_lock_states, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_lock_state_pin_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_lock_state_lock_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_lock_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_lock_state_description_lock_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_lock_state_description_lock_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_lock_state_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_shipping_lock(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_shipping_lock_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_list_tags(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  unsigned s_len;

  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_tag_list, tvb, offset, len, ENC_NA);
    while (len > 0) {
      proto_tree_add_item_ret_length(tree, hf_rdm_pd_tag_null, tvb, offset, -1, ENC_ASCII, &s_len);
      offset += s_len;
      len -= s_len;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_add_tag(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_tag, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_remove_tag(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_tag, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_check_tag(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_tag, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_tag_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_clear_tags(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_, uint8_t cc _U_)
{
  return offset;
}

static unsigned
dissect_rdm_pd_device_unit_number(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_device_unit_number, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_list_interfaces(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 6) {
      proto_tree_add_item(tree, hf_rdm_pd_list_interfaces_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_rdm_pd_list_interfaces_interface_hardware_type, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      len -= 6;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_interface_label(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_interface_label_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_interface_label_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_interface_label_label, tvb, offset, len-4, ENC_UTF_8);
    offset += len-4;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_hardware_address_type1(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_hardware_address_type1_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_hardware_address_type1_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_hardware_address_type1_hardware_address, tvb, offset, 6, ENC_NA);
    offset += 6;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dhcp_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_dhcp_mode_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_dhcp_mode_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_dhcp_mode_enabled, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_zeroconf_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_zeroconf_mode_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_zeroconf_mode_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_zeroconf_mode_enabled, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_current_address(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_current_address_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_current_address_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_current_address_ipv4_address, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_current_address_netmask, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_current_address_dhcp_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_static_address(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_static_address_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_static_address_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_static_address_ipv4_address, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_static_address_netmask, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_interface_renew_dhcp(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_interface_renew_dhcp_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_interface_release_dhcp(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_interface_release_dhcp_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_interface_apply_configuration(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_interface_apply_configuration_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_ipv4_default_route(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_ipv4_default_route_interface_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_ipv4_default_route_ipv4_default_route, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dns_ipv4_name_server(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_dns_ipv4_name_server_index, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_dns_ipv4_name_server_index, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_dns_ipv4_name_server_address, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dns_hostname(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_dns_hostname, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dns_domain_name(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_dns_domain_name, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_ftc_initiate(tvbuff_t *tvb, unsigned offset, packet_info* pinfo, proto_tree *tree, uint8_t cc)
{
  unsigned start_offset = offset;
  switch (cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_ftc_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_file_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_version_major, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_version_minor, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_pd_ftc_transfer_flags,
      ett_rdm_pd_ftc_transfer_flags, rdm_pd_ftc_transfer_flags, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_ftc_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_file_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_version_major, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_version_minor, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_pd_ftc_transfer_flags,
      ett_rdm_pd_ftc_transfer_flags, rdm_pd_ftc_transfer_flags, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_file_size, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_data, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_file_crc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    uint16_t crc_calc = crc16_rdm_tvb_offset(tvb, start_offset, offset-start_offset);
    proto_tree_add_checksum(tree, tvb, offset, hf_rdm_pd_ftc_packet_crc, hf_rdm_pd_ftc_packet_crc_status,
      &ei_rdm_ftc_crc, pinfo, crc_calc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND_RESPONSE:
    rdm_add_ftc_response_status_data(tree, tvb, &offset, RDM_PARAM_ID_FTC_INITIATE);
    proto_tree_add_item(tree, hf_rdm_pd_ftc_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_file_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_version_major, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_version_minor, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_file_size, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_pd_ftc_capabilities,
        ett_rdm_pd_ftc_capabilities, rdm_pd_ftc_capabilities, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_data_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_transfer_block_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_initial_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_inter_packet_delay, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_accumulated_byte_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_accumulated_byte_delay, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_validation_delay, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_max_inter_packet_delay, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_ftc_transfer_upload(tvbuff_t *tvb, unsigned offset, packet_info* pinfo, proto_tree *tree, uint8_t cc, uint8_t len)
{
  unsigned start_offset = offset;
  switch (cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_ftc_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_ftc_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_data_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_data, tvb, offset, len-7, ENC_NA);
    offset += len-7;
    uint16_t crc_calc = crc16_rdm_tvb_offset(tvb, start_offset, offset-start_offset);
    proto_tree_add_checksum(tree, tvb, offset, hf_rdm_pd_ftc_packet_crc, hf_rdm_pd_ftc_packet_crc_status,
      &ei_rdm_ftc_crc, pinfo, crc_calc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND_RESPONSE:
    rdm_add_ftc_response_status_data(tree, tvb, &offset, RDM_PARAM_ID_FTC_TRANSFER_UPLOAD);
    proto_tree_add_item(tree, hf_rdm_pd_ftc_data_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_ftc_commit(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch (cc) {
  case RDM_CC_GET_COMMAND:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_ftc_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_pd_ftc_commit_flags,
      ett_rdm_pd_ftc_commit_flags, rdm_pd_ftc_commit_flags, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND_RESPONSE:
    rdm_add_ftc_response_status_data(tree, tvb, &offset, RDM_PARAM_ID_FTC_COMMIT);
    proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_pd_ftc_commit_flags,
      ett_rdm_pd_ftc_commit_flags, rdm_pd_ftc_commit_flags, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_calculated_file_crc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    rdm_add_uid_item(tree, hf_rdm_pd_ftc_expected_uid, tvb, &offset,
      hf_rdm_pd_ftc_expected_uid_manf, hf_rdm_pd_ftc_expected_uid_dev,
      hf_rdm_pd_ftc_expected_uid_dyn);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_ftc_cancel(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch (cc) {
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_ftc_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_SET_COMMAND_RESPONSE:
    rdm_add_ftc_response_status_data(tree, tvb, &offset, RDM_PARAM_ID_FTC_CANCEL);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_ftc_filelist(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch (cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 43) {
      proto_tree_add_item(tree, hf_rdm_pd_ftc_file_id, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_pd_ftc_capabilities,
        ett_rdm_pd_ftc_capabilities, rdm_pd_ftc_capabilities, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_rdm_pd_ftc_file_description, tvb, offset, 32, ENC_UTF_8);
      offset += 32;
      proto_tree_add_item(tree, hf_rdm_pd_ftc_file_suffix, tvb, offset, 6, ENC_UTF_8);
      offset += 6;
      len -= 43;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_ftc_transfer_download(tvbuff_t *tvb, unsigned offset, packet_info* pinfo, proto_tree *tree, uint8_t cc, uint8_t len)
{
  unsigned start_offset = offset;
  switch (cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_ftc_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_command, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_data_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_add_ftc_response_status_data(tree, tvb, &offset, RDM_PARAM_ID_FTC_TRANSFER_DOWNLOAD);
    proto_tree_add_item(tree, hf_rdm_pd_ftc_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_ftc_data, tvb, offset, len-8, ENC_NA);
    offset += len-8;
    uint16_t crc_calc = crc16_rdm_tvb_offset(tvb, start_offset, offset-start_offset);
    proto_tree_add_checksum(tree, tvb, offset, hf_rdm_pd_ftc_packet_crc, hf_rdm_pd_ftc_packet_crc_status,
      &ei_rdm_ftc_crc, pinfo, crc_calc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_identify_device(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_identify_device, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_identify_device_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_reset_device(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_reset_device, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_power_state(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_power_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_perform_selftest(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_selftest_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_selftest_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_self_test_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_selftest_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_selftest_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_selftest_description, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_self_test_enhanced(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len, uint16_t device_manufacturer_id)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    /* Check for the first packet */
    if (len % 6 == 2) {
      rdm_add_param_id(tree, tvb, &offset, device_manufacturer_id);
      len -= 2;
    }
    while (len >= 6) {
      proto_tree_add_item(tree, hf_rdm_pd_selftest_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(tree, hf_rdm_pd_selftest_status, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_pd_selftest_capability,
        ett_rdm_pd_selftest_capability, rdm_pd_selftest_capability, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tree, hf_rdm_pd_selftest_result_code, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      len -= 6;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_capture_preset(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_capture_preset_scene_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_capture_preset_up_fade_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_capture_preset_down_fade_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_capture_preset_wait_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_preset_playback(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_preset_playback_mode, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_playback_level, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_identify_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_identify_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_preset_info(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_level_field_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_preset_sequence_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_split_times_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_dmx_fail_infinite_delay_time_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_dmx_fail_infinite_hold_time_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_start_up_infinite_hold_time_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_maximum_scene_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_minimum_preset_fade_time_supported, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_maximum_preset_fade_time_supported, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_minimum_preset_wait_time_supported, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_maximum_preset_wait_time_supported, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_minimum_dmx_fail_delay_time_supported, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_maximum_dmx_fail_delay_time_supported, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_minimum_dmx_fail_hold_time_supported, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_maximum_dmx_fail_hold_time_supported, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_minimum_start_up_delay_time_supported, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_maximum_start_up_delay_time_supported, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_minimum_start_up_hold_time_supported, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_info_maximum_start_up_hold_time_supported, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_preset_status(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_preset_status_scene_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_preset_status_scene_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_status_up_fade_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_status_down_fade_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_status_wait_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_status_programmed, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_preset_status_scene_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_status_up_fade_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_status_down_fade_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_status_wait_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_preset_status_clear_preset, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_preset_mergemode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_preset_mergemode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_power_on_self_test(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_power_on_self_test, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_identify_timeout(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_identify_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_power_off_ready(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_power_off_ready, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_list(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    /* Check for the first packet */
    if (len % 3 == 1 && len >= 4) {
      proto_tree_add_item(tree, hf_rdm_pd_endpoint_list_change_number, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      len -= 4;
    }
    while (len >= 3) {
      proto_tree_add_item(tree, hf_rdm_pd_endpoint_list_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tree, hf_rdm_pd_endpoint_list_endpoint_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      len -= 3;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_list_change(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_list_change_change_number, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_identify_endpoint(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
  case RDM_CC_SET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_identify_endpoint_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_identify_endpoint_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_identify_endpoint_identify_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_to_universe(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
  case RDM_CC_SET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_to_universe_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_to_universe_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_to_universe_universe_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
  case RDM_CC_SET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_mode_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_mode_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_mode_endpoint_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_label(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
  case RDM_CC_SET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_label_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_label_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_label_label, tvb, offset, len-2, ENC_UTF_8);
    offset += len-2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_rdm_traffic_enable(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_rdm_traffic_enable_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_rdm_traffic_enable_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_rdm_traffic_enable_rdm_enabled, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_discovery_state(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
  case RDM_CC_SET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_discovery_state_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_discovery_state_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_discovery_state_device_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_discovery_state_discovery_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_discovery_state_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_discovery_state_discovery_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_background_discovery(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
  case RDM_CC_SET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_background_discovery_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_background_discovery_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_background_discovery_enabled, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_timing(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
  case RDM_CC_SET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_timing_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_timing_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_timing_setting, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_timing_number_of_settings, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_timing_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_timing_setting, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_timing_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_timing_description_setting, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_timing_description_setting, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_timing_description_description, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_responders(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_responders_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    /* Note that in the case of ACK_OVERFLOW, we can't tell if this is a PID or a UID
     *     this applies to every response other than the initial one,
     *     regardless of if that response status is ACK or ACK_OVERFLOW
     */
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_responders_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_responders_change_number, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    len -= 6;
    while (len >= 6) {
      rdm_add_uid_item(tree, hf_rdm_pd_endpoint_responders_uid, tvb, &offset,
        hf_rdm_pd_endpoint_responders_uid_manf, hf_rdm_pd_endpoint_responders_uid_dev,
        hf_rdm_pd_endpoint_responders_uid_dyn);
      len -= 6;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_responder_list_change(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_responder_list_change_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_responder_list_change_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_endpoint_responder_list_change_change_number, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_binding_control_fields(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_binding_control_fields_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    rdm_add_uid_item(tree, hf_rdm_pd_binding_control_fields_uid, tvb, &offset,
      hf_rdm_pd_binding_control_fields_uid_manf, hf_rdm_pd_binding_control_fields_uid_dev,
      hf_rdm_pd_binding_control_fields_uid_dyn);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_binding_control_fields_endpoint_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    rdm_add_uid_item(tree, hf_rdm_pd_binding_control_fields_uid, tvb, &offset,
      hf_rdm_pd_binding_control_fields_uid_manf, hf_rdm_pd_binding_control_fields_uid_dev,
      hf_rdm_pd_binding_control_fields_uid_dyn);
    proto_tree_add_item(tree, hf_rdm_pd_binding_control_fields_control_field, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    rdm_add_uid_item(tree, hf_rdm_pd_binding_control_fields_binding_uid, tvb, &offset,
      hf_rdm_pd_binding_control_fields_binding_uid_manf, hf_rdm_pd_binding_control_fields_binding_uid_dev,
      hf_rdm_pd_binding_control_fields_binding_uid_dyn);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_background_queued_status_policy(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_background_queued_status_policy_current_policy, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_background_queued_status_policy_number_of_policies, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_background_queued_status_policy_current_policy, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_background_queued_status_policy_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_background_queued_status_policy_description_policy, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rdm_pd_background_queued_status_policy_description_policy, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_background_queued_status_policy_description_description, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_component_scope(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_component_scope_scope_slot, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_component_scope_scope_slot, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_rdm_pd_component_scope_scope_string, tvb, offset, 63, ENC_UTF_8);
    offset += 63;
    proto_tree_add_item(tree, hf_rdm_pd_component_scope_scope_static_config_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rdm_pd_component_scope_scope_static_ipv4_address, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_rdm_pd_component_scope_scope_static_ipv6_address, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_rdm_pd_component_scope_scope_static_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_search_domain(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_search_domain_dns_domain_name, tvb, offset, len, ENC_UTF_8);
    offset += len;
    break;
  }
  return offset;
}

static unsigned
dissect_rdm_pd_tcp_comms_status(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 87) {
      proto_tree_add_item(tree, hf_rdm_pd_tcp_comms_status_scope_string, tvb, offset, 63, ENC_UTF_8);
      offset += 63;
      proto_tree_add_item(tree, hf_rdm_pd_tcp_comms_status_broker_ipv4_address, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_rdm_pd_tcp_comms_status_broker_ipv6_address, tvb, offset, 16, ENC_NA);
      offset += 16;
      proto_tree_add_item(tree, hf_rdm_pd_tcp_comms_status_broker_port, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tree, hf_rdm_pd_tcp_comms_status_unhealthy_tcp_events, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      len -= 87;
    }
    break;
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rdm_pd_tcp_comms_status_scope_string, tvb, offset, 63, ENC_UTF_8);
    offset += 63;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_broker_status(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_rem_pd_broker_status_set_allowed, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rem_pd_broker_status_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_rem_pd_broker_status_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}


static unsigned
dissect_manufacturer_specific_pid(tvbuff_t *tvb, unsigned offset, packet_info *pinfo, proto_tree *tree, uint8_t cc, uint16_t param_id, uint8_t pdl, uint16_t device_manufacturer_id)
{
  rdm_pid_info info = {
    param_id,
    cc
  };

  unsigned int consumed = dissector_try_uint_with_data(
    rdm_manf_dissector_table,
    device_manufacturer_id,
    tvb_new_subset_length(tvb, offset, pdl),
    pinfo,
    tree,
    false,
    &info
  );
  offset += consumed;

  if (consumed < pdl) {
    proto_tree_add_item(tree, hf_rdm_parameter_data_raw, tvb, offset, pdl - consumed, ENC_NA);
    offset += pdl;
  }

  return offset;
}

/* Dissects data for any PID other than packed ones. Prevents recursive calls */
static unsigned
dissect_rdm_mdb_param_data_no_packed(tvbuff_t *tvb, unsigned offset, packet_info *pinfo, proto_tree *tree, uint8_t cc, uint16_t param_id, uint8_t pdl, uint16_t device_manufacturer_id)
{
  if (param_id >= 0x8000) {
    offset = dissect_manufacturer_specific_pid(tvb, offset, pinfo, tree, cc, param_id, pdl, device_manufacturer_id);
  } else {
    switch(param_id) {
    case RDM_PARAM_ID_SENSOR_VALUE:
      offset = dissect_rdm_pd_sensor_value(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_QUEUED_MESSAGE:
      offset = dissect_rdm_pd_queued_message(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DMX_START_ADDRESS:
      offset = dissect_rdm_pd_dmx_start_address(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DEVICE_INFO:
      offset = dissect_rdm_pd_device_info(tvb, offset, tree, cc, pdl, device_manufacturer_id);
      break;

    case RDM_PARAM_ID_DEVICE_MODEL_DESCRIPTION:
      offset = dissect_rdm_pd_device_model_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DEVICE_LABEL:
      offset = dissect_rdm_pd_device_label(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DEVICE_HOURS:
      offset = dissect_rdm_pd_device_hours(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_LAMP_HOURS:
      offset = dissect_rdm_pd_lamp_hours(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_LAMP_STRIKES:
      offset = dissect_rdm_pd_lamp_strikes(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_SENSOR_DEFINITION:
      offset = dissect_rdm_pd_sensor_definition(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_MANUFACTURER_LABEL:
      offset = dissect_rdm_pd_manufacturer_label(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DISC_UNIQUE_BRANCH:
      offset = dissect_rdm_pd_disc_unique_branch(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DISC_MUTE:
      offset = dissect_rdm_pd_disc_mute(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DISC_UN_MUTE:
      offset = dissect_rdm_pd_disc_un_mute(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_PROXIED_DEVICES:
      offset = dissect_rdm_pd_proxied_devices(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_PROXIED_DEVICE_COUNT:
      offset = dissect_rdm_pd_proxied_device_count(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_COMMS_STATUS:
      offset = dissect_rdm_pd_comms_status(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_TEST_DATA:
      offset = dissect_rdm_pd_test_data(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_COMMS_STATUS_NSC:
      offset = dissect_rdm_pd_comms_status_nsc(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_STATUS_MESSAGES:
      offset = dissect_rdm_pd_status_messages(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_STATUS_ID_DESCRIPTION:
      offset = dissect_rdm_pd_status_id_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_CLEAR_STATUS_ID:
      offset = dissect_rdm_pd_clear_status_id(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_SUB_DEVICE_STATUS_REPORT_THRESHOLD:
      offset = dissect_rdm_pd_sub_device_status_report_threshold(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_QUEUED_MESSAGE_SENSOR_SUBSCRIBE:
      offset = dissect_rdm_pd_queued_message_sensor_subscribe(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_SUPPORTED_PARAMETERS:
      offset = dissect_rdm_pd_supported_parameters(tvb, offset, tree, cc, pdl, device_manufacturer_id);
      break;

    case RDM_PARAM_ID_PARAMETER_DESCRIPTION:
      offset = dissect_rdm_pd_parameter_description(tvb, offset, tree, cc, pdl, device_manufacturer_id);
      break;

    case RDM_PARAM_ID_METADATA_PARAMETER_VERSION:
      offset = dissect_rdm_pd_metadata_parameter_version(tvb, offset, tree, cc, pdl, device_manufacturer_id);
      break;

    case RDM_PARAM_ID_METADATA_JSON:
      offset = dissect_rdm_pd_metadata_json(tvb, offset, tree, cc, pdl, device_manufacturer_id);
      break;

    case RDM_PARAM_ID_METADATA_JSON_URL:
      offset = dissect_rdm_pd_metadata_json_url(tvb, offset, tree, cc, pdl, device_manufacturer_id);
      break;

    case RDM_PARAM_ID_SUPPORTED_PARAMETERS_ENHANCED:
      offset = dissect_rdm_pd_supported_parameters_enhanced(tvb, offset, tree, cc, pdl, device_manufacturer_id);
      break;

    case RDM_PARAM_ID_CONTROLLER_FLAG_SUPPORT:
      offset = dissect_rdm_pd_controller_flag_support(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_NACK_DESCRIPTION:
      offset = dissect_rdm_pd_nack_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_ENUM_LABEL:
      offset = dissect_rdm_pd_enum_label(tvb, offset, tree, cc, pdl, device_manufacturer_id);
      break;

    case RDM_PARAM_ID_PRODUCT_DETAIL_ID_LIST:
      offset = dissect_rdm_pd_product_detail_id_list(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_FACTORY_DEFAULTS:
      offset = dissect_rdm_pd_factory_defaults(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_LANGUAGE_CAPABILITIES:
      offset = dissect_rdm_pd_language_capabilities(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_LANGUAGE:
      offset = dissect_rdm_pd_language(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_SOFTWARE_VERSION_LABEL:
      offset = dissect_rdm_pd_software_version_label(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_BOOT_SOFTWARE_VERSION_ID:
      offset = dissect_rdm_pd_boot_software_version_id(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_BOOT_SOFTWARE_VERSION_LABEL:
      offset = dissect_rdm_pd_boot_software_version_label(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_MANUFACTURER_URL:
      offset = dissect_rdm_pd_manufacturer_url(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_PRODUCT_URL:
      offset = dissect_rdm_pd_product_url(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_FIRMWARE_URL:
      offset = dissect_rdm_pd_firmware_url(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_SERIAL_NUMBER:
      offset = dissect_rdm_pd_serial_number(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DEVICE_INFO_OFFSTAGE:
      offset = dissect_rdm_pd_device_info_offstage(tvb, offset, tree, cc, pdl, device_manufacturer_id);
      break;

    case RDM_PARAM_ID_DMX_PERSONALITY:
      offset = dissect_rdm_pd_dmx_personality(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DMX_PERSONALITY_DESCRIPTION:
      offset = dissect_rdm_pd_dmx_personality_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DMX_PERSONALITY_ID:
      offset = dissect_rdm_pd_dmx_personality_id(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_SLOT_INFO:
      offset = dissect_rdm_pd_slot_info(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_SLOT_DESCRIPTION:
      offset = dissect_rdm_pd_slot_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DEFAULT_SLOT_VALUE:
      offset = dissect_rdm_pd_slot_value(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DMX_BLOCK_ADDRESS:
      offset = dissect_rdm_pd_dmx_block_address(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_DMX_FAIL_MODE:
      offset = dissect_rdm_pd_dmx_fail_mode(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_DMX_STARTUP_MODE:
      offset = dissect_rdm_pd_dmx_startup_mode(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_RECORD_SENSORS:
      offset = dissect_rdm_pd_record_sensors(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_SENSOR_TYPE_CUSTOM:
      offset = dissect_rdm_pd_sensor_type_custom(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_SENSOR_UNIT_CUSTOM:
      offset = dissect_rdm_pd_sensor_unit_custom(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DIMMER_INFO:
      offset = dissect_rdm_pd_dimmer_info(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_MINIMUM_LEVEL:
      offset = dissect_rdm_pd_minimum_level(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_MAXIMUM_LEVEL:
      offset = dissect_rdm_pd_maximum_level(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_CURVE:
      offset = dissect_rdm_pd_curve(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_CURVE_DESCRIPTION:
      offset = dissect_rdm_pd_curve_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_OUTPUT_RESPONSE_TIME:
      offset = dissect_rdm_pd_output_response_time(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_OUTPUT_RESPONSE_TIME_DESCRIPTION:
      offset = dissect_rdm_pd_output_response_time_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_MODULATION_FREQUENCY:
      offset = dissect_rdm_pd_modulation_frequency(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_MODULATION_FREQUENCY_DESCRIPTION:
      offset = dissect_rdm_pd_modulation_frequency_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_LAMP_STATE:
      offset = dissect_rdm_pd_lamp_state(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_LAMP_ON_MODE:
      offset = dissect_rdm_pd_lamp_on_mode(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DEVICE_POWER_CYCLES:
      offset = dissect_rdm_pd_device_power_cycles(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_BURN_IN:
      offset = dissect_rdm_pd_burn_in(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_DISPLAY_INVERT:
      offset = dissect_rdm_pd_display_invert(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DISPLAY_LEVEL:
      offset = dissect_rdm_pd_display_level(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_PAN_INVERT:
      offset = dissect_rdm_pd_pan_invert(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_TILT_INVERT:
      offset = dissect_rdm_pd_tilt_invert(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_PAN_TILT_SWAP:
      offset = dissect_rdm_pd_pan_tilt_swap(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_REAL_TIME_CLOCK:
      offset = dissect_rdm_pd_real_time_clock(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_LOCK_PIN:
      offset = dissect_rdm_pd_lock_pin(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_LOCK_STATE:
      offset = dissect_rdm_pd_lock_state(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_LOCK_STATE_DESCRIPTION:
      offset = dissect_rdm_pd_lock_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_SHIPPING_LOCK:
      offset = dissect_rdm_pd_shipping_lock(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_LIST_TAGS:
      offset = dissect_rdm_pd_list_tags(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_ADD_TAG:
      offset = dissect_rdm_pd_add_tag(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_REMOVE_TAG:
      offset = dissect_rdm_pd_remove_tag(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_CHECK_TAG:
      offset = dissect_rdm_pd_check_tag(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_CLEAR_TAGS:
      offset = dissect_rdm_pd_clear_tags(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_DEVICE_UNIT_NUMBER:
      offset = dissect_rdm_pd_device_unit_number(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_LIST_INTERFACES:
      offset = dissect_rdm_pd_list_interfaces(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_INTERFACE_LABEL:
      offset = dissect_rdm_pd_interface_label(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_INTERFACE_HARDWARE_ADDRESS_TYPE1:
      offset = dissect_rdm_pd_hardware_address_type1(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_IPV4_DHCP_MODE:
      offset = dissect_rdm_pd_dhcp_mode(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_IPV4_ZEROCONF_MODE:
      offset = dissect_rdm_pd_zeroconf_mode(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_IPV4_CURRENT_ADDRESS:
      offset = dissect_rdm_pd_current_address(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_IPV4_STATIC_ADDRESS:
      offset = dissect_rdm_pd_static_address(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_INTERFACE_RENEW_DHCP:
      offset = dissect_rdm_pd_interface_renew_dhcp(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_INTERFACE_RELEASE_DHCP:
      offset = dissect_rdm_pd_interface_release_dhcp(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_INTERFACE_APPLY_CONFIGURATION:
      offset = dissect_rdm_pd_interface_apply_configuration(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_IPV4_DEFAULT_ROUTE:
      offset = dissect_rdm_pd_ipv4_default_route(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_DNS_IPV4_NAME_SERVER:
      offset = dissect_rdm_pd_dns_ipv4_name_server(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_DNS_HOSTNAME:
      offset = dissect_rdm_pd_dns_hostname(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DNS_DOMAIN_NAME:
      offset = dissect_rdm_pd_dns_domain_name(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_FTC_INITIATE:
      offset = dissect_rdm_pd_ftc_initiate(tvb, offset, pinfo, tree, cc);
      break;

    case RDM_PARAM_ID_FTC_TRANSFER_UPLOAD:
      offset = dissect_rdm_pd_ftc_transfer_upload(tvb, offset, pinfo, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_FTC_COMMIT:
      offset = dissect_rdm_pd_ftc_commit(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_FTC_CANCEL:
      offset = dissect_rdm_pd_ftc_cancel(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_FTC_FILELIST:
      offset = dissect_rdm_pd_ftc_filelist(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_FTC_TRANSFER_DOWNLOAD:
      offset = dissect_rdm_pd_ftc_transfer_download(tvb, offset, pinfo, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_IDENTIFY_DEVICE:
      offset = dissect_rdm_pd_identify_device(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_RESET_DEVICE:
      offset = dissect_rdm_pd_reset_device(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_POWER_STATE:
      offset = dissect_rdm_pd_power_state(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_PERFORM_SELFTEST:
      offset = dissect_rdm_pd_perform_selftest(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_SELF_TEST_DESCRIPTION:
      offset = dissect_rdm_pd_self_test_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_SELF_TEST_ENHANCED:
      offset = dissect_rdm_pd_self_test_enhanced(tvb, offset, tree, cc, pdl, device_manufacturer_id);
      break;

    case RDM_PARAM_ID_CAPTURE_PRESET:
      offset = dissect_rdm_pd_capture_preset(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_PRESET_PLAYBACK:
      offset = dissect_rdm_pd_preset_playback(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_IDENTIFY_MODE:
      offset = dissect_rdm_pd_identify_mode(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_PRESET_INFO:
      offset = dissect_rdm_pd_preset_info(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_PRESET_STATUS:
      offset = dissect_rdm_pd_preset_status(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_PRESET_MERGEMODE:
      offset = dissect_rdm_pd_preset_mergemode(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_POWER_ON_SELF_TEST:
      offset = dissect_rdm_pd_power_on_self_test(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_IDENTIFY_TIMEOUT:
      offset = dissect_rdm_pd_identify_timeout(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_POWER_OFF_READY:
      offset = dissect_rdm_pd_power_off_ready(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_ENDPOINT_LIST:
      offset = dissect_rdm_pd_endpoint_list(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_ENDPOINT_LIST_CHANGE:
      offset = dissect_rdm_pd_endpoint_list_change(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_IDENTIFY_ENDPOINT:
      offset = dissect_rdm_pd_identify_endpoint(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_ENDPOINT_TO_UNIVERSE:
      offset = dissect_rdm_pd_endpoint_to_universe(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_ENDPOINT_MODE:
      offset = dissect_rdm_pd_endpoint_mode(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_ENDPOINT_LABEL:
      offset = dissect_rdm_pd_endpoint_label(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_RDM_TRAFFIC_ENABLE:
      offset = dissect_rdm_pd_rdm_traffic_enable(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_DISCOVERY_STATE:
      offset = dissect_rdm_pd_discovery_state(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_BACKGROUND_DISCOVERY:
      offset = dissect_rdm_pd_background_discovery(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_ENDPOINT_TIMING:
      offset = dissect_rdm_pd_endpoint_timing(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_ENDPOINT_TIMING_DESCRIPTION:
      offset = dissect_rdm_pd_endpoint_timing_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_ENDPOINT_RESPONDERS:
      offset = dissect_rdm_pd_endpoint_responders(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_ENDPOINT_RESPONDER_LIST_CHANGE:
      offset = dissect_rdm_pd_endpoint_responder_list_change(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_BINDING_CONTROL_FIELDS:
      offset = dissect_rdm_pd_binding_control_fields(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_BACKGROUND_QUEUED_STATUS_POLICY:
      offset = dissect_rdm_pd_background_queued_status_policy(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_BACKGROUND_QUEUED_STATUS_POLICY_DESCRIPTION:
      offset = dissect_rdm_pd_background_queued_status_policy_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_COMPONENT_SCOPE:
      offset = dissect_rdm_pd_component_scope(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_SEARCH_DOMAIN:
      offset = dissect_rdm_pd_search_domain(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_TCP_COMMS_STATUS:
      offset = dissect_rdm_pd_tcp_comms_status(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_BROKER_STATUS:
      offset = dissect_rdm_pd_broker_status(tvb, offset, tree, cc);
      break;

    default:
      proto_tree_add_item(tree, hf_rdm_parameter_data_raw, tvb,
        offset, pdl, ENC_NA);
      offset += pdl;
      break;
    }
  }

  return offset;
}

static unsigned
dissect_rdm_mdb_param_data(tvbuff_t *tvb, unsigned offset, packet_info *pinfo, proto_tree *tree, uint8_t cc, uint16_t param_id, uint8_t pdl, uint16_t device_manufacturer_id)
{
  switch(param_id) {
  case RDM_PARAM_ID_PACKED_PID_SUB:
    offset = dissect_rdm_pd_packed_pid_sub(tvb, offset, pinfo, tree, cc, pdl, device_manufacturer_id);
    break;
  case RDM_PARAM_ID_PACKED_PID_INDEX:
    offset = dissect_rdm_pd_packed_pid_index(tvb, offset, pinfo, tree, cc, pdl, device_manufacturer_id);
    break;
  default:
    offset = dissect_rdm_mdb_param_data_no_packed(tvb, offset, pinfo, tree, cc, param_id, pdl, device_manufacturer_id);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_ack_overflow(tvbuff_t *tvb, unsigned offset, packet_info* pinfo, proto_tree *tree, uint8_t cc, uint16_t param_id, uint8_t pdl, uint16_t device_manufacturer_id)
{
  /* handle known ACK_OVERFLOW pids,
   * where we know the function has suitable logic to handle partly formed packets
  */
  if (pdl > 0 && cc == RDM_CC_GET_COMMAND_RESPONSE) {
    switch(param_id) {
    /* E1.20 */
    case RDM_PARAM_ID_PROXIED_DEVICES:
    case RDM_PARAM_ID_STATUS_MESSAGES:
    case RDM_PARAM_ID_QUEUED_MESSAGE_SENSOR_SUBSCRIBE:
    case RDM_PARAM_ID_SUPPORTED_PARAMETERS:
    case RDM_PARAM_ID_SUPPORTED_PARAMETERS_ENHANCED:
    case RDM_PARAM_ID_PACKED_PID_SUB: /* Has header. Issues */
    case RDM_PARAM_ID_PACKED_PID_INDEX: /* Has header. Issues */
    case RDM_PARAM_ID_PRODUCT_DETAIL_ID_LIST:
    case RDM_PARAM_ID_LANGUAGE_CAPABILITIES:
    case RDM_PARAM_ID_SLOT_INFO:
    case RDM_PARAM_ID_DEFAULT_SLOT_VALUE:
    case RDM_PARAM_ID_SELF_TEST_ENHANCED: /* Has header */
    /* E1.37-2 */
    case RDM_PARAM_ID_LIST_INTERFACES:
    /* E1.37-7 */
    case RDM_PARAM_ID_ENDPOINT_LIST: /* Has header */
    case RDM_PARAM_ID_ENDPOINT_RESPONDERS: /* Has header. Issues */
    case RDM_PARAM_ID_TCP_COMMS_STATUS:
    /* E1.37-5 */
    case RDM_PARAM_ID_MANUFACTURER_URL:
    case RDM_PARAM_ID_PRODUCT_URL:
    case RDM_PARAM_ID_FIRMWARE_URL:
    case RDM_PARAM_ID_TEST_DATA:
    case RDM_PARAM_ID_LIST_TAGS:
    case RDM_PARAM_ID_METADATA_JSON:
    case RDM_PARAM_ID_METADATA_JSON_URL:
      return dissect_rdm_mdb_param_data(tvb, offset, pinfo, tree, cc, param_id, pdl, device_manufacturer_id);
    }
  }

  if (pdl > 0) {
    switch(cc) {
    case RDM_CC_GET_COMMAND_RESPONSE:
    case RDM_CC_SET_COMMAND_RESPONSE:
      proto_tree_add_item(tree, hf_rdm_pd_ack_overflow_raw_data, tvb, offset, pdl, ENC_NA);
      offset += pdl;
      break;
    }
  }

  return offset;
}

static unsigned
dissect_rdm_pd_ack_timer(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint16_t param_id _U_, uint8_t pdl)
{
  if (pdl == 2) {
    switch(cc) {
    case RDM_CC_GET_COMMAND_RESPONSE:
    case RDM_CC_SET_COMMAND_RESPONSE:
      proto_tree_add_item(tree, hf_rdm_pd_ack_timer_estimated_response_time, tvb,
        offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      break;
    }
  }
  return offset;
}

static unsigned
dissect_rdm_pd_ack_timer_hi_res(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint16_t param_id _U_, uint8_t pdl)
{
  if (pdl == 2) {
    switch(cc) {
    case RDM_CC_GET_COMMAND_RESPONSE:
    case RDM_CC_SET_COMMAND_RESPONSE:
      proto_tree_add_item(tree, hf_rdm_pd_ack_timer_hi_res_estimated_response_time, tvb,
        offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      break;
    }
  }
  return offset;
}

static unsigned
dissect_rdm_pd_nack_reason(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint16_t param_id _U_, uint8_t pdl _U_)
{
  if (pdl == 2) {
    switch(cc) {
    case RDM_CC_GET_COMMAND_RESPONSE:
    case RDM_CC_SET_COMMAND_RESPONSE:
      proto_tree_add_item(tree, hf_rdm_pd_nack_reason_code, tvb,
        offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      break;
    }
  }

  return offset;
}

static uint8_t
is_response(uint8_t command_class)
{
  if ((command_class & RDM_CC_COMMAND_RESPONSE_FLAG) == RDM_CC_COMMAND_RESPONSE_FLAG) {
    return 1;
  }
  return 0;
}

static void
add_pid_to_tree(uint16_t param_id, proto_tree *mdb_tree, tvbuff_t *tvb, unsigned offset, uint16_t device_manufacturer_id)
{
  if (param_id < 0x8000) {
    proto_tree_add_item(mdb_tree, hf_rdm_parameter_id, tvb, offset, 2, ENC_BIG_ENDIAN);
  } else {
    switch(device_manufacturer_id) {
    case RDM_MANUFACTURER_ID_ETC:
      proto_tree_add_item(mdb_tree, hf_rdm_etc_parameter_id, tvb, offset, 2, ENC_BIG_ENDIAN);
      break;
    default:
      proto_tree_add_item(mdb_tree, hf_rdm_parameter_id, tvb, offset, 2, ENC_BIG_ENDIAN);
      break;
    }
  }
}

static unsigned
dissect_rdm_mdb(tvbuff_t *tvb, unsigned offset, packet_info *pinfo, proto_tree *tree, uint16_t device_manufacturer_id)
{
  uint8_t     cc;
  uint8_t     rt;
  uint16_t     param_id;
  uint8_t     parameter_data_length;
  proto_tree *hi,*si, *mdb_tree;
  unsigned offset_data_end;

  rt = tvb_get_uint8(tvb, offset);
  cc = tvb_get_uint8(tvb, offset + 4);

  if (is_response(cc)) {
    proto_tree_add_item(tree, hf_rdm_response_type, tvb,
        offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

  } else {
    proto_tree_add_item(tree, hf_rdm_port_id, tvb,
                    offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
  }

  if (is_response(cc)) {
    proto_tree_add_item(tree, hf_rdm_message_count, tvb,
                    offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
  } else {
    proto_tree_add_bitmask(tree, tvb, offset, hf_rdm_controller_flags,
        ett_rdm_controller_flags, rdm_controller_flags, ENC_BIG_ENDIAN);
    offset += 1;
  }

  proto_tree_add_item(tree, hf_rdm_sub_device, tvb,
      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  hi = proto_tree_add_item(tree, hf_rdm_mdb, tvb,
      offset, -1, ENC_NA);
  mdb_tree = proto_item_add_subtree(hi,ett_rdm_mdb);

  proto_tree_add_item(mdb_tree, hf_rdm_command_class, tvb,
      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  param_id = tvb_get_ntohs(tvb, offset);
  add_pid_to_tree(param_id, mdb_tree, tvb, offset, device_manufacturer_id);
  offset += 2;

  parameter_data_length = tvb_get_uint8(tvb, offset);
  proto_tree_add_item(mdb_tree, hf_rdm_parameter_data_length, tvb,
      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_item_set_len( mdb_tree,  parameter_data_length + 4);

  if (parameter_data_length > 0) {

    hi = proto_tree_add_item(mdb_tree, hf_rdm_parameter_data, tvb,
        offset, parameter_data_length, ENC_NA);
    si = proto_item_add_subtree(hi,ett_rdm_pd);

    if (is_response(cc)) {
      switch(rt) {
      case RDM_RESPONSE_TYPE_ACK:
        offset_data_end = dissect_rdm_mdb_param_data(tvb, offset, pinfo, si, cc, param_id, parameter_data_length, device_manufacturer_id);
        break;
      case RDM_RESPONSE_TYPE_ACK_TIMER:
        offset_data_end = dissect_rdm_pd_ack_timer(tvb, offset, si, cc, param_id, parameter_data_length);
        break;
      case RDM_RESPONSE_TYPE_NACK_REASON:
        offset_data_end = dissect_rdm_pd_nack_reason(tvb, offset, si, cc, param_id, parameter_data_length);
        break;
      case RDM_RESPONSE_TYPE_ACK_OVERFLOW:
        offset_data_end = dissect_rdm_pd_ack_overflow(tvb, offset, pinfo, si, cc, param_id, parameter_data_length, device_manufacturer_id);
        break;
      case RDM_RESPONSE_TYPE_ACK_TIMER_HI_RES:
        offset_data_end = dissect_rdm_pd_ack_timer_hi_res(tvb, offset, si, cc, param_id, parameter_data_length);
        break;
      default:
        offset_data_end = offset;
        break;
      }
    } else {
      offset_data_end = dissect_rdm_mdb_param_data(tvb, offset, pinfo, si, cc, param_id, parameter_data_length, device_manufacturer_id);
    }

    if (offset_data_end != offset + (unsigned)parameter_data_length) {
      expert_add_info(pinfo, tree, &ei_rdm_parameter_data_length);
    }

    offset += parameter_data_length;
  }

  return offset;
}

static uint16_t
get_device_manufacturer_id(uint8_t command_class, uint16_t source_manufacturer_id, uint16_t destination_manufacturer_id)
{
  if ((command_class == RDM_CC_GET_COMMAND) ||
      (command_class == RDM_CC_SET_COMMAND)) {
    return destination_manufacturer_id;
  }
  if ((command_class == RDM_CC_GET_COMMAND_RESPONSE) ||
      (command_class == RDM_CC_SET_COMMAND_RESPONSE)) {
    return source_manufacturer_id;
  }
  return 0;
}

static int
dissect_rdm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDM");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    int       padding_size;
    uint8_t   command_class;
    uint16_t  destination_manufacturer_id;
    uint16_t  source_manufacturer_id;
    uint16_t  device_manufacturer_id;
    uint32_t  destination_device_id;
    uint32_t  source_device_id;
    unsigned  message_length, offset = 0;

    proto_tree *ti = proto_tree_add_item(tree, proto_rdm, tvb,
        offset, -1, ENC_NA);
    proto_tree *rdm_tree = proto_item_add_subtree(ti, ett_rdm);

    proto_tree_add_item(rdm_tree, hf_rdm_sub_start_code, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    message_length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(rdm_tree, hf_rdm_message_length, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    destination_manufacturer_id = tvb_get_ntohs(tvb, offset);
    destination_device_id = tvb_get_ntohl(tvb, offset + 2);
    proto_item_append_text(ti, ", Dst UID: %04x:%08x",
        destination_manufacturer_id, destination_device_id);
    rdm_add_uid_item(rdm_tree, hf_rdm_dest_uid, tvb, &offset,
        hf_rdm_dest_uid_manf, hf_rdm_dest_uid_dev, hf_rdm_dest_uid_dyn);

    source_manufacturer_id = tvb_get_ntohs(tvb, offset);
    source_device_id = tvb_get_ntohl(tvb, offset + 2);
    proto_item_append_text(ti, ", Src UID: %04x:%08x",
        source_manufacturer_id, source_device_id);
    rdm_add_uid_item(rdm_tree, hf_rdm_src_uid, tvb, &offset,
        hf_rdm_src_uid_manf, hf_rdm_src_uid_dev, hf_rdm_src_uid_dyn);

    proto_tree_add_item(rdm_tree, hf_rdm_transaction_number, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    command_class = tvb_get_uint8(tvb, offset + 4);
    device_manufacturer_id = get_device_manufacturer_id(command_class, source_manufacturer_id, destination_manufacturer_id);
    offset = dissect_rdm_mdb(tvb, offset, pinfo, rdm_tree, device_manufacturer_id);

    padding_size = offset - (message_length - 1);
    if (padding_size > 0) {
      proto_tree_add_item(rdm_tree, hf_rdm_intron, tvb,
          offset, padding_size, ENC_NA);
      offset += padding_size;
    }

    proto_tree_add_checksum(rdm_tree, tvb, offset, hf_rdm_checksum, hf_rdm_checksum_status, &ei_rdm_checksum, pinfo, rdm_checksum(tvb, offset),
              ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    offset += 2;

    if (offset < tvb_reported_length(tvb)) {
      proto_tree_add_item(rdm_tree, hf_rdm_trailer, tvb,
          offset, -1, ENC_NA);
    }
  }
  return tvb_captured_length(tvb);
}

void
proto_register_rdm(void)
{
  static hf_register_info hf[] = {
    { &hf_rdm_sub_start_code,
      { "Sub-start code", "rdm.ssc",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_message_length,
      { "Message length", "rdm.len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_dest_uid,
      { "Destination UID", "rdm.dst",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_dest_uid_dyn,
      { "Dynamic UID", "rdm.dst.dyn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

    { &hf_rdm_dest_uid_manf,
      { "Manufacturer ID", "rdm.dst.manf",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dmx_esta_manfid_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_dest_uid_dev,
      { "Device ID", "rdm.dst.dev",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_src_uid,
      { "Source UID", "rdm.src",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_src_uid_dyn,
      { "Dynamic UID", "rdm.src.dyn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

    { &hf_rdm_src_uid_manf,
      { "Manufacturer ID", "rdm.src.manf",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dmx_esta_manfid_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_src_uid_dev,
      { "Device ID", "rdm.src.dev",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_transaction_number,
      { "Transaction number", "rdm.tn",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_port_id,
      { "Port ID", "rdm.port_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_response_type,
      { "Response type", "rdm.rt",
        FT_UINT8, BASE_HEX, VALS(rdm_rt_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_message_count,
      { "Message count", "rdm.mc",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_controller_flags,
      { "Controller flags", "rdm.cf",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_controller_flags_unicode,
      { "Unicode support", "rdm.cf.unicode",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},

    { &hf_rdm_controller_flags_hi_res_ack_timer,
      { "Hi-Res ack timer support", "rdm.cf.hi_res_ack_timer",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},

    { &hf_rdm_sub_device,
      { "Sub-device", "rdm.sd",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_mdb,
      { "Message Data Block", "rdm.mdb",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_command_class,
      { "Command class", "rdm.cc",
        FT_UINT8, BASE_HEX, VALS(rdm_cc_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_parameter_id,
      { "Parameter ID", "rdm.pid",
        FT_UINT16, BASE_HEX | BASE_EXT_STRING, &rdm_param_id_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_parameter_data_length,
      { "Parameter data length", "rdm.pdl",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_parameter_data,
      { "Parameter data", "rdm.pd",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_parameter_data_raw,
      { "Raw Data", "rdm.pd.raw",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_intron,
      { "Intron", "rdm.intron",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_checksum,
      { "Checksum", "rdm.checksum",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_checksum_status,
      { "Checksum Status", "rdm.checksum.status",
        FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_trailer,
      { "Trailer", "rdm.trailer",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ack_overflow_raw_data,
      { "Raw Data", "rdm.pd.ack_overflow.raw_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ack_timer_estimated_response_time,
      { "Estimated Response Time", "rdm.pd.ack_timer.estimated_response_time",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ack_timer_hi_res_estimated_response_time,
      { "Estimated Response Time", "rdm.pd.ack_timer_hi_res.estimated_response_time",
        FT_INT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_nack_reason_code,
      { "NACK Reason Code", "rdm.pd.nack_reason.code",
        FT_UINT16, BASE_HEX, VALS(rdm_nr_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_queued_message_status,
      { "Status", "rdm.pd.queued_message.status",
        FT_UINT8, BASE_HEX, VALS(rdm_status_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_nr,
      { "Sensor Nr.", "rdm.pd.sensor.nr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_value_pres,
      { "Sensor Present Value", "rdm.pd.sensor.value.present",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_value_low,
      { "Sensor Lowest Value", "rdm.pd.sensor.value.lowest",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_value_high,
      { "Sensor Highest Value", "rdm.pd.sensor.value.highest",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_value_rec,
      { "Sensor Recorded Value", "rdm.pd.sensor.value.recorded",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_range_min_value,
      { "Sensor Range Min. Value", "rdm.pd.sensor.range.min_value",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_range_max_value,
      { "Sensor Range Max. Value", "rdm.pd.sensor.range.max_value",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_normal_min_value,
      { "Sensor Normal Min. Value", "rdm.pd.sensor.normal.min_value",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_normal_max_value,
      { "Sensor Normal Max. Value", "rdm.pd.sensor.normal.max_value",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_recorded_value_support,
      { "Sensor Recorded Value Support", "rdm.pd.sensor.recorded_value_support",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_recorded_value_support_recorded,
      { "Recorded Value Supported", "rdm.pd.sensor.recorded_value_support.recorded",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_recorded_value_support_low_high,
      { "Lowest/Highest Value Supported", "rdm.pd.sensor.recorded_value_support.low_high",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_type,
      { "Sensor Type", "rdm.pd.sensor_type",
        FT_UINT8, BASE_HEX | BASE_EXT_STRING, &rdm_sensor_type_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_unit,
      { "Sensor Unit", "rdm.pd.sensor_unit",
        FT_UINT8, BASE_HEX | BASE_EXT_STRING, &rdm_unit_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_prefix,
      { "Sensor Prefix", "rdm.pd.sensor_prefix",
        FT_UINT8, BASE_HEX | BASE_EXT_STRING, &rdm_prefix_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_description,
      { "Sensor Description", "rdm.pd.sensor.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_subscribe_action,
      { "Sensor Subscribe Action", "rdm.pd.sensor.subscribe_action",
        FT_UINT8, BASE_HEX, VALS(rdm_sensor_subscribe_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_type_label,
      { "Sensor Type Label", "rdm.pd.sensor_type.label",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_unit_label,
      { "Sensor Unit Label", "rdm.pd.sensor_unit.label",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_manu_label,
      { "Manufacturer Label", "rdm.pd.manu_label",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},


    { &hf_rdm_pd_device_label,
      { "Device Label", "rdm.pd.device_label",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_start_address,
      { "DMX Start Address", "rdm.pd.dmx_start_address",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_device_hours,
      { "Device Hours", "rdm.pd.device_hours",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_lamp_hours,
      { "Lamp Hours", "rdm.pd.lamp_hours",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_lamp_strikes,
      { "Lamp Strikes", "rdm.pd.lamp_strikes",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_proto_vers,
      { "RDM Protocol Version", "rdm.pd.proto_vers",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_device_model_id,
      { "Device Model ID", "rdm.pd.device_model_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_product_cat,
      { "Product Category", "rdm.pd.product_cat",
        FT_UINT16, BASE_HEX | BASE_EXT_STRING, &rdm_product_cat_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_software_vers_id,
      { "Software Version ID", "rdm.pd.software_version_id",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_footprint,
      { "DMX Footprint", "rdm.pd.dmx_footprint",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_pers_current,
      { "Current DMX Personality", "rdm.pd.dmx_pers_current",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_pers_total,
      { "Total nr. DMX Personalities", "rdm.pd.dmx_pers_total",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sub_device_count,
      { "Sub-Device Count", "rdm.pd.sub_device_count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sensor_count,
      { "Sensor Count", "rdm.pd.sensor_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_device_model_description,
      { "Device Model Description", "rdm.pd.device_model_description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_unique_branch_lb_uid,
      { "Lower Bound UID", "rdm.pd.disc_unique_branch.lb_uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_unique_branch_ub_uid,
      { "Upper Bound UID", "rdm.pd.disc_unique_branch.ub_uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_mute_control_field,
      { "Control Field", "rdm.pd.disc_mute.control_field",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_mute_control_field_managed,
      { "Managed Proxy", "rdm.pd.disc_mute.control_field.managed",
        FT_BOOLEAN, 16, NULL, 0x0001,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_mute_control_field_sub_device,
      { "Sub-Device", "rdm.pd.disc_mute.control_field.sub_device",
        FT_BOOLEAN, 16, NULL, 0x0002,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_mute_control_field_bootloader,
      { "Boot-Loader", "rdm.pd.disc_mute.control_field.bootloader",
        FT_BOOLEAN, 16, NULL, 0x0004,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_mute_control_field_proxied,
      { "Proxied Device", "rdm.pd.disc_mute.control_field.proxied",
        FT_BOOLEAN, 16, NULL, 0x0008,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_mute_binding_uid,
      { "Binding UID", "rdm.pd.disc_mute.binding_uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_mute_binding_uid_dyn,
      { "Dynamic UID", "rdm.pd.disc_mute.binding_uid.dyn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_mute_binding_uid_manf,
      { "Manufacturer ID", "rdm.pd.disc_mute.binding_uid.manf",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dmx_esta_manfid_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_mute_binding_uid_dev,
      { "Device ID", "rdm.pd.disc_mute.binding_uid.dev",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_unmute_control_field,
      { "Control Field", "rdm.pd.disc_unmute.control_field",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_unmute_control_field_managed,
      { "Managed Proxy", "rdm.pd.disc_unmute.control_field.managed",
        FT_BOOLEAN, 16, NULL, 0x0001,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_unmute_control_field_sub_device,
      { "Sub-Device", "rdm.pd.disc_unmute.control_field.sub_device",
        FT_BOOLEAN, 16, NULL, 0x0002,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_unmute_control_field_bootloader,
      { "Boot-Loader", "rdm.pd.disc_unmute.control_field.bootloader",
        FT_BOOLEAN, 16, NULL, 0x0004,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_unmute_control_field_proxied,
      { "Proxied Device", "rdm.pd.disc_unmute.control_field.proxied",
        FT_BOOLEAN, 16, NULL, 0x0008,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_unmute_binding_uid,
      { "Binding UID", "rdm.pd.disc_unmute.binding_uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_unmute_binding_uid_dyn,
      { "Dynamic UID", "rdm.pd.disc_unmute.binding_uid.dyn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_unmute_binding_uid_manf,
      { "Manufacturer ID", "rdm.pd.disc_unmute.binding_uid.manf",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dmx_esta_manfid_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_unmute_binding_uid_dev,
      { "Device ID", "rdm.pd.disc_unmute.binding_uid.dev",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_proxied_devices_uid,
      { "UID", "rdm.pd.proxied_devices.uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_proxied_devices_uid_dyn,
      { "Dynamic UID", "rdm.pd.proxied_devices.dyn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

    { &hf_rdm_pd_proxied_devices_uid_manf,
      { "Manufacturer ID", "rdm.pd.proxied_devices.uid.manf",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dmx_esta_manfid_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_proxied_devices_uid_dev,
      { "Device ID", "rdm.pd.proxied_devices.uid.dev",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_proxied_device_count,
      { "Device Count", "rdm.pd.device_count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_proxied_device_list_change,
      { "List Change", "rdm.pd.list_change",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_real_time_clock_year,
      { "Year", "rdm.pd.real_time_clock.year",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_real_time_clock_month,
      { "Month", "rdm.pd.real_time_clock.month",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_real_time_clock_day,
      { "Day", "rdm.pd.real_time_clock.day",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_real_time_clock_hour,
      { "Hour", "rdm.pd.real_time_clock.hour",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_real_time_clock_minute,
      { "Minute", "rdm.pd.real_time_clock.minute",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_real_time_clock_second,
      { "Second", "rdm.pd.real_time_clock.second",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_lamp_state,
      { "Lamp State", "rdm.pd.lamp_state",
        FT_UINT8, BASE_HEX, VALS(rdm_lamp_state_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_lamp_on_mode,
      { "Lamp On Mode", "rdm.pd.lamp_on_mode",
        FT_UINT8, BASE_HEX, VALS(rdm_lamp_on_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_device_power_cycles,
      { "Device Power Cycles", "rdm.pd.device_power_cycles",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_display_invert,
      { "Display Invert", "rdm.pd.display_invert",
        FT_UINT8, BASE_HEX, VALS(rdm_display_invert_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_display_level,
      { "Display Level", "rdm.pd.display_level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_pan_invert,
      { "Pan Invert", "rdm.pd.pan_invert",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_tilt_invert,
      { "Tilt Invert", "rdm.pd.tilt_invert",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_tilt_swap,
      { "Tilt Swap", "rdm.pd.tilt_swap",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_nr,
      { "Selftest Nr.", "rdm.pd.selftest.nr",
        FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS, VALS(rdm_self_test_nr_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_state,
      { "Selftest State", "rdm.pd.selftest.state",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_description,
      { "Selftest Description", "rdm.pd.selftest.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_status,
      { "Selftest Status", "rdm.pd.selftest.status",
        FT_UINT8, BASE_HEX, VALS(rdm_self_test_status_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_capability,
      { "Selftest Capability", "rdm.pd.selftest.capability",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_capability_auto_terminates,
      { "Auto-Terminates", "rdm.pd.selftest.capability.auto_terminates",
        FT_BOOLEAN, 16, NULL, 0x0001,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_capability_restricts_dmx,
      { "Restricts DMX Operation", "rdm.pd.selftest.capability.restricts_dmx",
        FT_BOOLEAN, 16, NULL, 0x0002,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_capability_restricts_rdm,
      { "Restricts RDM Operation", "rdm.pd.selftest.capability.restricts_rdm",
        FT_BOOLEAN, 16, NULL, 0x0004,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_capability_ignores_auto_terminate,
      { "SELF_TEST_ALL ignores Auto-Terminate", "rdm.pd.selftest.capability.ignores_auto_terminate",
        FT_BOOLEAN, 16, NULL, 0x0008,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_capability_result_codes_available,
      { "Manufacturer-Specific Result Codes Available", "rdm.pd.selftest.capability.result_codes_available",
        FT_BOOLEAN, 16, NULL, 0x0010,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_capability_generates_status_messages,
      { "Generates Status Messages", "rdm.pd.selftest.capability.generates_status_messages",
        FT_BOOLEAN, 16, NULL, 0x0020,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_result_code,
      { "Result Code", "rdm.pd.selftest.result_code",
        FT_UINT16, BASE_HEX|BASE_SPECIAL_VALS, VALS(rdm_self_test_result_code_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_language_code,
      { "Language Code", "rdm.pd.language_code",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_identify_device,
      { "Identify Device", "rdm.pd.identify_device",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_identify_device_state,
      { "Identify Device State", "rdm.pd.identify_device.state",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_reset_device,
      { "Reset Device", "rdm.pd.reset_device",
        FT_UINT8, BASE_HEX, VALS(rdm_reset_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_power_state,
      { "Power State", "rdm.pd.power_state",
        FT_UINT8, BASE_HEX, VALS(rdm_power_state_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_capture_preset_scene_nr,
      { "Scene Nr.", "rdm.pd.capture_preset.scene_nr",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_capture_preset_up_fade_time,
      { "Up Fade Time", "rdm.pd.capture_preset.up_fade_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_capture_preset_down_fade_time,
      { "Down Fade Time", "rdm.pd.capture_preset.down_fade_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_capture_preset_wait_time,
      { "Wait Time", "rdm.pd.capture_preset.wait_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_playback_mode,
      { "Mode", "rdm.pd.preset_playback.mode",
        FT_UINT16, BASE_DEC|BASE_SPECIAL_VALS, VALS(rdm_preset_playback_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_playback_level,
      { "Level", "rdm.pd.preset_playback.level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_id,
      { "ID", "rdm.pd.parameter.id",
        FT_UINT16, BASE_HEX | BASE_EXT_STRING, &rdm_param_id_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_pdl_size,
      { "PDL Size", "rdm.pd.parameter.pdl_size",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_data_type,
      { "Data Type", "rdm.pd.parameter.data_type",
        FT_UINT8, BASE_HEX, VALS(rdm_data_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_cmd_class,
      { "Command Class", "rdm.pd.parameter.cmd_class",
        FT_UINT8, BASE_HEX, VALS(rdm_supported_command_class_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_type,
      { "Type", "rdm.pd.parameter.type",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_unit,
      { "Unit", "rdm.pd.parameter.unit",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &rdm_unit_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_prefix,
      { "Prefix", "rdm.pd.parameter.prefix",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &rdm_prefix_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_min_value,
      { "Min. Value", "rdm.pd.parameter.min_value",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_max_value,
      { "Max. Value", "rdm.pd.parameter.max_value",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_default_value,
      { "Default Value", "rdm.pd.parameter.default_value",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_description,
      { "Description", "rdm.pd.parameter.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_software_version_label,
      { "Version Label", "rdm.pd.software_version.label",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_boot_software_version_id,
      { "Version ID", "rdm.pd.boot_software_version.id",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_boot_software_version_label,
      { "Version Label", "rdm.pd.boot_software_version.label",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_manufacturer_url,
      { "Manufacturer URL", "rdm.pd.manufacturer_url",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_product_url,
      { "Product URL", "rdm.pd.product_url",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_firmware_url,
      { "Firmware URL", "rdm.pd.firmware_url",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_serial_number,
      { "Serial Number", "rdm.pd.serial_number",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_info_offstage_root_personality,
      { "Root Personality", "rdm.pd.info_offstage.root_personality",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_info_offstage_sub_device,
      { "Sub-Device ID", "rdm.pd.info_offstage.sub_device",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_info_offstage_sub_device_personality,
      { "Sub-Device Personality", "rdm.pd.info_offstage.sub_device_personality",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_short_msg,
      { "Short Msg", "rdm.pd.comms_status.short_msg",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_len_mismatch,
      { "Len Mismatch", "rdm.pd.comms_status.len_mismatch",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_csum_fail,
      { "Checksum Fail", "rdm.pd.comms_status.csum_fail",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_test_data_pattern_length,
      { "Pattern Length", "rdm.pd.test_data.pattern_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_test_data_pattern_data,
      { "Pattern Data", "rdm.pd.test_data.pattern_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_nsc_supported_fields,
      { "Supported Fields", "rdm.pd.comms_status_nsc.supported_fields",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_nsc_supported_fields_csum,
      { "Checksum", "rdm.pd.comms_status_nsc.supported_fields.checksum",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_nsc_supported_fields_packet_count,
      { "Packet Count", "rdm.pd.comms_status_nsc.supported_fields.packet_count",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_nsc_supported_fields_slot_count,
      { "Slot Count", "rdm.pd.comms_status_nsc.supported_fields.slot_count",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_nsc_supported_fields_slot_min,
      { "Min Slot Count", "rdm.pd.comms_status_nsc.supported_fields.slot_count_min",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_nsc_supported_fields_slot_max,
      { "Max Slot Count", "rdm.pd.comms_status_nsc.supported_fields.slot_count_max",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_nsc_supported_fields_error_count,
      { "Error Count", "rdm.pd.comms_status_nsc.supported_fields.error_count",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_nsc_csum,
      { "Most Recent NSC Checksum", "rdm.pd.comms_status_nsc.checksum",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_nsc_packet_count,
      { "NSC Packet Count", "rdm.pd.comms_status_nsc.packet_count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_nsc_slot_count,
      { "Most Recent NSC Slot Count", "rdm.pd.comms_status_nsc.slot_count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_nsc_slot_min,
      { "NSC Min Slot Count", "rdm.pd.comms_status_nsc.slot_count_min",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_nsc_slot_max,
      { "NSC Max Slot Count", "rdm.pd.comms_status_nsc.slot_count_max",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_comms_status_nsc_error_count,
      { "NSC Error Count", "rdm.pd.comms_status_nsc.error_count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_status_messages_type,
      { "Type", "rdm.pd.status_messages.type",
        FT_UINT8, BASE_HEX, VALS(rdm_status_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_status_messages_sub_device_id,
      { "Sub. Device ID", "rdm.pd.status_messages.sub_devices_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_status_messages_id,
      { "ID", "rdm.pd.status_messages.id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_status_messages_data_value_1,
      { "Data Value 1", "rdm.pd.status_messages.data_value_1",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_status_messages_data_value_2,
      { "Data Value 2", "rdm.pd.status_messages.data_value_2",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_status_id,
      { "ID", "rdm.pd.status_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_status_id_description,
      { "Description", "rdm.pd.status_id.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_sub_device_status_report_threshold_status_type,
      { "Status Type", "rdm.pd.sub_device_status_report_threshold.status_type",
        FT_UINT8, BASE_HEX, VALS(rdm_status_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_metadata_parameter_version,
      { "Parameter Version", "rdm.pd.metadata.parameter_version",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_metadata_json,
      { "Json", "rdm.pd.metadata.json",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_metadata_json_url,
      { "Json URL", "rdm.pd.metadata.json_url",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_supported_parameters_pid_support,
      { "PID Support", "rdm.pd.supported_params.pid_support",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_supported_parameters_pid_support_get,
      { "GET_COMMAND", "rdm.pd.supported_params.pid_support.get",
        FT_BOOLEAN, 16, NULL, 0x0001,
        NULL, HFILL }},

    { &hf_rdm_pd_supported_parameters_pid_support_set,
      { "SET_COMMAND", "rdm.pd.supported_params.pid_support.set",
        FT_BOOLEAN, 16, NULL, 0x0002,
        NULL, HFILL }},

    { &hf_rdm_pd_supported_parameters_pid_support_packed_sub_get,
      { "PACKED_PID_SUB GET_COMMAND", "rdm.pd.supported_params.pid_support.packed_sub_get",
        FT_BOOLEAN, 16, NULL, 0x0004,
        NULL, HFILL }},

    { &hf_rdm_pd_supported_parameters_pid_support_packed_sub_set,
      { "PACKED_PID_SUB SET_COMMAND", "rdm.pd.supported_params.pid_support.packed_sub_set",
        FT_BOOLEAN, 16, NULL, 0x0008,
        NULL, HFILL }},

    { &hf_rdm_pd_supported_parameters_pid_support_packed_index_get,
      { "PACKED_PID_INDEX GET_COMMAND", "rdm.pd.supported_params.pid_support.packed_index_get",
        FT_BOOLEAN, 16, NULL, 0x0010,
        NULL, HFILL }},

    { &hf_rdm_pd_supported_parameters_pid_support_packed_index_set,
      { "PACKED_PID_INDEX SET_COMMAND", "rdm.pd.supported_params.pid_support.packed_index_set",
        FT_BOOLEAN, 16, NULL, 0x0020,
        NULL, HFILL }},

    { &hf_rdm_pd_supported_parameters_pid_support_non_identical_sub,
      { "Has Non-Identical Sub-Device data", "rdm.pd.supported_params.pid_support.non_identical_sub",
        FT_BOOLEAN, 16, NULL, 0x0040,
        NULL, HFILL }},

    { &hf_rdm_pd_supported_parameters_pid_support_json_metadata,
      { "JSON Metadata", "rdm.pd.supported_params.pid_support.json_metadata",
        FT_BOOLEAN, 16, NULL, 0x0080,
        NULL, HFILL }},

    { &hf_rdm_pd_controller_flag_support_flags,
      { "Controller Flags", "rdm.pd.controller_flag_support.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_controller_flag_support_flags_unicode,
      { "Unicode support", "rdm.pd.controller_flag_support.flags.unicode",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},

    { &hf_rdm_pd_controller_flag_support_flags_hi_res_ack_timer,
      { "Hi-Res ack timer support", "rdm.pd.controller_flag_support.flags.hi_res_ack_timer",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},

    { &hf_rdm_pd_nack_description_reason_code,
      { "NACK Reason Code", "rdm.pd.nack_description.reason_code",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_nack_description_text,
      { "Description", "rdm.pd.nack_description.text",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_packed_pid_index,
      { "Packed PID Index", "rdm.pd.packed_pid.index",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_packed_pid_index_count,
      { "Packed PID Index Count", "rdm.pd.packed_pid.index_count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_packed_pid_sub_device,
      { "Packed PID Sub-Device", "rdm.pd.packed_pid.sub_device",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_packed_pid_sub_device_count,
      { "Packed PID Sub-Device Count", "rdm.pd.packed_pid.sub_device_count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_packed_pid_data,
      { "Packed PID Data", "rdm.pd.packed_pid.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_packed_pid_data_none,
      { "Packed PID Data", "rdm.pd.packed_pid.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_packed_pid_data_len,
      { "Packed PID Data Length", "rdm.pd.packed_pid.data_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_enum_label_index,
      { "Requested Index", "rdm.pd.enum_label.index",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_enum_label_max_index,
      { "Maximum Index", "rdm.pd.enum_label.max_index",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_enum_label_label,
      { "Text Label", "rdm.pd.enum_label.label",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_product_detail_id,
      { "Product Detail ID", "rdm.pd.product_detail_id",
        FT_UINT16, BASE_HEX | BASE_EXT_STRING, &rdm_product_detail_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_factory_defaults,
      { "Factory Defaults", "rdm.pd.factory_defaults",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_background_discovery_endpoint_id,
      { "Endpoint ID", "rdm.pd.background_discovery.endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_background_discovery_enabled,
      { "Enabled", "rdm.pd.background_discovery.enabled",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_background_queued_status_policy_current_policy,
      { "Current Policy", "rdm.pd.background_queued_status_policy.current_policy",
        FT_UINT8, BASE_DEC, VALS(rdm_status_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_background_queued_status_policy_number_of_policies,
      { "Number Of Policies", "rdm.pd.background_queued_status_policy.number_of_policies",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_background_queued_status_policy_description_policy,
      { "Policy", "rdm.pd.background_queued_status_policy_description.policy",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_background_queued_status_policy_description_description,
      { "Description", "rdm.pd.background_queued_status_policy_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_search_domain_dns_domain_name,
      { "DNS Domain Name", "rdm.pd.search_domain.dns_domain_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_binding_control_fields_endpoint_id,
      { "Endpoint ID", "rdm.pd.binding_control_fields.endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_binding_control_fields_uid,
      { "UID", "rdm.pd.binding_control_fields.uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_binding_control_fields_uid_dyn,
      { "Dynamic UID", "rdm.pd.binding_control_fields.uid.dyn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

    { &hf_rdm_pd_binding_control_fields_uid_manf,
      { "Manufacturer ID", "rdm.pd.binding_control_fields.uid.manf",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dmx_esta_manfid_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_binding_control_fields_uid_dev,
      { "Device ID", "rdm.pd.binding_control_fields.uid.dev",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_binding_control_fields_control_field,
      { "Control Field", "rdm.pd.binding_control_fields.control_field",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_binding_control_fields_binding_uid,
      { "Binding UID", "rdm.pd.binding_control_fields.binding_uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_binding_control_fields_binding_uid_dyn,
      { "Dynamic UID", "rdm.pd.binding_control_fields.binding_uid.dyn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

    { &hf_rdm_pd_binding_control_fields_binding_uid_manf,
      { "Manufacturer ID", "rdm.pd.binding_control_fields.binding_uid.manf",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dmx_esta_manfid_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_binding_control_fields_binding_uid_dev,
      { "Device ID", "rdm.pd.binding_control_fields.binding_uid.dev",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rem_pd_broker_status_set_allowed,
      { "Set Allowed", "rdm.pd.broker_status.set_allowed",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_rem_pd_broker_status_state,
      { "State", "rdm.pd.broker_status.state",
        FT_UINT8, BASE_DEC, VALS(rdmnet_broker_status_states_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_burn_in,
      { "Burn In", "rdm.pd.burn_in",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_component_scope_scope_slot,
      { "Scope Slot", "rdm.pd.component_scope.scope_slot",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_component_scope_scope_string,
      { "Scope String", "rdm.pd.component_scope.scope_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_component_scope_scope_static_config_type,
      { "Static Config. Type", "rdm.pd.component_scope.static_config_type",
        FT_UINT8, BASE_DEC, VALS(rdmnet_component_scope_static_config_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_component_scope_scope_static_ipv4_address,
      { "Static IPv4 Address", "rdm.pd.component_scope.static_ipv4_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_component_scope_scope_static_ipv6_address,
      { "Static IPv6 Address", "rdm.pd.component_scope.static_ipv6_address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_component_scope_scope_static_port,
      { "Static Port", "rdm.pd.component_scope.static_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_current_address_interface_identifier,
      { "Interface Identifier", "rdm.pd.current_address.interface_identifier",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_current_address_ipv4_address,
      { "IPv4 Address", "rdm.pd.current_address.ipv4_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_current_address_netmask,
      { "Netmask", "rdm.pd.current_address.netmask",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_current_address_dhcp_status,
      { "DHCP Status", "rdm.pd.current_address.dhcp_status",
        FT_UINT8, BASE_DEC, VALS(rdm_dhcp_status_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_curve_curve,
      { "Curve", "rdm.pd.curve.curve",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_curve_number_of_curves,
      { "Number Of Curves", "rdm.pd.curve.number_of_curves",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_curve_description_curve,
      { "Curve", "rdm.pd.curve_description.curve",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_curve_description_text,
      { "Description", "rdm.pd.curve_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_device_unit_number,
      { "Device Unit Number", "rdm.pd.device_unit_number",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dhcp_mode_interface_identifier,
      { "Interface Identifier", "rdm.pd.dhcp_mode.interface_identifier",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dhcp_mode_enabled,
      { "Enabled", "rdm.pd.dhcp_mode.enabled",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dimmer_info_minimum_level_lower_limit,
      { "Minimum Level Lower Limit", "rdm.pd.dimmer_info.minimum_level_lower_limit",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dimmer_info_minimum_level_upper_limit,
      { "Minimum Level Upper Limit", "rdm.pd.dimmer_info.minimum_level_upper_limit",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dimmer_info_maximum_level_lower_limit,
      { "Maximum Level Lower Limit", "rdm.pd.dimmer_info.maximum_level_lower_limit",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dimmer_info_maximum_level_upper_limit,
      { "Maximum Level Upper Limit", "rdm.pd.dimmer_info.maximum_level_upper_limit",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dimmer_info_number_of_supported_curves,
      { "Number Of Supported Curves", "rdm.pd.dimmer_info.number_of_supported_curves",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dimmer_info_levels_resolution,
      { "Levels Resolution", "rdm.pd.dimmer_info.levels_resolution",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dimmer_info_minimum_level_split_levels_supported,
      { "Minimum Level Split Levels Supported", "rdm.pd.dimmer_info.minimum_level_split_levels_supported",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_discovery_state_endpoint_id,
      { "Endpoint ID", "rdm.pd.discovery_state.endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_discovery_state_device_count,
      { "Device Count", "rdm.pd.discovery_state.device_count",
        FT_UINT16, BASE_DEC|BASE_SPECIAL_VALS, VALS(rdm_discovery_count_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_discovery_state_discovery_state,
      { "State", "rdm.pd.discovery_state.state",
        FT_UINT8, BASE_DEC, VALS(rdm_discovery_state_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_block_address_base_dmx_address,
      { "Base DMX Address", "rdm.pd.dmx_block_address.base_dmx_address",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_block_address_subdevice_footprint,
      { "Sub-Device Footprint", "rdm.pd.dmx_block_address.subdevice_footprint",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_fail_mode_scene_number,
      { "Scene Number", "rdm.pd.dmx_fail_mode.scene_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_fail_mode_loss_of_signal_delay,
      { "Loss Of Signal Delay", "rdm.pd.dmx_fail_mode.loss_of_signal_delay",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_fail_mode_hold_time,
      { "Hold Time", "rdm.pd.dmx_fail_mode.hold_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_fail_mode_level,
      { "Level", "rdm.pd.dmx_fail_mode.level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_pers_nr,
      { "DMX Pers. Nr.", "rdm.pd.dmx_pers.nr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_pers_count,
      { "DMX Pers. Count", "rdm.pd.dmx_pers.count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_pers_requested,
      { "DMX Pers. Requested", "rdm.pd.dmx_pers.requested",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_pers_slots,
      { "DMX Pers. Slots", "rdm.pd.dmx_pers.slots",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_pers_text,
      { "DMX Pers. Text", "rdm.pd.dmx_pers.text",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_pers_id_major,
      { "DMX Pers. ID Major", "rdm.pd.dmx_pers.id_major",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_pers_id_minor,
      { "DMX Pers. ID Minor", "rdm.pd.dmx_pers.in_minor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_startup_mode_scene_number,
      { "Scene Number", "rdm.pd.dmx_startup_mode.scene_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_startup_mode_loss_of_signal_delay,
      { "Startup Delay Time", "rdm.pd.dmx_startup_mode.startup_delay_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_startup_mode_hold_time,
      { "Hold Time", "rdm.pd.dmx_startup_mode.hold_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dmx_startup_mode_level,
      { "Level", "rdm.pd.dmx_startup_mode.level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dns_domain_name,
      { "Domain Name", "rdm.pd.dns_domain_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dns_hostname,
      { "Host Name", "rdm.pd.dns_hostname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dns_ipv4_name_server_index,
      { "Index", "rdm.pd.dns_ipv4_name_server.index",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_dns_ipv4_name_server_address,
      { "Index", "rdm.pd.dns_ipv4_name_server.address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_label_endpoint_id,
      { "Endpoint ID", "rdm.pd.endpoint_label.endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_label_label,
      { "Label", "rdm.pd.endpoint_label.label",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_list_change_number,
      { "List Change Number", "rdm.pd.endpoint_list.change_number",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_list_endpoint_id,
      { "Endpoint ID", "rdm.pd.endpoint_list.endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_list_endpoint_type,
      { "Endpoint Type", "rdm.pd.endpoint_list.endpoint_type",
        FT_UINT8, BASE_DEC, VALS(rdm_endpoint_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_list_change_change_number,
      { "List Change Number", "rdm.pd.endpoint_list_change.change_number",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_mode_endpoint_id,
      { "Endpoint ID", "rdm.pd.endpoint_mode.endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_mode_endpoint_mode,
      { "Endpoint ID", "rdm.pd.endpoint_mode.endpoint_mode",
        FT_UINT8, BASE_DEC, VALS(rdm_endpoint_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_responder_list_change_endpoint_id,
      { "Endpoint ID", "rdm.pd.endpoint_responder_list_change.endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_responder_list_change_change_number,
      { "Change Number", "rdm.pd.endpoint_responder_list_change.change_number",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_responders_endpoint_id,
      { "Endpoint ID", "rdm.pd.endpoint_responders.endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_responders_change_number,
      { "Change Number", "rdm.pd.endpoint_responders.change_number",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_responders_uid,
      { "UID", "rdm.pd.endpoint_responders.uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_responders_uid_dyn,
      { "Dynamic UID", "rdm.pd.endpoint_responders.uid.dyn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_responders_uid_manf,
      { "Manufacturer ID", "rdm.pd.endpoint_responders.uid.manf",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dmx_esta_manfid_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_responders_uid_dev,
      { "Device ID", "rdm.pd.endpoint_responders.uid.dev",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_timing_endpoint_id,
      { "Endpoint ID", "rdm.pd.endpoint_timing.endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_timing_setting,
      { "Setting", "rdm.pd.endpoint_timing.setting",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_timing_number_of_settings,
      { "Number Of Settings", "rdm.pd.endpoint_timing.number_of_settings",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_timing_description_setting,
      { "Setting", "rdm.pd.endpoint_timing_description.setting",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_timing_description_description,
      { "Description", "rdm.pd.endpoint_timing_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_to_universe_endpoint_id,
      { "Endpoint ID", "rdm.pd.endpoint_to_universe.endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_endpoint_to_universe_universe_number,
      { "Universe Number", "rdm.pd.endpoint_to_universe.universe_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_hardware_address_type1_interface_identifier,
      { "Interface Identifier", "rdm.pd.hardware_address_type1.interface_identifier",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_hardware_address_type1_hardware_address,
      { "Hardware Address", "rdm.pd.hardware_address_type1.hardware_address",
        FT_BYTES, SEP_COLON, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_identify_endpoint_endpoint_id,
      { "Endpoint ID", "rdm.pd.identify_endpoint.endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_identify_endpoint_identify_state,
      { "Identify State", "rdm.pd.identify_endpoint.identify_state",
        FT_UINT8, BASE_DEC, VALS(on_off_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_identify_mode,
      { "Identify Mode", "rdm.pd.identify_mode.identify_mode",
        FT_UINT8, BASE_HEX|BASE_SPECIAL_VALS, VALS(rdm_identify_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_identify_timeout,
      { "Identify Timeout", "rdm.pd.identify_mode.identify_timeout",
        FT_UINT16, BASE_DEC|BASE_SPECIAL_VALS, VALS(rdm_identify_timeout_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_interface_apply_configuration_interface_identifier,
      { "Interface Identifier", "rdm.pd.interface_apply_configuration.interface_identifier",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_interface_label_interface_identifier,
      { "Interface Identifier", "rdm.pd.interface_label.interface_identifier",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_interface_label_label,
      { "Label", "rdm.pd.interface_label.label",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_interface_release_dhcp_interface_identifier,
      { "Interface Identifier", "rdm.pd.interface_release_dhcp.interface_identifier",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_interface_renew_dhcp_interface_identifier,
      { "Interface Identifier", "rdm.pd.interface_renew_dhcp.interface_identifier",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ipv4_default_route_interface_identifier,
      { "Interface Identifier", "rdm.pd.ipv4_default_route.interface_identifier",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ipv4_default_route_ipv4_default_route,
      { "Interface Identifier", "rdm.pd.ipv4_default_route.default_route",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_list_interfaces_interface_identifier,
      { "Interface Identifier", "rdm.pd.list_interfaces.interface_identifier",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_list_interfaces_interface_hardware_type,
      { "Interface Hardware Type", "rdm.pd.list_interfaces.interface_hardware_type",
        FT_UINT16, BASE_DEC, VALS(arp_hrd_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_lock_pin_pin_code,
      { "PIN Code", "rdm.pd.lock_pin.pin_code",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rdm_pd_lock_pin_new_pin_code,
      { "New PIN Code", "rdm.pd.lock_pin.new_pin_code",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_lock_state_lock_state,
      { "Lock State", "rdm.pd.lock_state.lock_state",
        FT_UINT8, BASE_HEX|BASE_SPECIAL_VALS, VALS(rdm_lock_state_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_lock_state_number_of_lock_states,
      { "Number Of Lock States", "rdm.pd.lock_state.number_of_lock_states",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_lock_state_pin_code,
      { "PIN Code", "rdm.pd.lock_state.pin_code",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_lock_state_description_lock_state,
      { "Lock State", "rdm.pd.lock_state_description.lock_state",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_lock_state_description_text,
      { "Description", "rdm.pd.lock_state_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_maximum_level_level,
      { "Level", "rdm.pd.maximum_level.level",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_mergemode,
      { "Merge Mode", "rdm.pd.preset_mergemode",
        FT_UINT8, BASE_DEC, VALS(rdm_mergemode_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_power_on_self_test,
      { "Power On Self Test", "rdm.pd.power_on_self_test",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_minimum_level_increasing,
      { "Increasing", "rdm.pd.minimum_level.increasing",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_minimum_level_decreasing,
      { "Decreasing", "rdm.pd.minimum_level.decreasing",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_minimum_level_on_below_minimum,
      { "On Below Minimum", "rdm.pd.minimum_level.on_below_minimum",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_modulation_frequency_modulation_frequency,
      { "Modulation Frequency", "rdm.pd.modulation_frequency.modulation_frequency",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_modulation_frequency_number_of_modulation_frequencies,
      { "Number Of Modulation Frequencies", "rdm.pd.modulation_frequency.number_of_modulation_frequencies",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_modulation_frequency_description_modulation_frequency,
      { "Modulation Frequency", "rdm.pd.modulation_frequency_description.modulation_frequency",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_modulation_frequency_description_hertz,
      { "Modulation Frequency", "rdm.pd.modulation_frequency_description.modulation_frequency",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_hz), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_modulation_frequency_description_text,
      { "Description", "rdm.pd.modulation_frequency_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_output_response_time_response_time,
      { "Response Time", "rdm.pd.response_time.response_time",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_output_response_time_number_of_response_times,
      { "Number Of Response Times", "rdm.pd.response_time.number_of_response_times",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_output_response_time_description_output_response_time,
      { "Output Response Time", "rdm.pd.output_response_time_description.output_response_time",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_output_response_time_description_text,
      { "Description", "rdm.pd.output_response_time_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_power_off_ready,
      { "Power Off Ready", "rdm.pd.power_off_ready",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_level_field_supported,
      { "Level Field Supported", "rdm.pd.preset_info.level_field_supported",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_preset_sequence_supported,
      { "Preset Sequence Supported", "rdm.pd.preset_info.preset_sequence_supported",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_split_times_supported,
      { "Split Times Supported", "rdm.pd.preset_info.split_times_supported",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_dmx_fail_infinite_delay_time_supported,
      { "DMX Fail Infinite Delay Time Supported", "rdm.pd.preset_info.dmx_fail_infinite_delay_time_supported",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_dmx_fail_infinite_hold_time_supported,
      { "DMX Fail Infinite Hold Time Supported", "rdm.pd.preset_info.dmx_fail_infinite_hold_time_supported",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_start_up_infinite_hold_time_supported,
      { "Start Up_ Infinite Hold Time Supported", "rdm.pd.preset_info.start_up_infinite_hold_time_supported",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_maximum_scene_number,
      { "Maximum Scene Number", "rdm.pd.preset_info.maximum_scene_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_minimum_preset_fade_time_supported,
      { "Minimum Preset Fade Time Supported", "rdm.pd.preset_info.minimum_preset_fade_time_supported",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_maximum_preset_fade_time_supported,
      { "Maximum Preset Fade Time Supported", "rdm.pd.preset_info.maximum_preset_fade_time_supported",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_minimum_preset_wait_time_supported,
      { "Minimum Preset Wait Time Supported", "rdm.pd.preset_info.minimum_preset_wait_time_supported",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_maximum_preset_wait_time_supported,
      { "Maximum Preset Wait Time Supported", "rdm.pd.preset_info.maximum_preset_wait_time_supported",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_minimum_dmx_fail_delay_time_supported,
      { "Minimum DMX Fail Delay Time Supported", "rdm.pd.preset_info.minimum_dmx_fail_delay_time_supported",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_maximum_dmx_fail_delay_time_supported,
      { "Maximum DMX Fail Delay Time Supported", "rdm.pd.preset_info.maximum_dmx_fail_delay_time_supported",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_minimum_dmx_fail_hold_time_supported,
      { "Minimum DMX Fail Hold Time Supported", "rdm.pd.preset_info.minimum_dmx_fail_hold_time_supported",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_maximum_dmx_fail_hold_time_supported,
      { "Maximum DMX Fail Hold Time Supported", "rdm.pd.preset_info.maximum_dmx_fail_hold_time_supported",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_minimum_start_up_delay_time_supported,
      { "Minimum Start Up Delay Time Supported", "rdm.pd.preset_info.minimum_start_up_delay_time_supported",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_maximum_start_up_delay_time_supported,
      { "Maximum Start Up Delay Time Supported", "rdm.pd.preset_info.maximum_start_up_delay_time_supported",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_minimum_start_up_hold_time_supported,
      { "Minimum Start Up Hold Time Supported", "rdm.pd.preset_info.minimum_start_up_hold_time_supported",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_info_maximum_start_up_hold_time_supported,
      { "Maximum Start Up Hold Time Supported", "rdm.pd.preset_info.maximum_start_up_hold_time_supported",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_status_scene_number,
      { "Scene Number", "rdm.pd.preset_status.scene_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_status_up_fade_time,
      { "Up Fade Time", "rdm.pd.preset_status.up_fade_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_status_down_fade_time,
      { "Down Fade Time", "rdm.pd.preset_status.down_fade_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_status_wait_time,
      { "Wait Time", "rdm.pd.preset_status.wait_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_status_programmed,
      { "Programmed", "rdm.pd.preset_status.programmed",
        FT_UINT8, BASE_DEC, VALS(rdm_preset_programmed_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_status_clear_preset,
      { "Clear Preset", "rdm.pd.preset_status.clear_preset",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_rdm_traffic_enable_endpoint_id,
      { "Endpoint ID", "rdm.pd.rdm_traffic_enable.endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_rdm_traffic_enable_rdm_enabled,
      { "Enabled", "rdm.pd.rdm_traffic_enable.enabled",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_shipping_lock_state,
      { "Shipping Lock State", "rdm.pd.shipping_lock_state",
        FT_UINT8, BASE_HEX, VALS(rdm_shipping_lock_state_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_slot_offset,
      { "Slot Offset", "rdm.pd.slot_offset",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_slot_type,
      { "Slot Type", "rdm.pd.slot_type",
        FT_UINT8, BASE_DEC, VALS(rdm_slot_types), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_slot_label_id,
      { "Slot Label ID", "rdm.pd.slot_label_id",
        FT_UINT16, BASE_HEX, VALS(rdm_slot_label_definitions), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_slot_primary_offset,
      { "Primary Slot Offset", "rdm.pd.slot_primary_offset",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_slot_nr,
      { "Slot Nr.", "rdm.pd.slot_nr",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_slot_description,
      { "Slot Description", "rdm.pd.slot_description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_slot_value,
      { "Slot Value", "rdm.pd.slot_value",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_static_address_interface_identifier,
      { "Interface Identifier", "rdm.pd.static_address.interface_identifier",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_static_address_ipv4_address,
      { "IPv4 Address", "rdm.pd.static_address.ipv4_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_static_address_netmask,
      { "Netmask", "rdm.pd.static_address.netmask",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_tag,
      { "Tag", "rdm.pd.tag",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_tag_null,
      { "Tag", "rdm.pd.tag",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_tag_status,
      { "Tag Status", "rdm.pd.tag.status",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_tag_list,
      { "Tag List", "rdm.pd.tag_list",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_tcp_comms_status_scope_string,
      { "Scope String", "rdm.pd.tcp_comms_status.scope_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_tcp_comms_status_broker_ipv4_address,
      { "Broker IPV4 Address", "rdm.pd.tcp_comms_status.broker_ipv4_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_tcp_comms_status_broker_ipv6_address,
      { "Broker IPV6 Address", "rdm.pd.tcp_comms_status.broker_ipv6_address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_tcp_comms_status_broker_port,
      { "Broker Port", "rdm.pd.tcp_comms_status.broker_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_tcp_comms_status_unhealthy_tcp_events,
      { "Unhealthy TCP Events", "rdm.pd.tcp_comms_status.unhealthy_tcp_events",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_zeroconf_mode_interface_identifier,
      { "Interface Identifier", "rdm.pd.zeroconf_mode.interface_identifier",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_zeroconf_mode_enabled,
      { "Enabled", "rdm.pd.zeroconf_mode.enabled",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_rec_value_support,
      { "Rec. Value Support", "rdm.pd.rec_value_support",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_session_id,
      { "Session ID", "rdm.pd.ftc.session_id",
        FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS, VALS(rdm_ftc_session_id_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_file_id,
      { "File ID", "rdm.pd.ftc.file_id",
        FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS, VALS(rdm_ftc_file_id_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_version_major,
      { "FTC Major Version", "rdm.pd.ftc.version_major",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_version_minor,
      { "FTC Minor Version", "rdm.pd.ftc.version_minor",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_transfer_flags,
      { "Transfer Flags", "rdm.pd.ftc.transfer_flags",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_transfer_flags_test_mode,
      { "Test Mode", "rdm.pd.ftc.transfer_flags.test_mode",
        FT_BOOLEAN, 16, NULL, 0x0001,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_transfer_flags_download,
      { "Download", "rdm.pd.ftc.transfer_flags.download",
        FT_BOOLEAN, 16, NULL, 0x0002,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_status,
      { "Response Status", "rdm.pd.ftc.response_status",
        FT_UINT8, BASE_HEX, VALS(rdm_ftc_response_status_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data,
      { "Response Data", "rdm.pd.ftc.response_data",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data_commit_time,
      { "Commit Time", "rdm.pd.ftc.response_data.commit_time",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data_time_to_wait,
      { "Time to Wait", "rdm.pd.ftc.response_data.time_to_wait",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data_received_crc,
      { "Received CRC", "rdm.pd.ftc.response_data.received_crc",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data_calculated_crc,
      { "Calculated CRC", "rdm.pd.ftc.response_data.calculated_crc",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data_offered_fileid,
      { "Offered File ID", "rdm.pd.ftc.response_data.offered_fileid",
        FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS, VALS(rdm_ftc_file_id_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data_supported_fileid,
      { "Supported File ID", "rdm.pd.ftc.response_data.supported_fileid",
        FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS, VALS(rdm_ftc_file_id_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data_received_sessionid,
      { "Received Session ID", "rdm.pd.ftc.response_data.received_sessionid",
        FT_UINT16, BASE_DEC|BASE_SPECIAL_VALS, VALS(rdm_ftc_session_id_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data_expected_sessionid,
      { "Expected Session ID", "rdm.pd.ftc.response_data.expected_sessionid",
        FT_UINT16, BASE_DEC|BASE_SPECIAL_VALS, VALS(rdm_ftc_session_id_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data_expected_offset,
      { "Expected Offset", "rdm.pd.ftc.response_data.expected_offset",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data_expected_file_size,
      { "Expected File Size", "rdm.pd.ftc.response_data.expected_file_size",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data_supported_major_ver,
      { "Supported Major Version", "rdm.pd.ftc.response_data.supported_major_ver",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data_supported_minor_ver,
      { "Supported Minor Version", "rdm.pd.ftc.response_data.supported_minor_ver",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_response_data_received_command,
      { "Received Command", "rdm.pd.ftc.response_data.received_command",
        FT_UINT32, BASE_HEX, VALS(rdm_ftc_download_command_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_file_size,
      { "File Size", "rdm.pd.ftc.file_size",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_data,
      { "File Data", "rdm.pd.ftc.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_file_crc,
      { "File CRC", "rdm.pd.ftc.file_crc",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_packet_crc,
      { "Packet CRC", "rdm.pd.ftc.packet_crc",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_packet_crc_status,
      { "Packet CRC Status", "rdm.pd.ftc.packet_crc.status",
        FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities,
      { "Capabilities", "rdm.pd.ftc.capabilities",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_accept_upload,
      { "Accepts Upload", "rdm.pd.ftc.capabilities.accept_upload",
        FT_BOOLEAN, 32, NULL, 0x00000001,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_accept_download,
      { "Accepts Download", "rdm.pd.ftc.capabilities.accept_download",
        FT_BOOLEAN, 32, NULL, 0x00000002,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_process_file_crc,
      { "Processes File CRC", "rdm.pd.ftc.capabilities.process_file_crc",
        FT_BOOLEAN, 32, NULL, 0x00000004,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_process_packet_crc,
      { "Processes Packet CRC", "rdm.pd.ftc.capabilities.process_packet_crc",
        FT_BOOLEAN, 32, NULL, 0x00000008,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_generate_file_crc,
      { "Generates File CRC", "rdm.pd.ftc.capabilities.generate_file_crc",
        FT_BOOLEAN, 32, NULL, 0x00000010,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_generate_packet_crc,
      { "Generates File CRC", "rdm.pd.ftc.capabilities.generate_packet_crc",
        FT_BOOLEAN, 32, NULL, 0x00000020,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_download_key,
      { "Download Key Required", "rdm.pd.ftc.capabilities.download_key",
        FT_BOOLEAN, 32, NULL, 0x00000040,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_bootloader_switch,
      { "Switch to Bootloader", "rdm.pd.ftc.capabilities.bootloader_switch",
        FT_BOOLEAN, 32, NULL, 0x00000080,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_nsc_no_iterleave,
      { "NSC No Interleave", "rdm.pd.ftc.capabilities.nsc_no_iterleave",
        FT_BOOLEAN, 32, NULL, 0x00000100,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_nsc_ignored,
      { "NSC Ignored", "rdm.pd.ftc.capabilities.nsc_ignored",
        FT_BOOLEAN, 32, NULL, 0x00000200,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_function_limit,
      { "Functions Limited", "rdm.pd.ftc.capabilities.function_limit",
        FT_BOOLEAN, 32, NULL, 0x00000400,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_e137_lock,
      { "E1.37 Unlock Required", "rdm.pd.ftc.capabilities.e137_lock",
        FT_BOOLEAN, 32, NULL, 0x00001000,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_other_lock,
      { "Other Unlock Required", "rdm.pd.ftc.capabilities.other_lock",
        FT_BOOLEAN, 32, NULL, 0x00002000,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_accept_broadcasts,
      { "Accepts Broadcasts", "rdm.pd.ftc.capabilities.accept_broadcasts",
        FT_BOOLEAN, 32, NULL, 0x00008000,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_fail_may_brick,
      { "Fail May Brick Device", "rdm.pd.ftc.capabilities.fail_may_brick",
        FT_BOOLEAN, 32, NULL, 0x00010000,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_alternate_error_recovery,
      { "Alternate Error Recovery Available", "rdm.pd.ftc.capabilities.alternate_error_recovery",
        FT_BOOLEAN, 32, NULL, 0x00020000,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_capabilities_test_mode_supported,
      { "Test Mode Supported", "rdm.pd.ftc.capabilities.test_mode_supported",
        FT_BOOLEAN, 32, NULL, 0x00800000,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_data_offset,
      { "Data Offset", "rdm.pd.ftc.data_offset",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_transfer_block_size,
      { "Transfer Block Size", "rdm.pd.ftc.transfer_block_size",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_initial_delay,
      { "Initial Delay Time", "rdm.pd.ftc.initial_delay",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_inter_packet_delay,
      { "Inter-Packet Delay Time", "rdm.pd.ftc.inter_packet_delay",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_accumulated_byte_count,
      { "Accumulated Byte Count", "rdm.pd.ftc.accumulated_byte_count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_accumulated_byte_delay,
      { "Accumulated Byte Delay", "rdm.pd.ftc.accumulated_byte_delay",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_validation_delay,
      { "Validation Delay Time", "rdm.pd.ftc.validation_delay",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_max_inter_packet_delay,
      { "Max Inter-Packet Delay Time", "rdm.pd.ftc.max_inter_packet_delay",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_commit_flags,
      { "Commit Flags", "rdm.pd.ftc.commit_flags",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_commit_flags_test_mode,
      { "Test Mode", "rdm.pd.ftc.commit_flags.test_mode",
        FT_BOOLEAN, 16, NULL, 0x0001,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_commit_flags_download,
      { "Download", "rdm.pd.ftc.commit_flags.download",
        FT_BOOLEAN, 16, NULL, 0x0002,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_calculated_file_crc,
      { "Calculated File CRC", "rdm.pd.ftc.calculated_file_crc",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_expected_uid,
      { "Expected UID", "rdm.pd.ftc.expected_uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_expected_uid_dyn,
      { "Dynamic UID", "rdm.pd.ftc.expected_uid.dyn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_expected_uid_manf,
      { "Manufacturer ID", "rdm.pd.ftc.expected_uid.manf",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dmx_esta_manfid_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_expected_uid_dev,
      { "Device ID", "rdm.pd.ftc.expected_uid.dev",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_file_description,
      { "File Description", "rdm.pd.ftc.file_description",
        FT_STRINGZPAD, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_file_suffix,
      { "File Extension", "rdm.pd.ftc.file_suffix",
        FT_STRINGZPAD, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_ftc_command,
      { "Download Command", "rdm.pd.ftc.command",
        FT_UINT8, BASE_HEX, VALS(rdm_ftc_download_command_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_etc_parameter_id,
      { "Parameter ID", "rdm.pid",
        FT_UINT16, BASE_HEX | BASE_EXT_STRING, &etc_param_id_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_etc_pd_parameter_id,
      { "ID (ETC)", "rdm.pd.parameter.id",
        FT_UINT16, BASE_HEX | BASE_EXT_STRING, &etc_param_id_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_rdm_etc_pd_device_model_id,
      { "Device Model ID", "rdm.pd.device_model_id",
        FT_UINT16, BASE_HEX, VALS(etc_model_id_vals), 0x0,
        NULL, HFILL }},
  };

  static int *ett[] = {
    &ett_rdm,
    &ett_rdm_mdb,
    &ett_rdm_pd,
    &ett_rdm_uid,
    &ett_rdm_controller_flags,
    &ett_rdm_packed_pid_data,
    &ett_rdm_pd_sensor_recorded_value_support,
    &ett_rdm_pd_disc_mute_control_field,
    &ett_rdm_pd_disc_unmute_control_field,
    &ett_rdm_pd_comms_status_nsc_supported_fields,
    &ett_rdm_pd_supported_parameters_pid_support,
    &ett_rdm_pd_controller_flag_support_flags,
    &ett_rdm_pd_selftest_capability,
    &ett_rdm_pd_ftc_response_data,
    &ett_rdm_pd_ftc_transfer_flags,
    &ett_rdm_pd_ftc_capabilities,
    &ett_rdm_pd_ftc_commit_flags
  };

  static ei_register_info ei[] = {
    { &ei_rdm_checksum, { "rdm.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
    { &ei_rdm_parameter_data_length, { "rdm.pdl.mismatch", PI_PROTOCOL, PI_WARN, "Parameter Data Length Mismatch", EXPFILL }},
    { &ei_rdm_ftc_crc, { "rdm.bad_ftc_crc", PI_CHECKSUM, PI_ERROR, "Bad FTC Packet CRC", EXPFILL }},
  };

  expert_module_t* expert_rdm;

  proto_rdm = proto_register_protocol("Remote Device Management", "RDM", "rdm");
  proto_register_field_array(proto_rdm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  rdm_handle = register_dissector("rdm", dissect_rdm, proto_rdm);
  expert_rdm = expert_register_protocol(proto_rdm);
  expert_register_field_array(expert_rdm, ei, array_length(ei));

  rdm_manf_dissector_table = register_dissector_table("rdm.manf_id", "RDM Manufacturer ID", proto_rdm, FT_UINT16, BASE_HEX);
}

void
proto_reg_handoff_rdm(void) {
  dissector_add_uint("dmx", 0xCC, rdm_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
