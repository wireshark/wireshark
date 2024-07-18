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
#include <epan/expert.h>
#include "packet-rdm.h"
#include "packet-arp.h"

void proto_register_rdm(void);
void proto_reg_handoff_rdm(void);

static dissector_handle_t rdm_handle;

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

#define RDM_RESPONSE_TYPE_ACK           0x00
#define RDM_RESPONSE_TYPE_ACK_TIMER     0x01
#define RDM_RESPONSE_TYPE_NACK_REASON   0x02
#define RDM_RESPONSE_TYPE_ACK_OVERFLOW  0x03

static const value_string rdm_rt_vals[] = {
  { RDM_RESPONSE_TYPE_ACK,           "Ack" },
  { RDM_RESPONSE_TYPE_ACK_TIMER,     "Ack Timer" },
  { RDM_RESPONSE_TYPE_NACK_REASON,   "Nack Reason" },
  { RDM_RESPONSE_TYPE_ACK_OVERFLOW,  "Ack Overflow" },
  { 0, NULL },
};

#define RDM_NR_UNKNOWN_PID                 0x0000
#define RDM_NR_FORMAT_ERROR                0x0001
#define RDM_NR_HARDWARE_FAULT              0x0002
#define RDM_NR_PROXY_REJECT                0x0003
#define RDM_NR_WRITE_PROTECT               0x0004
#define RDM_NR_UNSUPPORTED_COMMAND_CLASS   0x0005
#define RDM_NR_DATA_OUT_OF_RANGE           0x0006
#define RDM_NR_BUFFER_FULL                 0x0007
#define RDM_NR_PACKET_SIZE_UNSUPPORTED     0x0008
#define RDM_NR_SUB_DEVICE_OUT_OF_RANGE     0x0009
#define RDM_NR_PROXY_BUFFER_FULL           0x000A
#define RDM_NR_ACTION_NOT_SUPPORTED        0x000B  /* E1.37-2 */
#define RDM_NR_ENDPOINT_NUMBER_INVALID     0x000C  /* E1.37-7 */
#define RDM_NR_INVALID_ENDPOINT_MODE       0x000D
#define RDM_NR_UNKNOWN_UID                 0x000E

#define RDM_NR_UNKNOWN_SCOPE               0x000F  /* E1.33 */
#define RDM_NR_INVALID_STATIC_CONFIG_TYPE  0x0010  /* E1.33 */
#define RDM_NR_INVALID_IPV4_ADDRESS        0x0011  /* E1.33 */
#define RDM_NR_INVALID_IPV6_ADDRESS        0x0012  /* E1.33 */
#define RDM_NR_INVALID_PORT                0x0013  /* E1.33 */

static const value_string rdm_nr_vals[] = {
  { RDM_NR_UNKNOWN_PID,                 "Unknown PID" },
  { RDM_NR_FORMAT_ERROR,                "Format Error" },
  { RDM_NR_HARDWARE_FAULT,              "Hardware Fault" },
  { RDM_NR_PROXY_REJECT,                "Proxy Reject" },
  { RDM_NR_WRITE_PROTECT,               "Write Protect" },
  { RDM_NR_UNSUPPORTED_COMMAND_CLASS,   "Unsupported Command Class" },
  { RDM_NR_DATA_OUT_OF_RANGE,           "Data Out Of Range" },
  { RDM_NR_BUFFER_FULL,                 "Buffer Full" },
  { RDM_NR_PACKET_SIZE_UNSUPPORTED,     "Packet Size Unsupported" },
  { RDM_NR_SUB_DEVICE_OUT_OF_RANGE,     "Sub-Device Out Of Range" },
  { RDM_NR_PROXY_BUFFER_FULL,           "Proxy Buffer Full" },
  { RDM_NR_ACTION_NOT_SUPPORTED,        "Action Not Supported" },  /* E1.37-2 */
  { RDM_NR_ENDPOINT_NUMBER_INVALID,     "Endpoint Number Invalid" },  /* E1.37-7 */
  { RDM_NR_INVALID_ENDPOINT_MODE,       "Invalid Endpoint Mode" },
  { RDM_NR_UNKNOWN_UID,                 "Unknown UID" },
  { RDM_NR_UNKNOWN_SCOPE,               "Unknown Scope" },    /* E1.33 */
  { RDM_NR_INVALID_STATIC_CONFIG_TYPE,  "Invalid Static Config Type" },
  { RDM_NR_INVALID_IPV4_ADDRESS,        "Invalid IPv4 Address" },
  { RDM_NR_INVALID_IPV6_ADDRESS,        "Invalid IPv6 Address" },
  { RDM_NR_INVALID_PORT,                "Invalid Port" },
  { 0, NULL },
};

/* E1.20, E1.33, and E1.37 PIDs */
#define RDM_PARAM_ID_DISC_UNIQUE_BRANCH                           0x0001
#define RDM_PARAM_ID_DISC_MUTE                                    0x0002
#define RDM_PARAM_ID_DISC_UN_MUTE                                 0x0003
#define RDM_PARAM_ID_PROXIED_DEVICES                              0x0010
#define RDM_PARAM_ID_PROXIED_DEVICE_COUNT                         0x0011
#define RDM_PARAM_ID_COMMS_STATUS                                 0x0015
#define RDM_PARAM_ID_QUEUED_MESSAGE                               0x0020
#define RDM_PARAM_ID_STATUS_MESSAGES                              0x0030
#define RDM_PARAM_ID_STATUS_ID_DESCRIPTION                        0x0031
#define RDM_PARAM_ID_CLEAR_STATUS_ID                              0x0032
#define RDM_PARAM_ID_SUB_DEVICE_STATUS_REPORT_THRESHOLD           0x0033
#define RDM_PARAM_ID_SUPPORTED_PARAMETERS                         0x0050
#define RDM_PARAM_ID_PARAMETER_DESCRIPTION                        0x0051
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
#define RDM_PARAM_ID_DMX_PERSONALITY                              0x00E0
#define RDM_PARAM_ID_DMX_PERSONALITY_DESCRIPTION                  0x00E1
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
#define RDM_PARAM_ID_SEARCH_DOMAIN                                0x0801  /* E1.33 */
#define RDM_PARAM_ID_TCP_COMMS_STATUS                             0x0802  /* E1.33 */
#define RDM_PARAM_ID_BROKER_STATUS                                0x0803  /* E1.33 */

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
#define RDM_PARAM_ID_CAPTURE_PRESET                               0x1030
#define RDM_PARAM_ID_PRESET_PLAYBACK                              0x1031

#define RDM_PARAM_ID_IDENTIFY_MODE                                0x1040  /* E1.37-1 */
#define RDM_PARAM_ID_PRESET_INFO                                  0x1041
#define RDM_PARAM_ID_PRESET_STATUS                                0x1042
#define RDM_PARAM_ID_PRESET_MERGEMODE                             0x1043
#define RDM_PARAM_ID_POWER_ON_SELF_TEST                           0x1044

const value_string rdm_param_id_vals[] = {
  { RDM_PARAM_ID_DISC_UNIQUE_BRANCH,                  "Discovery Unique Branch" },
  { RDM_PARAM_ID_DISC_MUTE,                           "Discovery Mute" },
  { RDM_PARAM_ID_DISC_UN_MUTE,                        "Discovery Un-Mute" },
  { RDM_PARAM_ID_PROXIED_DEVICES,                     "Proxied Devices" },
  { RDM_PARAM_ID_PROXIED_DEVICE_COUNT,                "Proxied Device Count" },
  { RDM_PARAM_ID_COMMS_STATUS,                        "Communication Status" },
  { RDM_PARAM_ID_QUEUED_MESSAGE,                      "Queued Messages" },
  { RDM_PARAM_ID_STATUS_MESSAGES,                     "Status Messages" },
  { RDM_PARAM_ID_STATUS_ID_DESCRIPTION,               "Status ID Description" },
  { RDM_PARAM_ID_CLEAR_STATUS_ID,                     "Clear Status ID" },
  { RDM_PARAM_ID_SUB_DEVICE_STATUS_REPORT_THRESHOLD,  "Device Status Reporting Threshold" },
  { RDM_PARAM_ID_SUPPORTED_PARAMETERS,                "Supported Parameters" },
  { RDM_PARAM_ID_PARAMETER_DESCRIPTION,               "Parameter Description" },
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
  { RDM_PARAM_ID_DMX_PERSONALITY,                     "DMX Personality" },
  { RDM_PARAM_ID_DMX_PERSONALITY_DESCRIPTION,         "DMX Personality Description" },
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

  { RDM_PARAM_ID_COMPONENT_SCOPE,                     "Component Scope" },
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
  { RDM_PARAM_ID_CAPTURE_PRESET,                      "Capture Preset" },
  { RDM_PARAM_ID_PRESET_PLAYBACK,                     "Preset Playback" },

  { RDM_PARAM_ID_IDENTIFY_MODE,                       "Identify Mode" },  /* E1.37-1 */
  { RDM_PARAM_ID_PRESET_INFO,                         "Preset Info" },
  { RDM_PARAM_ID_PRESET_STATUS,                       "Preset Status" },
  { RDM_PARAM_ID_PRESET_MERGEMODE,                    "Preset Merge Mode" },
  { RDM_PARAM_ID_POWER_ON_SELF_TEST,                  "Power On Self Test" },

  { 0, NULL },
};

value_string_ext rdm_param_id_vals_ext = VALUE_STRING_EXT_INIT(rdm_param_id_vals);

/* manufacturer IDs */
#define RDM_MANUFACTURER_ID_ETC    0x6574

#define RDM_STATUS_NONE              0x00
#define RMD_STATUS_GET_LAST_MESSAGE  0x01
#define RDM_STATUS_ADVISORY          0x02
#define RDM_STATUS_WARNING           0x03
#define RDM_STATUS_ERROR             0x04

static const value_string rdm_status_vals[] = {
  { RDM_STATUS_NONE,              "None" },
  { RMD_STATUS_GET_LAST_MESSAGE,  "Get Last Message" },
  { RDM_STATUS_ADVISORY,          "Advisory" },
  { RDM_STATUS_WARNING,           "Warning" },
  { RDM_STATUS_ERROR,             "Error" },
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
  { 0, NULL },
};
static value_string_ext rdm_unit_vals_ext = VALUE_STRING_EXT_INIT(rdm_unit_vals);

#define RDM_SENS_TEMPERATURE         0x00
#define RDM_SENS_VOLTAGE             0x01
#define RDM_SENS_CURRENT             0x02
#define RDM_SENS_FREQUENCY           0x03
#define RDM_SENS_RESISTANCE          0x04
#define RDM_SENS_POWER               0x05
#define RDM_SENS_MASS                0x06
#define RDM_SENS_LENGTH              0x07
#define RDM_SENS_AREA                0x08
#define RDM_SENS_VOLUME              0x09
#define RDM_SENS_DENSITY             0x0A
#define RDM_SENS_VELOCITY            0x0B
#define RDM_SENS_ACCELERATION        0x0C
#define RDM_SENS_FORCE               0x0D
#define RDM_SENS_ENERGY              0x0E
#define RDM_SENS_PRESSURE            0x0F
#define RDM_SENS_TIME                0x10
#define RDM_SENS_ANGLE               0x11
#define RDM_SENS_POSITION_X          0x12
#define RDM_SENS_POSITION_Y          0x13
#define RDM_SENS_POSITION_Z          0x14
#define RDM_SENS_ANGULAR_VELOCITY    0x15
#define RDM_SENS_LUMINOUS_INTENSITY  0x16
#define RDM_SENS_LUMINOUS_FLUX       0x17
#define RDM_SENS_ILLUMINANCE         0x18
#define RDM_SENS_CHROMINANCE_RED     0x19
#define RDM_SENS_CHROMINANCE_GREEN   0x1A
#define RDM_SENS_CHROMINANCE_BLUE    0x1B
#define RDM_SENS_CONTACTS            0x1C
#define RDM_SENS_MEMORY              0x1D
#define RDM_SENS_ITEMS               0x1E
#define RDM_SENS_HUMIDITY            0x1F
#define RDM_SENS_COUNTER_16BIT       0x20
#define RDM_SENS_OTHER               0x7F

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
  { RDM_SENS_OTHER,               "Other" },
  { 0, NULL} ,
};
static value_string_ext rdm_sensor_type_vals_ext = VALUE_STRING_EXT_INIT(rdm_sensor_type_vals);

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
static int hf_rdm_src_uid;
static int hf_rdm_transaction_number;
static int hf_rdm_port_id;
static int hf_rdm_response_type;
static int hf_rdm_message_count;
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
static int hf_rdm_pd_sensor_description;

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
static int hf_rdm_pd_disc_mute_binding_uid;
static int hf_rdm_pd_disc_unmute_control_field;
static int hf_rdm_pd_disc_unmute_binding_uid;
static int hf_rdm_pd_proxied_devices_uid;
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
static int hf_rdm_pd_comms_status_short_msg;
static int hf_rdm_pd_comms_status_len_mismatch;
static int hf_rdm_pd_comms_status_csum_fail;
static int hf_rdm_pd_status_messages_type;
static int hf_rdm_pd_status_messages_sub_device_id;
static int hf_rdm_pd_status_messages_id;
static int hf_rdm_pd_status_messages_data_value_1;
static int hf_rdm_pd_status_messages_data_value_2;
static int hf_rdm_pd_status_id;
static int hf_rdm_pd_status_id_description;
static int hf_rdm_pd_sub_device_status_report_threshold_status_type;
static int hf_rdm_pd_product_detail_id_list;
static int hf_rdm_pd_factory_defaults;
static int hf_rdm_pd_background_discovery_endpoint_id;
static int hf_rdm_pd_background_discovery_enabled;
static int hf_rdm_pd_background_queued_status_policy_current_policy;
static int hf_rdm_pd_background_queued_status_policy_number_of_policies;
static int hf_rdm_pd_background_queued_status_policy_description_policy;
static int hf_rdm_pd_background_queued_status_policy_description_description;
static int hf_rdm_pd_binding_control_fields_endpoint_id;
static int hf_rdm_pd_binding_control_fields_uid;
static int hf_rdm_pd_binding_control_fields_control_field;
static int hf_rdm_pd_binding_control_fields_binding_uid;
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
static int hf_rdm_pd_modulation_frequency_description_text;
static int hf_rdm_pd_output_response_time_response_time;
static int hf_rdm_pd_output_response_time_number_of_response_times;
static int hf_rdm_pd_output_response_time_description_output_response_time;
static int hf_rdm_pd_output_response_time_description_text;
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
static int hf_rdm_pd_slot_offset;
static int hf_rdm_pd_slot_type;
static int hf_rdm_pd_slot_label_id;
static int hf_rdm_pd_slot_nr;
static int hf_rdm_pd_slot_description;
static int hf_rdm_pd_slot_value;
static int hf_rdm_pd_static_address_interface_identifier;
static int hf_rdm_pd_static_address_ipv4_address;
static int hf_rdm_pd_static_address_netmask;
static int hf_rdm_pd_tcp_comms_status_scope_string;
static int hf_rdm_pd_tcp_comms_status_broker_ipv4_address;
static int hf_rdm_pd_tcp_comms_status_broker_ipv6_address;
static int hf_rdm_pd_tcp_comms_status_broker_port;
static int hf_rdm_pd_tcp_comms_status_unhealthy_tcp_events;
static int hf_rdm_pd_zeroconf_mode_interface_identifier;
static int hf_rdm_pd_zeroconf_mode_enabled;
static int hf_rdm_pd_rec_value_support;

static int ett_rdm;

static expert_field ei_rdm_checksum;

/* begin manufacturer-specific constants and variables */
/* begin ETC */

/* ETC manufacturer-specific PIDs */
#define ETC_PARAM_ID_LED_CURVE                             0x8101
#define ETC_PARAM_ID_LED_CURVE_DESCRIPTION                 0x8102
#define ETC_PARAM_ID_LED_STROBE                            0x8103
#define ETC_PARAM_ID_LED_OUTPUT_MODE                       0x8104
#define ETC_PARAM_ID_LED_OUTPUT_MODE_DESCRIPTION           0x8105
#define ETC_PARAM_ID_LED_RED_SHIFT                         0x8106
#define ETC_PARAM_ID_LED_WHITE_POINT                       0x8107
#define ETC_PARAM_ID_LED_WHITE_POINT_DESCRIPTION           0x8108
#define ETC_PARAM_ID_LED_FREQUENCY                         0x8109
#define ETC_PARAM_ID_DMX_LOSS_BEHAVIOR                     0x810A
#define ETC_PARAM_ID_DMX_LOSS_BEHAVIOR_DESCRIPTION         0x810B
#define ETC_PARAM_ID_LED_PLUS_SEVEN                        0x810C
#define ETC_PARAM_ID_BACKLIGHT_BRIGHTNESS                  0x810D
#define ETC_PARAM_ID_BACKLIGHT_TIMEOUT                     0x810E
#define ETC_PARAM_ID_STATUS_INDICATORS                     0x810F
#define ETC_PARAM_ID_RECALIBRATE_FIXTURE                   0x8110
#define ETC_PARAM_ID_OVERTEMPMODE                          0x8111
#define ETC_PARAM_ID_SIMPLESETUPMODE                       0x8112
#define ETC_PARAM_ID_LED_STROBE_DESCRIPTION                0x8113
#define ETC_PARAM_ID_LED_RED_SHIFT_DESCRIPTION             0x8114
#define ETC_PARAM_ID_LED_PLUS_SEVEN_DESCRIPTION            0x8115
#define ETC_PARAM_ID_BACKLIGHT_TIMEOUT_DESCRIPTION         0x8116
#define ETC_PARAM_ID_SIMPLESETUPMODE_DESCRIPTION           0x8117
#define ETC_PARAM_ID_OVERTEMPMODE_DESCRIPTION              0x8118
#define ETC_PARAM_ID_LED_REQUESTED_XY                      0x8119
#define ETC_PARAM_ID_LED_CURRENT_XY                        0x811A
#define ETC_PARAM_ID_LED_CURRENT_PWM                       0x811B
#define ETC_PARAM_ID_LED_TRISTIMULUS                       0x811C
#define ETC_PARAM_ID_LED_INFORMATION                       0x811D
#define ETC_PARAM_ID_PRESETCONFIG                          0x811E
#define ETC_PARAM_ID_SEQUENCE_PLAYBACK                     0x811F
#define ETC_PARAM_ID_SEQUENCE_CONFIG                       0x8120
#define ETC_PARAM_ID_LOW_POWER_TIMEOUT                     0x8121
#define ETC_PARAM_ID_LOW_POWER_TIMEOUT_DESCRIPTION         0x8122
#define ETC_PARAM_ID_LED_ENUM_FREQUENCY                    0x8123
#define ETC_PARAM_ID_LED_ENUM_FREQUENCY_DESCRIPTION        0x8124
#define ETC_PARAM_ID_RGBI_PRESETCONFIG                     0x8125
#define ETC_PARAM_ID_CCT_PRESETCONFIG                      0x8126
#define ETC_PARAM_ID_SUPPLEMENTARY_DEVICE_VERSION          0x8130
/* do not display
#define ETC_PARAM_ID_START_UWB_DISCOVER                    0x8150
#define ETC_PARAM_ID_START_UWB_MEASURE                     0x8151
#define ETC_PARAM_ID_POSITION                              0x8152
*/
#define ETC_PARAM_ID_S4DIM_CALIBRATE                       0x9000
#define ETC_PARAM_ID_S4DIM_CALIBRATE_DESCRIPTION           0x9001
#define ETC_PARAM_ID_S4DIM_TEST_MODE                       0x9002
#define ETC_PARAM_ID_S4DIM_TEST_MODE_DESCRIPTION           0x9003
#define ETC_PARAM_ID_S4DIM_MAX_OUTPUT_VOLTAGE              0x9004
#define ETC_PARAM_ID_S4DIM_MAX_OUTPUT_VOLTAGE_DESCRIPTION  0x9005
#define ETC_PARAM_ID_POWER_COMMAND                         0xA000
#define ETC_PARAM_ID_POWER_COMMAND_DESCRIPTION             0xA001
#define ETC_PARAM_ID_THRESHOLD_COMMAND                     0xA002
#define ETC_PARAM_ID_TURNON_DELAY_COMMAND                  0xA003
#define ETC_PARAM_ID_SET_DALI_SHORTADDRESS                 0xA004
#define ETC_PARAM_ID_DALI_GROUP_MEMBERSHIP                 0xA005
#define ETC_PARAM_ID_AUTOBIND                              0xA006
#define ETC_PARAM_ID_DELETE_SUBDEVICE                      0xA007
#define ETC_PARAM_ID_PACKET_DELAY                          0xB000
#define ETC_PARAM_ID_HAS_ENUM_TEXT                         0xE000
#define ETC_PARAM_ID_GET_ENUM_TEXT                         0xE001
#define ETC_PARAM_ID_PREPAREFORSOFTWAREDOWNLOAD            0xF000

static const value_string etc_param_id_vals[] = {
  { ETC_PARAM_ID_LED_CURVE,                             "LED Curve" },
  { ETC_PARAM_ID_LED_CURVE_DESCRIPTION,                 "LED Curve Description" },
  { ETC_PARAM_ID_LED_STROBE,                            "LED Strobe" },
  { ETC_PARAM_ID_LED_OUTPUT_MODE,                       "LED Output Mode" },
  { ETC_PARAM_ID_LED_OUTPUT_MODE_DESCRIPTION,           "LED Output Mode Description" },
  { ETC_PARAM_ID_LED_RED_SHIFT,                         "LED Red Shift" },
  { ETC_PARAM_ID_LED_WHITE_POINT,                       "LED White Point" },
  { ETC_PARAM_ID_LED_WHITE_POINT_DESCRIPTION,           "LED White Point Description" },
  { ETC_PARAM_ID_LED_FREQUENCY,                         "LED Frequency" },
  { ETC_PARAM_ID_DMX_LOSS_BEHAVIOR,                     "DMX Loss Behavior" },
  { ETC_PARAM_ID_DMX_LOSS_BEHAVIOR_DESCRIPTION,         "DMX Loss Behavior Description" },
  { ETC_PARAM_ID_LED_PLUS_SEVEN,                        "LED Plus Seven" },
  { ETC_PARAM_ID_BACKLIGHT_BRIGHTNESS,                  "Backlight Brightness" },
  { ETC_PARAM_ID_BACKLIGHT_TIMEOUT,                     "Backlight Timeout" },
  { ETC_PARAM_ID_STATUS_INDICATORS,                     "Status Indicators" },
  { ETC_PARAM_ID_RECALIBRATE_FIXTURE,                   "Recalibrate Fixture" },
  { ETC_PARAM_ID_OVERTEMPMODE,                          "Overtemp Mode" },
  { ETC_PARAM_ID_SIMPLESETUPMODE,                       "Simple Setup Mode" },
  { ETC_PARAM_ID_LED_STROBE_DESCRIPTION,                "LED Strobe Description" },
  { ETC_PARAM_ID_LED_RED_SHIFT_DESCRIPTION,             "LED Red Shift Description" },
  { ETC_PARAM_ID_LED_PLUS_SEVEN_DESCRIPTION,            "LED Plus Seven Description" },
  { ETC_PARAM_ID_BACKLIGHT_TIMEOUT_DESCRIPTION,         "Backlight Timeout Description" },
  { ETC_PARAM_ID_SIMPLESETUPMODE_DESCRIPTION,           "Simple Setup Mode Description" },
  { ETC_PARAM_ID_OVERTEMPMODE_DESCRIPTION,              "Overtemp Mode Description" },
  { ETC_PARAM_ID_LED_REQUESTED_XY,                      "LED Requested XY" },
  { ETC_PARAM_ID_LED_CURRENT_XY,                        "LED Current XY" },
  { ETC_PARAM_ID_LED_CURRENT_PWM,                       "LED Current PWM" },
  { ETC_PARAM_ID_LED_TRISTIMULUS,                       "LED Tristimulus" },
  { ETC_PARAM_ID_LED_INFORMATION,                       "LED Information" },
  { ETC_PARAM_ID_PRESETCONFIG,                          "Preset Config" },
  { ETC_PARAM_ID_SEQUENCE_PLAYBACK,                     "Sequence Playback" },
  { ETC_PARAM_ID_SEQUENCE_CONFIG,                       "Sequence Config" },
  { ETC_PARAM_ID_LOW_POWER_TIMEOUT,                     "Low Power Timeout" },
  { ETC_PARAM_ID_LOW_POWER_TIMEOUT_DESCRIPTION,         "Low Power Timeout Description" },
  { ETC_PARAM_ID_LED_ENUM_FREQUENCY,                    "LED Enum Frequency" },
  { ETC_PARAM_ID_LED_ENUM_FREQUENCY_DESCRIPTION,        "LED Enum Frequency Description" },
  { ETC_PARAM_ID_RGBI_PRESETCONFIG,                     "RGBI Preset Config" },
  { ETC_PARAM_ID_CCT_PRESETCONFIG,                      "CCT Preset Config" },
  { ETC_PARAM_ID_SUPPLEMENTARY_DEVICE_VERSION,          "Supplementary Device Version" },
  /* do not display
  { ETC_PARAM_ID_START_UWB_DISCOVER,                    "Start UWB Discover" },
  { ETC_PARAM_ID_START_UWB_MEASURE,                     "Start UWB Measure" },
  { ETC_PARAM_ID_POSITION,                              "Position" },
  */
  { ETC_PARAM_ID_S4DIM_CALIBRATE,                       "S4Dimmer Calibrate" },
  { ETC_PARAM_ID_S4DIM_CALIBRATE_DESCRIPTION,           "S4Dimmer Calibrate Description" },
  { ETC_PARAM_ID_S4DIM_TEST_MODE,                       "S4Dimmer Test Mode" },
  { ETC_PARAM_ID_S4DIM_TEST_MODE_DESCRIPTION,           "S4Dimmer Test Mode Description" },
  { ETC_PARAM_ID_S4DIM_MAX_OUTPUT_VOLTAGE,              "S4Dimmer Max Output Voltage" },
  { ETC_PARAM_ID_S4DIM_MAX_OUTPUT_VOLTAGE_DESCRIPTION,  "S4Dimmer Max Output Voltage Description" },
  { ETC_PARAM_ID_POWER_COMMAND,                         "Power Command" },
  { ETC_PARAM_ID_POWER_COMMAND_DESCRIPTION,             "Power Command Description" },
  { ETC_PARAM_ID_THRESHOLD_COMMAND,                     "Threshold Command" },
  { ETC_PARAM_ID_TURNON_DELAY_COMMAND,                  "Turn On Delay Command" },
  { ETC_PARAM_ID_SET_DALI_SHORTADDRESS,                 "Set DALI Short Address" },
  { ETC_PARAM_ID_DALI_GROUP_MEMBERSHIP,                 "DALI Group Membership" },
  { ETC_PARAM_ID_AUTOBIND,                              "Auto Bind" },
  { ETC_PARAM_ID_DELETE_SUBDEVICE,                      "Delete Subdevice" },
  { ETC_PARAM_ID_PACKET_DELAY,                          "Packet Delay" },
  { ETC_PARAM_ID_HAS_ENUM_TEXT,                         "Has Enum Text" },
  { ETC_PARAM_ID_GET_ENUM_TEXT,                         "Get Enum Text" },
  { ETC_PARAM_ID_PREPAREFORSOFTWAREDOWNLOAD,            "Prepare For Software Load" },
  { 0, NULL },
};

static value_string_ext etc_param_id_vals_ext = VALUE_STRING_EXT_INIT(etc_param_id_vals);

#define ETC_LED_CURVE_STANDARD      0x00
#define ETC_LED_CURVE_INCANDESCENT  0x01
#define ETC_LED_CURVE_LINEAR        0x02
#define ETC_LED_CURVE_QUICK         0x03

static const value_string etc_led_curve_vals[] = {
  { ETC_LED_CURVE_STANDARD,      "Standard" },
  { ETC_LED_CURVE_INCANDESCENT,  "Incandescent" },
  { ETC_LED_CURVE_LINEAR,        "Linear" },
  { ETC_LED_CURVE_QUICK,         "Quick" },
  { 0, NULL },
};

#define ETC_LED_OUTPUT_MODE_REGULATED  0x00
#define ETC_LED_OUTPUT_MODE_BOOST      0x01
#define ETC_LED_OUTPUT_MODE_PROTECTED  0x02

static const value_string etc_led_output_mode_vals[] = {
  { ETC_LED_OUTPUT_MODE_REGULATED,  "Regulated" },
  { ETC_LED_OUTPUT_MODE_BOOST,      "Boost" },
  { ETC_LED_OUTPUT_MODE_PROTECTED,  "Protected" },
  { 0, NULL },
};

#define ETC_LED_WHITE_POINT_2950K    0x00
#define ETC_LED_WHITE_POINT_3200K    0x01
#define ETC_LED_WHITE_POINT_5600K    0x02
#define ETC_LED_WHITE_POINT_6500K    0x03

static const value_string etc_led_white_point_vals[] = {
  { ETC_LED_WHITE_POINT_2950K,    "2950 K" },
  { ETC_LED_WHITE_POINT_3200K,    "3200 K" },
  { ETC_LED_WHITE_POINT_5600K,    "5600 K" },
  { ETC_LED_WHITE_POINT_6500K,    "6500 K" },
  { 0, NULL },
};

#define ETC_DMX_LOSS_BEHAVIOR_INSTANT   0x00
#define ETC_DMX_LOSS_BEHAVIOR_WAIT2MIN  0x01
#define ETC_DMX_LOSS_BEHAVIOR_HLL       0x02

static const value_string etc_dmx_data_loss_vals[] = {
  { ETC_DMX_LOSS_BEHAVIOR_INSTANT,   "Instant" },
  { ETC_DMX_LOSS_BEHAVIOR_WAIT2MIN,  "Hold Last Look 2 Minutes" },
  { ETC_DMX_LOSS_BEHAVIOR_HLL,       "Hold Last Look Forever" },
  { 0, NULL },
};

#define ETC_DMX_BACKLIGHT_TIMEOUT_NEVER  0x00
#define ETC_DMX_BACKLIGHT_TIMEOUT_30SEC  0x01
#define ETC_DMX_BACKLIGHT_TIMEOUT_1MIN   0x02
#define ETC_DMX_BACKLIGHT_TIMEOUT_5MIN   0x03
#define ETC_DMX_BACKLIGHT_TIMEOUT_15MIN  0x04

static const value_string etc_backlight_timeout_vals[] = {
  { ETC_DMX_BACKLIGHT_TIMEOUT_NEVER,  "Never" },
  { ETC_DMX_BACKLIGHT_TIMEOUT_30SEC,  "30 Seconds" },
  { ETC_DMX_BACKLIGHT_TIMEOUT_1MIN,   "1 Minute" },
  { ETC_DMX_BACKLIGHT_TIMEOUT_5MIN,   "5 Minute" },
  { ETC_DMX_BACKLIGHT_TIMEOUT_15MIN,  "15 Minute" },
  { 0, NULL },
};

#define ETC_OVERTEMP_MODE_DARK     0x00
#define ETC_OVERTEMP_MODE_VISIBLE  0x01

static const value_string etc_overtemp_mode_vals[] = {
  { ETC_OVERTEMP_MODE_DARK,     "Dark When Overtemp" },
  { ETC_OVERTEMP_MODE_VISIBLE,  "Red When Overtemp" },
  { 0, NULL },
};

#define ETC_EASY_MODE_GENERAL   0x00
#define ETC_EASY_MODE_STAGE     0x01
#define ETC_EASY_MODE_ARCH      0x02
#define ETC_EASY_MODE_EFFECTS   0x03
#define ETC_EASY_MODE_STUDIO    0x04
#define ETC_EASY_MODE_ADVANCED  0x05

static const value_string etc_simple_setup_mode_vals[] = {
  { ETC_EASY_MODE_GENERAL,   "General Use" },
  { ETC_EASY_MODE_STAGE,     "Stage Setup" },
  { ETC_EASY_MODE_ARCH,      "Arch Setup" },
  { ETC_EASY_MODE_EFFECTS,   "Effects Setup" },
  { ETC_EASY_MODE_STUDIO,    "Studio Setup" },
  { ETC_EASY_MODE_ADVANCED,  "Advanced Setup" },
  { 0, NULL },
};

#define ETC_LOW_POWER_TIMEOUT_NEVER   0x00
#define ETC_LOW_POWER_TIMEOUT_15MIN   0x01
#define ETC_LOW_POWER_TIMEOUT_30MIN   0x02
#define ETC_LOW_POWER_TIMEOUT_1HOUR   0x03
#define ETC_LOW_POWER_TIMEOUT_4HOURS  0x04
#define ETC_LOW_POWER_TIMEOUT_8HOURS  0x05

static const value_string etc_low_power_timeout_vals[] = {
  { ETC_LOW_POWER_TIMEOUT_NEVER,   "Never" },
  { ETC_LOW_POWER_TIMEOUT_15MIN,   "15 Minutes" },
  { ETC_LOW_POWER_TIMEOUT_30MIN,   "30 Minutes" },
  { ETC_LOW_POWER_TIMEOUT_1HOUR,   "1 Hour" },
  { ETC_LOW_POWER_TIMEOUT_4HOURS,  "4 Hours" },
  { ETC_LOW_POWER_TIMEOUT_8HOURS,  "8 Hours" },
  { 0, NULL },
};

#define ETC_LED_FREQ_ENUM_1200HZ   0x00
#define ETC_LED_FREQ_ENUM_25000HZ  0x01

static const value_string etc_led_frequency_enum_vals[] = {
  { ETC_LED_FREQ_ENUM_1200HZ,   "1.2 kHz" },
  { ETC_LED_FREQ_ENUM_25000HZ,  "25 kHz" },
  { 0, NULL },
};

#define ETC_MODEL_ID_SMARTBAR                           0x0001
#define ETC_MODEL_ID_SOURCE_4_LED_LUSTR_PLUS            0x0101
#define ETC_MODEL_ID_DESIRE_ICE_40_LED                  0x0102
#define ETC_MODEL_ID_DESIRE_FIRE_40_LED                 0x0103
#define ETC_MODEL_ID_SOURCE_4_LED_TUNGSTEN              0x0107
#define ETC_MODEL_ID_SOURCE_4_LED_DAYLIGHT              0x0108
#define ETC_MODEL_ID_DESIRE_VIVID_40_LED                0x0109
#define ETC_MODEL_ID_DESIRE_LUSTR_60_LED_OBS            0x0111
#define ETC_MODEL_ID_DESIRE_ICE_60_LED                  0x0112
#define ETC_MODEL_ID_DESIRE_FIRE_60_LED                 0x0113
#define ETC_MODEL_ID_DESIRE_VIVID_60_LED                0x0119
#define ETC_MODEL_ID_DESIRE_STUDIO_40_LED               0x0121
#define ETC_MODEL_ID_DESIRE_STUDIO_60_LED               0x0129
#define ETC_MODEL_ID_DESIRE_LUSTR_40_LED                0x0131
#define ETC_MODEL_ID_DESIRE_LUSTR_60_LED                0x0139
#define ETC_MODEL_ID_DESIRE_DAYLIGHT_40_LED             0x0141
#define ETC_MODEL_ID_DESIRE_TUNGSTEN_40_LED             0x0142
#define ETC_MODEL_ID_DESIRE_DAYLIGHT_60_LED             0x0149
#define ETC_MODEL_ID_DESIRE_TUNGSTEN_60_LED             0x014A
#define ETC_MODEL_ID_DESIRE_D22_LUSTR_PLUS_LED          0x0151
#define ETC_MODEL_ID_DESIRE_D22_DAYLIGHT_LED            0x0159
#define ETC_MODEL_ID_DESIRE_D22_TUNGSTEN_LED            0x015A
#define ETC_MODEL_ID_SOURCE_4_LED_STUDIO_HD             0x0179
#define ETC_MODEL_ID_SOURCE_4_LED_SERIES_2_LUSTR        0x0181
#define ETC_MODEL_ID_DESIRE_D22_STUDIO_HD               0x0189
#define ETC_MODEL_ID_SOURCE_4_LED_SERIES_2_TUNGSTEN_HD  0x0191
#define ETC_MODEL_ID_SOURCE_4_LED_SERIES_2_DAYLIGHT_HD  0x0199
#define ETC_MODEL_ID_COLORSOURCE_BOOTLOADER             0x0200
#define ETC_MODEL_ID_COLORSOURCE_PAR                    0x0201
#define ETC_MODEL_ID_COLORSOURCE_PAR_DEEP_BLUE          0x0202
#define ETC_MODEL_ID_COLORSOURCE_PAR_PEARL              0x0203
#define ETC_MODEL_ID_COLORSOURCE_SPOT                   0x0205
#define ETC_MODEL_ID_COLORSOURCE_SPOT_DEEP_BLUE         0x0206
#define ETC_MODEL_ID_COLORSOURCE_SPOT_PEARL             0x0207
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_1               0x0209
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_1_DEEP_BLUE     0x020A
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_1_PEARL         0x020B
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_2               0x020D
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_2_DEEP_BLUE     0x020E
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_2_PEARL         0x020F
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_4               0x0211
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_4_DEEP_BLUE     0x0212
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_4_PEARL         0x0213
#define ETC_MODEL_ID_COLORSOURCE_CYC                    0x0215
#define ETC_MODEL_ID_SOURCE_FORWARD_120V                0x0800
#define ETC_MODEL_ID_SOURCE_FORWARD_230V                0x0801
#define ETC_MODEL_ID_IRIDEON_FPZ                        0x0900
#define ETC_MODEL_ID_SOURCE_FOUR_DIMMER                 0x1001
#define ETC_MODEL_ID_KILLSWITCH_WIRELESS                0x1002
#define ETC_MODEL_ID_KILLSWITCH_DMX                     0x1003
#define ETC_MODEL_ID_KILLSWITCH_ETHERNET                0x1004
#define ETC_MODEL_ID_KILLSWITCH_TRANSMITTER             0x1005
#define ETC_MODEL_ID_DMX_ZONE_CONTROLLER_SINGLE_DIMMER  0x1006
#define ETC_MODEL_ID_DMX_ZONE_CONTROLLER_RELAY          0x1007
#define ETC_MODEL_ID_DMX_ZONE_CONTROLLER__4_8_CH        0x1008
#define ETC_MODEL_ID_COLORSOURCE_THRUPOWER_DIMMER       0x1101
#define ETC_MODEL_ID_DMX_DALI_GATEWAY_DIN_RAIL          0x1110

static const value_string etc_model_id_vals[] = {
  { ETC_MODEL_ID_SMARTBAR,                           "Smartbar" },
  { ETC_MODEL_ID_SOURCE_4_LED_LUSTR_PLUS,            "Source 4 LED Lustr+" },
  { ETC_MODEL_ID_DESIRE_ICE_40_LED,                  "Desire Ice 40 LED" },
  { ETC_MODEL_ID_DESIRE_FIRE_40_LED,                 "Desire Fire 40 LED" },
  { ETC_MODEL_ID_SOURCE_4_LED_TUNGSTEN,              "Source 4 LED Tungsten" },
  { ETC_MODEL_ID_SOURCE_4_LED_DAYLIGHT,              "Source 4 LED Daylight" },
  { ETC_MODEL_ID_DESIRE_VIVID_40_LED,                "Desire Vivid 40 LED" },
  { ETC_MODEL_ID_DESIRE_LUSTR_60_LED_OBS,            "Desire Lustr 60 LED (obsolete)" },
  { ETC_MODEL_ID_DESIRE_ICE_60_LED,                  "Desire Ice 60 LED" },
  { ETC_MODEL_ID_DESIRE_FIRE_60_LED,                 "Desire Fire 60 LED" },
  { ETC_MODEL_ID_DESIRE_VIVID_60_LED,                "Desire Vivid 60 LED" },
  { ETC_MODEL_ID_DESIRE_STUDIO_40_LED,               "Desire Studio 40 LED" },
  { ETC_MODEL_ID_DESIRE_STUDIO_60_LED,               "Desire Studio 60 LED" },
  { ETC_MODEL_ID_DESIRE_LUSTR_40_LED,                "Desire Lustr 40 LED" },
  { ETC_MODEL_ID_DESIRE_LUSTR_60_LED,                "Desire Lustr 60 LED" },
  { ETC_MODEL_ID_DESIRE_DAYLIGHT_40_LED,             "Desire Daylight 40 LED" },
  { ETC_MODEL_ID_DESIRE_TUNGSTEN_40_LED,             "Desire Tungsten 40 LED" },
  { ETC_MODEL_ID_DESIRE_DAYLIGHT_60_LED,             "Desire Daylight 60 LED" },
  { ETC_MODEL_ID_DESIRE_TUNGSTEN_60_LED,             "Desire Tungsten 60 LED" },
  { ETC_MODEL_ID_DESIRE_D22_LUSTR_PLUS_LED,          "Desire D22 Lustr+ LED" },
  { ETC_MODEL_ID_DESIRE_D22_DAYLIGHT_LED,            "Desire D22 Daylight LED" },
  { ETC_MODEL_ID_DESIRE_D22_TUNGSTEN_LED,            "Desire D22 Tungsten LED" },
  { ETC_MODEL_ID_SOURCE_4_LED_STUDIO_HD,             "Source 4 LED Studio HD" },
  { ETC_MODEL_ID_SOURCE_4_LED_SERIES_2_LUSTR,        "Source 4 LED Series 2 Lustr" },
  { ETC_MODEL_ID_DESIRE_D22_STUDIO_HD,               "Desire D22 Studio HD" },
  { ETC_MODEL_ID_SOURCE_4_LED_SERIES_2_TUNGSTEN_HD,  "Source 4 LED Series 2 Tungsten HD" },
  { ETC_MODEL_ID_SOURCE_4_LED_SERIES_2_DAYLIGHT_HD,  "Source 4 LED Series 2 Daylight HD" },
  { ETC_MODEL_ID_COLORSOURCE_BOOTLOADER,             "ColorSource Bootloader" },
  { ETC_MODEL_ID_COLORSOURCE_PAR,                    "ColorSource Par" },
  { ETC_MODEL_ID_COLORSOURCE_PAR_DEEP_BLUE,          "ColorSource Par DeepBlue" },
  { ETC_MODEL_ID_COLORSOURCE_PAR_PEARL,              "ColorSource Par Pearl" },
  { ETC_MODEL_ID_COLORSOURCE_SPOT,                   "ColorSource Spot" },
  { ETC_MODEL_ID_COLORSOURCE_SPOT_DEEP_BLUE,         "ColorSource Spot DeepBlue" },
  { ETC_MODEL_ID_COLORSOURCE_SPOT_PEARL,             "ColorSource Spot Pearl" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_1,               "ColorSource Linear 1" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_1_DEEP_BLUE,     "ColorSource Linear 1 DeepBlue" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_1_PEARL,         "ColorSource Linear 1 Pearl" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_2,               "ColorSource Linear 2" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_2_DEEP_BLUE,     "ColorSource Linear 2 DeepBlue" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_2_PEARL,         "ColorSource Linear 2 Pearl" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_4,               "ColorSource Linear 4" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_4_DEEP_BLUE,     "ColorSource Linear 4 DeepBlue" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_4_PEARL,         "ColorSource Linear 4 Pearl" },
  { ETC_MODEL_ID_COLORSOURCE_CYC,                    "ColorSource Cyc" },
  { ETC_MODEL_ID_SOURCE_FORWARD_120V,                "Source Forward 120v" },
  { ETC_MODEL_ID_SOURCE_FORWARD_230V,                "Source Forward 230v" },
  { ETC_MODEL_ID_IRIDEON_FPZ,                        "Irideon FPZ" },
  { ETC_MODEL_ID_SOURCE_FOUR_DIMMER,                 "Source Four Dimmer" },
  { ETC_MODEL_ID_KILLSWITCH_WIRELESS,                "Killswitch Wireless" },
  { ETC_MODEL_ID_KILLSWITCH_DMX,                     "Killswitch DMX" },
  { ETC_MODEL_ID_KILLSWITCH_ETHERNET,                "Killswitch Ethernet" },
  { ETC_MODEL_ID_KILLSWITCH_TRANSMITTER,             "Killswitch Transmitter" },
  { ETC_MODEL_ID_DMX_ZONE_CONTROLLER_SINGLE_DIMMER,  "DMX Zone Controller, Single Dimmer" },
  { ETC_MODEL_ID_DMX_ZONE_CONTROLLER_RELAY,          "DMX Zone Controller, Relay" },
  { ETC_MODEL_ID_DMX_ZONE_CONTROLLER__4_8_CH,        "DMX Zone Controller, 4-8 Channel Room Controller" },
  { ETC_MODEL_ID_COLORSOURCE_THRUPOWER_DIMMER,       "ColorSource Thrupower Dimmer" },
  { ETC_MODEL_ID_DMX_DALI_GATEWAY_DIN_RAIL,          "DMX-DALI Gateway, DIN Rail" },
  { 0, NULL },
};

static int hf_etc_parameter_id;       /* every manufacturer needs one of these */
static int hf_etc_pd_parameter_id;    /* every manufacturer needs one of these */
static int hf_etc_pd_device_model_id;
static int hf_etc_pd_led_curve;
static int hf_etc_pd_led_curve_description_curve;
static int hf_etc_pd_led_curve_description_text;
static int hf_etc_pd_led_strobe;
static int hf_etc_pd_led_output_mode;
static int hf_etc_pd_led_output_mode_description_mode;
static int hf_etc_pd_led_output_mode_description_text;
static int hf_etc_pd_led_red_shift;
static int hf_etc_pd_led_white_point;
static int hf_etc_pd_led_white_point_description_white_point;
static int hf_etc_pd_led_white_point_description_text;
static int hf_etc_pd_led_frequency;
static int hf_etc_pd_dmx_data_loss_behavior;
static int hf_etc_pd_dmx_data_loss_behavior_description_behavior;
static int hf_etc_pd_dmx_data_loss_behavior_description_text;
static int hf_etc_pd_led_plus_seven;
static int hf_etc_pd_backlight_brightness;
static int hf_etc_pd_backlight_timeout;
static int hf_etc_pd_status_indicators;
static int hf_etc_pd_overtemp_mode;
static int hf_etc_pd_simple_setup_mode;
static int hf_etc_pd_led_strobe_description_strobe;
static int hf_etc_pd_led_strobe_description_text;
static int hf_etc_pd_red_shift_description_red_shift;
static int hf_etc_pd_red_shift_description_text;
static int hf_etc_pd_plus_seven_description_plus_seven;
static int hf_etc_pd_plus_seven_description_text;
static int hf_etc_pd_backlight_timeout_description_timeout;
static int hf_etc_pd_backlight_timeout_description_text;
static int hf_etc_pd_simple_setup_mode_description_mode;
static int hf_etc_pd_simple_setup_mode_description_text;
static int hf_etc_pd_overtemp_mode_description_mode;
static int hf_etc_pd_overtemp_mode_description_text;
static int hf_etc_pd_led_requested_xy_x;
static int hf_etc_pd_led_requested_xy_y;
static int hf_etc_pd_led_current_xy_x;
static int hf_etc_pd_led_current_xy_y;
static int hf_etc_pd_current_pwm_led_number;
static int hf_etc_pd_current_pwm_channel_duty_cycle;
static int hf_etc_pd_tristimulus_led_number;
static int hf_etc_pd_tristimulus_x;
static int hf_etc_pd_tristimulus_y;
static int hf_etc_pd_tristimulus_z;
static int hf_etc_pd_led_information_led_number;
static int hf_etc_pd_led_information_type;
static int hf_etc_pd_led_information_dmx_control_channel;
static int hf_etc_pd_led_information_drive_current;
static int hf_etc_pd_led_information_gamut_polygon_order;
static int hf_etc_pd_led_information_quantity;
static int hf_etc_pd_preset_config_preset_number;
static int hf_etc_pd_preset_config_fade_time;
static int hf_etc_pd_preset_config_delay_time;
static int hf_etc_pd_preset_config_hue;
static int hf_etc_pd_preset_config_saturation;
static int hf_etc_pd_preset_config_intensity;
static int hf_etc_pd_preset_config_strobe;
static int hf_etc_pd_sequence_playback_sequence_number;
static int hf_etc_pd_sequence_config_sequence_number;
static int hf_etc_pd_sequence_config_preset_steps;
static int hf_etc_pd_sequence_config_preset_step;
static int hf_etc_pd_sequence_config_step_link_times;
static int hf_etc_pd_sequence_config_step_link_time;
static int hf_etc_pd_sequence_config_rate;
static int hf_etc_pd_sequence_config_end_state;
static int hf_etc_pd_low_power_timeout;
static int hf_etc_pd_low_power_timeout_description_timeout;
static int hf_etc_pd_low_power_timeout_description_text;
static int hf_etc_pd_led_enum_frequency;
static int hf_etc_pd_led_enum_frequency_description_frequency;
static int hf_etc_pd_led_enum_frequency_description_text;
static int hf_etc_pd_rgbi_preset_config_preset_number;
static int hf_etc_pd_rgbi_preset_config_fade_time;
static int hf_etc_pd_rgbi_preset_config_delay_time;
static int hf_etc_pd_rgbi_preset_config_red;
static int hf_etc_pd_rgbi_preset_config_green;
static int hf_etc_pd_rgbi_preset_config_blue;
static int hf_etc_pd_rgbi_preset_config_intensity;
static int hf_etc_pd_rgbi_preset_config_strobe;
static int hf_etc_pd_cct_preset_config_preset_number;
static int hf_etc_pd_cct_preset_config_fade_time;
static int hf_etc_pd_cct_preset_config_delay_time;
static int hf_etc_pd_cct_preset_config_white_point;
static int hf_etc_pd_cct_preset_config_tint;
static int hf_etc_pd_cct_preset_config_strobe;
static int hf_etc_pd_cct_preset_config_intensity;
static int hf_etc_pd_cct_preset_config_tone;
static int hf_etc_pd_cct_preset_config_reserved;
static int hf_etc_pd_supplementary_device_version_param_index;
static int hf_etc_pd_supplementary_device_version_param_description;
static int hf_etc_pd_power_command;
static int hf_etc_pd_power_command_description_state;
static int hf_etc_pd_power_command_description_text;
static int hf_etc_pd_dali_short_address;
static int hf_etc_pd_dali_group_membership;
static int hf_etc_pd_auto_bind;
static int hf_etc_pd_packet_delay;
static int hf_etc_pd_has_enum_text_pid;
static int hf_etc_pd_has_enum_text_true_false;
static int hf_etc_pd_get_enum_text_pid;
static int hf_etc_pd_get_enum_text_enum;
static int hf_etc_pd_get_enum_text_description;

static int ett_etc_sequence_config_steps;
static int ett_etc_sequence_config_times;

/* end ETC */
/* end manufacturer-specific constants and variables */

static uint16_t
rdm_checksum(tvbuff_t *tvb, unsigned length)
{
  uint16_t sum = RDM_SC_RDM;
  unsigned  i;
  for (i = 0; i < length; i++)
    sum += tvb_get_uint8(tvb, i);
  return sum;
}

static void
rdm_proto_tree_add_numeric_item(proto_tree *tree, int hfindex, tvbuff_t *tvb, unsigned *offset_ptr, uint8_t len)
{
  unsigned offset = *offset_ptr;
  proto_tree_add_item(tree, hfindex, tvb, offset, len, ENC_BIG_ENDIAN);
  *offset_ptr += len;
}

static void
rdm_proto_tree_add_ascii_item(proto_tree *tree, int hfindex, tvbuff_t *tvb, unsigned *offset_ptr, int len)
{
  unsigned offset = *offset_ptr;
  proto_tree_add_item(tree, hfindex, tvb, offset, len, ENC_ASCII|ENC_NA);
  *offset_ptr += len;
}

static void
rdm_proto_tree_add_bytes_item(proto_tree *tree, int hfindex, tvbuff_t *tvb, unsigned *offset_ptr, int len)
{
  unsigned offset = *offset_ptr;
  proto_tree_add_item(tree, hfindex, tvb, offset, len, ENC_NA);
  *offset_ptr += len;
}

static unsigned
dissect_rdm_pd_queued_message(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_queued_message_status, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_start_address, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_device_info(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_, uint8_t cc, uint8_t len _U_, uint16_t device_manufacturer_id)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_proto_vers, tvb, &offset, 2);
    switch(device_manufacturer_id) {
    case RDM_MANUFACTURER_ID_ETC:
      rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_device_model_id, tvb, &offset, 2);
      break;
    default:
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_device_model_id, tvb, &offset, 2);
      break;
    }
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_product_cat, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_software_vers_id, tvb, &offset, 4);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_footprint, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_pers_current, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_pers_total, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_start_address, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sub_device_count, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_count, tvb, &offset, 1);
    break;
  }

  return offset;
}


static unsigned
dissect_rdm_pd_device_model_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_device_model_description, tvb, &offset, len);
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
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_device_label, tvb, &offset, len);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_device_hours, tvb, &offset, 4);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_lamp_hours, tvb, &offset, 4);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_lamp_strikes, tvb, &offset, 4);
    break;
  }

  return offset;
}


static unsigned
dissect_rdm_pd_sensor_definition(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_nr, tvb, &offset, 1);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_nr, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_type, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_unit, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_prefix, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_range_min_value, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_range_max_value, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_normal_min_value, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_normal_max_value, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_recorded_value_support, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_sensor_description, tvb, &offset, len-13);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_sensor_value(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  uint8_t original_len = len;

  switch(cc) {
  case RDM_CC_GET_COMMAND:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_nr, tvb, &offset, 1);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_nr, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_value_pres, tvb, &offset, 2);

    if (original_len == 7 || original_len == 9) {
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_value_low, tvb, &offset, 2);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_value_high, tvb, &offset, 2);
    }

    if (original_len == 5 || original_len == 9) {
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_value_rec, tvb, &offset, 2);
    }

    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_manufacturer_label(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_manu_label, tvb, &offset, len);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_disc_unique_branch(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_DISCOVERY_COMMAND:
    rdm_proto_tree_add_bytes_item(tree, hf_rdm_pd_disc_unique_branch_lb_uid, tvb, &offset, 6);
    rdm_proto_tree_add_bytes_item(tree, hf_rdm_pd_disc_unique_branch_ub_uid, tvb, &offset, 6);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_disc_mute(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_DISCOVERY_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_disc_mute_control_field, tvb, &offset, 2);
    if (len > 2) {
      rdm_proto_tree_add_bytes_item(tree, hf_rdm_pd_disc_mute_binding_uid, tvb, &offset, 6);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_disc_unmute_control_field, tvb, &offset, 2);
    if (len > 2) {
      rdm_proto_tree_add_bytes_item(tree, hf_rdm_pd_disc_unmute_binding_uid, tvb, &offset, 6);
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
      rdm_proto_tree_add_bytes_item(tree, hf_rdm_pd_proxied_devices_uid, tvb, &offset, 6);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_proxied_device_count, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_proxied_device_list_change, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_comms_status(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_comms_status_short_msg, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_comms_status_len_mismatch, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_comms_status_csum_fail, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_status_messages(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_status_messages_type, tvb, &offset, 1);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 9) {
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_status_messages_sub_device_id, tvb, &offset, 2);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_status_messages_type, tvb, &offset, 1);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_status_messages_id, tvb, &offset, 2);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_status_messages_data_value_1, tvb, &offset, 2);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_status_messages_data_value_2, tvb, &offset, 2);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_status_id, tvb, &offset, 2);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_status_id_description, tvb, &offset, len);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sub_device_status_report_threshold_status_type, tvb, &offset, 1);
    break;
  }

  return offset;
}

static void
add_param_id_to_tree(uint16_t param_id, proto_tree *tree, tvbuff_t *tvb, unsigned *offset, uint16_t device_manufacturer_id)
{
  if (param_id < 0x8000) {
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_parameter_id, tvb, offset, 2);
  } else {
    switch(device_manufacturer_id) {
    case RDM_MANUFACTURER_ID_ETC:
      rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_parameter_id, tvb, offset, 2);
      break;
    default:
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_parameter_id, tvb, offset, 2);
      break;
    }
  }
}

static unsigned
dissect_rdm_pd_supported_parameters(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len, uint16_t device_manufacturer_id)
{
  uint16_t     param_id;

  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 2) {
      param_id = tvb_get_ntohs(tvb, offset);
      add_param_id_to_tree(param_id, tree, tvb, &offset, device_manufacturer_id);
      len -= 2;
    }
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_parameter_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len, uint16_t device_manufacturer_id)
{
  uint16_t     param_id;

  switch(cc) {
  case RDM_CC_GET_COMMAND:
    param_id = tvb_get_ntohs(tvb, offset);
    add_param_id_to_tree(param_id, tree, tvb, &offset, device_manufacturer_id);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    param_id = tvb_get_ntohs(tvb, offset);
    add_param_id_to_tree(param_id, tree, tvb, &offset, device_manufacturer_id);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_parameter_pdl_size, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_parameter_data_type, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_parameter_cmd_class, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_parameter_type, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_parameter_unit, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_parameter_prefix, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_parameter_min_value, tvb, &offset, 4);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_parameter_max_value, tvb, &offset, 4);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_parameter_default_value, tvb, &offset, 4);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_parameter_description, tvb, &offset, len-20);
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
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_product_detail_id_list, tvb, &offset, 2);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_factory_defaults, tvb, &offset, 1);
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
      rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_language_code, tvb, &offset, 2);
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
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_language_code, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_software_version_label(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_software_version_label, tvb, &offset, len);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_boot_software_version_id(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_boot_software_version_id, tvb, &offset, 4);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_boot_software_version_label(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_boot_software_version_label, tvb, &offset, len);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dmx_personality(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_pers_nr, tvb, &offset, 1);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_pers_current, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_pers_count, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dmx_personality_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_pers_requested, tvb, &offset, 1);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_pers_requested, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_pers_slots, tvb, &offset, 2);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_dmx_pers_text, tvb, &offset, len-3);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_slot_info(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    while (len >= 5) {
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_slot_offset, tvb, &offset, 2);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_slot_type, tvb, &offset, 1);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_slot_label_id, tvb, &offset, 2);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_slot_nr, tvb, &offset, 2);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_slot_nr, tvb, &offset, 2);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_slot_description, tvb, &offset, len-2);
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
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_slot_offset, tvb, &offset, 2);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_slot_value, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_block_address_subdevice_footprint, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_block_address_base_dmx_address, tvb, &offset, 2);
    break;

  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_block_address_base_dmx_address, tvb, &offset, 2);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_fail_mode_scene_number, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_fail_mode_loss_of_signal_delay, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_fail_mode_hold_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_fail_mode_level, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_startup_mode_scene_number, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_startup_mode_loss_of_signal_delay, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_startup_mode_hold_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dmx_startup_mode_level, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_record_sensors(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_nr, tvb, &offset, 1);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_nr, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_type, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_unit, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_prefix, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_range_min_value, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_range_max_value, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_normal_min_value, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_sensor_normal_max_value, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_rec_value_support, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_sensor_description, tvb, &offset, len-13);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dimmer_info(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dimmer_info_minimum_level_lower_limit, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dimmer_info_minimum_level_upper_limit, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dimmer_info_maximum_level_lower_limit, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dimmer_info_maximum_level_upper_limit, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dimmer_info_number_of_supported_curves, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dimmer_info_levels_resolution, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dimmer_info_minimum_level_split_levels_supported, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_minimum_level_increasing, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_minimum_level_decreasing, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_minimum_level_on_below_minimum, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_maximum_level_level, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_curve(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_curve_curve, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_curve_number_of_curves, tvb, &offset, 1);
    break;

  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_curve_curve, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_curve_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_curve_description_curve, tvb, &offset, 1);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_curve_description_curve, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_curve_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_output_response_time(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_output_response_time_response_time, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_output_response_time_number_of_response_times, tvb, &offset, 1);
    break;

  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_output_response_time_response_time, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_output_response_time_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_output_response_time_description_output_response_time, tvb, &offset, 1);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_output_response_time_description_output_response_time, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_output_response_time_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_modulation_frequency(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_modulation_frequency_modulation_frequency, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_modulation_frequency_number_of_modulation_frequencies, tvb, &offset, 1);
    break;

  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_modulation_frequency_modulation_frequency, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_modulation_frequency_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_modulation_frequency_description_modulation_frequency, tvb, &offset, 1);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_modulation_frequency_description_modulation_frequency, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_modulation_frequency_description_text, tvb, &offset, len-1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_lamp_state, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_lamp_on_mode, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_device_power_cycles, tvb, &offset, 4);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_burn_in, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_display_invert, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_display_level, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_pan_invert, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_tilt_invert, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_tilt_swap, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_real_time_clock_year, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_real_time_clock_month, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_real_time_clock_day, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_real_time_clock_hour, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_real_time_clock_minute, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_real_time_clock_second, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_lock_pin(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_lock_pin_pin_code, tvb, &offset, 2);
    break;

  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_lock_pin_new_pin_code, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_lock_pin_pin_code, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_lock_state(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_lock_state_lock_state, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_lock_state_number_of_lock_states, tvb, &offset, 1);
    break;

  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_lock_state_pin_code, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_lock_state_lock_state, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_lock_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_lock_state_description_lock_state, tvb, &offset, 1);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_lock_state_description_lock_state, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_lock_state_description_text, tvb, &offset, len-1);
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
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_list_interfaces_interface_identifier, tvb, &offset, 4);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_list_interfaces_interface_hardware_type, tvb, &offset, 2);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_interface_label_interface_identifier, tvb, &offset, 4);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_interface_label_interface_identifier, tvb, &offset, 4);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_interface_label_label, tvb, &offset, len-4);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_hardware_address_type1(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_hardware_address_type1_interface_identifier, tvb, &offset, 4);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_hardware_address_type1_interface_identifier, tvb, &offset, 4);
    rdm_proto_tree_add_bytes_item(tree, hf_rdm_pd_hardware_address_type1_hardware_address, tvb, &offset, 6);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dhcp_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dhcp_mode_interface_identifier, tvb, &offset, 4);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dhcp_mode_interface_identifier, tvb, &offset, 4);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dhcp_mode_enabled, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_zeroconf_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_zeroconf_mode_interface_identifier, tvb, &offset, 4);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_zeroconf_mode_interface_identifier, tvb, &offset, 4);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_zeroconf_mode_enabled, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_current_address(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_current_address_interface_identifier, tvb, &offset, 4);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_current_address_interface_identifier, tvb, &offset, 4);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_current_address_ipv4_address, tvb, &offset, 4);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_current_address_netmask, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_current_address_dhcp_status, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_static_address(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_static_address_interface_identifier, tvb, &offset, 4);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_static_address_interface_identifier, tvb, &offset, 4);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_static_address_ipv4_address, tvb, &offset, 4);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_static_address_netmask, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_interface_renew_dhcp(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_interface_renew_dhcp_interface_identifier, tvb, &offset, 4);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_interface_release_dhcp(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_interface_release_dhcp_interface_identifier, tvb, &offset, 4);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_interface_apply_configuration(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_interface_apply_configuration_interface_identifier, tvb, &offset, 4);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_ipv4_default_route_interface_identifier, tvb, &offset, 4);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_ipv4_default_route_ipv4_default_route, tvb, &offset, 4);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_dns_ipv4_name_server(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dns_ipv4_name_server_index, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dns_ipv4_name_server_index, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_dns_ipv4_name_server_address, tvb, &offset, 4);
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
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_dns_hostname, tvb, &offset, len);
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
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_dns_domain_name, tvb, &offset, len);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_identify_device(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_identify_device, tvb, &offset, 1);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_identify_device_state, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_reset_device(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_reset_device, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_power_state, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_perform_selftest(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_selftest_nr, tvb, &offset, 1);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_selftest_state, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_self_test_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_selftest_nr, tvb, &offset, 1);
    break;

  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_selftest_nr, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_selftest_description, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_capture_preset(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len _U_)
{
  switch(cc) {
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_capture_preset_scene_nr, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_capture_preset_up_fade_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_capture_preset_down_fade_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_capture_preset_wait_time, tvb, &offset, 2);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_playback_mode, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_playback_level, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_identify_mode, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_preset_info(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_level_field_supported, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_preset_sequence_supported, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_split_times_supported, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_dmx_fail_infinite_delay_time_supported, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_dmx_fail_infinite_hold_time_supported, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_start_up_infinite_hold_time_supported, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_maximum_scene_number, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_minimum_preset_fade_time_supported, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_maximum_preset_fade_time_supported, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_minimum_preset_wait_time_supported, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_maximum_preset_wait_time_supported, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_minimum_dmx_fail_delay_time_supported, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_maximum_dmx_fail_delay_time_supported, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_minimum_dmx_fail_hold_time_supported, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_maximum_dmx_fail_hold_time_supported, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_minimum_start_up_delay_time_supported, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_maximum_start_up_delay_time_supported, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_minimum_start_up_hold_time_supported, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_info_maximum_start_up_hold_time_supported, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_preset_status(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_status_scene_number, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_status_scene_number, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_status_up_fade_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_status_down_fade_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_status_wait_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_status_programmed, tvb, &offset, 1);
    break;
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_status_scene_number, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_status_up_fade_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_status_down_fade_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_status_wait_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_status_clear_preset, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_preset_mergemode, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_power_on_self_test, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_background_queued_status_policy(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_background_queued_status_policy_current_policy, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_background_queued_status_policy_number_of_policies, tvb, &offset, 1);
    break;
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_background_queued_status_policy_current_policy, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_background_queued_status_policy_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_background_queued_status_policy_description_policy, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_background_queued_status_policy_description_policy, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_background_queued_status_policy_description_description, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_list(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_list_change_number, tvb, &offset, 4);
    len -= 4;
    while (len >= 3) {
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_list_endpoint_id, tvb, &offset, 2);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_list_endpoint_type, tvb, &offset, 1);
      len -= 3;
    }
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
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_search_domain_dns_domain_name, tvb, &offset, len);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_to_universe_endpoint_id, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_to_universe_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_to_universe_universe_number, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_rdm_traffic_enable(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_rdm_traffic_enable_endpoint_id, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_rdm_traffic_enable_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_rdm_traffic_enable_rdm_enabled, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_mode_endpoint_id, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_mode_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_mode_endpoint_mode, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_label_endpoint_id, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_label_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_endpoint_label_label, tvb, &offset, len-2);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_discovery_state_endpoint_id, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_discovery_state_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_discovery_state_device_count, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_discovery_state_discovery_state, tvb, &offset, 1);
    break;
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_discovery_state_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_discovery_state_discovery_state, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_timing_endpoint_id, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_timing_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_timing_setting, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_timing_number_of_settings, tvb, &offset, 1);
    break;
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_timing_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_timing_setting, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_timing_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_timing_description_setting, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_timing_description_setting, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_endpoint_timing_description_description, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_binding_control_fields(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_binding_control_fields_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_bytes_item(tree, hf_rdm_pd_binding_control_fields_uid, tvb, &offset, 6);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_binding_control_fields_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_bytes_item(tree, hf_rdm_pd_binding_control_fields_uid, tvb, &offset, 6);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_binding_control_fields_control_field, tvb, &offset, 2);
    rdm_proto_tree_add_bytes_item(tree, hf_rdm_pd_binding_control_fields_binding_uid, tvb, &offset, 6);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_identify_endpoint_endpoint_id, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_identify_endpoint_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_identify_endpoint_identify_state, tvb, &offset, 1);
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
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_background_discovery_endpoint_id, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_background_discovery_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_background_discovery_enabled, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_responder_list_change(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_responder_list_change_endpoint_id, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_responder_list_change_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_responder_list_change_change_number, tvb, &offset, 4);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_responders(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_responders_endpoint_id, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_responders_endpoint_id, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_responders_change_number, tvb, &offset, 4);
    len -= 6;
    while (len >= 6) {
      rdm_proto_tree_add_bytes_item(tree, hf_rdm_pd_endpoint_responders_uid, tvb, &offset, 6);
      len -= 6;
    }
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
      rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_tcp_comms_status_scope_string, tvb, &offset, 63);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_tcp_comms_status_broker_ipv4_address, tvb, &offset, 4);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_tcp_comms_status_broker_ipv6_address, tvb, &offset, 16);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_tcp_comms_status_broker_port, tvb, &offset, 2);
      rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_tcp_comms_status_unhealthy_tcp_events, tvb, &offset, 2);
      len -= 87;
    }
    break;
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_tcp_comms_status_scope_string, tvb, &offset, 63);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_endpoint_list_change(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_endpoint_list_change_change_number, tvb, &offset, 4);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_component_scope(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_component_scope_scope_slot, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_component_scope_scope_slot, tvb, &offset, 2);
    rdm_proto_tree_add_ascii_item(tree, hf_rdm_pd_component_scope_scope_string, tvb, &offset, 63);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_component_scope_scope_static_config_type, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_component_scope_scope_static_ipv4_address, tvb, &offset, 4);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_component_scope_scope_static_ipv6_address, tvb, &offset, 16);
    rdm_proto_tree_add_numeric_item(tree, hf_rdm_pd_component_scope_scope_static_port, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_pd_broker_status(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_rem_pd_broker_status_set_allowed, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_rem_pd_broker_status_state, tvb, &offset, 1);
    break;
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_rem_pd_broker_status_state, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_curve(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_curve, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_curve_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_curve_description_curve, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_curve_description_curve, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_led_curve_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_strobe(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_strobe, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_output_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_output_mode, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_output_mode_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_output_mode_description_mode, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_output_mode_description_mode, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_led_output_mode_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_red_shift(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_red_shift, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_white_point(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_white_point, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_white_point_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_white_point_description_white_point, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_white_point_description_white_point, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_led_white_point_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_frequency(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_frequency, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_dmx_data_loss_behavior(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_dmx_data_loss_behavior, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_dmx_data_loss_behavior_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_dmx_data_loss_behavior_description_behavior, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_dmx_data_loss_behavior_description_behavior, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_dmx_data_loss_behavior_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_plus_seven(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_plus_seven, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_backlight_brightness(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_backlight_brightness, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_backlight_timeout(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_backlight_timeout, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_status_indicators(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_status_indicators, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_recalibrate_fixture(unsigned offset)
{
  /* set-only, no data */
  return offset;
}

static unsigned
dissect_etc_pd_overtemp_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_overtemp_mode, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_simple_setup_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_simple_setup_mode, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_strobe_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_strobe_description_strobe, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_strobe_description_strobe, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_led_strobe_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_red_shift_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_red_shift_description_red_shift, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_red_shift_description_red_shift, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_red_shift_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_plus_seven_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_plus_seven_description_plus_seven, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_plus_seven_description_plus_seven, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_plus_seven_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_backlight_timeout_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_backlight_timeout_description_timeout, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_backlight_timeout_description_timeout, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_backlight_timeout_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_simple_setup_mode_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_simple_setup_mode_description_mode, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_simple_setup_mode_description_mode, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_simple_setup_mode_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_overtemp_mode_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_overtemp_mode_description_mode, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_overtemp_mode_description_mode, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_overtemp_mode_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_requested_xy(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_requested_xy_x, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_requested_xy_y, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_current_xy(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_current_xy_x, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_current_xy_y, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_current_pwm(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_current_pwm_led_number, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_current_pwm_led_number, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_current_pwm_channel_duty_cycle, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_tristimulus(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_tristimulus_led_number, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_tristimulus_led_number, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_tristimulus_x, tvb, &offset, 4);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_tristimulus_y, tvb, &offset, 4);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_tristimulus_z, tvb, &offset, 4);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_information(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_information_led_number, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_information_led_number, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_information_type, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_information_dmx_control_channel, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_information_drive_current, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_information_gamut_polygon_order, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_information_quantity, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_preset_config(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_preset_config_preset_number, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_preset_config_preset_number, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_preset_config_fade_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_preset_config_delay_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_preset_config_hue, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_preset_config_saturation, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_preset_config_intensity, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_preset_config_strobe, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_sequence_playback(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_sequence_playback_sequence_number, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_sequence_config(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  unsigned    i;
  proto_tree *preset_steps_tree, *preset_steps_sub_item;
  proto_tree *step_link_times_tree, *step_link_times_sub_item;

  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_sequence_config_sequence_number, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_sequence_config_sequence_number, tvb, &offset, 2);

    preset_steps_tree = proto_tree_add_item(tree, hf_etc_pd_sequence_config_preset_steps, tvb, offset, 24, ENC_NA);
    preset_steps_sub_item = proto_item_add_subtree(preset_steps_tree, ett_etc_sequence_config_steps);
    for (i = 0; i < 24; i++) {
      rdm_proto_tree_add_numeric_item(preset_steps_sub_item, hf_etc_pd_sequence_config_preset_step, tvb, &offset, 1);
    }

    step_link_times_tree = proto_tree_add_item(tree, hf_etc_pd_sequence_config_step_link_times, tvb, offset, 48, ENC_NA);
    step_link_times_sub_item = proto_item_add_subtree(step_link_times_tree, ett_etc_sequence_config_times);
    for (i = 0; i < 24; i++) {
      rdm_proto_tree_add_numeric_item(step_link_times_sub_item, hf_etc_pd_sequence_config_step_link_time, tvb, &offset, 2);
    }

    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_sequence_config_rate, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_sequence_config_end_state, tvb, &offset, 1);
    break;
  }

  return offset;
}


static unsigned
dissect_etc_pd_low_power_timeout(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_low_power_timeout, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_low_power_timeout_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_low_power_timeout_description_timeout, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_low_power_timeout_description_timeout, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_low_power_timeout_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_enum_frequency(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_enum_frequency, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_enum_frequency_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_enum_frequency_description_frequency, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_led_enum_frequency_description_frequency, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_led_enum_frequency_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_rgbi_preset_config(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_rgbi_preset_config_preset_number, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_rgbi_preset_config_preset_number, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_rgbi_preset_config_fade_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_rgbi_preset_config_delay_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_rgbi_preset_config_red, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_rgbi_preset_config_green, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_rgbi_preset_config_blue, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_rgbi_preset_config_intensity, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_rgbi_preset_config_strobe, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_cct_preset_config(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_cct_preset_config_preset_number, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_cct_preset_config_preset_number, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_cct_preset_config_fade_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_cct_preset_config_delay_time, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_cct_preset_config_white_point, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_cct_preset_config_tint, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_cct_preset_config_strobe, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_cct_preset_config_intensity, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_cct_preset_config_tone, tvb, &offset, 1);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_cct_preset_config_reserved, tvb, &offset, 4);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_supplementary_device_version(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_supplementary_device_version_param_index, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_supplementary_device_version_param_index, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_supplementary_device_version_param_description, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_power_command(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_power_command, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_power_command_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_power_command_description_state, tvb, &offset, 1);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_power_command_description_state, tvb, &offset, 1);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_power_command_description_text, tvb, &offset, len-1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_dali_short_address(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_dali_short_address, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_dali_group_membership(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_dali_group_membership, tvb, &offset, 2);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_auto_bind(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_auto_bind, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_delete_subdevice(unsigned offset)
{
  /* set-only, no data */
  return offset;
}

static unsigned
dissect_etc_pd_packet_delay(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_packet_delay, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_has_enum_text(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_has_enum_text_pid, tvb, &offset, 2);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_has_enum_text_pid, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_has_enum_text_true_false, tvb, &offset, 1);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_get_enum_text(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_get_enum_text_pid, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_get_enum_text_enum, tvb, &offset, 4);
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_get_enum_text_pid, tvb, &offset, 2);
    rdm_proto_tree_add_numeric_item(tree, hf_etc_pd_get_enum_text_enum, tvb, &offset, 4);
    rdm_proto_tree_add_ascii_item(tree, hf_etc_pd_get_enum_text_description, tvb, &offset, len-6);
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_prepare_for_software_download(unsigned offset)
{
  /* set-only, no data */
  return offset;
}

static unsigned
dissect_etc_pid(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint16_t param_id, uint8_t pdl)
{
  switch(param_id) {
  case ETC_PARAM_ID_LED_CURVE:
    offset = dissect_etc_pd_led_curve(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_CURVE_DESCRIPTION:
    offset = dissect_etc_pd_led_curve_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_STROBE:
    offset = dissect_etc_pd_led_strobe(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_OUTPUT_MODE:
    offset = dissect_etc_pd_led_output_mode(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_OUTPUT_MODE_DESCRIPTION:
    offset = dissect_etc_pd_led_output_mode_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_RED_SHIFT:
    offset = dissect_etc_pd_led_red_shift(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_WHITE_POINT:
    offset = dissect_etc_pd_led_white_point(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_WHITE_POINT_DESCRIPTION:
    offset = dissect_etc_pd_led_white_point_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_FREQUENCY:
    offset = dissect_etc_pd_led_frequency(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_DMX_LOSS_BEHAVIOR:
    offset = dissect_etc_pd_dmx_data_loss_behavior(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_DMX_LOSS_BEHAVIOR_DESCRIPTION:
    offset = dissect_etc_pd_dmx_data_loss_behavior_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_PLUS_SEVEN:
    offset = dissect_etc_pd_led_plus_seven(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_BACKLIGHT_BRIGHTNESS:
    offset = dissect_etc_pd_backlight_brightness(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_BACKLIGHT_TIMEOUT:
    offset = dissect_etc_pd_backlight_timeout(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_STATUS_INDICATORS:
    offset = dissect_etc_pd_status_indicators(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_RECALIBRATE_FIXTURE:
    offset = dissect_etc_pd_recalibrate_fixture(offset);
    break;
  case ETC_PARAM_ID_OVERTEMPMODE:
    offset = dissect_etc_pd_overtemp_mode(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_SIMPLESETUPMODE:
    offset = dissect_etc_pd_simple_setup_mode(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_STROBE_DESCRIPTION:
    offset = dissect_etc_pd_led_strobe_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_RED_SHIFT_DESCRIPTION:
    offset = dissect_etc_pd_red_shift_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_PLUS_SEVEN_DESCRIPTION:
    offset = dissect_etc_pd_plus_seven_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_BACKLIGHT_TIMEOUT_DESCRIPTION:
    offset = dissect_etc_pd_backlight_timeout_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_SIMPLESETUPMODE_DESCRIPTION:
    offset = dissect_etc_pd_simple_setup_mode_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_OVERTEMPMODE_DESCRIPTION:
    offset = dissect_etc_pd_overtemp_mode_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_REQUESTED_XY:
    offset = dissect_etc_pd_led_requested_xy(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_CURRENT_XY:
    offset = dissect_etc_pd_led_current_xy(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_CURRENT_PWM:
    offset = dissect_etc_pd_current_pwm(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_TRISTIMULUS:
    offset = dissect_etc_pd_tristimulus(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_INFORMATION:
    offset = dissect_etc_pd_led_information(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_PRESETCONFIG:
    offset = dissect_etc_pd_preset_config(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_SEQUENCE_PLAYBACK:
    offset = dissect_etc_pd_sequence_playback(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_SEQUENCE_CONFIG:
    offset = dissect_etc_pd_sequence_config(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LOW_POWER_TIMEOUT:
    offset = dissect_etc_pd_low_power_timeout(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LOW_POWER_TIMEOUT_DESCRIPTION:
    offset = dissect_etc_pd_low_power_timeout_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_ENUM_FREQUENCY:
    offset = dissect_etc_pd_led_enum_frequency(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_ENUM_FREQUENCY_DESCRIPTION:
    offset = dissect_etc_pd_led_enum_frequency_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_RGBI_PRESETCONFIG:
    offset = dissect_etc_pd_rgbi_preset_config(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_CCT_PRESETCONFIG:
    offset = dissect_etc_pd_cct_preset_config(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_SUPPLEMENTARY_DEVICE_VERSION:
    offset = dissect_etc_pd_supplementary_device_version(tvb, offset, tree, cc, pdl);
    break;
/* do not display
  case ETC_PARAM_ID_START_UWB_DISCOVER:
    break;
  case ETC_PARAM_ID_START_UWB_MEASURE:
    break;
  case ETC_PARAM_ID_POSITION:
    break;
*/
/* TODO: begin need descriptions */
  case ETC_PARAM_ID_S4DIM_CALIBRATE:
    break;
  case ETC_PARAM_ID_S4DIM_CALIBRATE_DESCRIPTION:
    break;
  case ETC_PARAM_ID_S4DIM_TEST_MODE:
    break;
  case ETC_PARAM_ID_S4DIM_TEST_MODE_DESCRIPTION:
    break;
  case ETC_PARAM_ID_S4DIM_MAX_OUTPUT_VOLTAGE:
    break;
  case ETC_PARAM_ID_S4DIM_MAX_OUTPUT_VOLTAGE_DESCRIPTION:
    break;
/* TODO: end need descriptions */
  case ETC_PARAM_ID_POWER_COMMAND:
    offset = dissect_etc_pd_power_command(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_POWER_COMMAND_DESCRIPTION:
    offset = dissect_etc_pd_power_command_description(tvb, offset, tree, cc, pdl);
    break;
/* TODO: begin need descriptions */
  case ETC_PARAM_ID_THRESHOLD_COMMAND:
    break;
  case ETC_PARAM_ID_TURNON_DELAY_COMMAND:
    break;
/* TODO: end need descriptions */
  case ETC_PARAM_ID_SET_DALI_SHORTADDRESS:
    offset = dissect_etc_pd_dali_short_address(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_DALI_GROUP_MEMBERSHIP:
    offset = dissect_etc_pd_dali_group_membership(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_AUTOBIND:
    offset = dissect_etc_pd_auto_bind(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_DELETE_SUBDEVICE:
    offset = dissect_etc_pd_delete_subdevice(offset);
    break;
  case ETC_PARAM_ID_PACKET_DELAY:
    offset = dissect_etc_pd_packet_delay(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_HAS_ENUM_TEXT:
    offset = dissect_etc_pd_has_enum_text(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_GET_ENUM_TEXT:
    offset = dissect_etc_pd_get_enum_text(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_PREPAREFORSOFTWAREDOWNLOAD:
    offset = dissect_etc_pd_prepare_for_software_download(offset);
    break;
  default:
    proto_tree_add_item(tree, hf_rdm_parameter_data_raw, tvb, offset, pdl, ENC_NA);
    offset += pdl;
  }

  return offset;
}

static unsigned
dissect_manufacturer_specific_pid(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint16_t param_id, uint8_t pdl, uint16_t device_manufacturer_id)
{
  switch(device_manufacturer_id) {
  case RDM_MANUFACTURER_ID_ETC:
    offset = dissect_etc_pid(tvb, offset, tree, cc, param_id, pdl);
    break;
  default:
    proto_tree_add_item(tree, hf_rdm_parameter_data_raw, tvb, offset, pdl, ENC_NA);
    offset += pdl;
    break;
  }

  return offset;
}

static unsigned
dissect_rdm_mdb_param_data(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint16_t param_id, uint8_t pdl, uint16_t device_manufacturer_id)
{
  if (param_id >= 0x8000) {
    offset = dissect_manufacturer_specific_pid(tvb, offset, tree, cc, param_id, pdl, device_manufacturer_id);
  } else {
    switch(param_id) {
    case RDM_PARAM_ID_SENSOR_VALUE:
      offset = dissect_rdm_pd_sensor_value(tvb, offset, tree, cc, pdl);
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

    case RDM_PARAM_ID_SUPPORTED_PARAMETERS:
      offset = dissect_rdm_pd_supported_parameters(tvb, offset, tree, cc, pdl, device_manufacturer_id);
      break;

    case RDM_PARAM_ID_PARAMETER_DESCRIPTION:
      offset = dissect_rdm_pd_parameter_description(tvb, offset, tree, cc, pdl, device_manufacturer_id);
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

    case RDM_PARAM_ID_DMX_PERSONALITY:
      offset = dissect_rdm_pd_dmx_personality(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DMX_PERSONALITY_DESCRIPTION:
      offset = dissect_rdm_pd_dmx_personality_description(tvb, offset, tree, cc, pdl);
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
      offset = dissect_rdm_pd_record_sensors(tvb, offset, tree, cc, pdl);
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

    case RDM_PARAM_ID_BACKGROUND_QUEUED_STATUS_POLICY:
      offset = dissect_rdm_pd_background_queued_status_policy(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_BACKGROUND_QUEUED_STATUS_POLICY_DESCRIPTION:
      offset = dissect_rdm_pd_background_queued_status_policy_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_ENDPOINT_LIST:
      offset = dissect_rdm_pd_endpoint_list(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_SEARCH_DOMAIN:
      offset = dissect_rdm_pd_search_domain(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_ENDPOINT_TO_UNIVERSE:
      offset = dissect_rdm_pd_endpoint_to_universe(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_RDM_TRAFFIC_ENABLE:
      offset = dissect_rdm_pd_rdm_traffic_enable(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_ENDPOINT_MODE:
      offset = dissect_rdm_pd_endpoint_mode(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_ENDPOINT_LABEL:
      offset = dissect_rdm_pd_endpoint_label(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_DISCOVERY_STATE:
      offset = dissect_rdm_pd_discovery_state(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_ENDPOINT_TIMING:
      offset = dissect_rdm_pd_endpoint_timing(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_ENDPOINT_TIMING_DESCRIPTION:
      offset = dissect_rdm_pd_endpoint_timing_description(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_BINDING_CONTROL_FIELDS:
      offset = dissect_rdm_pd_binding_control_fields(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_IDENTIFY_ENDPOINT:
      offset = dissect_rdm_pd_identify_endpoint(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_BACKGROUND_DISCOVERY:
      offset = dissect_rdm_pd_background_discovery(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_ENDPOINT_RESPONDER_LIST_CHANGE:
      offset = dissect_rdm_pd_endpoint_responder_list_change(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_ENDPOINT_RESPONDERS:
      offset = dissect_rdm_pd_endpoint_responders(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_TCP_COMMS_STATUS:
      offset = dissect_rdm_pd_tcp_comms_status(tvb, offset, tree, cc, pdl);
      break;

    case RDM_PARAM_ID_ENDPOINT_LIST_CHANGE:
      offset = dissect_rdm_pd_endpoint_list_change(tvb, offset, tree, cc);
      break;

    case RDM_PARAM_ID_COMPONENT_SCOPE:
      offset = dissect_rdm_pd_component_scope(tvb, offset, tree, cc);
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
dissect_rdm_pd_ack_overflow(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint16_t param_id _U_, uint8_t pdl)
{
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
      proto_tree_add_item(mdb_tree, hf_etc_parameter_id, tvb, offset, 2, ENC_BIG_ENDIAN);
      break;
    default:
      proto_tree_add_item(mdb_tree, hf_rdm_parameter_id, tvb, offset, 2, ENC_BIG_ENDIAN);
      break;
    }
  }
}

static unsigned
dissect_rdm_mdb(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint16_t device_manufacturer_id)
{
  uint8_t     cc;
  uint8_t     rt;
  uint16_t     param_id;
  uint8_t     parameter_data_length;
  proto_tree *hi,*si, *mdb_tree;

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

  proto_tree_add_item(tree, hf_rdm_message_count, tvb,
      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_rdm_sub_device, tvb,
      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  hi = proto_tree_add_item(tree, hf_rdm_mdb, tvb,
      offset, -1, ENC_NA);
  mdb_tree = proto_item_add_subtree(hi,ett_rdm);

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
    si = proto_item_add_subtree(hi,ett_rdm);

    if (is_response(cc)) {

      switch(rt) {
      case RDM_RESPONSE_TYPE_ACK:
        offset = dissect_rdm_mdb_param_data(tvb, offset, si, cc, param_id, parameter_data_length, device_manufacturer_id);
        break;
      case RDM_RESPONSE_TYPE_ACK_TIMER:
        offset = dissect_rdm_pd_ack_timer(tvb, offset, si, cc, param_id, parameter_data_length);
        break;
      case RDM_RESPONSE_TYPE_NACK_REASON:
        offset = dissect_rdm_pd_nack_reason(tvb, offset, si, cc, param_id, parameter_data_length);
        break;
      case RDM_RESPONSE_TYPE_ACK_OVERFLOW:
        offset = dissect_rdm_pd_ack_overflow(tvb, offset, si, cc, param_id, parameter_data_length);
        break;
      }

    } else {
      offset = dissect_rdm_mdb_param_data(tvb, offset, si, cc, param_id, parameter_data_length, device_manufacturer_id);
    }
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
    proto_tree_add_item(rdm_tree, hf_rdm_dest_uid, tvb,
        offset, 6, ENC_NA);
    offset += 6;

    source_manufacturer_id = tvb_get_ntohs(tvb, offset);
    source_device_id = tvb_get_ntohl(tvb, offset + 2);
    proto_item_append_text(ti, ", Src UID: %04x:%08x",
        source_manufacturer_id, source_device_id);
    proto_tree_add_item(rdm_tree, hf_rdm_src_uid, tvb,
        offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(rdm_tree, hf_rdm_transaction_number, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    command_class = tvb_get_uint8(tvb, offset + 4);
    device_manufacturer_id = get_device_manufacturer_id(command_class, source_manufacturer_id, destination_manufacturer_id);
    offset = dissect_rdm_mdb(tvb, offset, rdm_tree, device_manufacturer_id);

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

    { &hf_rdm_src_uid,
      { "Source UID", "rdm.src",
        FT_BYTES, BASE_NONE, NULL, 0x0,
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
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_mute_binding_uid,
      { "Binding UID", "rdm.pd.disc_mute.binding_uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_unmute_control_field,
      { "Control Field", "rdm.pd.disc_unmute.control_field",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_disc_unmute_binding_uid,
      { "Binding UID", "rdm.pd.disc_unmute.binding_uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_proxied_devices_uid,
      { "UID", "rdm.pd.proxied_devices.uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
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
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_lamp_on_mode,
      { "Lamp On Mode", "rdm.pd.lamp_on_mode",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_device_power_cycles,
      { "Device Power Cycles", "rdm.pd.device_power_cycles",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_display_invert,
      { "Display Invert", "rdm.pd.display_invert",
        FT_UINT8, BASE_HEX, NULL, 0x0,
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
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_state,
      { "Selftest State", "rdm.pd.selftest.state",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_selftest_description,
      { "Selftest Description", "rdm.pd.selftest.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
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
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_power_state,
      { "Power State", "rdm.pd.power_state",
        FT_UINT8, BASE_HEX, NULL, 0x0,
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
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_preset_playback_level,
      { "Level", "rdm.pd.preset_playback.level",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_id,
      { "ID", "rdm.pd.parameter.id",
        FT_UINT16, BASE_HEX, VALS(rdm_param_id_vals), 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_pdl_size,
      { "PDL Size", "rdm.pd.parameter.pdl_size",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_data_type,
      { "Data Type", "rdm.pd.parameter.data_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_cmd_class,
      { "Command Class", "rdm.pd.parameter.cmd_class",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_type,
      { "Type", "rdm.pd.parameter.type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_unit,
      { "Unit", "rdm.pd.parameter.unit",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_parameter_prefix,
      { "Prefix", "rdm.pd.parameter.prefix",
        FT_UINT8, BASE_DEC, NULL, 0x0,
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

    { &hf_rdm_pd_status_messages_type,
      { "Type", "rdm.pd.status_messages.type",
        FT_UINT8, BASE_HEX, NULL, 0x0,
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
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_product_detail_id_list,
      { "Sensor Count", "rdm.pd.product_detail_id_list",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_factory_defaults,
      { "Factory Defaults", "rdm.pd.factory_defaults",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_background_discovery_endpoint_id,
      { "Endpoint ID", "rdm.pd.background_discovery.endpoint_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
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

    { &hf_rdm_pd_binding_control_fields_control_field,
      { "Control Field", "rdm.pd.binding_control_fields.control_field",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_binding_control_fields_binding_uid,
      { "Binding UID", "rdm.pd.binding_control_fields.binding_uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
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
        FT_UINT16, BASE_DEC, NULL, 0x0,
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
        FT_UINT8, BASE_DEC, NULL, 0x0,
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
        FT_UINT8, BASE_DEC, NULL, 0x0,
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

    { &hf_rdm_pd_slot_offset,
      { "Slot Offset", "rdm.pd.slot_offset",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_slot_type,
      { "Slot Type", "rdm.pd.slot_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rdm_pd_slot_label_id,
      { "Slot Label ID", "rdm.pd.slot_label_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
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

    { &hf_etc_parameter_id,
      { "Parameter ID", "rdm.pid",
        FT_UINT16, BASE_HEX | BASE_EXT_STRING, &etc_param_id_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_parameter_id,
      { "ID", "rdm.pd.parameter.id",
        FT_UINT16, BASE_HEX, VALS(etc_param_id_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_device_model_id,
      { "Device Model ID", "rdm.pd.device_model_id",
        FT_UINT16, BASE_HEX, VALS(etc_model_id_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_curve,
      { "Curve", "rdm.pd.led_curve.curve",
        FT_UINT8, BASE_DEC, VALS(etc_led_curve_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_curve_description_curve,
      { "Curve", "rdm.pd.led_curve_description.curve",
        FT_UINT8, BASE_DEC, VALS(etc_led_curve_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_curve_description_text,
      { "Description", "rdm.pd.led_curve_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_strobe,
      { "Strobe", "rdm.pd.led_strobe",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_output_mode,
      { "Output Mode", "rdm.pd.led_output_mode",
        FT_UINT8, BASE_DEC, VALS(etc_led_output_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_output_mode_description_mode,
      { "Output Mode", "rdm.pd.led_output_mode_description.output_mode",
        FT_UINT8, BASE_DEC, VALS(etc_led_output_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_output_mode_description_text,
      { "Description", "rdm.pd.lled_output_mode_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_red_shift,
      { "Red Shift", "rdm.pd.led_red_shift",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_white_point,
      { "White Point", "rdm.pd.led_white_point",
        FT_UINT8, BASE_DEC, VALS(etc_led_white_point_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_white_point_description_white_point,
      { "White Point", "rdm.pd.led_white_point_description.white_point",
        FT_UINT8, BASE_DEC, VALS(etc_led_white_point_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_white_point_description_text,
      { "Description", "rdm.pd.led_white_point_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_frequency,
      { "LED Frequency (Hz)", "rdm.pd.led_frequency",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_dmx_data_loss_behavior,
      { "DMX Data Loss Behavior", "rdm.pd.dmx_data_loss_behavior",
        FT_UINT8, BASE_DEC, VALS(etc_dmx_data_loss_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_dmx_data_loss_behavior_description_behavior,
      { "DMX Data Loss Behavior", "rdm.pd.dmx_data_loss_behavior_description.behavior",
        FT_UINT8, BASE_DEC, VALS(etc_dmx_data_loss_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_dmx_data_loss_behavior_description_text,
      { "Description", "rdm.pd.dmx_data_loss_behavior_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_plus_seven,
      { "LED Plus Seven", "rdm.pd.led_plus_seven",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_backlight_brightness,
      { "Backlight Brightness", "rdm.pd.backlight_brightness",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_backlight_timeout,
      { "Backlight Timeout", "rdm.pd.backlight_timeout",
        FT_UINT8, BASE_DEC, VALS(etc_backlight_timeout_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_status_indicators,
      { "Status Indicators", "rdm.pd.status_indicators",
        FT_UINT8, BASE_DEC, VALS(on_off_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_overtemp_mode,
      { "Overtemp Mode", "rdm.pd.overtemp_mode",
        FT_UINT8, BASE_DEC, VALS(etc_overtemp_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_simple_setup_mode,
      { "Simple Setup Mode", "rdm.pd.simple_setup_mode",
        FT_UINT8, BASE_DEC, VALS(etc_simple_setup_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_strobe_description_strobe,
      { "Strobe", "rdm.pd.led_strobe_description.led_strobe",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_strobe_description_text,
      { "Description", "rdm.pd.led_strobe_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_red_shift_description_red_shift,
      { "Red Shift", "rdm.pd.red_shift_description.red_shift",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_red_shift_description_text,
      { "Description", "rdm.pd.red_shift_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_plus_seven_description_plus_seven,
      { "Plus Seven", "rdm.pd.plus_seven_description.plus_seven",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_plus_seven_description_text,
      { "Description", "rdm.pd.plus_seven_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_backlight_timeout_description_timeout,
      { "Backlight Timeout", "rdm.pd.backlight_timeout_description.backlight_timeout",
        FT_UINT8, BASE_DEC, VALS(etc_backlight_timeout_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_backlight_timeout_description_text,
      { "Description", "rdm.pd.backlight_timeout_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_simple_setup_mode_description_mode,
      { "Simple Setup Mode", "rdm.pd.simple_setup_mode_description.mode",
        FT_UINT8, BASE_DEC, VALS(etc_simple_setup_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_simple_setup_mode_description_text,
      { "Description", "rdm.pd.simple_setup_mode_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_overtemp_mode_description_mode,
      { "Overtemp Mode", "rdm.pd.overtemp_mode_description.mode",
        FT_UINT8, BASE_DEC, VALS(etc_overtemp_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_overtemp_mode_description_text,
      { "Description", "rdm.pd.overtemp_mode_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_requested_xy_x,
      { "X Coordinate", "rdm.pd.led_requested_xy.x",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_requested_xy_y,
      { "Y Coordinate", "rdm.pd.led_requested_xy.y",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_current_xy_x,
      { "X Coordinate", "rdm.pd.led_current_xy.x",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_current_xy_y,
      { "Y Coordinate", "rdm.pd.led_current_xy.y",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_current_pwm_led_number,
      { "LED Number", "rdm.pd.current_pwm.led_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_current_pwm_channel_duty_cycle,
      { "Channel Duty Cycle", "rdm.pd.current_pwm.channel_duty_cycle",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_tristimulus_led_number,
      { "LED Number", "rdm.pd.tristimulus.led_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_tristimulus_x,
      { "X", "rdm.pd.tristimulus.x",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_tristimulus_y,
      { "Y", "rdm.pd.tristimulus.y",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_tristimulus_z,
      { "Z", "rdm.pd.tristimulus.z",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_information_led_number,
      { "LED Number", "rdm.pd.led_information.led_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_information_type,
      { "Type", "rdm.pd.led_information.type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_information_dmx_control_channel,
      { "DMX Control Channel", "rdm.pd.led_information.dmx_control_channel",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_information_drive_current,
      { "Drive Current (ma)", "rdm.pd.led_information.drive_current",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_information_gamut_polygon_order,
      { "Gamut Polygon Order", "rdm.pd.led_information.gamut_polygon_order",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_information_quantity,
      { "Quantity", "rdm.pd.led_information.quantity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_preset_number,
      { "Preset Number", "rdm.pd.preset_config.preset_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_fade_time,
      { "Fade Time (seconds)", "rdm.pd.preset_config.fade_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_delay_time,
      { "Delay Time (seconds)", "rdm.pd.preset_config.delay_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_hue,
      { "Hue", "rdm.pd.preset_config.hue",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_saturation,
      { "Saturation", "rdm.pd.preset_config.saturation",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_intensity,
      { "Intensity", "rdm.pd.preset_config.intensity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_strobe,
      { "Strobe", "rdm.pd.preset_config.strobe",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_playback_sequence_number,
      { "Sequence Number", "rdm.pd.sequence_playback.sequence_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_sequence_number,
      { "Sequence Number", "rdm.pd.sequence_config.sequence_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_preset_steps,
      { "Preset Steps", "rdm.pd.sequence_config.preset_steps",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_preset_step,
      { "Preset Step", "rdm.pd.sequence_config.preset_step",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_step_link_times,
      { "Step Link Times (seconds)", "rdm.pd.sequence_config.step_link_times",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_step_link_time,
      { "Step Link Time", "rdm.pd.sequence_config.step_link_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_rate,
      { "Rate", "rdm.pd.sequence_config.rate",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_end_state,
      { "End State", "rdm.pd.sequence_config.end_state",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_low_power_timeout,
      { "Low Power Timeout", "rdm.pd.low_power_timeout",
        FT_UINT8, BASE_DEC, VALS(etc_low_power_timeout_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_low_power_timeout_description_timeout,
      { "Low Power Timeout", "rdm.pd.low_power_timeout_description.timeout",
        FT_UINT8, BASE_DEC, VALS(etc_low_power_timeout_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_low_power_timeout_description_text,
      { "Description", "rdm.pd.low_power_timeout_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_enum_frequency,
      { "Frequency", "rdm.pd.led_enum_frequency",
        FT_UINT8, BASE_DEC, VALS(etc_led_frequency_enum_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_enum_frequency_description_frequency,
      { "Frequency", "rdm.pd.led_enum_frequency_description.frequency",
        FT_UINT8, BASE_DEC, VALS(etc_led_frequency_enum_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_enum_frequency_description_text,
      { "Description", "rdm.pd.led_enum_frequency_description.description",
        FT_UINT8, BASE_DEC, VALS(etc_led_frequency_enum_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_preset_number,
      { "Preset Number", "rdm.pd.rgbi_preset_config.preset_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_fade_time,
      { "Fade Time (seconds)", "rdm.pd.rgbi_preset_config.fade_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_delay_time,
      { "Delay Time (seconds)", "rdm.pd.rgbi_preset_config.delay_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_red,
      { "Red", "rdm.pd.rgbi_preset_config.red",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_green,
      { "Green", "rdm.pd.rgbi_preset_config.green",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_blue,
      { "Blue", "rdm.pd.rgbi_preset_config.blue",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_intensity,
      { "Intensity", "rdm.pd.rgbi_preset_config.intensity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_strobe,
      { "Strobe", "rdm.pd.rgbi_preset_config.strobe",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_preset_number,
      { "Preset Number", "rdm.pd.cct_preset_config.preset_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_fade_time,
      { "Fade Time (seconds)", "rdm.pd.cct_preset_config.fade_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_delay_time,
      { "Delay Time (seconds)", "rdm.pd.cct_preset_config.delay_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_white_point,
      { "White Point", "rdm.pd.cct_preset_config.white_point",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_tint,
      { "Tint", "rdm.pd.cct_preset_config.tint",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_strobe,
      { "Strobe", "rdm.pd.cct_preset_config.strobe",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_intensity,
      { "Intensity", "rdm.pd.cct_preset_config.intensity",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_tone,
      { "Tone", "rdm.pd.cct_preset_config.tone",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_reserved,
      { "Reserved", "rdm.pd.cct_preset_config.reserved",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_supplementary_device_version_param_index,
      { "Param Index", "rdm.pd.supplementary_device_version.param_index",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_supplementary_device_version_param_description,
      { "Param Description", "rdm.pd.supplementary_device_version.param_description",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_power_command,
      { "State", "rdm.pd.power_command",
        FT_UINT8, BASE_DEC, VALS(on_off_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_power_command_description_state,
      { "State", "rdm.pd.power_command_description.state",
        FT_UINT8, BASE_DEC, VALS(on_off_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_power_command_description_text,
      { "Description", "rdm.pd.power_command_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_dali_short_address,
      { "Short Address", "rdm.pd.dali_short_address",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_dali_group_membership,
      { "Group Membership", "rdm.pd.dali_group_membership",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_auto_bind,
      { "Auto Bind", "rdm.pd.auto_bind",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_packet_delay,
      { "Packet Delay", "rdm.pd.packet_delay",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_has_enum_text_pid,
      { "PID", "rdm.pd.has_enum_text.pid",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_has_enum_text_true_false,
      { "Value", "rdm.pd.has_enum_text.value",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_get_enum_text_pid,
      { "PID", "rdm.pd.get_enum_text.pid",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_get_enum_text_enum,
      { "Enum", "rdm.pd.get_enum_text.enum",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_get_enum_text_description,
      { "Description", "rdm.pd.get_enum_text.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

  };

  static int *ett[] = {
    &ett_rdm,
    &ett_etc_sequence_config_steps,
    &ett_etc_sequence_config_times
  };

  static ei_register_info ei[] = {
    { &ei_rdm_checksum, { "rdm.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
  };

  expert_module_t* expert_rdm;

  proto_rdm = proto_register_protocol("Remote Device Management", "RDM", "rdm");
  proto_register_field_array(proto_rdm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  rdm_handle = register_dissector("rdm", dissect_rdm, proto_rdm);
  expert_rdm = expert_register_protocol(proto_rdm);
  expert_register_field_array(expert_rdm, ei, array_length(ei));
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
