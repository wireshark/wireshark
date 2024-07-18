/* packet-rf4ce-nwk.c
 * Network layer related functions and objects for RF4CE dissector
 * Copyright (C) Atmosic 2023
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdbool.h>
#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include "packet-ieee802154.h"
#include "packet-rf4ce-secur.h"

#define RF4CE_MIN_NWK_LENGTH        5
#define RF4CE_MAX_NWK_LENGTH        148

/* Profile IDs */
#define RF4CE_NWK_PROFILE_ID_GDP    0x00
#define RF4CE_NWK_PROFILE_ID_ZRC10  0x01
#define RF4CE_NWK_PROFILE_ID_ZID    0x02
#define RF4CE_NWK_PROFILE_ID_ZRC20  0x03

#define RF4CE_PROTOABBREV_NWK       "rf4ce_nwk"
#define RF4CE_PROTOABBREV_PROFILE   "rf4ce_profile"

static int proto_rf4ce_nwk;
static dissector_handle_t rf4ce_gdp_handle;

/* UAT vars */
static uat_t *rf4ce_security_table_uat;

#define RF4CE_SEC_STR_TYPE_NWK_KEY       0
#define RF4CE_SEC_STR_TYPE_VENDOR_SECRET 1

static const value_string sec_str_type_vals[] = {
    { RF4CE_SEC_STR_TYPE_NWK_KEY,       "NWK Key"},
    { RF4CE_SEC_STR_TYPE_VENDOR_SECRET, "Vendor Secret"},
    { 0, NULL }
};

UAT_CSTRING_CB_DEF(uat_security_records, sec_str, uat_security_record_t)
UAT_VS_DEF(uat_security_records, type, uat_security_record_t, uint8_t, 0, "NWK Key")
UAT_CSTRING_CB_DEF(uat_security_records, label, uat_security_record_t)

static uat_security_record_t *uat_security_records;
static unsigned num_uat_security_records;

static int ett_rf4ce_nwk;
static int ett_rf4ce_nwk_payload;
static int ett_rf4ce_nwk_vendor_info;
static int ett_rf4ce_nwk_usr_str;
static int ett_rf4ce_nwk_usr_str_class_descriptor;
static int ett_rf4ce_nwk_dev_types_list;
static int ett_rf4ce_nwk_profiles_list;

/* RF4CE NWK header */
static int hf_rf4ce_nwk_fcf;
static int hf_rf4ce_nwk_fcf_frame_type;
static int hf_rf4ce_nwk_fcf_security_enabled;
static int hf_rf4ce_nwk_fcf_protocol_version;
static int hf_rf4ce_nwk_fcf_reserved;
static int hf_rf4ce_nwk_fcf_channel_designator;
static int hf_rf4ce_nwk_seq_num;
static int hf_rf4ce_nwk_profile_id;
static int hf_rf4ce_nwk_vendor_id;

/* RF4CE NWK payload common */
static int hf_rf4ce_nwk_cmd_id;

static int hf_rf4ce_nwk_node_capabilities;
static int hf_rf4ce_nwk_node_capabilities_node_type;
static int hf_rf4ce_nwk_node_capabilities_power_source;
static int hf_rf4ce_nwk_node_capabilities_security;
static int hf_rf4ce_nwk_node_capabilities_channel_normalization;
static int hf_rf4ce_nwk_node_capabilities_reserved;

static int hf_rf4ce_nwk_disc_req_vendor_id;

#define RF4CE_NWK_VENDOR_STRING_MAX_LENGTH 7
static int hf_rf4ce_nwk_vendor_string;

static int hf_rf4ce_nwk_app_capabilities;
static int hf_rf4ce_nwk_app_capabilities_usr_str;
static int hf_rf4ce_nwk_app_capabilities_supported_dev_num;
static int hf_rf4ce_nwk_app_capabilities_reserved1;
static int hf_rf4ce_nwk_app_capabilities_supported_profiles_num;
static int hf_rf4ce_nwk_app_capabilities_reserved2;

static int hf_rf4ce_nwk_usr_str;
static int hf_rf4ce_nwk_usr_str_disc_rsp_app_usr_str;
static int hf_rf4ce_nwk_usr_str_disc_rsp_null;
static int hf_rf4ce_nwk_usr_str_disc_rsp_reserved;

static int hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_tertiary;
static int hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_secondary;
static int hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_primary;

static int hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_class_num;
static int hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_duplicate_class_num_handling;
static int hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_reserved;

static int hf_rf4ce_nwk_usr_str_disc_rsp_discovery_lqi_threshold;

#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_MASK                    0b00001111
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_DUPLICATE_CLASS_NUM_HANDLING_MASK 0b00110000
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_RESERVED_MASK                     0b11000000

#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_PRE_COMMISSIONED           0x00
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_BUTTON_PRESS_INDICATION    0x01
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_RESERVED_2                 0x02
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_RESERVED_3                 0x03
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_04 0x04
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_05 0x05
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_06 0x06
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_07 0x07
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_08 0x08
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_09 0x09
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_0A 0x0A
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_0B 0x0B
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_0C 0x0C
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_0D 0x0D
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_0E 0x0E
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_DISCOVERABLE_ONLY          0x0F

static const value_string rf4ce_nwk_usr_str_disc_rsp_class_desc_class_num_vals[] = {
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_PRE_COMMISSIONED,           "Pre-Commissioned" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_BUTTON_PRESS_INDICATION,    "Button Press Indication" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_RESERVED_2,                 "Reserved" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_RESERVED_3,                 "Reserved" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_04, "Implementation Specific" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_05, "Implementation Specific" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_06, "Implementation Specific" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_07, "Implementation Specific" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_08, "Implementation Specific" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_09, "Implementation Specific" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_0A, "Implementation Specific" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_0B, "Implementation Specific" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_0C, "Implementation Specific" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_0D, "Implementation Specific" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_IMPLEMENTATION_SPECIFIC_0E, "Implementation Specific" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_DISCOVERABLE_ONLY,          "Discoverable Only" },
    { 0, NULL }
};

#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_DUPLICATE_CLASS_NUM_HANDLING_AS_IS         0x00
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_DUPLICATE_CLASS_NUM_HANDLING_RECLASSIFY    0x01
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_DUPLICATE_CLASS_NUM_HANDLING_ABORT_BINDING 0x02
#define RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_DUPLICATE_CLASS_NUM_HANDLING_RESERVED      0x03

static const value_string rf4ce_nwk_usr_str_disc_rsp_class_desc_duplicate_class_num_handling_vals[] = {
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_DUPLICATE_CLASS_NUM_HANDLING_AS_IS,         "Use node descriptor as is" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_DUPLICATE_CLASS_NUM_HANDLING_RECLASSIFY,    "Reclassify node descriptor" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_DUPLICATE_CLASS_NUM_HANDLING_ABORT_BINDING, "Abort binding" },
    { RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_DUPLICATE_CLASS_NUM_HANDLING_RESERVED,      "Reserved" },
    { 0, NULL }
};

#define RF4CE_NWK_USR_STR_DISC_RSP_APP_USR_STR_LENGTH 9

#define RF4CE_NWK_USR_STR_PARSING_MASK_NONE      0b00000001
#define RF4CE_NWK_USR_STR_PARSING_MASK_DISC_RESP 0b00000010

static int hf_rf4ce_nwk_app_cap_dev_type;
static int hf_rf4ce_nwk_app_cap_profile_id;

/* RF4CE NWK Discovery Request */
static int hf_rf4ce_nwk_requested_dev_type;

/* RF4CE NWK Discovery Response */
static int hf_rf4ce_nwk_disc_resp_status;
static int hf_rf4ce_nwk_disc_resp_lqi;

/* RF4CE NWK Pair Request */
static int hf_rf4ce_nwk_pair_req_nwk_addr;
static int hf_rf4ce_nwk_pair_req_key_exch_num;

/* RF4CE NWK Pair Response */
static int hf_rf4ce_nwk_pair_rsp_status;
static int hf_rf4ce_nwk_pair_rsp_allocated_nwk_addr;
static int hf_rf4ce_nwk_pair_rsp_nwk_addr;

/* RF4CE NWK Key Seed */
static int hf_rf4ce_nwk_seed_seq_num;

#define RF4CE_NWK_KEY_SEED_DATA_LENGTH 80
static int hf_rf4ce_nwk_seed_data;

/* RF4CE NWK Ping Request and Response */
static int hf_rf4ce_nwk_ping_options;
static int hf_rf4ce_nwk_ping_payload;

#if 0
/* Should be at the end of a decrypted NWK packet */
static int hf_rf4ce_nwk_mic;
#endif

static int hf_rf4ce_nwk_unparsed_payload;

/* Frame Control Field */
#define RF4CE_NWK_FCF_FRAME_TYPE_MASK         0b00000011
#define RF4CE_NWK_FCF_SECURITY_MASK           0b00000100
#define RF4CE_NWK_FCF_PROTOCOL_VERSION_MASK   0b00011000
#define RF4CE_NWK_FCF_RESERVED_MASK           0b00100000
#define RF4CE_NWK_FCF_CHANNEL_DESIGNATOR_MASK 0b11000000

/* Frame types */
#define RF4CE_NWK_FCF_FRAME_TYPE_RESERVED        0
#define RF4CE_NWK_FCF_FRAME_TYPE_DATA            1
#define RF4CE_NWK_FCF_FRAME_TYPE_CMD             2
#define RF4CE_NWK_FCF_FRAME_TYPE_VENDOR_SPECIFIC 3

static const value_string rf4ce_nwk_frame_types[] = {
    { RF4CE_NWK_FCF_FRAME_TYPE_RESERVED,        "Reserved" },
    { RF4CE_NWK_FCF_FRAME_TYPE_DATA,            "Standard Data Frame" },
    { RF4CE_NWK_FCF_FRAME_TYPE_CMD,             "NWK Command Frame" },
    { RF4CE_NWK_FCF_FRAME_TYPE_VENDOR_SPECIFIC, "Vendor-specific data frame" },
    { 0, NULL }
};

/* Channel Designators */
#define RF4CE_NWK_FCF_CHANNEL_NOT_SPECIFIED 0
#define RF4CE_NWK_FCF_CHANNEL_15            1
#define RF4CE_NWK_FCF_CHANNEL_20            2
#define RF4CE_NWK_FCF_CHANNEL_25            3

static const value_string rf4ce_nwk_channel_designators[] = {
    { RF4CE_NWK_FCF_CHANNEL_NOT_SPECIFIED, "Channel not specified" },
    { RF4CE_NWK_FCF_CHANNEL_15,            "Channel 15" },
    { RF4CE_NWK_FCF_CHANNEL_20,            "Channel 20" },
    { RF4CE_NWK_FCF_CHANNEL_25,            "Channel 25" },
    { 0, NULL }
};

/* Profile IDs */
#define RF4CE_NWK_PROFILE_ID_GDP            0x00
#define RF4CE_NWK_PROFILE_ID_ZRC10          0x01
#define RF4CE_NWK_PROFILE_ID_ZID            0x02
#define RF4CE_NWK_PROFILE_ID_ZRC20          0x03
#define RF4CE_NWK_PROFILE_ID_WILDCARD       0xff

/* Vendor IDs */
#define RF4CE_VENDOR_ID_PANASONIC           0x0001
#define RF4CE_VENDOR_ID_SONY                0x0002
#define RF4CE_VENDOR_ID_SAMSUNG             0x0003
#define RF4CE_VENDOR_ID_PHILIPS             0x0004
#define RF4CE_VENDOR_ID_FREESCALE           0x0005
#define RF4CE_VENDOR_ID_OKI                 0x0006
#define RF4CE_VENDOR_ID_TEXAS_INSTRUMENTS   0x0007
#define RF4CE_VENDOR_ID_TEST_1              0xfff1
#define RF4CE_VENDOR_ID_TEST_2              0xfff2
#define RF4CE_VENDOR_ID_TEST_3              0xfff3

static const value_string rf4ce_nwk_profile_ids[] = {
    { RF4CE_NWK_PROFILE_ID_GDP,   "GDP" },
    { RF4CE_NWK_PROFILE_ID_ZRC10, "ZRC 1.0" },
    { RF4CE_NWK_PROFILE_ID_ZID,   "ZID" },
    { RF4CE_NWK_PROFILE_ID_ZRC20, "ZRC 2.0" },
    { 0, NULL }
};

/* NWK Commands */
#define RF4CE_NWK_CMD_DISCOVERY_REQ 0x01
#define RF4CE_NWK_CMD_DISCOVERY_RSP 0x02
#define RF4CE_NWK_CMD_PAIR_REQ      0x03
#define RF4CE_NWK_CMD_PAIR_RSP      0x04
#define RF4CE_NWK_CMD_UNPAIR_REQ    0x05
#define RF4CE_NWK_CMD_KEY_SEED      0x06
#define RF4CE_NWK_CMD_PING_REQ      0x07
#define RF4CE_NWK_CMD_PING_RSP      0x08

static const value_string rf4ce_nwk_cmd_names[] = {
    { RF4CE_NWK_CMD_DISCOVERY_REQ, "Discovery Request" },
    { RF4CE_NWK_CMD_DISCOVERY_RSP, "Discovery Response" },
    { RF4CE_NWK_CMD_PAIR_REQ,      "Pair Request" },
    { RF4CE_NWK_CMD_PAIR_RSP,      "Pair Response" },
    { RF4CE_NWK_CMD_UNPAIR_REQ,    "Unpair Request" },
    { RF4CE_NWK_CMD_KEY_SEED,      "Key Seed" },
    { RF4CE_NWK_CMD_PING_REQ,      "Ping Request" },
    { RF4CE_NWK_CMD_PING_RSP,      "Ping Response" },
    { 0, NULL }
};

/* NWK Commands - Discovery Request - Node Capabilities */
#define RF4CE_NWK_NODE_TYPE_MASK             0b00000001
#define RF4CE_NWK_POWER_SOURCE_MASK          0b00000010
#define RF4CE_NWK_SECURITY_MASK              0b00000100
#define RF4CE_NWK_CHANNEL_NORMALIZATION_MASK 0b00001000
#define RF4CE_NWK_RESERVED_MASK              0b11110000

#define RF4CE_NWK_NODE_TYPE_CONTROLLER 0
#define RF4CE_NWK_NODE_TYPE_TARGET     1

static const value_string rf4ce_nwk_node_types[] = {
    { RF4CE_NWK_NODE_TYPE_CONTROLLER, "Controller" },
    { RF4CE_NWK_NODE_TYPE_TARGET,     "Target" },
    { 0, NULL }
};

#define RF4CE_NWK_POWER_SOURCE_NO_ALTERNATING_CURRENT_MAINS 0
#define RF4CE_NWK_POWER_SOURCE_ALTERNATING_CURRENT_MAINS    1

static const value_string rf4ce_nwk_power_sources[] = {
    { RF4CE_NWK_POWER_SOURCE_NO_ALTERNATING_CURRENT_MAINS, "No Alternating Current Mains" },
    { RF4CE_NWK_POWER_SOURCE_ALTERNATING_CURRENT_MAINS, "Alternating Current Mains" },
    { 0, NULL }
};

#define RF4CE_DISC_REQ_VENDOR_ID_TEXAS_INSTRUMENTS 0x0007
static const value_string rf4ce_disc_req_vendor_ids[] = {
    { RF4CE_DISC_REQ_VENDOR_ID_TEXAS_INSTRUMENTS, "Texas Instruments" },
    { 0, NULL }
};

/* NWK Commands - Discovery Request - App Capabilities */
#define RF4CE_NWK_USR_STR_SPECIFIED_MASK      0b00000001
#define RF4CE_NWK_SUPPORTED_DEV_NUM_MASK      0b00000110
#define RF4CE_NWK_RESERVED1_MASK              0b00001000
#define RF4CE_NWK_SUPPORTED_PROFILES_NUM_MASK 0b01110000
#define RF4CE_NWK_RESERVED2_MASK              0b10000000

#define RF4CE_NWK_USR_STR_LENGTH 15
#define RF4CE_NWK_SUPPORTED_DEV_NUM_OFFSET 1
#define RF4CE_NWK_SUPPORTED_PROFILES_NUM_OFFSET 4

/* NWK Commands - Discovery Request - Device Types */
#define RF4CE_DEVICE_RESERVED_INVALID               0x00
#define RF4CE_DEVICE_REMOTE_CONTROL                 0x01
#define RF4CE_DEVICE_TELEVISION                     0x02
#define RF4CE_DEVICE_PROJECTOR                      0x03
#define RF4CE_DEVICE_PLAYER                         0x04
#define RF4CE_DEVICE_RECORDER                       0x05
#define RF4CE_DEVICE_VIDEO_PLAYER_RECORDER          0x06
#define RF4CE_DEVICE_AUDIO_PLAYER_RECORDER          0x07
#define RF4CE_DEVICE_AUDIO_VIDEO_RECORDER           0x08
#define RF4CE_DEVICE_SET_TOP_BOX                    0x09
#define RF4CE_DEVICE_HOME_THEATER_SYSTEM            0x0a
#define RF4CE_DEVICE_MEDIA_CENTER_PC                0x0b
#define RF4CE_DEVICE_GAME_CONSOLE                   0x0c
#define RF4CE_DEVICE_SATELLITE_RADIO_RECEIVER       0x0d
#define RF4CE_DEVICE_IR_EXTENDER                    0x0e
#define RF4CE_DEVICE_MONITOR                        0x0f
#define RF4CE_DEVICE_ALL_DEVICES                    0xff

static const value_string rf4ce_nwk_device_type_vals[] = {
    { RF4CE_DEVICE_RESERVED_INVALID,         "Invalid" },
    { RF4CE_DEVICE_REMOTE_CONTROL,           "Remote Control" },
    { RF4CE_DEVICE_TELEVISION,               "Television" },
    { RF4CE_DEVICE_PROJECTOR,                "Projector" },
    { RF4CE_DEVICE_PLAYER,                   "Player" },
    { RF4CE_DEVICE_RECORDER,                 "Recorder" },
    { RF4CE_DEVICE_VIDEO_PLAYER_RECORDER,    "Video Player Recorder" },
    { RF4CE_DEVICE_AUDIO_PLAYER_RECORDER,    "Audio Player Recorder" },
    { RF4CE_DEVICE_AUDIO_VIDEO_RECORDER,     "Audio Video Recorder" },
    { RF4CE_DEVICE_SET_TOP_BOX,              "Set Top Box" },
    { RF4CE_DEVICE_HOME_THEATER_SYSTEM,      "Home Theater System" },
    { RF4CE_DEVICE_MEDIA_CENTER_PC,          "Media Center PC" },
    { RF4CE_DEVICE_GAME_CONSOLE,             "Game Console" },
    { RF4CE_DEVICE_SATELLITE_RADIO_RECEIVER, "Satellite Radio Receiver" },
    { RF4CE_DEVICE_IR_EXTENDER,              "IR Extender" },
    { RF4CE_DEVICE_MONITOR,                  "Monitor" },
    { RF4CE_DEVICE_ALL_DEVICES,              "All the Devices" },
    { 0, NULL }
};

#define RF4CE_NWK_STATUS_SUCCESS               0x00
#define RF4CE_NWK_STATUS_NO_ORG_CAPACITY       0xb0
#define RF4CE_NWK_STATUS_NO_REC_CAPACITY       0xb1
#define RF4CE_NWK_STATUS_NO_PAIRING            0xb2
#define RF4CE_NWK_STATUS_NO_RESPONSE           0xb3
#define RF4CE_NWK_STATUS_NOT_PERMITTED         0xb4
#define RF4CE_NWK_STATUS_DUPLICATE_PAIRING     0xb5
#define RF4CE_NWK_STATUS_FRAME_COUNTER_EXPIRED 0xb6
#define RF4CE_NWK_STATUS_DISCOVERY_ERROR       0xb7
#define RF4CE_NWK_STATUS_DISCOVERY_TIMEOUT     0xb8
#define RF4CE_NWK_STATUS_SECURITY_TIMEOUT      0xb9
#define RF4CE_NWK_STATUS_SECURITY_FAILURE      0xba
#define RF4CE_NWK_STATUS_INVALID_PARAMETER     0xe8
#define RF4CE_NWK_STATUS_UNSUPPORTED_ATTRIBUTE 0xf4
#define RF4CE_NWK_STATUS_INVALID_INDEX         0xf9

static const value_string rf4ce_nwk_disc_status_vals[] = {
    { RF4CE_NWK_STATUS_SUCCESS,               "Success" },
    { RF4CE_NWK_STATUS_NO_ORG_CAPACITY,       "No Org Capacity" },
    { RF4CE_NWK_STATUS_NO_REC_CAPACITY,       "No Rec Capacity" },
    { RF4CE_NWK_STATUS_NO_PAIRING,            "No Pairing" },
    { RF4CE_NWK_STATUS_NO_RESPONSE,           "No Response" },
    { RF4CE_NWK_STATUS_NOT_PERMITTED,         "Not Permitted" },
    { RF4CE_NWK_STATUS_DUPLICATE_PAIRING,     "Duplicate Pairing" },
    { RF4CE_NWK_STATUS_FRAME_COUNTER_EXPIRED, "Frame Counter Expired" },
    { RF4CE_NWK_STATUS_DISCOVERY_ERROR,       "Discovery Error" },
    { RF4CE_NWK_STATUS_DISCOVERY_TIMEOUT,     "Discovery Timeout" },
    { RF4CE_NWK_STATUS_SECURITY_TIMEOUT,      "Security Timeout" },
    { RF4CE_NWK_STATUS_SECURITY_FAILURE,      "Security Failure" },
    { RF4CE_NWK_STATUS_INVALID_PARAMETER,     "Invalid Parameter" },
    { RF4CE_NWK_STATUS_UNSUPPORTED_ATTRIBUTE, "Unsupported Attribute" },
    { RF4CE_NWK_STATUS_INVALID_INDEX,         "Invalid Index" },
    { 0, NULL }
};

static bool dissect_rf4ce_nwk_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

/* RF4CE NWK commands dissectors */
static int dissect_rf4ce_nwk_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

static void dissect_rf4ce_nwk_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset);

static void dissect_rf4ce_nwk_common_node_capabilities(tvbuff_t *tvb, proto_tree *tree, int *offset);
static void dissect_rf4ce_nwk_common_vendor_info(tvbuff_t *tvb, proto_tree *tree, int *offset);
static void dissect_rf4ce_nwk_common_app_capabilities(tvbuff_t *tvb, proto_tree *tree, int *offset, uint8_t parsing_mask);
static void dissect_rf4ce_nwk_disc_resp_class_descriptor(tvbuff_t *tvb, proto_tree *tree, int *offset, int hf);

static void dissect_rf4ce_nwk_cmd_disc_req(tvbuff_t *tvb, proto_tree *tree, int *offset);
static void dissect_rf4ce_nwk_cmd_disc_rsp(tvbuff_t *tvb, proto_tree *tree, int *offset);

static void dissect_rf4ce_nwk_cmd_pair_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset);
static void dissect_rf4ce_nwk_cmd_pair_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset);

static void dissect_rf4ce_nwk_cmd_key_seed(tvbuff_t *tvb, proto_tree *tree, int *offset);

static void dissect_rf4ce_nwk_cmd_ping(tvbuff_t *tvb, proto_tree *tree, int *offset);

static void rf4ce_cleanup(void)
{
    rf4ce_secur_cleanup();
}

static void *uat_sec_record_copy_cb(void *n, const void *o, size_t siz _U_)
{
    uat_security_record_t *new_sec_rec = (uat_security_record_t *)n;
    const uat_security_record_t *old_sec_rec = (const uat_security_record_t *)o;

    new_sec_rec->sec_str = g_strdup(old_sec_rec->sec_str);
    new_sec_rec->type = old_sec_rec->type;
    new_sec_rec->label = g_strdup(old_sec_rec->label);

    return new_sec_rec;
}

static bool rf4ce_security_parse_sec_str(const char *data_str, uint8_t *dst_buf)
{
    int i, j;
    char temp;
    bool string_mode = false;

    if (data_str == NULL || dst_buf == NULL)
    {
        return false;
    }

    /* Clear the key. */
    memset(dst_buf, 0, SEC_STR_LEN);

    /*
     * Attempt to parse the key string. The key string must
     * be at least 16 pairs of hexidecimal digits with the
     * following optional separators: ':', '-', " ", or 16
     * alphanumeric characters after a double-quote.
     */
    temp = *data_str++;
    if (temp == '"')
    {
        string_mode = true;
        temp = *data_str++;
    }

    j = 0;
    for (i = SEC_STR_LEN - 1; i >= 0; i--)
    {
        if (string_mode)
        {
            if (g_ascii_isprint(temp))
            {
                dst_buf[j] = temp;
                temp = *data_str++;
            }
            else
            {
                return false;
            }
        }
        else
        {
            /* If this character is a separator, skip it. */
            if ((temp == ':') || (temp == '-') || (temp == ' '))
            {
                temp = *(data_str++);
            }

            /* Process a nibble. */
            if (g_ascii_isxdigit(temp))
            {
                dst_buf[j] = g_ascii_xdigit_value(temp) << 4;
            }
            else
            {
                return false;
            }

            /* Get the next nibble. */
            temp = *(data_str++);

            /* Process another nibble. */
            if (g_ascii_isxdigit(temp))
            {
                dst_buf[j] |= g_ascii_xdigit_value(temp);
            }
            else
            {
                return false;
            }

            /* Get the next nibble. */
            temp = *(data_str++);
        }

        j++;
    } /* for */

    /* If we get this far, then the key was good. */
    return true;
}

static bool uat_sec_record_update_cb(void *r, char **err)
{
    uat_security_record_t *rec = (uat_security_record_t *)r;
    uint8_t sec_str[SEC_STR_LEN] = {0};

    if (rec->sec_str == NULL)
    {
        *err = g_strdup("Data field can't be blank");
        return false;
    }

    g_strstrip(rec->sec_str);

    if (rf4ce_security_parse_sec_str(rec->sec_str, sec_str))
    {
        *err = NULL;

        if (rec->type == RF4CE_SEC_STR_TYPE_NWK_KEY)
        {
            nwk_key_storage_add_entry(
                sec_str,
                NULL, /* controller addr */
                NULL, /* target addr     */
                true, /* key from GUI    */
                false /* packet number   */);

            vendor_secret_storage_release_entry(sec_str);
        }
        else
        {
            vendor_secret_storage_add_entry(sec_str);
            nwk_key_storage_release_entry(sec_str, true /* key from GUI */);
        }
    }
    else
    {
        *err = ws_strdup_printf(
            "Expecting %d hexadecimal bytes or a %d character double-quoted string", SEC_STR_LEN, SEC_STR_LEN);
        return false;
    }

    return true;
}

static void uat_sec_record_free_cb(void *r)
{
    uat_security_record_t *sec_record = (uat_security_record_t *)r;
    uint8_t sec_str[SEC_STR_LEN];

    if (rf4ce_security_parse_sec_str(sec_record->sec_str, sec_str))
    {
        if (sec_record->type == RF4CE_SEC_STR_TYPE_NWK_KEY)
        {
            nwk_key_storage_release_entry(sec_str, true /* key from GUI */);
        }
        else
        {
            vendor_secret_storage_release_entry(sec_str);
        }
    }

    g_free(sec_record->sec_str);
    g_free(sec_record->label);
}

static void uat_sec_record_post_update(void)
{
    uint8_t sec_str[SEC_STR_LEN];

    vendor_secret_storage_add_entry(DEFAULT_SECRET);

    /* Load the pre-configured slist from the UAT. */
    for (unsigned i = 0; (uat_security_records) && (i < num_uat_security_records); i++)
    {
        if (rf4ce_security_parse_sec_str(uat_security_records[i].sec_str, sec_str))
        {
            if (uat_security_records[i].type == RF4CE_SEC_STR_TYPE_NWK_KEY)
            {
                nwk_key_storage_add_entry(
                    sec_str,
                    NULL, /* controller addr */
                    NULL, /* target addr     */
                    true, /* key from GUI    */
                    false /* packet number   */);

                vendor_secret_storage_release_entry(sec_str);
            }
            else
            {
                vendor_secret_storage_add_entry(sec_str);
                nwk_key_storage_release_entry(sec_str, true /* key from GUI */);
            }
        }
    }
}

static bool dissect_rf4ce_nwk_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    unsigned reported_length = tvb_reported_length(tvb);
    unsigned length = tvb_captured_length(tvb);
    uint8_t fcf;
    uint8_t frame_type;
    uint8_t security_enabled;
    uint8_t reserved;
    uint8_t profile_id;
    uint16_t vendor_id;
    uint8_t command_id;

    if (reported_length >= RF4CE_MIN_NWK_LENGTH && reported_length <= RF4CE_MAX_NWK_LENGTH)
    {
        if (length < RF4CE_MIN_NWK_LENGTH)
        {
            return false;
        }
        fcf = tvb_get_uint8(tvb, 0);
        frame_type = fcf & RF4CE_NWK_FCF_FRAME_TYPE_MASK;
        security_enabled = fcf & RF4CE_NWK_FCF_SECURITY_MASK;
        reserved = (fcf & RF4CE_NWK_FCF_RESERVED_MASK) >> 5;

        switch (frame_type)
        {
            case RF4CE_NWK_FCF_FRAME_TYPE_DATA:
            case RF4CE_NWK_FCF_FRAME_TYPE_CMD:
            case RF4CE_NWK_FCF_FRAME_TYPE_VENDOR_SPECIFIC:
                /* Accepted frame types */
                break;

            default:
                return false;
        }
        /* Reserved value must be 1 */
        if (reserved != 1)
        {
            return false;
        }
        if((frame_type == RF4CE_NWK_FCF_FRAME_TYPE_DATA) || (frame_type == RF4CE_NWK_FCF_FRAME_TYPE_VENDOR_SPECIFIC))
        {
            if (length < 6)
            {
                return false;
            }
            profile_id = tvb_get_uint8(tvb, 5);
            if ((profile_id >= 0x04) && (profile_id <= 0xbf))
            {
                return false;
            }
            if (frame_type == RF4CE_NWK_FCF_FRAME_TYPE_VENDOR_SPECIFIC)
            {
                if (length < 8)
                {
                    return false;
                }
                vendor_id = tvb_get_letohs(tvb, 6);
                switch (vendor_id)
                {
                    case RF4CE_VENDOR_ID_PANASONIC:
                    case RF4CE_VENDOR_ID_SONY:
                    case RF4CE_VENDOR_ID_SAMSUNG:
                    case RF4CE_VENDOR_ID_PHILIPS:
                    case RF4CE_VENDOR_ID_FREESCALE:
                    case RF4CE_VENDOR_ID_OKI:
                    case RF4CE_VENDOR_ID_TEXAS_INSTRUMENTS:
                    case RF4CE_VENDOR_ID_TEST_1:
                    case RF4CE_VENDOR_ID_TEST_2:
                    case RF4CE_VENDOR_ID_TEST_3:
                        /* Allowed vendor IDs */
                        break;

                    default:
                        return false;
                }
            }
        }
        else if(frame_type == RF4CE_NWK_FCF_FRAME_TYPE_CMD)
        {
            if (length < 6)
            {
                return false;
            }
            /* If security is enabled, the command ID will be encrypted */
            if (!security_enabled)
            {
                command_id = tvb_get_uint8(tvb, 5);
                switch (command_id)
                {
                    case RF4CE_NWK_CMD_DISCOVERY_REQ:
                    case RF4CE_NWK_CMD_DISCOVERY_RSP:
                    case RF4CE_NWK_CMD_PAIR_REQ:
                    case RF4CE_NWK_CMD_PAIR_RSP:
                    case RF4CE_NWK_CMD_UNPAIR_REQ:
                    case RF4CE_NWK_CMD_KEY_SEED:
                    case RF4CE_NWK_CMD_PING_REQ:
                    case RF4CE_NWK_CMD_PING_RSP:
                        /* Allowed command IDs */
                        break;

                    default:
                        return false;
                }
            }
        }
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RF4CE NWK");
        col_clear(pinfo->cinfo, COL_INFO);

        dissect_rf4ce_nwk_common(tvb, pinfo, tree, data);

        return true;
    }
    return false;
}

static int dissect_rf4ce_nwk_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    unsigned offset = 0;
    bool success;
    uint8_t *decrypted = (uint8_t *)wmem_alloc(pinfo->pool, 512);
    uint8_t src_addr[RF4CE_IEEE_ADDR_LEN] = {0};
    uint8_t dst_addr[RF4CE_IEEE_ADDR_LEN] = {0};

    uint8_t fcf = 0xff;
    uint8_t frame_type = 0xff;
    uint8_t profile_id = 0xff;
    uint16_t size;

    proto_item *ti = proto_tree_add_item(tree, proto_rf4ce_nwk, tvb, 0, -1, ENC_LITTLE_ENDIAN);
    proto_tree *rf4ce_nwk_tree = proto_item_add_subtree(ti, ett_rf4ce_nwk);

    static int *const nwk_fcf_bits[] = {
        &hf_rf4ce_nwk_fcf_frame_type,
        &hf_rf4ce_nwk_fcf_security_enabled,
        &hf_rf4ce_nwk_fcf_protocol_version,
        &hf_rf4ce_nwk_fcf_reserved,
        &hf_rf4ce_nwk_fcf_channel_designator,
        NULL};

    proto_tree_add_bitmask(rf4ce_nwk_tree, tvb, offset, hf_rf4ce_nwk_fcf, ett_rf4ce_nwk, nwk_fcf_bits, ENC_LITTLE_ENDIAN);
    fcf = tvb_get_uint8(tvb, offset);
    offset += 1;

    proto_tree_add_item(rf4ce_nwk_tree, hf_rf4ce_nwk_seq_num, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    frame_type = fcf & RF4CE_NWK_FCF_FRAME_TYPE_MASK;

    if (frame_type == RF4CE_NWK_FCF_FRAME_TYPE_DATA || frame_type == RF4CE_NWK_FCF_FRAME_TYPE_VENDOR_SPECIFIC)
    {
        proto_tree_add_item(rf4ce_nwk_tree, hf_rf4ce_nwk_profile_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        profile_id = tvb_get_uint8(tvb, offset);
        offset += 1;
    }

    if (frame_type == RF4CE_NWK_FCF_FRAME_TYPE_VENDOR_SPECIFIC)
    {
        proto_tree_add_item(rf4ce_nwk_tree, hf_rf4ce_nwk_vendor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    rf4ce_addr_table_get_ieee_addr(src_addr, pinfo, true);
    rf4ce_addr_table_get_ieee_addr(dst_addr, pinfo, false);

    size = tvb_captured_length_remaining(tvb, 0);

    if (fcf & RF4CE_NWK_FCF_SECURITY_MASK)
    {
        success = decrypt_data(
            tvb_get_ptr(tvb, 0, size),
            decrypted,
            offset,
            &size,
            src_addr,
            dst_addr);
    }
    else if (size > offset)
    {
        size -= offset;
        tvb_memcpy(tvb, decrypted, offset, size);
        success = true;
    }
    else
    {
        success = false;
    }

    if (success)
    {
        unsigned decrypted_offset = 0;

        /* On decryption success: replace the tvb, make offset point to its beginning */
        tvb = tvb_new_child_real_data(tvb, decrypted, size, size);
        add_new_data_source(pinfo, tvb, "CCM* decrypted payload");

        if (frame_type == RF4CE_NWK_FCF_FRAME_TYPE_CMD)
        {
            proto_tree *nwk_payload_tree = proto_tree_add_subtree(rf4ce_nwk_tree, tvb, decrypted_offset, tvb_captured_length(tvb) - decrypted_offset, ett_rf4ce_nwk_payload, NULL, "NWK Payload");
            dissect_rf4ce_nwk_cmd(tvb, pinfo, nwk_payload_tree, &decrypted_offset);
        }
        else if (frame_type == RF4CE_NWK_FCF_FRAME_TYPE_DATA)
        {
            if (profile_id == RF4CE_NWK_PROFILE_ID_GDP)
            {
                decrypted_offset += call_dissector_with_data(rf4ce_gdp_handle, tvb, pinfo, tree, (void *)("GDP"));
            }
            else if (profile_id == RF4CE_NWK_PROFILE_ID_ZRC20)
            {
                decrypted_offset += call_dissector_with_data(rf4ce_gdp_handle, tvb, pinfo, tree, (void *)("ZRC 2.0"));
            }
            else if (profile_id == RF4CE_NWK_PROFILE_ID_ZRC10)
            {
                decrypted_offset += call_dissector_with_data(rf4ce_gdp_handle, tvb, pinfo, tree, (void *)("ZRC 1.0"));
            }
        }

        offset += decrypted_offset;
    }
    else
    {
        /* On decryption error: make offset point to the end of original tvb */
        offset = tvb_reported_length(tvb);
    }

    if (offset < tvb_captured_length(tvb))
    {
        unsigned unparsed_length = tvb_captured_length(tvb) - offset;
        proto_tree_add_item(rf4ce_nwk_tree, hf_rf4ce_nwk_unparsed_payload, tvb, offset, unparsed_length, ENC_NA);
#if 0
        /* enable this block if you need to add NWK MIC */
        offset += unparsed_length;
#endif
    }

#if 0
  if (fcf & RF4CE_NWK_FCF_SECURITY_MASK)
  {
    proto_tree_add_item(rf4ce_nwk_tree, hf_rf4ce_nwk_mic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
  }
#endif

    return tvb_captured_length(tvb);
}

static void dissect_rf4ce_nwk_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset)
{
    int cmd_id = tvb_get_uint8(tvb, *offset);

    proto_tree_add_item(tree, hf_rf4ce_nwk_cmd_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(cmd_id, rf4ce_nwk_cmd_names, "Unknown Command"));

    switch (cmd_id)
    {
    case RF4CE_NWK_CMD_DISCOVERY_REQ:
        dissect_rf4ce_nwk_cmd_disc_req(tvb, tree, offset);
        break;

    case RF4CE_NWK_CMD_DISCOVERY_RSP:
        dissect_rf4ce_nwk_cmd_disc_rsp(tvb, tree, offset);
        break;

    case RF4CE_NWK_CMD_PAIR_REQ:
        dissect_rf4ce_nwk_cmd_pair_req(tvb, pinfo, tree, offset);
        break;

    case RF4CE_NWK_CMD_PAIR_RSP:
        dissect_rf4ce_nwk_cmd_pair_rsp(tvb, pinfo, tree, offset);
        break;

    case RF4CE_NWK_CMD_UNPAIR_REQ:
        break;

    case RF4CE_NWK_CMD_KEY_SEED:
        dissect_rf4ce_nwk_cmd_key_seed(tvb, tree, offset);
        break;

    case RF4CE_NWK_CMD_PING_REQ:
        dissect_rf4ce_nwk_cmd_ping(tvb, tree, offset);
        break;

    case RF4CE_NWK_CMD_PING_RSP:
        dissect_rf4ce_nwk_cmd_ping(tvb, tree, offset);
        break;
    }
}

static void dissect_rf4ce_nwk_common_node_capabilities(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    static int *const nwk_node_capabilities_bits[] = {
        &hf_rf4ce_nwk_node_capabilities_node_type,
        &hf_rf4ce_nwk_node_capabilities_power_source,
        &hf_rf4ce_nwk_node_capabilities_security,
        &hf_rf4ce_nwk_node_capabilities_channel_normalization,
        &hf_rf4ce_nwk_node_capabilities_reserved,
        NULL};

    proto_tree_add_bitmask(tree, tvb, *offset, hf_rf4ce_nwk_node_capabilities, ett_rf4ce_nwk, nwk_node_capabilities_bits, ENC_LITTLE_ENDIAN);
    *offset += 1;
}

static void dissect_rf4ce_nwk_common_vendor_info(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_tree *vendor_info_tree = proto_tree_add_subtree(tree, tvb, *offset, tvb_captured_length(tvb) - *offset, ett_rf4ce_nwk_vendor_info, NULL, "Vendor Information Fields");

    proto_tree_add_item(vendor_info_tree, hf_rf4ce_nwk_disc_req_vendor_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    proto_tree_add_item(vendor_info_tree, hf_rf4ce_nwk_vendor_string, tvb, *offset, RF4CE_NWK_VENDOR_STRING_MAX_LENGTH, ENC_UTF_8);
    *offset += RF4CE_NWK_VENDOR_STRING_MAX_LENGTH;
}

static void dissect_rf4ce_nwk_common_app_capabilities(tvbuff_t *tvb, proto_tree *tree, int *offset, uint8_t parsing_mask)
{
    int nwk_app_capabilities = 0;
    int supported_devices_num = 0;
    int supported_profiles_num = 0;

    static int *const nwk_app_capabilities_bits[] = {
        &hf_rf4ce_nwk_app_capabilities_usr_str,
        &hf_rf4ce_nwk_app_capabilities_supported_dev_num,
        &hf_rf4ce_nwk_app_capabilities_reserved1,
        &hf_rf4ce_nwk_app_capabilities_supported_profiles_num,
        &hf_rf4ce_nwk_app_capabilities_reserved2,
        NULL};

    proto_tree_add_bitmask(tree, tvb, *offset, hf_rf4ce_nwk_app_capabilities, ett_rf4ce_nwk, nwk_app_capabilities_bits, ENC_LITTLE_ENDIAN);
    nwk_app_capabilities = tvb_get_uint8(tvb, *offset);
    *offset += 1;

    if (nwk_app_capabilities & RF4CE_NWK_USR_STR_SPECIFIED_MASK)
    {
        if (parsing_mask & RF4CE_NWK_USR_STR_PARSING_MASK_DISC_RESP)
        {
            proto_tree *usr_str_tree = proto_tree_add_subtree(tree, tvb, *offset, RF4CE_NWK_USR_STR_LENGTH, ett_rf4ce_nwk_usr_str, NULL, "Extra Status Information");

            proto_tree_add_item(usr_str_tree, hf_rf4ce_nwk_usr_str_disc_rsp_app_usr_str, tvb, *offset, RF4CE_NWK_USR_STR_DISC_RSP_APP_USR_STR_LENGTH, ENC_UTF_8);
            /* -1: to show the NULL-terminator byte in a tree */
            *offset += RF4CE_NWK_USR_STR_DISC_RSP_APP_USR_STR_LENGTH - 1;

            proto_tree_add_item(usr_str_tree, hf_rf4ce_nwk_usr_str_disc_rsp_null, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;

            proto_tree_add_item(usr_str_tree, hf_rf4ce_nwk_usr_str_disc_rsp_reserved, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;

            dissect_rf4ce_nwk_disc_resp_class_descriptor(tvb, usr_str_tree, offset, hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_tertiary);
            dissect_rf4ce_nwk_disc_resp_class_descriptor(tvb, usr_str_tree, offset, hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_secondary);
            dissect_rf4ce_nwk_disc_resp_class_descriptor(tvb, usr_str_tree, offset, hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_primary);

            proto_tree_add_item(usr_str_tree, hf_rf4ce_nwk_usr_str_disc_rsp_discovery_lqi_threshold, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
        }
        else
        {
            proto_tree_add_item(tree, hf_rf4ce_nwk_usr_str, tvb, *offset, RF4CE_NWK_USR_STR_LENGTH, ENC_NA);
            *offset += RF4CE_NWK_USR_STR_LENGTH;
        }
    }

    supported_devices_num = ((nwk_app_capabilities & RF4CE_NWK_SUPPORTED_DEV_NUM_MASK) >> RF4CE_NWK_SUPPORTED_DEV_NUM_OFFSET);
    if (supported_devices_num > 0)
    {
        proto_tree *dev_type_tree = proto_tree_add_subtree(tree, tvb, *offset, supported_devices_num, ett_rf4ce_nwk_dev_types_list, NULL, "Device Type List");

        for (int i = 0; i < supported_devices_num; i++)
        {
            proto_tree_add_item(dev_type_tree, hf_rf4ce_nwk_app_cap_dev_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
        }
    }

    supported_profiles_num = ((nwk_app_capabilities & RF4CE_NWK_SUPPORTED_PROFILES_NUM_MASK) >> RF4CE_NWK_SUPPORTED_PROFILES_NUM_OFFSET);
    if (supported_profiles_num > 0)
    {
        proto_tree *profiles_tree = proto_tree_add_subtree(tree, tvb, *offset, supported_profiles_num, ett_rf4ce_nwk_profiles_list, NULL, "Profiles ID List");

        for (int i = 0; i < supported_profiles_num; i++)
        {
            proto_tree_add_item(profiles_tree, hf_rf4ce_nwk_app_cap_profile_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
        }
    }
}

static void dissect_rf4ce_nwk_disc_resp_class_descriptor(tvbuff_t *tvb, proto_tree *tree, int *offset, int hf)
{
    static int *const class_num_bits[] = {
        &hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_class_num,
        &hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_duplicate_class_num_handling,
        &hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_reserved,
        NULL};

    proto_tree_add_bitmask(tree, tvb, *offset, hf, ett_rf4ce_nwk_usr_str_class_descriptor, class_num_bits, ENC_LITTLE_ENDIAN);
    *offset += 1;
}

static void dissect_rf4ce_nwk_cmd_disc_req(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    dissect_rf4ce_nwk_common_node_capabilities(tvb, tree, offset);
    dissect_rf4ce_nwk_common_vendor_info(tvb, tree, offset);
    dissect_rf4ce_nwk_common_app_capabilities(tvb, tree, offset, RF4CE_NWK_USR_STR_PARSING_MASK_NONE);

    proto_tree_add_item(tree, hf_rf4ce_nwk_requested_dev_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
}

static void dissect_rf4ce_nwk_cmd_disc_rsp(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_tree_add_item(tree, hf_rf4ce_nwk_disc_resp_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    dissect_rf4ce_nwk_common_node_capabilities(tvb, tree, offset);
    dissect_rf4ce_nwk_common_vendor_info(tvb, tree, offset);
    dissect_rf4ce_nwk_common_app_capabilities(tvb, tree, offset, RF4CE_NWK_USR_STR_PARSING_MASK_DISC_RESP);

    proto_tree_add_item(tree, hf_rf4ce_nwk_disc_resp_lqi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
}

static void dissect_rf4ce_nwk_cmd_pair_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset)
{
    uint8_t expected_transfer_count;

    proto_tree_add_item(tree, hf_rf4ce_nwk_pair_req_nwk_addr, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    dissect_rf4ce_nwk_common_node_capabilities(tvb, tree, offset);
    dissect_rf4ce_nwk_common_vendor_info(tvb, tree, offset);
    dissect_rf4ce_nwk_common_app_capabilities(tvb, tree, offset, RF4CE_NWK_USR_STR_PARSING_MASK_NONE);

    proto_tree_add_item(tree, hf_rf4ce_nwk_pair_req_key_exch_num, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

    expected_transfer_count = tvb_get_uint8(tvb, *offset) + 1;
    keypair_context_init((const uint8_t *)pinfo->dl_src.data, (const uint8_t *)pinfo->dl_dst.data, expected_transfer_count);
    *offset += 1;
}

static void dissect_rf4ce_nwk_cmd_pair_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset)
{
    uint16_t allocated_nwk_addr;
    uint16_t nwk_addr;

    proto_tree_add_item(tree, hf_rf4ce_nwk_pair_rsp_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    proto_tree_add_item(tree, hf_rf4ce_nwk_pair_rsp_allocated_nwk_addr, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    allocated_nwk_addr = tvb_get_uint16(tvb, *offset, ENC_LITTLE_ENDIAN);
    *offset += 2;

    proto_tree_add_item(tree, hf_rf4ce_nwk_pair_rsp_nwk_addr, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    nwk_addr = tvb_get_uint16(tvb, *offset, ENC_LITTLE_ENDIAN);
    *offset += 2;

    dissect_rf4ce_nwk_common_node_capabilities(tvb, tree, offset);
    dissect_rf4ce_nwk_common_vendor_info(tvb, tree, offset);
    dissect_rf4ce_nwk_common_app_capabilities(tvb, tree, offset, RF4CE_NWK_USR_STR_PARSING_MASK_NONE);

    rf4ce_addr_table_add_addrs(pinfo->dl_dst.data, allocated_nwk_addr);
    rf4ce_addr_table_add_addrs(pinfo->dl_src.data, nwk_addr);
}

static void dissect_rf4ce_nwk_cmd_key_seed(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    uint8_t seed_data[RF4CE_NWK_KEY_SEED_DATA_LENGTH] = {0};
    uint8_t seed_seq_num = 0;

    proto_tree_add_item(tree, hf_rf4ce_nwk_seed_seq_num, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    seed_seq_num = tvb_get_uint8(tvb, *offset);
    *offset += 1;

    proto_tree_add_item(tree, hf_rf4ce_nwk_seed_data, tvb, *offset, RF4CE_NWK_KEY_SEED_DATA_LENGTH, ENC_NA);
    tvb_memcpy(tvb, (void *)seed_data, *offset, RF4CE_NWK_KEY_SEED_DATA_LENGTH);
    *offset += RF4CE_NWK_KEY_SEED_DATA_LENGTH;

    keypair_context_update_seed(seed_data, seed_seq_num);
}

static void dissect_rf4ce_nwk_cmd_ping(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_tree_add_item(tree, hf_rf4ce_nwk_ping_options, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    proto_tree_add_item(tree, hf_rf4ce_nwk_ping_payload, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
}

void proto_register_rf4ce_nwk(void)
{
    static hf_register_info hf[] = {
        {&hf_rf4ce_nwk_fcf,
         {"Frame Control Field", "rf4ce-nwk.fcf",
          FT_UINT8, BASE_HEX,
          NULL, 0x00,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_fcf_frame_type,
         {"Frame Type", "rf4ce-nwk.fcf.frame_type",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_nwk_frame_types), RF4CE_NWK_FCF_FRAME_TYPE_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_fcf_security_enabled,
         {"Security enabled", "rf4ce-nwk.fcf.security_enabled",
          FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), RF4CE_NWK_FCF_SECURITY_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_fcf_protocol_version,
         {"Protocol version", "rf4ce-nwk.fcf.protocol_version",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_NWK_FCF_PROTOCOL_VERSION_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_fcf_reserved,
         {"Reserved", "rf4ce-nwk.fcf.reserved",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_NWK_FCF_RESERVED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_fcf_channel_designator,
         {"Channel designator", "rf4ce-nwk.fcf.channel_designator",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_nwk_channel_designators), RF4CE_NWK_FCF_CHANNEL_DESIGNATOR_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_seq_num,
         {"Sequence number", "rf4ce-nwk.seqn",
          FT_UINT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_profile_id,
         {"Profile ID", "rf4ce-nwk.profile_id",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_nwk_profile_ids), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_vendor_id,
         {"Vendor ID", "rf4ce-nwk.vendor_id",
          FT_UINT16, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_cmd_id,
         {"Command ID", "rf4ce-nwk.cmd_id",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_nwk_cmd_names), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_node_capabilities,
         {"Node Capabilities", "rf4ce-nwk.node_capabilities",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_node_capabilities_node_type,
         {"Node Type", "rf4ce-nwk.node_capabilities.node_type",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_nwk_node_types), RF4CE_NWK_NODE_TYPE_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_node_capabilities_power_source,
         {"Power Source", "rf4ce-nwk.node_capabilities.power_source",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_nwk_power_sources), RF4CE_NWK_POWER_SOURCE_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_node_capabilities_security,
         {"Security Capable", "rf4ce-nwk.node_capabilities.security",
          FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), RF4CE_NWK_SECURITY_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_node_capabilities_channel_normalization,
         {"Channel Normalization", "rf4ce-nwk.node_capabilities.channel_normalization",
          FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), RF4CE_NWK_CHANNEL_NORMALIZATION_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_node_capabilities_reserved,
         {"Reserved", "rf4ce-nwk.node_capabilities.reserved",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_NWK_RESERVED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_disc_req_vendor_id,
         {"Vendor ID", "rf4ce-nwk.disc_req.vendor_id",
          FT_UINT16, BASE_HEX,
          VALS(rf4ce_disc_req_vendor_ids), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_vendor_string,
         {"Vendor String", "rf4ce-nwk.disc_req.vendor_str",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_app_capabilities,
         {"App Capabilities", "rf4ce-nwk.app_capabilities",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_app_capabilities_usr_str,
         {"User String Specified", "rf4ce-nwk.app_capabilities.usr_str",
          FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), RF4CE_NWK_USR_STR_SPECIFIED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_app_capabilities_supported_dev_num,
         {"Number of Supported Device Types", "rf4ce-nwk.app_capabilities.supported_dev_num",
          FT_UINT8, BASE_DEC,
          NULL, RF4CE_NWK_SUPPORTED_DEV_NUM_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_app_capabilities_reserved1,
         {"Reserved", "rf4ce-nwk.app_capabilities.reserved1",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_NWK_RESERVED1_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_app_capabilities_supported_profiles_num,
         {"Number of Supported Profiles", "rf4ce-nwk.app_capabilities.supported_profiles_num",
          FT_UINT8, BASE_DEC,
          NULL, RF4CE_NWK_SUPPORTED_PROFILES_NUM_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_app_capabilities_reserved2,
         {"Reserved", "rf4ce-nwk.app_capabilities.reserved2",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_NWK_RESERVED2_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_usr_str,
         {"User String", "rf4ce-nwk.usr_str",
          FT_BYTES, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_usr_str_disc_rsp_app_usr_str,
         {"App Specific User String", "rf4ce-nwk.usr_str.disc_rsp.app_usr_str",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_usr_str_disc_rsp_null,
         {"NULL-terminator", "rf4ce-nwk.usr_str.disc_rsp.null",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_usr_str_disc_rsp_reserved,
         {"Reserved", "rf4ce-nwk.usr_str.disc_rsp.reserved",
          FT_UINT16, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_tertiary,
         {"Tertiary Class Descriptor", "rf4ce-nwk.usr_str.disc_rsp.class_descriptor.tertiary",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_secondary,
         {"Secondary Class Descriptor", "rf4ce-nwk.usr_str.disc_rsp.class_descriptor.secondary",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_primary,
         {"Primary Class Descriptor", "rf4ce-nwk.usr_str.disc_rsp.class_descriptor.primary",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_class_num,
         {"Class Number", "rf4ce-nwk.usr_str.disc_rsp.class_descriptor.class_number",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_nwk_usr_str_disc_rsp_class_desc_class_num_vals), RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_CLASS_NUM_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_duplicate_class_num_handling,
         {"Duplicate Class Number Handling", "rf4ce-nwk.usr_str.disc_rsp.class_descriptor.duplicate_class_num_handling",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_nwk_usr_str_disc_rsp_class_desc_duplicate_class_num_handling_vals), RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_DUPLICATE_CLASS_NUM_HANDLING_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_usr_str_disc_rsp_class_desc_reserved,
         {"Reserved", "rf4ce-nwk.usr_str.disc_rsp.class_descriptor.reserved",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_NWK_USR_STR_DISC_RSP_CLASS_DESC_RESERVED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_usr_str_disc_rsp_discovery_lqi_threshold,
         {"Discovery LQI Threshold", "rf4ce-nwk.usr_str.disc_rsp.discovery_lqi_threshold",
          FT_INT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_app_cap_dev_type,
         {"Device Type", "rf4ce-nwk.app_cap.dev_type",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_app_cap_profile_id,
         {"Profile ID", "rf4ce-nwk.app_cap.profile_id",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_requested_dev_type,
         {"Requested Device Type", "rf4ce-nwk.requested_dev_type",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_nwk_device_type_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_disc_resp_status,
         {"Status", "rf4ce-nwk.disc_resp.status",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_nwk_disc_status_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_disc_resp_lqi,
         {"Discovery Request LQI", "rf4ce-nwk.disc_resp.lqi",
          FT_INT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_pair_req_nwk_addr,
         {"Network Address", "rf4ce-nwk.pair_req.nwk_addr",
          FT_UINT16, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_pair_req_key_exch_num,
         {"Key Exchange Transfer Count", "rf4ce-nwk.pair_req.key_exch_num",
          FT_INT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_pair_rsp_status,
         {"Status", "rf4ce-nwk.pair_rsp.status",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_nwk_disc_status_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_pair_rsp_allocated_nwk_addr,
         {"Allocated Network Address", "rf4ce-nwk.pair_rsp.allocated_nwk_addr",
          FT_UINT16, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_pair_rsp_nwk_addr,
         {"Network Address", "rf4ce-nwk.pair_rsp.nwk_addr",
          FT_UINT16, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_seed_seq_num,
         {"Seed Sequence Number", "rf4ce-nwk.key_seed.seed_seq_num",
          FT_INT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_seed_data,
         {"Seed Data", "rf4ce-nwk.key_seed.seed_data",
          FT_BYTES, SEP_COLON,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_ping_options,
         {"Ping Options", "rf4ce-nwk.ping_options",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_nwk_ping_payload,
         {"Ping Payload", "rf4ce-nwk.ping_payload",
          FT_UINT32, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
#if 0
        {&hf_rf4ce_nwk_mic,
         {"Ping Payload", "rf4ce-nwk.mic",
          FT_UINT32, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
#endif
        {&hf_rf4ce_nwk_unparsed_payload,
         {"Unparsed Payload", "rf4ce-nwk.unparsed_payload",
          FT_BYTES, SEP_COLON,
          NULL, 0x0,
          NULL, HFILL}},
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_rf4ce_nwk,
        &ett_rf4ce_nwk_payload,
        &ett_rf4ce_nwk_vendor_info,
        &ett_rf4ce_nwk_usr_str,
        &ett_rf4ce_nwk_usr_str_class_descriptor,
        &ett_rf4ce_nwk_dev_types_list,
        &ett_rf4ce_nwk_profiles_list,
    };

    proto_rf4ce_nwk = proto_register_protocol("RF4CE Network Layer", "RF4CE", RF4CE_PROTOABBREV_NWK);
    proto_register_field_array(proto_rf4ce_nwk, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_cleanup_routine(rf4ce_cleanup);

    register_dissector(RF4CE_PROTOABBREV_NWK, dissect_rf4ce_nwk_common, proto_rf4ce_nwk);

    static uat_field_t key_uat_fields[] =
        {
            UAT_FLD_CSTRING(uat_security_records, sec_str, "Byte sequence",
                            "In case of NWK key type it is a 16-byte key in hexadecimal with optional dash-,\n"
                            "colon-, or space-separator characters, or \n"
                            "a 16-character string in double-quotes.\n"
                            "In case of Vendor Secret type it is a secret byte sequence\n"
                            "to calculate NWK keys during Key Exchange procedure."),
            UAT_FLD_VS(uat_security_records, type, "Type", sec_str_type_vals, "Type of a security string."),
            UAT_FLD_CSTRING(uat_security_records, label, "Label", "User label for a security string."),
            UAT_END_FIELDS};

    rf4ce_security_table_uat =
        uat_new("Pre-configured security table",
                sizeof(uat_security_record_t),
                "rf4ce_pc_sec",
                true,
                &uat_security_records,
                &num_uat_security_records,
                UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
                NULL,                   /* TODO: ptr to help manual? */
                uat_sec_record_copy_cb,
                uat_sec_record_update_cb,
                uat_sec_record_free_cb,
                uat_sec_record_post_update,
                NULL,
                key_uat_fields);

    module_t *rf4ce_prefs = prefs_register_protocol(proto_rf4ce_nwk, NULL);

    prefs_register_uat_preference(
        rf4ce_prefs,
        "security_table",
        "Pre-configured security strings",
        "Pre-configured vendor secrets or network keys.",
        rf4ce_security_table_uat);
}

void proto_reg_handoff_rf4ce_nwk(void)
{
    rf4ce_gdp_handle = find_dissector_add_dependency(RF4CE_PROTOABBREV_PROFILE, proto_rf4ce_nwk);

    /* create_dissector_handle(dissect_rf4ce_nwk_common, proto_rf4ce_nwk); */
    dissector_add_for_decode_as(IEEE802154_PROTOABBREV_WPAN_PANID, find_dissector(RF4CE_PROTOABBREV_NWK));
    heur_dissector_add(IEEE802154_PROTOABBREV_WPAN, dissect_rf4ce_nwk_heur, "Radio Frequency for Consumer Electronics over IEEE 802.15.4", RF4CE_PROTOABBREV_NWK, proto_rf4ce_nwk, HEURISTIC_ENABLE);
}
