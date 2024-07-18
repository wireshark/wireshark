/* packet-rf4ce-profile.c
 * Profile layer related functions and objects for RF4CE dissector
 * Copyright (C) Atmosic 2023
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdbool.h>
#include <stdio.h>
#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/reassemble.h>
#include "packet-ieee802154.h"
#include "packet-rf4ce-secur.h"

/* TLV Node-elements */
static int proto_rf4ce_profile;

static int ett_rf4ce_profile;
static int ett_rf4ce_profile_cmd_frame;
static int ett_rf4ce_profile_attrs;
static int ett_rf4ce_profile_attrs_sub;
static int ett_rf4ce_profile_zrc20_ident_cap;
static int ett_rf4ce_profile_zrc20_mappable_actions_entry;
static int ett_rf4ce_profile_zrc20_action_control;
static int ett_rf4ce_profile_zrc20_action_mappings_flags;
static int ett_rf4ce_profile_zrc20_action_mappings_rf_descr;
static int ett_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf;
static int ett_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts;
static int ett_rf4ce_profile_zrc20_action_mappings_ir_descr;
static int ett_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_conf;
static int ett_rf4ce_profile_gdp_poll_constraints_polling_rec;
static int ett_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap;
static int ett_rf4ce_profile_gdp_poll_configuration_polling_trig_conf;
static int ett_rf4ce_profile_action_records;
static int ett_rf4ce_profile_action_records_sub;
static int ett_rf4ce_profile_zrc10_supported_commands;
static int ett_rf4ce_profile_zrc10_supported_commands_sub;

static dissector_table_t rf4ce_profile_dissector_table;

static dissector_handle_t rf4ce_profile_handle;

/* RF4CE Profile header */
static int hf_rf4ce_profile_fcf;
static int hf_rf4ce_profile_fcf_cmd_id;
static int hf_rf4ce_zrc20_fcf_cmd_id;
static int hf_rf4ce_profile_fcf_reserved;
static int hf_rf4ce_profile_fcf_cmd_frame;
static int hf_rf4ce_profile_fcf_data_pending;

/* RF4CE Profile command - Generic Response */
static int hf_rf4ce_profile_cmd_generic_resp_status;

/* RF4CE Profile command - Configuration Complete */
static int hf_rf4ce_profile_cmd_configuration_complete_status;

/* RF4CE Profile command - Heartbeat */
static int hf_rf4ce_profile_cmd_heartbeat_trigger;

/* RF4CE Profile Attributes - general */
static int hf_rf4ce_profile_gdp_attr_id;
static int hf_rf4ce_profile_zrc20_attr_id;
static int hf_rf4ce_profile_attr_entry_id;
static int hf_rf4ce_profile_attr_status;
static int hf_rf4ce_profile_attr_length;
static int hf_rf4ce_profile_attr_value;

/* RF4CE Profile command - Check Validation */
static int hf_rf4ce_profile_cmd_check_validation_sub_type;
static int hf_rf4ce_profile_cmd_check_validation_control;
static int hf_rf4ce_profile_cmd_check_validation_status;

/* RF4CE Profile command - Client Notification */
static int hf_rf4ce_profile_cmd_client_notification_sub_type;

static int hf_rf4ce_profile_cmd_client_notification_identify_flags;
static int hf_rf4ce_profile_cmd_client_notification_identify_flags_stop_on_action;
static int hf_rf4ce_profile_cmd_client_notification_identify_flags_flash_light;
static int hf_rf4ce_profile_cmd_client_notification_identify_flags_make_sound;
static int hf_rf4ce_profile_cmd_client_notification_identify_flags_vibrate;
static int hf_rf4ce_profile_cmd_client_notification_identify_flags_reserved;

static int hf_rf4ce_profile_cmd_client_notification_identify_time;

/* RF4CE Profile command - Key Exchange */
static int hf_rf4ce_profile_cmd_key_exchange_sub_type;

static int hf_rf4ce_profile_cmd_key_exchange_flags;
static int hf_rf4ce_profile_cmd_key_exchange_flags_default_secret;
static int hf_rf4ce_profile_cmd_key_exchange_flags_initiator_vendor_specific_secret;
static int hf_rf4ce_profile_cmd_key_exchange_flags_responder_vendor_specific_secret;
static int hf_rf4ce_profile_cmd_key_exchange_flags_reserved;
static int hf_rf4ce_profile_cmd_key_exchange_flags_vendor_specific_parameter;

static int hf_rf4ce_profile_cmd_key_exchange_rand_a;
static int hf_rf4ce_profile_cmd_key_exchange_rand_b;
static int hf_rf4ce_profile_cmd_key_exchange_tag_b;
static int hf_rf4ce_profile_cmd_key_exchange_tag_a;

#if 0
/* RF4CE ZRC 2.0 Profile command - Actions */
static int hf_rf4ce_zrc20_cmd_actions;
#endif

static int hf_rf4ce_zrc20_cmd_actions_action_control;
static int hf_rf4ce_zrc20_cmd_actions_action_control_action_type;
static int hf_rf4ce_zrc20_cmd_actions_action_control_reserved;
static int hf_rf4ce_zrc20_cmd_actions_action_control_modifier_bits_gui;
static int hf_rf4ce_zrc20_cmd_actions_action_control_modifier_bits_alt;
static int hf_rf4ce_zrc20_cmd_actions_action_control_modifier_bits_shift;
static int hf_rf4ce_zrc20_cmd_actions_action_control_modifier_bits_ctrl;

static int hf_rf4ce_zrc20_cmd_actions_action_data_payload_length;
static int hf_rf4ce_zrc20_cmd_actions_action_data_action_bank;
static int hf_rf4ce_zrc20_cmd_actions_action_data_action_code;
static int hf_rf4ce_zrc20_cmd_actions_action_data_action_vendor;
static int hf_rf4ce_zrc20_cmd_actions_action_data_action_payload;

/* RF4CE ZRC 1.0 profile header */
static int hf_rf4ce_zrc10_fcf;
static int hf_rf4ce_zrc10_fcf_cmd_id;
static int hf_rf4ce_zrc10_fcf_reserved;

#define RF4CE_ZRC10_FCF_CMD_ID_RESERVED                       0b00000000
#define RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_PRESSED           0b00000001
#define RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_REPEATED          0b00000010
#define RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_RELEASED          0b00000011
#define RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_CMD_DISCOVERY_REQ 0b00000100
#define RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_CMD_DISCOVERY_RSP 0b00000101

#define RF4CE_ZRC10_FCF_CMD_ID_MASK   0b00001111
#define RF4CE_ZRC10_FCF_RESERVED_MASK 0b11110000

static const value_string rf4ce_zrc10_fcf_cmd_id_vals[] = {
    { RF4CE_ZRC10_FCF_CMD_ID_RESERVED,                       "Reserved" },
    { RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_PRESSED,           "User Control Pressed" },
    { RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_REPEATED,          "User Control Repeated" },
    { RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_RELEASED,          "User Control Released" },
    { RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_CMD_DISCOVERY_REQ, "Command Discovery Request" },
    { RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_CMD_DISCOVERY_RSP, "Command Discovery Response" },
    { 0, NULL }
};

static int hf_rf4ce_zrc10_cmd_common_rc_command_code;
static int hf_rf4ce_zrc10_cmd_common_rc_command_payload;
static int hf_rf4ce_zrc10_cmd_disc_reserved;
static int hf_rf4ce_zrc10_cmd_disc_rsp_supported_commands;

static int hf_rf4ce_profile_unparsed_payload;

#define RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_RESERVED 0b00000000
#define RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_START    0b00000001
#define RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_REPEAT   0b00000010
#define RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_ATOMIC   0b00000011
#define RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_RESERVED             0b00001100
#define RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_MODIFIER_BITS_GUI    0b00010000
#define RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_MODIFIER_BITS_ALT    0b00100000
#define RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_MODIFIER_BITS_SHIFT  0b01000000
#define RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_MODIFIER_BITS_CTRL   0b10000000

#define RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_MASK     \
    (RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_RESERVED    \
     | RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_START     \
     | RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_REPEAT    \
     | RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_ATOMIC)

static const value_string rf4ce_zrc20_cmd_actions_action_control_action_type_vals[] = {
    { RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_RESERVED, "Reserved" },
    { RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_START,    "Start" },
    { RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_REPEAT,   "Repeat" },
    { RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_ATOMIC,   "Atomic" },
    { 0, NULL }
};

/* RF4CE Profile frame control field */
#define RF4CE_PROFILE_FCF_CMD_ID_MASK       0b00001111
#define RF4CE_PROFILE_FCF_RESERVED_MASK     0b00110000
#define RF4CE_PROFILE_FCF_CMD_FRAME_MASK    0b01000000
#define RF4CE_PROFILE_FCF_DATA_PENDING_MASK 0b10000000

/* RF4CE Profile commands */
#define RF4CE_PROFILE_CMD_GENERIC_RESPONSE         0x00
#define RF4CE_PROFILE_CMD_CONFIGURATION_COMPLETE   0x01
#define RF4CE_PROFILE_CMD_HEARTBEAT                0x02
#define RF4CE_PROFILE_CMD_GET_ATTRIBUTES           0x03
#define RF4CE_PROFILE_CMD_GET_ATTRIBUTES_RESPONSE  0x04
#define RF4CE_PROFILE_CMD_PUSH_ATTRIBUTES          0x05
#define RF4CE_PROFILE_CMD_SET_ATTRIBUTES           0x06
#define RF4CE_PROFILE_CMD_PULL_ATTRIBUTES          0x07
#define RF4CE_PROFILE_CMD_PULL_ATTRIBUTES_RESPONSE 0x08
#define RF4CE_PROFILE_CMD_CHECK_VALIDATION         0x09
#define RF4CE_PROFILE_CMD_CLIENT_NOTIFICATION      0x0a
#define RF4CE_PROFILE_CMD_KEY_EXCHANGE             0x0b

static const value_string rf4ce_profile_fcf_cmd_id_vals[] = {
    { RF4CE_PROFILE_CMD_GENERIC_RESPONSE,         "Generic Response" },
    { RF4CE_PROFILE_CMD_CONFIGURATION_COMPLETE,   "Configuration Complete" },
    { RF4CE_PROFILE_CMD_HEARTBEAT,                "Heartbeat" },
    { RF4CE_PROFILE_CMD_GET_ATTRIBUTES,           "Get Attributes" },
    { RF4CE_PROFILE_CMD_GET_ATTRIBUTES_RESPONSE,  "Get Attributes Response" },
    { RF4CE_PROFILE_CMD_PUSH_ATTRIBUTES,          "Push Attributes" },
    { RF4CE_PROFILE_CMD_SET_ATTRIBUTES,           "Set Attributes" },
    { RF4CE_PROFILE_CMD_PULL_ATTRIBUTES,          "Pull Attributes" },
    { RF4CE_PROFILE_CMD_PULL_ATTRIBUTES_RESPONSE, "Pull Attributes Response" },
    { RF4CE_PROFILE_CMD_CHECK_VALIDATION,         "Check Validation" },
    { RF4CE_PROFILE_CMD_CLIENT_NOTIFICATION,      "Client Notification" },
    { RF4CE_PROFILE_CMD_KEY_EXCHANGE,             "Key Exchange" },
    { 0, NULL }
};

#define RF4CE_PROFILE_FCF_CMD_PROFILE_SPECIFIC_COMMAND 0
#define RF4CE_PROFILE_FCF_CMD_GDP_COMMAND     1

static const value_string rf4ce_profile_fcf_cmd_frame_vals[] = {
    { RF4CE_PROFILE_FCF_CMD_PROFILE_SPECIFIC_COMMAND, "Profile Specific Command" },
    { RF4CE_PROFILE_FCF_CMD_GDP_COMMAND,              "GDP Command" },
    { 0, NULL }
};

/* RF4CE ZRC 2.0 Profile commands */
                             /* 0x00 - 0x05 - Reserved */
#define RF4CE_ZRC20_CMD_ACTIONS 0x06
                             /* 0x07 - 0x0f - Reserved */

static const value_string rf4ce_zrc20_fcf_cmd_id_vals[] = {
    { RF4CE_ZRC20_CMD_ACTIONS, "Actions" },    { 0, NULL }
};

/* RF4CE Profile command - Generic Response */
#define RF4CE_PROFILE_CMD_GENERIC_RESP_STATUS_SUCCESS               0x00
#define RF4CE_PROFILE_CMD_GENERIC_RESP_STATUS_UNSUPPORTED_REQUEST   0x01
#define RF4CE_PROFILE_CMD_GENERIC_RESP_STATUS_INVALID_PARAMETER     0x02
#define RF4CE_PROFILE_CMD_GENERIC_RESP_STATUS_CONFIGURATION_FAILURE 0x03
                                                                 /* 0x04 – 0x3f Reserved error codes */
                                                                 /* 0x40 – 0xff Profile specific error codes */

static const value_string hf_rf4ce_profile_cmd_generic_resp_status_vals[] = {
    { RF4CE_PROFILE_CMD_GENERIC_RESP_STATUS_SUCCESS,               "Success" },
    { RF4CE_PROFILE_CMD_GENERIC_RESP_STATUS_UNSUPPORTED_REQUEST,   "Unsupported Request" },
    { RF4CE_PROFILE_CMD_GENERIC_RESP_STATUS_INVALID_PARAMETER,     "Invalid Parameter" },
    { RF4CE_PROFILE_CMD_GENERIC_RESP_STATUS_CONFIGURATION_FAILURE, "Configuration Failure" },
    { 0, NULL }
};

/* RF4CE Profile command - Configuration Complete */
#define RF4CE_PROFILE_CMD_CONFIGURATION_COMPLETE_STATUS_SUCCESS               0x00
                                                                           /* 0x01 – 0x02 Reserved error codes */
#define RF4CE_PROFILE_CMD_CONFIGURATION_COMPLETE_STATUS_CONFIGURATION_FAILURE 0x03
                                                                           /* 0x04 – 0x3f Reserved error codes */
                                                                           /* 0x40 – 0xff Profile specific error codes */

static const value_string hf_rf4ce_profile_cmd_configuration_complete_status_vals[] = {
    { RF4CE_PROFILE_CMD_CONFIGURATION_COMPLETE_STATUS_SUCCESS,               "Success" },
    { RF4CE_PROFILE_CMD_CONFIGURATION_COMPLETE_STATUS_CONFIGURATION_FAILURE, "Configuration Failure" },
    { 0, NULL }
};

/* RF4CE Profile command - Heartbeat */
#define RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_GENERIC_ACTIVITY               0x00
#define RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_TIME_BASED_POLLING             0x01
#define RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_POLLING_ON_KEY_PRESS           0x02
#define RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_POLLING_ON_PICKUP              0x03
#define RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_POLLING_ON_RESET               0x04
#define RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_POLLING_ON_MICROPHONE_ACTIVITY 0x05
#define RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_POLLING_ON_OTHER_USER_ACTIVITY 0x06
                                                                        /* 0x07 – 0xff Reserved */

static const value_string hf_rf4ce_profile_cmd_heartbeat_trigger_vals[] = {
    { RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_GENERIC_ACTIVITY,               "Generic Activity" },
    { RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_TIME_BASED_POLLING,             "Time Based Polling" },
    { RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_POLLING_ON_KEY_PRESS,           "Polling on Key Press" },
    { RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_POLLING_ON_PICKUP,              "Polling on Pickup" },
    { RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_POLLING_ON_RESET,               "Polling on Reset" },
    { RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_POLLING_ON_MICROPHONE_ACTIVITY, "Polling on Microphone Activity" },
    { RF4CE_PROFILE_CMD_HEARTBEAT_TRIGGER_POLLING_ON_OTHER_USER_ACTIVITY, "Polling on other User Activity" },
    { 0, NULL }
};

/* RF4CE Profile Attributes common */
#define RF4CE_PROFILE_ATTR_DISSECT_NOT_SET                      0b00000000
#define RF4CE_PROFILE_ATTR_DISSECT_ATTR_ID_MASK                 0b00000001
#define RF4CE_PROFILE_ATTR_DISSECT_ENTRY_ID_MASK                0b00000010
#define RF4CE_PROFILE_ATTR_DISSECT_ATTR_STATUS_MASK             0b00000100
#define RF4CE_PROFILE_ATTR_DISSECT_ATTR_LENGTH_MASK             0b00001000
#define RF4CE_PROFILE_ATTR_DISSECT_ATTR_VALUE_MASK              0b00010000

#define RF4CE_PROFILE_ATTR_DISSECT_GET_ATTRS_MASK       \
    (RF4CE_PROFILE_ATTR_DISSECT_ATTR_ID_MASK            \
     | RF4CE_PROFILE_ATTR_DISSECT_ENTRY_ID_MASK)

#define RF4CE_PROFILE_ATTR_DISSECT_GET_ATTRS_RESP_MASK  \
    (RF4CE_PROFILE_ATTR_DISSECT_ATTR_ID_MASK            \
     | RF4CE_PROFILE_ATTR_DISSECT_ENTRY_ID_MASK         \
     | RF4CE_PROFILE_ATTR_DISSECT_ATTR_STATUS_MASK      \
     | RF4CE_PROFILE_ATTR_DISSECT_ATTR_LENGTH_MASK      \
     | RF4CE_PROFILE_ATTR_DISSECT_ATTR_VALUE_MASK)      \

#define RF4CE_PROFILE_ATTR_DISSECT_PUSH_ATTRS_MASK      \
    (RF4CE_PROFILE_ATTR_DISSECT_ATTR_ID_MASK            \
     | RF4CE_PROFILE_ATTR_DISSECT_ENTRY_ID_MASK         \
     | RF4CE_PROFILE_ATTR_DISSECT_ATTR_LENGTH_MASK      \
     | RF4CE_PROFILE_ATTR_DISSECT_ATTR_VALUE_MASK)

#define RF4CE_PROFILE_ATTR_DISSECT_SET_ATTRS_MASK       \
    (RF4CE_PROFILE_ATTR_DISSECT_ATTR_ID_MASK            \
     | RF4CE_PROFILE_ATTR_DISSECT_ENTRY_ID_MASK         \
     | RF4CE_PROFILE_ATTR_DISSECT_ATTR_LENGTH_MASK      \
     | RF4CE_PROFILE_ATTR_DISSECT_ATTR_VALUE_MASK)

#define RF4CE_PROFILE_ATTR_DISSECT_PULL_ATTRS_MASK      \
    (RF4CE_PROFILE_ATTR_DISSECT_ATTR_ID_MASK            \
     | RF4CE_PROFILE_ATTR_DISSECT_ENTRY_ID_MASK)

#define RF4CE_PROFILE_ATTR_DISSECT_PULL_ATTRS_RESP_MASK \
    (RF4CE_PROFILE_ATTR_DISSECT_ATTR_ID_MASK            \
     | RF4CE_PROFILE_ATTR_DISSECT_ENTRY_ID_MASK         \
     | RF4CE_PROFILE_ATTR_DISSECT_ATTR_STATUS_MASK      \
     | RF4CE_PROFILE_ATTR_DISSECT_ATTR_LENGTH_MASK      \
     | RF4CE_PROFILE_ATTR_DISSECT_ATTR_VALUE_MASK)

/* RF4CE GDP Attributes */

/* GDP Attribute - Identification Capabilities */
static int hf_rf4ce_profile_gdp_ident_cap;
static int hf_rf4ce_profile_gdp_ident_cap_reserved;
static int hf_rf4ce_profile_gdp_ident_cap_support_flash_light;
static int hf_rf4ce_profile_gdp_ident_cap_support_make_short_sound;
static int hf_rf4ce_profile_gdp_ident_cap_support_vibrate;
static int hf_rf4ce_profile_gdp_ident_cap_reserved2;

#define RF4CE_PROFILE_GDP_IDENT_CAP_RESERVED_MASK                 0b00000001
#define RF4CE_PROFILE_GDP_IDENT_CAP_SUPPORT_FLASH_LIGHT_MASK      0b00000010
#define RF4CE_PROFILE_GDP_IDENT_CAP_SUPPORT_MAKE_SHORT_SOUND_MASK 0b00000100
#define RF4CE_PROFILE_GDP_IDENT_CAP_SUPPORT_VIBRATE_MASK          0b00001000
#define RF4CE_PROFILE_GDP_IDENT_CAP_RESERVED2_MASK                0b11110000

#define RF4CE_PROFILE_GDP_IDENT_CAP_MASK                            \
    (RF4CE_PROFILE_GDP_IDENT_CAP_SUPPORT_FLASH_LIGHT_MASK           \
     | RF4CE_PROFILE_GDP_IDENT_CAP_SUPPORT_MAKE_SHORT_SOUND_MASK    \
     | RF4CE_PROFILE_GDP_IDENT_CAP_SUPPORT_VIBRATE_MASK             \
     | RF4CE_PROFILE_GDP_IDENT_CAP_RESERVED2_MASK)

/* GDP Attribute - Poll Constraints */
static int hf_rf4ce_profile_gdp_poll_constraints_methods_num;

/* Polling constraint record - Polling method ID */
static int hf_rf4ce_profile_gdp_poll_constraints_polling_rec_method_id;

#define RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_METHOD_ID_DIS           0x00
#define RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_METHOD_ID_GDP_HEARTBEAT 0x01

static const value_string rf4ce_profile_gdp_poll_constraints_polling_rec_method_id_vals[] = {
    { RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_METHOD_ID_DIS,           "Disabled" },
    { RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_METHOD_ID_GDP_HEARTBEAT, "GDP heartbeat based polling" },
    { 0, NULL}
};

/* Polling constraint record - Polling trigger capabilities */
static int hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap;
static int hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_tbased;
static int hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_k_press;
static int hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_pick_up;
static int hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_reset;
static int hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_micro_act;
static int hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_user_act;
static int hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_reserved;

#define RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_TBASED_MASK       (0b0000000000000001)
#define RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_K_PRESS_MASK   (0b0000000000000010)
#define RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_PICK_UP_MASK   (0b0000000000000100)
#define RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_RESET_MASK     (0b0000000000001000)
#define RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_MICRO_ACT_MASK (0b0000000000010000)
#define RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_USER_ACT_MASK  (0b0000000000100000)
#define RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_RESERVED_MASK     (0b1111111111000000)

#define RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_MASK                \
    (RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_TBASED_MASK            \
     | RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_K_PRESS_MASK      \
     | RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_PICK_UP_MASK      \
     | RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_RESET_MASK        \
     | RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_MICRO_ACT_MASK    \
     | RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_USER_ACT_MASK     \
     | RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_RESERVED_MASK)

/* Polling constraint record - other fields */
static int hf_rf4ce_profile_gdp_poll_constraints_polling_rec_min_polling_key_press_cnt;
static int hf_rf4ce_profile_gdp_poll_constraints_polling_rec_max_polling_key_press_cnt;

static int hf_rf4ce_profile_gdp_poll_constraints_polling_rec_min_polling_time_interval;
static int hf_rf4ce_profile_gdp_poll_constraints_polling_rec_max_polling_time_interval;

/* GDP Attribute - Poll Configuration */
static int hf_rf4ce_profile_gdp_poll_configuration_method_id;

/* GDP Attribute - Poll Configuration - Polling Trigger Configuration */
static int hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf;
static int hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_tbased;
static int hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_k_press;
static int hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_pick_up;
static int hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_reset;
static int hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_micro_act;
static int hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_user_act;
static int hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_reserved;

#define RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_TBASED_MASK       (0b0000000000000001)
#define RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_K_PRESS_MASK   (0b0000000000000010)
#define RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_PICK_UP_MASK   (0b0000000000000100)
#define RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_RESET_MASK     (0b0000000000001000)
#define RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_MICRO_ACT_MASK (0b0000000000010000)
#define RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_USER_ACT_MASK  (0b0000000000100000)
#define RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_RESERVED_MASK     (0b1111111111000000)

#define RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_MASK             \
    (RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_TBASED_MASK         \
     | RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_K_PRESS_MASK   \
     | RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_PICK_UP_MASK   \
     | RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_RESET_MASK     \
     | RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_MICRO_ACT_MASK \
     | RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_USER_ACT_MASK  \
     | RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_RESERVED_MASK)

static int hf_rf4ce_profile_gdp_poll_configuration_polling_key_press_cnt;
static int hf_rf4ce_profile_gdp_poll_configuration_polling_time_interval;
static int hf_rf4ce_profile_gdp_poll_configuration_polling_timeout;

                                                             /* 0x00 - 0x7f - Reserved */
#define RF4CE_GDP_ATTR_GDP_PROFILE_VERSION                      0x80
#define RF4CE_GDP_ATTR_GDP_PROFILE_CAPABILITIES                 0x81
#define RF4CE_GDP_ATTR_KEY_EXCHANGE_TRANSFER_COUNT              0x82
#define RF4CE_GDP_ATTR_POWER_STATUS                             0x83
#define RF4CE_GDP_ATTR_POLL_CONSTRAINTS                         0x84
#define RF4CE_GDP_ATTR_POLL_CONFIGURATION                       0x85
#define RF4CE_GDP_ATTR_MAX_BINDING_CANDIDATES                   0x86
#define RF4CE_GDP_ATTR_AUTO_CHECK_VALID_PERIOD                  0x87
#define RF4CE_GDP_ATTR_BINDING_RECIPIENT_VALIDATION_WAIT_TIME   0x88
#define RF4CE_GDP_ATTR_BINDING_ORIGINATOR_VALIDATION_WAIT_TIME  0x89
#define RF4CE_GDP_ATTR_LINK_LOST_WAIT_TIME                      0x8a
#define RF4CE_GDP_ATTR_IDENTIFICATION_CAPABILITIES              0x8b

/* Reserved for scalar Profile attributes */
#define RF4CE_GDP_ATTR_SCALAR1_RESERVED_MIN                     0x8c
#define RF4CE_GDP_ATTR_SCALAR1_RESERVED_MAX                     0x8f

/* Reserved for arrayed Profile attributes */
#define RF4CE_GDP_ATTR_ARRAYED1_RESERVED_MIN                    0x90
#define RF4CE_GDP_ATTR_ARRAYED1_RESERVED_MAX                    0x90

/* Reserved for scalar Profile attributes */
#define RF4CE_GDP_ATTR_SCALAR2_RESERVED_MIN                     0xa0
#define RF4CE_GDP_ATTR_SCALAR2_RESERVED_MAX                     0xbf

/* Reserved for arrayed Profile attributes */
#define RF4CE_GDP_ATTR_ARRAYED2_RESERVED_MIN                    0xc0
#define RF4CE_GDP_ATTR_ARRAYED2_RESERVED_MAX                    0xdf

/* Reserved for scalar Profile attributes */
#define RF4CE_GDP_ATTR_SCALAR3_RESERVED_MIN                     0xe0
#define RF4CE_GDP_ATTR_SCALAR3_RESERVED_MAX                     0xff

static const value_string rf4ce_profile_gdp_attr_vals[] = {
    { RF4CE_GDP_ATTR_GDP_PROFILE_VERSION,                     "Profile Version" },
    { RF4CE_GDP_ATTR_GDP_PROFILE_CAPABILITIES,                "Profile Capabilities" },
    { RF4CE_GDP_ATTR_KEY_EXCHANGE_TRANSFER_COUNT,             "KEY Exchange Transfer Count" },
    { RF4CE_GDP_ATTR_POWER_STATUS,                            "Power Status" },
    { RF4CE_GDP_ATTR_POLL_CONSTRAINTS,                        "Poll Constraints" },
    { RF4CE_GDP_ATTR_POLL_CONFIGURATION,                      "Poll Configuration" },
    { RF4CE_GDP_ATTR_MAX_BINDING_CANDIDATES,                  "Max Binding Candidates" },
    { RF4CE_GDP_ATTR_AUTO_CHECK_VALID_PERIOD,                 "Auto Check Valid Period" },
    { RF4CE_GDP_ATTR_BINDING_RECIPIENT_VALIDATION_WAIT_TIME,  "Binding Recipient Validation Wait Time" },
    { RF4CE_GDP_ATTR_BINDING_ORIGINATOR_VALIDATION_WAIT_TIME, "Binding Originator Validation Wait Time" },
    { RF4CE_GDP_ATTR_LINK_LOST_WAIT_TIME,                     "Link Lost Wait Time" },
    { RF4CE_GDP_ATTR_IDENTIFICATION_CAPABILITIES,             "Identification Capabilities" },
    { 0, NULL }
};

/* RF4CE ZRC 2.0 Attributes */
#define RF4CE_ZRC20_ATTR_ZRC_PROFILE_VERSION            0xA0
#define RF4CE_ZRC20_ATTR_ZRC_PROFILE_CAPABILITIES       0xA1
#define RF4CE_ZRC20_ATTR_ACTION_REPEAT_TRIGGER_INTERVAL 0xA2
#define RF4CE_ZRC20_ATTR_ACTION_REPEAT_WAIT_TIME        0xA3
#define RF4CE_ZRC20_ATTR_ACTION_BANKS_SUPPORTED_RX      0xA4
#define RF4CE_ZRC20_ATTR_ACTION_BANKS_SUPPORTED_TX      0xA5
#define RF4CE_ZRC20_ATTR_IRDB_VENDOR_SUPPORT            0xA6
#define RF4CE_ZRC20_ATTR_ZRC_ACTION_BANKS_VERSION       0xA7

/* Reserved for scalar profile attributes */
#define RF4CE_ZRC20_ATTR_SCALAR1_MIN                    0xA8
#define RF4CE_ZRC20_ATTR_SCALAR1_MAX                    0xBF

#define RF4CE_ZRC20_ATTR_ACTION_CODES_SUPPORTED_RX      0xC0
#define RF4CE_ZRC20_ATTR_ACTION_CODES_SUPPORTED_TX      0xC1
#define RF4CE_ZRC20_ATTR_MAPPABLE_ACTIONS               0xC2
#define RF4CE_ZRC20_ATTR_ACTION_MAPPINGS                0xC3
#define RF4CE_ZRC20_ATTR_HOME_AUTOMATION                0xC4
#define RF4CE_ZRC20_ATTR_HOME_AUTOMATION_SUPPORTED      0xC5

/* Reserved for arrayed profile attributes */
#define RF4CE_ZRC20_ATTR_ARRAYED1_MIN                   0xC6
#define RF4CE_ZRC20_ATTR_ARRAYED2_MAX                   0xDF

/* Reserved for scalar profile attributes */
#define RF4CE_ZRC20_ATTR_SCALAR2_MIN                    0xE0
#define RF4CE_ZRC20_ATTR_SCALAR2_MAX                    0xFF

static const value_string rf4ce_profile_zrc20_attr_vals[] = {
    { RF4CE_ZRC20_ATTR_ZRC_PROFILE_VERSION,            "ZRC Profile Version" },
    { RF4CE_ZRC20_ATTR_ZRC_PROFILE_CAPABILITIES,       "ZRC Profile Capabilities" },
    { RF4CE_ZRC20_ATTR_ACTION_REPEAT_TRIGGER_INTERVAL, "Action Repeat Trigger Interval" },
    { RF4CE_ZRC20_ATTR_ACTION_REPEAT_WAIT_TIME,        "Action Repeat Wait Time" },
    { RF4CE_ZRC20_ATTR_ACTION_BANKS_SUPPORTED_RX,      "Action Banks Supported RX" },
    { RF4CE_ZRC20_ATTR_ACTION_BANKS_SUPPORTED_TX,      "Action Banks Supported TX" },
    { RF4CE_ZRC20_ATTR_IRDB_VENDOR_SUPPORT,            "IRDB Vendor Support" },
    { RF4CE_ZRC20_ATTR_ZRC_ACTION_BANKS_VERSION,       "ZRC Action Banks Version" },
    { RF4CE_ZRC20_ATTR_ACTION_CODES_SUPPORTED_RX,      "Action Codes Supported RX" },
    { RF4CE_ZRC20_ATTR_ACTION_CODES_SUPPORTED_TX,      "Action Codes Supported TX" },
    { RF4CE_ZRC20_ATTR_MAPPABLE_ACTIONS,               "Mappable Actions" },
    { RF4CE_ZRC20_ATTR_ACTION_MAPPINGS,                "Action Mappings" },
    { RF4CE_ZRC20_ATTR_HOME_AUTOMATION,                "Home Automation" },
    { RF4CE_ZRC20_ATTR_HOME_AUTOMATION_SUPPORTED,      "Home Automation Supported" },
    { 0, NULL }
};

#define RF4CE_PROFILE_ATTR_STATUS_ATTRIBUTE_SUCCESSFULLY_READ_AND_INCLUDED 0x00
#define RF4CE_PROFILE_ATTR_STATUS_UNSUPPORTED_ATTRIBUTE                    0x01
#define RF4CE_PROFILE_ATTR_STATUS_ILLEGAL_REQUEST                          0x02
#define RF4CE_PROFILE_ATTR_STATUS_INVALID_ENTRY                            0x03
                                                                        /* 0x04 - 0xff Reserved error codes */

static const value_string hf_rf4ce_profile_attr_status_vals[] = {
    { RF4CE_PROFILE_ATTR_STATUS_ATTRIBUTE_SUCCESSFULLY_READ_AND_INCLUDED, "Attribute Successfully Read and Included" },
    { RF4CE_PROFILE_ATTR_STATUS_UNSUPPORTED_ATTRIBUTE,                    "Unsupported Attribute" },
    { RF4CE_PROFILE_ATTR_STATUS_ILLEGAL_REQUEST,                          "Illegal Request" },
    { RF4CE_PROFILE_ATTR_STATUS_INVALID_ENTRY,                            "Invalid Entry" },
    { 0, NULL }
};

/* RF4CE ZRC 2.0 Profile - Mappable Actions attribute */
static int hf_rf4ce_profile_zrc20_mappable_actions_action_dev_type;
static int hf_rf4ce_profile_zrc20_mappable_actions_action_bank;
static int hf_rf4ce_profile_zrc20_mappable_actions_action_code;

#define RF4CE_PROFILE_DEV_TYPE_RESERVED                         0x00
#define RF4CE_PROFILE_DEV_TYPE_REMOTE_CONTROL                   0x01
#define RF4CE_PROFILE_DEV_TYPE_TELEVISION                       0x02
#define RF4CE_PROFILE_DEV_TYPE_PROJECTOR                        0x03
#define RF4CE_PROFILE_DEV_TYPE_PLAYER                           0x04
#define RF4CE_PROFILE_DEV_TYPE_RECORDER                         0x05
#define RF4CE_PROFILE_DEV_TYPE_VIDEO_PLAYER_OR_RECORDER         0x06 /* (VCR, DVR, DVD, Blu-ray, portable) */
#define RF4CE_PROFILE_DEV_TYPE_AUDIO_PLAYER_OR_RECORDER         0x07 /* (CD, portable) */
#define RF4CE_PROFILE_DEV_TYPE_AUDIO_VIDEO_RECORDER             0x08
#define RF4CE_PROFILE_DEV_TYPE_SET_TOP_BOX                      0x09
#define RF4CE_PROFILE_DEV_TYPE_HOME_THEATER_SYSTEM              0x0a
#define RF4CE_PROFILE_DEV_TYPE_MEDIA_CENTER_OR_PC               0x0b
#define RF4CE_PROFILE_DEV_TYPE_GAME_CONSOLE                     0x0c
#define RF4CE_PROFILE_DEV_TYPE_SATELLITE_RADIO_RECEIVER         0x0d
#define RF4CE_PROFILE_DEV_TYPE_IR_EXTENDER                      0x0e
#define RF4CE_PROFILE_DEV_TYPE_MONITOR                          0x0f
                                                                /* 0x10 – 0xcf Reserved */
                                                                /* 0xd0 – 0xef Vendor-specific device */
                                                                /* 0xf0 – 0xfb Reserved */
#define RF4CE_PROFILE_DEV_TYPE_VENDOR_SPECIFIC_WILDCARD_DEV     0xfc
#define RF4CE_PROFILE_DEV_TYPE_NON_VENDOR_SPECIFIC_WILDCARD_DEV 0xfd
#define RF4CE_PROFILE_DEV_TYPE_GENERIC                          0xfe
#define RF4CE_PROFILE_DEV_TYPE_RESERVED_FOR_WILDCARDS           0xff

static const value_string rf4ce_profile_device_type_vals[] = {
    { RF4CE_PROFILE_DEV_TYPE_RESERVED,                         "Reserved" },
    { RF4CE_PROFILE_DEV_TYPE_REMOTE_CONTROL,                   "Remote Control" },
    { RF4CE_PROFILE_DEV_TYPE_TELEVISION,                       "Television" },
    { RF4CE_PROFILE_DEV_TYPE_PROJECTOR,                        "Projector" },
    { RF4CE_PROFILE_DEV_TYPE_PLAYER,                           "Player" },
    { RF4CE_PROFILE_DEV_TYPE_RECORDER,                         "Recorder" },
    { RF4CE_PROFILE_DEV_TYPE_VIDEO_PLAYER_OR_RECORDER,         "Video Player\\Recorder" },
    { RF4CE_PROFILE_DEV_TYPE_AUDIO_PLAYER_OR_RECORDER,         "Audio Player\\Recorder" },
    { RF4CE_PROFILE_DEV_TYPE_AUDIO_VIDEO_RECORDER,             "Audio Video Recorder" },
    { RF4CE_PROFILE_DEV_TYPE_SET_TOP_BOX,                      "Set Top Box" },
    { RF4CE_PROFILE_DEV_TYPE_HOME_THEATER_SYSTEM,              "Home Theater System" },
    { RF4CE_PROFILE_DEV_TYPE_MEDIA_CENTER_OR_PC,               "Media Center\\PC" },
    { RF4CE_PROFILE_DEV_TYPE_GAME_CONSOLE,                     "Game Console" },
    { RF4CE_PROFILE_DEV_TYPE_SATELLITE_RADIO_RECEIVER,         "Satellite Radio Receiver" },
    { RF4CE_PROFILE_DEV_TYPE_IR_EXTENDER,                      "IR Extender" },
    { RF4CE_PROFILE_DEV_TYPE_MONITOR,                          "Monitor" },
    { RF4CE_PROFILE_DEV_TYPE_VENDOR_SPECIFIC_WILDCARD_DEV,     "Vendor Specific Wildcard Device" },
    { RF4CE_PROFILE_DEV_TYPE_NON_VENDOR_SPECIFIC_WILDCARD_DEV, "Non-Vendor Specific Wildcard Device" },
    { RF4CE_PROFILE_DEV_TYPE_GENERIC,                          "Generic" },
    { RF4CE_PROFILE_DEV_TYPE_RESERVED_FOR_WILDCARDS,           "Reserved for Wildcards" },
    { 0, NULL }
};

/* RF4CE ZRC 2.0 Profile - Action Mappings attribute - Mapping Flags */
static int hf_rf4ce_profile_zrc20_action_mappings_mapping_flags;
static int hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_rf_specified;
static int hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_ir_specified;
static int hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_rf_descr_first;
static int hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_reserved;
static int hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_use_default;
static int hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_permanent;

#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_RF_SPECIFIED_MASK   0b00000001
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_IR_SPECIFIED_MASK   0b00000010
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_RF_DESCR_FIRST_MASK 0b00000100
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_RESERVED_MASK       0b00111000
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_USE_DEFAULT_MASK    0b01000000
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_PERMANENT_MASK      0b10000000

#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_MASK                  \
    (RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_RF_SPECIFIED_MASK        \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_IR_SPECIFIED_MASK      \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_RF_DESCR_FIRST_MASK    \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_RESERVED_MASK          \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_USE_DEFAULT_MASK       \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_PERMANENT_MASK)

/* RF4CE ZRC 2.0 Profile - Action Mappings attribute - RF Descriptor - RF Config */
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf;
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_min_num_of_trans;
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_keep_trans_until_key_release;
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_short_rf_retry;
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_atomic_action;
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_reserved;

#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_MIN_NUM_OF_TRANS_MASK             0b00001111
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_KEEP_TRANS_UNTIL_KEY_RELEASE_MASK 0b00010000
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_SHORT_RF_RETRY_MASK               0b00100000
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_ATOMIC_ACTION_MASK                0b01000000
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_RESERVED_MASK                     0b10000000

#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_MASK                               \
    (RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_MIN_NUM_OF_TRANS_MASK                 \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_KEEP_TRANS_UNTIL_KEY_RELEASE_MASK   \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_SHORT_RF_RETRY_MASK                 \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_ATOMIC_ACTION_MASK                  \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_RESERVED_MASK)

/* RF4CE ZRC 2.0 Profile - Action Mappings attribute - RF Descriptor - RF4CE TX Options */
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts;
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_trans_mode;
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_dst_addr_mode;
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ack_mode;
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_sec_mode;
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ch_ag_mode;
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ch_norm_mode;
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_payload_mode;
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_reserved;

#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_TRANS_MODE_MASK    0b00000001
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_DST_ADDR_MODE_MASK 0b00000010
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_ACK_MODE_MASK      0b00000100
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_SEC_MODE_MASK      0b00001000
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_CH_AG_MODE_MASK    0b00010000
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_CH_NORM_MODE_MASK  0b00100000
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_PAYLOAD_MODE_MASK  0b01000000
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_RESERVED_MASK      0b10000000

#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_MASK               \
    (RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_TRANS_MODE_MASK       \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_DST_ADDR_MODE_MASK  \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_ACK_MODE_MASK       \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_SEC_MODE_MASK       \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_CH_AG_MODE_MASK     \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_CH_NORM_MODE_MASK   \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_PAYLOAD_MODE_MASK   \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_RESERVED_MASK)

static const true_false_string rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_trans_mode_vals = {
    "Broadcast Transmission",
    "Unicast Transmission"
};

static const true_false_string rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_dst_addr_mode_vals = {
    "Use Destination IEEE Address",
    "Use Destination Network Address"
};

static const true_false_string rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ack_mode_vals = {
    "Acknowledged Transmission",
    "Unacknowledged Transmission"
};

static const true_false_string rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_sec_mode_vals = {
    "Transmit with Security",
    "Transmit without Security"
};

static const true_false_string rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ch_ag_mode_vals = {
    "Use Single Channel Operation",
    "Use Multiple Channel Operation"
};

static const true_false_string rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ch_norm_mode_vals = {
    "Specify Channel Designator",
    "Do not Specify Channel Designator"
};

static const true_false_string rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_payload_mode_vals = {
    "Data is Vendor-specific",
    "Data is not Vendor-specific"
};

/* RF4CE ZRC 2.0 Profile - Action Mappings attribute - RF Descriptor - Action Data Length */
static int hf_rf4ce_profile_zrc20_action_mappings_rf_descr_action_data_len;

/* RF4CE ZRC 2.0 Profile - Action Mappings attribute - IR Descriptor - IR Config */
static int hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_conf;
static int hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_conf_vendor_specific;
static int hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_conf_reserved;

#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_IR_DESCR_IR_CONF_VENDOR_SPECIFIC_MASK 0b00000001
#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_IR_DESCR_IR_CONF_RESERVED_MASK        0b11111110

#define RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_IR_DESCR_IR_CONF_MASK               \
    (RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_IR_DESCR_IR_CONF_VENDOR_SPECIFIC_MASK  \
     | RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_IR_DESCR_IR_CONF_RESERVED_MASK)

/* RF4CE ZRC 2.0 Profile - Action Mappings attribute - IR Descriptor */
static int hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_vendor_id;
static int hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_code_len;
static int hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_code;

/* RF4CE ZRC 2.0 Profile - IRDB Vendor Support attribute - Vendor ID */
static int hf_rf4ce_profile_zrc20_irdb_vendor_support_vendor_id;

/* RF4CE Profile command - Check Validation */
#define RF4CE_PROFILE_CMD_CHECK_VALIDATION_SUB_TYPE_REQ 0x00
#define RF4CE_PROFILE_CMD_CHECK_VALIDATION_SUB_TYPE_RSP 0x01
                                                     /* 0x02 - 0xff - reserved */

static const value_string rf4ce_profile_cmd_check_validation_sub_type_vals[] = {
    { RF4CE_PROFILE_CMD_CHECK_VALIDATION_SUB_TYPE_REQ, "Request" },
    { RF4CE_PROFILE_CMD_CHECK_VALIDATION_SUB_TYPE_RSP, "Response" },
    { 0, NULL }
};

#define RF4CE_PROFILE_CMD_CHECK_VALIDATION_STATUS_SUCCESS 0x00
#define RF4CE_PROFILE_CMD_CHECK_VALIDATION_STATUS_PENDING 0x01
#define RF4CE_PROFILE_CMD_CHECK_VALIDATION_STATUS_TIMEOUT 0x02
#define RF4CE_PROFILE_CMD_CHECK_VALIDATION_STATUS_FAILURE 0x03

static const value_string rf4ce_profile_cmd_check_validation_status_vals[] = {
    { RF4CE_PROFILE_CMD_CHECK_VALIDATION_STATUS_SUCCESS, "Success" },
    { RF4CE_PROFILE_CMD_CHECK_VALIDATION_STATUS_PENDING, "Pending" },
    { RF4CE_PROFILE_CMD_CHECK_VALIDATION_STATUS_TIMEOUT, "Timeout" },
    { RF4CE_PROFILE_CMD_CHECK_VALIDATION_STATUS_FAILURE, "Failure" },
    { 0, NULL }
};

/* RF4CE Profile command - Client Notification */
#define RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY                            0x00
#define RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_REQ_POLL_NEGOTIATION                0x01
                                                                             /* 0x02 - 0x3f
                                                                                Reserved for Profile Client Notification Sub Types. */
#define RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_REQ_ACTION_MAPPING_NEGOTIATION      0x40
#define RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_REQ_HOME_AUTOMATION_PULL            0x41
#define RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_REQ_SELECTIVE_ACTION_MAPPING_UPDATE 0x42
                                                                             /* 0x43 - 0x7f
                                                                                Reserved for profile-specific (non-Profile) Client Notification Sub Types. */
                                                                             /* 0x80 - 0x8f
                                                                                Reserved */
                                                                             /* 0xa0 - 0xff
                                                                                Reserved for vendor specific Client
                                                                                Notification Sub Types. The contents of
                                                                                this field shall be interpreted according to
                                                                                the vendor id of the Recipient. */

static const value_string rf4ce_profile_cmd_client_notification_sub_type_vals[] = {
    { RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY,                            "Identify" },
    { RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_REQ_POLL_NEGOTIATION,                "Request Poll Negotiation" },
    { RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_REQ_ACTION_MAPPING_NEGOTIATION,      "Request Action Mapping Negotiation" },
    { RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_REQ_HOME_AUTOMATION_PULL,            "Request Home Automation Pull" },
    { RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_REQ_SELECTIVE_ACTION_MAPPING_UPDATE, "Request Selective Action Mapping Update" },
    { 0, NULL }
};

#define RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_STOP_ON_ACTION_FLAG 0b00000001
#define RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_FLASH_LIGHT_FLAG    0b00000010
#define RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_MAKE_SOUND_FLAG     0b00000100
#define RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_VIBRATE_FLAG        0b00001000
#define RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_RESERVED_FLAG       0b11110000

#define RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_MASK               \
    (RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_STOP_ON_ACTION_FLAG   \
     | RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_FLASH_LIGHT_FLAG    \
     | RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_MAKE_SOUND_FLAG     \
     | RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_VIBRATE_FLAG        \
     | RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_RESERVED_FLAG)

/* RF4CE Profile command - Key Exchange */
#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_SUB_TYPE_CHALLENGE     0x00
#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_SUB_TYPE_CHALLENGE_RSP 0x01
#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_SUB_TYPE_RSP           0x02
#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_SUB_TYPE_CONFIRM       0x03
                                                           /* 0x04 - 0xff - Reserved */

static const value_string rf4ce_profile_cmd_key_exchange_sub_type_vals[] = {
    { RF4CE_PROFILE_CMD_KEY_EXCHANGE_SUB_TYPE_CHALLENGE,     "Challenge" },
    { RF4CE_PROFILE_CMD_KEY_EXCHANGE_SUB_TYPE_CHALLENGE_RSP, "Challenge Response" },
    { RF4CE_PROFILE_CMD_KEY_EXCHANGE_SUB_TYPE_RSP,           "Response" },
    { RF4CE_PROFILE_CMD_KEY_EXCHANGE_SUB_TYPE_CONFIRM,       "Confirm" },
    { 0, NULL }
};

#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_DEFAULT_SECRET_FLAG                   (0b0000000000000001)
#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_INITIATOR_VENDOR_SPECIFIC_SECRET_FLAG (0b0000000000000010)
#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_RESPONDER_VENDOR_SPECIFIC_SECRET_FLAG (0b0000000000000100)
#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_RESERVED_FLAG                         (0b0000000011111000)
#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_VENDOR_SPECIFIC_PARAMETER_FLAG        (0b1111111100000000)

#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_MASK                                   \
    (RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_DEFAULT_SECRET_FLAG                       \
     | RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_INITIATOR_VENDOR_SPECIFIC_SECRET_FLAG   \
     | RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_RESPONDER_VENDOR_SPECIFIC_SECRET_FLAG   \
     | RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_RESERVED_FLAG                           \
     | RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_VENDOR_SPECIFIC_PARAMETER_FLAG)

/* RF4CE - Vendor ID list */
#define RF4CE_VENDOR_ID_RESERVED          0x0000
#define RF4CE_VENDOR_ID_PANASONIC         0x0001
#define RF4CE_VENDOR_ID_SONY              0x0002
#define RF4CE_VENDOR_ID_SAMSUNG           0x0003
#define RF4CE_VENDOR_ID_PHILIPS           0x0004
#define RF4CE_VENDOR_ID_FREESCALE         0x0005
#define RF4CE_VENDOR_ID_OKI_SEMICONDUCTOR 0x0006
#define RF4CE_VENDOR_ID_TEXAS_INSTRUMENTS 0x0007
                                       /* 0x0008 - 0xfff0 Reserved */
#define RF4CE_VENDOR_ID_TEST_VENDOR_1     0xfff1
#define RF4CE_VENDOR_ID_TEST_VENDOR_2     0xfff2
#define RF4CE_VENDOR_ID_TEST_VENDOR_3     0xfff3
                                       /* 0xfff4 - 0xffff Reserved */

#define RF4CE_VENDOR_ID_MASK              0x0007

static const value_string rf4ce_vendor_id_vals[] = {
    { RF4CE_VENDOR_ID_RESERVED,          "Reserved" },
    { RF4CE_VENDOR_ID_PANASONIC,         "Panasonic" },
    { RF4CE_VENDOR_ID_SONY,              "Sony" },
    { RF4CE_VENDOR_ID_SAMSUNG,           "Samsung" },
    { RF4CE_VENDOR_ID_PHILIPS,           "Philips" },
    { RF4CE_VENDOR_ID_FREESCALE,         "Freescale" },
    { RF4CE_VENDOR_ID_OKI_SEMICONDUCTOR, "Oki Semiconductor" },
    { RF4CE_VENDOR_ID_TEXAS_INSTRUMENTS, "Texas Instruments" },
    { 0, NULL }
};

static int dissect_rf4ce_profile_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

/* RF4CE Profile common commands dissectors */
static void dissect_rf4ce_profile_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset, uint8_t cmd_id, char *profile_str, bool is_cmd_frame);

static void dissect_rf4ce_profile_common_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset, uint8_t cmd_id, bool is_zrc20);

static void dissect_rf4ce_profile_cmd_generic_resp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_rf4ce_profile_cmd_configuration_complete(tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_rf4ce_profile_cmd_heartbeat(tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

static bool dissect_rf4ce_profile_zrc20_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, uint8_t attr_id, uint8_t attr_length);
static bool dissect_rf4ce_profile_gdp_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, uint8_t attr_id);
static void dissect_rf4ce_profile_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, uint8_t dissection_mask, bool is_zrc20);
static void dissect_rf4ce_profile_cmd_get_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool is_zrc20);
static void dissect_rf4ce_profile_cmd_get_attrs_resp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool is_zrc20);
static void dissect_rf4ce_profile_cmd_push_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool is_zrc20);
static void dissect_rf4ce_profile_cmd_set_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool is_zrc20);
static void dissect_rf4ce_profile_cmd_pull_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool is_zrc20);
static void dissect_rf4ce_profile_cmd_pull_attrs_resp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool is_zrc20);
static bool rf4ce_profile_is_gdp_attr_arrayed(uint8_t attr_id);
static bool rf4ce_profile_is_zrc20_attr_arrayed(uint8_t attr_id);

static void dissect_rf4ce_profile_cmd_check_validation(tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_rf4ce_profile_cmd_client_notification(tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_rf4ce_profile_cmd_key_exchange(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset);

/* RF4CE ZRC 1.0 profile commands dissectors */
static void dissect_rf4ce_profile_zrc10_cmd(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, uint8_t cmd_id);

static void dissect_rf4ce_profile_zrc10_cmd_user_control_common(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool parse_payload);

static void dissect_rf4ce_profile_zrc10_cmd_discovery_req(tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_rf4ce_profile_zrc10_cmd_discovery_rsp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

/* RF4CE ZRC 2.0 profile commands dissectors */
static void dissect_rf4ce_profile_zrc20_cmd(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, uint8_t cmd_id);
static void dissect_rf4ce_profile_zrc20_action_data(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool dissect_action_control);

void proto_register_rf4ce_profile(void)
{
    static hf_register_info hf[] = {
        {&hf_rf4ce_profile_fcf,
         {"Frame Control Field", "rf4ce-profile.fcf",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_fcf_cmd_id,
         {"Command ID", "rf4ce-profile.fcf.cmd_id",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_profile_fcf_cmd_id_vals), RF4CE_PROFILE_FCF_CMD_ID_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_zrc20_fcf_cmd_id,
         {"Command ID", "rf4ce-profile.fcf.cmd_id",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_zrc20_fcf_cmd_id_vals), RF4CE_PROFILE_FCF_CMD_ID_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_fcf_reserved,
         {"Reserved", "rf4ce-profile.fcf.reserved",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_FCF_RESERVED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_fcf_cmd_frame,
         {"Command Frame", "rf4ce-profile.fcf.cmd_frame",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_profile_fcf_cmd_frame_vals), RF4CE_PROFILE_FCF_CMD_FRAME_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_fcf_data_pending,
         {"Data Pending", "rf4ce-profile.fcf.data_pending",
          FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), RF4CE_PROFILE_FCF_DATA_PENDING_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_generic_resp_status,
         {"Status", "rf4ce-profile.cmd.generic_resp.status",
          FT_UINT8, BASE_HEX,
          VALS(hf_rf4ce_profile_cmd_generic_resp_status_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_configuration_complete_status,
         {"Status", "rf4ce-profile.cmd.configuration_complete.status",
          FT_UINT8, BASE_HEX,
          VALS(hf_rf4ce_profile_cmd_configuration_complete_status_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_heartbeat_trigger,
         {"Trigger", "rf4ce-profile.cmd.heartbeat.trigger",
          FT_UINT8, BASE_HEX,
          VALS(hf_rf4ce_profile_cmd_heartbeat_trigger_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_attr_id,
         {"Attribute ID", "rf4ce-profile.gdp.attr.id",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_profile_gdp_attr_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_attr_id,
         {"Attribute ID", "rf4ce-profile.zrc20.attr.id",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_profile_zrc20_attr_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_attr_entry_id,
         {"Entry Identifier", "rf4ce-profile.zrc20.attr.entry_identifier",
          FT_BYTES, SEP_COLON,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_attr_status,
         {"Status", "rf4ce-profile.attr.status",
          FT_UINT8, BASE_HEX,
          VALS(hf_rf4ce_profile_attr_status_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_attr_length,
         {"Length", "rf4ce-profile.attr.length",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_attr_value,
         {"Value", "rf4ce-profile.attr.value",
          FT_BYTES, SEP_COLON,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_ident_cap,
         {"Identification Capabilities", "rf4ce-profile.attr.ident_cap",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_ident_cap_reserved,
         {"Reserved", "rf4ce-profile.attr.ident_cap.reserved",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_GDP_IDENT_CAP_RESERVED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_ident_cap_support_flash_light,
         {"Support Flash Light", "rf4ce-profile.attr.ident_cap.support_flash_light",
          FT_BOOLEAN, SEP_DOT,
          NULL, RF4CE_PROFILE_GDP_IDENT_CAP_SUPPORT_FLASH_LIGHT_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_ident_cap_support_make_short_sound,
         {"Support Make Short Sound", "rf4ce-profile.attr.ident_cap.support_make_short_sound",
          FT_BOOLEAN, SEP_DOT,
          NULL, RF4CE_PROFILE_GDP_IDENT_CAP_SUPPORT_MAKE_SHORT_SOUND_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_ident_cap_support_vibrate,
         {"Support Vibrate", "rf4ce-profile.attr.ident_cap.support_vibrate",
          FT_BOOLEAN, SEP_DOT,
          NULL, RF4CE_PROFILE_GDP_IDENT_CAP_SUPPORT_VIBRATE_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_ident_cap_reserved2,
         {"Reserved", "rf4ce-profile.attr.ident_cap.reserved2",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_GDP_IDENT_CAP_RESERVED2_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_methods_num,
         {"Polling Methods Number", "rf4ce-profile.attr.poll_constraints.methods_num",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_polling_rec_method_id,
         {"Polling Method ID", "rf4ce-profile.attr.poll_constraints.polling_record.method_id",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_profile_gdp_poll_constraints_polling_rec_method_id_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap,
         {"Polling Trigger Capabilities", "rf4ce-profile.attr.poll_constraints.polling_record.polling_trig_cap",
          FT_UINT16, BASE_HEX,
          NULL, RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_tbased,
         {"Time based polling capable", "rf4ce-profile.attr.poll_constraints.polling_record.polling_trig_cap.tbased",
          FT_BOOLEAN, 16,
          TFS(&tfs_enabled_disabled), RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_TBASED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_k_press,
         {"Polling On Key Press Capable", "rf4ce-profile.attr.poll_constraints.polling_record.polling_trig_cap.on_k_press",
          FT_BOOLEAN, 16,
          TFS(&tfs_enabled_disabled), RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_K_PRESS_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_pick_up,
         {"Polling On Pick Up Capable", "rf4ce-profile.attr.poll_constraints.polling_record.polling_trig_cap.on_pick_up",
          FT_BOOLEAN, 16,
          TFS(&tfs_enabled_disabled), RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_PICK_UP_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_reset,
         {"Polling On Reset Capable", "rf4ce-profile.attr.poll_constraints.polling_record.polling_trig_cap.on_reset",
          FT_BOOLEAN, 16,
          TFS(&tfs_enabled_disabled), RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_RESET_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_micro_act,
         {"Polling On Microphone Activity Capable", "rf4ce-profile.attr.poll_constraints.polling_record.polling_trig_cap.on_micro_act",
          FT_BOOLEAN, 16,
          TFS(&tfs_enabled_disabled), RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_MICRO_ACT_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_user_act,
         {"Polling On Other User Activity Capable", "rf4ce-profile.attr.poll_constraints.polling_record.polling_trig_cap.on_user_act",
          FT_BOOLEAN, 16,
          TFS(&tfs_enabled_disabled), RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_ON_USER_ACT_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_reserved,
         {"Reserved", "rf4ce-profile.attr.poll_constraints.polling_record.polling_trig_cap.reserved",
          FT_UINT16, BASE_HEX,
          NULL, RF4CE_PROFILE_GDP_POLL_CONSTRAINTS_POLLING_REC_POLLING_TRIG_CAP_RESERVED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_polling_rec_min_polling_key_press_cnt,
         {"Minimum Polling Key Press Counter", "rf4ce-profile.attr.poll_constraints.polling_record.min_polling_key_press_cnt",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_polling_rec_max_polling_key_press_cnt,
         {"Maximum Polling Key Press Counter", "rf4ce-profile.attr.poll_constraints.polling_record.max_polling_key_press_cnt",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_polling_rec_min_polling_time_interval,
         {"Minimum Polling Time Interval", "rf4ce-profile.attr.poll_constraints.polling_record.min_polling_time_interval",
          FT_UINT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_constraints_polling_rec_max_polling_time_interval,
         {"Maximum Polling Time Interval", "rf4ce-profile.attr.poll_constraints.polling_record.max_polling_time_interval",
          FT_UINT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_configuration_method_id,
         {"Polling Method ID", "rf4ce-profile.attr.poll_configuration.method_id",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_profile_gdp_poll_constraints_polling_rec_method_id_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf,
         {"Polling Trigger Configuration", "rf4ce-profile.attr.poll_configuration.polling_trig_conf",
          FT_UINT16, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_tbased,
         {"Time Based Polling", "rf4ce-profile.attr.poll_configuration.polling_trig_conf.tbased",
          FT_BOOLEAN, 16,
          TFS(&tfs_enabled_disabled), RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_TBASED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_k_press,
         {"Polling on Key Press", "rf4ce-profile.attr.poll_configuration.polling_trig_conf.on_k_press",
          FT_BOOLEAN, 16,
          TFS(&tfs_enabled_disabled), RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_K_PRESS_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_pick_up,
         {"Polling on Pick up", "rf4ce-profile.attr.poll_configuration.polling_trig_conf.on_pick_up",
          FT_BOOLEAN, 16,
          TFS(&tfs_enabled_disabled), RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_PICK_UP_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_reset,
         {"Polling on Reset", "rf4ce-profile.attr.poll_configuration.polling_trig_conf.on_reset",
          FT_BOOLEAN, 16,
          TFS(&tfs_enabled_disabled), RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_RESET_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_micro_act,
         {"Polling on Microphone Activity", "rf4ce-profile.attr.poll_configuration.polling_trig_conf.on_micro_act",
          FT_BOOLEAN, 16,
          TFS(&tfs_enabled_disabled), RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_MICRO_ACT_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_user_act,
         {"Polling on User Activity", "rf4ce-profile.attr.poll_configuration.polling_trig_conf.on_user_act",
          FT_BOOLEAN, 16,
          TFS(&tfs_enabled_disabled), RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_ON_USER_ACT_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_reserved,
         {"Reserved", "rf4ce-profile.attr.poll_configuration.polling_trig_conf.reserved",
          FT_UINT16, BASE_HEX,
          NULL, RF4CE_PROFILE_GDP_POLL_CONFIGURATION_POLLING_TRIG_CONF_RESERVED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_configuration_polling_key_press_cnt,
         {"Polling Key Press Counter", "rf4ce-profile.attr.poll_configuration.polling_key_press_cnt",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_configuration_polling_time_interval,
         {"Polling Time Interval", "rf4ce-profile.attr.poll_configuration.polling_time_interval",
          FT_UINT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_gdp_poll_configuration_polling_timeout,
         {"Polling Timeout", "rf4ce-profile.attr.poll_configuration.polling_timeout",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_mappable_actions_action_dev_type,
         {"Action Device Type", "rf4ce-profile.attr.mappable_actions.action_dev_type",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_profile_device_type_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_mappable_actions_action_bank,
         {"Action Bank", "rf4ce-profile.attr.mappable_actions.action_bank",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_mappable_actions_action_code,
         {"Action Code", "rf4ce-profile.attr.mappable_actions.action_code",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_mapping_flags,
         {"Mapping Flags", "rf4ce-profile.attr.action_mappings.mapping_flags",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_rf_specified,
         {"RF Specified", "rf4ce-profile.attr.action_mappings.mapping_flags.rf_specified",
          FT_BOOLEAN, SEP_DOT,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_RF_SPECIFIED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_ir_specified,
         {"IR Specified", "rf4ce-profile.attr.action_mappings.mapping_flags.ir_specified",
          FT_BOOLEAN, SEP_DOT,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_IR_SPECIFIED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_rf_descr_first,
         {"RF Descriptor First", "rf4ce-profile.attr.action_mappings.mapping_flags.rf_descr_first",
          FT_BOOLEAN, SEP_DOT,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_RF_DESCR_FIRST_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_reserved,
         {"Reserved", "rf4ce-profile.attr.action_mappings.mapping_flags.reserved",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_RESERVED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_use_default,
         {"Use Default", "rf4ce-profile.attr.action_mappings.mapping_flags.use_default",
          FT_BOOLEAN, SEP_DOT,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_USE_DEFAULT_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_permanent,
         {"Permanent", "rf4ce-profile.attr.action_mappings.mapping_flags.permanent",
          FT_BOOLEAN, SEP_DOT,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_PERMANENT_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf,
         {"RF Config", "rf4ce-profile.attr.action_mappings.rf_descr.rf_conf",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_min_num_of_trans,
         {"Minimum Number of Transmissions", "rf4ce-profile.attr.action_mappings.rf_descr.rf_conf.min_num_of_trans",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_MIN_NUM_OF_TRANS_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_keep_trans_until_key_release,
         {"Keep Transmitting Until Key Release", "rf4ce-profile.attr.action_mappings.rf_descr.rf_conf.keep_trans_until_key_release",
          FT_BOOLEAN, SEP_DOT,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_KEEP_TRANS_UNTIL_KEY_RELEASE_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_short_rf_retry,
         {"Short RF Retry", "rf4ce-profile.attr.action_mappings.rf_descr.rf_conf.short_rf_retry",
          FT_BOOLEAN, SEP_DOT,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_SHORT_RF_RETRY_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_atomic_action,
         {"Atomic Action", "rf4ce-profile.attr.action_mappings.rf_descr.rf_conf.atomic_action",
          FT_BOOLEAN, SEP_DOT,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_ATOMIC_ACTION_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_reserved,
         {"Reserved", "rf4ce-profile.attr.action_mappings.rf_descr.rf_conf.reserved",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_RF_CONF_RESERVED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts,
         {"TX Options", "rf4ce-profile.attr.action_mappings.rf_descr.tx_opts",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_trans_mode,
         {"Transmission Mode", "rf4ce-profile.attr.action_mappings.rf_descr.tx_opts.trans_mode",
          FT_BOOLEAN, SEP_DOT,
          TFS(&rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_trans_mode_vals), RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_TRANS_MODE_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_dst_addr_mode,
         {"Destination Addressing Mode", "rf4ce-profile.attr.action_mappings.rf_descr.tx_opts.dst_addr_mode",
          FT_BOOLEAN, SEP_DOT,
          TFS(&rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_dst_addr_mode_vals), RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_DST_ADDR_MODE_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ack_mode,
         {"Acknowledgement Mode", "rf4ce-profile.attr.action_mappings.rf_descr.tx_opts.ack_mode",
          FT_BOOLEAN, SEP_DOT,
          TFS(&rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ack_mode_vals), RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_ACK_MODE_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_sec_mode,
         {"Security Mode", "rf4ce-profile.attr.action_mappings.rf_descr.tx_opts.sec_mode",
          FT_BOOLEAN, SEP_DOT,
          TFS(&rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_sec_mode_vals), RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_SEC_MODE_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ch_ag_mode,
         {"Channel Agility Mode", "rf4ce-profile.attr.action_mappings.rf_descr.tx_opts.ch_ag_mode",
          FT_BOOLEAN, SEP_DOT,
          TFS(&rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ch_ag_mode_vals), RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_CH_AG_MODE_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ch_norm_mode,
         {"Channel Normalization Mode", "rf4ce-profile.attr.action_mappings.rf_descr.tx_opts.ch_norm_mode",
          FT_BOOLEAN, SEP_DOT,
          TFS(&rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ch_norm_mode_vals), RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_CH_NORM_MODE_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_payload_mode,
         {"Payload Mode", "rf4ce-profile.attr.action_mappings.rf_descr.tx_opts.payload_mode",
          FT_BOOLEAN, SEP_DOT,
          TFS(&rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_payload_mode_vals), RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_PAYLOAD_MODE_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_reserved,
         {"Reserved", "rf4ce-profile.attr.action_mappings.rf_descr.tx_opts.reserved",
          FT_BOOLEAN, SEP_DOT,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_RF_DESCR_TX_OPTS_RESERVED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_rf_descr_action_data_len,
         {"Action Data Length", "rf4ce-profile.attr.action_mappings.rf_descr.action_data_len",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_conf,
         {"IR Config", "rf4ce-profile.attr.action_mappings.ir_descr.ir_conf",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_IR_DESCR_IR_CONF_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_conf_vendor_specific,
         {"Vendor Specific", "rf4ce-profile.attr.action_mappings.ir_descr.ir_conf.vendor_specific",
          FT_BOOLEAN, SEP_DOT,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_IR_DESCR_IR_CONF_VENDOR_SPECIFIC_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_conf_reserved,
         {"Reserved", "rf4ce-profile.attr.action_mappings.ir_descr.ir_conf.reserved",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_IR_DESCR_IR_CONF_RESERVED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_vendor_id,
         {"IR Vendor ID", "rf4ce-profile.attr.action_mappings.ir_descr.ir_vendor_id",
          FT_UINT16, BASE_HEX,
          VALS(rf4ce_vendor_id_vals), RF4CE_VENDOR_ID_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_code_len,
         {"IR Code Length", "rf4ce-profile.attr.action_mappings.ir_descr.ir_code_len",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_code,
         {"IR Code", "rf4ce-profile.attr.action_mappings.ir_descr.ir_code",
          FT_BYTES, SEP_COLON,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_zrc20_irdb_vendor_support_vendor_id,
         {"Vendor ID", "rf4ce-profile.attr.irdb_vendor_support.vendor_id",
          FT_UINT16, BASE_HEX,
          VALS(rf4ce_vendor_id_vals), RF4CE_VENDOR_ID_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_check_validation_sub_type,
         {"Sub-type", "rf4ce-profile.cmd.check_validation.sub_type",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_profile_cmd_check_validation_sub_type_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_check_validation_control,
         {"Validation Control", "rf4ce-profile.cmd.check_validation.validation_control",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_check_validation_status,
         {"Validation Status", "rf4ce-profile.cmd.check_validation.validation_status",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_profile_cmd_check_validation_status_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_client_notification_sub_type,
         {"Sub-ype", "rf4ce-profile.cmd.client_notification.sub_type",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_profile_cmd_client_notification_sub_type_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_client_notification_identify_flags,
         {"Identify Flags", "rf4ce-profile.cmd.client_notification.identify_flags",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_client_notification_identify_flags_stop_on_action,
         {"Stop on Action", "rf4ce-profile.cmd.client_notification.identify_flags.stop_on_action",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_STOP_ON_ACTION_FLAG,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_client_notification_identify_flags_flash_light,
         {"Flash Light", "rf4ce-profile.cmd.client_notification.identify_flags.flash_light",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_FLASH_LIGHT_FLAG,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_client_notification_identify_flags_make_sound,
         {"Make Sound", "rf4ce-profile.cmd.client_notification.identify_flags.make_sound",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_MAKE_SOUND_FLAG,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_client_notification_identify_flags_vibrate,
         {"Vibrate", "rf4ce-profile.cmd.client_notification.identify_flags.vibrate",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_VIBRATE_FLAG,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_client_notification_identify_flags_reserved,
         {"Reserved", "rf4ce-profile.cmd.client_notification.identify_flags.reserved",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY_RESERVED_FLAG,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_client_notification_identify_time,
         {"Identify Time", "rf4ce-profile.cmd.client_notification.identify_time",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_key_exchange_sub_type,
         {"Sub-type", "rf4ce-profile.cmd.key_exchange.sub_type",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_profile_cmd_key_exchange_sub_type_vals), 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_key_exchange_flags,
         {"Key Exchange Flags", "rf4ce-profile.cmd.key_exchange.flags",
          FT_UINT16, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_key_exchange_flags_default_secret,
         {"Default Secret", "rf4ce-profile.cmd.key_exchange.flags.default_secret",
          FT_UINT16, BASE_HEX,
          NULL, RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_DEFAULT_SECRET_FLAG,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_key_exchange_flags_initiator_vendor_specific_secret,
         {"Initiator Vendor Specific Secret", "rf4ce-profile.cmd.key_exchange.flags.initiator_vendor_specific_secret",
          FT_UINT16, BASE_HEX,
          NULL, RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_INITIATOR_VENDOR_SPECIFIC_SECRET_FLAG,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_key_exchange_flags_responder_vendor_specific_secret,
         {"Responder Vendor Specific Secret", "rf4ce-profile.cmd.key_exchange.flags.responder_vendor_specific_secret",
          FT_UINT16, BASE_HEX,
          NULL, RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_RESPONDER_VENDOR_SPECIFIC_SECRET_FLAG,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_key_exchange_flags_reserved,
         {"Reserved", "rf4ce-profile.cmd.key_exchange.flags.reserved",
          FT_UINT16, BASE_HEX,
          NULL, RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_RESERVED_FLAG,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_key_exchange_flags_vendor_specific_parameter,
         {"Vendor Specific Parameter", "rf4ce-profile.cmd.key_exchange.flags.vendor_specific_parameter",
          FT_UINT16, BASE_HEX,
          NULL, RF4CE_PROFILE_CMD_KEY_EXCHANGE_FLAGS_VENDOR_SPECIFIC_PARAMETER_FLAG,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_key_exchange_rand_a,
         {"Rand-A", "rf4ce-profile.cmd.key_exchange.rand_a",
          FT_BYTES, SEP_COLON,
          NULL, 0x00,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_key_exchange_rand_b,
         {"Rand-B", "rf4ce-profile.cmd.key_exchange.rand_b",
          FT_BYTES, SEP_COLON,
          NULL, 0x00,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_key_exchange_tag_b,
         {"TAG-B", "rf4ce-profile.cmd.key_exchange.tag_b",
          FT_BYTES, SEP_COLON,
          NULL, 0x00,
          NULL, HFILL}},
        {&hf_rf4ce_profile_cmd_key_exchange_tag_a,
         {"TAG-A", "rf4ce-profile.cmd.key_exchange.tag_a",
          FT_BYTES, SEP_COLON,
          NULL, 0x00,
          NULL, HFILL}},
#if 0
        {&hf_rf4ce_zrc20_cmd_actions,
         {"Actions", "rf4ce-profile.zrc20.cmd.actions",
          FT_BYTES, SEP_COLON,
          NULL, 0x00,
          NULL, HFILL}},
#endif
        {&hf_rf4ce_zrc20_cmd_actions_action_control,
         {"Action Control", "rf4ce-profile.zrc20.cmd.actions.action_control",
          FT_UINT8, BASE_HEX,
          NULL, 0x00,
          NULL, HFILL}},
        {&hf_rf4ce_zrc20_cmd_actions_action_control_action_type,
         {"Action Type", "rf4ce-profile.zrc20.cmd.actions.action_control.action_type",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_zrc20_cmd_actions_action_control_action_type_vals), RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_ACTION_TYPE_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_zrc20_cmd_actions_action_control_reserved,
         {"Reserved", "rf4ce-profile.zrc20.cmd.actions.action_control.reserved",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_RESERVED,
          NULL, HFILL}},
        {&hf_rf4ce_zrc20_cmd_actions_action_control_modifier_bits_gui,
         {"GUI Modifier", "rf4ce-profile.zrc20.cmd.actions.action_control.modifier_bits.gui",
          FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_MODIFIER_BITS_GUI,
          NULL, HFILL}},
        {&hf_rf4ce_zrc20_cmd_actions_action_control_modifier_bits_alt,
         {"ALT Modifier", "rf4ce-profile.zrc20.cmd.actions.action_control.modifier_bits.alt",
          FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_MODIFIER_BITS_ALT,
          NULL, HFILL}},
        {&hf_rf4ce_zrc20_cmd_actions_action_control_modifier_bits_shift,
         {"SHIFT Modifier", "rf4ce-profile.zrc20.cmd.actions.action_control.modifier_bits.shift",
          FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_MODIFIER_BITS_SHIFT,
          NULL, HFILL}},
        {&hf_rf4ce_zrc20_cmd_actions_action_control_modifier_bits_ctrl,
         {"CTRL Modifier", "rf4ce-profile.zrc20.cmd.actions.action_control.modifier_bits.ctrl",
          FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), RF4CE_ZRC20_CMD_ACTIONS_ACTION_CONTROL_MODIFIER_BITS_CTRL,
          NULL, HFILL}},
        {&hf_rf4ce_zrc20_cmd_actions_action_data_payload_length,
         {"Payload Length", "rf4ce-profile.zrc20.cmd.actions.action_data.payload_length",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_zrc20_cmd_actions_action_data_action_bank,
         {"Action Bank", "rf4ce-profile.zrc20.cmd.actions.action_data.action_bank",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_zrc20_cmd_actions_action_data_action_code,
         {"Action Code", "rf4ce-profile.zrc20.cmd.actions.action_data.action_code",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_zrc20_cmd_actions_action_data_action_vendor,
         {"Action Vendor", "rf4ce-profile.zrc20.cmd.actions.action_data.action_vendor",
          FT_UINT16, BASE_HEX,
          VALS(rf4ce_vendor_id_vals), RF4CE_VENDOR_ID_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_zrc20_cmd_actions_action_data_action_payload,
         {"Action Payload", "rf4ce-profile.zrc20.cmd.actions.action_data.action_payload",
          FT_BYTES, SEP_COLON,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_zrc10_fcf,
         {"Frame Control Field", "rf4ce-profile.zrc10.fcf",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_zrc10_fcf_cmd_id,
         {"Command ID", "rf4ce-profile.zrc10.fcf.cmd_id",
          FT_UINT8, BASE_HEX,
          VALS(rf4ce_zrc10_fcf_cmd_id_vals), RF4CE_ZRC10_FCF_CMD_ID_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_zrc10_fcf_reserved,
         {"Reserved", "rf4ce-profile.zrc10.fcf.reserved",
          FT_UINT8, BASE_HEX,
          NULL, RF4CE_ZRC10_FCF_RESERVED_MASK,
          NULL, HFILL}},
        {&hf_rf4ce_zrc10_cmd_common_rc_command_code,
         {"RC Command Code", "rf4ce-profile.zrc10.cmd_common.rc_command_code",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_zrc10_cmd_common_rc_command_payload,
         {"RC Command Payload", "rf4ce-profile.zrc10.cmd_common.rc_command_payload",
          FT_BYTES, SEP_COLON,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_zrc10_cmd_disc_reserved,
         {"Reserved", "rf4ce-profile.zrc10.cmd.discovery.reserved",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_zrc10_cmd_disc_rsp_supported_commands,
         {"Supported Commands", "rf4ce-profile.zrc10.cmd_disc_rsp.supported_commands",
          FT_BYTES, SEP_COLON,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_rf4ce_profile_unparsed_payload,
         {"Unparsed Profile Payload", "rf4ce-profile.unparsed_payload",
          FT_BYTES, SEP_COLON,
          NULL, 0x0,
          NULL, HFILL}},
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_rf4ce_profile,
        &ett_rf4ce_profile_cmd_frame,
        &ett_rf4ce_profile_attrs,
        &ett_rf4ce_profile_attrs_sub,
        &ett_rf4ce_profile_zrc20_ident_cap,
        &ett_rf4ce_profile_zrc20_mappable_actions_entry,
        &ett_rf4ce_profile_zrc20_action_control,
        &ett_rf4ce_profile_zrc20_action_mappings_flags,
        &ett_rf4ce_profile_zrc20_action_mappings_rf_descr,
        &ett_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf,
        &ett_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts,
        &ett_rf4ce_profile_zrc20_action_mappings_ir_descr,
        &ett_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_conf,
        &ett_rf4ce_profile_gdp_poll_constraints_polling_rec,
        &ett_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap,
        &ett_rf4ce_profile_gdp_poll_configuration_polling_trig_conf,
        &ett_rf4ce_profile_action_records,
        &ett_rf4ce_profile_action_records_sub,
        &ett_rf4ce_profile_zrc10_supported_commands,
        &ett_rf4ce_profile_zrc10_supported_commands_sub};

    proto_rf4ce_profile = proto_register_protocol("RF4CE Profile", "RF4CE Profile", "rf4ce_profile");
    proto_register_field_array(proto_rf4ce_profile, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    rf4ce_profile_dissector_table = register_dissector_table("rf4ce.profile", "RF4CE Profile", proto_rf4ce_profile, FT_NONE, BASE_NONE);
    rf4ce_profile_handle = register_dissector("rf4ce_profile", dissect_rf4ce_profile_common, proto_rf4ce_profile);
}

void proto_reg_handoff_rf4ce_profile(void)
{
}

/* RF4CE Profile common dissector */
static int dissect_rf4ce_profile_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    unsigned offset = 0;
    proto_item *ti = proto_tree_add_item(tree, proto_rf4ce_profile, tvb, 0, -1, ENC_LITTLE_ENDIAN);
    proto_tree *rf4ce_profile_tree = proto_item_add_subtree(ti, ett_rf4ce_profile);

    uint8_t fcf = tvb_get_uint8(tvb, offset);
    uint8_t cmd_id = fcf & RF4CE_PROFILE_FCF_CMD_ID_MASK;
    bool is_cmd_frame = fcf & RF4CE_PROFILE_FCF_CMD_FRAME_MASK;
    bool is_gdp = !strncmp("GDP", (char *)data, 3);
    bool is_zrc20 = !strncmp("ZRC 2.0", (char *)data, 7);
    bool is_zrc10 = !strncmp("ZRC 1.0", (char *)data, 7);

    char protocol_str[14] = {0};

    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    if (is_gdp || (is_zrc20 && is_cmd_frame))
    {
        static int *const gdp_fcf_bits[] = {
            &hf_rf4ce_profile_fcf_cmd_id,
            &hf_rf4ce_profile_fcf_reserved,
            &hf_rf4ce_profile_fcf_cmd_frame,
            &hf_rf4ce_profile_fcf_data_pending,
            NULL};

        proto_tree_add_bitmask(rf4ce_profile_tree, tvb, offset, hf_rf4ce_profile_fcf, ett_rf4ce_profile, gdp_fcf_bits, ENC_LITTLE_ENDIAN);
        offset += 1;
    }
    else if (is_zrc20)
    {
        static int *const zrc20_fcf_bits[] = {
            &hf_rf4ce_zrc20_fcf_cmd_id,
            &hf_rf4ce_profile_fcf_reserved,
            &hf_rf4ce_profile_fcf_cmd_frame,
            &hf_rf4ce_profile_fcf_data_pending,
            NULL};

        proto_tree_add_bitmask(rf4ce_profile_tree, tvb, offset, hf_rf4ce_profile_fcf, ett_rf4ce_profile, zrc20_fcf_bits, ENC_LITTLE_ENDIAN);
        offset += 1;
    }
    else if (is_zrc10)
    {
        static int *const zrc10_fcf_bits[] = {
            &hf_rf4ce_zrc10_fcf_cmd_id,
            &hf_rf4ce_zrc10_fcf_reserved,
            NULL};

        proto_tree_add_bitmask(rf4ce_profile_tree, tvb, offset, hf_rf4ce_zrc10_fcf, ett_rf4ce_profile, zrc10_fcf_bits, ENC_LITTLE_ENDIAN);
        offset += 1;

        cmd_id = fcf & RF4CE_ZRC10_FCF_CMD_ID_MASK;
    }

    snprintf(protocol_str, sizeof(protocol_str), "%s %s", "RF4CE", (char *)data);
    col_add_str(pinfo->cinfo, COL_PROTOCOL, protocol_str);

    if (is_gdp || is_zrc20 || is_zrc10)
    {
        dissect_rf4ce_profile_cmd(tvb, pinfo, rf4ce_profile_tree, &offset, cmd_id, (char *)data, is_cmd_frame);
    }

    if (offset < tvb_captured_length(tvb))
    {
        unsigned unparsed_length = tvb_captured_length(tvb) - offset;
        proto_tree_add_item(rf4ce_profile_tree, hf_rf4ce_profile_unparsed_payload, tvb, offset, unparsed_length, ENC_NA);
        offset += unparsed_length;
    }

    return offset;
}

static void dissect_rf4ce_profile_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset, uint8_t cmd_id, char *profile_str, bool is_cmd_frame)
{
    proto_tree *profile_cmd_tree;
    bool is_zrc10 = !strncmp("ZRC 1.0", profile_str, 7);
    bool is_zrc20 = !strncmp("ZRC 2.0", profile_str, 7);

    profile_cmd_tree = proto_tree_add_subtree(tree, tvb, *offset, tvb_captured_length(tvb) - *offset, ett_rf4ce_profile_cmd_frame, NULL, "Profile Command Frame");

    if (is_cmd_frame)
    {
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(cmd_id, rf4ce_profile_fcf_cmd_id_vals, "Unknown Command"));
        dissect_rf4ce_profile_common_cmd(tvb, pinfo, profile_cmd_tree, offset, cmd_id, is_zrc20);
    }
    else if (is_zrc10)
    {
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(cmd_id, rf4ce_zrc10_fcf_cmd_id_vals, "Unknown Command"));
        dissect_rf4ce_profile_zrc10_cmd(tvb, profile_cmd_tree, offset, cmd_id);
    }
    /* cmd_frame bit MUST be zero for ZRC 2.0 profile */
    else if (is_zrc20 || !is_cmd_frame)
    {
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(cmd_id, rf4ce_zrc20_fcf_cmd_id_vals, "Unknown Command"));
        dissect_rf4ce_profile_zrc20_cmd(tvb, profile_cmd_tree, offset, cmd_id);
    }
}

static void dissect_rf4ce_profile_common_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset, uint8_t cmd_id, bool is_zrc20)
{
    switch (cmd_id)
    {
    case RF4CE_PROFILE_CMD_GENERIC_RESPONSE:
        dissect_rf4ce_profile_cmd_generic_resp(tvb, tree, offset);
        break;

    case RF4CE_PROFILE_CMD_CONFIGURATION_COMPLETE:
        dissect_rf4ce_profile_cmd_configuration_complete(tvb, tree, offset);
        break;

    case RF4CE_PROFILE_CMD_HEARTBEAT:
        dissect_rf4ce_profile_cmd_heartbeat(tvb, tree, offset);
        break;

    case RF4CE_PROFILE_CMD_GET_ATTRIBUTES:
        dissect_rf4ce_profile_cmd_get_attrs(tvb, tree, offset, is_zrc20);
        break;

    case RF4CE_PROFILE_CMD_GET_ATTRIBUTES_RESPONSE:
        dissect_rf4ce_profile_cmd_get_attrs_resp(tvb, tree, offset, is_zrc20);
        break;

    case RF4CE_PROFILE_CMD_PUSH_ATTRIBUTES:
        dissect_rf4ce_profile_cmd_push_attrs(tvb, tree, offset, is_zrc20);
        break;

    case RF4CE_PROFILE_CMD_SET_ATTRIBUTES:
        dissect_rf4ce_profile_cmd_set_attrs(tvb, tree, offset, is_zrc20);
        break;

    case RF4CE_PROFILE_CMD_PULL_ATTRIBUTES:
        dissect_rf4ce_profile_cmd_pull_attrs(tvb, tree, offset, is_zrc20);
        break;

    case RF4CE_PROFILE_CMD_PULL_ATTRIBUTES_RESPONSE:
        dissect_rf4ce_profile_cmd_pull_attrs_resp(tvb, tree, offset, is_zrc20);
        break;

    case RF4CE_PROFILE_CMD_CHECK_VALIDATION:
        dissect_rf4ce_profile_cmd_check_validation(tvb, tree, offset);
        break;

    case RF4CE_PROFILE_CMD_CLIENT_NOTIFICATION:
        dissect_rf4ce_profile_cmd_client_notification(tvb, tree, offset);
        break;

    case RF4CE_PROFILE_CMD_KEY_EXCHANGE:
        dissect_rf4ce_profile_cmd_key_exchange(tvb, pinfo, tree, offset);
        break;
    }
}

static void dissect_rf4ce_profile_cmd_generic_resp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree_add_item(tree, hf_rf4ce_profile_cmd_generic_resp_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
}

static void dissect_rf4ce_profile_cmd_configuration_complete(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree_add_item(tree, hf_rf4ce_profile_cmd_configuration_complete_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
}

static void dissect_rf4ce_profile_cmd_heartbeat(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree_add_item(tree, hf_rf4ce_profile_cmd_heartbeat_trigger, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
}

static bool dissect_rf4ce_profile_gdp_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, uint8_t attr_id)
{
    bool is_parsed = true;

    if (attr_id == RF4CE_GDP_ATTR_IDENTIFICATION_CAPABILITIES)
    {
        static int *const ident_cap_bits[] = {
            &hf_rf4ce_profile_gdp_ident_cap_reserved,
            &hf_rf4ce_profile_gdp_ident_cap_support_flash_light,
            &hf_rf4ce_profile_gdp_ident_cap_support_make_short_sound,
            &hf_rf4ce_profile_gdp_ident_cap_support_vibrate,
            &hf_rf4ce_profile_gdp_ident_cap_reserved2,
            NULL};

        proto_tree_add_bitmask(tree, tvb, *offset, hf_rf4ce_profile_gdp_ident_cap, ett_rf4ce_profile_zrc20_ident_cap, ident_cap_bits, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }
    else if (attr_id == RF4CE_GDP_ATTR_POLL_CONSTRAINTS)
    {
        int methods_index;
        uint8_t methods_num;

        static int *const polling_trig_cap_bits[] = {
            &hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_tbased,
            &hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_k_press,
            &hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_pick_up,
            &hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_reset,
            &hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_micro_act,
            &hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_on_user_act,
            &hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap_reserved,
            NULL};

        proto_tree_add_item(tree, hf_rf4ce_profile_gdp_poll_constraints_methods_num, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        methods_num = tvb_get_uint8(tvb, *offset);
        *offset += 1;

        for (methods_index = 1; methods_index <= methods_num; methods_index++)
        {
            char subtree_name[40];
            proto_tree *record_subtree;

            snprintf(subtree_name, sizeof(subtree_name), "Polling Constraint Record %d:", methods_index);
            record_subtree = proto_tree_add_subtree(tree, tvb, *offset, tvb_captured_length(tvb) - *offset, ett_rf4ce_profile_gdp_poll_constraints_polling_rec, NULL, subtree_name);

            proto_tree_add_item(record_subtree, hf_rf4ce_profile_gdp_poll_constraints_polling_rec_method_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;

            proto_tree_add_bitmask(record_subtree, tvb, *offset, hf_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap, ett_rf4ce_profile_gdp_poll_constraints_polling_rec_polling_trig_cap, polling_trig_cap_bits, ENC_LITTLE_ENDIAN);
            *offset += 2;

            proto_tree_add_item(record_subtree, hf_rf4ce_profile_gdp_poll_constraints_polling_rec_min_polling_key_press_cnt, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;

            proto_tree_add_item(record_subtree, hf_rf4ce_profile_gdp_poll_constraints_polling_rec_max_polling_key_press_cnt, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;

            proto_tree_add_item(record_subtree, hf_rf4ce_profile_gdp_poll_constraints_polling_rec_min_polling_time_interval, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            *offset += 4;

            proto_tree_add_item(record_subtree, hf_rf4ce_profile_gdp_poll_constraints_polling_rec_max_polling_time_interval, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            *offset += 4;
        }
    }
    else if (attr_id == RF4CE_GDP_ATTR_POLL_CONFIGURATION)
    {
        proto_tree_add_item(tree, hf_rf4ce_profile_gdp_poll_configuration_method_id, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;

        static int *const polling_trig_conf_bits[] = {
            &hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_tbased,
            &hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_k_press,
            &hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_pick_up,
            &hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_reset,
            &hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_micro_act,
            &hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_on_user_act,
            &hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf_reserved,
            NULL};

        proto_tree_add_bitmask_len(tree, tvb, *offset, 2, hf_rf4ce_profile_gdp_poll_configuration_polling_trig_conf, ett_rf4ce_profile_gdp_poll_configuration_polling_trig_conf, polling_trig_conf_bits, NULL, ENC_LITTLE_ENDIAN);
        *offset += 2;

        proto_tree_add_item(tree, hf_rf4ce_profile_gdp_poll_configuration_polling_key_press_cnt, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;

        proto_tree_add_item(tree, hf_rf4ce_profile_gdp_poll_configuration_polling_time_interval, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;

        proto_tree_add_item(tree, hf_rf4ce_profile_gdp_poll_configuration_polling_timeout, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }
#if 0
  else if (attr_id == RF4CE_GDP_ATTR_GDP_PROFILE_CAPABILITIES)
  {
    /* TODO: Implement RF4CE_GDP_ATTR_GDP_CAPABILITIES parsing */
  }
  else if (attr_id == RF4CE_GDP_ATTR_POWER_STATUS)
  {
    /* TODO: Implement RF4CE_GDP_ATTR_POWER_STATUS parsing */
  }
#endif
    else
    {
        is_parsed = false;
    }

    return is_parsed;
}

static bool dissect_rf4ce_profile_zrc20_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, uint8_t attr_id, uint8_t attr_length)
{
    bool is_parsed = true;

    if (attr_id == RF4CE_ZRC20_ATTR_MAPPABLE_ACTIONS)
    {
        proto_tree *entry_subtree;
        char entry_subtree_name[11];
        unsigned entries_num = attr_length / 3;

        for (unsigned i = 1; i <= entries_num; i++)
        {
            snprintf(entry_subtree_name, sizeof(entry_subtree_name), "Entry %d:", i);
            entry_subtree = proto_tree_add_subtree(tree, tvb, *offset, tvb_captured_length(tvb) - *offset, ett_rf4ce_profile_zrc20_mappable_actions_entry, NULL, entry_subtree_name);

            proto_tree_add_item(entry_subtree, hf_rf4ce_profile_zrc20_mappable_actions_action_dev_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;

            proto_tree_add_item(entry_subtree, hf_rf4ce_profile_zrc20_mappable_actions_action_bank, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;

            proto_tree_add_item(entry_subtree, hf_rf4ce_profile_zrc20_mappable_actions_action_code, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
        }
    }
    else if (attr_id == RF4CE_ZRC20_ATTR_ACTION_MAPPINGS)
    {
        uint8_t action_mapping_flags = tvb_get_uint8(tvb, *offset);
        bool rf_specified = (action_mapping_flags & RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_RF_SPECIFIED_MASK) != 0;
        bool ir_specified = (action_mapping_flags & RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_IR_SPECIFIED_MASK) != 0;
        bool use_default = (action_mapping_flags & RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_MAPPING_FLAGS_USE_DEFAULT_MASK) != 0;

        static int *const action_mapping_flags_bits[] = {
            &hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_rf_specified,
            &hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_ir_specified,
            &hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_rf_descr_first,
            &hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_reserved,
            &hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_use_default,
            &hf_rf4ce_profile_zrc20_action_mappings_mapping_flags_permanent,
            NULL};

        proto_tree_add_bitmask(tree, tvb, *offset, hf_rf4ce_profile_zrc20_action_mappings_mapping_flags, ett_rf4ce_profile_zrc20_action_mappings_flags, action_mapping_flags_bits, ENC_LITTLE_ENDIAN);
        *offset += 1;

        if (rf_specified && !use_default)
        {
            proto_tree *rf_desc_subtree = proto_tree_add_subtree(tree, tvb, *offset, tvb_captured_length(tvb) - *offset, ett_rf4ce_profile_zrc20_action_mappings_rf_descr, NULL, "RF Descriptor");
            uint8_t action_data_len;

            static int *const rf_conf_bits[] = {
                &hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_min_num_of_trans,
                &hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_keep_trans_until_key_release,
                &hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_short_rf_retry,
                &hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_atomic_action,
                &hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf_reserved,
                NULL};

            proto_tree_add_bitmask(rf_desc_subtree, tvb, *offset, hf_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf, ett_rf4ce_profile_zrc20_action_mappings_rf_descr_rf_conf, rf_conf_bits, ENC_LITTLE_ENDIAN);
            *offset += 1;

            static int *const tx_opts_bits[] = {
                &hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_trans_mode,
                &hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_dst_addr_mode,
                &hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ack_mode,
                &hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_sec_mode,
                &hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ch_ag_mode,
                &hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_ch_norm_mode,
                &hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_payload_mode,
                &hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts_reserved,
                NULL};

            proto_tree_add_bitmask(rf_desc_subtree, tvb, *offset, hf_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts, ett_rf4ce_profile_zrc20_action_mappings_rf_descr_tx_opts, tx_opts_bits, ENC_LITTLE_ENDIAN);
            *offset += 1;

            proto_tree_add_item(rf_desc_subtree, hf_rf4ce_profile_zrc20_action_mappings_rf_descr_action_data_len, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            action_data_len = tvb_get_uint8(tvb, *offset);
            *offset += 1;

            if (action_data_len > 0)
            {
                dissect_rf4ce_profile_zrc20_action_data(tvb, rf_desc_subtree, offset, false /* do not dissect the Action Control field */);
            }
        }

        if (ir_specified && !use_default)
        {
            proto_tree *ir_desc_subtree = proto_tree_add_subtree(tree, tvb, *offset, tvb_captured_length(tvb) - *offset, ett_rf4ce_profile_zrc20_action_mappings_ir_descr, NULL, "IR Descriptor");
            uint8_t ir_config;
            bool vendor_specific;
            uint8_t ir_code_len;

            static int *const ir_conf_bits[] = {
                &hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_conf_vendor_specific,
                &hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_conf_reserved,
                NULL};

            proto_tree_add_bitmask(ir_desc_subtree, tvb, *offset, hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_conf, ett_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_conf, ir_conf_bits, ENC_LITTLE_ENDIAN);
            ir_config = tvb_get_uint8(tvb, *offset);
            *offset += 1;

            vendor_specific = (ir_config & RF4CE_PROFILE_ZRC20_ACTION_MAPPINGS_IR_DESCR_IR_CONF_VENDOR_SPECIFIC_MASK) != 0;
            if (vendor_specific)
            {
                proto_tree_add_item(ir_desc_subtree, hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_vendor_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                *offset += 2;
            }

            proto_tree_add_item(ir_desc_subtree, hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_code_len, tvb, *offset, 1, ENC_NA);
            ir_code_len = tvb_get_uint8(tvb, *offset);
            *offset += 1;

            if (ir_code_len > 0)
            {
                proto_tree_add_item(ir_desc_subtree, hf_rf4ce_profile_zrc20_action_mappings_ir_descr_ir_code, tvb, *offset, ir_code_len, ENC_NA);
                *offset += ir_code_len;
            }
        }
    }
    else if (attr_id == RF4CE_ZRC20_ATTR_IRDB_VENDOR_SUPPORT)
    {
        int remaining_length = tvb_reported_length_remaining(tvb, *offset);
        while (remaining_length > 0)
        {
            proto_tree_add_item(tree, hf_rf4ce_profile_zrc20_irdb_vendor_support_vendor_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            remaining_length -= 2;
        }
    }
    else
    {
        is_parsed = false;
    }

    return is_parsed;
}

static void dissect_rf4ce_profile_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, uint8_t dissection_mask, bool is_zrc20)
{
    int attr_counter = 1;
    uint8_t attr_id = 0xff;
    uint8_t attr_status = RF4CE_PROFILE_ATTR_STATUS_ATTRIBUTE_SUCCESSFULLY_READ_AND_INCLUDED;
    uint8_t attr_length = 0xff;
    proto_tree *attrs_tree = proto_tree_add_subtree(tree, tvb, *offset, tvb_captured_length(tvb) - *offset, ett_rf4ce_profile_attrs, NULL, "Attributes List");
    unsigned prev_offset = *offset;

    while (tvb_captured_length(tvb) - *offset)
    {
        char attr_subtree_name[14];
        proto_tree *attrs_subtree;

        snprintf(attr_subtree_name, sizeof(attr_subtree_name), "Attribute %d:", attr_counter);
        attr_counter++;

        attrs_subtree = proto_tree_add_subtree(attrs_tree, tvb, *offset, tvb_captured_length(tvb) - *offset, ett_rf4ce_profile_attrs_sub, NULL, attr_subtree_name);

        if (dissection_mask & RF4CE_PROFILE_ATTR_DISSECT_ATTR_ID_MASK)
        {
            int hf_temp = is_zrc20 ? hf_rf4ce_profile_zrc20_attr_id : hf_rf4ce_profile_gdp_attr_id;

            proto_tree_add_item(attrs_subtree, hf_temp, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            attr_id = tvb_get_uint8(tvb, *offset);
            *offset += 1;
        }

        if (dissection_mask & RF4CE_PROFILE_ATTR_DISSECT_ENTRY_ID_MASK)
        {
            bool is_attr_arrayed =
                is_zrc20 ? rf4ce_profile_is_zrc20_attr_arrayed(attr_id) : rf4ce_profile_is_gdp_attr_arrayed(attr_id);
            if (is_attr_arrayed)
            {
                proto_tree_add_item(attrs_subtree, hf_rf4ce_profile_attr_entry_id, tvb, *offset, 2, ENC_NA);
                *offset += 2;
            }
        }

        if (dissection_mask & RF4CE_PROFILE_ATTR_DISSECT_ATTR_STATUS_MASK)
        {
            proto_tree_add_item(attrs_subtree, hf_rf4ce_profile_attr_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            attr_status = tvb_get_uint8(tvb, *offset);
            *offset += 1;
        }

        if (attr_status == RF4CE_PROFILE_ATTR_STATUS_ATTRIBUTE_SUCCESSFULLY_READ_AND_INCLUDED && dissection_mask & RF4CE_PROFILE_ATTR_DISSECT_ATTR_LENGTH_MASK)
        {
            proto_tree_add_item(attrs_subtree, hf_rf4ce_profile_attr_length, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            attr_length = tvb_get_uint8(tvb, *offset);
            *offset += 1;
        }

        if (attr_status == RF4CE_PROFILE_ATTR_STATUS_ATTRIBUTE_SUCCESSFULLY_READ_AND_INCLUDED && dissection_mask & RF4CE_PROFILE_ATTR_DISSECT_ATTR_VALUE_MASK && attr_length != 0xff && attr_length != 0x00)
        {
            bool is_parsed;

            if (is_zrc20)
            {
                is_parsed = dissect_rf4ce_profile_zrc20_attrs(tvb, attrs_subtree, offset, attr_id, attr_length);
            }
            else
            {
                is_parsed = dissect_rf4ce_profile_gdp_attrs(tvb, attrs_subtree, offset, attr_id);
            }

            if (!is_parsed)
            {
                proto_tree_add_item(attrs_subtree, hf_rf4ce_profile_attr_value, tvb, *offset, attr_length, ENC_NA);
                *offset += attr_length;
            }
        }

        if (dissection_mask == RF4CE_PROFILE_ATTR_DISSECT_NOT_SET || prev_offset == *offset)
        {
            attr_length = tvb_captured_length(tvb) - *offset;
            proto_tree_add_item(attrs_subtree, hf_rf4ce_profile_attr_value, tvb, *offset, attr_length, ENC_NA);
            *offset += attr_length;
        }

	    prev_offset = *offset;
    }
}

static void dissect_rf4ce_profile_cmd_get_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool is_zrc20)
{
    dissect_rf4ce_profile_attrs(tvb, tree, offset, RF4CE_PROFILE_ATTR_DISSECT_GET_ATTRS_MASK, is_zrc20);
}

static void dissect_rf4ce_profile_cmd_get_attrs_resp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool is_zrc20)
{
    dissect_rf4ce_profile_attrs(tvb, tree, offset, RF4CE_PROFILE_ATTR_DISSECT_GET_ATTRS_RESP_MASK, is_zrc20);
}

static void dissect_rf4ce_profile_cmd_push_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool is_zrc20)
{
    dissect_rf4ce_profile_attrs(tvb, tree, offset, RF4CE_PROFILE_ATTR_DISSECT_PUSH_ATTRS_MASK, is_zrc20);
}

static void dissect_rf4ce_profile_cmd_set_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool is_zrc20)
{
    dissect_rf4ce_profile_attrs(tvb, tree, offset, RF4CE_PROFILE_ATTR_DISSECT_SET_ATTRS_MASK, is_zrc20);
}

static void dissect_rf4ce_profile_cmd_pull_attrs(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool is_zrc20)
{
    dissect_rf4ce_profile_attrs(tvb, tree, offset, RF4CE_PROFILE_ATTR_DISSECT_PULL_ATTRS_MASK, is_zrc20);
}

static void dissect_rf4ce_profile_cmd_pull_attrs_resp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool is_zrc20)
{
    dissect_rf4ce_profile_attrs(tvb, tree, offset, RF4CE_PROFILE_ATTR_DISSECT_PULL_ATTRS_RESP_MASK, is_zrc20);
}

static bool rf4ce_profile_is_gdp_attr_arrayed(uint8_t attr_id)
{
    /* other values are scalar */
    return ((attr_id >= RF4CE_GDP_ATTR_ARRAYED1_RESERVED_MIN && attr_id <= RF4CE_GDP_ATTR_ARRAYED1_RESERVED_MAX) || (attr_id >= RF4CE_GDP_ATTR_ARRAYED2_RESERVED_MIN && attr_id <= RF4CE_GDP_ATTR_ARRAYED2_RESERVED_MAX));
}

static bool rf4ce_profile_is_zrc20_attr_arrayed(uint8_t attr_id)
{
    /* other values are scalar */
    return (attr_id == RF4CE_ZRC20_ATTR_ACTION_CODES_SUPPORTED_RX || attr_id == RF4CE_ZRC20_ATTR_ACTION_CODES_SUPPORTED_TX || attr_id == RF4CE_ZRC20_ATTR_MAPPABLE_ACTIONS || attr_id == RF4CE_ZRC20_ATTR_ACTION_MAPPINGS || attr_id == RF4CE_ZRC20_ATTR_HOME_AUTOMATION || attr_id == RF4CE_ZRC20_ATTR_HOME_AUTOMATION_SUPPORTED || (attr_id >= RF4CE_ZRC20_ATTR_ARRAYED1_MIN && attr_id <= RF4CE_ZRC20_ATTR_ARRAYED2_MAX));
}

static void dissect_rf4ce_profile_cmd_check_validation(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t sub_type = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_rf4ce_profile_cmd_check_validation_sub_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    if (sub_type == RF4CE_PROFILE_CMD_CHECK_VALIDATION_SUB_TYPE_REQ)
    {
        proto_tree_add_item(tree, hf_rf4ce_profile_cmd_check_validation_control, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }
    else if (sub_type == RF4CE_PROFILE_CMD_CHECK_VALIDATION_SUB_TYPE_RSP)
    {
        proto_tree_add_item(tree, hf_rf4ce_profile_cmd_check_validation_status, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }
}

static void dissect_rf4ce_profile_cmd_client_notification(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t sub_type = tvb_get_uint8(tvb, *offset);
    ;
    proto_tree_add_item(tree, hf_rf4ce_profile_cmd_client_notification_sub_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    if (sub_type == RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_IDENTIFY)
    {
        static int *const identify_bits[] = {
            &hf_rf4ce_profile_cmd_client_notification_identify_flags_stop_on_action,
            &hf_rf4ce_profile_cmd_client_notification_identify_flags_flash_light,
            &hf_rf4ce_profile_cmd_client_notification_identify_flags_make_sound,
            &hf_rf4ce_profile_cmd_client_notification_identify_flags_vibrate,
            &hf_rf4ce_profile_cmd_client_notification_identify_flags_reserved,
            NULL};

        proto_tree_add_bitmask(tree, tvb, *offset, hf_rf4ce_profile_cmd_client_notification_identify_flags, ett_rf4ce_profile_cmd_frame, identify_bits, ENC_LITTLE_ENDIAN);
        *offset += 1;

        proto_tree_add_item(tree, hf_rf4ce_profile_cmd_client_notification_identify_time, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }
    else if (sub_type == RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_REQ_HOME_AUTOMATION_PULL)
    {
        /* TODO: implement payload parsing */
    }
    else if (sub_type == RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_REQ_SELECTIVE_ACTION_MAPPING_UPDATE)
    {
        /* TODO: implement payload parsing */
    }
    else if (sub_type == RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_REQ_POLL_NEGOTIATION || sub_type == RF4CE_PROFILE_CMD_CL_NOTIF_SUB_TYPE_REQ_ACTION_MAPPING_NEGOTIATION)
    {
        /* No payload */
    }
}

static void dissect_rf4ce_profile_cmd_key_exchange(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset)
{
    uint8_t sub_type = tvb_get_uint8(tvb, *offset);

    proto_tree_add_item(tree, hf_rf4ce_profile_cmd_key_exchange_sub_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    if (sub_type == RF4CE_PROFILE_CMD_KEY_EXCHANGE_SUB_TYPE_CHALLENGE || sub_type == RF4CE_PROFILE_CMD_KEY_EXCHANGE_SUB_TYPE_CHALLENGE_RSP)
    {
        static int *const key_exchange_bits[] = {
            &hf_rf4ce_profile_cmd_key_exchange_flags_default_secret,
            &hf_rf4ce_profile_cmd_key_exchange_flags_initiator_vendor_specific_secret,
            &hf_rf4ce_profile_cmd_key_exchange_flags_responder_vendor_specific_secret,
            &hf_rf4ce_profile_cmd_key_exchange_flags_reserved,
            &hf_rf4ce_profile_cmd_key_exchange_flags_vendor_specific_parameter,
            NULL};

        proto_tree_add_bitmask(tree, tvb, *offset, hf_rf4ce_profile_cmd_key_exchange_flags, ett_rf4ce_profile_cmd_frame, key_exchange_bits, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }

    if (sub_type == RF4CE_PROFILE_CMD_KEY_EXCHANGE_SUB_TYPE_CHALLENGE)
    {
        uint8_t rand_a[RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH];
        uint8_t target_addr[RF4CE_IEEE_ADDR_LEN];

        proto_tree_add_item(tree, hf_rf4ce_profile_cmd_key_exchange_rand_a, tvb, *offset, RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH, ENC_NA);
        tvb_memcpy(tvb, (void *)rand_a, *offset, RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH);
        *offset += RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH;

        if (!key_exchange_context_is_procedure_started())
        {
            if (rf4ce_addr_table_get_ieee_addr(target_addr, pinfo, true))
            {
                key_exchange_context_init();

                key_exchange_context_set_rand_a(rand_a);
                key_exchange_context_set_mac_a(target_addr);

                key_exchange_context_start_procedure();
            }
        }
    }

    if (sub_type == RF4CE_PROFILE_CMD_KEY_EXCHANGE_SUB_TYPE_CHALLENGE_RSP)
    {
        uint8_t rand_b[RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH];
        uint32_t tag_b_pack;

        uint8_t controller_addr[RF4CE_IEEE_ADDR_LEN];

        proto_tree_add_item(tree, hf_rf4ce_profile_cmd_key_exchange_rand_b, tvb, *offset, RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_B_LENGTH, ENC_NA);
        tvb_memcpy(tvb, (void *)rand_b, *offset, RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH);
        *offset += RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_B_LENGTH;

        proto_tree_add_item(tree, hf_rf4ce_profile_cmd_key_exchange_tag_b, tvb, *offset, RF4CE_PROFILE_CMD_KEY_EXCHANGE_TAG_B_LENGTH, ENC_NA);
        tag_b_pack = tvb_get_uint32(tvb, *offset, ENC_LITTLE_ENDIAN);
        *offset += RF4CE_PROFILE_CMD_KEY_EXCHANGE_TAG_B_LENGTH;

        if (key_exchange_context_is_procedure_started())
        {
            if (rf4ce_addr_table_get_ieee_addr(controller_addr, pinfo, true))
            {
                key_exchange_context_set_rand_b(rand_b);
                key_exchange_context_set_mac_b(controller_addr);

                key_exchange_calc_key(tag_b_pack);
            }

            key_exchange_context_stop_procedure();
        }
    }

    if (sub_type == RF4CE_PROFILE_CMD_KEY_EXCHANGE_SUB_TYPE_RSP)
    {
        proto_tree_add_item(tree, hf_rf4ce_profile_cmd_key_exchange_tag_a, tvb, *offset, RF4CE_PROFILE_CMD_KEY_EXCHANGE_TAG_A_LENGTH, ENC_NA);
        *offset += RF4CE_PROFILE_CMD_KEY_EXCHANGE_TAG_A_LENGTH;
    }
}

static void dissect_rf4ce_profile_zrc10_cmd(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, uint8_t cmd_id)
{
    switch (cmd_id)
    {
    case RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_PRESSED:
        dissect_rf4ce_profile_zrc10_cmd_user_control_common(tvb, tree, offset, true);
        break;

    case RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_REPEATED:
        dissect_rf4ce_profile_zrc10_cmd_user_control_common(tvb, tree, offset, true);
        break;

    case RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_RELEASED:
        dissect_rf4ce_profile_zrc10_cmd_user_control_common(tvb, tree, offset, false);
        break;

    case RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_CMD_DISCOVERY_REQ:
        dissect_rf4ce_profile_zrc10_cmd_discovery_req(tvb, tree, offset);
        break;

    case RF4CE_ZRC10_FCF_CMD_ID_USER_CONTROL_CMD_DISCOVERY_RSP:
        dissect_rf4ce_profile_zrc10_cmd_discovery_rsp(tvb, tree, offset);
        break;
    }
}

static void dissect_rf4ce_profile_zrc10_cmd_user_control_common(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool parse_payload)
{
    proto_tree_add_item(tree, hf_rf4ce_zrc10_cmd_common_rc_command_code, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    if (parse_payload)
    {
        int remaining_length = tvb_reported_length_remaining(tvb, *offset);
        if (remaining_length > 0)
        {
            proto_tree_add_item(tree, hf_rf4ce_zrc10_cmd_common_rc_command_payload, tvb, *offset, remaining_length, ENC_NA);
            *offset += remaining_length;
        }
    }
}

static void dissect_rf4ce_profile_zrc10_cmd_discovery_req(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree_add_item(tree, hf_rf4ce_zrc10_cmd_disc_reserved, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
}

static void dissect_rf4ce_profile_zrc10_cmd_discovery_rsp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
  int remaining_length = tvb_reported_length_remaining(tvb, *offset);

  if (remaining_length > 0)
  {
    proto_tree_add_item(tree, hf_rf4ce_zrc10_cmd_disc_rsp_supported_commands, tvb, *offset, remaining_length, ENC_NA);
    *offset += remaining_length;
  }
}

static void dissect_rf4ce_profile_zrc20_cmd(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, uint8_t cmd_id)
{
    if (cmd_id == RF4CE_ZRC20_CMD_ACTIONS)
    {
        int remaining_length = tvb_reported_length_remaining(tvb, *offset);
        proto_tree *action_records_tree;

        if (remaining_length > 0)
        {
            action_records_tree = proto_tree_add_subtree(tree, tvb, *offset, remaining_length, ett_rf4ce_profile_action_records, NULL, "Action Records List");

            while (remaining_length > 0)
            {
                dissect_rf4ce_profile_zrc20_action_data(tvb, action_records_tree, offset, true /* dissect the Action Control field */);
                remaining_length = tvb_reported_length_remaining(tvb, *offset);
            }
        }
        else
        {
            proto_tree_add_subtree(tree, tvb, *offset, remaining_length, ett_rf4ce_profile_action_records, NULL, "Action Records List - empty");
        }
    }
}

static void dissect_rf4ce_profile_zrc20_action_data(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, bool dissect_action_control)
{
    char record_tree_name[10];
    proto_tree *record_tree;
    uint8_t payload_length;
    int remaining_length;
    int attr_counter = 1;

    snprintf(record_tree_name, sizeof(record_tree_name), "Record %d:", attr_counter);
    attr_counter++;

    record_tree = proto_tree_add_subtree(tree, tvb, *offset, tvb_reported_length_remaining(tvb, *offset), ett_rf4ce_profile_action_records_sub, NULL, record_tree_name);

    if (dissect_action_control)
    {
        static int *const action_control_bits[] = {
            &hf_rf4ce_zrc20_cmd_actions_action_control_action_type,
            &hf_rf4ce_zrc20_cmd_actions_action_control_reserved,
            &hf_rf4ce_zrc20_cmd_actions_action_control_modifier_bits_gui,
            &hf_rf4ce_zrc20_cmd_actions_action_control_modifier_bits_alt,
            &hf_rf4ce_zrc20_cmd_actions_action_control_modifier_bits_shift,
            &hf_rf4ce_zrc20_cmd_actions_action_control_modifier_bits_ctrl,
            NULL};

        proto_tree_add_bitmask(record_tree, tvb, *offset, hf_rf4ce_zrc20_cmd_actions_action_control, ett_rf4ce_profile_zrc20_action_control, action_control_bits, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }

    proto_tree_add_item(record_tree, hf_rf4ce_zrc20_cmd_actions_action_data_payload_length, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    payload_length = tvb_get_uint8(tvb, *offset);
    *offset += 1;

    proto_tree_add_item(record_tree, hf_rf4ce_zrc20_cmd_actions_action_data_action_bank, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    proto_tree_add_item(record_tree, hf_rf4ce_zrc20_cmd_actions_action_data_action_code, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    /* TODO: fix action_vendor parsing according to spec */
    remaining_length = tvb_reported_length_remaining(tvb, *offset);
    if (((payload_length > 0) && (remaining_length - payload_length == 3)) || ((payload_length == 0) && (remaining_length - payload_length == 2)))
    {
        proto_tree_add_item(record_tree, hf_rf4ce_zrc20_cmd_actions_action_data_action_vendor, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }

    if (payload_length > 0)
    {
        proto_tree_add_item(record_tree, hf_rf4ce_zrc20_cmd_actions_action_data_action_payload, tvb, *offset, payload_length, ENC_NA);
        *offset += payload_length;
    }
}
