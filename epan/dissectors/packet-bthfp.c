/* packet-bthfp.c
 * Routines for Bluetooth Handsfree Profile (HFP)
 *
 * Copyright 2002, Wolfgang Hansmann <hansmann@cs.uni-bonn.de>
 * Copyright 2006, Ronnie Sahlberg
 *     - refactored for Wireshark checkin
 * Copyright 2013, Michal Labedzki for Tieto Corporation
 *     - add reassembling
 *     - dissection of HFP's AT-commands
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
#include <epan/strutil.h>
#include "packet-btrfcomm.h"
#include "packet-btsdp.h"

static int proto_bthfp;

static int hf_command;
static int hf_parameters;
static int hf_role;
static int hf_at_cmd;
static int hf_at_cmd_type;
static int hf_at_command_line_prefix;
static int hf_at_ignored;
static int hf_parameter;
static int hf_unknown_parameter;
static int hf_data;
static int hf_fragment;
static int hf_fragmented;
static int hf_brsf_hs;
static int hf_brsf_hs_ec_nr_function;
static int hf_brsf_hs_call_waiting_or_tree_way;
static int hf_brsf_hs_cli_presentation;
static int hf_brsf_hs_voice_recognition_activation;
static int hf_brsf_hs_remote_volume_control;
static int hf_brsf_hs_enhanced_call_status;
static int hf_brsf_hs_enhanced_call_control;
static int hf_brsf_hs_codec_negotiation;
static int hf_brsf_hs_hf_indicators;
static int hf_brsf_hs_esco_s4_t2_settings_support;
static int hf_brsf_hs_reserved;
static int hf_brsf_ag;
static int hf_brsf_ag_three_way_calling;
static int hf_brsf_ag_ec_nr_function;
static int hf_brsf_ag_voice_recognition_function;
static int hf_brsf_ag_inband_ring_tone;
static int hf_brsf_ag_attach_number_to_voice_tag;
static int hf_brsf_ag_ability_to_reject_a_call;
static int hf_brsf_ag_enhanced_call_status;
static int hf_brsf_ag_enhanced_call_control;
static int hf_brsf_ag_extended_error_result_codes;
static int hf_brsf_ag_codec_negotiation;
static int hf_brsf_ag_hf_indicators;
static int hf_brsf_ag_esco_s4_t2_settings_support;
static int hf_brsf_ag_reserved;
static int hf_vgs;
static int hf_vgm;
static int hf_nrec;
static int hf_bvra_vrect;
static int hf_bsir;
static int hf_btrh;
static int hf_chld_mode;
static int hf_chld_mode_1x;
static int hf_chld_mode_2x;
static int hf_chld_supported_modes;
static int hf_cmer_mode;
static int hf_cmer_keyp;
static int hf_cmer_disp;
static int hf_cmer_ind;
static int hf_cmer_bfr;
static int hf_cmee;
static int hf_cme_error;
static int hf_cnum_speed;
static int hf_cnum_service;
static int hf_cnum_itc;
static int hf_bcs_codec;
static int hf_bac_codec;
static int hf_binp_request;
static int hf_binp_response;
static int hf_ciev_indicator_index;
static int hf_vts_dtmf;
static int hf_vts_duration;
static int hf_cops_mode;
static int hf_cops_format;
static int hf_cops_operator;
static int hf_cops_act;
static int hf_at_number;
static int hf_at_type;
static int hf_at_subaddress;
static int hf_at_subaddress_type;
static int hf_at_alpha;
static int hf_at_priority;
static int hf_at_cli_validity;
static int hf_clip_mode;
static int hf_clip_status;
static int hf_clcc_id;
static int hf_clcc_dir;
static int hf_clcc_stat;
static int hf_clcc_mode;
static int hf_clcc_mpty;
static int hf_ccwa_show_result_code;
static int hf_ccwa_mode;
static int hf_ccwa_class;
static int hf_biev_assigned_number;
static int hf_biev_value;
static int hf_bind_parameter;
static int hf_bia_indicator[20];
static int hf_indicator[20];
static int hf_aplefm_state;
static int hf_aplsiri_state;
static int hf_iphoneaccev_count;
static int hf_iphoneaccev_key;
static int hf_iphoneaccev_value;
static int hf_xapl_accessory_info;
static int hf_xapl_accessory_info_vendor_id;
static int hf_xapl_accessory_info_product_id;
static int hf_xapl_accessory_info_version;
static int hf_xapl_host_info;
static int hf_xapl_features;
static int hf_xapl_features_reserved_x;
static int hf_xapl_features_noise_reduction_status_reporting;
static int hf_xapl_features_siri_status_reporting;
static int hf_xapl_features_docked_or_powered;
static int hf_xapl_features_battery_reporting;
static int hf_xapl_features_reserved;

static expert_field ei_non_mandatory_command;
static expert_field ei_invalid_usage;
static expert_field ei_unknown_parameter;
static expert_field ei_brfs_hs_reserved_bits;
static expert_field ei_brfs_ag_reserved_bits;
static expert_field ei_vgm_gain;
static expert_field ei_vgs_gain;
static expert_field ei_nrec;
static expert_field ei_bvra;
static expert_field ei_bcs;
static expert_field ei_bac;
static expert_field ei_bsir;
static expert_field ei_btrh;
static expert_field ei_binp;
static expert_field ei_biev_assigned_number;
static expert_field ei_biev_assigned_number_no;
static expert_field ei_bia;
static expert_field ei_cmer_mode;
static expert_field ei_cmer_keyp;
static expert_field ei_cmer_disp;
static expert_field ei_cmer_ind;
static expert_field ei_cmer_btr;
static expert_field ei_chld_mode;
static expert_field ei_ciev_indicator;
static expert_field ei_vts_dtmf;
static expert_field ei_at_type;
static expert_field ei_cnum_service;
static expert_field ei_cnum_itc;
static expert_field ei_aplefm_out_of_range;
static expert_field ei_aplsiri_out_of_range;
static expert_field ei_iphoneaccev_key_out_of_range;
static expert_field ei_xapl_features_reserved;
static expert_field ei_parameter_blank;

static int ett_bthfp;
static int ett_bthfp_command;
static int ett_bthfp_parameters;
static int ett_bthfp_brsf_hf;
static int ett_bthfp_brsf_ag;
static int ett_bthfp_xapl_features;
static int ett_bthfp_xapl_accessory_info;

static dissector_handle_t bthfp_handle;

static wmem_tree_t *fragments;

#define ROLE_UNKNOWN  0
#define ROLE_AG       1
#define ROLE_HS       2

#define TYPE_UNKNOWN       0x0000
#define TYPE_RESPONSE_ACK  0x0d0a
#define TYPE_RESPONSE      0x003a
#define TYPE_ACTION        0x003d
#define TYPE_ACTION_SIMPLY 0x000d
#define TYPE_READ          0x003f
#define TYPE_TEST          0x3d3f

static int hfp_role = ROLE_UNKNOWN;

enum reassemble_state_t {
    REASSEMBLE_FRAGMENT,
    REASSEMBLE_PARTIALLY,
    REASSEMBLE_DONE
};

typedef struct _fragment_t {
    uint32_t                 interface_id;
    uint32_t                 adapter_id;
    uint32_t                 chandle;
    uint32_t                 dlci;
    uint32_t                 role;

    unsigned                 idx;
    unsigned                 length;
    uint8_t                 *data;
    struct _fragment_t      *previous_fragment;

    unsigned                 reassemble_start_offset;
    unsigned                 reassemble_end_offset;
    enum reassemble_state_t  reassemble_state;
} fragment_t;

typedef struct _at_cmd_t {
    const char *name;
    const char *long_name;

    bool (*check_command)(int role, uint16_t type);
    bool (*dissect_parameter)(tvbuff_t *tvb, packet_info *pinfo,
            proto_tree *tree, int offset, int role, uint16_t type,
            uint8_t *parameter_stream, unsigned parameter_number,
            int parameter_length, void **data);
} at_cmd_t;

static const value_string role_vals[] = {
    { ROLE_UNKNOWN,   "Unknown" },
    { ROLE_AG,        "AG - Audio Gate" },
    { ROLE_HS,        "HS - Headset" },
    { 0, NULL }
};

static const value_string at_cmd_type_vals[] = {
    { 0x0d,   "Action Command" },
    { 0x3a,   "Response" },
    { 0x3d,   "Action Command" },
    { 0x3f,   "Read Command" },
    { 0x0d0a, "Response" },
    { 0x3d3f, "Test Command" },
    { 0, NULL }
};

static const enum_val_t pref_hfp_role[] = {
    { "off",     "Off",                    ROLE_UNKNOWN },
    { "ag",      "Sent is AG, Rcvd is HS", ROLE_AG },
    { "hs",      "Sent is HS, Rcvd is AG", ROLE_HS },
    { NULL, NULL, 0 }
};

static const value_string nrec_vals[] = {
    { 0x00,   "Disable EC/NR in the AG" },
    { 0, NULL }
};

static const value_string bvra_vrect_vals[] = {
    { 0x00,   "Disable Voice recognition in the AG" },
    { 0x01,   "Enable Voice recognition in the AG" },
    { 0, NULL }
};

static const value_string bsir_vals[] = {
    { 0x00,   "The AG provides no in-band ring tone" },
    { 0x01,   "The AG provides an in-band ring tone" },
    { 0, NULL }
};

static const value_string btrh_vals[] = {
    { 0x00,   "Incoming call is put on hold in the AG" },
    { 0x01,   "Held incoming call is accepted in the AG" },
    { 0x02,   "Held incoming call is rejected in the AG" },
    { 0, NULL }
};

static const value_string codecs_vals[] = {
    { 0x01,   "CVSD" },
    { 0x02,   "mSBC" },
    { 0, NULL }
};

static const value_string binp_request_vals[] = {
    { 0x01,   "Phone number corresponding to the last voice tag recorded in the HF" },
    { 0, NULL }
};

static const value_string indicator_vals[] = {
    { 0x00,   "Deactivate" },
    { 0x01,   "Activate" },
    { 0, NULL }
};

static const value_string cme_error_vals[] = {
    {   0,   "Phone/AG failure" },
    {   1,   "No Connection to Phone" },
    {   2,   "Phone-adaptor Link Reserved" },
    {   3,   "Operation not Allowed" },
    {   4,   "Operation not Supported" },
    {   5,   "PH-SIM PIN required" },
    {   6,   "PH-FSIM PIN Required" },
    {   7,   "PH-FSIM PUK Required" },
    {  10,   "SIM not Inserted" },
    {  11,   "SIM PIN Required" },
    {  12,   "SIM PUK Required" },
    {  13,   "SIM Failure" },
    {  14,   "SIM Busy" },
    {  15,   "SIM Wrong" },
    {  16,   "Incorrect Password" },
    {  17,   "SIM PIN2 Required" },
    {  18,   "SIM PUK2 Required" },
    {  20,   "Memory Full" },
    {  21,   "Invalid Index" },
    {  22,   "Not Found" },
    {  23,   "Memory Failure" },
    {  24,   "Text String too Long" },
    {  25,   "Invalid Characters in Text String" },
    {  26,   "Dial String too Long" },
    {  27,   "Invalid Characters in Dial String" },
    {  30,   "No Network Service" },
    {  31,   "Network Timeout" },
    {  32,   "Network not Allowed - Emergency Calls Only" },
    {  40,   "Network Personalization PIN Required" },
    {  41,   "Network Personalization PUK Required" },
    {  42,   "Network Subset Personalization PIN Required" },
    {  43,   "Network Subset Personalization PUK Required" },
    {  44,   "Service Provider Personalization PIN Required" },
    {  45,   "Service Provider Personalization PUK Required" },
    {  46,   "Corporate Personalization PIN Required" },
    {  47,   "Corporate Personalization PUK Required" },
    {  48,   "Hidden Key Required" },
    {  49,   "EAP Method not Supported" },
    {  50,   "Incorrect Parameters" },
    { 100,   "Unknown" },
    { 0, NULL }
};

static const value_string cmee_vals[] = {
    { 0,   "Disabled" },
    { 1,   "Enabled" },
    { 2,   "Verbose" },
    { 0, NULL }
};

static const value_string chld_vals[] = {
    { 0,   "Releases all held calls or sets User Determined User Busy (UDUB) for a waiting call" },
    { 1,   "Releases all active calls (if any exist) and accepts the other (held or waiting) call" },
    { 2,   "Places all active calls (if any exist) on hold and accepts the other (held or waiting) call" },
    { 3,   "Adds a held call to the conversation" },
    { 4,   "Connects the two calls and disconnects the subscriber from both calls (Explicit Call Transfer)" },
    { 0, NULL }
};

static const value_string cops_mode_vals[] = {
    { 0,   "Automatic" },
    { 1,   "Manual" },
    { 2,   "Deregister from Network" },
    { 3,   "Set Only Format" },
    { 4,   "Manual/Automatic" },
    { 0, NULL }
};

static const value_string cops_format_vals[] = {
    { 0,   "Long Format Alphanumeric" },
    { 1,   "Short Format Alphanumeric" },
    { 2,   "Numeric" },
    { 0, NULL }
};

static const value_string cops_act_vals[] = {
    { 0,   "GSM" },
    { 1,   "GSM Compact" },
    { 2,   "UTRAN" },
    { 0, NULL }
};

static const range_string at_type_vals[] = {
    { 128, 143,  "The phone number format may be a national or international format, and may contain prefix and/or escape digits. No changes on the number presentation are required." },
    { 144, 159,  "The phone number format is an international number, including the country code prefix. If the plus sign (\"+\") is not included as part of the number and shall be added by the AG as needed." },
    { 160, 175,  "National number. No prefix nor escape digits included." },
    { 0, 0, NULL }
};

static const value_string cli_validity_vals[] = {
    { 0,   "CLI Valid" },
    { 1,   "CLI has been withheld by the originator" },
    { 2,   "CLI is not available due to interworking problems or limitations of originating network" },
    { 0, NULL }
};

static const value_string cnum_service_vals[] = {
    { 0,   "Asynchronous Modem" },
    { 1,   "Synchronous Modem" },
    { 2,   "PAD Access" },
    { 3,   "Packet Access" },
    { 4,   "Voice" },
    { 5,   "Fax" },
    { 0, NULL }
};

static const value_string cnum_itc_vals[] = {
    { 0,   "3.1 kHz" },
    { 1,   "UDI" },
    { 0, NULL }
};

static const value_string clip_mode_vals[] = {
    { 0,   "Disabled" },
    { 1,   "Enabled" },
    { 0, NULL }
};

static const value_string clip_status_vals[] = {
    { 0,   "CLIP not Provisioned" },
    { 1,   "CLIP Provisioned" },
    { 2,   "Unknown" },
    { 0, NULL }
};

static const value_string clcc_dir_vals[] = {
    { 0,   "Mobile Originated" },
    { 1,   "Mobile Terminated" },
    { 0, NULL }
};

static const value_string clcc_stat_vals[] = {
    { 0,   "Active" },
    { 1,   "Held" },
    { 2,   "Dialing" },
    { 3,   "Alerting" },
    { 4,   "Incoming" },
    { 5,   "Waiting" },
    { 0, NULL }
};

static const value_string clcc_mode_vals[] = {
    { 0,   "Voice" },
    { 1,   "Data" },
    { 2,   "Fax" },
    { 3,   "Voice Followed by Data, Voice Mode" },
    { 4,   "Alternating Voice/Data, Voice Mode" },
    { 5,   "Alternating Voice/Fax, Voice Mode" },
    { 6,   "Voice Followed by Data, Data Mode" },
    { 7,   "Alternating Voice/Data, Data Mode" },
    { 8,   "Alternating Voice/Fax, Fax Mode" },
    { 9,   "Unknown" },
    { 0, NULL }
};

static const value_string clcc_mpty_vals[] = {
    { 0,   "Call is not one of multiparty (conference) call parties" },
    { 1,   "Call is one of multiparty (conference) call parties" },
    { 0, NULL }
};

static const value_string ccwa_show_result_code_vals[] = {
    { 0,   "Disabled" },
    { 1,   "Enabled" },
    { 0, NULL }
};

static const value_string ccwa_mode_vals[] = {
    { 0,   "Disabled" },
    { 1,   "Enabled" },
    { 2,   "Query Status" },
    { 0, NULL }
};

static const value_string ccwa_class_vals[] = {
    {   1,   "Voice" },
    {   2,   "Data" },
    {   4,   "Fax" },
    {   8,   "Short Message Service" },
    {  16,   "Data Circuit Sync" },
    {  32,   "Data Circuit Async" },
    {  64,   "Dedicated Packet Access" },
    { 128,   "Dedicated PAD Access" },
    { 0, NULL }
};

static const value_string biev_assigned_number_vals[] = {
    { 1,   "Enhanced Safety" },
    { 2,   "Battery Level" },
    { 0, NULL }
};

static const value_string aplefm_state_vals[] = {
    { 0,   "Disable" },
    { 1,   "Enable" },
    { 0, NULL }
};

static const value_string aplsiri_state_vals[] = {
    { 1,   "Enabled" },
    { 2,   "Disabled" },
    { 0, NULL }
};

static const value_string iphoneaccev_key_vals[] = {
    { 1,   "Battery Level" },
    { 2,   "Dock State" },
    { 0, NULL }
};


static const unit_name_string units_slash15 = { "/15", NULL };

extern value_string_ext csd_data_rate_vals_ext;

void proto_register_bthfp(void);
void proto_reg_handoff_bthfp(void);

static uint32_t get_uint_parameter(uint8_t *parameter_stream, int parameter_length)
{
    uint32_t     value;
    char        *val;

    val = (char *) wmem_alloc(wmem_packet_scope(), parameter_length + 1);
    memcpy(val, parameter_stream, parameter_length);
    val[parameter_length] = '\0';
    value = (uint32_t) g_ascii_strtoull(val, NULL, 10);

    return value;
}

static uint32_t get_uint_hex_parameter(uint8_t *parameter_stream, int parameter_length)
{
    uint32_t     value;
    char        *val;

    val = (char *) wmem_alloc(wmem_packet_scope(), parameter_length + 1);
    memcpy(val, parameter_stream, parameter_length);
    val[parameter_length] = '\0';
    value = (uint32_t) g_ascii_strtoull(val, NULL, 16);

    return value;
}

static bool check_aplefm(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_aplsiri(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_READ) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_iphoneaccev(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;

    return false;
}

static bool check_xapl(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;
    if (role == ROLE_AG && (type == TYPE_RESPONSE || type == TYPE_ACTION)) return true;

    return false;
}

static bool check_biev(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;

    return false;
}

static bool check_bind(int role, uint16_t type) {
    if (role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_READ || type == TYPE_TEST)) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_bac(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;

    return false;
}

static bool check_bcs(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_bcc(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION_SIMPLY) return true;

    return false;
}

static bool check_bia(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;

    return false;
}

static bool check_binp(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_bldn(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION_SIMPLY) return true;

    return false;
}

static bool check_bvra(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_brsf(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_nrec(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;

    return false;
}

static bool check_vgs(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_vgm(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_bsir(int role, uint16_t type) {
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_btrh(int role, uint16_t type) {
    if (role == ROLE_HS && (type == TYPE_READ || type == TYPE_ACTION)) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_only_ag_role(int role, uint16_t type) {
    if (role == ROLE_AG && type == TYPE_RESPONSE_ACK) return true;

    return false;
}

static bool check_only_hs_role(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION_SIMPLY) return true;

    return false;
}

static bool check_ccwa(int role, uint16_t type) {
    if (role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_READ || type == TYPE_TEST)) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_chld(int role, uint16_t type) {
    if (role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_TEST)) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_chup(int role, uint16_t type) {
    if (role == ROLE_HS && (type == TYPE_ACTION_SIMPLY || type == TYPE_TEST)) return true;

    return false;
}

static bool check_clcc(int role, uint16_t type) {
    if (role == ROLE_HS && (type == TYPE_ACTION_SIMPLY || type == TYPE_TEST)) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_cind(int role, uint16_t type) {
    if (role == ROLE_HS && (type == TYPE_READ || type == TYPE_TEST)) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_cmer(int role, uint16_t type) {
    if (role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_READ || type == TYPE_TEST)) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_cops(int role, uint16_t type) {
    if (role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_READ)) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_cmee(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return true;

    return false;
}

static bool check_cme(int role, uint16_t type) {
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_clip(int role, uint16_t type) {
    if (role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_READ || type == TYPE_TEST)) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_ciev(int role, uint16_t type) {
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_vts(int role, uint16_t type) {
    if (role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_TEST)) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool check_cnum(int role, uint16_t type) {
    if (role == ROLE_HS && type == TYPE_ACTION_SIMPLY) return true;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return true;

    return false;
}

static bool
dissect_brsf_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return false;
    }

    if (parameter_number > 0) return false;

    value = get_uint_parameter(parameter_stream, parameter_length);

    if (role == ROLE_HS) {
        static int * const hs[] = {
            &hf_brsf_hs_ec_nr_function,
            &hf_brsf_hs_call_waiting_or_tree_way,
            &hf_brsf_hs_cli_presentation,
            &hf_brsf_hs_voice_recognition_activation,
            &hf_brsf_hs_remote_volume_control,
            &hf_brsf_hs_enhanced_call_status,
            &hf_brsf_hs_enhanced_call_control,
            &hf_brsf_hs_codec_negotiation,
            &hf_brsf_hs_hf_indicators,
            &hf_brsf_hs_esco_s4_t2_settings_support,
            &hf_brsf_hs_reserved,
            NULL
        };

        pitem = proto_tree_add_bitmask_value_with_flags(tree, tvb, offset, hf_brsf_hs, ett_bthfp_brsf_hf, hs, value, BMT_NO_APPEND);
        if (value >> 10) {
            expert_add_info(pinfo, pitem, &ei_brfs_hs_reserved_bits);
        }
    } else {
        static int * const ag[] = {
            &hf_brsf_ag_three_way_calling,
            &hf_brsf_ag_ec_nr_function,
            &hf_brsf_ag_voice_recognition_function,
            &hf_brsf_ag_inband_ring_tone,
            &hf_brsf_ag_attach_number_to_voice_tag,
            &hf_brsf_ag_ability_to_reject_a_call,
            &hf_brsf_ag_enhanced_call_status,
            &hf_brsf_ag_enhanced_call_control,
            &hf_brsf_ag_extended_error_result_codes,
            &hf_brsf_ag_codec_negotiation,
            &hf_brsf_ag_hf_indicators,
            &hf_brsf_ag_esco_s4_t2_settings_support,
            &hf_brsf_ag_reserved,
            NULL
        };

        pitem = proto_tree_add_bitmask_value_with_flags(tree, tvb, offset, hf_brsf_ag, ett_bthfp_brsf_ag, ag, value, BMT_NO_APPEND);

        if (value >> 12) {
            expert_add_info(pinfo, pitem, &ei_brfs_ag_reserved_bits);
        }
    }

    return true;
}

static bool
dissect_vgs_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return false;
    }

    if (parameter_number > 0) return false;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_vgs, tvb, offset, parameter_length, value);

    if (value > 15) {
        expert_add_info(pinfo, pitem, &ei_vgs_gain);
    }

    return true;
}

static bool
dissect_vgm_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return false;
    }

    if (parameter_number > 0) return false;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_vgm, tvb, offset, parameter_length, value);

    if (value > 15) {
        expert_add_info(pinfo, pitem, &ei_vgm_gain);
    }

    return true;
}

static bool
dissect_nrec_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return false;
    }

    if (parameter_number > 0) return false;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_nrec, tvb, offset, parameter_length, value);

    if (value != 0) {
        expert_add_info(pinfo, pitem, &ei_nrec);
    }

    return true;
}

static bool
dissect_bvra_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return false;
    }

    if (parameter_number > 0) return false;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_bvra_vrect, tvb, offset, parameter_length, value);

    if (value > 1) {
        expert_add_info(pinfo, pitem, &ei_bvra);
    }

    return true;
}

static bool
dissect_bcs_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!check_bcs(role, type)) {
        return false;
    }

    if (parameter_number > 0) return false;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_bcs_codec, tvb, offset, parameter_length, value);

    if (value <  1 ||  value > 2) {
        expert_add_info(pinfo, pitem, &ei_bcs);
    }

    return true;
}

static bool
dissect_bac_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number _U_, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!check_bac(role, type)) {
        return false;
    }

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_bac_codec, tvb, offset, parameter_length, value);

    if (value <  1 ||  value > 2)  {
        expert_add_info(pinfo, pitem, &ei_bac);
    }

    return true;
}

static bool
dissect_bind_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    uint32_t     value;

    if (!check_bind(role, type)) return false;

/* TODO Need to implement request-response tracking to recognise answer to AT+BIND? vs unsolicited */
    if (parameter_number < 20) {
        value = get_uint_parameter(parameter_stream, parameter_length);

        proto_tree_add_uint(tree, hf_bind_parameter, tvb, offset,
                parameter_length, value);

        return true;
    }

    return false;
}

static bool
dissect_aplefm_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!check_aplefm(role, type)) return false;

    if (parameter_number == 0) {
        value = get_uint_parameter(parameter_stream, parameter_length);

        pitem = proto_tree_add_uint(tree, hf_aplefm_state, tvb, offset,
                parameter_length, value);

        if (value > 1) {
            expert_add_info(pinfo, pitem, &ei_aplefm_out_of_range);
        }
    } else return false;

    return true;
}

static bool
dissect_aplsiri_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!check_aplsiri(role, type)) return false;

    if (parameter_number == 0) {
        value = get_uint_parameter(parameter_stream, parameter_length);

        pitem = proto_tree_add_uint(tree, hf_aplsiri_state, tvb, offset,
                parameter_length, value);

        if (value < 1 || value > 2) {
            expert_add_info(pinfo, pitem, &ei_aplsiri_out_of_range);
        }
    } else return false;

    return true;
}

static bool
dissect_iphoneaccev_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!check_iphoneaccev(role, type)) return false;

    if (parameter_number == 0) {
        value = get_uint_parameter(parameter_stream, parameter_length);

        proto_tree_add_uint(tree, hf_iphoneaccev_count, tvb, offset,
                parameter_length, value);
    } else if (parameter_number % 2 == 1) {
        value = get_uint_parameter(parameter_stream, parameter_length);

        pitem = proto_tree_add_uint(tree, hf_iphoneaccev_key, tvb, offset,
                parameter_length, value);

        if (value < 1 || value > 2) {
            expert_add_info(pinfo, pitem, &ei_iphoneaccev_key_out_of_range);
        }
    } else {
        value = get_uint_parameter(parameter_stream, parameter_length);

        proto_tree_add_uint(tree, hf_iphoneaccev_value, tvb, offset,
                parameter_length, value);
    }

    return true;
}

static bool
dissect_xapl_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    proto_tree  *ptree;
    uint32_t     value;

    if (!check_xapl(role, type)) return false;

    if (parameter_number == 0) {
        if (role == ROLE_HS) {
            pitem = proto_tree_add_item(tree, hf_xapl_accessory_info, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
            ptree = proto_item_add_subtree(pitem, ett_bthfp_xapl_accessory_info);

            value = get_uint_hex_parameter(parameter_stream + (4 + 1) * 0, 4);
            proto_tree_add_uint(ptree, hf_xapl_accessory_info_vendor_id, tvb, offset, 4, value);

            value = get_uint_hex_parameter(parameter_stream + (4 + 1) * 1, 4);
            proto_tree_add_uint(ptree, hf_xapl_accessory_info_product_id, tvb, offset + (4 + 1) * 1, 4, value);

            value = get_uint_hex_parameter(parameter_stream + (4 + 1) * 2, 4);
            proto_tree_add_uint(ptree, hf_xapl_accessory_info_version, tvb, offset + (4 + 1) * 2, 4, value);
        } else {
            proto_tree_add_item(tree, hf_xapl_host_info, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
        }
    } else if (parameter_number == 1) {
        static int * const hfx[] = {
            &hf_xapl_features_reserved_x,
            &hf_xapl_features_noise_reduction_status_reporting,
            &hf_xapl_features_siri_status_reporting,
            &hf_xapl_features_docked_or_powered,
            &hf_xapl_features_battery_reporting,
            &hf_xapl_features_reserved,
            NULL
        };

        value = get_uint_parameter(parameter_stream, parameter_length);

        pitem = proto_tree_add_bitmask_value_with_flags(tree, tvb, offset, hf_xapl_features, ett_bthfp_xapl_features, hfx, value, BMT_NO_APPEND);

        if (value >> 5) {
            expert_add_info(pinfo, pitem, &ei_xapl_features_reserved);
        }
    } else return false;

    return true;
}

static bool
dissect_biev_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!check_biev(role, type)) return false;
    if (parameter_number == 0) {
        value = get_uint_parameter(parameter_stream, parameter_length);

        pitem = proto_tree_add_uint(tree, hf_biev_assigned_number, tvb, offset,
                parameter_length, value);

        if (value > 65535) {
            expert_add_info(pinfo, pitem, &ei_biev_assigned_number);
        } else if (value > 2) {
            expert_add_info(pinfo, pitem, &ei_biev_assigned_number_no);
        }
    } else if (parameter_number == 1) {
        value = get_uint_parameter(parameter_stream, parameter_length);
/* TODO: Decode assigned numbers - assigned_number=1 */
        /*pitem =*/ proto_tree_add_uint(tree, hf_biev_value, tvb, offset,
                parameter_length, value);
    } else return false;

    return true;
}

static bool
dissect_no_parameter(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_,
        int offset _U_, int role _U_, uint16_t type _U_, uint8_t *parameter_stream _U_,
        unsigned parameter_number _U_, int parameter_length _U_, void **data _U_)
{
    return false;
}

static bool
dissect_bsir_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!(role == ROLE_AG && type == TYPE_RESPONSE)) {
        return false;
    }

    if (parameter_number > 0) return false;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_bsir, tvb, offset, parameter_length, value);

    if (value > 1) {
        expert_add_info(pinfo, pitem, &ei_bsir);
    }

    return true;
}

static bool
dissect_btrh_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return false;
    }

    if (parameter_number > 0) return false;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_btrh, tvb, offset, parameter_length, value);

    if (value != 0) {
        expert_add_info(pinfo, pitem, &ei_btrh);
    }

    return true;
}


static bool
dissect_binp_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return false;
    }

    if (role == ROLE_HS && type == TYPE_ACTION) {
        if (parameter_number == 0) {
            value = get_uint_parameter(parameter_stream, parameter_length);

            pitem = proto_tree_add_uint(tree, hf_binp_request, tvb, offset,
                    parameter_length, value);

            if (value != 1) {
                expert_add_info(pinfo, pitem, &ei_binp);
            }
        } else return false;
    } else {
        proto_tree_add_item(tree, hf_binp_response, tvb, offset,
                parameter_length, ENC_NA | ENC_ASCII);
    }
    return true;
}

static bool
dissect_bia_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!((role == ROLE_HS && type == TYPE_ACTION))) return false;
    if (parameter_number > 19) return false;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_bia_indicator[parameter_number], tvb,
            offset, parameter_length, value);
    if (value > 1) {
        expert_add_info(pinfo, pitem, &ei_bia);
    }

    return true;
}

static bool
dissect_cind_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream _U_,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    if (!check_cind(role, type)) return false;
    if (parameter_number > 19) return false;

    proto_tree_add_item(tree, hf_indicator[parameter_number], tvb, offset,
            parameter_length, ENC_NA | ENC_ASCII);

    return true;
}

static bool
dissect_chld_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    uint32_t     value;

    if (!check_chld(role, type)) return false;

    if (role == ROLE_HS && type == TYPE_ACTION && parameter_number == 0) {
        value = get_uint_parameter(parameter_stream, 1);

        if (parameter_length >= 2) {
            if (tvb_get_uint8(tvb, offset + 1) == 'x') {
                if (value == 1)
                    proto_tree_add_item(tree, hf_chld_mode_1x, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
                else if (value == 2)
                    proto_tree_add_item(tree, hf_chld_mode_2x, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
            }

            if (tvb_get_uint8(tvb, offset + 1) != 'x' || value > 4) {
                proto_tree_add_expert(tree, pinfo, &ei_chld_mode, tvb, offset, parameter_length);
            }
        }

        proto_tree_add_uint(tree, hf_chld_mode, tvb, offset, parameter_length, value);
        return true;
    }

    /* Type == Test  */
    proto_tree_add_item(tree, hf_chld_supported_modes, tvb, offset,
            parameter_length, ENC_NA | ENC_ASCII);

    return true;
}

static bool
dissect_ccwa_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!check_ccwa(role, type)) return false;

    if (role == ROLE_HS && parameter_number > 2) return false;
    if (role == ROLE_AG && parameter_number > 7) return false;

    if (role == ROLE_HS) switch (parameter_number) {
        case 0:
            value = get_uint_parameter(parameter_stream, parameter_length);
            proto_tree_add_uint(tree, hf_ccwa_show_result_code, tvb, offset, parameter_length, value);
            break;
        case 1:
            value = get_uint_parameter(parameter_stream, parameter_length);
            proto_tree_add_uint(tree, hf_ccwa_mode, tvb, offset, parameter_length, value);
            break;
        case 2:
            value = get_uint_parameter(parameter_stream, parameter_length);
            proto_tree_add_uint(tree, hf_ccwa_class, tvb, offset, parameter_length, value);
            break;
    }

    /* If AT+CCWA = 1 */
    if (role == ROLE_AG) switch (parameter_number) {
        case 0:
            proto_tree_add_item(tree, hf_at_number, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
            break;
        case 1:
            value = get_uint_parameter(parameter_stream, parameter_length);
            pitem = proto_tree_add_uint(tree, hf_at_type, tvb, offset, parameter_length, value);
            if (value < 128 || value > 175)
                expert_add_info(pinfo, pitem, &ei_at_type);
            break;
        case 2:
            value = get_uint_parameter(parameter_stream, parameter_length);
            proto_tree_add_uint(tree, hf_ccwa_class, tvb, offset, parameter_length, value);
            break;
        case 3:
            proto_tree_add_item(tree, hf_at_alpha, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
            break;
        case 4:
            value = get_uint_parameter(parameter_stream, parameter_length);
            proto_tree_add_uint(tree, hf_at_cli_validity, tvb, offset, parameter_length, value);
            break;
        case 5:
            proto_tree_add_item(tree, hf_at_subaddress, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
            break;
        case 6:
            value = get_uint_parameter(parameter_stream, parameter_length);
            proto_tree_add_uint(tree, hf_at_subaddress_type, tvb, offset, parameter_length, value);
            break;
        case 7:
            value = get_uint_parameter(parameter_stream, parameter_length);
            proto_tree_add_uint(tree, hf_at_priority, tvb, offset, parameter_length, value);
            break;
    }

    return true;
}

static bool
dissect_cmer_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!((role == ROLE_HS && type == TYPE_ACTION))) {
        return false;
    }

    if (parameter_number > 4) return false;

    value = get_uint_parameter(parameter_stream, parameter_length);

    switch (parameter_number) {
        case 0:
            pitem = proto_tree_add_uint(tree, hf_cmer_mode, tvb, offset, parameter_length, value);
            if (value != 3)
                expert_add_info(pinfo, pitem, &ei_cmer_mode);
            break;
        case 1:
            pitem = proto_tree_add_uint(tree, hf_cmer_keyp, tvb, offset, parameter_length, value);
            if (value != 0)
                expert_add_info(pinfo, pitem, &ei_cmer_keyp);
            break;
        case 2:
            pitem = proto_tree_add_uint(tree, hf_cmer_disp, tvb, offset, parameter_length, value);
            if (value != 0)
                expert_add_info(pinfo, pitem, &ei_cmer_disp);
            break;
        case 3:
            pitem = proto_tree_add_uint(tree, hf_cmer_ind, tvb, offset, parameter_length, value);
            if (value > 1)
                expert_add_info(pinfo, pitem, &ei_cmer_ind);
            break;
        case 4:
            pitem = proto_tree_add_uint(tree, hf_cmer_bfr, tvb, offset, parameter_length, value);
            if (value != 0)
                expert_add_info(pinfo, pitem, &ei_cmer_btr);
            break;
    }

    return true;
}

static bool
dissect_clip_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!check_clip(role, type))
        return false;

    if (role == ROLE_HS && type == TYPE_ACTION && parameter_number > 1)
        return false;
    else if (role == ROLE_AG && parameter_number > 5)
        return false;

    if (role == ROLE_HS && type == TYPE_ACTION) switch (parameter_number) {
        case 0:
            value = get_uint_parameter(parameter_stream, parameter_length);
            proto_tree_add_uint(tree, hf_clip_mode, tvb, offset, parameter_length, value);
            break;
        case 1:
            value = get_uint_parameter(parameter_stream, parameter_length);
            proto_tree_add_uint(tree, hf_clip_status, tvb, offset, parameter_length, value);
            break;
    } else {
        switch (parameter_number) {
        case 0:
            proto_tree_add_item(tree, hf_at_number, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
            break;
        case 1:
            value = get_uint_parameter(parameter_stream, parameter_length);
            pitem = proto_tree_add_uint(tree, hf_at_type, tvb, offset, parameter_length, value);
            if (value < 128 || value > 175)
                expert_add_info(pinfo, pitem, &ei_at_type);
            break;
        case 2:
            proto_tree_add_item(tree, hf_at_subaddress, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
            break;
        case 3:
            value = get_uint_parameter(parameter_stream, parameter_length);
            proto_tree_add_uint(tree, hf_at_subaddress_type, tvb, offset, parameter_length, value);
            break;
        case 4:
            proto_tree_add_item(tree, hf_at_alpha, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
            break;
        case 5:
            value = get_uint_parameter(parameter_stream, parameter_length);
            proto_tree_add_uint(tree, hf_at_cli_validity, tvb, offset, parameter_length, value);
            break;
        }
    }

    return true;
}

static bool
dissect_cmee_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    uint32_t     value;

    if (!(role == ROLE_HS && type == TYPE_ACTION)) {
        return false;
    }

    if (parameter_number > 0) return false;

    value = get_uint_parameter(parameter_stream, parameter_length);
    proto_tree_add_uint(tree, hf_cmee, tvb, offset, parameter_length, value);

    return true;
}

static bool
dissect_cops_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    uint32_t     value;

    if (!((role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_READ)) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return false;
    }

    if (parameter_number > 3) return false;

    switch (parameter_number) {
    case 0:
        value = get_uint_parameter(parameter_stream, parameter_length);
        proto_tree_add_uint(tree, hf_cops_mode, tvb, offset, parameter_length, value);
        break;
    case 1:
        value = get_uint_parameter(parameter_stream, parameter_length);
        proto_tree_add_uint(tree, hf_cops_format, tvb, offset, parameter_length, value);
        break;
    case 2:
        proto_tree_add_item(tree, hf_cops_operator, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
        break;
    case 3:
        value = get_uint_parameter(parameter_stream, parameter_length);
        proto_tree_add_uint(tree, hf_cops_act, tvb, offset, parameter_length, value);
        break;
    }

    return true;
}

static bool
dissect_clcc_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!((role == ROLE_HS && type == TYPE_ACTION_SIMPLY) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return false;
    }

    if (parameter_number > 8) return false;

    switch (parameter_number) {
    case 0:
        value = get_uint_parameter(parameter_stream, parameter_length);
        proto_tree_add_uint(tree, hf_clcc_id, tvb, offset, parameter_length, value);
        break;
    case 1:
        value = get_uint_parameter(parameter_stream, parameter_length);
        proto_tree_add_uint(tree, hf_clcc_dir, tvb, offset, parameter_length, value);
        break;
    case 2:
        value = get_uint_parameter(parameter_stream, parameter_length);
        proto_tree_add_uint(tree, hf_clcc_stat, tvb, offset, parameter_length, value);
        break;
    case 3:
        value = get_uint_parameter(parameter_stream, parameter_length);
        proto_tree_add_uint(tree, hf_clcc_mode, tvb, offset, parameter_length, value);
        break;
    case 4:
        value = get_uint_parameter(parameter_stream, parameter_length);
        proto_tree_add_uint(tree, hf_clcc_mpty, tvb, offset, parameter_length, value);
        break;
    case 5:
        proto_tree_add_item(tree, hf_at_number, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
        break;
    case 6:
        value = get_uint_parameter(parameter_stream, parameter_length);
        pitem = proto_tree_add_uint(tree, hf_at_type, tvb, offset, parameter_length, value);
        if (value < 128 || value > 175)
            expert_add_info(pinfo, pitem, &ei_at_type);
        break;
    case 7:
        proto_tree_add_item(tree, hf_at_alpha, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
        break;
    case 8:
        value = get_uint_parameter(parameter_stream, parameter_length);
        proto_tree_add_uint(tree, hf_at_priority, tvb, offset, parameter_length, value);
        break;
    }

    return true;
}


static bool
dissect_cme_error_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    uint32_t     value;

    if (!(role == ROLE_AG && type == TYPE_RESPONSE)) {
        return false;
    }

    if (parameter_number > 0) return false;

    value = get_uint_parameter(parameter_stream, parameter_length);
    proto_tree_add_uint(tree, hf_cme_error, tvb, offset, parameter_length, value);

    return true;
}

static bool
dissect_cnum_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!(role == ROLE_AG && type == TYPE_RESPONSE)) return true;
    if (parameter_number > 5) return false;

    switch (parameter_number) {
    case 0:
        pitem = proto_tree_add_item(tree, hf_at_alpha, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
        if (parameter_length > 0)
            expert_add_info(pinfo, pitem, &ei_parameter_blank);
        break;
    case 1:
        proto_tree_add_item(tree, hf_at_number, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
        break;
    case 2:
        value = get_uint_parameter(parameter_stream, parameter_length);
        pitem = proto_tree_add_uint(tree, hf_at_type, tvb, offset, parameter_length, value);
        if (value < 128 || value > 175)
            expert_add_info(pinfo, pitem, &ei_at_type);
        break;
    case 3:
        value = get_uint_parameter(parameter_stream, parameter_length);
        pitem = proto_tree_add_uint(tree, hf_cnum_speed, tvb, offset, parameter_length, value);
        if (parameter_length > 0)
            expert_add_info(pinfo, pitem, &ei_parameter_blank);
        break;
    case 4:
        value = get_uint_parameter(parameter_stream, parameter_length);
        pitem = proto_tree_add_uint(tree, hf_cnum_service, tvb, offset, parameter_length, value);
        if (value > 5)
            expert_add_info(pinfo, pitem, &ei_cnum_service);
        break;
    case 5:
        value = get_uint_parameter(parameter_stream, parameter_length);
        pitem = proto_tree_add_uint(tree, hf_cnum_itc, tvb, offset, parameter_length, value);
        if (value > 1)
            expert_add_info(pinfo, pitem, &ei_cnum_itc);
        break;
    }

    return true;
}

static bool
dissect_vts_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data _U_)
{
    proto_item  *pitem;
    uint32_t     value;

    if (!(role == ROLE_HS && type == TYPE_ACTION)) return true;
    if (parameter_number > 1) return false;

    switch (parameter_number) {
    case 0:
        pitem = proto_tree_add_item(tree, hf_vts_dtmf, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
        if (parameter_length != 1)
            expert_add_info(pinfo, pitem, &ei_vts_dtmf);
        break;
    case 1:
        value = get_uint_parameter(parameter_stream, parameter_length);
        proto_tree_add_uint(tree, hf_vts_duration, tvb, offset, parameter_length, value);
        break;
    }

    return true;
}

static bool
dissect_ciev_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int role, uint16_t type, uint8_t *parameter_stream,
        unsigned parameter_number, int parameter_length, void **data)
{
    uint32_t     value;
    unsigned     indicator_index;

    if (!(role == ROLE_AG && type == TYPE_RESPONSE)) return true;
    if (parameter_number > 1) return false;

    switch (parameter_number) {
    case 0:
        value = get_uint_parameter(parameter_stream, parameter_length);
        proto_tree_add_uint(tree, hf_ciev_indicator_index, tvb, offset, parameter_length, value);
        *data = wmem_alloc(pinfo->pool, sizeof(unsigned));
        *((unsigned *) *data) = value;
        break;
    case 1:
        indicator_index = *((unsigned *) *data) - 1;
        if (indicator_index > 19) {
            proto_tree_add_expert(tree, pinfo, &ei_ciev_indicator, tvb, offset, parameter_length);
        } else {
            proto_tree_add_item(tree, hf_indicator[indicator_index], tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
        }
        break;
    }

    return true;
}

/* TODO: Some commands need to save request command type (request with TYPE_READ vs TYPE_TEST, etc.)
         to properly dissect response parameters.
         Some commands can use TYPE_TEST respose to properly dissect parameters,
         for example: AT+CIND=?, AT+CIND? */
static const at_cmd_t at_cmds[] = {
    /* Vendor specific: Apple */
    { "+XAPL",        "Apple Bluetooth Accessory Identification",         check_xapl,        dissect_xapl_parameter },
    { "+IPHONEACCEV", "Apple Bluetooth Headset Battery Level Indication", check_iphoneaccev, dissect_iphoneaccev_parameter },
    { "+APLSIRI",     "Apple Siri Availability Information",              check_aplsiri,     dissect_aplsiri_parameter },
    { "+APLEFM",      "Apple Siri Eyes Free Mode",                        check_aplefm,      dissect_aplefm_parameter },
    /* Bluetooth HFP specific AT Commands */
    { "+BIEV",      "Bluetooth Indicator Enter Value",          check_biev, dissect_biev_parameter }, /* HFP 1.7 */
    { "+BIND",      "Bluetooth Indicator",                      check_bind, dissect_bind_parameter }, /* HFP 1.7 */
    { "+BAC",       "Bluetooth Available Codecs",               check_bac,  dissect_bac_parameter  },
    { "+BCS",       "Bluetooth Codec Selection",                check_bcs,  dissect_bcs_parameter  },
    { "+BCC",       "Bluetooth Codec Connection",               check_bcc,  dissect_no_parameter   },
    { "+BTRH",      "Bluetooth Response and Hold Feature",      check_btrh, dissect_btrh_parameter },
    { "+BSIR",      "Bluetooth Setting of In-band Ring Tone",   check_bsir, dissect_bsir_parameter },
    { "+VGS",       "Gain of Speaker",                          check_vgs,  dissect_vgs_parameter  },
    { "+VGM",       "Gain of Microphone",                       check_vgm,  dissect_vgm_parameter  },
    { "+NREC",      "Noise Reduction and Echo Cancelling",      check_nrec, dissect_nrec_parameter },
    { "+BRSF",      "Bluetooth Retrieve Supported Features",    check_brsf, dissect_brsf_parameter },
    { "+BVRA",      "Bluetooth Voice Recognition Activation",   check_bvra, dissect_bvra_parameter },
    { "+BLDN",      "Bluetooth Last Dialled Number",            check_bldn, dissect_no_parameter   },
    { "+BINP",      "Bluetooth Input",                          check_binp, dissect_binp_parameter },
    { "+BIA",       "Bluetooth Indicators Activation",          check_bia,  dissect_bia_parameter  },
    /* Inherited from normal AT Commands */
    { "+CCWA",      "Call Waiting Notification",                check_ccwa, dissect_ccwa_parameter },
    { "+CHLD",      "Call Hold and Multiparty Handling",        check_chld, dissect_chld_parameter },
    { "+CHUP",      "Call Hang-up",                             check_chup, dissect_no_parameter   },
    { "+CIND",      "Phone Indicators",                         check_cind, dissect_cind_parameter },
    { "+CLCC",      "Current Calls",                            check_clcc, dissect_clcc_parameter },
    { "+COPS",      "Reading Network Operator",                 check_cops, dissect_cops_parameter },
    { "+CMEE",      "Mobile Equipment Error",                   check_cmee, dissect_cmee_parameter },
    { "+CME ERROR", "Extended Audio Gateway Error Result Code", check_cme,  dissect_cme_error_parameter },
    { "+CLIP",      "Calling Line Identification Notification", check_clip, dissect_clip_parameter },
    { "+CMER",      "Event Reporting Activation/Deactivation",  check_cmer, dissect_cmer_parameter },
    { "+CIEV",      "Indicator Events Reporting",               check_ciev, dissect_ciev_parameter },
    { "+VTS",       "DTMF and tone generation",                 check_vts,  dissect_vts_parameter  },
    { "+CNUM",      "Subscriber Number Information",            check_cnum, dissect_cnum_parameter },
    { "ERROR",      "ERROR",                                    check_only_ag_role, dissect_no_parameter },
    { "RING",       "Incoming Call Indication",                 check_only_ag_role, dissect_no_parameter },
    { "OK",         "OK",                                       check_only_ag_role, dissect_no_parameter },
    { "D",          "Dial",                                     check_only_hs_role, NULL },
    { "A",          "Call Answer",                              check_only_hs_role, dissect_no_parameter },
    { NULL, NULL, NULL, NULL }
};


static int
dissect_at_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, uint32_t role, int command_number)
{
    proto_item      *pitem;
    proto_tree      *command_item = NULL;
    proto_item      *command_tree = NULL;
    proto_tree      *parameters_item = NULL;
    proto_item      *parameters_tree = NULL;
    uint8_t         *col_str = NULL;
    uint8_t         *at_stream;
    uint8_t         *at_command = NULL;
    int              i_char = 0;
    unsigned         i_char_fix = 0;
    int              length;
    const at_cmd_t  *i_at_cmd;
    int              parameter_length;
    unsigned         parameter_number = 0;
    int              first_parameter_offset = offset;
    int              last_parameter_offset  = offset;
    uint16_t         type = TYPE_UNKNOWN;
    uint32_t         brackets;
    bool             quotation;
    bool             next;
    void            *data;

    length = tvb_reported_length_remaining(tvb, offset);
    if (length <= 0)
        return tvb_reported_length(tvb);

    if (!command_number) {
        proto_tree_add_item(tree, hf_data, tvb, offset, length, ENC_NA | ENC_ASCII);
        col_str = (uint8_t *) wmem_alloc(pinfo->pool, length + 1);
        tvb_memcpy(tvb, col_str, offset, length);
        col_str[length] = '\0';
    }

    at_stream = (uint8_t *) wmem_alloc(pinfo->pool, length + 1);
    tvb_memcpy(tvb, at_stream, offset, length);
    at_stream[length] = '\0';

    while (at_stream[i_char]) {
        at_stream[i_char] = g_ascii_toupper(at_stream[i_char]);
        if (!command_number) {
            col_str[i_char] = g_ascii_toupper(col_str[i_char]);
            if (!g_ascii_isgraph(col_str[i_char])) col_str[i_char] = ' ';
        }
        i_char += 1;
    }

    if (!command_number) col_append_str(pinfo->cinfo, COL_INFO, col_str);

    if (role == ROLE_HS) {
        if (command_number) {
            at_command = at_stream;
            i_char = 0;
        } else {
            at_command = g_strstr_len(at_stream, length, "AT");
            if (at_command) {
                command_item = proto_tree_add_none_format(tree, hf_command, tvb,
                        offset, 0, "Command %u", command_number);
                command_tree = proto_item_add_subtree(command_item, ett_bthfp_command);

                i_char = (unsigned) (at_command - at_stream);
                if (i_char) {
                    proto_tree_add_item(command_tree, hf_at_ignored, tvb, offset,
                        i_char, ENC_NA | ENC_ASCII);
                    offset += i_char;
                }

                proto_tree_add_item(command_tree, hf_at_command_line_prefix,
                        tvb, offset, 2, ENC_NA | ENC_ASCII);
                offset += 2;
                i_char += 2;
                at_command = at_stream;
                at_command += i_char;
                length -= i_char;
                i_char_fix += i_char;
                i_char = 0;
            }
        }
    } else if (at_stream[0] == '\r' && at_stream[1] == '\n') {
        command_item = proto_tree_add_none_format(tree, hf_command, tvb,
                offset, 0, "Command %u", command_number);
        command_tree = proto_item_add_subtree(command_item, ett_bthfp_command);

        at_command = at_stream;
        i_char = 0;
        while (i_char <= length &&
                (at_command[i_char] == '\r' || at_command[i_char] == '\n' ||
                at_command[i_char] == ' ' || at_command[i_char] == '\t')) {
            /* ignore white characters */
            i_char += 1;
        }

        offset += i_char;
        at_command += i_char;
        length -= i_char;
        i_char_fix += i_char;
        i_char = 0;
    }

    if (at_command) {

        while (i_char < length &&
                        (at_command[i_char] != '\r' && at_command[i_char] != '=' &&
                        at_command[i_char] != ';' && at_command[i_char] != '?' &&
                        at_command[i_char] != ':')) {
            i_char += 1;
        }

        i_at_cmd = at_cmds;
        if (at_command[0] == '\r') {
            pitem = proto_tree_add_item(command_tree, hf_at_cmd, tvb, offset - 2,
                    2, ENC_NA | ENC_ASCII);
            i_at_cmd = NULL;
        } else {
            pitem = NULL;
            while (i_at_cmd->name) {
                if (g_str_has_prefix(&at_command[0], i_at_cmd->name)) {
                    pitem = proto_tree_add_item(command_tree, hf_at_cmd, tvb, offset,
                            (int) strlen(i_at_cmd->name), ENC_NA | ENC_ASCII);
                    proto_item_append_text(pitem, " (%s)", i_at_cmd->long_name);
                    break;
                }
                i_at_cmd += 1;
            }

            if (!pitem) {
                pitem = proto_tree_add_item(command_tree, hf_at_cmd, tvb, offset,
                        i_char, ENC_NA | ENC_ASCII);
            }
        }


        if (i_at_cmd && i_at_cmd->name == NULL) {
            char *name;

            name = format_text(pinfo->pool, at_command, i_char + 1);
            proto_item_append_text(command_item, ": %s (Unknown)", name);
            proto_item_append_text(pitem, " (Unknown - Non-Standard HFP Command)");
            expert_add_info(pinfo, pitem, &ei_non_mandatory_command);
        } else if (i_at_cmd == NULL) {
            proto_item_append_text(command_item, ": AT");
        } else {
            proto_item_append_text(command_item, ": %s", i_at_cmd->name);
        }

        offset += i_char;

        if (i_at_cmd && g_strcmp0(i_at_cmd->name, "D")) {
            if (length >= 2 && at_command[i_char] == '=' && at_command[i_char + 1] == '?') {
                type = at_command[i_char] << 8 | at_command[i_char + 1];
                proto_tree_add_uint(command_tree, hf_at_cmd_type, tvb, offset, 2, type);
                offset += 2;
                i_char += 2;
            } else if (role == ROLE_AG && length >= 2 && at_command[i_char] == '\r' && at_command[i_char + 1] == '\n') {
                type = at_command[i_char] << 8 | at_command[i_char + 1];
                proto_tree_add_uint(command_tree, hf_at_cmd_type, tvb, offset, 2, type);
                offset += 2;
                i_char += 2;
            } else if (length >= 1 && (at_command[i_char] == '=' ||
                        at_command[i_char] == '\r' ||
                        at_command[i_char] == ':' ||
                        at_command[i_char] == '?')) {
                type = at_command[i_char];
                proto_tree_add_uint(command_tree, hf_at_cmd_type, tvb, offset, 1, type);
                offset += 1;
                i_char += 1;
            }
        }

        if (i_at_cmd && i_at_cmd->check_command && !i_at_cmd->check_command(role, type)) {
            expert_add_info(pinfo, command_item, &ei_invalid_usage);
        }

        parameters_item = proto_tree_add_none_format(command_tree, hf_parameters, tvb,
                offset, 0, "Parameters");
        parameters_tree = proto_item_add_subtree(parameters_item, ett_bthfp_parameters);
        first_parameter_offset = offset;

        data = NULL;

        while (i_char < length) {

            while (at_command[i_char] == ' ' || at_command[i_char]  == '\t') {
                offset += 1;
                i_char += 1;
            }

            parameter_length = 0;
            brackets = 0;
            quotation = false;
            next = false;

            if (at_command[i_char + parameter_length] != '\r') {
                while (i_char + parameter_length < length &&
                        at_command[i_char + parameter_length] != '\r') {

                    if (at_command[i_char + parameter_length] == ';') {
                        next = true;
                        break;
                    }

                    if (at_command[i_char + parameter_length] == '"') {
                        quotation = quotation ? false : true;
                    }

                    if (quotation == true) {
                        parameter_length += 1;
                        continue;
                    }

                    if (at_command[i_char + parameter_length] == '(') {
                        brackets += 1;
                    }
                    if (at_command[i_char + parameter_length] == ')') {
                        brackets -= 1;
                    }

                    if (brackets == 0 && at_command[i_char + parameter_length] == ',') {
                        break;
                    }

                    parameter_length += 1;
                }

                if (type == TYPE_ACTION || type == TYPE_RESPONSE) {
                    if (i_at_cmd && (i_at_cmd->dissect_parameter != NULL &&
                            !i_at_cmd->dissect_parameter(tvb, pinfo, parameters_tree, offset, role,
                            type, &at_command[i_char], parameter_number, parameter_length, &data) )) {
                        pitem = proto_tree_add_item(parameters_tree,
                                hf_unknown_parameter, tvb, offset,
                                parameter_length, ENC_NA | ENC_ASCII);
                        expert_add_info(pinfo, pitem, &ei_unknown_parameter);
                    } else if (i_at_cmd && i_at_cmd->dissect_parameter == NULL) {
                        proto_tree_add_item(parameters_tree, hf_parameter, tvb, offset,
                                parameter_length, ENC_NA | ENC_ASCII);
                    }
                }
            }

            if (type != TYPE_ACTION_SIMPLY && type != TYPE_RESPONSE_ACK && type != TYPE_TEST && type != TYPE_READ)
                parameter_number += 1;
            i_char += parameter_length;
            offset += parameter_length;
            last_parameter_offset = offset;

            if (role == ROLE_AG &&
                    i_char + 1 <= length &&
                    at_command[i_char] == '\r' &&
                    at_command[i_char + 1] == '\n') {
                offset += 2;
                i_char += 2;
                break;
            } else if (at_command[i_char] == ',' ||
                        at_command[i_char] == '\r' ||
                        at_command[i_char] == ';') {
                    i_char += 1;
                    offset += 1;
            }

            if (next) break;
        }

        i_char += i_char_fix;
        proto_item_set_len(command_item, i_char);
    } else {
        length = tvb_reported_length_remaining(tvb, offset);
        if (length < 0)
            length = 0;
        offset += length;
    }

    if (parameter_number > 0 && last_parameter_offset - first_parameter_offset > 0)
        proto_item_set_len(parameters_item, last_parameter_offset - first_parameter_offset);
    else
        proto_item_append_text(parameters_item, ": No");

    return offset;
}

static int
dissect_bthfp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item       *main_item;
    proto_tree       *main_tree;
    proto_item       *pitem;
    int               offset = 0;
    uint32_t          role = ROLE_UNKNOWN;
    wmem_tree_key_t   key[10];
    uint32_t          interface_id;
    uint32_t          adapter_id;
    uint32_t          chandle;
    uint32_t          dlci;
    uint32_t          frame_number;
    uint32_t          direction;
    uint32_t          bd_addr_oui;
    uint32_t          bd_addr_id;
    fragment_t       *fragment;
    fragment_t       *previous_fragment;
    fragment_t       *i_fragment;
    uint8_t          *at_stream;
    int               length;
    int               command_number;
    int               i_length;
    tvbuff_t         *reassembled_tvb = NULL;
    unsigned          reassemble_start_offset = 0;
    unsigned          reassemble_end_offset   = 0;
    int               previous_proto;

    previous_proto = (GPOINTER_TO_INT(wmem_list_frame_data(wmem_list_frame_prev(wmem_list_tail(pinfo->layers)))));
    if (data && previous_proto == proto_btrfcomm) {
        btrfcomm_data_t  *rfcomm_data;

        rfcomm_data = (btrfcomm_data_t *) data;

        interface_id = rfcomm_data->interface_id;
        adapter_id   = rfcomm_data->adapter_id;
        chandle      = rfcomm_data->chandle;
        dlci         = rfcomm_data->dlci;
        direction    = (rfcomm_data->is_local_psm) ? P2P_DIR_SENT : P2P_DIR_RECV;

        if (direction == P2P_DIR_RECV) {
            bd_addr_oui     = rfcomm_data->remote_bd_addr_oui;
            bd_addr_id      = rfcomm_data->remote_bd_addr_id;
        } else {
            bd_addr_oui     = 0;
            bd_addr_id      = 0;
        }
    } else {
        interface_id = HCI_INTERFACE_DEFAULT;
        adapter_id   = HCI_ADAPTER_DEFAULT;
        chandle      = 0;
        dlci         = 0;
        direction    = P2P_DIR_UNKNOWN;

        bd_addr_oui     = 0;
        bd_addr_id      = 0;
    }

    main_item = proto_tree_add_item(tree, proto_bthfp, tvb, 0, tvb_captured_length(tvb), ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_bthfp);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HFP");

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
            break;
    }

    if ((hfp_role == ROLE_AG && pinfo->p2p_dir == P2P_DIR_SENT) ||
            (hfp_role == ROLE_HS && pinfo->p2p_dir == P2P_DIR_RECV)) {
        role = ROLE_AG;
    } else if (hfp_role != ROLE_UNKNOWN) {
        role = ROLE_HS;
    }

    if (role == ROLE_UNKNOWN) {
        uint32_t         sdp_psm;
        uint32_t         service_type;
        uint32_t         service_channel;
        service_info_t  *service_info;

        sdp_psm         = SDP_PSM_DEFAULT;

        service_type    = BTSDP_RFCOMM_PROTOCOL_UUID;
        service_channel = dlci >> 1;
        frame_number    = pinfo->num;

        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &adapter_id;
        key[2].length = 1;
        key[2].key = &sdp_psm;
        key[3].length = 1;
        key[3].key = &direction;
        key[4].length = 1;
        key[4].key = &bd_addr_oui;
        key[5].length = 1;
        key[5].key = &bd_addr_id;
        key[6].length = 1;
        key[6].key = &service_type;
        key[7].length = 1;
        key[7].key = &service_channel;
        key[8].length = 1;
        key[8].key = &frame_number;
        key[9].length = 0;
        key[9].key = NULL;

        service_info = btsdp_get_service_info(key);
        if (service_info && service_info->interface_id == interface_id &&
                service_info->adapter_id == adapter_id &&
                service_info->sdp_psm == SDP_PSM_DEFAULT &&
                ((service_info->direction == P2P_DIR_RECV &&
                service_info->bd_addr_oui == bd_addr_oui &&
                service_info->bd_addr_id == bd_addr_id) ||
                (service_info->direction != P2P_DIR_RECV &&
                service_info->bd_addr_oui == 0 &&
                service_info->bd_addr_id == 0)) &&
                service_info->type == BTSDP_RFCOMM_PROTOCOL_UUID &&
                service_info->channel == (dlci >> 1)) {
            if ((service_info->uuid.bt_uuid == BTSDP_HFP_GW_SERVICE_UUID && service_info->direction == P2P_DIR_RECV && pinfo->p2p_dir == P2P_DIR_SENT) ||
                (service_info->uuid.bt_uuid == BTSDP_HFP_GW_SERVICE_UUID && service_info->direction == P2P_DIR_SENT && pinfo->p2p_dir == P2P_DIR_RECV) ||
                (service_info->uuid.bt_uuid == BTSDP_HFP_SERVICE_UUID && service_info->direction == P2P_DIR_RECV && pinfo->p2p_dir == P2P_DIR_RECV) ||
                (service_info->uuid.bt_uuid == BTSDP_HFP_SERVICE_UUID && service_info->direction == P2P_DIR_SENT && pinfo->p2p_dir == P2P_DIR_SENT)) {
                role = ROLE_HS;
            } else {
                role = ROLE_AG;
            }
        }
    }

    pitem = proto_tree_add_uint(main_tree, hf_role, tvb, 0, 0, role);
    proto_item_set_generated(pitem);

    if (role == ROLE_UNKNOWN) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Data: %s",
                tvb_format_text(pinfo->pool, tvb, 0, tvb_reported_length(tvb)));
        proto_tree_add_item(main_tree, hf_data, tvb, 0, tvb_captured_length(tvb), ENC_NA | ENC_ASCII);
        return tvb_reported_length(tvb);
    }

    /* save fragments */
    if (!pinfo->fd->visited) {
        frame_number = pinfo->num - 1;

        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &adapter_id;
        key[2].length = 1;
        key[2].key = &chandle;
        key[3].length = 1;
        key[3].key = &dlci;
        key[4].length = 1;
        key[4].key = &role;
        key[5].length = 1;
        key[5].key = &frame_number;
        key[6].length = 0;
        key[6].key = NULL;

        previous_fragment = (fragment_t *) wmem_tree_lookup32_array_le(fragments, key);
        if (!(previous_fragment && previous_fragment->interface_id == interface_id &&
                previous_fragment->adapter_id == adapter_id &&
                previous_fragment->chandle == chandle &&
                previous_fragment->dlci == dlci &&
                previous_fragment->role == role &&
                previous_fragment->reassemble_state != REASSEMBLE_DONE)) {
            previous_fragment = NULL;
        }

        frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &adapter_id;
        key[2].length = 1;
        key[2].key = &chandle;
        key[3].length = 1;
        key[3].key = &dlci;
        key[4].length = 1;
        key[4].key = &role;
        key[5].length = 1;
        key[5].key = &frame_number;
        key[6].length = 0;
        key[6].key = NULL;

        fragment = wmem_new(wmem_file_scope(), fragment_t);
        fragment->interface_id      = interface_id;
        fragment->adapter_id        = adapter_id;
        fragment->chandle           = chandle;
        fragment->dlci              = dlci;
        fragment->role              = role;
        fragment->idx               = previous_fragment ? previous_fragment->idx + previous_fragment->length : 0;
        fragment->reassemble_state  = REASSEMBLE_FRAGMENT;
        fragment->length            = tvb_reported_length(tvb);
        fragment->data              = (uint8_t *) wmem_alloc(wmem_file_scope(), fragment->length);
        fragment->previous_fragment = previous_fragment;
        tvb_memcpy(tvb, fragment->data, offset, fragment->length);

        wmem_tree_insert32_array(fragments, key, fragment);

        /* Detect reassemble end character: \r for HS or \n for AG */
        length = tvb_reported_length(tvb);
        at_stream = tvb_get_string_enc(pinfo->pool, tvb, 0, length, ENC_ASCII);

        reassemble_start_offset = 0;

        for (i_length = 0; i_length < length; i_length += 1) {
            if (!((role == ROLE_HS && at_stream[i_length] == '\r') ||
                    (role == ROLE_AG && at_stream[i_length] == '\n'))) {
                continue;
            }

            if (role == ROLE_HS && at_stream[i_length] == '\r') {
                reassemble_start_offset = i_length + 1;
                if (reassemble_end_offset == 0) reassemble_end_offset = i_length + 1;
            }

            if (role == ROLE_AG && at_stream[i_length] == '\n') {
                reassemble_start_offset = i_length + 1;
            }

            frame_number = pinfo->num;

            key[0].length = 1;
            key[0].key = &interface_id;
            key[1].length = 1;
            key[1].key = &adapter_id;
            key[2].length = 1;
            key[2].key = &chandle;
            key[3].length = 1;
            key[3].key = &dlci;
            key[4].length = 1;
            key[4].key = &role;
            key[5].length = 1;
            key[5].key = &frame_number;
            key[6].length = 0;
            key[6].key = NULL;

            fragment = (fragment_t *) wmem_tree_lookup32_array_le(fragments, key);
            if (fragment && fragment->interface_id == interface_id &&
                    fragment->adapter_id == adapter_id &&
                    fragment->chandle == chandle &&
                    fragment->dlci == dlci &&
                    fragment->role == role) {
                i_fragment = fragment;
                while (i_fragment && i_fragment->idx > 0) {
                    i_fragment = i_fragment->previous_fragment;
                }

                if (i_length + 1 == length &&
                        role == ROLE_HS &&
                        at_stream[i_length] == '\r') {
                    fragment->reassemble_state = REASSEMBLE_DONE;
                } else if (i_length + 1 == length &&
                        role == ROLE_AG &&
                        i_length >= 4 &&
                        at_stream[i_length] == '\n' &&
                        at_stream[i_length - 1] == '\r' &&
                        at_stream[0] == '\r' &&
                        at_stream[1] == '\n') {
                    fragment->reassemble_state = REASSEMBLE_DONE;
                } else if (i_length + 1 == length &&
                        role == ROLE_AG &&
                        i_length >= 2 &&
                        at_stream[i_length] == '\n' &&
                        at_stream[i_length - 1] == '\r' &&
                        i_fragment &&
                        i_fragment->reassemble_state == REASSEMBLE_FRAGMENT &&
                        i_fragment->length >= 2 &&
                        i_fragment->data[0] == '\r' &&
                        i_fragment->data[1] == '\n') {
                    fragment->reassemble_state = REASSEMBLE_DONE;
                } else if (role == ROLE_HS) {
/* XXX: Temporary disable reassembling of partial message, it seems to be broken */
/*                    fragment->reassemble_state = REASSEMBLE_PARTIALLY;*/
                }
                fragment->reassemble_start_offset = reassemble_start_offset;
                fragment->reassemble_end_offset = reassemble_end_offset;
            }
        }
    }

    /* recover reassembled payload */
    frame_number = pinfo->num;

    key[0].length = 1;
    key[0].key = &interface_id;
    key[1].length = 1;
    key[1].key = &adapter_id;
    key[2].length = 1;
    key[2].key = &chandle;
    key[3].length = 1;
    key[3].key = &dlci;
    key[4].length = 1;
    key[4].key = &role;
    key[5].length = 1;
    key[5].key = &frame_number;
    key[6].length = 0;
    key[6].key = NULL;

    fragment = (fragment_t *) wmem_tree_lookup32_array_le(fragments, key);
    if (fragment && fragment->interface_id == interface_id &&
            fragment->adapter_id == adapter_id &&
            fragment->chandle == chandle &&
            fragment->dlci == dlci &&
            fragment->role == role &&
            fragment->reassemble_state != REASSEMBLE_FRAGMENT) {
        uint8_t   *at_data;
        unsigned   i_data_offset;

        i_data_offset = fragment->idx + fragment->length;
        at_data = (uint8_t *) wmem_alloc(pinfo->pool, fragment->idx + fragment->length);

        i_fragment = fragment;

        if (i_fragment && i_fragment->reassemble_state == REASSEMBLE_PARTIALLY) {
            i_data_offset -= i_fragment->reassemble_end_offset;
            memcpy(at_data + i_data_offset, i_fragment->data, i_fragment->reassemble_end_offset);
            i_fragment = i_fragment->previous_fragment;
        }

        if (i_fragment) {
            while (i_fragment && i_fragment->idx > 0) {
                i_data_offset -= i_fragment->length;
                memcpy(at_data + i_data_offset, i_fragment->data, i_fragment->length);
                i_fragment = i_fragment->previous_fragment;
            }

            if (i_fragment && i_fragment->reassemble_state == REASSEMBLE_PARTIALLY) {
                i_data_offset -= (i_fragment->length - i_fragment->reassemble_start_offset);
                memcpy(at_data + i_data_offset, i_fragment->data + i_fragment->reassemble_start_offset,
                        i_fragment->length - i_fragment->reassemble_start_offset);
            } else if (i_fragment) {
                i_data_offset -= i_fragment->length;
                memcpy(at_data + i_data_offset, i_fragment->data, i_fragment->length);
            }
        }

        if (fragment->idx > 0 && fragment->length > 0) {
            proto_tree_add_item(main_tree, hf_fragment, tvb, offset,
                    tvb_captured_length_remaining(tvb, offset), ENC_ASCII | ENC_NA);
            reassembled_tvb = tvb_new_child_real_data(tvb, at_data,
                    fragment->idx + fragment->length, fragment->idx + fragment->length);
            add_new_data_source(pinfo, reassembled_tvb, "Reassembled HFP");
        }

        command_number = 0;
        if (reassembled_tvb) {
            unsigned reassembled_offset = 0;

            while (tvb_reported_length(reassembled_tvb) > reassembled_offset) {
                reassembled_offset = dissect_at_command(reassembled_tvb,
                        pinfo, main_tree, reassembled_offset, role, command_number);
                command_number += 1;
            }
            offset = tvb_captured_length(tvb);
        } else {
            while (tvb_reported_length(tvb) > (unsigned) offset) {
                offset = dissect_at_command(tvb, pinfo, main_tree, offset, role, command_number);
                command_number += 1;
            }
        }
    } else {
        pitem = proto_tree_add_item(main_tree, hf_fragmented, tvb, 0, 0, ENC_NA);
        proto_item_set_generated(pitem);
        char *display_str;
        proto_tree_add_item_ret_display_string(main_tree, hf_fragment, tvb, offset, -1, ENC_ASCII, pinfo->pool, &display_str);
        col_append_fstr(pinfo->cinfo, COL_INFO, "Fragment: %s", display_str);
        offset = tvb_captured_length(tvb);
    }

    return offset;
}

void
proto_register_bthfp(void)
{
    module_t         *module;
    expert_module_t  *expert_bthfp;

    static hf_register_info hf[] = {
        { &hf_command,
           { "Command",                          "bthfp.command",
           FT_NONE, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_parameters,
           { "Parameters",                       "bthfp.parameters",
           FT_NONE, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_data,
           { "AT Stream",                        "bthfp.data",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_fragment,
           { "Fragment",                         "bthfp.fragment",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_fragmented,
           { "Fragmented",                       "bthfp.fragmented",
           FT_NONE, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_ignored,
           { "Ignored",                          "bthfp.ignored",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_cmd,
           { "Command",                          "bthfp.at_cmd",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_cmd_type,
           { "Type",                             "bthfp.at_cmd.type",
           FT_UINT16, BASE_HEX, VALS(at_cmd_type_vals), 0,
           NULL, HFILL}
        },
        { &hf_at_command_line_prefix,
           { "Command Line Prefix",              "bthfp.command_line_prefix",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_parameter,
           { "Parameter",                        "bthfp.parameter",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_unknown_parameter,
           { "Unknown Parameter",                "bthfp.unknown_parameter",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_role,
           { "Role",                             "bthfp.role",
           FT_UINT8, BASE_DEC, VALS(role_vals), 0,
           NULL, HFILL}
        },
        { &hf_brsf_hs,
           { "HS supported features bitmask",    "bthfp.brsf.hs.features",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_brsf_hs_ec_nr_function,
           { "EC and/or NR function",            "bthfp.brsf.hs.ec_nr_function",
           FT_BOOLEAN, 32, NULL, 0x00000001,
           NULL, HFILL}
        },
        { &hf_brsf_hs_call_waiting_or_tree_way,
           { "Call waiting or 3-way calling",    "bthfp.brsf.hs.call_waiting_or_tree_way",
           FT_BOOLEAN, 32, NULL, 0x00000002,
           NULL, HFILL}
        },
        { &hf_brsf_hs_cli_presentation,
           { "CLI Presentation",                 "bthfp.brsf.hs.cli_presentation",
           FT_BOOLEAN, 32, NULL, 0x00000004,
           NULL, HFILL}
        },
        { &hf_brsf_hs_voice_recognition_activation,
           { "Voice Recognition Activation",     "bthfp.brsf.hs.voice_recognition_activation",
           FT_BOOLEAN, 32, NULL, 0x00000008,
           NULL, HFILL}
        },
        { &hf_brsf_hs_remote_volume_control,
           { "Remote Volume Control",            "bthfp.brsf.hs.remote_volume_control",
           FT_BOOLEAN, 32, NULL, 0x00000010,
           NULL, HFILL}
        },
        { &hf_brsf_hs_enhanced_call_status,
           { "Enhanced Call Status",             "bthfp.brsf.hs.enhanced_call_status",
           FT_BOOLEAN, 32, NULL, 0x00000020,
           NULL, HFILL}
        },
        { &hf_brsf_hs_enhanced_call_control,
           { "Enhanced Call Control",            "bthfp.brsf.hs.enhanced_call_control",
           FT_BOOLEAN, 32, NULL, 0x00000040,
           NULL, HFILL}
        },
        { &hf_brsf_hs_codec_negotiation,
           { "Codec Negotiation",                "bthfp.brsf.hs.codec_negotiation",
           FT_BOOLEAN, 32, NULL, 0x00000080,
           NULL, HFILL}
        },
        { &hf_brsf_hs_hf_indicators,
           { "HF Indicators",                    "bthfp.brsf.hs.hf_indicators",
           FT_BOOLEAN, 32, NULL, 0x00000100,
           NULL, HFILL}
        },
        { &hf_brsf_hs_esco_s4_t2_settings_support,
           { "eSCO S4 (and T2) Settings Support","bthfp.brsf.hs.esco_s4_t2_settings_support",
           FT_BOOLEAN, 32, NULL, 0x00000200,
           NULL, HFILL}
        },
        { &hf_brsf_hs_reserved,
           { "Reserved",                         "bthfp.brsf.hs.reserved",
           FT_UINT32, BASE_HEX, NULL, 0xFFFFFC00,
           NULL, HFILL}
        },
        { &hf_brsf_ag,
           { "AG supported features bitmask",    "bthfp.brsf.ag.features",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_brsf_ag_three_way_calling,
           { "Three Way Calling",                "bthfp.brsf.ag.three_way_calling",
           FT_BOOLEAN, 32, NULL, 0x00000001,
           NULL, HFILL}
        },
        { &hf_brsf_ag_ec_nr_function,
           { "EC and/or NR function",            "bthfp.brsf.ag.ec_nr_function",
           FT_BOOLEAN, 32, NULL, 0x00000002,
           NULL, HFILL}
        },
        { &hf_brsf_ag_voice_recognition_function,
           { "Voice Recognition Function",       "bthfp.brsf.ag.voice_recognition_function",
           FT_BOOLEAN, 32, NULL, 0x00000004,
           NULL, HFILL}
        },
        { &hf_brsf_ag_inband_ring_tone,
           { "In-band Ring Tone",                "bthfp.brsf.ag.inband_ring_tone",
           FT_BOOLEAN, 32, NULL, 0x00000008,
           NULL, HFILL}
        },
        { &hf_brsf_ag_attach_number_to_voice_tag,
           { "Attach Number to Voice Tag",       "bthfp.brsf.ag.attach_number_to_voice_tag",
           FT_BOOLEAN, 32, NULL, 0x00000010,
           NULL, HFILL}
        },
        { &hf_brsf_ag_ability_to_reject_a_call,
           { "Ability to Reject a Call",         "bthfp.brsf.ag.ability_to_reject_a_call",
           FT_BOOLEAN, 32, NULL, 0x00000020,
           NULL, HFILL}
        },
        { &hf_brsf_ag_enhanced_call_status,
           { "Enhanced Call Status",             "bthfp.brsf.ag.enhanced_call_status",
           FT_BOOLEAN, 32, NULL, 0x00000040,
           NULL, HFILL}
        },
        { &hf_brsf_ag_enhanced_call_control,
           { "Enhanced Call Control",            "bthfp.brsf.ag.enhanced_call_control",
           FT_BOOLEAN, 32, NULL, 0x00000080,
           NULL, HFILL}
        },
        { &hf_brsf_ag_extended_error_result_codes,
           { "Extended Error Result Codes",      "bthfp.brsf.ag.extended_error_result_codes",
           FT_BOOLEAN, 32, NULL, 0x00000100,
           NULL, HFILL}
        },
        { &hf_brsf_ag_codec_negotiation,
           { "Codec Negotiation",                "bthfp.brsf.ag.codec_negotiation",
           FT_BOOLEAN, 32, NULL, 0x00000200,
           NULL, HFILL}
        },
        { &hf_brsf_ag_hf_indicators,
           { "HF Indicators",                    "bthfp.brsf.ag.hf_indicators",
           FT_BOOLEAN, 32, NULL, 0x00000400,
           NULL, HFILL}
        },
        { &hf_brsf_ag_esco_s4_t2_settings_support,
           { "eSCO S4 (and T2) Settings Support","bthfp.brsf.ag.esco_s4_t2_settings_support",
           FT_BOOLEAN, 32, NULL, 0x00000800,
           NULL, HFILL}
        },
        { &hf_brsf_ag_reserved,
           { "Reserved",                         "bthfp.brsf.ag.reserved",
           FT_UINT32, BASE_HEX, NULL, 0xFFFFF000,
           NULL, HFILL}
        },
        { &hf_vgs,
           { "Gain",                             "bthfp.vgs",
           FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_slash15, 0,
           NULL, HFILL}
        },
        { &hf_vgm,
           { "Gain",                             "bthfp.vgm",
           FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_slash15, 0,
           NULL, HFILL}
        },
        { &hf_nrec,
           { "Noise Reduction",                  "bthfp.nrec",
           FT_UINT8, BASE_DEC, VALS(nrec_vals), 0,
           NULL, HFILL}
        },
        { &hf_bvra_vrect,
           { "Voice Recognition",                "bthfp.bvra.vrect",
           FT_UINT8, BASE_DEC, VALS(bvra_vrect_vals), 0,
           NULL, HFILL}
        },
        { &hf_bsir,
           { "Feature",                          "bthfp.bsir",
           FT_UINT8, BASE_DEC, VALS(bsir_vals), 0,
           NULL, HFILL}
        },
        { &hf_btrh,
           { "Feature",                          "bthfp.btrh",
           FT_UINT8, BASE_DEC, VALS(btrh_vals), 0,
           NULL, HFILL}
        },
        { &hf_cmer_mode,
           { "Mode",                             "bthfp.cmer.mode",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cmer_keyp,
           { "Keypad",                           "bthfp.cmer.keyp",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cmer_disp,
           { "Display",                          "bthfp.cmer.disp",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cmer_ind,
           { "Indicator",                        "bthfp.cmer.ind",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cmer_bfr,
           { "Buffer",                           "bthfp.cmer.bfr",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_bac_codec,
           { "Codec",                            "bthfp.bac.codec",
           FT_UINT8, BASE_DEC, VALS(codecs_vals), 0,
           NULL, HFILL}
        },
        { &hf_bcs_codec,
           { "Codec",                            "bthfp.bcs.codec",
           FT_UINT8, BASE_DEC, VALS(codecs_vals), 0,
           NULL, HFILL}
        },
        { &hf_binp_request,
           { "Request",                          "bthfp.binp.request",
           FT_UINT8, BASE_DEC, VALS(binp_request_vals), 0,
           NULL, HFILL}
        },
        { &hf_binp_response,
           { "Response",                         "bthfp.binp.response",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cme_error,
           { "CME Error",                        "bthfp.cme_error",
           FT_UINT8, BASE_DEC, VALS(cme_error_vals), 0,
           NULL, HFILL}
        },
        { &hf_cmee,
           { "Mode",                             "bthfp.cmee",
           FT_UINT8, BASE_DEC, VALS(cmee_vals), 0,
           NULL, HFILL}
        },
        { &hf_chld_mode,
           { "Mode",                             "bthfp.chld.mode_value",
           FT_UINT8, BASE_DEC, VALS(chld_vals), 0,
           NULL, HFILL}
        },
        { &hf_chld_mode_1x,
           { "Mode: Releases specified active call only",  "bthfp.chld.mode",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_chld_mode_2x,
           { "Mode:  Request private consultation mode with specified call - place all calls on hold EXCEPT the call indicated by x",  "bthfp.chld.mode",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_chld_supported_modes,
           { "Supported Modes",                  "bthfp.chld.supported_modes",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_ciev_indicator_index,
           { "Indicator Index",                  "bthfp.ciev.indicator_index",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_vts_dtmf,
           { "DTMF",                             "bthfp.vts.dtmf",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_vts_duration,
           { "Duration",                         "bthfp.vts.duration",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cops_mode,
           { "Mode",                             "bthfp.cops.mode",
           FT_UINT8, BASE_DEC, VALS(cops_mode_vals), 0,
           NULL, HFILL}
        },
        { &hf_cops_format,
           { "Format",                           "bthfp.cops.format",
           FT_UINT8, BASE_DEC, VALS(cops_format_vals), 0,
           NULL, HFILL}
        },
        { &hf_cops_operator,
           { "Operator",                         "bthfp.cops.operator",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cops_act,
           { "AcT",                              "bthfp.cops.act",
           FT_UINT8, BASE_DEC, VALS(cops_act_vals), 0,
           NULL, HFILL}
        },
        { &hf_clip_mode,
           { "Mode",                             "bthfp.clip.mode",
           FT_UINT8, BASE_DEC, VALS(clip_mode_vals), 0,
           NULL, HFILL}
        },
        { &hf_clip_status,
           { "Status",                           "bthfp.clip.status",
           FT_UINT8, BASE_DEC, VALS(clip_status_vals), 0,
           NULL, HFILL}
        },
        { &hf_at_number,
           { "Number",                           "bthfp.at.number",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_type,
           { "Type",                             "bthfp.at.type",
           FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(at_type_vals), 0,
           NULL, HFILL}
        },
        { &hf_at_subaddress,
           { "Subaddress",                       "bthfp.at.subaddress",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_subaddress_type,
           { "Subaddress Type",                  "bthfp.at.subaddress_type",
           FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(at_type_vals), 0,
           NULL, HFILL}
        },
        { &hf_cnum_speed,
           { "Speed",                            "bthfp.cnum.speed",
           FT_UINT8, BASE_DEC | BASE_EXT_STRING, &csd_data_rate_vals_ext, 0,
           NULL, HFILL}
        },
        { &hf_cnum_service,
           { "Service",                          "bthfp.cnum.service",
           FT_UINT8, BASE_DEC, VALS(cnum_service_vals), 0,
           NULL, HFILL}
        },
        { &hf_cnum_itc,
           { "Information Transfer Capability",  "bthfp.cnum.itc",
           FT_UINT8, BASE_DEC, VALS(cnum_itc_vals), 0,
           NULL, HFILL}
        },
        { &hf_at_alpha,
           { "Alpha",                            "bthfp.at.alpha",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_cli_validity,
           { "CLI Validity",                     "bthfp.at.cli_validity",
           FT_UINT8, BASE_DEC, VALS(cli_validity_vals), 0,
           NULL, HFILL}
        },
        { &hf_at_priority,
           { "Priority",                         "bthfp.at.priority",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_clcc_id,
           { "ID",                               "bthfp.clcc.id",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_clcc_dir,
           { "Direction",                        "bthfp.clcc.dir",
           FT_UINT32, BASE_DEC, VALS(clcc_dir_vals), 0,
           NULL, HFILL}
        },
        { &hf_clcc_stat,
           { "State",                            "bthfp.clcc.stat",
           FT_UINT32, BASE_DEC, VALS(clcc_stat_vals), 0,
           NULL, HFILL}
        },
        { &hf_clcc_mode,
           { "Mode",                             "bthfp.clcc.mode",
           FT_UINT32, BASE_DEC, VALS(clcc_mode_vals), 0,
           NULL, HFILL}
        },
        { &hf_clcc_mpty,
           { "Mpty",                             "bthfp.clcc.mpty",
           FT_UINT32, BASE_DEC, VALS(clcc_mpty_vals), 0,
           NULL, HFILL}
        },
        { &hf_ccwa_show_result_code,
           { "Show Result Code Presentation Status",       "bthfp.ccwa.presentation_status",
           FT_UINT32, BASE_DEC, VALS(ccwa_show_result_code_vals), 0,
           NULL, HFILL}
        },
        { &hf_ccwa_mode,
           { "Mode",                             "bthfp.ccwa.mode",
           FT_UINT32, BASE_DEC, VALS(ccwa_mode_vals), 0,
           NULL, HFILL}
        },
        { &hf_ccwa_class,
           { "Class",                             "bthfp.ccwa.class",
           FT_UINT32, BASE_DEC, VALS(ccwa_class_vals), 0,
           NULL, HFILL}
        },
        { &hf_biev_assigned_number,
           { "Assigned Number",                  "bthfp.biev.assigned_number",
           FT_UINT16, BASE_DEC, VALS(biev_assigned_number_vals), 0,
           NULL, HFILL}
        },
        { &hf_bind_parameter,
           { "Parameter",                        "bthfp.bind.parameter",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_biev_value,
           { "Value",                            "bthfp.biev.value",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[0],
           { "Indicator 1",                      "bthfp.bia.indicator.1",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[1],
           { "Indicator 2",                      "bthfp.bia.indicator.2",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[2],
           { "Indicator 3",                      "bthfp.bia.indicator.3",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[3],
           { "Indicator 4",                      "bthfp.bia.indicator.4",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[4],
           { "Indicator 5",                      "bthfp.bia.indicator.5",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[5],
           { "Indicator 6",                      "bthfp.bia.indicator.6",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[6],
           { "Indicator 7",                      "bthfp.bia.indicator.7",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[7],
           { "Indicator 8",                      "bthfp.bia.indicator.8",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[8],
           { "Indicator 9",                      "bthfp.bia.indicator.9",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[9],
           { "Indicator 10",                     "bthfp.bia.indicator.10",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[10],
           { "Indicator 11",                     "bthfp.bia.indicator.11",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[11],
           { "Indicator 12",                     "bthfp.bia.indicator.12",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[12],
           { "Indicator 13",                     "bthfp.bia.indicator.13",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[13],
           { "Indicator 14",                     "bthfp.bia.indicator.14",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[14],
           { "Indicator 15",                     "bthfp.bia.indicator.15",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[15],
           { "Indicator 16",                     "bthfp.bia.indicator.16",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[16],
           { "Indicator 17",                     "bthfp.bia.indicator.17",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[17],
           { "Indicator 18",                     "bthfp.bia.indicator.18",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[18],
           { "Indicator 19",                     "bthfp.bia.indicator.19",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_bia_indicator[19],
           { "Indicator 20",                     "bthfp.bia.indicator.20",
           FT_UINT8, BASE_DEC, VALS(indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_indicator[0],
           { "Indicator 1",                      "bthfp.indicator.1",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[1],
           { "Indicator 2",                      "bthfp.indicator.2",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[2],
           { "Indicator 3",                      "bthfp.indicator.3",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[3],
           { "Indicator 4",                      "bthfp.indicator.4",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[4],
           { "Indicator 5",                      "bthfp.indicator.5",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[5],
           { "Indicator 6",                      "bthfp.indicator.6",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[6],
           { "Indicator 7",                      "bthfp.indicator.7",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[7],
           { "Indicator 8",                      "bthfp.indicator.8",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[8],
           { "Indicator 9",                      "bthfp.indicator.9",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[9],
           { "Indicator 10",                     "bthfp.indicator.10",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[10],
           { "Indicator 11",                     "bthfp.indicator.11",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[11],
           { "Indicator 12",                     "bthfp.indicator.12",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[12],
           { "Indicator 13",                     "bthfp.indicator.13",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[13],
           { "Indicator 14",                     "bthfp.indicator.14",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[14],
           { "Indicator 15",                     "bthfp.indicator.15",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[15],
           { "Indicator 16",                     "bthfp.indicator.16",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[16],
           { "Indicator 17",                     "bthfp.indicator.17",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[17],
           { "Indicator 18",                     "bthfp.indicator.18",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[18],
           { "Indicator 19",                     "bthfp.indicator.19",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[19],
           { "Indicator 20",                     "bthfp.indicator.20",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_aplefm_state,
           { "State",                            "bthfp.aplefm.state",
           FT_UINT16, BASE_DEC, VALS(aplefm_state_vals), 0,
           NULL, HFILL}
        },
        { &hf_aplsiri_state,
           { "Siri State",                       "bthfp.aplsiri.state",
           FT_UINT16, BASE_DEC, VALS(aplsiri_state_vals), 0,
           NULL, HFILL}
        },
        { &hf_iphoneaccev_count,
           { "Count",                            "bthfp.iphoneaccev.count",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_iphoneaccev_key,
           { "Key",                              "bthfp.iphoneaccev.key",
           FT_UINT16, BASE_DEC, VALS(iphoneaccev_key_vals), 0,
           NULL, HFILL}
        },
        { &hf_iphoneaccev_value,
           { "Value",                            "bthfp.iphoneaccev.value",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_xapl_accessory_info,
           { "Accessory Info",                   "bthfp.xapl.accessory_info",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_xapl_accessory_info_vendor_id,
           { "Vendor ID",                        "bthfp.xapl.accessory_info.vendor_id",
           FT_UINT32, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        { &hf_xapl_accessory_info_product_id,
           { "Product ID",                       "bthfp.xapl.accessory_info.product_id",
           FT_UINT16, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        { &hf_xapl_accessory_info_version,
           { "Version",                          "bthfp.xapl.accessory_info.version",
           FT_UINT16, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        { &hf_xapl_host_info,
           { "Host Info",                        "bthfp.xapl.host_info",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_xapl_features,
           { "Features",                         "bthfp.xapl.features",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_xapl_features_reserved,
           { "Reserved",                         "bthfp.xapl.features.reserved.0",
           FT_BOOLEAN, 32, NULL, 0x00000001,
           NULL, HFILL}
        },
        { &hf_xapl_features_battery_reporting,
           { "Battery Reporting",                "bthfp.xapl.features.battery_reporting",
           FT_BOOLEAN, 32, NULL, 0x00000002,
           NULL, HFILL}
        },
        { &hf_xapl_features_docked_or_powered,
           { "Accessory is Docked or Powered",   "bthfp.xapl.features.docked_or_powered",
           FT_BOOLEAN, 32, NULL, 0x00000004,
           NULL, HFILL}
        },
        { &hf_xapl_features_siri_status_reporting,
           { "Siri Status Reporting",            "bthfp.xapl.features.siri_status_reporting",
           FT_BOOLEAN, 32, NULL, 0x00000008,
           NULL, HFILL}
        },
        { &hf_xapl_features_noise_reduction_status_reporting,
           { "Noise Reduction Status Reporting", "bthfp.xapl.features.noise_reduction_status_reporting",
           FT_BOOLEAN, 32, NULL, 0x00000010,
           NULL, HFILL}
        },
        { &hf_xapl_features_reserved_x,
           { "Reserved",                         "bthfp.xapl.features.reserved.x",
           FT_BOOLEAN, 32, NULL, 0xFFFFFFE0,
           NULL, HFILL}
        }
    };

    static ei_register_info ei[] = {
        { &ei_non_mandatory_command, { "bthfp.expert.non_mandatory_command", PI_PROTOCOL, PI_NOTE, "Non-mandatory command in HFP", EXPFILL }},
        { &ei_invalid_usage,         { "bthfp.expert.invalid_usage", PI_PROTOCOL, PI_WARN, "Non mandatory type or command in this role", EXPFILL }},
        { &ei_unknown_parameter,     { "bthfp.expert.unknown_parameter", PI_PROTOCOL, PI_WARN, "Unknown parameter", EXPFILL }},
        { &ei_brfs_hs_reserved_bits, { "bthfp.expert.brsf.hs.reserved_bits", PI_PROTOCOL, PI_WARN, "The reserved bits [10-31] shall be initialized to Zero", EXPFILL }},
        { &ei_brfs_ag_reserved_bits, { "bthfp.expert.brsf.ag.reserved_bits", PI_PROTOCOL, PI_WARN, "The reserved bits [12-31] shall be initialized to Zero", EXPFILL }},
        { &ei_vgm_gain,              { "bthfp.expert.vgm", PI_PROTOCOL, PI_WARN, "Gain of microphone exceeds range 0-15", EXPFILL }},
        { &ei_vgs_gain,              { "bthfp.expert.vgs", PI_PROTOCOL, PI_WARN, "Gain of speaker exceeds range 0-15", EXPFILL }},
        { &ei_nrec,                  { "bthfp.expert.nrec", PI_PROTOCOL, PI_WARN, "Only 0 is valid", EXPFILL }},
        { &ei_bvra,                  { "bthfp.expert.bvra", PI_PROTOCOL, PI_WARN, "Only 0-1 is valid", EXPFILL }},
        { &ei_bcs,                   { "bthfp.expert.bcs", PI_PROTOCOL, PI_NOTE, "Reserved value", EXPFILL }},
        { &ei_bac,                   { "bthfp.expert.bac", PI_PROTOCOL, PI_NOTE, "Reserved value", EXPFILL }},
        { &ei_bsir,                  { "bthfp.expert.bsir", PI_PROTOCOL, PI_WARN, "Only 0-1 is valid", EXPFILL }},
        { &ei_btrh,                  { "bthfp.expert.btrh", PI_PROTOCOL, PI_WARN, "Only 0-2 is valid", EXPFILL }},
        { &ei_binp,                  { "bthfp.expert.binp", PI_PROTOCOL, PI_WARN, "Only 1 is valid", EXPFILL }},
        { &ei_bia,                   { "bthfp.expert.bia", PI_PROTOCOL, PI_WARN, "Only 0-1 is valid", EXPFILL }},
        { &ei_biev_assigned_number,  { "bthfp.expert.biev.assigned_number", PI_PROTOCOL, PI_WARN, "Only 0-65535 is valid", EXPFILL }},
        { &ei_biev_assigned_number_no, { "bthfp.expert.biev.assigned_number.not_assigned", PI_PROTOCOL, PI_WARN, "Value is unknown for Assign Numbers", EXPFILL }},
        { &ei_cmer_mode,             { "bthfp.expert.cmer.mode", PI_PROTOCOL, PI_NOTE, "Only 3 is valid for HFP", EXPFILL }},
        { &ei_cmer_disp,             { "bthfp.expert.cmer.disp", PI_PROTOCOL, PI_WARN, "Value is ignored for HFP", EXPFILL }},
        { &ei_cmer_keyp,             { "bthfp.expert.cmer.keyp", PI_PROTOCOL, PI_WARN, "Value is ignored for HFP", EXPFILL }},
        { &ei_cmer_ind,              { "bthfp.expert.cmer.ind", PI_PROTOCOL, PI_NOTE, "Only 0-1 is valid for HFP", EXPFILL }},
        { &ei_cmer_btr,              { "bthfp.expert.cmer.btr", PI_PROTOCOL, PI_WARN, "Value is ignored for HFP", EXPFILL }},
        { &ei_chld_mode,             { "bthfp.expert.chld.mode", PI_PROTOCOL, PI_WARN, "Invalid value for HFP", EXPFILL }},
        { &ei_ciev_indicator,        { "bthfp.expert.ciev.indicator", PI_PROTOCOL, PI_WARN, "Unknown indicator", EXPFILL }},
        { &ei_vts_dtmf,              { "bthfp.expert.vts.dtmf", PI_PROTOCOL, PI_WARN, "DTMF should be single character", EXPFILL }},
        { &ei_at_type,               { "bthfp.expert.at.type", PI_PROTOCOL, PI_WARN, "Unknown type value", EXPFILL }},
        { &ei_parameter_blank,       { "bthfp.expert.parameter_blank", PI_PROTOCOL, PI_WARN, "Should be blank for HFP", EXPFILL }},
        { &ei_cnum_service,          { "bthfp.expert.cnum.service", PI_PROTOCOL, PI_WARN, "Only 0-5 is valid", EXPFILL }},
        { &ei_cnum_itc,              { "bthfp.expert.cnum.itc", PI_PROTOCOL, PI_WARN, "Only 0-1 is valid", EXPFILL }},
        { &ei_aplefm_out_of_range,   { "bthfp.expert.aplefm.out_of_range", PI_PROTOCOL, PI_WARN, "Only 0-1 is valid", EXPFILL }},
        { &ei_aplsiri_out_of_range,  { "bthfp.expert.aplsiri.out_of_range", PI_PROTOCOL, PI_WARN, "Only 1-2 is valid", EXPFILL }},
        { &ei_iphoneaccev_key_out_of_range,  { "bthfp.expert.iphoneaccev.out_of_range", PI_PROTOCOL, PI_WARN, "Only 1-2 is valid", EXPFILL }},
        { &ei_xapl_features_reserved, { "bthfp.expert.xapl.reserved", PI_PROTOCOL, PI_WARN, "The reserved bits [6-31] shall be initialized to Zero", EXPFILL }}
    };

    static int *ett[] = {
        &ett_bthfp,
        &ett_bthfp_brsf_hf,
        &ett_bthfp_brsf_ag,
        &ett_bthfp_command,
        &ett_bthfp_parameters,
        &ett_bthfp_xapl_features,
        &ett_bthfp_xapl_accessory_info
    };

    fragments = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_bthfp = proto_register_protocol("Bluetooth HFP Profile", "BT HFP", "bthfp");
    bthfp_handle = register_dissector("bthfp", dissect_bthfp, proto_bthfp);

    proto_register_field_array(proto_bthfp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module = prefs_register_protocol_subtree("Bluetooth", proto_bthfp, NULL);
    prefs_register_static_text_preference(module, "hfp.version",
            "Bluetooth Profile HFP version: 1.7",
            "Version of profile supported by this dissector.");

    prefs_register_enum_preference(module, "hfp.hfp_role",
            "Force treat packets as AG or HS role",
            "Force treat packets as AG or HS role",
            &hfp_role, pref_hfp_role, true);

    expert_bthfp = expert_register_protocol(proto_bthfp);
    expert_register_field_array(expert_bthfp, ei, array_length(ei));
}

void
proto_reg_handoff_bthfp(void)
{
    dissector_add_string("bluetooth.uuid", "111e", bthfp_handle);
    dissector_add_string("bluetooth.uuid", "111f", bthfp_handle);

    dissector_add_for_decode_as("btrfcomm.dlci", bthfp_handle);
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
