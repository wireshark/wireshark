/* packet-at.c
 * Dissector for AT Commands
 *
 * Copyright 2011, Tyson Key <tyson.key@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_at_command(void);
void proto_reg_handoff_at_command(void);

static int proto_at = -1;

static int hf_command                                                      = -1;
static int hf_parameters                                                   = -1;
static int hf_role                                                         = -1;
static int hf_at_cmd                                                       = -1;
static int hf_at_cmd_type                                                  = -1;
static int hf_at_command_line_prefix                                       = -1;
static int hf_at_ignored                                                   = -1;
static int hf_parameter                                                    = -1;
static int hf_unknown_parameter                                            = -1;
static int hf_data                                                         = -1;
static int hf_chld_mode                                                    = -1;
static int hf_chld_mode_1x                                                 = -1;
static int hf_chld_mode_2x                                                 = -1;
static int hf_chld_supported_modes                                         = -1;
static int hf_cmer_mode                                                    = -1;
static int hf_cmer_keyp                                                    = -1;
static int hf_cmer_disp                                                    = -1;
static int hf_cmer_ind                                                     = -1;
static int hf_cmer_bfr                                                     = -1;
static int hf_cmee                                                         = -1;
static int hf_cme_error                                                    = -1;
static int hf_cme_error_verbose                                            = -1;
static int hf_cnum_speed                                                   = -1;
static int hf_cnum_service                                                 = -1;
static int hf_cnum_itc                                                     = -1;
static int hf_ciev_indicator_index                                         = -1;
static int hf_vts_dtmf                                                     = -1;
static int hf_vts_duration                                                 = -1;
static int hf_cops_mode                                                    = -1;
static int hf_cops_format                                                  = -1;
static int hf_cops_operator                                                = -1;
static int hf_cops_act                                                     = -1;
static int hf_at_number                                                    = -1;
static int hf_at_type                                                      = -1;
static int hf_at_subaddress                                                = -1;
static int hf_at_subaddress_type                                           = -1;
static int hf_at_alpha                                                     = -1;
static int hf_at_priority                                                  = -1;
static int hf_at_cli_validity                                              = -1;
static int hf_clip_mode                                                    = -1;
static int hf_clip_status                                                  = -1;
static int hf_clcc_id                                                      = -1;
static int hf_clcc_dir                                                     = -1;
static int hf_clcc_stat                                                    = -1;
static int hf_clcc_mode                                                    = -1;
static int hf_clcc_mpty                                                    = -1;
static int hf_ccwa_show_result_code                                        = -1;
static int hf_ccwa_mode                                                    = -1;
static int hf_ccwa_class                                                   = -1;
static int hf_cgmm_model_id                                                = -1;
static int hf_indicator[20] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

static expert_field ei_unknown_command                                = EI_INIT;
static expert_field ei_invalid_usage                                  = EI_INIT;
static expert_field ei_unknown_parameter                              = EI_INIT;
static expert_field ei_cmer_mode                                      = EI_INIT;
static expert_field ei_cmer_keyp                                      = EI_INIT;
static expert_field ei_cmer_disp                                      = EI_INIT;
static expert_field ei_cmer_ind                                       = EI_INIT;
static expert_field ei_cmer_bfr                                       = EI_INIT;
static expert_field ei_chld_mode                                      = EI_INIT;
static expert_field ei_ciev_indicator                                 = EI_INIT;
static expert_field ei_vts_dtmf                                       = EI_INIT;
static expert_field ei_at_type                                        = EI_INIT;
static expert_field ei_cnum_service                                   = EI_INIT;
static expert_field ei_cnum_itc                                       = EI_INIT;

/* Subtree handles: set by register_subtree_array */
static gint ett_at = -1;
static gint ett_at_command    = -1;
static gint ett_at_parameters = -1;

#define ROLE_UNKNOWN   0
#define ROLE_DCE       1
#define ROLE_DTE       2

#define TYPE_UNKNOWN       0x0000
#define TYPE_RESPONSE_ACK  0x0d0a
#define TYPE_RESPONSE      0x003a
#define TYPE_ACTION        0x003d
#define TYPE_ACTION_SIMPLY 0x000d
#define TYPE_READ          0x003f
#define TYPE_TEST          0x3d3f

static gint at_role = ROLE_UNKNOWN;

static const value_string role_vals[] = {
    { ROLE_UNKNOWN,   "Unknown" },
    { ROLE_DCE,        "DCE - Data Circuit terminating Equipment" },
    { ROLE_DTE,        "DTE - Data Terminal Equipment (PC)" },
    { 0, NULL }
};

static const enum_val_t pref_at_role[] = {
    { "off",     "Off",                    ROLE_UNKNOWN },
    { "dte",      "Sent is DTE, Rcvd is DCE", ROLE_DTE },
    { "dce",      "Sent is DCE, Rcvd is DTE", ROLE_DCE },
    { NULL, NULL, 0 }
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
    {  43,   "Network Subset upersonalization PUK Required" },
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
    { 3,   "GSM with EGPRS" },
    { 4,   "UTRAN with HSDPA" },
    { 5,   "UTRAN with HSUPA" },
    { 6,   "UTRAN with HSDPA and HSUPA" },
    { 7,   "E-UTRAN" },
    { 8,   "EC-GSM-IoT (A/Gb mode)" },
    { 9,   "E-UTRAN (NB-S1 mode)" },
    { 10,  "E-UTRA connected to a 5GCN" },
    { 11,  "NR connected to a 5GCCN" },
    { 12,  "NR connected to an EPS core" },
    { 13,  "NG-RAN" },
    { 14,  "E-UTRA-NR dual connectivity" },
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

extern value_string_ext csd_data_rate_vals_ext;

typedef struct _at_cmd_t {
    const guint8 *name;
    const guint8 *long_name;

    gboolean (*check_command)(gint role, guint16 type);
    gboolean (*dissect_parameter)(tvbuff_t *tvb, packet_info *pinfo,
            proto_tree *tree, gint offset, gint role, guint16 type,
            guint8 *parameter_stream, guint parameter_number,
            gint parameter_length, void **data);
} at_cmd_t;


static guint32 get_uint_parameter(guint8 *parameter_stream, gint parameter_length)
{
    guint32      value;
    guint8      *val;

    val = (guint8 *) wmem_alloc(wmem_packet_scope(), parameter_length + 1);
    memcpy(val, parameter_stream, parameter_length);
    val[parameter_length] = '\0';
    value = (guint32) g_ascii_strtoull(val, NULL, 10);

    return value;
}

static gboolean check_only_dce_role(gint role, guint16 type) {
    if (role == ROLE_DCE && type == TYPE_RESPONSE_ACK) return TRUE;

    return FALSE;
}

static gboolean check_only_dte_role(gint role, guint16 type) {
    if (role == ROLE_DTE && type == TYPE_ACTION_SIMPLY) return TRUE;

    return FALSE;
}

static gboolean check_ccwa(gint role, guint16 type) {
    if (role == ROLE_DTE && (type == TYPE_ACTION || type == TYPE_READ || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_DCE && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_cgmm(gint role, guint16 type) {
    if (role == ROLE_DTE && (type == TYPE_ACTION_SIMPLY || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_DCE && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_chld(gint role, guint16 type) {
    if (role == ROLE_DTE && (type == TYPE_ACTION || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_DCE && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_chup(gint role, guint16 type) {
    if (role == ROLE_DTE && (type == TYPE_ACTION_SIMPLY || type == TYPE_TEST)) return TRUE;

    return FALSE;
}

static gboolean check_clcc(gint role, guint16 type) {
    if (role == ROLE_DTE && (type == TYPE_ACTION_SIMPLY || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_DCE && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_cind(gint role, guint16 type) {
    if (role == ROLE_DTE && (type == TYPE_READ || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_DCE && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_cmer(gint role, guint16 type) {
    if (role == ROLE_DTE && (type == TYPE_ACTION || type == TYPE_READ || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_DCE && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_cops(gint role, guint16 type) {
    if (role == ROLE_DTE && (type == TYPE_ACTION || type == TYPE_READ)) return TRUE;
    if (role == ROLE_DCE && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_cmee(gint role, guint16 type) {
    if (role == ROLE_DTE && type == TYPE_ACTION) return TRUE;

    return FALSE;
}

static gboolean check_cme(gint role, guint16 type) {
    if (role == ROLE_DCE && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_clip(gint role, guint16 type) {
    if (role == ROLE_DTE && (type == TYPE_ACTION || type == TYPE_READ || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_DCE && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_ciev(gint role, guint16 type) {
    if (role == ROLE_DCE && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_vts(gint role, guint16 type) {
    if (role == ROLE_DTE && (type == TYPE_ACTION || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_DCE && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_cnum(gint role, guint16 type) {
    if (role == ROLE_DTE && type == TYPE_ACTION_SIMPLY) return TRUE;
    if (role == ROLE_DCE && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gint
dissect_cind_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream _U_,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    if (!check_cind(role, type)) return FALSE;
    if (parameter_number > 19) return FALSE;

    proto_tree_add_item(tree, hf_indicator[parameter_number], tvb, offset,
            parameter_length, ENC_NA | ENC_ASCII);

    return TRUE;
}

static gint
dissect_chld_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    guint32      value;

    if (!check_chld(role, type)) return FALSE;

    if (role == ROLE_DTE && type == TYPE_ACTION && parameter_number == 0) {
        value = get_uint_parameter(parameter_stream, 1);

        if (parameter_length >= 2) {
            if (tvb_get_guint8(tvb, offset + 1) == 'x') {
                if (value == 1)
                    proto_tree_add_item(tree, hf_chld_mode_1x, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
                else if (value == 2)
                    proto_tree_add_item(tree, hf_chld_mode_2x, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
            }

            if (tvb_get_guint8(tvb, offset + 1) != 'x' || value > 4) {
                proto_tree_add_expert(tree, pinfo, &ei_chld_mode, tvb, offset, parameter_length);
            }
        }

        proto_tree_add_uint(tree, hf_chld_mode, tvb, offset, parameter_length, value);
        return TRUE;
    }

    /* Type == Test  */
    proto_tree_add_item(tree, hf_chld_supported_modes, tvb, offset,
            parameter_length, ENC_NA | ENC_ASCII);

    return TRUE;
}

static gint
dissect_ccwa_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    proto_item  *pitem;
    guint32      value;

    if (!check_ccwa(role, type)) return FALSE;

    if (role == ROLE_DTE && parameter_number > 2) return FALSE;
    if (role == ROLE_DCE && parameter_number > 7) return FALSE;

    if (role == ROLE_DTE) switch (parameter_number) {
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
    if (role == ROLE_DCE) switch (parameter_number) {
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

    return TRUE;
}

static gint
dissect_cgmm_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream _U_,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    if (!(role == ROLE_DCE && type == TYPE_RESPONSE)) {
        return FALSE;
    }

    if (parameter_number > 1) return FALSE;

    proto_tree_add_item(tree, hf_cgmm_model_id, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);

    return TRUE;
}

static gint
dissect_cmer_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    proto_item  *pitem;
    guint32      value;

    if (!((role == ROLE_DTE && type == TYPE_ACTION))) {
        return FALSE;
    }

    if (parameter_number > 4) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);

    switch (parameter_number) {
        case 0:
            pitem = proto_tree_add_uint(tree, hf_cmer_mode, tvb, offset, parameter_length, value);
            if (value > 3)
                expert_add_info(pinfo, pitem, &ei_cmer_mode);
            break;
        case 1:
            pitem = proto_tree_add_uint(tree, hf_cmer_keyp, tvb, offset, parameter_length, value);
            if (value > 2)
                expert_add_info(pinfo, pitem, &ei_cmer_keyp);
            break;
        case 2:
            pitem = proto_tree_add_uint(tree, hf_cmer_disp, tvb, offset, parameter_length, value);
            if (value > 2)
                expert_add_info(pinfo, pitem, &ei_cmer_disp);
            break;
        case 3:
            pitem = proto_tree_add_uint(tree, hf_cmer_ind, tvb, offset, parameter_length, value);
            if (value > 2)
                expert_add_info(pinfo, pitem, &ei_cmer_ind);
            break;
        case 4:
            pitem = proto_tree_add_uint(tree, hf_cmer_bfr, tvb, offset, parameter_length, value);
            if (value > 1)
                expert_add_info(pinfo, pitem, &ei_cmer_bfr);
            break;
    }

    return TRUE;
}

static gint
dissect_clip_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    proto_item  *pitem;
    guint32      value;

    if (!check_clip(role, type))
        return FALSE;

    if (role == ROLE_DTE && type == TYPE_ACTION && parameter_number > 1)
        return FALSE;
    else if (role == ROLE_DCE && parameter_number > 5)
        return FALSE;

    if (role == ROLE_DTE && type == TYPE_ACTION) switch (parameter_number) {
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

    return TRUE;
}

static gint
dissect_cmee_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    guint32      value;

    if (!(role == ROLE_DTE && type == TYPE_ACTION)) {
        return FALSE;
    }

    if (parameter_number > 0) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);
    proto_tree_add_uint(tree, hf_cmee, tvb, offset, parameter_length, value);

    return TRUE;
}

static gint
dissect_cops_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    guint32      value;

    if (!((role == ROLE_DTE && (type == TYPE_ACTION || type == TYPE_READ)) ||
            (role == ROLE_DCE && type == TYPE_RESPONSE))) {
        return FALSE;
    }

    if (parameter_number > 3) return FALSE;

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

    return TRUE;
}

static gint
dissect_clcc_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    proto_item  *pitem;
    guint32      value;

    if (!((role == ROLE_DTE && type == TYPE_ACTION_SIMPLY) ||
            (role == ROLE_DCE && type == TYPE_RESPONSE))) {
        return FALSE;
    }

    if (parameter_number > 8) return FALSE;

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

    return TRUE;
}


static gint
dissect_cme_error_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    guint32      value;
    gint         i;
    guint8      *next_char;

    if (!(role == ROLE_DCE && type == TYPE_RESPONSE)) {
        return FALSE;
    }

    if (parameter_number > 0) return FALSE;

    /* CME Error might work in 2 modes: Numeric error codes or Verbose error messages */
    /* if the parameter stream contains any letters, assume verbose */
    next_char = parameter_stream;
    for (i = 0; i < parameter_length; i++) {
        if (g_ascii_isalpha(next_char)) {
            proto_tree_add_item(tree, hf_cme_error_verbose, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
            return TRUE;
        }
        next_char++;
    }
    /* Assume numeric error code*/
    value = get_uint_parameter(parameter_stream, parameter_length);
    proto_tree_add_uint(tree, hf_cme_error, tvb, offset, parameter_length, value);

    return TRUE;
}

static gint
dissect_cnum_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    proto_item  *pitem;
    guint32      value;

    if (!(role == ROLE_DCE && type == TYPE_RESPONSE)) return TRUE;
    if (parameter_number > 5) return FALSE;

    switch (parameter_number) {
    case 0:
        proto_tree_add_item(tree, hf_at_alpha, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
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
        proto_tree_add_uint(tree, hf_cnum_speed, tvb, offset, parameter_length, value);
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

    return TRUE;
}

static gint
dissect_vts_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data _U_)
{
    proto_item  *pitem;
    guint32      value;

    if (!(role == ROLE_DTE && type == TYPE_ACTION)) return TRUE;
    if (parameter_number > 1) return FALSE;

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

    return TRUE;
}

static gint
dissect_ciev_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length, void **data)
{
    guint32      value;
    guint        indicator_index;

    if (!(role == ROLE_DCE && type == TYPE_RESPONSE)) return TRUE;
    if (parameter_number > 1) return FALSE;

    switch (parameter_number) {
    case 0:
        value = get_uint_parameter(parameter_stream, parameter_length);
        proto_tree_add_uint(tree, hf_ciev_indicator_index, tvb, offset, parameter_length, value);
        *data = wmem_alloc(wmem_packet_scope(), sizeof(guint));
        *((guint *) *data) = value;
        break;
    case 1:
        indicator_index = *((guint *) *data) - 1;
        if (indicator_index > 19) {
            proto_tree_add_expert(tree, pinfo, &ei_ciev_indicator, tvb, offset, parameter_length);
        } else {
            proto_tree_add_item(tree, hf_indicator[indicator_index], tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
        }
        break;
    }

    return TRUE;
}

static gint
dissect_no_parameter(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_,
        gint offset _U_, gint role _U_, guint16 type _U_, guint8 *parameter_stream _U_,
        guint parameter_number _U_, gint parameter_length _U_, void **data _U_)
{
    return FALSE;
}

/* TODO: Some commands need to save request command type (request with TYPE_READ vs TYPE_TEST, etc.)
         to properly dissect response parameters.
         Some commands can use TYPE_TEST respose to properly dissect parameters,
         for example: AT+CIND=?, AT+CIND? */
static const at_cmd_t at_cmds[] = {
    { "+CCWA",      "Call Waiting Notification",                  check_ccwa, dissect_ccwa_parameter },
    { "+CGMM",      "Request model identification",               check_cgmm, dissect_cgmm_parameter },
    { "+CHLD",      "Call Hold and Multiparty Handling",          check_chld, dissect_chld_parameter },
    { "+CHUP",      "Call Hang-up",                               check_chup, dissect_no_parameter   },
    { "+CIND",      "Phone Indicators",                           check_cind, dissect_cind_parameter },
    { "+CLCC",      "Current Calls",                              check_clcc, dissect_clcc_parameter },
    { "+COPS",      "Reading Network Operator",                   check_cops, dissect_cops_parameter },
    { "+CMEE",      "Mobile Equipment Error",                     check_cmee, dissect_cmee_parameter },
    { "+CME ERROR", "Extended Audio Gateway Error Result Code",   check_cme,  dissect_cme_error_parameter },
    { "+CLIP",      "Calling Line Identification Notification",   check_clip, dissect_clip_parameter },
    { "+CMER",      "Event Reporting Activation/Deactivation",    check_cmer, dissect_cmer_parameter },
    { "+CIEV",      "Indicator Events Reporting",                 check_ciev, dissect_ciev_parameter },
    { "+VTS",       "DTMF and tone generation",                   check_vts,  dissect_vts_parameter  },
    { "+CNUM",      "Subscriber Number Information",              check_cnum, dissect_cnum_parameter },
    { "ERROR",      "ERROR",                                      check_only_dce_role, dissect_no_parameter },
    { "RING",       "Incoming Call Indication",                   check_only_dce_role, dissect_no_parameter },
    { "OK",         "OK",                                         check_only_dce_role, dissect_no_parameter },
    { "D",          "Dial",                                       check_only_dte_role, NULL },
    { "A",          "Call Answer",                                check_only_dte_role, dissect_no_parameter },
    { "E0",         "Disable Echo",                               check_only_dte_role, dissect_no_parameter },
    { "E1",         "Enable Echo",                                check_only_dte_role, dissect_no_parameter },
    { "I",          "Product Identification Information",         check_only_dte_role, dissect_no_parameter },
    { NULL, NULL, NULL, NULL }
};

static gint
dissect_at_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, guint32 role, gint command_number)
{
    proto_item      *pitem;
    proto_tree      *command_item = NULL;
    proto_item      *command_tree = NULL;
    proto_tree      *parameters_item = NULL;
    proto_item      *parameters_tree = NULL;
    guint8          *col_str = NULL;
    guint8          *at_stream;
    guint8          *at_command = NULL;
    gint             i_char = 0;
    guint            i_char_fix = 0;
    gint             length;
    const at_cmd_t  *i_at_cmd;
    gint             parameter_length;
    guint            parameter_number = 0;
    gint             first_parameter_offset = offset;
    gint             last_parameter_offset  = offset;
    guint16          type = TYPE_UNKNOWN;
    guint32          brackets;
    gboolean         quotation;
    gboolean         next;
    void            *data;

    length = tvb_reported_length_remaining(tvb, offset);
    if (length <= 0)
        return tvb_reported_length(tvb);

    if (!command_number) {
        proto_tree_add_item(tree, hf_data, tvb, offset, length, ENC_NA | ENC_ASCII);
        col_str = (guint8 *) wmem_alloc(wmem_packet_scope(), length + 1);
        tvb_memcpy(tvb, col_str, offset, length);
        col_str[length] = '\0';
    }

    at_stream = (guint8 *) wmem_alloc(wmem_packet_scope(), length + 1);
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

    if (role == ROLE_DTE) {
        if (command_number) {
            at_command = at_stream;
            i_char = 0;
        } else {
            at_command = g_strstr_len(at_stream, length, "AT");
            if (at_command) {
                command_item = proto_tree_add_none_format(tree, hf_command, tvb,
                        offset, 0, "Command %u", command_number);
                command_tree = proto_item_add_subtree(command_item, ett_at_command);

                i_char = (guint) (at_command - at_stream);
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
        command_tree = proto_item_add_subtree(command_item, ett_at_command);

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
                            (gint) strlen(i_at_cmd->name), ENC_NA | ENC_ASCII);
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

            name = (char *) wmem_alloc(wmem_packet_scope(), i_char + 2);
            g_strlcpy(name, at_command, i_char + 1);
            name[i_char + 1] = '\0';
            proto_item_append_text(command_item, ": %s (Unknown)", name);
            proto_item_append_text(pitem, " (Unknown)");
            expert_add_info(pinfo, pitem, &ei_unknown_command);
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
            } else if (role == ROLE_DCE && length >= 2 && at_command[i_char] == '\r' && at_command[i_char + 1] == '\n') {
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
        parameters_tree = proto_item_add_subtree(parameters_item, ett_at_parameters);
        first_parameter_offset = offset;

        data = NULL;

        while (i_char < length) {

            while (at_command[i_char] == ' ' || at_command[i_char]  == '\t') {
                offset += 1;
                i_char += 1;
            }

            parameter_length = 0;
            brackets = 0;
            quotation = FALSE;
            next = FALSE;

            if (at_command[i_char + parameter_length] != '\r') {
                while (i_char + parameter_length < length &&
                        at_command[i_char + parameter_length] != '\r') {

                    if (at_command[i_char + parameter_length] == ';') {
                        next = TRUE;
                        break;
                    }

                    if (at_command[i_char + parameter_length] == '"') {
                        quotation = quotation ? FALSE : TRUE;
                    }

                    if (quotation == TRUE) {
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

            if (role == ROLE_DCE &&
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


/* The dissector itself */
static int dissect_at(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *item;
    proto_tree *at_tree;
    gchar      *string;
    guint32     role = ROLE_UNKNOWN;
    gint        offset;
    gint        len;
    guint32         cmd_indx;

    string = tvb_format_text_wsp(wmem_packet_scope(), tvb, 0, tvb_captured_length(tvb));
    col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "AT");
    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Rcvd ");
            break;
        default:
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "UnknownDirection ");
            break;
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, "AT Command: %s", string);

    /* Check if user forces roles using preferences */
    if ((at_role == ROLE_DCE && pinfo->p2p_dir == P2P_DIR_SENT) ||
            (at_role == ROLE_DTE && pinfo->p2p_dir == P2P_DIR_RECV)) {
        role = ROLE_DCE;
    } else if (at_role != ROLE_UNKNOWN) {
        role = ROLE_DTE;
    }

    /* If no roles are forced, assume SENT from PC and RECV from device */
    if (role == ROLE_UNKNOWN) {
        if (pinfo->p2p_dir == P2P_DIR_SENT) {
            role = ROLE_DTE;
        } else {
            role = ROLE_DCE;
        }
    }

    /* Start with a top-level item to add everything else to */
    item = proto_tree_add_item(tree, proto_at, tvb, 0, -1, ENC_NA);
    proto_item_append_text(item, ": %s", string);
    at_tree = proto_item_add_subtree(item, ett_at);

    /* Show role in tree */
    item = proto_tree_add_uint(at_tree, hf_role, tvb, 0, 0, role);
    PROTO_ITEM_SET_GENERATED(item);


    /* Dissect command(s) */
    len = tvb_captured_length(tvb);
    offset = 0;
    cmd_indx = 0;
    while(offset < len) {
        offset = dissect_at_command(tvb, pinfo, at_tree, offset, role, cmd_indx);
        cmd_indx++;
    }

    return tvb_captured_length(tvb);
}

static gint allowed_chars_len(tvbuff_t *tvb, gint captured_len)
{
    gint offset;
    guint8 val;

    /* Get the amount of characters within the TVB which are ASCII,
     * cartridge return or new line */
    for (offset = 0; offset < captured_len; offset++) {
        val = tvb_get_guint8(tvb, offset);
        if (!(g_ascii_isprint(val) || (val == 0x0a) || (val == 0x0d)))
            return offset;
    }
    return captured_len;
}
static gboolean is_padded(tvbuff_t *tvb, gint captured_len, gint first_pad_offset)
{
    gint offset;
    guint8 val;

    /* Check if the rest of the packet is 0x00 padding
     * and no other values*/
    for (offset = first_pad_offset; offset < captured_len; offset++) {
        val = tvb_get_guint8(tvb, offset);
        if (val != 0x00)
            return (FALSE);
    }
    return (TRUE);
}

#define MIN_PADDED_ALLOWED_CHARS 4
/* Experimental approach based upon the one used for PPP */
static gboolean heur_dissect_at(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const gchar at_magic1[2] = {0x0d, 0x0a};
    const gchar at_magic2[3] = {0x0d, 0x0d, 0x0a};
    const gchar at_magic3[2] = {'A', 'T'};
    gint len, allwd_chars_len;
    tvbuff_t *tvb_no_padding;

    if ((tvb_memeql(tvb, 0, at_magic1, sizeof(at_magic1)) == 0) ||
        (tvb_memeql(tvb, 0, at_magic2, sizeof(at_magic2)) == 0) ||
        (tvb_memeql(tvb, 0, at_magic3, sizeof(at_magic3)) == 0)){
        len = tvb_captured_length(tvb);
        allwd_chars_len = allowed_chars_len(tvb,len);
        if(allwd_chars_len < len && allwd_chars_len > MIN_PADDED_ALLOWED_CHARS) {
            /* Found some valid characters, check if rest is padding */
            if(is_padded(tvb,len,allwd_chars_len)) {
                /* This is a padded AT Command */
                tvb_no_padding = tvb_new_subset_length_caplen(tvb, 0, allwd_chars_len, allwd_chars_len);
                dissect_at(tvb_no_padding, pinfo, tree, data);
                return (TRUE);
            }
        }
        else if(allwd_chars_len == len) {
            /* This is an (unpadded) AT Command */
            dissect_at(tvb, pinfo, tree, data);
            return (TRUE);
        }
    }
    return (FALSE);
}

void
proto_register_at_command(void)
{
    module_t         *module;
    expert_module_t  *expert_at;

    static hf_register_info hf[] = {
        { &hf_command,
           { "Command",                          "at.command",
           FT_NONE, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_parameters,
           { "Parameters",                       "at.parameters",
           FT_NONE, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_data,
           { "AT Stream",                        "at.data",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_ignored,
           { "Ignored",                          "at.ignored",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_cmd,
           { "Command",                          "at.cmd",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_cmd_type,
           { "Type",                             "at.cmd.type",
           FT_UINT16, BASE_HEX, VALS(at_cmd_type_vals), 0,
           NULL, HFILL}
        },
        { &hf_at_command_line_prefix,
           { "Command Line Prefix",              "at.command_line_prefix",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_parameter,
           { "Parameter",                        "at.parameter",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_unknown_parameter,
           { "Unknown Parameter",                "at.unknown_parameter",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_role,
           { "Role",                             "at.role",
           FT_UINT8, BASE_DEC, VALS(role_vals), 0,
           NULL, HFILL}
        },
        { &hf_cmer_mode,
           { "Mode",                             "at.cmer.mode",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cmer_keyp,
           { "Keypad",                           "at.cmer.keyp",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cmer_disp,
           { "Display",                          "at.cmer.disp",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cmer_ind,
           { "Indicator",                        "at.cmer.ind",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cmer_bfr,
           { "Buffer",                           "at.cmer.bfr",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cme_error,
           { "CME Error (Numeric)",              "at.cme_error",
           FT_UINT8, BASE_DEC, VALS(cme_error_vals), 0,
           NULL, HFILL}
        },
        { &hf_cme_error_verbose,
           { "CME Error (Verbose)",              "at.cme_error_verbose",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cmee,
           { "Mode",                             "at.cmee",
           FT_UINT8, BASE_DEC, VALS(cmee_vals), 0,
           NULL, HFILL}
        },
        { &hf_chld_mode,
           { "Mode",                             "at.chld.mode_value",
           FT_UINT8, BASE_DEC, VALS(chld_vals), 0,
           NULL, HFILL}
        },
        { &hf_chld_mode_1x,
           { "Mode: Releases specified active call only",  "at.chld.mode",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_chld_mode_2x,
           { "Mode:  Request private consultation mode with specified call - place all calls on hold EXCEPT the call indicated by x",  "at.chld.mode",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_chld_supported_modes,
           { "Supported Modes",                  "at.chld.supported_modes",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_ciev_indicator_index,
           { "Indicator Index",                  "at.ciev.indicator_index",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_vts_dtmf,
           { "DTMF",                             "at.vts.dtmf",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_vts_duration,
           { "Duration",                         "at.vts.duration",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cops_mode,
           { "Mode",                             "at.cops.mode",
           FT_UINT8, BASE_DEC, VALS(cops_mode_vals), 0,
           NULL, HFILL}
        },
        { &hf_cops_format,
           { "Format",                           "at.cops.format",
           FT_UINT8, BASE_DEC, VALS(cops_format_vals), 0,
           NULL, HFILL}
        },
        { &hf_cops_operator,
           { "Operator",                         "at.cops.operator",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cops_act,
           { "AcT",                              "at.cops.act",
           FT_UINT8, BASE_DEC, VALS(cops_act_vals), 0,
           NULL, HFILL}
        },
        { &hf_clip_mode,
           { "Mode",                             "at.clip.mode",
           FT_UINT8, BASE_DEC, VALS(clip_mode_vals), 0,
           NULL, HFILL}
        },
        { &hf_clip_status,
           { "Status",                           "at.clip.status",
           FT_UINT8, BASE_DEC, VALS(clip_status_vals), 0,
           NULL, HFILL}
        },
        { &hf_at_number,
           { "Number",                           "at.number",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_type,
           { "Type",                             "at.type",
           FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(at_type_vals), 0,
           NULL, HFILL}
        },
        { &hf_at_subaddress,
           { "Subaddress",                       "at.subaddress",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_subaddress_type,
           { "Subaddress Type",                  "at.subaddress_type",
           FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(at_type_vals), 0,
           NULL, HFILL}
        },
        { &hf_cnum_speed,
           { "Speed",                            "at.cnum.speed",
           FT_UINT8, BASE_DEC | BASE_EXT_STRING, &csd_data_rate_vals_ext, 0,
           NULL, HFILL}
        },
        { &hf_cnum_service,
           { "Service",                          "at.cnum.service",
           FT_UINT8, BASE_DEC, VALS(cnum_service_vals), 0,
           NULL, HFILL}
        },
        { &hf_cnum_itc,
           { "Information Transfer Capability",  "at.cnum.itc",
           FT_UINT8, BASE_DEC, VALS(cnum_itc_vals), 0,
           NULL, HFILL}
        },
        { &hf_at_alpha,
           { "Alpha",                            "at.alpha",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_at_cli_validity,
           { "CLI Validity",                     "at.cli_validity",
           FT_UINT8, BASE_DEC, VALS(cli_validity_vals), 0,
           NULL, HFILL}
        },
        { &hf_at_priority,
           { "Priority",                         "at.priority",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_clcc_id,
           { "ID",                               "at.clcc.id",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_clcc_dir,
           { "Direction",                        "at.clcc.dir",
           FT_UINT32, BASE_DEC, VALS(clcc_dir_vals), 0,
           NULL, HFILL}
        },
        { &hf_clcc_stat,
           { "State",                            "at.clcc.stat",
           FT_UINT32, BASE_DEC, VALS(clcc_stat_vals), 0,
           NULL, HFILL}
        },
        { &hf_clcc_mode,
           { "Mode",                             "at.clcc.mode",
           FT_UINT32, BASE_DEC, VALS(clcc_mode_vals), 0,
           NULL, HFILL}
        },
        { &hf_clcc_mpty,
           { "Mpty",                             "at.clcc.mpty",
           FT_UINT32, BASE_DEC, VALS(clcc_mpty_vals), 0,
           NULL, HFILL}
        },
        { &hf_ccwa_show_result_code,
           { "Show Result Code Presentation Status",       "at.ccwa.presentaion_status",
           FT_UINT32, BASE_DEC, VALS(ccwa_show_result_code_vals), 0,
           NULL, HFILL}
        },
        { &hf_ccwa_mode,
           { "Mode",                             "at.ccwa.mode",
           FT_UINT32, BASE_DEC, VALS(ccwa_mode_vals), 0,
           NULL, HFILL}
        },
        { &hf_ccwa_class,
           { "Class",                             "at.ccwa.class",
           FT_UINT32, BASE_DEC, VALS(ccwa_class_vals), 0,
           NULL, HFILL}
        },
        { &hf_cgmm_model_id,
           { "Model Identification",              "at.cgmm.model_id",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[0],
           { "Indicator 1",                      "at.indicator.1",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[1],
           { "Indicator 2",                      "at.indicator.2",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[2],
           { "Indicator 3",                      "at.indicator.3",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[3],
           { "Indicator 4",                      "at.indicator.4",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[4],
           { "Indicator 5",                      "at.indicator.5",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[5],
           { "Indicator 6",                      "at.indicator.6",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[6],
           { "Indicator 7",                      "at.indicator.7",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[7],
           { "Indicator 8",                      "at.indicator.8",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[8],
           { "Indicator 9",                      "at.indicator.9",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[9],
           { "Indicator 10",                     "at.indicator.10",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[10],
           { "Indicator 11",                     "at.indicator.11",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[11],
           { "Indicator 12",                     "at.indicator.12",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[12],
           { "Indicator 13",                     "at.indicator.13",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[13],
           { "Indicator 14",                     "at.indicator.14",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[14],
           { "Indicator 15",                     "at.indicator.15",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[15],
           { "Indicator 16",                     "at.indicator.16",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[16],
           { "Indicator 17",                     "at.indicator.17",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[17],
           { "Indicator 18",                     "at.indicator.18",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[18],
           { "Indicator 19",                     "at.indicator.19",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_indicator[19],
           { "Indicator 20",                     "at.indicator.20",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
    };

    static ei_register_info ei[] = {
        { &ei_unknown_command,         { "at.expert.unknown_command", PI_PROTOCOL, PI_NOTE, "Unknown or Non-standard AT command", EXPFILL }},
        { &ei_invalid_usage,           { "at.expert.invalid_usage", PI_PROTOCOL, PI_WARN, "Non mandatory type or command in this role", EXPFILL }},
        { &ei_unknown_parameter,       { "at.expert.unknown_parameter", PI_PROTOCOL, PI_WARN, "Unknown parameter", EXPFILL }},
        { &ei_cmer_mode,               { "at.expert.cmer.mode", PI_PROTOCOL, PI_WARN, "Only 0-3 are valid", EXPFILL }},
        { &ei_cmer_keyp,               { "at.expert.cmer.keyp", PI_PROTOCOL, PI_WARN, "Only 0-2 are valid", EXPFILL }},
        { &ei_cmer_disp,               { "at.expert.cmer.disp", PI_PROTOCOL, PI_WARN, "Only 0-2 are valid", EXPFILL }},
        { &ei_cmer_ind,                { "at.expert.cmer.ind", PI_PROTOCOL, PI_WARN, "Only 0-2 are valid", EXPFILL }},
        { &ei_cmer_bfr,                { "at.expert.cmer.bfr", PI_PROTOCOL, PI_WARN, "Only 0-1 are valid", EXPFILL }},
        { &ei_chld_mode,               { "at.expert.chld.mode", PI_PROTOCOL, PI_WARN, "Invalid value", EXPFILL }},
        { &ei_ciev_indicator,          { "at.expert.ciev.indicator", PI_PROTOCOL, PI_WARN, "Unknown indicator", EXPFILL }},
        { &ei_vts_dtmf,                { "at.expert.vts.dtmf", PI_PROTOCOL, PI_WARN, "DTMF should be single character", EXPFILL }},
        { &ei_at_type,                 { "at.expert.at.type", PI_PROTOCOL, PI_WARN, "Unknown type value", EXPFILL }},
        { &ei_cnum_service,            { "at.expert.cnum.service", PI_PROTOCOL, PI_WARN, "Only 0-5 are valid", EXPFILL }},
        { &ei_cnum_itc,                { "at.expert.cnum.itc", PI_PROTOCOL, PI_WARN, "Only 0-1 are valid", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_at,
        &ett_at_command,
        &ett_at_parameters,
    };

    proto_at = proto_register_protocol("AT Command", "AT", "at");
    proto_register_field_array(proto_at, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_at = expert_register_protocol(proto_at);
    expert_register_field_array(expert_at, ei, array_length(ei));

    module = prefs_register_protocol(proto_at, NULL);
    prefs_register_enum_preference(module, "role",
        "Force treat packets as DTE (PC) or DCE role",
        "Force treat packets as DTE (PC) or DCE role",
        &at_role, pref_at_role, TRUE);

    register_dissector("at", dissect_at, proto_at);
}

/* Handler registration */
void
proto_reg_handoff_at_command(void)
{
    heur_dissector_add("usb.bulk", heur_dissect_at, "AT Command USB bulk endpoint", "at_usb_bulk", proto_at, HEURISTIC_ENABLE);
    heur_dissector_add("usb.control", heur_dissect_at, "AT Command USB control endpoint", "at_usb_control", proto_at, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
