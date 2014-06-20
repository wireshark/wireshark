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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <ctype.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>

#include "packet-btrfcomm.h"
#include "packet-btsdp.h"

static int proto_bthfp = -1;

static int hf_command                                                      = -1;
static int hf_role                                                         = -1;
static int hf_at_cmd                                                       = -1;
static int hf_at_cmd_type                                                  = -1;
static int hf_at_command_line_prefix                                       = -1;
static int hf_at_ignored                                                   = -1;
static int hf_parameter                                                    = -1;
static int hf_unknown_parameter                                            = -1;
static int hf_data                                                         = -1;
static int hf_fragment                                                     = -1;
static int hf_fragmented                                                   = -1;
static int hf_brsf_hs                                                      = -1;
static int hf_brsf_hs_ec_nr_function                                       = -1;
static int hf_brsf_hs_call_waiting_or_tree_way                             = -1;
static int hf_brsf_hs_cli_presentation                                     = -1;
static int hf_brsf_hs_voice_recognition_activation                         = -1;
static int hf_brsf_hs_remote_volume_control                                = -1;
static int hf_brsf_hs_enhanced_call_status                                 = -1;
static int hf_brsf_hs_enhanced_call_control                                = -1;
static int hf_brsf_hs_codec_negotiation                                    = -1;
static int hf_brsf_hs_reserved                                             = -1;
static int hf_brsf_ag                                                      = -1;
static int hf_brsf_ag_three_way_calling                                    = -1;
static int hf_brsf_ag_ec_nr_function                                       = -1;
static int hf_brsf_ag_voice_recognition_function                           = -1;
static int hf_brsf_ag_inband_ring_tone                                     = -1;
static int hf_brsf_ag_attach_number_to_voice_tag                           = -1;
static int hf_brsf_ag_ability_to_reject_a_call                             = -1;
static int hf_brsf_ag_enhanced_call_status                                 = -1;
static int hf_brsf_ag_enhanced_call_control                                = -1;
static int hf_brsf_ag_extended_error_result_codes                          = -1;
static int hf_brsf_ag_codec_negotiation                                    = -1;
static int hf_brsf_ag_reserved                                             = -1;
static int hf_vgs                                                          = -1;
static int hf_vgm                                                          = -1;
static int hf_nrec                                                         = -1;
static int hf_bvra_vrect                                                   = -1;
static int hf_bsir                                                         = -1;
static int hf_btrh                                                         = -1;
static int hf_cmer_mode                                                    = -1;
static int hf_cmer_keyp                                                    = -1;
static int hf_cmer_disp                                                    = -1;
static int hf_cmer_ind                                                     = -1;
static int hf_cmer_bfr                                                     = -1;
static int hf_bcs_codec                                                    = -1;
static int hf_bac_codec                                                    = -1;
static int hf_binp_request                                                 = -1;
static int hf_binp_response                                                = -1;
static int hf_bia_indicator[20]  = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hf_cind_indicator[20] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

static expert_field ei_non_mandatory_command                          = EI_INIT;
static expert_field ei_invalid_usage                                  = EI_INIT;
static expert_field ei_unknown_parameter                              = EI_INIT;
static expert_field ei_brfs_hs_reserved_bits                          = EI_INIT;
static expert_field ei_brfs_ag_reserved_bits                          = EI_INIT;
static expert_field ei_vgm_gain                                       = EI_INIT;
static expert_field ei_vgs_gain                                       = EI_INIT;
static expert_field ei_nrec                                           = EI_INIT;
static expert_field ei_bvra                                           = EI_INIT;
static expert_field ei_bcs                                            = EI_INIT;
static expert_field ei_bac                                            = EI_INIT;
static expert_field ei_bsir                                           = EI_INIT;
static expert_field ei_btrh                                           = EI_INIT;
static expert_field ei_binp                                           = EI_INIT;
static expert_field ei_bia                                            = EI_INIT;
static expert_field ei_cmer_mode                                      = EI_INIT;
static expert_field ei_cmer_keyp                                      = EI_INIT;
static expert_field ei_cmer_disp                                      = EI_INIT;
static expert_field ei_cmer_ind                                       = EI_INIT;
static expert_field ei_cmer_btr                                       = EI_INIT;

static gint ett_bthfp         = -1;
static gint ett_bthfp_command = -1;
static gint ett_bthfp_brsf_hf = -1;
static gint ett_bthfp_brsf_ag = -1;

static dissector_handle_t bthfp_handle;

static wmem_tree_t *fragments = NULL;

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

static gint hfp_role = ROLE_UNKNOWN;

enum reassemble_state_t {
    REASSEMBLE_FRAGMENT,
    REASSEMBLE_PARTIALLY,
    REASSEMBLE_DONE
};

typedef struct _fragment_t {
    guint32                  interface_id;
    guint32                  adapter_id;
    guint32                  chandle;
    guint32                  dlci;
    guint32                  role;

    guint                    index;
    guint                    length;
    guint8                  *data;
    struct _fragment_t      *previous_fragment;

    guint                    reassemble_start_offset;
    guint                    reassemble_end_offset;
    enum reassemble_state_t  reassemble_state;
} fragment_t;

typedef struct _at_cmd_t {
    const guint8 *name;
    const guint8 *long_name;

    gboolean (*check_command)(gint role, guint16 type);
    gboolean (*dissect_parameter)(tvbuff_t *tvb, packet_info *pinfo,
            proto_tree *tree, gint offset, gint role, guint16 type,
            guint8 *parameter_stream, guint parameter_number, gint parameter_length);
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

void proto_register_bthfp(void);
void proto_reg_handoff_bthfp(void);

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

static gboolean check_bac(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return TRUE;

    return FALSE;
}

static gboolean check_bcs(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_bcc(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION_SIMPLY) return TRUE;

    return FALSE;
}

static gboolean check_bia(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return TRUE;

    return FALSE;
}

static gboolean check_binp(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_bldn(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION_SIMPLY) return TRUE;

    return FALSE;
}

static gboolean check_bvra(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_brsf(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_nrec(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return TRUE;

    return FALSE;
}

static gboolean check_vgs(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_vgm(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_bsir(gint role, guint16 type) {
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_btrh(gint role, guint16 type) {
    if (role == ROLE_HS && (type == TYPE_READ || type == TYPE_ACTION)) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_only_ag_role(gint role, guint16 type) {
    if (role == ROLE_AG && type == TYPE_RESPONSE_ACK) return TRUE;

    return FALSE;
}

static gboolean check_only_hs_role(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION_SIMPLY) return TRUE;

    return FALSE;
}

static gboolean check_ccwa(gint role, guint16 type) {
    if (role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_READ || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_chld(gint role, guint16 type) {
    if (role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_chup(gint role, guint16 type) {
    if (role == ROLE_HS && (type == TYPE_ACTION_SIMPLY || type == TYPE_TEST)) return TRUE;

    return FALSE;
}

static gboolean check_clcc(gint role, guint16 type) {
    if (role == ROLE_HS && (type == TYPE_ACTION_SIMPLY || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_cind(gint role, guint16 type) {
    if (role == ROLE_HS && (type == TYPE_READ || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_cmer(gint role, guint16 type) {
    if (role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_READ || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_cops(gint role, guint16 type) {
    if (role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_READ)) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_cmee(gint role, guint16 type) {
    if (role == ROLE_HS && type == TYPE_ACTION) return TRUE;

    return FALSE;
}

static gboolean check_cme(gint role, guint16 type) {
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_clip(gint role, guint16 type) {
    if (role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_READ || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_ciev(gint role, guint16 type) {
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_vts(gint role, guint16 type) {
    if (role == ROLE_HS && (type == TYPE_ACTION || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean check_cnum(gint role, guint16 type) {
    if (role == ROLE_HS && (type == TYPE_ACTION_SIMPLY || type == TYPE_TEST)) return TRUE;
    if (role == ROLE_AG && type == TYPE_RESPONSE) return TRUE;

    return FALSE;
}

static gboolean
dissect_brsf_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length)
{
    proto_tree  *ptree;
    proto_item  *pitem;
    guint32      value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return FALSE;
    }

    if (parameter_number > 0) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);

    if (role == ROLE_HS) {
        pitem = proto_tree_add_uint(tree, hf_brsf_hs, tvb, offset, parameter_length, value);
        ptree = proto_item_add_subtree(pitem, ett_bthfp_brsf_hf);

        proto_tree_add_boolean(ptree, hf_brsf_hs_ec_nr_function, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_hs_call_waiting_or_tree_way, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_hs_cli_presentation, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_hs_voice_recognition_activation, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_hs_remote_volume_control, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_hs_enhanced_call_status, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_hs_enhanced_call_control, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_hs_codec_negotiation, tvb, offset, parameter_length, value);
        pitem = proto_tree_add_uint(ptree, hf_brsf_hs_reserved, tvb, offset, parameter_length, value);

        if (value >> 8) {
            expert_add_info(pinfo, pitem, &ei_brfs_hs_reserved_bits);
        }
    } else {
        pitem = proto_tree_add_uint(tree, hf_brsf_ag, tvb, offset, parameter_length, value);
        ptree = proto_item_add_subtree(pitem, ett_bthfp_brsf_ag);

        proto_tree_add_boolean(ptree, hf_brsf_ag_three_way_calling, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_ag_ec_nr_function, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_ag_voice_recognition_function, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_ag_inband_ring_tone, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_ag_attach_number_to_voice_tag, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_ag_ability_to_reject_a_call, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_ag_enhanced_call_status, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_ag_enhanced_call_control, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_ag_extended_error_result_codes, tvb, offset, parameter_length, value);
        proto_tree_add_boolean(ptree, hf_brsf_ag_codec_negotiation, tvb, offset, parameter_length, value);
        pitem = proto_tree_add_uint(ptree, hf_brsf_ag_reserved, tvb, offset, parameter_length, value);

        if (value >> 10) {
            expert_add_info(pinfo, pitem, &ei_brfs_ag_reserved_bits);
        }
    }

    return TRUE;
}

static gint
dissect_vgs_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length)
{
    proto_item  *pitem;
    guint32      value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return FALSE;
    }

    if (parameter_number > 0) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_vgs, tvb, offset, parameter_length, value);
    proto_item_append_text(pitem, "/15");

    if (value > 15) {
        expert_add_info(pinfo, pitem, &ei_vgs_gain);
    }

    return TRUE;
}

static gint
dissect_vgm_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length)
{
    proto_item  *pitem;
    guint32      value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return FALSE;
    }

    if (parameter_number > 0) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_vgm, tvb, offset, parameter_length, value);
    proto_item_append_text(pitem, "/15");

    if (value > 15) {
        expert_add_info(pinfo, pitem, &ei_vgm_gain);
    }

    return TRUE;
}

static gint
dissect_nrec_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length)
{
    proto_item  *pitem;
    guint32      value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return FALSE;
    }

    if (parameter_number > 0) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_nrec, tvb, offset, parameter_length, value);

    if (value != 0) {
        expert_add_info(pinfo, pitem, &ei_nrec);
    }

    return TRUE;
}

static gint
dissect_bvra_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length)
{
    proto_item  *pitem;
    guint32      value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return FALSE;
    }

    if (parameter_number > 0) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_bvra_vrect, tvb, offset, parameter_length, value);

    if (value > 1) {
        expert_add_info(pinfo, pitem, &ei_bvra);
    }

    return TRUE;
}

static gint
dissect_bcs_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length)
{
    proto_item  *pitem;
    guint32      value;

    if (!check_bcs(role, type)) {
        return FALSE;
    }

    if (parameter_number > 0) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_bcs_codec, tvb, offset, parameter_length, value);

    if (value <  1 ||  value > 2) {
        expert_add_info(pinfo, pitem, &ei_bcs);
    }

    return TRUE;
}

static gint
dissect_bac_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number _U_, gint parameter_length)
{
    proto_item  *pitem;
    guint32      value;

    if (!check_bac(role, type)) {
        return FALSE;
    }

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_bac_codec, tvb, offset, parameter_length, value);

    if (value <  1 ||  value > 2)  {
        expert_add_info(pinfo, pitem, &ei_bac);
    }

    return TRUE;
}

static gint
dissect_no_parameter(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_,
        gint offset _U_, gint role _U_, guint16 type _U_, guint8 *parameter_stream _U_,
        guint parameter_number _U_, gint parameter_length _U_)
{
    return FALSE;
}

static gint
dissect_bsir_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length)
{
    proto_item  *pitem;
    guint32      value;

    if (!(role == ROLE_AG && type == TYPE_RESPONSE)) {
        return FALSE;
    }

    if (parameter_number > 0) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_bsir, tvb, offset, parameter_length, value);

    if (value > 1) {
        expert_add_info(pinfo, pitem, &ei_bsir);
    }

    return TRUE;
}

static gint
dissect_btrh_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length)
{
    proto_item  *pitem;
    guint32      value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return FALSE;
    }

    if (parameter_number > 0) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_btrh, tvb, offset, parameter_length, value);

    if (value != 0) {
        expert_add_info(pinfo, pitem, &ei_btrh);
    }

    return TRUE;
}


static gint
dissect_binp_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length)
{
    proto_item  *pitem;
    guint32      value;

    if (!((role == ROLE_HS && type == TYPE_ACTION) ||
            (role == ROLE_AG && type == TYPE_RESPONSE))) {
        return FALSE;
    }

    if (role == ROLE_HS && type == TYPE_ACTION) {
        if (parameter_number == 0) {
            value = get_uint_parameter(parameter_stream, parameter_length);

            pitem = proto_tree_add_uint(tree, hf_binp_request, tvb, offset,
                    parameter_length, value);

            if (value != 1) {
                expert_add_info(pinfo, pitem, &ei_binp);
            }
        } else return FALSE;
    } else {
        proto_tree_add_item(tree, hf_binp_response, tvb, offset,
                parameter_length, ENC_NA | ENC_ASCII);
    }
    return TRUE;
}

static gint
dissect_bia_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length)
{
    proto_item  *pitem;
    guint32      value;

    if (!((role == ROLE_HS && type == TYPE_ACTION))) return FALSE;
    if (parameter_number > 19) return FALSE;

    value = get_uint_parameter(parameter_stream, parameter_length);

    pitem = proto_tree_add_uint(tree, hf_bia_indicator[parameter_number], tvb,
            offset, parameter_length, value);
    if (value > 1) {
        expert_add_info(pinfo, pitem, &ei_bia);
    }

    return TRUE;
}

static gint
dissect_cind_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream _U_,
        guint parameter_number, gint parameter_length)
{
    if (!check_cind(role, type)) return FALSE;
    if (parameter_number > 19) return FALSE;

    proto_tree_add_item(tree, hf_cind_indicator[parameter_number], tvb, offset,
            parameter_length, ENC_NA | ENC_ASCII);

    return TRUE;
}


static gint
dissect_cmer_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gint role, guint16 type, guint8 *parameter_stream,
        guint parameter_number, gint parameter_length)
{
    proto_item  *pitem;
    guint32      value;

    if (!((role == ROLE_HS && type == TYPE_ACTION))) {
        return FALSE;
    }

    if (parameter_number > 5) return FALSE;

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

    return TRUE;
}

/* TODO: Some commands need to save request command type (request with TYPE_READ vs TYPE_TEST, etc.)
         to properly dissect response parameters.
         Some commands can use TYPE_TEST respose to properly dissect parameters,
         for example: AT+CIND=?, AT+CIND? */
static const at_cmd_t at_cmds[] = {
    /* Bluetooth HFP specific AT Commands */
    { "+BAC",       "Bluetooth Available Codecs",               check_bac,  dissect_bac_parameter  },
    { "+BCS",       "Bluetooth Codec Selection",                check_bcs,  dissect_bcs_parameter  },
    { "+BCC",       "Bluetooth Codec Connection",               check_bcc,  dissect_no_parameter   },
    { "+BTRH",      "Bluetooth Response and Hold Feature",      check_btrh, dissect_btrh_parameter },
    { "+BSIR",      "Bluetooth Setting of In-band Ring Tone",   check_bsir, dissect_bsir_parameter },
    { "+VGS",       "Gain of Speaker",                          check_vgs,  dissect_vgs_parameter  },
    { "+VGM",       "Gain of Microphone",                       check_vgm,  dissect_vgm_parameter  },
    { "+NREC",      "Noise Reduction and Echo Canceling",       check_nrec, dissect_nrec_parameter },
    { "+BRSF",      "Bluetooth Retrieve Supported Features",    check_brsf, dissect_brsf_parameter },
    { "+BVRA",      "Bluetooth Voice Recognition Activation",   check_bvra, dissect_bvra_parameter },
    { "+BLDN",      "Bluetooth Last Dialed Number",             check_bldn, dissect_no_parameter   },
    { "+BINP",      "Bluetooth Input",                          check_binp, dissect_binp_parameter },
    { "+BIA",       "Bluetooth Indicators Activation",          check_bia,  dissect_bia_parameter  },
    /* Inherited from normal AT Commands */
    { "+CCWA",      "Call Waiting Notification",                check_ccwa, NULL }, /* TODO */
    { "+CHLD",      "Call Hold and Multiparty Handling",        check_chld, NULL }, /* TODO */
    { "+CHUP",      "Call Hang-up",                             check_chup, NULL }, /* TODO */
    { "+CIND",      "Phone Indicators",                         check_cind, dissect_cind_parameter },
    { "+CLCC",      "Current Calls",                            check_clcc, NULL }, /* TODO */
    { "+COPS",      "Reading Network Operator",                 check_cops, NULL }, /* TODO */
    { "+CMEE",      "Mobile Equipment Error",                   check_cmee, NULL }, /* TODO */
    { "+CME ERROR", "Extended Audio Gateway Error Result Code", check_cme,  NULL }, /* TODO */
    { "+CLIP",      "Calling Line Identification Notification", check_clip, NULL }, /* TODO */
    { "+CMER",      "Event Reporting Activation/Deactivation",  check_cmer, dissect_cmer_parameter },
    { "+CIEV",      "Indicator Events Reporting",               check_ciev, NULL }, /* TODO */
    { "+VTS",       "DTMF and tone generation",                 check_vts,  NULL }, /* TODO */
    { "+CNUM",      "Subscriber Number Information",            check_cnum, NULL }, /* TODO */
    { "ERROR",      "ERROR",                                    check_only_ag_role, dissect_no_parameter },
    { "RING",       "Incomming Call Indication",                check_only_ag_role, dissect_no_parameter },
    { "OK",         "OK",                                       check_only_ag_role, dissect_no_parameter },
    { "D",          "Dial",                                     check_only_hs_role, NULL },
    { "A",          "Call Answer",                              check_only_hs_role, dissect_no_parameter },
    { NULL, NULL, NULL, NULL }
};


static gint
dissect_at_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, guint32 role, gint command_number)
{
    proto_item      *pitem;
    proto_tree      *command_item;
    proto_item      *command_tree;
    guint8          *col_str = NULL;
    guint8          *at_stream;
    guint8          *at_command = NULL;
    gint             i_char = 0;
    guint            i_char_fix = 0;
    gint             length;
    const at_cmd_t  *i_at_cmd;
    gint             parameter_length;
    guint            parameter_number;
    guint16          type = TYPE_UNKNOWN;
    guint32          brackets;
    gboolean         quotation;
    gboolean         next;

    length = tvb_length_remaining(tvb, offset);
    if (length <= 0)
        return tvb_length(tvb);

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
        at_stream[i_char] = toupper(at_stream[i_char]);
        if (!command_number) {
            col_str[i_char] = toupper(col_str[i_char]);
            if (!g_ascii_isgraph(col_str[i_char])) col_str[i_char] = ' ';
        }
        i_char += 1;
    }

    command_item = proto_tree_add_none_format(tree, hf_command, tvb,
            offset, 0, "Command %u", command_number);
    command_tree = proto_item_add_subtree(command_item, ett_bthfp_command);

    if (!command_number) col_append_fstr(pinfo->cinfo, COL_INFO, "%s", col_str);

    if (role == ROLE_HS) {
        if (command_number) {
            at_command = at_stream;
            i_char = 0;
        } else {
            at_command = g_strstr_len(at_stream, length, "AT");

            if (at_command) {
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
    } else {
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

        parameter_number = 0;

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
                            !i_at_cmd->dissect_parameter(tvb, pinfo, command_tree, offset, role,
                            type, &at_command[i_char], parameter_number, parameter_length) )) {
                        pitem = proto_tree_add_item(command_tree,
                                hf_unknown_parameter, tvb, offset,
                                parameter_length, ENC_NA | ENC_ASCII);
                        expert_add_info(pinfo, pitem, &ei_unknown_parameter);
                    } else if (i_at_cmd && i_at_cmd->dissect_parameter == NULL) {
                        proto_tree_add_item(command_tree, hf_parameter, tvb, offset,
                                parameter_length, ENC_NA | ENC_ASCII);
                    }
                }
            }

            parameter_number += 1;
            i_char += parameter_length;
            offset += parameter_length;

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
        length = tvb_length_remaining(tvb, offset);
        if (length < 0)
            length = 0;
        proto_item_set_len(command_item, length);
        offset += length;
    }

    return offset;
}

static gint
dissect_bthfp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item       *main_item;
    proto_tree       *main_tree;
    proto_item       *pitem;
    gint              offset = 0;
    guint32           role = ROLE_UNKNOWN;
    wmem_tree_key_t   key[10];
    guint32           k_interface_id;
    guint32           k_adapter_id;
    guint32           k_chandle;
    guint32           k_dlci;
    guint32           k_role;
    guint32           k_frame_number;
    guint32           interface_id;
    guint32           adapter_id;
    guint32           chandle;
    guint32           dlci;
    fragment_t       *fragment;
    fragment_t       *previous_fragment;
    fragment_t       *i_fragment;
    btrfcomm_data_t  *rfcomm_data;
    guint8           *at_stream;
    gint              length;
    gint              command_number;
    gint              i_length;
    tvbuff_t         *reassembled_tvb = NULL;
    guint             reassemble_start_offset = 0;
    guint             reassemble_end_offset   = 0;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    rfcomm_data = (btrfcomm_data_t *) data;

    main_item = proto_tree_add_item(tree, proto_bthfp, tvb, 0, -1, ENC_NA);
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
            col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ", pinfo->p2p_dir);
            break;
    }

    interface_id = rfcomm_data->interface_id;
    adapter_id   = rfcomm_data->adapter_id;
    chandle      = rfcomm_data->chandle;
    dlci         = rfcomm_data->dlci;

    if ((hfp_role == ROLE_AG && pinfo->p2p_dir == P2P_DIR_SENT) ||
            (hfp_role == ROLE_HS && pinfo->p2p_dir == P2P_DIR_RECV)) {
        role = ROLE_AG;
    } else if (hfp_role != ROLE_UNKNOWN) {
        role = ROLE_HS;
    }

    if (role == ROLE_UNKNOWN) {
        guint32          k_sdp_psm;
        guint32          k_direction;
        guint32          k_bd_addr_oui;
        guint32          k_bd_addr_id;
        guint32          k_service_type;
        guint32          k_service_channel;
        service_info_t  *service_info;

        k_interface_id    = rfcomm_data->interface_id;
        k_adapter_id      = rfcomm_data->adapter_id;
        k_sdp_psm         = SDP_PSM_DEFAULT;
        k_direction       = (rfcomm_data->is_local_psm) ? P2P_DIR_SENT : P2P_DIR_RECV;
        if (k_direction == P2P_DIR_RECV) {
            k_bd_addr_oui     = rfcomm_data->remote_bd_addr_oui;
            k_bd_addr_id      = rfcomm_data->remote_bd_addr_id;
        } else {
            k_bd_addr_oui     = 0;
            k_bd_addr_id      = 0;
        }
        k_service_type    = BTSDP_RFCOMM_PROTOCOL_UUID;
        k_service_channel = rfcomm_data->dlci >> 1;
        k_frame_number    = pinfo->fd->num;

        key[0].length = 1;
        key[0].key = &k_interface_id;
        key[1].length = 1;
        key[1].key = &k_adapter_id;
        key[2].length = 1;
        key[2].key = &k_sdp_psm;
        key[3].length = 1;
        key[3].key = &k_direction;
        key[4].length = 1;
        key[4].key = &k_bd_addr_oui;
        key[5].length = 1;
        key[5].key = &k_bd_addr_id;
        key[6].length = 1;
        key[6].key = &k_service_type;
        key[7].length = 1;
        key[7].key = &k_service_channel;
        key[8].length = 1;
        key[8].key = &k_frame_number;
        key[9].length = 0;
        key[9].key = NULL;

        service_info = btsdp_get_service_info(key);
        if (service_info && service_info->interface_id == rfcomm_data->interface_id &&
                service_info->adapter_id == rfcomm_data->adapter_id &&
                service_info->sdp_psm == SDP_PSM_DEFAULT &&
                ((service_info->direction == P2P_DIR_RECV &&
                service_info->bd_addr_oui == rfcomm_data->remote_bd_addr_oui &&
                service_info->bd_addr_id == rfcomm_data->remote_bd_addr_id) ||
                (service_info->direction != P2P_DIR_RECV &&
                service_info->bd_addr_oui == 0 &&
                service_info->bd_addr_id == 0)) &&
                service_info->type == BTSDP_RFCOMM_PROTOCOL_UUID &&
                service_info->channel == (rfcomm_data->dlci >> 1)) {
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
    PROTO_ITEM_SET_GENERATED(pitem);

    if (role == ROLE_UNKNOWN) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Data: %s",
                tvb_format_text(tvb, 0, tvb_length(tvb)));
        proto_tree_add_item(main_tree, hf_data, tvb, 0, -1, ENC_NA | ENC_ASCII);
        return tvb_length(tvb);
    }

    /* save fragments */
    if (!pinfo->fd->flags.visited) {
        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_dlci         = dlci;
        k_role         = role;
        k_frame_number = pinfo->fd->num - 1;

        key[0].length = 1;
        key[0].key = &k_interface_id;
        key[1].length = 1;
        key[1].key = &k_adapter_id;
        key[2].length = 1;
        key[2].key = &k_chandle;
        key[3].length = 1;
        key[3].key = &k_dlci;
        key[4].length = 1;
        key[4].key = &k_role;
        key[5].length = 1;
        key[5].key = &k_frame_number;
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

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_dlci         = dlci;
        k_role         = role;
        k_frame_number = pinfo->fd->num;

        key[0].length = 1;
        key[0].key = &k_interface_id;
        key[1].length = 1;
        key[1].key = &k_adapter_id;
        key[2].length = 1;
        key[2].key = &k_chandle;
        key[3].length = 1;
        key[3].key = &k_dlci;
        key[4].length = 1;
        key[4].key = &k_role;
        key[5].length = 1;
        key[5].key = &k_frame_number;
        key[6].length = 0;
        key[6].key = NULL;

        fragment = wmem_new(wmem_file_scope(), fragment_t);
        fragment->interface_id      = interface_id;
        fragment->adapter_id        = adapter_id;
        fragment->chandle           = chandle;
        fragment->dlci              = dlci;
        fragment->role              = role;
        fragment->index             = previous_fragment ? previous_fragment->index + previous_fragment->length : 0;
        fragment->reassemble_state  = REASSEMBLE_FRAGMENT;
        fragment->length            = tvb_length(tvb);
        fragment->data              = (guint8 *) wmem_alloc(wmem_file_scope(), fragment->length);
        fragment->previous_fragment = previous_fragment;
        tvb_memcpy(tvb, fragment->data, offset, fragment->length);

        wmem_tree_insert32_array(fragments, key, fragment);

        /* Detect reassemble end character: \r for HS or \n for AG */
        length = tvb_length(tvb);
        at_stream = tvb_get_string_enc(wmem_packet_scope(), tvb, 0, length, ENC_ASCII);

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

            k_interface_id = interface_id;
            k_adapter_id   = adapter_id;
            k_chandle      = chandle;
            k_dlci         = dlci;
            k_role         = role;
            k_frame_number = pinfo->fd->num;

            key[0].length = 1;
            key[0].key = &k_interface_id;
            key[1].length = 1;
            key[1].key = &k_adapter_id;
            key[2].length = 1;
            key[2].key = &k_chandle;
            key[3].length = 1;
            key[3].key = &k_dlci;
            key[4].length = 1;
            key[4].key = &k_role;
            key[5].length = 1;
            key[5].key = &k_frame_number;
            key[6].length = 0;
            key[6].key = NULL;

            fragment = (fragment_t *) wmem_tree_lookup32_array_le(fragments, key);
            if (fragment && fragment->interface_id == interface_id &&
                    fragment->adapter_id == adapter_id &&
                    fragment->chandle == chandle &&
                    fragment->dlci == dlci &&
                    fragment->role == role) {
                i_fragment = fragment;
                while (i_fragment && i_fragment->index > 0) {
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
                    fragment->reassemble_state = REASSEMBLE_PARTIALLY;
                }
                fragment->reassemble_start_offset = reassemble_start_offset;
                fragment->reassemble_end_offset = reassemble_end_offset;
            }
        }
    }

    /* recover reassembled payload */
    k_interface_id = interface_id;
    k_adapter_id   = adapter_id;
    k_chandle      = chandle;
    k_dlci         = dlci;
    k_role         = role;
    k_frame_number = pinfo->fd->num;

    key[0].length = 1;
    key[0].key = &k_interface_id;
    key[1].length = 1;
    key[1].key = &k_adapter_id;
    key[2].length = 1;
    key[2].key = &k_chandle;
    key[3].length = 1;
    key[3].key = &k_dlci;
    key[4].length = 1;
    key[4].key = &k_role;
    key[5].length = 1;
    key[5].key = &k_frame_number;
    key[6].length = 0;
    key[6].key = NULL;

    fragment = (fragment_t *) wmem_tree_lookup32_array_le(fragments, key);
    if (fragment && fragment->interface_id == interface_id &&
            fragment->adapter_id == adapter_id &&
            fragment->chandle == chandle &&
            fragment->dlci == dlci &&
            fragment->role == role &&
            fragment->reassemble_state != REASSEMBLE_FRAGMENT) {
        guint8    *at_data;
        guint      i_data_offset;

        i_data_offset = fragment->index + fragment->length;
        at_data = (guint8 *) wmem_alloc(pinfo->pool, fragment->index + fragment->length);

        i_fragment = fragment;

        if (i_fragment && i_fragment->reassemble_state == REASSEMBLE_PARTIALLY) {
                i_data_offset -= i_fragment->reassemble_end_offset;
                memcpy(at_data + i_data_offset, i_fragment->data, i_fragment->reassemble_end_offset);

            i_fragment = i_fragment->previous_fragment;
        }

        if (i_fragment) {
            while (i_fragment && i_fragment->index > 0) {
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

        if (fragment->index > 0 && fragment->length > 0) {
            proto_tree_add_item(main_tree, hf_fragment, tvb, offset,
                                tvb_length_remaining(tvb, offset), ENC_ASCII | ENC_NA);
            reassembled_tvb = tvb_new_child_real_data(tvb, at_data,
                    fragment->index + fragment->length, fragment->index + fragment->length);
            add_new_data_source(pinfo, reassembled_tvb, "Reassembled HFP");
        }

        command_number = 0;
        if (reassembled_tvb) {
            guint reassembled_offset = 0;

            while (tvb_length(reassembled_tvb) > reassembled_offset) {
                reassembled_offset = dissect_at_command(reassembled_tvb,
                        pinfo, main_tree, reassembled_offset, role, command_number);
                command_number += 1;
            }
        } else {
            while (tvb_length(tvb) > (guint) offset) {
                offset = dissect_at_command(tvb, pinfo, main_tree, offset, role, command_number);
                command_number += 1;
            }
        }
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Fragment: %s",
                tvb_format_text_wsp(tvb, offset, tvb_length_remaining(tvb, offset)));
        pitem = proto_tree_add_item(main_tree, hf_fragmented, tvb, 0, 0, ENC_NA);
        PROTO_ITEM_SET_GENERATED(pitem);
        proto_tree_add_item(main_tree, hf_fragment, tvb, offset,
                tvb_length_remaining(tvb, offset), ENC_ASCII | ENC_NA);
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
        { &hf_brsf_hs_reserved,
           { "Reserved",                         "bthfp.brsf.hs.reserved",
           FT_UINT32, BASE_HEX, NULL, 0xFFFFFF00,
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
        { &hf_brsf_ag_reserved,
           { "Reserved",                         "bthfp.brsf.ag.reserved",
           FT_UINT32, BASE_HEX, NULL, 0xFFFFFC00,
           NULL, HFILL}
        },
        { &hf_vgs,
           { "Gain",                             "bthfp.vgs",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_vgm,
           { "Gain",                             "bthfp.vgm",
           FT_UINT8, BASE_DEC, NULL, 0,
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
        { &hf_cind_indicator[0],
           { "Indicator 1",                      "bthfp.cind.indicator.1",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[1],
           { "Indicator 2",                      "bthfp.cind.indicator.2",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[2],
           { "Indicator 3",                      "bthfp.cind.indicator.3",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[3],
           { "Indicator 4",                      "bthfp.cind.indicator.4",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[4],
           { "Indicator 5",                      "bthfp.cind.indicator.5",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[5],
           { "Indicator 6",                      "bthfp.cind.indicator.6",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[6],
           { "Indicator 7",                      "bthfp.cind.indicator.7",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[7],
           { "Indicator 8",                      "bthfp.cind.indicator.8",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[8],
           { "Indicator 9",                      "bthfp.cind.indicator.9",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[9],
           { "Indicator 10",                     "bthfp.cind.indicator.10",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[10],
           { "Indicator 11",                     "bthfp.cind.indicator.11",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[11],
           { "Indicator 12",                     "bthfp.cind.indicator.12",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[12],
           { "Indicator 13",                     "bthfp.cind.indicator.13",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[13],
           { "Indicator 14",                     "bthfp.cind.indicator.14",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[14],
           { "Indicator 15",                     "bthfp.cind.indicator.15",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[15],
           { "Indicator 16",                     "bthfp.cind.indicator.16",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[16],
           { "Indicator 17",                     "bthfp.cind.indicator.17",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[17],
           { "Indicator 18",                     "bthfp.cind.indicator.18",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[18],
           { "Indicator 19",                     "bthfp.cind.indicator.19",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_cind_indicator[19],
           { "Indicator 20",                     "bthfp.cind.indicator.20",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        }
    };

    static ei_register_info ei[] = {
        { &ei_non_mandatory_command, { "bthfp.expert.non_mandatory_command", PI_PROTOCOL, PI_NOTE, "Non-mandatory command in HFP", EXPFILL }},
        { &ei_invalid_usage,         { "bthfp.expert.invalid_usage", PI_PROTOCOL, PI_WARN, "Non mandatory type or command in this role", EXPFILL }},
        { &ei_unknown_parameter,     { "bthfp.expert.unknown_parameter", PI_PROTOCOL, PI_WARN, "Unknown parameter", EXPFILL }},
        { &ei_brfs_hs_reserved_bits, { "bthfp.expert.brsf.hs.reserved_bits", PI_PROTOCOL, PI_WARN, "The reserved bits [8-31] shall be initialized to Zero", EXPFILL }},
        { &ei_brfs_ag_reserved_bits, { "bthfp.expert.brsf.ag.reserved_bits", PI_PROTOCOL, PI_WARN, "The reserved bits [10-31] shall be initialized to Zero", EXPFILL }},
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
        { &ei_cmer_mode,             { "bthfp.expert.cmer.mode", PI_PROTOCOL, PI_NOTE, "Only 3 is valid for HFP", EXPFILL }},
        { &ei_cmer_disp,             { "bthfp.expert.cmer.disp", PI_PROTOCOL, PI_WARN, "Value is ignored for HFP", EXPFILL }},
        { &ei_cmer_keyp,             { "bthfp.expert.cmer.keyp", PI_PROTOCOL, PI_WARN, "Value is ignored for HFP", EXPFILL }},
        { &ei_cmer_ind,              { "bthfp.expert.cmer.ind", PI_PROTOCOL, PI_NOTE, "Only 0-1 is valid for HFP", EXPFILL }},
        { &ei_cmer_btr,              { "bthfp.expert.cmer.btr", PI_PROTOCOL, PI_WARN, "Value is ignored for HFP", EXPFILL }}
    };

    static gint *ett[] = {
        &ett_bthfp,
        &ett_bthfp_brsf_hf,
        &ett_bthfp_brsf_ag,
        &ett_bthfp_command
    };

    fragments = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_bthfp = proto_register_protocol("Bluetooth HFP Profile", "BT HFP", "bthfp");
    bthfp_handle = new_register_dissector("bthfp", dissect_bthfp, proto_bthfp);

    proto_register_field_array(proto_bthfp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module = prefs_register_protocol(proto_bthfp, NULL);
    prefs_register_static_text_preference(module, "hfp.version",
            "Bluetooth Profile HFP version: 1.6",
            "Version of profile supported by this dissector.");

    prefs_register_enum_preference(module, "hfp.hfp_role",
            "Force treat packets as AG or HS role",
            "Force treat packets as AG or HS role",
            &hfp_role, pref_hfp_role, TRUE);

    expert_bthfp = expert_register_protocol(proto_bthfp);
    expert_register_field_array(expert_bthfp, ei, array_length(ei));
}

void
proto_reg_handoff_bthfp(void)
{
    dissector_add_uint("btrfcomm.service", BTSDP_HFP_SERVICE_UUID, bthfp_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_HFP_GW_SERVICE_UUID, bthfp_handle);
    dissector_add_for_decode_as("btrfcomm.channel", bthfp_handle);
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
