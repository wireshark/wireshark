/* packet-gsm_sms.c
 * Routines for GSM SMS TPDU (GSM 03.40) dissection
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * TPDU User-Data unpack routines from GNOKII.
 *
 *   Reference [1]
 *   Universal Mobile Telecommunications System (UMTS);
 *   Technical realization of Short Message Service (SMS)
 *   (3GPP TS 23.040 version 5.4.0 Release 5)
 *
 * Header field support for TPDU Parameters added by
 * Abhik Sarkar.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/charsets.h>
#include <epan/proto_data.h>
#include "packet-e164.h"
#include <epan/asn1.h>
#include "packet-gsm_sms.h"
#include "packet-gsm_map.h"
#include "packet-sip.h"

static gint proto_gsm_map = -1;
static gint proto_sip     = -1;

void proto_register_gsm_sms(void);
void proto_reg_handoff_gsm_sms(void);

#define MAX_SMS_FRAG_LEN      134

/* PROTOTYPES/FORWARDS */
#define SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
    if ((sdc_len) < (sdc_min_len)) \
    { \
        proto_tree_add_expert(tree, pinfo, &ei_gsm_sms_short_data, tvb, \
            offset, (sdc_len)); \
        return; \
    }

#define EXACT_DATA_CHECK(edc_len, edc_eq_len) \
    if ((edc_len) != (edc_eq_len)) \
    { \
        proto_tree_add_expert(tree, pinfo, &ei_gsm_sms_unexpected_data_length, tvb, \
            offset, (edc_len)); \
        return; \
    }

static const char *gsm_sms_proto_name = "GSM SMS TPDU (GSM 03.40)";
static const char *gsm_sms_proto_name_short = "GSM SMS";

/* Initialize the subtree pointers */
static gint ett_gsm_sms = -1;
static gint ett_pid = -1;
static gint ett_pi = -1;
static gint ett_fcs = -1;
static gint ett_vp = -1;
static gint ett_scts = -1;
static gint ett_dt = -1;
static gint ett_st = -1;
static gint ett_addr = -1;
static gint ett_dcs = -1;
static gint ett_ud = -1;
static gint ett_udh = -1;

static gint ett_udh_tfm = -1;
static gint ett_udh_tfc = -1;

/* Initialize the protocol and registered fields */
static int proto_gsm_sms = -1;

static gint hf_gsm_sms_coding_group_bits2 = -1;
static gint hf_gsm_sms_coding_group_bits4 = -1;
static gint hf_gsm_sms_ud_multiple_messages_msg_id = -1;
static gint hf_gsm_sms_ud_multiple_messages_msg_parts = -1;
static gint hf_gsm_sms_ud_multiple_messages_msg_part = -1;

/* TPDU Parameters */
static gint hf_gsm_sms_tp_mti_up = -1;
static gint hf_gsm_sms_tp_mti_down = -1;
static gint hf_gsm_sms_tp_mms = -1;
static gint hf_gsm_sms_tp_lp = -1;
static gint hf_gsm_sms_tp_vpf = -1;
static gint hf_gsm_sms_tp_sri = -1;
static gint hf_gsm_sms_tp_srr = -1;
static gint hf_gsm_sms_tp_mr = -1;
static gint hf_gsm_sms_tp_oa = -1;
static gint hf_gsm_sms_tp_da = -1;
static gint hf_gsm_sms_tp_pid = -1;
static gint hf_gsm_sms_tp_dcs = -1;
static gint hf_gsm_sms_tp_ra = -1;
static gint hf_gsm_sms_tp_digits = -1;
static gint hf_gsm_sms_tp_rp = -1;
static gint hf_gsm_sms_tp_udhi = -1;
static gint hf_gsm_sms_tp_rd = -1;
static gint hf_gsm_sms_tp_srq = -1;
static gint hf_gsm_sms_text = -1;
static gint hf_gsm_sms_body = -1;
static gint hf_gsm_sms_tp_fail_cause = -1;
#if 0
static gint hf_gsm_sms_tp_scts = -1;
static gint hf_gsm_sms_tp_vp = -1;
static gint hf_gsm_sms_tp_dt = -1;
static gint hf_gsm_sms_tp_st = -1;
static gint hf_gsm_sms_tp_mn = -1;
static gint hf_gsm_sms_tp_ct = -1;
static gint hf_gsm_sms_tp_cdl = -1;
static gint hf_gsm_sms_tp_cd = -1;
static gint hf_gsm_sms_tp_ud = -1;
#endif
static gint hf_gsm_sms_tp_parameter_indicator = -1;
static gint hf_gsm_sms_tp_extension = -1;
static gint hf_gsm_sms_tp_reserved = -1;
static gint hf_gsm_sms_tp_udl_present = -1;
static gint hf_gsm_sms_tp_dcs_present = -1;
static gint hf_gsm_sms_tp_pid_present = -1;
static gint hf_gsm_sms_dis_field_addr_extension = -1;
static gint hf_gsm_sms_dis_field_addr_num_type = -1;
static gint hf_gsm_sms_dis_field_addr_num_plan = -1;
static gint hf_gsm_sms_tp_pid_format_subsequent_bits = -1;
static gint hf_gsm_sms_tp_pid_telematic_interworking = -1;
static gint hf_gsm_sms_tp_pid_device_type = -1;
static gint hf_gsm_sms_tp_pid_sm_al_proto = -1;
static gint hf_gsm_sms_tp_pid_message_type = -1;
static gint hf_gsm_sms_tp_pid_reserved = -1;
static gint hf_gsm_sms_tp_pid_undefined = -1;
static gint hf_gsm_sms_tp_pid_sc_specific_use = -1;
static gint hf_gsm_sms_tp_pid_sc_specific = -1;
static gint hf_gsm_sms_dcs_text_compressed = -1;
static gint hf_gsm_sms_dcs_message_class_defined = -1;
static gint hf_gsm_sms_dcs_character_set = -1;
static gint hf_gsm_sms_dcs_message_class = -1;
static gint hf_gsm_sms_dcs_indication_sense = -1;
static gint hf_gsm_sms_dcs_reserved04 = -1;
static gint hf_gsm_sms_dcs_message_waiting = -1;
static gint hf_gsm_sms_dcs_reserved08 = -1;
static gint hf_gsm_sms_dcs_message_coding = -1;
static gint hf_gsm_sms_vp_extension = -1;
static gint hf_gsm_sms_vp_extension_ignored = -1;
static gint hf_gsm_sms_vp_single_shot_sm = -1;
static gint hf_gsm_sms_vp_reserved = -1;
static gint hf_gsm_sms_vp_validity_period_format = -1;
static gint hf_gsm_sms_vp_validity_period = -1;
static gint hf_gsm_sms_dis_field_definition = -1;
static gint hf_gsm_sms_dis_field_st_error = -1;
static gint hf_gsm_sms_dis_field_st_reason[4] = { -1, -1, -1, -1 };
static gint hf_gsm_sms_tp_user_data_length = -1;
static gint hf_gsm_sms_tp_command_type = -1;
static gint hf_gsm_sms_tp_message_number = -1;
static gint hf_gsm_sms_tp_command_data = -1;
static gint hf_gsm_sms_tp_command_data_length = -1;
static gint hf_gsm_sms_msg_ind_type_and_stor = -1;
static gint hf_gsm_sms_msg_profile_id = -1;
static gint hf_gsm_sms_ext_msg_ind_type = -1;
static gint hf_gsm_sms_msg_ind_type = -1;
static gint hf_gsm_sms_msg_count = -1;
static gint hf_gsm_sms_destination_port8 = -1;
static gint hf_gsm_sms_originator_port8 = -1;
static gint hf_gsm_sms_destination_port16 = -1;
static gint hf_gsm_sms_originator_port16 = -1;
static gint hf_gsm_sms_status_report = -1;
static gint hf_gsm_sms_status_report_short_msg = -1;
static gint hf_gsm_sms_status_report_permanent_error = -1;
static gint hf_gsm_sms_status_report_temp_error_no_attempt = -1;
static gint hf_gsm_sms_status_report_temp_error_transfer = -1;
static gint hf_gsm_sms_status_report_active = -1;
static gint hf_gsm_sms_status_report_original_udh = -1;
static gint hf_gsm_sms_udh_created = -1;
static gint hf_gsm_sms_formatting_mode = -1;
static gint hf_gsm_sms_formatting_mode_alignment = -1;
static gint hf_gsm_sms_formatting_mode_font_size = -1;
static gint hf_gsm_sms_formatting_mode_style_bold = -1;
static gint hf_gsm_sms_formatting_mode_style_italic = -1;
static gint hf_gsm_sms_formatting_mode_style_underlined = -1;
static gint hf_gsm_sms_formatting_mode_style_strikethrough = -1;
static gint hf_gsm_sms_ie_identifier = -1;
static gint hf_gsm_sms_scts_year = -1;
static gint hf_gsm_sms_scts_month = -1;
static gint hf_gsm_sms_scts_day = -1;
static gint hf_gsm_sms_scts_hour = -1;
static gint hf_gsm_sms_scts_minutes = -1;
static gint hf_gsm_sms_scts_seconds = -1;
static gint hf_gsm_sms_scts_timezone = -1;
static gint hf_gsm_sms_vp_validity_period_hour = -1;
static gint hf_gsm_sms_vp_validity_period_minutes = -1;
static gint hf_gsm_sms_vp_validity_period_seconds = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_gsm_sms_dis_field_udh_user_data_header_length = -1;
static int hf_gsm_sms_compressed_data = -1;
static int hf_gsm_sms_dis_iei_la_large_animation = -1;
static int hf_gsm_sms_dis_iei_vp_variable_picture = -1;
static int hf_gsm_sms_dis_iei_vp_horizontal_dimension = -1;
static int hf_gsm_sms_dis_iei_vp_position = -1;
static int hf_gsm_sms_dis_iei_sp_small_picture = -1;
static int hf_gsm_sms_dis_iei_tf_background_colour = -1;
static int hf_gsm_sms_dis_iei_pa_position = -1;
static int hf_gsm_sms_dis_iei_sa_position = -1;
static int hf_gsm_sms_dis_iei_ps_position = -1;
static int hf_gsm_sms_dis_field_ud_iei_length = -1;
static int hf_gsm_sms_dis_iei_upi_num_corresponding_objects = -1;
static int hf_gsm_sms_dis_iei_lp_large_picture = -1;
static int hf_gsm_sms_dis_iei_la_position = -1;
static int hf_gsm_sms_dis_iei_sa_small_animation = -1;
static int hf_gsm_sms_dis_iei_tf_start_position = -1;
static int hf_gsm_sms_dis_iei_lp_position = -1;
static int hf_gsm_sms_gsm_7_bit_default_alphabet = -1;
static int hf_gsm_sms_dis_iei_ps_sound_number = -1;
static int hf_gsm_sms_ie_data = -1;
static int hf_gsm_sms_dis_iei_vp_vertical_dimension = -1;
static int hf_gsm_sms_dis_iei_tf_foreground_colour = -1;
static int hf_gsm_sms_dis_iei_uds_user_defined_sound = -1;
static int hf_gsm_sms_dis_iei_sp_position = -1;
static int hf_gsm_sms_dis_field_addr_length = -1;
static int hf_gsm_sms_dis_iei_uds_position = -1;
static int hf_gsm_sms_dis_iei_tf_length = -1;
static int hf_gsm_sms_dis_iei_pa_animation_number = -1;
static int hf_gsm_sms_dis_iei_lang_single_shift = -1;
static int hf_gsm_sms_dis_iei_lang_locking_shift = -1;
static gint hf_gsm_sms_dis_field_udh_gsm_mask00 = -1;
static gint hf_gsm_sms_dis_field_udh_gsm_mask01 = -1;
static gint hf_gsm_sms_dis_field_udh_gsm_mask03 = -1;
static gint hf_gsm_sms_dis_field_udh_gsm_mask07 = -1;
static gint hf_gsm_sms_dis_field_udh_gsm_mask0f = -1;
static gint hf_gsm_sms_dis_field_udh_gsm_mask1f = -1;
static gint hf_gsm_sms_dis_field_udh_gsm_mask3f = -1;
static gint hf_gsm_sms_dis_field_udh_ascii_mask00 = -1;
static gint hf_gsm_sms_dis_field_udh_ascii_mask80 = -1;
static gint hf_gsm_sms_dis_field_udh_ascii_maskc0 = -1;
static gint hf_gsm_sms_dis_field_udh_ascii_maske0 = -1;
static gint hf_gsm_sms_dis_field_udh_ascii_maskf0 = -1;
static gint hf_gsm_sms_dis_field_udh_ascii_maskf8 = -1;
static gint hf_gsm_sms_dis_field_udh_ascii_maskfc = -1;


static expert_field ei_gsm_sms_short_data = EI_INIT;
static expert_field ei_gsm_sms_unexpected_data_length = EI_INIT;
static expert_field ei_gsm_sms_message_dissector_not_implemented = EI_INIT;

static gboolean reassemble_sms = TRUE;
static gboolean reassemble_sms_with_lower_layers_info = TRUE;
static proto_tree *g_tree;

/* 3GPP TS 23.038 version 7.0.0 Release 7
 * The TP-Data-Coding-Scheme field, defined in 3GPP TS 23.040 [4],
 * indicates the data coding scheme of the TP-UD field, and may indicate a message class.
 * Any reserved codings shall be assumed to be the GSM 7 bit default alphabet
 * (the same as codepoint 00000000) by a receiving entity.
 * The octet is used according to a coding group which is indicated in bits 7..4.
 */

/* Coding Group Bits */
static const value_string gsm_sms_coding_group_bits_vals[] = {
    {  0, "General Data Coding indication" },                    /* 00xx */
    {  1, "General Data Coding indication" },                    /* 00xx */
    {  2, "General Data Coding indication" },                    /* 00xx */
    {  3, "General Data Coding indication" },                    /* 00xx */
    {  4, "Message Marked for Automatic Deletion Group" },       /* 01xx */
    {  5, "Message Marked for Automatic Deletion Group" },       /* 01xx */
    {  6, "Message Marked for Automatic Deletion Group" },       /* 01xx */
    {  7, "Message Marked for Automatic Deletion Group" },       /* 01xx */
    {  8, "Reserved coding groups" },                            /* 1000..1011  */
    {  9, "Reserved coding groups" },                            /* 1000..1011  */
    { 10, "Reserved coding groups" },                            /* 1000..1011  */
    { 11, "Reserved coding groups" },                            /* 1000..1011  */
    { 12, "Message Waiting Indication Group: Discard Message" }, /* 1100  */
    { 13, "Message Waiting Indication Group: Store Message" },   /* 1101  */
    { 14, "Message Waiting Indication Group: Store Message" },   /* 1110  */
    { 15, "Data coding/message class" },                         /* 1111  */
    { 0, NULL },
};
static value_string_ext gsm_sms_coding_group_bits_vals_ext = VALUE_STRING_EXT_INIT(gsm_sms_coding_group_bits_vals);

static dissector_table_t gsm_sms_dissector_tbl;
/* Short Message reassembly */
static reassembly_table g_sm_reassembly_table;
static wmem_multimap_t *g_sm_fragment_params_table = NULL;
static gint ett_gsm_sms_ud_fragment = -1;
static gint ett_gsm_sms_ud_fragments = -1;
 /*
 * Short Message fragment handling
 */
static int hf_gsm_sms_ud_fragments = -1;
static int hf_gsm_sms_ud_fragment = -1;
static int hf_gsm_sms_ud_fragment_overlap = -1;
static int hf_gsm_sms_ud_fragment_overlap_conflicts = -1;
static int hf_gsm_sms_ud_fragment_multiple_tails = -1;
static int hf_gsm_sms_ud_fragment_too_long_fragment = -1;
static int hf_gsm_sms_ud_fragment_error = -1;
static int hf_gsm_sms_ud_fragment_count = -1;
static int hf_gsm_sms_ud_reassembled_in = -1;
static int hf_gsm_sms_ud_reassembled_length = -1;

static const fragment_items sm_frag_items = {
    /* Fragment subtrees */
    &ett_gsm_sms_ud_fragment,
    &ett_gsm_sms_ud_fragments,
    /* Fragment fields */
    &hf_gsm_sms_ud_fragments,
    &hf_gsm_sms_ud_fragment,
    &hf_gsm_sms_ud_fragment_overlap,
    &hf_gsm_sms_ud_fragment_overlap_conflicts,
    &hf_gsm_sms_ud_fragment_multiple_tails,
    &hf_gsm_sms_ud_fragment_too_long_fragment,
    &hf_gsm_sms_ud_fragment_error,
    &hf_gsm_sms_ud_fragment_count,
    /* Reassembled in field */
    &hf_gsm_sms_ud_reassembled_in,
    /* Reassembled length field */
    &hf_gsm_sms_ud_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Short Message fragments"
};

typedef struct {
    guint32 length;
    guint8  udl;
    guint8  fill_bits;
} sm_fragment_params;

typedef struct {
    const gchar *addr_info; /* TP-OA or TP-DA + optional lower layer info */
    int p2p_dir;
    address src;
    address dst;
    guint32 id;
} sm_fragment_params_key;

static guint
sm_fragment_params_hash(gconstpointer k)
{
    const sm_fragment_params_key* key = (const sm_fragment_params_key*) k;
    guint hash_val;

    hash_val = (wmem_str_hash(key->addr_info) ^ key->id) + key->p2p_dir;

    return hash_val;
}

static gboolean
sm_fragment_params_equal(gconstpointer v1, gconstpointer v2)
{
    const sm_fragment_params_key *key1 = (const sm_fragment_params_key*)v1;
    const sm_fragment_params_key *key2 = (const sm_fragment_params_key*)v2;

    return (key1->id == key2->id) &&
           (key1->p2p_dir == key2->p2p_dir) &&
           !g_strcmp0(key1->addr_info, key2->addr_info) &&
           addresses_equal(&key1->src, &key2->src) &&
           addresses_equal(&key1->dst, &key2->dst);
}

typedef struct {
    const gchar *addr_info; /* TP-OA or TP-DA + optional lower layer info */
    int p2p_dir;
    address src;
    address dst;
    guint32 id;
} sm_fragment_key;

static guint
sm_fragment_hash(gconstpointer k)
{
    const sm_fragment_key* key = (const sm_fragment_key*) k;
    guint hash_val;

    if (!key || !key->addr_info)
       return 0;

    hash_val = (wmem_str_hash(key->addr_info) ^ key->id) + key->p2p_dir;

    return hash_val;
}

static gint
sm_fragment_equal(gconstpointer k1, gconstpointer k2)
{
    const sm_fragment_key* key1 = (const sm_fragment_key*) k1;
    const sm_fragment_key* key2 = (const sm_fragment_key*) k2;

    if (!key1 || !key2)
        return FALSE;

    return (key1->id == key2->id) &&
           (key1->p2p_dir == key2->p2p_dir) &&
           !g_strcmp0(key1->addr_info, key2->addr_info) &&
           addresses_equal(&key1->src, &key2->src) &&
           addresses_equal(&key1->dst, &key2->dst);
}

static gpointer
sm_fragment_temporary_key(const packet_info *pinfo,
                          const guint32 id, const void *data)
{
    const gchar* addr = (const char*)data;
    sm_fragment_key *key;

    if (addr == NULL || pinfo->src.data == NULL || pinfo->dst.data == NULL)
        return NULL;

    key = g_slice_new(sm_fragment_key);
    key->addr_info = addr;
    key->p2p_dir = pinfo->p2p_dir;
    copy_address_shallow(&key->src, &pinfo->src);
    copy_address_shallow(&key->dst, &pinfo->dst);
    key->id = id;

    return (gpointer)key;
}

static gpointer
sm_fragment_persistent_key(const packet_info *pinfo,
                           const guint32 id, const void *data)
{
    const gchar* addr = (const char*)data;
    sm_fragment_key *key = g_slice_new(sm_fragment_key);

    if (addr == NULL || pinfo->src.data == NULL || pinfo->dst.data == NULL)
        return NULL;

    key->addr_info = wmem_strdup(NULL, addr);
    key->p2p_dir = pinfo->p2p_dir;
    copy_address(&key->src, &pinfo->src);
    copy_address(&key->dst, &pinfo->dst);
    key->id = id;

    return (gpointer)key;
}

static void
sm_fragment_free_temporary_key(gpointer ptr)
{
    sm_fragment_key *key = (sm_fragment_key *)ptr;
    g_slice_free(sm_fragment_key, key);
}

static void
sm_fragment_free_persistent_key(gpointer ptr)
{
    sm_fragment_key *key = (sm_fragment_key *)ptr;

    if(key) {
        wmem_free(NULL, (void*)key->addr_info);
        free_address(&key->src);
        free_address(&key->dst);
        g_slice_free(sm_fragment_key, key);
    }
}

static const reassembly_table_functions
sm_reassembly_table_functions = {
    sm_fragment_hash,
    sm_fragment_equal,
    sm_fragment_temporary_key,
    sm_fragment_persistent_key,
    sm_fragment_free_temporary_key,
    sm_fragment_free_persistent_key
};

/*
 * this is the GSM 03.40 definition with the bit 2
 * set to 1 for uplink messages
 */
static const value_string msg_type_strings[] = {
    { 0,        "SMS-DELIVER" },
    { 4,        "SMS-DELIVER REPORT" },
    { 5,        "SMS-SUBMIT" },
    { 1,        "SMS-SUBMIT REPORT" },
    { 2,        "SMS-STATUS REPORT" },
    { 6,        "SMS-COMMAND" },
    { 3,        "Reserved" },
    { 7,        "Reserved" },
    { 0, NULL },
};

static const value_string msg_type_strings_sc_to_ms[] = {
    { 0,        "SMS-DELIVER" },
    { 1,        "SMS-SUBMIT REPORT" },
    { 2,        "SMS-STATUS REPORT" },
    { 3,        "Reserved" },
    { 0, NULL },
};

static const value_string msg_type_strings_ms_to_sc[] = {
    { 0,        "SMS-DELIVER REPORT" },
    { 1,        "SMS-SUBMIT" },
    { 2,        "SMS-COMMAND" },
    { 3,        "Reserved" },
    { 0, NULL },
};

/* 9.2.3.3 TP-Validity-Period-Format (TP-VPF) */
static const value_string vp_type_strings[] = {
    { 0,        "TP-VP field not present"},
    { 2,        "TP-VP field present - relative format"},
    { 1,        "TP-VP field present - enhanced format"},
    { 3,        "TP-VP field present - absolute format"},
    { 0, NULL },
};

static const true_false_string mms_bool_strings = {
    "No more messages are waiting for the MS in this SC",
    "More messages are waiting for the MS in this SC"
};

static const true_false_string lp_bool_strings = {
    "The message has either been forwarded or is a spawned message",
    "The message has not been forwarded and is not a spawned message"
};

static const true_false_string sri_bool_strings = {
    "A status report shall be returned to the SME",
    "A status report shall not be returned to the SME"
};

static const true_false_string srr_bool_strings = {
    "A status report is requested",
    "A status report is not requested"
};

static const true_false_string udhi_bool_strings = {
    "The beginning of the TP UD field contains a Header in addition to the short message",
    "The TP UD field contains only the short message"
};

static const true_false_string rp_bool_strings = {
    "TP Reply Path parameter is set in this SMS SUBMIT/DELIVER",
    "TP Reply Path parameter is not set in this SMS SUBMIT/DELIVER"
};

static const true_false_string rd_bool_strings = {
    "Instruct SC to reject duplicates",
    "Instruct SC to accept duplicates"
};

static const true_false_string srq_bool_strings = {
    "The SMS STATUS REPORT is the result of an SMS COMMAND e.g. an Enquiry.",
    "SMS STATUS REPORT is the result of a SMS SUBMIT."
};

static const true_false_string tfs_extended_no_extension = {
    "Extended",
    "No extension"
};

static const true_false_string tfs_no_extension_extended = {
    "No extension",
    "Extended"
};


#define NUM_UDH_IEIS        256
static gint ett_udh_ieis[NUM_UDH_IEIS];

#define MAX_ADDR_SIZE 20

static const value_string dis_field_addr_num_types_vals[] = {
   {0,    "Unknown"},
   {1,    "International"},
   {2,    "National"},
   {3,    "Network specific"},
   {4,    "Subscriber"},
   {5,    "Alphanumeric (coded according to 3GPP TS 23.038 GSM 7-bit default alphabet)"},
   {6,    "Abbreviated number"},
   {7,    "Reserved for extension"},
   {0,    NULL }
};

static const value_string dis_field_addr_numbering_plan_vals[] = {
   {0x0,    "Unknown"},
   {0x1,    "ISDN/telephone (E.164/E.163)"},
   {0x3,    "Data numbering plan (X.121)"},
   {0x4,    "Telex numbering plan"},
   {0x5,    "Service Centre Specific plan"},
   {0x6,    "Service Centre Specific plan"},
   {0x8,    "National numbering plan"},
   {0x9,    "Private numbering plan"},
   {0xa,    "ERMES numbering plan (ETSI DE/PS 3 01-3)"},
   {0xf,    "Reserved for extension"},
   {0,      NULL }
};

void
dis_field_addr(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 *offset_p, const gchar *title)
{
    proto_item  *item;
    proto_tree  *subtree;
    guint8       oct, nt_mp;
    guint32      offset;
    guint32      numdigocts;
    guint32      length, addrlength;
    gchar       *addrstr;

    offset = *offset_p;

    addrlength = tvb_get_guint8(tvb, offset);
    numdigocts = (addrlength + 1) / 2;

    length = tvb_reported_length_remaining(tvb, offset);

    if (length <= numdigocts)
    {
        proto_tree_add_expert_format(tree, pinfo, &ei_gsm_sms_short_data,
            tvb, offset, length, "%s: Short Data (?)", title);

        *offset_p += length;
        return;
    }

    subtree = proto_tree_add_subtree(tree, tvb,
            offset, numdigocts + 2, ett_addr, &item, title);

    proto_tree_add_uint_format_value(subtree, hf_gsm_sms_dis_field_addr_length,
        tvb, offset, 1,
        addrlength, "%d address digits", addrlength);

    offset++;
    oct = tvb_get_guint8(tvb, offset);
    nt_mp = oct & 0x7f;

    proto_tree_add_item(subtree, hf_gsm_sms_dis_field_addr_extension, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_gsm_sms_dis_field_addr_num_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_sms_dis_field_addr_num_plan, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    switch ((oct & 0x70) >> 4)
    {
    case 0x05: /* "Alphanumeric (coded according to 3GPP TS 23.038 GSM 7-bit default alphabet)" */
        addrlength = (addrlength << 2) / 7;
        addrstr = tvb_get_ts_23_038_7bits_string_packed(pinfo->pool, tvb, offset << 3,
                                                 (addrlength > MAX_ADDR_SIZE) ? MAX_ADDR_SIZE : addrlength);
        break;
    default:
        addrstr = tvb_get_string_enc(pinfo->pool, tvb, offset, numdigocts, ENC_KEYPAD_ABC_TBCD|ENC_NA);
        break;
    }

    if (g_ascii_strncasecmp(title, "TP-O", 4) == 0) {
        proto_tree_add_string(subtree, hf_gsm_sms_tp_oa, tvb,
                offset, numdigocts, addrstr);
        if (((nt_mp >> 4) == 1) && ((nt_mp & 0x0f) == 1)) {
            /* if Type of number international and number plan is E.164*/
            dissect_e164_msisdn(tvb, subtree, offset, numdigocts, E164_ENC_BCD);
        }
        p_add_proto_data(pinfo->pool, pinfo, proto_gsm_sms, 0,
                         wmem_strdup(pinfo->pool, addrstr));
    } else if (g_ascii_strncasecmp(title, "TP-D", 4) == 0) {
        proto_tree_add_string(subtree, hf_gsm_sms_tp_da, tvb,
                offset, numdigocts, addrstr);
        if (((nt_mp >> 4) == 1) && ((nt_mp & 0x0f) == 1)) {
            /* if Type of number international and number plan is E.164*/
            dissect_e164_msisdn(tvb, subtree, offset, numdigocts, E164_ENC_BCD);
        }
        p_add_proto_data(pinfo->pool, pinfo, proto_gsm_sms, 0,
                         wmem_strdup(pinfo->pool, addrstr));
    } else if (g_ascii_strncasecmp(title, "TP-R", 4) == 0) {
        proto_tree_add_string(subtree, hf_gsm_sms_tp_ra, tvb,
                offset, numdigocts, addrstr);
    } else {
        proto_tree_add_string(subtree, hf_gsm_sms_tp_digits, tvb,
                offset, numdigocts, addrstr);
    }

    proto_item_append_text(item, " - (%s)", addrstr);

    *offset_p = offset + numdigocts;
}

/* 9.2.3.7 */
/* use dis_field_addr() */

/* 9.2.3.8 */
/* use dis_field_addr() */

/* 9.2.3.9 */
static const true_false_string tfs_telematic_interworking = { "Yes", "no telematic interworking, but SME-to-SME protocol" };

static const range_string tp_pid_device_type_rvals[] = {
    { 0x00, 0x00,  "implicit - device type is specific to this SC, or can be concluded on the basis of the address" },
    { 0x01, 0x01,  "telex (or teletex reduced to telex format)" },
    { 0x02, 0x02,  "group 3 telefax" },
    { 0x03, 0x03,  "group 4 telefax" },
    { 0x04, 0x04,  "voice telephone (i.e. conversion to speech)" },
    { 0x05, 0x05,  "ERMES (European Radio Messaging System)" },
    { 0x06, 0x06,  "National Paging system (known to the SC)" },
    { 0x07, 0x07,  "Videotex (T.100 [20] /T.101 [21])" },
    { 0x08, 0x08,  "teletex, carrier unspecified" },
    { 0x09, 0x09,  "teletex, in PSPDN" },
    { 0x0A, 0x0A,  "teletex, in CSPDN" },
    { 0x0B, 0x0B,  "teletex, in analog PSTN" },
    { 0x0C, 0x0C,  "teletex, in digital ISDN" },
    { 0x0D, 0x0D,  "UCI (Universal Computer Interface, ETSI DE/PS 3 01-3)" },
    { 0x0E, 0x0F,  "Reserved" },
    { 0x10, 0x10,  "a message handling facility (known to the SC)" },
    { 0x11, 0x11,  "any public X.400-based message handling system" },
    { 0x12, 0x12,  "Internet Electronic Mail" },
    { 0x13, 0x17,  "Reserved" },
    { 0x18, 0x1E,  "values specific to each SC" },
    { 0x1F, 0x1F,  "GSM/UMTS mobile station" },
    { 0, 0, NULL }
};

static const value_string pid_message_type_vals[] = {
   {0x00,    "Short Message Type 0"},
   {0x01,    "Replace Short Message Type 1"},
   {0x02,    "Replace Short Message Type 2"},
   {0x03,    "Replace Short Message Type 3"},
   {0x04,    "Replace Short Message Type 4"},
   {0x05,    "Replace Short Message Type 5"},
   {0x06,    "Replace Short Message Type 6"},
   {0x07,    "Replace Short Message Type 7"},
   {0x08,    "Device Triggering Short Message"},
   {0x1e,    "Enhanced Message Service (Obsolete)"},
   {0x1f,    "Return Call Message"},
   {0x3c,    "ANSI-136 R-DATA"},
   {0x3d,    "ME Data download"},
   {0x3e,    "ME De-personalization Short Message"},
   {0x3f,    "(U)SIM Data download"},
   {0,      NULL }
};

static void
dis_field_pid(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 oct)
{
    proto_item  *item;
    proto_tree  *subtree;

    item = proto_tree_add_item(tree, hf_gsm_sms_tp_pid, tvb, offset, 1, ENC_BIG_ENDIAN);
    subtree = proto_item_add_subtree(item, ett_pid);

    switch ((oct & 0xc0) >> 6)
    {
    case 0:
        proto_tree_add_item(subtree, hf_gsm_sms_tp_pid_format_subsequent_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_sms_tp_pid_telematic_interworking, tvb, offset, 1, ENC_NA);

        if (oct & 0x20)
        {
            proto_tree_add_item(subtree, hf_gsm_sms_tp_pid_device_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        else
        {
            proto_tree_add_item(subtree, hf_gsm_sms_tp_pid_sm_al_proto, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        break;

    case 1:
        proto_tree_add_item(subtree, hf_gsm_sms_tp_pid_format_subsequent_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_sms_tp_pid_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;

    case 2:
        proto_tree_add_item(subtree, hf_gsm_sms_tp_pid_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_sms_tp_pid_undefined, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;

    case 3:
        proto_tree_add_item(subtree, hf_gsm_sms_tp_pid_sc_specific_use, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_sms_tp_pid_sc_specific, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    }
}

/* 9.2.3.10 */
static const value_string dcs_character_set_vals[] = {
   {0x00,    "GSM 7 bit default alphabet"},
   {0x01,    "8 bit data"},
   {0x02,    "UCS2 (16 bit)/UTF-16"},
   {0x03,    "Reserved"},
   {0,      NULL }
};

static const value_string dcs_message_class_vals[] = {
   {0x00,    "Class 0"},
   {0x01,    "Class 1 Default meaning: ME-specific"},
   {0x02,    "Class 2 (U)SIM specific message"},
   {0x03,    "Class 3 Default meaning: TE-specific"},
   {0,      NULL }
};

static const value_string dcs_message_waiting_vals[] = {
   {0x00,    "Voicemail"},
   {0x01,    "Fax"},
   {0x02,    "Electronic Mail"},
   {0x03,    "Other"},
   {0,      NULL }
};

static const true_false_string tfs_indication_sense = { "Set Indication Active", "Set Indication Inactive"};
static const true_false_string tfs_message_coding = { "8 bit data", "GSM 7 bit default alphabet"};
static const true_false_string tfs_compressed_not_compressed = { "Compressed", "Not compressed"};
static const true_false_string tfs_message_class_defined = { "Defined below", "Reserved, no message class"};

static void
dis_field_dcs(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 oct,
    enum character_set *cset, gboolean *compressed)
{
    proto_item  *item;
    proto_tree  *subtree;
    gboolean     default_5_bits;
    gboolean     default_3_bits;
    gboolean     default_data;

    *cset       = OTHER;
    *compressed = FALSE;

    item = proto_tree_add_item(tree, hf_gsm_sms_tp_dcs, tvb, offset, 1, ENC_BIG_ENDIAN);

    subtree = proto_item_add_subtree(item, ett_dcs);
    if (oct&0x80) {
        proto_tree_add_item(subtree, hf_gsm_sms_coding_group_bits4, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(subtree, hf_gsm_sms_coding_group_bits2, tvb, offset, 1, ENC_BIG_ENDIAN);
    }

    if (oct == 0x00)
    {
        proto_tree_add_item(subtree, hf_gsm_sms_gsm_7_bit_default_alphabet, tvb, offset, 1, ENC_NA);

        *cset      = GSM_7BITS;
        return;
    }

    default_5_bits = FALSE;
    default_3_bits = FALSE;
    default_data   = FALSE;

    switch ((oct & 0xc0) >> 6)
    {
    case 0:
        default_5_bits = TRUE;
        break;

    case 1:
        default_5_bits = TRUE;
        break;

    case 2:
        /* Reserved coding groups */
        return;

    case 3:
        switch ((oct & 0x30) >> 4)
        {
        case 0x00:
            default_3_bits = TRUE;
            *cset      = GSM_7BITS;
            break;
        case 0x01:
            default_3_bits = TRUE;
            *cset      = GSM_7BITS;
            break;
        case 0x02:
            default_3_bits = TRUE;
            *cset      = UCS2;
            break;
        case 0x03:
            default_data = TRUE;
            break;
        }
        break;
    }

    if (default_5_bits)
    {
        *compressed = (oct & 0x20) >> 5;
        proto_tree_add_item(subtree, hf_gsm_sms_dcs_text_compressed, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_sms_dcs_message_class_defined, tvb, offset, 1, ENC_NA);

        switch ((oct & 0x0c) >> 2)
        {
        case 0x00:
            *cset      = GSM_7BITS;
            break;
        case 0x01:
            *cset      = OTHER;
            break;
        case 0x02:
            *cset      = UCS2;
            break;
        case 0x03:
            /* Reserved */
            break;
        }

        proto_tree_add_item(subtree, hf_gsm_sms_dcs_character_set, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_sms_dcs_message_class, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    else if (default_3_bits)
    {
        proto_tree_add_item(subtree, hf_gsm_sms_dcs_indication_sense, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_sms_dcs_reserved04, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_sms_dcs_message_waiting, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    else if (default_data)
    {
        *cset      = (oct & 0x04) ? OTHER : GSM_7BITS;
        proto_tree_add_item(subtree, hf_gsm_sms_dcs_reserved08, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_sms_dcs_message_coding, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_sms_dcs_message_class, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
}

static void
dis_field_scts_aux(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    guint8 oct;
    guint16 value;
    char   sign;

    oct = tvb_get_guint8(tvb, offset);
    value = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
    proto_tree_add_uint(tree, hf_gsm_sms_scts_year, tvb, offset, 1, value);
    offset++;
    oct = tvb_get_guint8(tvb, offset);
    value = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
    proto_tree_add_uint(tree, hf_gsm_sms_scts_month, tvb, offset, 1, value);
    offset++;
    oct = tvb_get_guint8(tvb, offset);
    value = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
    proto_tree_add_uint(tree, hf_gsm_sms_scts_day, tvb, offset, 1, value);
    offset++;
    oct = tvb_get_guint8(tvb, offset);
    value = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
    proto_tree_add_uint(tree, hf_gsm_sms_scts_hour, tvb, offset, 1, value);
    offset++;
    oct = tvb_get_guint8(tvb, offset);
    value = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
    proto_tree_add_uint(tree, hf_gsm_sms_scts_minutes, tvb, offset, 1, value);
    offset++;
    oct = tvb_get_guint8(tvb, offset);
    value = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
    proto_tree_add_uint(tree, hf_gsm_sms_scts_seconds, tvb, offset, 1, value);
    offset++;

    oct = tvb_get_guint8(tvb, offset);

    sign = (oct & 0x08)?'-':'+';
    oct = (oct >> 4) + (oct & 0x07) * 10;

    proto_tree_add_uint_format_value(tree, hf_gsm_sms_scts_timezone, tvb, offset, 1,
        oct, "GMT %c %d hours %d minutes",
        sign, oct / 4, oct % 4 * 15);
}

/* 9.2.3.11 */
static void
dis_field_scts(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 *offset_p)
{
    proto_tree *subtree;
    guint32     offset;
    guint32     length;


    offset = *offset_p;

    length = tvb_reported_length_remaining(tvb, offset);

    if (length < 7)
    {
        proto_tree_add_expert_format(tree, pinfo, &ei_gsm_sms_short_data,
            tvb, offset, length,
            "TP-Service-Centre-Time-Stamp: Short Data (?)");

        *offset_p += length;
        return;
    }

    subtree = proto_tree_add_subtree(tree, tvb,
            offset, 7, ett_scts, NULL,
            "TP-Service-Centre-Time-Stamp");

    dis_field_scts_aux(tvb, subtree, *offset_p);

    *offset_p += 7;
}

/* 9.2.3.12 */
static const value_string vp_validity_period_format_vals[] = {
   {0x00,    "None specified"},
   {0x01,    "Relative"},
   {0x02,    "Relative"},
   {0x03,    "Relative"},
   {0x04,    "Reserved"},
   {0x05,    "Reserved"},
   {0x06,    "Reserved"},
   {0x07,    "Reserved"},
   {0,      NULL }
};

static void
dis_field_vp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 *offset_p, guint8 vp_form)
{
    proto_tree *subtree;
    guint32     offset;
    guint32     length;
    guint8      oct;
    guint8      loc_form;
    guint16     value;
    guint32     mins, hours;
    gboolean    done;


    if (vp_form == 0x00) return;

    offset  = *offset_p;
    subtree = tree;

    done = FALSE;
    do
    {
        switch (vp_form)
        {
        case 1:
            length = tvb_reported_length_remaining(tvb, offset);

            if (length < 7)
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_gsm_sms_short_data,
                    tvb, offset, length,
                    "TP-Validity-Period: Short Data (?)");

                *offset_p += length;
                return;
            }

            subtree = proto_tree_add_subtree(tree, tvb, offset, 7, ett_vp, NULL, "TP-Validity-Period");

            oct = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(subtree, hf_gsm_sms_vp_extension, tvb, offset, 1, ENC_NA);
            if (oct & 0x80)
            {
                proto_tree_add_item(subtree, hf_gsm_sms_vp_extension_ignored, tvb, offset + 1, 6, ENC_NA);
                *offset_p += 7;
                return;
            }

            proto_tree_add_item(subtree, hf_gsm_sms_vp_single_shot_sm, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(subtree, hf_gsm_sms_vp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_gsm_sms_vp_validity_period_format, tvb, offset, 1, ENC_BIG_ENDIAN);

            loc_form = oct & 0x7;
            switch (loc_form)
            {
            case 0x00:
                done = TRUE;
                break;

            case 0x01:
                offset++;
                /* go around again */
                vp_form = 2;
                break;

            case 0x02:
                offset++;
                oct = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint_format_value(subtree, hf_gsm_sms_vp_validity_period, tvb, offset, 1,
                    oct, "%d seconds", oct);
                done = TRUE;
                break;

            case 0x03:
                offset++;
                oct = tvb_get_guint8(tvb, offset);
                value = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
                proto_tree_add_uint(subtree, hf_gsm_sms_vp_validity_period_hour, tvb, offset, 1, value);
                offset++;
                oct = tvb_get_guint8(tvb, offset);
                value = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
                proto_tree_add_uint(subtree, hf_gsm_sms_vp_validity_period_minutes, tvb, offset, 1, value);
                offset++;
                oct = tvb_get_guint8(tvb, offset);
                value = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
                proto_tree_add_uint(subtree, hf_gsm_sms_vp_validity_period_seconds, tvb, offset, 1, value);
                offset++;
                done = TRUE;
                break;

            default:
                done = TRUE;
                break;
            }
            break;

        case 2:
            oct = tvb_get_guint8(tvb, offset);

            if (oct <= 143)
            {
                mins = (oct + 1) * 5;
                if (mins >= 60)
                {
                    hours = mins / 60;
                    mins %= 60;

                    proto_tree_add_uint_format_value(subtree, hf_gsm_sms_vp_validity_period, tvb, offset, 1,
                        oct, "%d hours %d minutes", hours, mins);
                }
                else
                {
                    proto_tree_add_uint_format_value(subtree, hf_gsm_sms_vp_validity_period, tvb, offset, 1,
                        oct, "%d minutes", mins);
                }
            }
            else if ((oct >= 144) &&
                (oct <= 167))
            {
                mins = (oct - 143) * 30;
                hours = 12 + (mins / 60);
                mins %= 60;

                    proto_tree_add_uint_format_value(subtree, hf_gsm_sms_vp_validity_period, tvb, offset, 1,
                        oct, "%d hours %d minutes", hours, mins);
            }
            else if ((oct >= 168) &&
                (oct <= 196))
            {
                proto_tree_add_uint_format_value(subtree, hf_gsm_sms_vp_validity_period, tvb, offset, 1,
                    oct, "%d day(s)", oct - 166);
            }
            else if (oct >= 197)
            {
                proto_tree_add_uint_format_value(subtree, hf_gsm_sms_vp_validity_period, tvb, offset, 1,
                    oct, "%d week(s)", oct - 192);
            }

            done = TRUE;
            break;

        case 3:
            length = tvb_reported_length_remaining(tvb, offset);

            if (length < 7)
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_gsm_sms_short_data,
                    tvb, offset, length,
                    "TP-Validity-Period: Short Data (?)");

                *offset_p += length;
                return;
            }

            subtree = proto_tree_add_subtree(tree, tvb,
                    offset, 7, ett_vp, NULL,
                    "TP-Validity-Period: absolute");

            dis_field_scts_aux(tvb, subtree, *offset_p);

            done = TRUE;
            break;
        }
    }
    while (!done);

    if (vp_form == 2)
    {
        (*offset_p)++;
    }
    else
    {
        *offset_p += 7;
    }
}

/* 9.2.3.13 */
static void
dis_field_dt(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 *offset_p)
{
    proto_tree *subtree;
    guint32     offset;
    guint32     length;


    offset = *offset_p;

    length = tvb_reported_length_remaining(tvb, offset);

    if (length < 7)
    {
        proto_tree_add_expert_format(tree, pinfo, &ei_gsm_sms_short_data,
            tvb, offset, length,
            "TP-Discharge-Time: Short Data (?)");

        *offset_p += length;
        return;
    }

    subtree = proto_tree_add_subtree(tree, tvb,
            offset, 7, ett_dt, NULL,
            "TP-Discharge-Time");

    dis_field_scts_aux(tvb, subtree, *offset_p);

    *offset_p += 7;
}

/* 9.2.3.14 */
/* use dis_field_addr() */

/* 9.2.3.15 TP-Status (TP-ST) */
static const value_string dis_field_st_error_vals[] = {
    { 0x00,  "No error, short message transaction completed" },
    { 0x01,  "Temporary error, SC still trying to transfer SM" },
    { 0x02,  "Permanent error, SC is not making any more transfer attempts" },
    { 0x03,  "Temporary error, SC is not making any more transfer attempts" },
    { 0x00,  NULL },
};

static const range_string dis_field_st_error00_reason_rvals[] = {
    { 0x00, 0x00,  "Short message received by the SME" },
    { 0x01, 0x01,  "Short message forwarded by the SC to the SME but the SC is unable to confirm delivery" },
    { 0x02, 0x02,  "Short message replaced by the SC Reserved values" },
    { 0x03, 0x0F,  "Reserved" },
    { 0x10, 0x1F,  "Values specific to each SC" },
    { 0x00, 0x00,  NULL },
};

static const range_string dis_field_st_error01_reason_rvals[] = {
    { 0x00, 0x00,  "Congestion" },
    { 0x01, 0x01,  "SME busy" },
    { 0x02, 0x02,  "No response from SME" },
    { 0x03, 0x03,  "Service rejected" },
    { 0x04, 0x04,  "Quality of service not available" },
    { 0x05, 0x05,  "Error in SME" },
    { 0x06, 0x0F,  "Reserved" },
    { 0x10, 0x1F,  "Values specific to each SC" },
    { 0x00, 0x00,  NULL },
};

static const range_string dis_field_st_error10_reason_rvals[] = {
    { 0x00, 0x00,  "Remote procedure error" },
    { 0x01, 0x01,  "Incompatible destination" },
    { 0x02, 0x02,  "Connection rejected by SME" },
    { 0x03, 0x03,  "Not obtainable" },
    { 0x04, 0x04,  "Quality of service not available" },
    { 0x05, 0x05,  "No interworking available" },
    { 0x06, 0x06,  "SM Validity Period Expired" },
    { 0x07, 0x07,  "SM Deleted by originating SME" },
    { 0x08, 0x08,  "SM Deleted by SC Administration" },
    { 0x09, 0x09,  "SM does not exist (The SM may have previously existed in the SC but the SC no longer has knowledge of it or the SM may never have previously existed in the SC)" },
    { 0x0A, 0x0F,  "Reserved" },
    { 0x10, 0x1f,  "Values specific to each SC" },
    { 0x00, 0x00,  NULL },
};

static const range_string dis_field_st_error11_reason_rvals[] = {
    { 0x00, 0x00,  "Congestion" },
    { 0x01, 0x01,  "SME busy" },
    { 0x02, 0x02,  "No response from SME" },
    { 0x03, 0x03,  "Service rejected" },
    { 0x04, 0x04,  "Quality of service not available" },
    { 0x05, 0x05,  "Error in SME" },
    { 0x06, 0x0F,  "Reserved" },
    { 0x10, 0x1F,  "Values specific to each SC" },
    { 0x00, 0x00,  NULL },
};

static const true_false_string tfs_dis_field_definition = { "Reserved", "as follows" };

static void
dis_field_st(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_tree         *subtree;
    guint32             error;

    subtree = proto_tree_add_subtree(tree, tvb,
            offset, 1, ett_st, NULL, "TP-Status");

    proto_tree_add_item(subtree, hf_gsm_sms_dis_field_definition, tvb, offset, 1, ENC_NA);
    proto_tree_add_item_ret_uint(subtree, hf_gsm_sms_dis_field_st_error,
                                 tvb, offset, 1, ENC_BIG_ENDIAN, &error);

    /* Shall not happen as we use mask 0x60 (2 bits high) to get the value */
    DISSECTOR_ASSERT(error < array_length(hf_gsm_sms_dis_field_st_reason));
    proto_tree_add_item(subtree, hf_gsm_sms_dis_field_st_reason[error],
                        tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 9.2.3.16 */
#define DIS_FIELD_UDL(m_tree, m_offset) \
    proto_tree_add_uint_format_value(m_tree, hf_gsm_sms_tp_user_data_length, tvb, m_offset, 1, oct, \
                                     "(%d) %s", oct, oct ? "depends on Data-Coding-Scheme" : "no User-Data");

/* 9.2.3.17 */
#define DIS_FIELD_RP(m_tree, hf, m_offset) \
    proto_tree_add_item(m_tree, hf, tvb, m_offset, 1, ENC_NA);

/* 9.2.3.18 */
#define DIS_FIELD_MN(m_tree, m_offset) \
    proto_tree_add_item(m_tree, hf_gsm_sms_tp_message_number, tvb, m_offset, 1, ENC_BIG_ENDIAN);

/* 9.2.3.19 */
static const range_string tp_command_type_rvals[] = {
    { 0x00, 0x00,  "Enquiry relating to previously submitted short message" },
    { 0x01, 0x01,  "Cancel Status Report Request relating to previously submitted short message" },
    { 0x02, 0x02,  "Delete previously submitted Short Message" },
    { 0x03, 0x03,  "Enable Status Report Request relating to previously submitted short message" },
    { 0x04, 0x1F,  "Reserved unspecified" },
    { 0x20, 0xDF,  "Undefined" },
    { 0xE0, 0xFF,  "Values specific for each SC" },
    { 0x00, 0x00,  NULL },
};

#define DIS_FIELD_CT(m_tree, m_offset) \
    proto_tree_add_item(m_tree, hf_gsm_sms_tp_command_type, tvb, m_offset, 1, ENC_BIG_ENDIAN);

/* 9.2.3.20 */
#define DIS_FIELD_CDL(m_tree, m_offset) \
    if (oct) \
        proto_tree_add_item(m_tree, hf_gsm_sms_tp_command_data_length, tvb, m_offset, 1, ENC_BIG_ENDIAN); \
    else    \
        proto_tree_add_uint_format_value(m_tree, hf_gsm_sms_tp_command_data_length, tvb, m_offset, 1, 0, "(0) no Command-Data"); \

/* 9.2.3.21 */
/* done in-line in the message functions */

/*
 * 9.2.3.22 TP-Failure-Cause (TP-FCS)
 */


static const range_string gsm_sms_tp_failure_cause_values[] = {
  { 0x00, 0x7F,  "Reserved" },
        /* 80 - 8F TP-PID errors */
  { 0x80, 0x80,  "Telematic interworking not supported" },
  { 0x81, 0x81,  "Short message Type 0 not supported" },
  { 0x82, 0x82,  "Cannot replace short message" },
  { 0x83, 0x8E,  "Reserved" },
  { 0x8F, 0x8F,  "Unspecified TP-PID error" },
        /* 90 - 9F TP-DCS errors */
  { 0x90, 0x90,  "Data coding scheme (alphabet) not supported" },
  { 0x91, 0x91,  "Message class not supported" },
  { 0x92, 0x9E,  "Reserved" },
  { 0x9F, 0x9F,  "Unspecified TP-DCS error" },
        /* A0 - AF TP-Command Errors */
  { 0xA0, 0xA0,  "Command cannot be actioned" },
  { 0xA1, 0xA1,  "Command unsupported" },
  { 0xA2, 0xAE,  "Reserved" },
  { 0xAF, 0xAF,  "Unspecified TP-Command error" },
  { 0xB0, 0xB0,  "TPDU not supported" },
  { 0xB1, 0xBF,  "Reserved" },
  { 0xC0, 0xC0,  "SC busy" },
  { 0xC1, 0xC1,  "No SC subscription" },
  { 0xC2, 0xC2,  "SC system failure" },
  { 0xC3, 0xC3,  "Invalid SME address" },
  { 0xC4, 0xC4,  "Destination SME barred" },
  { 0xC5, 0xC5,  "SM Rejected-Duplicate SM" },
  { 0xC6, 0xC6,  "TP-VPF not supported" },
  { 0xC7, 0xC7,  "TP-VP not supported" },
  { 0xC8, 0xCF,  "Reserved" },
  { 0xD0, 0xD0,  "(U)SIM SMS storage full" },
  { 0xD1, 0xD1,  "No SMS storage capability in (U)SIM" },
  { 0xD2, 0xD2,  "Error in MS" },
  { 0xD3, 0xD3,  "Memory Capacity Exceeded" },
  { 0xD4, 0xD4,  "(U)SIM Application Toolkit Busy" },
  { 0xD5, 0xD5,  "(U)SIM data download error" },
  { 0xD6, 0xDF,  "Reserved" },
  { 0xE0, 0xFE,  "Value specific to an application" },
  { 0xFF, 0xFF,  "Unspecified error cause" },
  { 0,    0,     NULL }
 };

static void
dis_field_fcs(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 oct _U_)
{
    proto_tree_add_item(tree, hf_gsm_sms_tp_fail_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 9.2.3.23 */
#if 0
static const true_false_string tfs_user_data_header_indicator = { "The beginning of the TP-UD field contains a Header in addition to the short message",
            "The TP-UD field contains only the short message" };
#endif

#define DIS_FIELD_UDHI(m_tree, hf, m_offset) \
    proto_tree_add_item(m_tree, hf, tvb, m_offset, 1, ENC_BIG_ENDIAN);

/* 9.2.3.24.1 */
static void
dis_iei_csm8(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields)
{
    guint8        oct;

    EXACT_DATA_CHECK(length, 3);
    oct = tvb_get_guint8(tvb, offset);
    p_udh_fields->sm_id = oct;
    proto_tree_add_uint (tree, hf_gsm_sms_ud_multiple_messages_msg_id,
                         tvb, offset, 1, oct);
    offset++;

    oct = tvb_get_guint8(tvb, offset);
    p_udh_fields->frags = oct;
    proto_tree_add_uint (tree, hf_gsm_sms_ud_multiple_messages_msg_parts,
                         tvb, offset, 1, oct);
    offset++;
    oct = tvb_get_guint8(tvb, offset);
    p_udh_fields->frag = oct;
    proto_tree_add_uint (tree,
                         hf_gsm_sms_ud_multiple_messages_msg_part,
                         tvb, offset, 1, oct);

}

/* 9.2.3.24.2 Special SMS Message Indication */
static const true_false_string gsm_sms_msg_type_and_stor_value = {
    "Store message after updating indication",
    "Discard message after updating indication"
};

static const value_string gsm_sms_profile_id_vals[] = {
    { 0, "Profile ID 1" },
    { 1, "Profile ID 2" },
    { 2, "Profile ID 3" },
    { 3, "Profile ID 4" },
    { 0, NULL },
};

static const range_string gsm_sms_ext_msg_ind_type_vals[] = {
  { 0, 0, "No extended message indication type" },
  { 1, 1, "Video Message Waiting" },
  { 2, 7, "Reserved" },
  { 0, 0, NULL }
};

static const value_string gsm_sms_msg_ind_type_vals[] = {
    { 0, "Voice Message Waiting" },
    { 1, "Fax Message Waiting" },
    { 2, "Electronic Mail Message Waiting" },
    { 3, "Extended Message Type Waiting" },
    { 0, NULL },
};

static void
dis_iei_spe_sms_msg_ind(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset,
                        guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    EXACT_DATA_CHECK(length, 2);

    proto_tree_add_item(tree, hf_gsm_sms_msg_ind_type_and_stor, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_msg_profile_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_ext_msg_ind_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_msg_ind_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_msg_count, tvb, offset+1, 1, ENC_BIG_ENDIAN);
}

/* 9.2.3.24.3 */
static const range_string gsm_sms_8bit_port_values[] = {
  { 0,   239,  "Reserved" },
  { 240, 255,  "Available for allocation by applications" },
  { 0,   0,     NULL }
};

static void
dis_iei_apa_8bit(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields)
{
    EXACT_DATA_CHECK(length, 2);

    p_udh_fields->port_dst = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gsm_sms_destination_port8, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    p_udh_fields->port_src = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gsm_sms_originator_port8, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 9.2.3.24.4 */
static const range_string gsm_sms_16bit_port_values[] = {
  { 0,     15999, "UDP/TCP port numbers assigned by IANA without the need to refer to 3GPP" },
  { 16000, 16999, "Available for allocation by SMS applications without the need to refer to 3GPP or IANA" },
  { 17000, 49151, "UDP/TCP port numbers assigned by IANA" },
  { 49152, 65535, "Reserved for future allocation by 3GPP" },
  { 0,   0,     NULL }
};

static void
dis_iei_apa_16bit(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields)
{
    EXACT_DATA_CHECK(length, 4);

    p_udh_fields->port_dst = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_gsm_sms_destination_port16, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    p_udh_fields->port_src = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_gsm_sms_originator_port16, tvb, offset, 2, ENC_BIG_ENDIAN);
}

/* 9.2.3.24.5 */
static const true_false_string tfs_status_report_active = { "A Status Report generated by this Short Message, due to a permanent error or last temporary error, cancels the SRR of the rest of the Short Messages in a concatenated message",
                                                            "No activation" };

static void
dis_iei_scp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    static int * const status_flags[] = {
        &hf_gsm_sms_status_report_short_msg,
        &hf_gsm_sms_status_report_permanent_error,
        &hf_gsm_sms_status_report_temp_error_no_attempt,
        &hf_gsm_sms_status_report_temp_error_transfer,
        &hf_gsm_sms_status_report_active,
        &hf_gsm_sms_status_report_original_udh,
        NULL
    };

    EXACT_DATA_CHECK(length, 1);

    proto_tree_add_bitmask(tree, tvb, offset, hf_gsm_sms_status_report, ett_st, status_flags, ENC_NA);
}

/* 9.2.3.24.6 */
static const value_string udh_created_vals[] = {
   {0x01,    "Original sender (valid in case of Status Report)"},
   {0x02,    "Original receiver (valid in case of Status Report)"},
   {0x03,    "SMSC (can occur in any message or report)"},
   {0,      NULL }
};

static void
dis_iei_udh_si(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    EXACT_DATA_CHECK(length, 1);

    proto_tree_add_item(tree, hf_gsm_sms_udh_created, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 9.2.3.24.8 */
static void
dis_iei_csm16(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields)
{
    guint8        oct;
    guint16       oct_ref;

    EXACT_DATA_CHECK(length, 4);
    oct_ref = tvb_get_ntohs(tvb, offset);
    p_udh_fields->sm_id = oct_ref;
    proto_tree_add_uint (tree,
                         hf_gsm_sms_ud_multiple_messages_msg_id,
                         tvb, offset, 2, oct_ref);
    offset+=2;
    oct = tvb_get_guint8(tvb, offset);
    p_udh_fields->frags = oct;
    proto_tree_add_uint (tree,
                         hf_gsm_sms_ud_multiple_messages_msg_parts,
                         tvb , offset , 1, oct);

    offset++;
    oct = tvb_get_guint8(tvb, offset);
    p_udh_fields->frag = oct;
    proto_tree_add_uint (tree,
                         hf_gsm_sms_ud_multiple_messages_msg_part,
                         tvb, offset, 1, oct);
}

static const value_string text_color_values[] = {
  { 0x00,        "Black" },
  { 0x01,        "Dark Grey" },
  { 0x02,        "Dark Red" },
  { 0x03,        "Dark Yellow" },
  { 0x04,        "Dark Green" },
  { 0x05,        "Dark Cyan" },
  { 0x06,        "Dark Blue" },
  { 0x07,        "Dark Magenta" },
  { 0x08,        "Grey" },
  { 0x09,        "White" },
  { 0x0A,        "Bright Red" },
  { 0x0B,        "Bright Yellow" },
  { 0x0C,        "Bright Green" },
  { 0x0D,        "Bright Cyan" },
  { 0x0E,        "Bright Blue" },
  { 0x0F,        "Bright Magenta" },
  { 0,           NULL }
};
static value_string_ext text_color_values_ext = VALUE_STRING_EXT_INIT(text_color_values);

static const value_string alignment_values[] = {
  { 0x00,        "Left" },
  { 0x01,        "Center" },
  { 0x02,        "Right" },
  { 0x03,        "Language dependent" },
  { 0,           NULL }
};

static const value_string font_size_values[] = {
  { 0x00,        "Normal" },
  { 0x01,        "Large" },
  { 0x02,        "Small" },
  { 0x03,        "Reserved" },
  { 0,           NULL }
};

/* 9.2.3.24.10.1.1 */
static void
dis_iei_tf(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    proto_tree* subtree_colour;

    static int * const format_flags[] = {
        &hf_gsm_sms_formatting_mode_alignment,
        &hf_gsm_sms_formatting_mode_font_size,
        &hf_gsm_sms_formatting_mode_style_bold,
        &hf_gsm_sms_formatting_mode_style_italic,
        &hf_gsm_sms_formatting_mode_style_underlined,
        &hf_gsm_sms_formatting_mode_style_strikethrough,
        NULL
    };

    SHORT_DATA_CHECK(length, 3);

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_tf_start_position, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_tf_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_bitmask(tree, tvb, offset, hf_gsm_sms_formatting_mode, ett_udh_tfm, format_flags, ENC_NA);
    offset++;

    if (length > 3)
    {
        subtree_colour = proto_tree_add_subtree(tree, tvb, offset, 1, ett_udh_tfc, NULL, "Text Colour");

        proto_tree_add_item(subtree_colour, hf_gsm_sms_dis_iei_tf_foreground_colour, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(subtree_colour, hf_gsm_sms_dis_iei_tf_background_colour, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
}

/* 9.2.3.24.10.1.2 */
static void
dis_iei_ps(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    EXACT_DATA_CHECK(length, 2);

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_ps_position, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_ps_sound_number, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 9.2.3.24.10.1.3 */
static void
dis_iei_uds(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    SHORT_DATA_CHECK(length, 2);

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_uds_position, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_uds_user_defined_sound, tvb, offset, length - 1, ENC_NA);
}


/* 9.2.3.24.10.1.4 */
static void
dis_iei_pa(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    EXACT_DATA_CHECK(length, 2);

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_pa_position, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_pa_animation_number, tvb, offset, 1, ENC_BIG_ENDIAN);
}


/* 9.2.3.24.10.1.5 */
static void
dis_iei_la(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    SHORT_DATA_CHECK(length, 2);

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_la_position, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_la_large_animation, tvb, offset, length - 1, ENC_NA);
}

/* 9.2.3.24.10.1.6 */
static void
dis_iei_sa(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    SHORT_DATA_CHECK(length, 2);

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_sa_position, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_sa_small_animation, tvb, offset, length - 1, ENC_NA);
}


/* 9.2.3.24.10.1.7 */
static void
dis_iei_lp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    SHORT_DATA_CHECK(length, 2);

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_lp_position, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_lp_large_picture, tvb, offset, length - 1, ENC_NA);
}

/* 9.2.3.24.10.1.8 */
static void
dis_iei_sp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    SHORT_DATA_CHECK(length, 2);

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_sp_position, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_sp_small_picture, tvb, offset, length - 1, ENC_NA);
}


/* 9.2.3.24.10.1.9 */
static void
dis_iei_vp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    SHORT_DATA_CHECK(length, 4);

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_vp_position, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_vp_horizontal_dimension, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_vp_vertical_dimension, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_vp_variable_picture, tvb, offset, length - 3, ENC_NA);
}

/* 9.2.3.24.10.1.10 */
static void
dis_iei_upi(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    EXACT_DATA_CHECK(length, 1);

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_upi_num_corresponding_objects, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
}

/* TS 123.038 V17.0.0 (2022-04), Table 6.2.1.4.1 */
static const value_string lang_single_shift_vals[] = {
    { 0x01, "Turkish" },
    { 0x02, "Spanish" },
    { 0x03, "Portuguese" },
    { 0x04, "Bengali" },
    { 0x05, "Gujarati" },
    { 0x06, "Hindi" },
    { 0x07, "Kannada" },
    { 0x08, "Malayalam" },
    { 0x09, "Oriya" },
    { 0x0A, "Punjabi" },
    { 0x0B, "Tamil" },
    { 0x0C, "Telugu" },
    { 0x0D, "Urdu" },
    { 0, NULL }
};

/* 9.2.3.24.15 */
static void
dis_iei_lang_ss(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    EXACT_DATA_CHECK(length, 1);

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_lang_single_shift, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* TS 123.038 V17.0.0 (2022-04), Table 6.2.1.4.1 */
static const value_string lang_locking_shift_vals[] = {
    { 0x01, "Turkish" },
//  { 0x02, "Spanish" }, Not defined, fallback to GSM 7 bit alphabet
    { 0x03, "Portuguese" },
    { 0x04, "Bengali" },
    { 0x05, "Gujarati" },
    { 0x06, "Hindi" },
    { 0x07, "Kannada" },
    { 0x08, "Malayalam" },
    { 0x09, "Oriya" },
    { 0x0A, "Punjabi" },
    { 0x0B, "Tamil" },
    { 0x0C, "Telugu" },
    { 0x0D, "Urdu" },
    { 0, NULL }
};

/* 9.2.3.24.16 */
static void
dis_iei_lang_ls(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields _U_)
{
    EXACT_DATA_CHECK(length, 1);

    proto_tree_add_item(tree, hf_gsm_sms_dis_iei_lang_locking_shift, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/*
 * 9.2.3.24 TP-User Data (TP-UD)
 * Information Element Identifier octet
 */

/* TS 123 040 V17.2.0 (2022-05) */
static const range_string gsm_sms_tp_ud_ie_id_rvals[] = {
    { 0x00, 0x00,  "Concatenated short messages, 8-bit reference number (SMS Control)" },
    { 0x01, 0x01,  "Special SMS Message Indication (SMS Control)" },
    { 0x02, 0x02,  "Reserved N/A" },
    { 0x03, 0x03,  "Value not used to avoid misinterpretation as <LF> character N/A" },
    { 0x04, 0x04,  "Application port addressing scheme, 8 bit address (SMS Control)" },
    { 0x05, 0x05,  "Application port addressing scheme, 16 bit address (SMS Control)" },
    { 0x06, 0x06,  "SMSC Control Parameters (SMS Control)" },
    { 0x07, 0x07,  "UDH Source Indicator (SMS Control)" },
    { 0x08, 0x08,  "Concatenated short message, 16-bit reference number (SMS Control)" },
    { 0x09, 0x09,  "Wireless Control Message Protocol (SMS Control)" },
    { 0x0A, 0x0A,  "Text Formatting (EMS Control)" },
    { 0x0B, 0x0B,  "Predefined Sound (EMS Content)" },
    { 0x0C, 0x0C,  "User Defined Sound (iMelody max 128 bytes) (EMS Content)" },
    { 0x0D, 0x0D,  "Predefined Animation (EMS Content)" },
    { 0x0E, 0x0E,  "Large Animation (16*16 times 4 = 32*4 =128 bytes) (EMS Content)" },
    { 0x0F, 0x0F,  "Small Animation (8*8 times 4 = 8*4 =32 bytes) (EMS Content)" },
    { 0x10, 0x10,  "Large Picture (32*32 = 128 bytes) (EMS Content)" },
    { 0x11, 0x11,  "Small Picture (16*16 = 32 bytes) (EMS Content)" },
    { 0x12, 0x12,  "Variable Picture (EMS Content)" },
    { 0x13, 0x13,  "User prompt indicator (EMS Control)" },
    { 0x14, 0x14,  "Extended Object (EMS Content)" },
    { 0x15, 0x15,  "Reused Extended Object (EMS Control)" },
    { 0x16, 0x16,  "Compression Control (EMS Control)" },
    { 0x17, 0x17,  "Object Distribution Indicator (EMS Control)" },
    { 0x18, 0x18,  "Standard WVG object (EMS Content)" },
    { 0x19, 0x19,  "Character Size WVG object (EMS Content)" },
    { 0x1A, 0x1A,  "Extended Object Data Request Command (EMS Control)" },
    { 0x1B, 0x1F,  "Reserved for future EMS features (see subclause 3.10) N/A" },
    { 0x20, 0x20,  "RFC 822 E-Mail Header (SMS Control)" },
    { 0x21, 0x21,  "Hyperlink format element (SMS Control)" },
    { 0x22, 0x22,  "Reply Address Element (SMS Control)" },
    { 0x23, 0x23,  "Enhanced Voice Mail Information (SMS Control)" },
    { 0x24, 0x24,  "National Language Single Shift (SMS Control)" },
    { 0x25, 0x25,  "National Language Locking Shift (SMS Control)" },
    { 0x26, 0x6F,  "Reserved for future use N/A" },
    { 0x70, 0x7F,  "(U)SIM Toolkit Security Headers (SMS Control)" },
    { 0x80, 0x9F,  "SME to SME specific use (SMS Control)" },
    { 0xA0, 0xBF,  "Reserved for future use N/A" },
    { 0xC0, 0xDF,  "SC specific use (SMS Control)" },
    { 0xE0, 0xFF,  "Reserved for future use N/A" },
    { 0x00, 0x00,  NULL },
};

static void
dis_field_ud_iei(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields)
{
    void (*iei_fcn)(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, guint8 length, gsm_sms_udh_fields_t *p_udh_fields);
    guint8         oct;
    proto_tree    *subtree;
    guint8         iei_len;


    while (length >= 2)
    {
        iei_fcn = NULL;

        oct = tvb_get_guint8(tvb, offset);

        switch (oct)
        {
            case 0x00:
                iei_fcn = dis_iei_csm8;
                break;
            case 0x01:
                iei_fcn = dis_iei_spe_sms_msg_ind;
                break;
            case 0x04:
                iei_fcn = dis_iei_apa_8bit;
                break;
            case 0x05:
                iei_fcn = dis_iei_apa_16bit;
                break;
            case 0x06:
                iei_fcn = dis_iei_scp;
                break;
            case 0x07:
                iei_fcn = dis_iei_udh_si;
                break;
            case 0x08:
                iei_fcn = dis_iei_csm16;
                break;
            case 0x0A:
                iei_fcn = dis_iei_tf;
                break;
            case 0x0B:
                iei_fcn = dis_iei_ps;
                break;
            case 0x0C:
                iei_fcn = dis_iei_uds;
                break;
            case 0x0D:
                iei_fcn = dis_iei_pa;
                break;
            case 0x0E:
                iei_fcn = dis_iei_la;
                break;
            case 0x0F:
                iei_fcn = dis_iei_sa;
                break;
            case 0x10:
                iei_fcn = dis_iei_lp;
                break;
            case 0x11:
                iei_fcn = dis_iei_sp;
                break;
            case 0x12:
                iei_fcn = dis_iei_vp;
                break;
            case 0x13:
                iei_fcn = dis_iei_upi;
                break;
            case 0x24:
                iei_fcn = dis_iei_lang_ss;
                break;
            case 0x25:
                iei_fcn = dis_iei_lang_ls;
                break;
        }

        iei_len = tvb_get_guint8(tvb, offset + 1);

        subtree = proto_tree_add_subtree_format(tree,
                                tvb, offset, iei_len + 2,
                                ett_udh_ieis[oct], NULL, "IE: %s",
                                rval_to_str_const(oct, gsm_sms_tp_ud_ie_id_rvals, "Reserved"));

        proto_tree_add_item(subtree, hf_gsm_sms_ie_identifier, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(subtree, hf_gsm_sms_dis_field_ud_iei_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (iei_len > 0)
        {
            if (iei_fcn == NULL)
            {
                proto_tree_add_item(subtree, hf_gsm_sms_ie_data, tvb, offset, iei_len, ENC_NA);
            }
            else
            {
                iei_fcn(tvb, pinfo, subtree, offset, iei_len, p_udh_fields);
            }
        }

        length -= 2 + iei_len;
        offset += iei_len;
    }
}

void
dis_field_udh(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 *offset, guint32 *length,
              guint8 *udl, enum character_set cset, guint8 *fill_bits, gsm_sms_udh_fields_t *p_udh_fields)
{
    guint8      oct;
    proto_tree *udh_subtree;
    static const gint* fill_bits_mask_gsm[7] = { &hf_gsm_sms_dis_field_udh_gsm_mask00, &hf_gsm_sms_dis_field_udh_gsm_mask01, &hf_gsm_sms_dis_field_udh_gsm_mask03,
                                                &hf_gsm_sms_dis_field_udh_gsm_mask07, &hf_gsm_sms_dis_field_udh_gsm_mask0f, &hf_gsm_sms_dis_field_udh_gsm_mask1f,
                                                &hf_gsm_sms_dis_field_udh_gsm_mask3f };
    static const gint* fill_bits_mask_ascii[7] = {&hf_gsm_sms_dis_field_udh_ascii_mask00, &hf_gsm_sms_dis_field_udh_ascii_mask80, &hf_gsm_sms_dis_field_udh_ascii_maskc0,
                                                &hf_gsm_sms_dis_field_udh_ascii_maske0, &hf_gsm_sms_dis_field_udh_ascii_maskf0, &hf_gsm_sms_dis_field_udh_ascii_maskf8,
                                                &hf_gsm_sms_dis_field_udh_ascii_maskfc };

    /* step over header */

    oct = tvb_get_guint8(tvb, *offset);

    udh_subtree =
        proto_tree_add_subtree(tree, tvb,
                            *offset, oct + 1,
                            ett_udh, NULL, "User-Data Header");

    proto_tree_add_item(udh_subtree, hf_gsm_sms_dis_field_udh_user_data_header_length, tvb, *offset, 1, ENC_BIG_ENDIAN);

    (*offset)++;
    (*length)--;

    dis_field_ud_iei(tvb, pinfo, udh_subtree, *offset, oct, p_udh_fields);

    *offset += oct;
    *length -= oct;

    if (cset == GSM_7BITS || cset == ASCII_7BITS)
    {
        /* step over fill bits ? */

        *fill_bits = 6 - ((oct * 8) % 7);
        *udl -= (((oct + 1)*8) + *fill_bits) / 7;
        if (*fill_bits)
        {

            if (cset == GSM_7BITS)
            {
                proto_tree_add_item(udh_subtree, *fill_bits_mask_gsm[*fill_bits], tvb, *offset, 1, ENC_NA);
            }
            else
            {
                proto_tree_add_item(udh_subtree, *fill_bits_mask_ascii[*fill_bits], tvb, *offset, 1, ENC_NA);
            }
            /* Note: Could add an expert item here if ((oct & fill_bits_mask[*fill_bits]) != 0) */
        }
    }
    else
    {
        *udl -= oct + 1;
    }
}

/* 9.2.3.24 */
#define SMS_MAX_MESSAGE_SIZE 160
static void
dis_field_ud(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset,
             guint32 length, gboolean udhi, guint8 udl, enum character_set cset,
             gboolean compressed, gsm_sms_data_t *data)
{
    proto_tree        *subtree;
    tvbuff_t          *sm_tvb = NULL;
    fragment_head     *fd_sm = NULL;
    guint8             fill_bits;
    guint32            total_sms_len, i;

    gboolean    reassembled     = FALSE;
    guint32     reassembled_in  = 0;
    gboolean    is_fragmented   = FALSE;
    gboolean    save_fragmented = FALSE, try_gsm_sms_ud_reassemble = FALSE;

    sm_fragment_params     *p_frag_params;
    sm_fragment_params_key *p_frag_params_key, frag_params_key;
    const gchar            *addr_info, *addr;
    gsm_sms_udh_fields_t    udh_fields;

    memset(&udh_fields, 0, sizeof(udh_fields));
    fill_bits = 0;

    addr = (gchar*)p_get_proto_data(pinfo->pool, pinfo, proto_gsm_sms, 0);
    if (addr == NULL)
        addr = "";
    /* check if lower layers provide additional info */
    if (reassemble_sms_with_lower_layers_info) {
        wmem_strbuf_t *addr_info_strbuf = wmem_strbuf_new(pinfo->pool, addr);
        if (proto_is_frame_protocol(pinfo->layers, "gsm_map")) {
            gsm_map_packet_info_t *gsm_map_packet_info;
            wmem_strbuf_append(addr_info_strbuf, "MAP");
            if ((gsm_map_packet_info = (gsm_map_packet_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_gsm_map, 0)) != NULL) {
                if (gsm_map_packet_info->sm_rp_oa_id == GSM_MAP_SM_RP_OA_MSISDN)
                    wmem_strbuf_append(addr_info_strbuf, gsm_map_packet_info->sm_rp_oa_str);
                else if (gsm_map_packet_info->sm_rp_da_id == GSM_MAP_SM_RP_DA_IMSI)
                    wmem_strbuf_append(addr_info_strbuf, gsm_map_packet_info->sm_rp_da_str);
                else if (gsm_map_packet_info->sm_rp_da_id == GSM_MAP_SM_RP_DA_LMSI)
                    wmem_strbuf_append(addr_info_strbuf, gsm_map_packet_info->sm_rp_da_str);
                else /* no identity provided by GSM MAP layer, use TCAP OTID as last resort */
                    wmem_strbuf_append_printf(addr_info_strbuf, "TCAP%u", gsm_map_packet_info->tcap_src_tid);
            }
        } else if (proto_is_frame_protocol(pinfo->layers, "sip")) {
            sip_info_value_t *sip_info;
            wmem_list_frame_t *frame;
            guint8 curr_layer_num;
            wmem_strbuf_append(addr_info_strbuf, "SIP");
            curr_layer_num = pinfo->curr_layer_num-1;
            frame = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
            while (frame && (proto_sip != (gint) GPOINTER_TO_UINT(wmem_list_frame_data(frame)))) {
                frame = wmem_list_frame_prev(frame);
                curr_layer_num--;
            }
            if ((sip_info = (sip_info_value_t*)p_get_proto_data(pinfo->pool, pinfo, proto_sip, curr_layer_num)) != NULL) {
                if (sip_info->tap_from_addr)
                    wmem_strbuf_append(addr_info_strbuf, sip_info->tap_from_addr);
                if (sip_info->tap_to_addr)
                    wmem_strbuf_append(addr_info_strbuf, sip_info->tap_to_addr);
            }
        } else if (proto_is_frame_protocol(pinfo->layers, "gsm_a.rp")) {
            wmem_strbuf_append(addr_info_strbuf, "RP");
        } else if (proto_is_frame_protocol(pinfo->layers, "etsi_cat")) {
            wmem_strbuf_append(addr_info_strbuf, "CAT");
        } else if (proto_is_frame_protocol(pinfo->layers, "mbim")) {
            wmem_strbuf_append(addr_info_strbuf, "MBIM");
        }
        addr_info = wmem_strbuf_finalize(addr_info_strbuf);
    } else {
        addr_info = addr;
    }

    subtree =
        proto_tree_add_subtree(tree, tvb,
                            offset, length,
                            ett_ud, NULL, "TP-User-Data");

    if (data && data->stk_packing_required)
    {
        cset = GSM_7BITS_UNPACKED;
    }

    if (udhi)
    {
        dis_field_udh(tvb, pinfo, subtree, &offset, &length, &udl, compressed ? OTHER : cset, &fill_bits, &udh_fields);
    }

    if (udh_fields.frags > 1)
        is_fragmented = TRUE;

    if ( is_fragmented && reassemble_sms)
    {
        try_gsm_sms_ud_reassemble = TRUE;
        save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;
        fd_sm = fragment_add_seq_check (&g_sm_reassembly_table, tvb, offset,
                                        pinfo,
                                        udh_fields.sm_id, /* guint32 ID for fragments belonging together */
                                        addr_info,
                                        udh_fields.frag-1, /* guint32 fragment sequence number */
                                        length, /* guint32 fragment length */
                                        (udh_fields.frag != udh_fields.frags)); /* More fragments? */
        if (fd_sm)
        {
            reassembled = TRUE;
            reassembled_in = fd_sm->reassembled_in;
        }

        sm_tvb = process_reassembled_data(tvb, offset, pinfo,
                                          "Reassembled Short Message", fd_sm, &sm_frag_items,
                                          NULL, subtree);

        if(reassembled && pinfo->num == reassembled_in)
        {
            /* Reassembled */
            col_append_str (pinfo->cinfo, COL_INFO,
                            " (Short Message Reassembled)");
        }
        else
        {
            /* Not last packet of reassembled Short Message */
            col_append_fstr (pinfo->cinfo, COL_INFO,
                             " (Short Message fragment %u of %u)", udh_fields.frag, udh_fields.frags);
        }

        if (!PINFO_FD_VISITED(pinfo)) {
            /* Store udl and length for later decoding of reassembled SMS */
            p_frag_params_key = wmem_new(wmem_file_scope(), sm_fragment_params_key);
            p_frag_params_key->addr_info = wmem_strdup(wmem_file_scope(), addr_info);
            p_frag_params_key->p2p_dir = pinfo->p2p_dir;
            copy_address_wmem(wmem_file_scope(), &p_frag_params_key->src, &pinfo->src);
            copy_address_wmem(wmem_file_scope(), &p_frag_params_key->dst, &pinfo->dst);
            p_frag_params_key->id = (udh_fields.sm_id<<16)|(udh_fields.frag-1);
            p_frag_params = wmem_new0(wmem_file_scope(), sm_fragment_params);
            p_frag_params->udl = udl;
            p_frag_params->fill_bits =  fill_bits;
            p_frag_params->length = length;
            wmem_multimap_insert32(g_sm_fragment_params_table, p_frag_params_key, pinfo->num, p_frag_params);
        }
    } /* Else: not fragmented */
    if (! sm_tvb) /* One single Short Message, or not reassembled */
        sm_tvb = tvb_new_subset_remaining (tvb, offset);

    if (compressed)
    {
        proto_tree_add_item(subtree, hf_gsm_sms_compressed_data, tvb, offset, length, ENC_NA);
    }
    else
    {
        if (cset == GSM_7BITS_UNPACKED)
        {
            /*
             * STK requires SMS packing by the terminal; this means
             * that the string here is *not* packet 7 bits per
             * character, but is unpacked, with each character in
             * an octet, with the expectation that the recipient
             * will pack it before sending it on the network.
             *
             * Per 3GPP 31.111 chapter 6.4.10:
             * It shall use the SMS default 7-bit coded alphabet
             * as defined in TS 23.038 with bit 8 set to 0
             *
             * I.e., bit 8 of each octet should be 0.
             */
            if(!(reassembled && pinfo->num == reassembled_in))
            {
                proto_tree_add_item(subtree, hf_gsm_sms_text, tvb, offset,
                                    length, ENC_3GPP_TS_23_038_7BITS_UNPACKED);
            }
            else
            {
                total_sms_len = 0;
                for(i = 0 ; i < udh_fields.frags; i++)
                {
                    frag_params_key.addr_info = addr_info;
                    frag_params_key.p2p_dir = pinfo->p2p_dir;
                    copy_address_shallow(&frag_params_key.src, &pinfo->src);
                    copy_address_shallow(&frag_params_key.dst, &pinfo->dst);
                    frag_params_key.id = (udh_fields.sm_id<<16)|i;
                    p_frag_params = (sm_fragment_params*)wmem_multimap_lookup32_le(g_sm_fragment_params_table,
                                                                         &frag_params_key, pinfo->num);

                    if (p_frag_params) {
                        proto_tree_add_item(subtree, hf_gsm_sms_text, sm_tvb, total_sms_len,
                                            p_frag_params->length, ENC_ASCII);
                        total_sms_len += p_frag_params->length;
                    }
                }
            }
        }
        else if (cset == GSM_7BITS)
        {
            if(!(reassembled && pinfo->num == reassembled_in))
            {
                /* Show unassembled SMS */
                proto_tree_add_ts_23_038_7bits_packed_item(subtree, hf_gsm_sms_text, tvb, (offset<<3)+fill_bits,
                                                    (udl > SMS_MAX_MESSAGE_SIZE ? SMS_MAX_MESSAGE_SIZE : udl));
            }
            else
            {
                /*  Show reassembled SMS.  We show each fragment separately
                 *  so that the text doesn't get truncated when we add it to
                 *  the tree.
                 */
                total_sms_len = 0;
                for(i = 0 ; i < udh_fields.frags; i++)
                {
                    frag_params_key.addr_info = addr_info;
                    frag_params_key.p2p_dir = pinfo->p2p_dir;
                    copy_address_shallow(&frag_params_key.src, &pinfo->src);
                    copy_address_shallow(&frag_params_key.dst, &pinfo->dst);
                    frag_params_key.id = (udh_fields.sm_id<<16)|i;
                    p_frag_params = (sm_fragment_params*)wmem_multimap_lookup32_le(g_sm_fragment_params_table,
                                                                         &frag_params_key, pinfo->num);

                    if (p_frag_params) {
                        proto_tree_add_ts_23_038_7bits_packed_item(subtree, hf_gsm_sms_text, sm_tvb,
                            (total_sms_len<<3)+p_frag_params->fill_bits,
                            (p_frag_params->udl > SMS_MAX_MESSAGE_SIZE ? SMS_MAX_MESSAGE_SIZE : p_frag_params->udl));

                        total_sms_len += p_frag_params->length;
                    }
                }
            }
        }
        else if (cset == OTHER)
        {
            if (!is_fragmented || (reassembled && pinfo->num == reassembled_in)) {
                if (! dissector_try_uint(gsm_sms_dissector_tbl, udh_fields.port_src, sm_tvb, pinfo, subtree))
                {
                    if (! dissector_try_uint(gsm_sms_dissector_tbl, udh_fields.port_dst,sm_tvb, pinfo, subtree))
                    {
                        proto_tree_add_item(subtree, hf_gsm_sms_body, sm_tvb, 0, tvb_reported_length(sm_tvb), ENC_NA);
                    }
                }
            } else {
                proto_tree_add_item(subtree, hf_gsm_sms_body, tvb, offset, length, ENC_NA);
            }
        }
        else if (cset == UCS2)
        {
            {
                guint rep_len = tvb_reported_length(sm_tvb);

                if (!(reassembled && pinfo->num == reassembled_in))
                {
                    /* Show unreassembled SMS
                     * Decode as ENC_UTF_16 instead of UCS2 because Android and iOS smartphones
                     * encode emoji characters as UTF-16 big endian and although the UTF-16
                     * is not specified in the 3GPP 23.038 (GSM 03.38) it seems to be widely supported
                     */
                    proto_tree_add_item(subtree, hf_gsm_sms_text, sm_tvb,
                                        0, rep_len, ENC_UTF_16|ENC_BIG_ENDIAN);
                } else {
                    /*  Show reassembled SMS.  We show each fragment separately
                     *  so that the text doesn't get truncated when we add it to
                     *  the tree.
                     */
                    total_sms_len = 0;
                    for(i = 0 ; i < udh_fields.frags; i++)
                    {
                        frag_params_key.addr_info = addr_info;
                        frag_params_key.p2p_dir = pinfo->p2p_dir;
                        copy_address_shallow(&frag_params_key.src, &pinfo->src);
                        copy_address_shallow(&frag_params_key.dst, &pinfo->dst);
                        frag_params_key.id = (udh_fields.sm_id<<16)|i;
                        p_frag_params = (sm_fragment_params*)wmem_multimap_lookup32_le(g_sm_fragment_params_table,
                                                                             &frag_params_key, pinfo->num);

                        if (p_frag_params) {
                            /* Decode as ENC_UTF_16 instead of UCS2 because Android and iOS smartphones
                             * encode emoji characters as UTF-16 big endian and although the UTF-16
                             * is not specified in the 3GPP 23.038 (GSM 03.38) it seems to be widely supported
                             */
                            proto_tree_add_item(subtree, hf_gsm_sms_text, sm_tvb, total_sms_len,
                                (p_frag_params->udl > SMS_MAX_MESSAGE_SIZE ? SMS_MAX_MESSAGE_SIZE : p_frag_params->udl),
                                ENC_UTF_16|ENC_BIG_ENDIAN);

                            total_sms_len += p_frag_params->length;
                        }
                    }
                }
            }
        }
    }

    if (try_gsm_sms_ud_reassemble) /* Clean up defragmentation */
        pinfo->fragmented = save_fragmented;
}

/* 9.2.3.27 */
static void
dis_field_pi(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    static int * const pi_flags[] = {
        &hf_gsm_sms_tp_extension,
        &hf_gsm_sms_tp_reserved,
        &hf_gsm_sms_tp_udl_present,
        &hf_gsm_sms_tp_dcs_present,
        &hf_gsm_sms_tp_pid_present,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_gsm_sms_tp_parameter_indicator, ett_pi, pi_flags, ENC_NA);
}

/*
 * Ref. GSM 03.40
 * Section 9.2.2
 */
static void
dis_msg_deliver(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gsm_sms_data_t *data)
{
    guint32             saved_offset;
    guint32             length;
    guint8              oct;
    guint8              udl;
    enum character_set  cset;
    gboolean            compressed;
    gboolean            udhi;

    saved_offset = offset;
    length = tvb_reported_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);
    udhi = oct & 0x40;

    proto_tree_add_item(tree, hf_gsm_sms_tp_rp, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_udhi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_sri, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_lp, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mms, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mti_down, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    dis_field_addr(tvb, pinfo, tree, &offset, "TP-Originating-Address");

    oct = tvb_get_guint8(tvb, offset);

    dis_field_pid(tvb, tree, offset, oct);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    dis_field_dcs(tvb, tree, offset, oct, &cset, &compressed);

    offset++;
    dis_field_scts(tvb, pinfo, tree, &offset);

    oct = tvb_get_guint8(tvb, offset);
    udl = oct;

    DIS_FIELD_UDL(tree, offset);

    if (udl > 0)
    {
        offset++;

        dis_field_ud(tvb, pinfo, tree, offset, length - (offset - saved_offset), udhi, udl,
            cset, compressed, data);
    }
}

/*
 * Ref. GSM 03.40
 * Section 9.2.2
 */
static void
dis_msg_deliver_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gsm_sms_data_t *data)
{
    guint32             saved_offset;
    guint32             length;
    guint8              oct;
    guint8              pi;
    guint8              udl;
    enum character_set  cset = OTHER;
    gboolean            compressed = FALSE;
    gboolean            udhi;


    udl = 0;
    saved_offset = offset;
    length = tvb_reported_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);
    udhi = oct & 0x40;

    proto_tree_add_item(tree, hf_gsm_sms_tp_udhi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mti_up, tvb, offset, 1, ENC_BIG_ENDIAN);

    if (length < 2)
    {
        proto_tree_add_expert(tree, pinfo, &ei_gsm_sms_short_data,
            tvb, offset, length);
        return;
    }

    /*
     * there does not seem to be a way to determine that this
     * deliver report is from an RP-ERROR or RP-ACK other
     * than to look at the next octet
     *
     * FCS values are 0x80 and higher
     * PI uses bit 7 as an extension indicator
     *
     * will assume that if bit 7 is set then this octet
     * is an FCS otherwise PI
     */
    offset++;
    oct = tvb_get_guint8(tvb, offset);

    if (oct & 0x80)
    {
        dis_field_fcs(tvb, tree, offset, oct);
        offset++;
    }

    pi = tvb_get_guint8(tvb, offset);

    dis_field_pi(tvb, tree, offset);

    if (pi & 0x01)
    {
        if (length <= (offset - saved_offset))
        {
            proto_tree_add_expert(tree, pinfo, &ei_gsm_sms_short_data,
                tvb, offset, -1);
            return;
        }

        offset++;
        oct = tvb_get_guint8(tvb, offset);

        dis_field_pid(tvb, tree, offset, oct);
    }

    if (pi & 0x02)
    {
        if (length <= (offset - saved_offset))
        {
            proto_tree_add_expert(tree, pinfo, &ei_gsm_sms_short_data,
                tvb, offset, -1);
            return;
        }

        offset++;
        oct = tvb_get_guint8(tvb, offset);

        dis_field_dcs(tvb, tree, offset, oct, &cset, &compressed);
    }

    if (pi & 0x04)
    {
        if (length <= (offset - saved_offset))
        {
            proto_tree_add_expert(tree, pinfo, &ei_gsm_sms_short_data,
                tvb, offset, -1);
            return;
        }

        offset++;
        oct = tvb_get_guint8(tvb, offset);
        udl = oct;

        DIS_FIELD_UDL(tree, offset);
    }

    if (udl > 0)
    {
        offset++;

        dis_field_ud(tvb, pinfo, tree, offset, length - (offset - saved_offset), udhi, udl,
            cset, compressed, data);
    }
}

/*
 * Ref. GSM 03.40
 * Section 9.2.2
 */
static void
dis_msg_submit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gsm_sms_data_t *data)
{
    guint32             saved_offset;
    guint32             length;
    guint8              oct;
    guint8              vp_form;
    guint8              udl;
    enum character_set  cset;
    gboolean            compressed;
    gboolean            udhi;


    saved_offset = offset;
    length = tvb_reported_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);
    udhi = oct & 0x40;
    vp_form = ((oct & 0x18) >> 3);

    proto_tree_add_item(tree, hf_gsm_sms_tp_rp, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_udhi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_srr, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_vpf, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_rd, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mti_up, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_tp_mr, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    dis_field_addr(tvb, pinfo, tree, &offset, "TP-Destination-Address");

    oct = tvb_get_guint8(tvb, offset);

    dis_field_pid(tvb, tree, offset, oct);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    dis_field_dcs(tvb, tree, offset, oct, &cset, &compressed);

    offset++;
    dis_field_vp(tvb, pinfo, tree, &offset, vp_form);

    oct = tvb_get_guint8(tvb, offset);
    udl = oct;

    DIS_FIELD_UDL(tree, offset);

    if (udl > 0)
    {
        offset++;

        dis_field_ud(tvb, pinfo, tree, offset, length - (offset - saved_offset), udhi, udl,
            cset, compressed, data);
    }
}

/*
 * Ref. GSM 03.40
 * Section 9.2.2
 */
static void
dis_msg_submit_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gsm_sms_data_t *data)
{
    guint32             saved_offset;
    guint32             length;
    guint8              oct;
    guint8              pi;
    guint8              udl;
    enum character_set  cset = OTHER;
    gboolean            compressed = FALSE;
    gboolean            udhi;


    udl = 0;
    saved_offset = offset;
    length = tvb_reported_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);
    udhi = oct & 0x40;

    proto_tree_add_item(tree, hf_gsm_sms_tp_udhi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mti_down, tvb, offset, 1, ENC_BIG_ENDIAN);

    /*
     * there does not seem to be a way to determine that this
     * deliver report is from an RP-ERROR or RP-ACK other
     * than to look at the next octet
     *
     * FCS values are 0x80 and higher
     * PI uses bit 7 as an extension indicator
     *
     * will assume that if bit 7 is set then this octet
     * is an FCS otherwise PI
     */
    offset++;
    oct = tvb_get_guint8(tvb, offset);

    if (oct & 0x80)
    {
        dis_field_fcs(tvb, tree, offset, oct);
        offset++;
    }

    pi = tvb_get_guint8(tvb, offset);
    dis_field_pi(tvb, tree, offset);
    offset++;

    dis_field_scts(tvb, pinfo, tree, &offset);

    if (pi & 0x01) {
        if (length <= (offset - saved_offset)) {
            proto_tree_add_expert(tree, pinfo, &ei_gsm_sms_short_data,
                tvb, offset, -1);
            return;
        }

        oct = tvb_get_guint8(tvb, offset);

        dis_field_pid(tvb, tree, offset, oct);
        offset++;
    }

    if (pi & 0x02)
    {
        if (length <= (offset - saved_offset))
        {
            proto_tree_add_expert(tree, pinfo, &ei_gsm_sms_short_data,
                tvb, offset, -1);
            return;
        }

        oct = tvb_get_guint8(tvb, offset);

        dis_field_dcs(tvb, tree, offset, oct, &cset, &compressed);
        offset++;
    }

    if (pi & 0x04)
    {
        if (length <= (offset - saved_offset))
        {
            proto_tree_add_expert(tree, pinfo, &ei_gsm_sms_short_data,
                tvb, offset, -1);
            return;
        }

        oct = tvb_get_guint8(tvb, offset);
        udl = oct;

        DIS_FIELD_UDL(tree, offset);
        offset++;
    }

    if (udl > 0)
    {
        dis_field_ud(tvb, pinfo, tree, offset, length - (offset - saved_offset), udhi, udl,
            cset, compressed, data);
    }
}

/*
 * Ref. GSM 03.40
 * Section 9.2.2
 */
static void
dis_msg_status_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gsm_sms_data_t *data)
{
    guint32             saved_offset;
    guint32             length;
    guint8              oct;
    guint8              pi;
    guint8              udl;
    enum character_set  cset = OTHER;
    gboolean            compressed = FALSE;
    gboolean            udhi;


    udl = 0;
    saved_offset = offset;
    length = tvb_reported_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);
    udhi = oct & 0x40;

    proto_tree_add_item(tree, hf_gsm_sms_tp_udhi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_srq, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_lp, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mms, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mti_down, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_tp_mr, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    dis_field_addr(tvb, pinfo, tree, &offset, "TP-Recipient-Address");

    dis_field_scts(tvb, pinfo, tree, &offset);

    dis_field_dt(tvb, pinfo, tree, &offset);

    dis_field_st(tvb, tree, offset);

    offset++;
    /* Parameter indicating the presence of any of
     * the optional parameters which follow
     * 4) Mandatory if any of the optional parameters following TP-PI is present,
     * otherwise optional.
     */
    if (length <= (offset - saved_offset))
    {
        return;
    }

    /* Read Parameter Indicator byte */
    pi = tvb_get_guint8(tvb, offset);
    dis_field_pi(tvb, tree, offset);
    offset++;

    /* TODO: (9.2.3.27) If a Reserved bit is set to "1" then the receiving entity shall ignore the setting */

    if (pi & 0x01)
    {
        if (length <= (offset - saved_offset))
        {
            proto_tree_add_expert(tree, pinfo, &ei_gsm_sms_short_data,
                tvb, offset, -1);
            return;
        }

        oct = tvb_get_guint8(tvb, offset);
        dis_field_pid(tvb, tree, offset, oct);
        offset++;
    }

    if (pi & 0x02)
    {
        if (length <= (offset - saved_offset))
        {
            proto_tree_add_expert(tree, pinfo, &ei_gsm_sms_short_data,
                tvb, offset, -1);
            return;
        }

        oct = tvb_get_guint8(tvb, offset);
        dis_field_dcs(tvb, tree, offset, oct, &cset, &compressed);
        offset++;
    }

    if (pi & 0x04)
    {
        if (length <= (offset - saved_offset))
        {
            proto_tree_add_expert(tree, pinfo, &ei_gsm_sms_short_data,
                tvb, offset, -1);
            return;
        }

        oct = tvb_get_guint8(tvb, offset);
        udl = oct;

        DIS_FIELD_UDL(tree, offset);
        offset++;
    }

    if (udl > 0)
    {
        dis_field_ud(tvb, pinfo, tree, offset, length - (offset - saved_offset), udhi, udl,
            cset, compressed, data);
    }
}

/*
 * Ref. GSM 03.40
 * Section 9.2.2
 */
static void
dis_msg_command(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, gsm_sms_data_t *data _U_)
{
    guint8        oct;
    guint8        cdl;

    proto_tree_add_item(tree, hf_gsm_sms_tp_udhi,   tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_srr,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mti_up, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_tp_mr, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    dis_field_pid(tvb, tree, offset, oct);

    offset++;

    DIS_FIELD_CT(tree, offset);

    offset++;

    DIS_FIELD_MN(tree, offset);

    offset++;

    dis_field_addr(tvb, pinfo, tree, &offset, "TP-Destination-Address");

    oct = tvb_get_guint8(tvb, offset);
    cdl = oct;

    DIS_FIELD_CDL(tree, offset);

    if (cdl > 0)
    {
        offset++;

        proto_tree_add_item(tree, hf_gsm_sms_tp_command_data, tvb, offset, cdl, ENC_NA);
    }
}

#if 0
#define NUM_MSGS (sizeof(msg_type_strings)/sizeof(value_string))
static gint ett_msgs[NUM_MSGS];
#endif

static void (*gsm_sms_msg_fcn[])(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gsm_sms_data_t *data) = {
    dis_msg_deliver,        /* SMS-DELIVER */
    dis_msg_deliver_report, /* SMS-DELIVER REPORT */
    dis_msg_submit,         /* SMS-SUBMIT */
    dis_msg_submit_report,  /* SMS-SUBMIT REPORT */
    dis_msg_status_report,  /* SMS-STATUS REPORT */
    dis_msg_command,        /* SMS-COMMAND */
    NULL,                   /* Reserved */
    NULL,                   /* Reserved */
    NULL,                   /* NONE */
};

/* GENERIC DISSECTOR FUNCTIONS */

static int
dissect_gsm_sms(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    void (*msg_fcn)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    guint32 offset, gsm_sms_data_t *gsm_data) = NULL;
    guint32      offset;
    guint8       msg_type;
    guint8       oct;
    gint         idx;
    const gchar *str          = NULL;
    /*gint         ett_msg_idx;*/
    gsm_sms_data_t *gsm_data = (gsm_sms_data_t*) data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, gsm_sms_proto_name_short);

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree || reassemble_sms)
    {
        proto_item  *gsm_sms_item;
        proto_tree  *gsm_sms_tree;

        g_tree = tree;

        offset = 0;

        oct = tvb_get_guint8(tvb, offset);

        oct &= 0x03;
        msg_type = oct;

        /*
         * convert the 2 bit value to one based on direction
         */
        msg_type |= ((pinfo->p2p_dir == P2P_DIR_RECV) ? 0x04 : 0x00);

        str = try_val_to_str_idx(msg_type, msg_type_strings, &idx);

        /*
         * create the GSM_SMS protocol tree
         */
        gsm_sms_item =
            proto_tree_add_protocol_format(tree, proto_gsm_sms, tvb, 0, -1,
                "%s %s",
                gsm_sms_proto_name,
                (str == NULL) ? "Unknown message identifier" : str);

        gsm_sms_tree =
            proto_item_add_subtree(gsm_sms_item, ett_gsm_sms);

        if ((str == NULL) ||
            (msg_type == 0x03) ||
            (msg_type == 0x07))
        {
            return tvb_captured_length(tvb);
        }
        else
        {
            /*ett_msg_idx = ett_msgs[idx];*/ /* XXX: Not actually used */
            msg_fcn = gsm_sms_msg_fcn[idx];
        }

        if (msg_fcn == NULL)
        {
            proto_tree_add_expert(gsm_sms_tree, pinfo, &ei_gsm_sms_message_dissector_not_implemented,
                tvb, offset, -1);
        }
        else
        {
            (*msg_fcn)(tvb, pinfo, gsm_sms_tree, offset, gsm_data);
        }
    }
    return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */
void
proto_register_gsm_sms(void)
{
    guint     i;
    guint     last_offset;
    module_t *gsm_sms_module;   /* Preferences for GSM SMS UD */
    expert_module_t* expert_gsm_sms;

    /* Setup list of header fields */
    static hf_register_info hf[] =
        {
            { &hf_gsm_sms_coding_group_bits2,
              { "Coding Group Bits", "gsm_sms.coding_group_bits2",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &gsm_sms_coding_group_bits_vals_ext, 0xc0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_coding_group_bits4,
              { "Coding Group Bits", "gsm_sms.coding_group_bits4",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &gsm_sms_coding_group_bits_vals_ext, 0xf0,
                NULL, HFILL }
            },

            /*
             * Short Message fragment reassembly
             */
            { &hf_gsm_sms_ud_fragments,
              { "Short Message fragments", "gsm_sms.fragments",
                 FT_NONE, BASE_NONE, NULL, 0x00,
                 "GSM Short Message fragments", HFILL }
            },
            { &hf_gsm_sms_ud_fragment,
              { "Short Message fragment", "gsm_sms.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00,
                "GSM Short Message fragment", HFILL }
            },
            { &hf_gsm_sms_ud_fragment_overlap,
              { "Short Message fragment overlap", "gsm_sms.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "GSM Short Message fragment overlaps with other fragment(s)", HFILL }
            },
            { &hf_gsm_sms_ud_fragment_overlap_conflicts,
              { "Short Message fragment overlapping with conflicting data", "gsm_sms.fragment.overlap.conflicts",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "GSM Short Message fragment overlaps with conflicting data", HFILL }
            },
            { &hf_gsm_sms_ud_fragment_multiple_tails,
              { "Short Message has multiple tail fragments", "gsm_sms.fragment.multiple_tails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "GSM Short Message fragment has multiple tail fragments", HFILL }
            },
            { &hf_gsm_sms_ud_fragment_too_long_fragment,
              { "Short Message fragment too long", "gsm_sms.fragment.too_long_fragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "GSM Short Message fragment data goes beyond the packet end", HFILL }
            },
            { &hf_gsm_sms_ud_fragment_error,
              { "Short Message defragmentation error", "gsm_sms.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00,
                "GSM Short Message defragmentation error due to illegal fragments", HFILL }
            },
            { &hf_gsm_sms_ud_fragment_count,
              { "Short Message fragment count", "gsm_sms.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_sms_ud_reassembled_in,
              { "Reassembled in", "gsm_sms.reassembled.in",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00,
                "GSM Short Message has been reassembled in this packet.", HFILL }
            },
            { &hf_gsm_sms_ud_reassembled_length,
              { "Reassembled Short Message length", "gsm_sms.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "The total length of the reassembled payload", HFILL }
            },
            { &hf_gsm_sms_ud_multiple_messages_msg_id,
              { "Message identifier", "gsm_sms.udh.mm.msg_id",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                "Identification of the message", HFILL }
            },
            { &hf_gsm_sms_ud_multiple_messages_msg_parts,
              { "Message parts", "gsm_sms.udh.mm.msg_parts",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Total number of message parts (fragments)", HFILL }
            },
            { &hf_gsm_sms_ud_multiple_messages_msg_part,
              { "Message part number", "gsm_sms.udh.mm.msg_part",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Message part (fragment) sequence number", HFILL }
            },
            /* TPDU parameters */
            { &hf_gsm_sms_tp_mti_up,
              { "TP-MTI", "gsm_sms.tp-mti",
                FT_UINT8, BASE_DEC, VALS(msg_type_strings_ms_to_sc), 0x03,
                "TP-Message-Type-Indicator (in the direction MS to SC)", HFILL }
            },
            { &hf_gsm_sms_tp_mti_down,
              { "TP-MTI", "gsm_sms.tp-mti",
                FT_UINT8, BASE_DEC, VALS(msg_type_strings_sc_to_ms), 0x03,
                "TP-Message-Type-Indicator (in the direction SC to MS)", HFILL }
            },
            { &hf_gsm_sms_tp_oa,
              { "TP-OA Digits", "gsm_sms.tp-oa",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "TP-Originating-Address Digits", HFILL }
            },
            { &hf_gsm_sms_tp_da,
              { "TP-DA Digits", "gsm_sms.tp-da",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "TP-Destination-Address Digits", HFILL }
            },
            { &hf_gsm_sms_tp_ra,
              { "TP-RA Digits", "gsm_sms.tp-ra",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "TP-Recipient-Address Digits", HFILL }
            },
            { &hf_gsm_sms_tp_digits,
              { "Digits", "gsm_sms.tp-digits",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "TP (Unknown) Digits", HFILL }
            },
            { &hf_gsm_sms_tp_pid,
              { "TP-PID", "gsm_sms.tp-pid",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "TP-Protocol-Identifier", HFILL }
            },
            { &hf_gsm_sms_tp_dcs,
              { "TP-DCS", "gsm_sms.tp-dcs",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "TP-Data-Coding-Scheme", HFILL }
            },
            { &hf_gsm_sms_tp_mr,
              { "TP-MR", "gsm_sms.tp-mr",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "TP-Message-Reference", HFILL }
            },
            { &hf_gsm_sms_tp_mms,
              { "TP-MMS", "gsm_sms.tp-mms",
                FT_BOOLEAN, 8, TFS(&mms_bool_strings), 0x04,
                "TP-More-Messages-to-Send", HFILL }
            },
            { &hf_gsm_sms_tp_lp,
              { "TP-LP", "gsm_sms.tp-lp",
                FT_BOOLEAN, 8, TFS(&lp_bool_strings), 0x08,
                "TP-Loop-Prevention", HFILL }
            },
            { &hf_gsm_sms_tp_sri,
              { "TP-SRI", "gsm_sms.tp-sri",
                FT_BOOLEAN, 8, TFS(&sri_bool_strings), 0x20,
                "TP-Status-Report-Indication", HFILL }
            },
            { &hf_gsm_sms_tp_srr,
              { "TP-SRR", "gsm_sms.tp-srr",
                FT_BOOLEAN, 8, TFS(&srr_bool_strings), 0x20,
                "TP-Status-Report-Request", HFILL }
            },
            { &hf_gsm_sms_tp_udhi,
              { "TP-UDHI", "gsm_sms.tp-udhi",
                FT_BOOLEAN, 8, TFS(&udhi_bool_strings), 0x40,
                "TP-User-Data-Header-Indicator", HFILL }
            },
            { &hf_gsm_sms_tp_rp,
              { "TP-RP", "gsm_sms.tp-rp",
                FT_BOOLEAN, 8, TFS(&rp_bool_strings), 0x80,
                "TP-Reply-Path", HFILL }
            },
            { &hf_gsm_sms_tp_vpf,
              { "TP-VPF", "gsm_sms.tp-vpf",
                FT_UINT8, BASE_DEC, VALS(vp_type_strings), 0x18,
                "TP-Validity-Period-Format", HFILL }
            },
            { &hf_gsm_sms_tp_rd,
              { "TP-RD", "gsm_sms.tp-rd",
                FT_BOOLEAN, 8, TFS(&rd_bool_strings), 0x04,
                "TP-Reject-Duplicates", HFILL }
            },
            { &hf_gsm_sms_tp_srq,
              { "TP-SRQ", "gsm_sms.tp-srq",
                FT_BOOLEAN, 8, TFS(&srq_bool_strings), 0x20,
                "TP-Status-Report-Qualifier", HFILL }
            },
            { &hf_gsm_sms_text,
              { "SMS text", "gsm_sms.sms_text",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "The text of the SMS", HFILL }
            },
            { &hf_gsm_sms_body,
              { "SMS body", "gsm_sms.sms_body",
                FT_BYTES, BASE_NONE, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_fail_cause,
              { "TP-Failure-Cause (TP-FCS)", "gsm_sms.tp-fcs",
                FT_UINT8, BASE_HEX_DEC|BASE_RANGE_STRING, RVALS(gsm_sms_tp_failure_cause_values), 0x0,
                "TP-Validity-Period-Format", HFILL }
            },
            { &hf_gsm_sms_dis_field_addr_extension,
              { "Extension", "gsm_sms.dis_field_addr.extension",
                FT_BOOLEAN, 8, TFS(&tfs_no_extension_extended), 0x80,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dis_field_addr_num_type,
              { "Type of number", "gsm_sms.dis_field_addr.num_type",
                FT_UINT8, BASE_DEC, VALS(dis_field_addr_num_types_vals), 0x70,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dis_field_addr_num_plan,
              { "Numbering plan", "gsm_sms.dis_field_addr.num_plan",
                FT_UINT8, BASE_DEC, VALS(dis_field_addr_numbering_plan_vals), 0x0F,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_parameter_indicator,
              { "TP-Parameter-Indicator", "gsm_sms.tp.parameter_indicator",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_extension,
              { "Extension", "gsm_sms.tp.extension",
                FT_BOOLEAN, 8, TFS(&tfs_extended_no_extension), 0x80,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_reserved,
              { "Reserved", "gsm_sms.tp.reserved",
                FT_UINT8, BASE_DEC, NULL, 0x78,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_udl_present,
              { "TP-UDL", "gsm_sms.tp.udl.present",
                FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_dcs_present,
              { "TP-DCS", "gsm_sms.tp.dcs.present",
                FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_pid_present,
              { "TP-PID", "gsm_sms.tp.pid.present",
                FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_pid_format_subsequent_bits,
              { "Defines formatting for subsequent bits", "gsm_sms.tp.pid.format_subsequent_bits",
                FT_UINT8, BASE_HEX, NULL, 0xC0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_pid_telematic_interworking,
              { "Telematic interworking", "gsm_sms.tp.pid.telematic_interworking",
                FT_BOOLEAN, 8, TFS(&tfs_telematic_interworking), 0x20,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_pid_device_type,
              { "Device type", "gsm_sms.tp.pid.device_type",
                FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(tp_pid_device_type_rvals), 0x1F,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_pid_sm_al_proto,
              { "The SM-AL protocol being used between the SME and the MS", "gsm_sms.tp.pid.sm_al_proto",
                FT_UINT8, BASE_DEC, NULL, 0x1F,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_pid_message_type,
              { "Message type", "gsm_sms.tp.pid.message_type",
                FT_UINT8, BASE_DEC, VALS(pid_message_type_vals), 0x3F,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_pid_reserved,
              { "Reserved", "gsm_sms.tp.pid.reserved",
                FT_UINT8, BASE_HEX, NULL, 0xC0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_pid_undefined,
              { "Undefined", "gsm_sms.tp.pid.undefined",
                FT_UINT8, BASE_HEX, NULL, 0x3F,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_pid_sc_specific_use,
              { "Bits 0-5 for SC specific use", "gsm_sms.tp.pid.sc_specific_use",
                FT_UINT8, BASE_HEX, NULL, 0xC0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_pid_sc_specific,
              { "SC specific", "gsm_sms.tp.pid.sc_specific",
                FT_UINT8, BASE_HEX, NULL, 0x3F,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dcs_text_compressed,
              { "Text", "gsm_sms.dcs.text_compressed",
                FT_BOOLEAN, 8, TFS(&tfs_compressed_not_compressed), 0x20,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dcs_message_class_defined,
              { "Message Class", "gsm_sms.dcs.message_class_defined",
                FT_BOOLEAN, 8, TFS(&tfs_message_class_defined), 0x10,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dcs_character_set,
              { "Character Set", "gsm_sms.dcs.character_set",
                FT_UINT8, BASE_HEX, VALS(dcs_character_set_vals), 0x0C,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dcs_message_class,
              { "Message Class", "gsm_sms.dcs.message_class",
                FT_UINT8, BASE_HEX, VALS(dcs_message_class_vals), 0x03,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dcs_indication_sense,
              { "Indication Sense", "gsm_sms.dcs.indication_sense",
                FT_BOOLEAN, 8, TFS(&tfs_indication_sense), 0x08,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dcs_reserved04,
              { "Reserved", "gsm_sms.dcs.reserved",
                FT_UINT8, BASE_DEC, NULL, 0x04,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dcs_reserved08,
              { "Reserved", "gsm_sms.dcs.reserved",
                FT_UINT8, BASE_DEC, NULL, 0x08,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dcs_message_waiting,
              { "Message Waiting", "gsm_sms.dcs.message_waiting",
                FT_UINT8, BASE_HEX, VALS(dcs_message_waiting_vals), 0x03,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dcs_message_coding,
              { "Message coding", "gsm_sms.dcs.message_coding",
                FT_BOOLEAN, 8, TFS(&tfs_message_coding), 0x04,
                NULL, HFILL }
            },
            { &hf_gsm_sms_vp_extension,
              { "Extension", "gsm_sms.vp.extension",
                FT_BOOLEAN, 8, TFS(&tfs_extended_no_extension), 0x80,
                NULL, HFILL }
            },
            { &hf_gsm_sms_vp_extension_ignored,
              { "Extension not implemented, ignored", "gsm_sms.vp.extension_ignored",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_vp_single_shot_sm,
              { "Single shot SM", "gsm_sms.vp.single_shot_sm",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
                NULL, HFILL }
            },
            { &hf_gsm_sms_vp_reserved,
              { "Reserved", "gsm_sms.vp.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x38,
                NULL, HFILL }
            },
            { &hf_gsm_sms_vp_validity_period_format,
              { "Validity Period Format", "gsm_sms.vp.validity_period_format",
                FT_UINT8, BASE_DEC, VALS(vp_validity_period_format_vals), 0x07,
                NULL, HFILL }
            },
            { &hf_gsm_sms_vp_validity_period,
              { "TP-Validity-Period", "gsm_sms.vp.validity_period",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dis_field_definition,
              { "Definition of bits 0-6", "gsm_sms.dis_field.definition",
                FT_BOOLEAN, 8, TFS(&tfs_dis_field_definition), 0x80,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dis_field_st_error,
              { "Error", "gsm_sms.dis_field.st_error",
                FT_UINT8, BASE_DEC, VALS(dis_field_st_error_vals), 0x60,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dis_field_st_reason[0],
              { "Reason", "gsm_sms.dis.field_st_reason",
                FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(dis_field_st_error00_reason_rvals), 0x1F,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dis_field_st_reason[1],
              { "Reason", "gsm_sms.dis.field_st_reason",
                FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(dis_field_st_error01_reason_rvals), 0x1F,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dis_field_st_reason[2],
              { "Reason", "gsm_sms.dis.field_st_reason",
                FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(dis_field_st_error10_reason_rvals), 0x1F,
                NULL, HFILL }
            },
            { &hf_gsm_sms_dis_field_st_reason[3],
              { "Reason", "gsm_sms.dis.field_st_reason",
                FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(dis_field_st_error11_reason_rvals), 0x1F,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_user_data_length,
              { "TP-User-Data-Length", "gsm_sms.tp.user_data_length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_message_number,
              { "TP-Message-Number", "gsm_sms.tp.message_number",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_command_type,
              { "TP-Command-Type", "gsm_sms.tp.command_type",
                FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(tp_command_type_rvals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_command_data,
              { "TP-Command-Data", "gsm_sms.tp.command_data",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_tp_command_data_length,
              { "TP-Command-Data-Length", "gsm_sms.tp.command_data_length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_msg_ind_type_and_stor,
              { "Message Indication type and Storage", "gsm_sms.msg_ind_type_and_stor",
                FT_BOOLEAN, 8, TFS(&gsm_sms_msg_type_and_stor_value), 0x80,
                NULL, HFILL }
            },
            { &hf_gsm_sms_msg_profile_id,
              { "Multiple Subscriber Profile", "gsm_sms.profile_id",
                FT_UINT8, BASE_DEC, VALS(gsm_sms_profile_id_vals), 0x60,
                NULL, HFILL }
            },
            { &hf_gsm_sms_ext_msg_ind_type,
              { "Extended Message Indication Type", "gsm_sms.ext_msg_ind_type",
                FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_sms_ext_msg_ind_type_vals), 0x1c,
                NULL, HFILL }
            },
            { &hf_gsm_sms_msg_ind_type,
              { "Message Indication Type", "gsm_sms.msg_ind_type",
                FT_UINT8, BASE_DEC, VALS(gsm_sms_msg_ind_type_vals), 0x03,
                NULL, HFILL }
            },
            { &hf_gsm_sms_msg_count,
              { "Message Count", "gsm_sms.msg_count",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_destination_port8,
              { "Destination port", "gsm_sms.destination_port",
                FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_sms_8bit_port_values), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_originator_port8,
              { "Originator port", "gsm_sms.originator_port",
                FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_sms_8bit_port_values), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_destination_port16,
              { "Destination port", "gsm_sms.destination_port",
                FT_UINT16, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_sms_16bit_port_values), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_originator_port16,
              { "Originator port", "gsm_sms.originator_port",
                FT_UINT16, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_sms_16bit_port_values), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_status_report,
              { "Status Report", "gsm_sms.status_report",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_status_report_short_msg,
              { "Status Report for short message transaction completed", "gsm_sms.status_report.short_msg",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
                NULL, HFILL }
            },
            { &hf_gsm_sms_status_report_permanent_error,
              { "Status Report for permanent error when SC is not making any more transfer attempts", "gsm_sms.status_report.permanent_error",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
                NULL, HFILL }
            },
            { &hf_gsm_sms_status_report_temp_error_no_attempt,
              { "Status Report for temporary error when SC is not making any more transfer attempts", "gsm_sms.status_report.temp_error_no_attempt",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
                NULL, HFILL }
            },
            { &hf_gsm_sms_status_report_temp_error_transfer,
              { "Status Report for temporary error when SC is still trying to transfer SM", "gsm_sms.status_report.temp_error_transfer",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
                NULL, HFILL }
            },
            { &hf_gsm_sms_status_report_active,
              { "Single shot SM", "gsm_sms.status_report.active",
                FT_BOOLEAN, 8, TFS(&tfs_status_report_active), 0x40,
                NULL, HFILL }
            },
            { &hf_gsm_sms_status_report_original_udh,
              { "Include original UDH into the Status Report", "gsm_sms.status_report.original_udh",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
                NULL, HFILL }
            },
            { &hf_gsm_sms_udh_created,
              { "The following part of the UDH is created by", "gsm_sms.udh_created",
                FT_UINT8, BASE_DEC, VALS(udh_created_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_formatting_mode,
              { "Formatting mode", "gsm_sms.formatting_mode",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_formatting_mode_alignment,
              { "Alignment", "gsm_sms.udh_created",
                FT_UINT8, BASE_DEC, VALS(alignment_values), 0x03,
                NULL, HFILL }
            },
            { &hf_gsm_sms_formatting_mode_font_size,
              { "Font Size", "gsm_sms.udh_created",
                FT_UINT8, BASE_DEC, VALS(font_size_values), 0x0C,
                NULL, HFILL }
            },
            { &hf_gsm_sms_formatting_mode_style_bold,
              { "Style bold", "gsm_sms.formatting_mode.style_bold",
                FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x10,
                NULL, HFILL }
            },
            { &hf_gsm_sms_formatting_mode_style_italic,
              { "Style Italic", "gsm_sms.formatting_mode.style_italic",
                FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x20,
                NULL, HFILL }
            },
            { &hf_gsm_sms_formatting_mode_style_underlined,
              { "Style Underlined", "gsm_sms.formatting_mode.style_underlined",
                FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x40,
                NULL, HFILL }
            },
            { &hf_gsm_sms_formatting_mode_style_strikethrough,
              { "Style Strikethrough", "gsm_sms.formatting_mode.style_strikethrough",
                FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x80,
                NULL, HFILL }
            },
            { &hf_gsm_sms_ie_identifier,
              { "Information Element Identifier", "gsm_sms.ie_identifier",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_scts_year,
              { "Year", "gsm_sms.scts.year",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_scts_month,
              { "Month", "gsm_sms.scts.month",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_scts_day,
              { "Day", "gsm_sms.scts.day",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_scts_hour,
              { "Hour", "gsm_sms.scts.hour",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_scts_minutes,
              { "Minutes", "gsm_sms.scts.minutes",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_scts_seconds,
              { "Seconds", "gsm_sms.scts.seconds",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_scts_timezone,
              { "Timezone", "gsm_sms.scts.timezone",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_vp_validity_period_hour,
              { "Hour", "gsm_sms.vp.validity_period.hour",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_vp_validity_period_minutes,
              { "Minutes", "gsm_sms.vp.validity_period.minutes",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_vp_validity_period_seconds,
              { "Seconds", "gsm_sms.vp.validity_period.seconds",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_gsm_sms_dis_field_addr_length, { "Length", "gsm_sms.dis_field_addr.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_gsm_7_bit_default_alphabet, { "Special case, GSM 7 bit default alphabet", "gsm_sms.gsm_7_bit_default_alphabet", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_tf_start_position, { "Start position of the text formatting", "gsm_sms.dis_iei_tf.start_position", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_tf_length, { "Text formatting length", "gsm_sms.dis_iei_tf.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_tf_foreground_colour, { "Foreground Colour", "gsm_sms.dis_iei_tf.foreground_colour", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &text_color_values_ext, 0x0F, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_tf_background_colour, { "Background Colour", "gsm_sms.dis_iei_tf.background_colour", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &text_color_values_ext, 0xF0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_ps_position, { "Position", "gsm_sms.dis_iei_ps.position", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_ps_sound_number, { "Sound number", "gsm_sms.dis_iei_ps.sound_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_uds_position, { "Position", "gsm_sms.dis_iei_uds.position", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_uds_user_defined_sound, { "User Defined Sound", "gsm_sms.dis_iei_uds.user_defined_sound", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_pa_position, { "Position", "gsm_sms.dis_iei_pa.position", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_pa_animation_number, { "Animation number", "gsm_sms.dis_iei_pa.animation_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_la_position, { "Position", "gsm_sms.dis_iei_la.position", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_la_large_animation, { "Large Animation", "gsm_sms.dis_iei_la.large_animation", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_sa_position, { "Position", "gsm_sms.dis_iei_sa.position", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_sa_small_animation, { "Small Animation", "gsm_sms.dis_iei_sa.small_animation", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_lp_position, { "Position", "gsm_sms.dis_iei_lp.position", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_lp_large_picture, { "Large Picture", "gsm_sms.dis_iei_lp.large_picture", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_sp_position, { "Position", "gsm_sms.dis_iei_sp.position", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_sp_small_picture, { "Small Picture", "gsm_sms.dis_iei_sp.small_picture", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_vp_position, { "position", "gsm_sms.dis_iei_vp.position", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_vp_horizontal_dimension, { "Horizontal dimension", "gsm_sms.dis_iei_vp.horizontal_dimension", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_vp_vertical_dimension, { "Vertical dimension", "gsm_sms.dis_iei_vp.vertical_dimension", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_vp_variable_picture, { "Variable Picture", "gsm_sms.dis_iei_vp.variable_picture", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_upi_num_corresponding_objects, { "Number of corresponding objects", "gsm_sms.dis_iei_upi.num_corresponding_objects", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_lang_single_shift, { "Language (Single Shift)", "gsm_sms.dis_iei_lang.single_shift", FT_UINT8, BASE_DEC, VALS(lang_single_shift_vals), 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_iei_lang_locking_shift, { "Language (Locking Shift)", "gsm_sms.dis_iei_lang.locking_shift", FT_UINT8, BASE_DEC, VALS(lang_locking_shift_vals), 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_ud_iei_length, { "Length", "gsm_sms.dis_field_ud_iei.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_ie_data, { "IE Data", "gsm_sms.ie_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_user_data_header_length, { "User Data Header Length", "gsm_sms.dis_field_udh.user_data_header_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_compressed_data, { "Compressed data", "gsm_sms.compressed_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_gsm_mask00, { "Fill bits", "gsm_sms.dis_field_udh.gsm.fill_bits", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_gsm_mask01, { "Fill bits", "gsm_sms.dis_field_udh.gsm.fill_bits", FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_gsm_mask03, { "Fill bits", "gsm_sms.dis_field_udh.gsm.fill_bits", FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_gsm_mask07, { "Fill bits", "gsm_sms.dis_field_udh.gsm.fill_bits", FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_gsm_mask0f, { "Fill bits", "gsm_sms.dis_field_udh.gsm.fill_bits", FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_gsm_mask1f, { "Fill bits", "gsm_sms.dis_field_udh.gsm.fill_bits", FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_gsm_mask3f, { "Fill bits", "gsm_sms.dis_field_udh.gsm.fill_bits", FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_ascii_mask00, { "Fill bits", "gsm_sms.dis_field_udh.ascii.fill_bits", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_ascii_mask80, { "Fill bits", "gsm_sms.dis_field_udh.ascii.fill_bits", FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_ascii_maskc0, { "Fill bits", "gsm_sms.dis_field_udh.ascii.fill_bits", FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_ascii_maske0, { "Fill bits", "gsm_sms.dis_field_udh.ascii.fill_bits", FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_ascii_maskf0, { "Fill bits", "gsm_sms.dis_field_udh.ascii.fill_bits", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_ascii_maskf8, { "Fill bits", "gsm_sms.dis_field_udh.ascii.fill_bits", FT_UINT8, BASE_HEX, NULL, 0xF8, NULL, HFILL }},
      { &hf_gsm_sms_dis_field_udh_ascii_maskfc, { "Fill bits", "gsm_sms.dis_field_udh.ascii.fill_bits", FT_UINT8, BASE_HEX, NULL, 0xFC, NULL, HFILL }},
        };

    static ei_register_info ei[] = {
        { &ei_gsm_sms_short_data, { "gsm_sms.short_data", PI_MALFORMED, PI_ERROR, "Short Data (?)", EXPFILL }},
        { &ei_gsm_sms_unexpected_data_length, { "gsm_sms.unexpected_data_length", PI_MALFORMED, PI_ERROR, "Unexpected Data Length", EXPFILL }},
        { &ei_gsm_sms_message_dissector_not_implemented, { "gsm_sms.message_dissector_not_implemented", PI_UNDECODED, PI_WARN, "Message dissector not implemented", EXPFILL }},
    };

    /* Setup protocol subtree array */
#define NUM_INDIVIDUAL_PARMS        14
    gint *ett[NUM_INDIVIDUAL_PARMS/*+NUM_MSGS*/+NUM_UDH_IEIS+2];

    ett[0]  = &ett_gsm_sms;
    ett[1]  = &ett_pid;
    ett[2]  = &ett_pi;
    ett[3]  = &ett_fcs;
    ett[4]  = &ett_vp;
    ett[5]  = &ett_scts;
    ett[6]  = &ett_dt;
    ett[7]  = &ett_st;
    ett[8]  = &ett_addr;
    ett[9]  = &ett_dcs;
    ett[10] = &ett_ud;
    ett[11] = &ett_udh;
    ett[12] = &ett_udh_tfm;
    ett[13] = &ett_udh_tfc;

    last_offset = NUM_INDIVIDUAL_PARMS;

#if 0
    for (i=0; i < NUM_MSGS; i++, last_offset++)
    {
        ett_msgs[i] = -1;
        ett[last_offset] = &ett_msgs[i];
    }
#endif

    for (i=0; i < NUM_UDH_IEIS; i++, last_offset++)
    {
        ett_udh_ieis[i] = -1;
        ett[last_offset] = &ett_udh_ieis[i];
    }

    ett[last_offset++] = &ett_gsm_sms_ud_fragment;
    ett[last_offset] = &ett_gsm_sms_ud_fragments;

    /* Register the protocol name and description */

    proto_gsm_sms = proto_register_protocol(gsm_sms_proto_name, gsm_sms_proto_name_short, "gsm_sms");

    proto_register_field_array(proto_gsm_sms, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_gsm_sms = expert_register_protocol(proto_gsm_sms);
    expert_register_field_array(expert_gsm_sms, ei, array_length(ei));

    gsm_sms_dissector_tbl = register_dissector_table("gsm_sms.udh.port",
        "GSM SMS port IE in UDH", proto_gsm_sms, FT_UINT16, BASE_DEC);

    gsm_sms_module = prefs_register_protocol (proto_gsm_sms, NULL);

    prefs_register_obsolete_preference(gsm_sms_module,
                                       "try_dissect_message_fragment");
    prefs_register_bool_preference(gsm_sms_module, "reassemble",
                                   "Reassemble fragmented SMS",
                                   "Whether the dissector should reassemble SMS spanning multiple packets",
                                    &reassemble_sms);
    prefs_register_bool_preference(gsm_sms_module, "reassemble_with_lower_layers_info",
                                   "Use lower layers info for SMS reassembly",
                                   "Whether the dissector should take into account info coming "
                                   "from lower layers (like GSM-MAP) to perform SMS reassembly",
                                    &reassemble_sms_with_lower_layers_info);

    register_dissector("gsm_sms", dissect_gsm_sms, proto_gsm_sms);

    g_sm_fragment_params_table = wmem_multimap_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                                        sm_fragment_params_hash, sm_fragment_params_equal);

    reassembly_table_register(&g_sm_reassembly_table,
                              &sm_reassembly_table_functions);

}

void
proto_reg_handoff_gsm_sms(void)
{
    proto_gsm_map = proto_get_id_by_filter_name("gsm_map");
    proto_sip = proto_get_id_by_filter_name("sip");
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
