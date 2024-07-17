/* packet-dect_nwk.c
 *
 * Dissector for the DECT (Digital Enhanced Cordless Telecommunications)
 * NWK protocol layer as described in ETSI EN 300 175-5 V2.7.1 (2017-11)
 *
 * Copyright 2018 by Harald Welte <laforge@gnumonks.org>
 * Copyright 2022 by Bernhard Dick <bernhard@bdick.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/proto.h>
#include <epan/tfs.h>
#include <epan/tvbuff.h>
#include <epan/value_string.h>
#include <epan/wmem_scopes.h>
#include <ftypes/ftypes.h>

#include "packet-e212.h"

void proto_register_dect_nwk(void);
void proto_reg_handoff_dect_nwk(void);

static int proto_dect_nwk;

static int hf_nwk_ti;
static int hf_nwk_pdisc;
static int hf_nwk_msg_type_lce;
static int hf_nwk_msg_type_cc;
static int hf_dect_nwk_message_type_ciss;
static int hf_dect_nwk_message_type_crss;
static int hf_dect_nwk_message_type_clms;
static int hf_dect_nwk_message_type_coms;
static int hf_nwk_msg_type_mm;

static int ett_dect_nwk_s_ie_element;

static int hf_dect_nwk_s_ie_fl;

static int hf_dect_nwk_s_ie_fl_type;
static int hf_dect_nwk_s_ie_fl_double_octet_type;

static int hf_dect_nwk_s_ie_fl_control_type;

static int hf_dect_nwk_s_ie_fl_repeat_indicator_type;

static int hf_dect_nwk_s_ie_fl_shift_locking;
static int hf_dect_nwk_s_ie_fl_shift_new_codeset;

static int hf_dect_nwk_s_ie_fl_basic_service_call_class;
static int hf_dect_nwk_s_ie_fl_basic_service_type;

static int hf_dect_nwk_s_ie_fl_single_display_display_info;

static int hf_dect_nwk_s_ie_fl_single_keypad_keypad_info;

static int hf_dect_nwk_s_ie_fl_release_reason_code;

static int hf_dect_nwk_s_ie_fl_signal_value;

static int hf_dect_nwk_s_ie_fl_timer_restart_value;

static int hf_dect_nwk_s_ie_fl_test_hook_control_hook_value;

static int hf_dect_nwk_s_ie_type;
static int hf_dect_nwk_s_ie_length;

static int hf_dect_nwk_s_ie_octet_group_extension;

static int hf_dect_nwk_s_ie_auth_type_authentication_algorithm;
static int hf_dect_nwk_s_ie_auth_type_proprietary_algorithm;
static int hf_dect_nwk_s_ie_auth_type_ak_type;
static int hf_dect_nwk_s_ie_auth_type_ak_number;
static int hf_dect_nwk_s_ie_auth_type_inc;
static int hf_dect_nwk_s_ie_auth_type_def;
static int hf_dect_nwk_s_ie_auth_type_txc;
static int hf_dect_nwk_s_ie_auth_type_upc;
static int hf_dect_nwk_s_ie_auth_type_cipher_key_number;
static int hf_dect_nwk_s_ie_auth_type_cipher_key_number_related;
static int hf_dect_nwk_s_ie_auth_type_default_cipher_key_index;
static int hf_dect_nwk_s_ie_auth_type_default_cipher_key_algorithm;

static int hf_dect_nwk_s_ie_calling_party_number_type;
static int hf_dect_nwk_s_ie_calling_party_number_numbering_plan;
static int hf_dect_nwk_s_ie_calling_party_number_presentation;
static int hf_dect_nwk_s_ie_calling_party_number_screening;
static int hf_dect_nwk_s_ie_calling_party_number_address;

static int hf_dect_nwk_s_ie_cipher_info_yn;
static int hf_dect_nwk_s_ie_cipher_info_algorithm;
static int hf_dect_nwk_s_ie_cipher_info_proprietary_algorithm;
static int hf_dect_nwk_s_ie_cipher_info_key_type;
static int hf_dect_nwk_s_ie_cipher_info_key_number;

static int hf_dect_nwk_s_ie_duration_lock_limits;
static int hf_dect_nwk_s_ie_duration_time_limits;
static int hf_dect_nwk_s_ie_duration_time_duration;

static int hf_dect_nwk_s_ie_fixed_identity_type;
static int hf_dect_nwk_s_ie_fixed_identity_value_length;
static int hf_dect_nwk_s_ie_fixed_identity_arc;
static int hf_dect_nwk_s_ie_fixed_identity_ard;
static int hf_dect_nwk_s_ie_fixed_identity_padding;

static int hf_dect_nwk_s_ie_iwu_to_iwu_sr;
static int hf_dect_nwk_s_ie_iwu_to_iwu_protocol_discriminator;
static int hf_dect_nwk_s_ie_iwu_to_iwu_information;
static int hf_dect_nwk_s_ie_iwu_to_iwu_discriminator_type;
static int hf_dect_nwk_s_ie_iwu_to_iwu_user_specific_contents;
static int hf_dect_nwk_s_ie_iwu_to_iwu_emc_discriminator;
static int hf_dect_nwk_s_ie_iwu_to_iwu_proprietary_contents;

static int ett_dect_nwk_s_ie_location_area_li_type;
static int hf_dect_nwk_s_ie_location_area_li_type;
static int hf_dect_nwk_s_ie_location_area_la_level_included;
static int hf_dect_nwk_s_ie_location_area_li_extended_included;
static int hf_dect_nwk_s_ie_location_area_la_level;
static int hf_dect_nwk_s_ie_location_area_eli_type;
static int hf_dect_nwk_s_ie_location_area_lac;
static int hf_dect_nwk_s_ie_location_area_ci;

static int hf_dect_nwk_s_ie_multi_display_information;

static int hf_dect_nwk_s_ie_multi_keypad_information;

static int hf_dect_nwk_s_ie_nwk_assigned_identity_type;
static int hf_dect_nwk_s_ie_nwk_assigned_identity_value_length;
static int hf_dect_nwk_s_ie_nwk_assigned_identity_value;
static int hf_dect_nwk_s_ie_nwk_assigned_identity_padding;

static int hf_dect_nwk_s_ie_portable_identity_type;
static int hf_dect_nwk_s_ie_portable_identity_value_length;
static int hf_dect_nwk_s_ie_portable_identity_put;
static int hf_dect_nwk_s_ie_portable_identity_padding;
static int hf_dect_nwk_s_ie_portable_identity_ipei;
static int hf_dect_nwk_s_ie_portable_identity_tpui_assignment_type;
static int hf_dect_nwk_s_ie_portable_identity_tpui_value;
static int hf_dect_nwk_s_ie_portable_identity_ipui_o_number;
static int hf_dect_nwk_s_ie_portable_identity_ipui_p_poc;
static int hf_dect_nwk_s_ie_portable_identity_ipui_p_acc;
static int hf_dect_nwk_s_ie_portable_identity_ipui_q_bacn;
static int hf_dect_nwk_s_ie_portable_identity_ipui_r_imsi;
static int hf_dect_nwk_s_ie_portable_identity_ipui_s_number;
static int hf_dect_nwk_s_ie_portable_identity_ipui_t_eic;
static int hf_dect_nwk_s_ie_portable_identity_ipui_t_number;
static int hf_dect_nwk_s_ie_portable_identity_ipui_u_cacn;

static int hf_dect_nwk_s_ie_rand_rand_field;

static int hf_dect_nwk_s_ie_res_res_field;

static int hf_dect_nwk_s_ie_rs_rs_field;

static int hf_dect_nwk_s_ie_terminal_capability_tone_capabilities;
static int hf_dect_nwk_s_ie_terminal_capability_display_capabilities;
static int hf_dect_nwk_s_ie_terminal_capability_echo_parameter;
static int hf_dect_nwk_s_ie_terminal_capability_n_rej;
static int hf_dect_nwk_s_ie_terminal_capability_a_vol;
static int hf_dect_nwk_s_ie_terminal_capability_slot_type_capability;
static int hf_dect_nwk_s_ie_terminal_capability_slot_type_half_80;
static int hf_dect_nwk_s_ie_terminal_capability_slot_type_long_640;
static int hf_dect_nwk_s_ie_terminal_capability_slot_type_long_672;
static int hf_dect_nwk_s_ie_terminal_capability_slot_type_full;
static int hf_dect_nwk_s_ie_terminal_capability_slot_type_double;
static int hf_dect_nwk_s_ie_terminal_capability_stored_display_characters;
static int hf_dect_nwk_s_ie_terminal_capability_lines_in_display;
static int hf_dect_nwk_s_ie_terminal_capability_chars_per_line;
static int hf_dect_nwk_s_ie_terminal_capability_scrolling_behaviour;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_cap;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_gap;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_dect_gsm;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_isdn;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_lrms;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_dprs_stream;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_dprs_asymmetric;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_dprs_class_2;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_data_services;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_isdn;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_dect_umts_bearer;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_dect_umts_sms;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_dect_umts_facsimile;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_rap;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_dect_gsm;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_wrs;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_sms;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_dmap;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_cta;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_ethernet;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_token_ring;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_ip;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_ppp;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_v24;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_cf;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_ipq;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_rap_2;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_dprs;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_2bz;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_4bz;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_8bz;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_16bz;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_2a;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_4a;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_8a;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_dect_umts;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_dect_umts_gprs;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_odap;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_f_mms;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_gf;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_fast_hopping;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_no_emission;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_mod64;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_ng_dect_1;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_ng_dect_3;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_headset_management;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_re_keying;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_associated_melody;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_ng_dect_5;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8_mux_e_u;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8_channel_ipf;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8_channel_sipf;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8_packet_data_category;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9_dprs_3;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9_dprs_4;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9_dect_ule;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9_light_data;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_date_time_recovery;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_extended_list_change;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_screening;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_wrs_2;
static int hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_wrs_ule;
static int hf_dect_nwk_s_ie_terminal_capability_dsaa2;
static int hf_dect_nwk_s_ie_terminal_capability_dsc2;
static int hf_dect_nwk_s_ie_terminal_capability_control_codes;
static int hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1;
static int hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1_latin_no1;
static int hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1_latin_no9;
static int hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1_latin_no5;
static int hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1_greek;
static int hf_dect_nwk_s_ie_terminal_capability_blind_slot_6;
static int hf_dect_nwk_s_ie_terminal_capability_blind_slot_indication;
static int hf_dect_nwk_s_ie_terminal_capability_sp0;
static int hf_dect_nwk_s_ie_terminal_capability_sp1;
static int hf_dect_nwk_s_ie_terminal_capability_sp2;
static int hf_dect_nwk_s_ie_terminal_capability_sp3;
static int hf_dect_nwk_s_ie_terminal_capability_sp4;
static int hf_dect_nwk_s_ie_terminal_capability_blind_slot_6a;
static int hf_dect_nwk_s_ie_terminal_capability_sp5;
static int hf_dect_nwk_s_ie_terminal_capability_sp6;
static int hf_dect_nwk_s_ie_terminal_capability_sp7;
static int hf_dect_nwk_s_ie_terminal_capability_sp8;
static int hf_dect_nwk_s_ie_terminal_capability_sp9;
static int hf_dect_nwk_s_ie_terminal_capability_sp10;
static int hf_dect_nwk_s_ie_terminal_capability_sp11;

static int hf_dect_nwk_s_ie_escape_to_proprietary_discriminator_type;
static int hf_dect_nwk_s_ie_escape_to_proprietary_discriminator;

static int hf_dect_nwk_s_ie_model_identifier_manic;
static int hf_dect_nwk_s_ie_model_identifier_modic;
static int hf_dect_nwk_s_ie_model_identifier_imeisv;

static int hf_dect_nwk_s_ie_codec_list_negotiation_indicator;
static int hf_dect_nwk_s_ie_codec_list_codec_identifier;
static int hf_dect_nwk_s_ie_codec_list_mac_and_dlc_service;
static int hf_dect_nwk_s_ie_codec_list_last_codec;
static int hf_dect_nwk_s_ie_codec_list_c_plane_routing;
static int hf_dect_nwk_s_ie_codec_list_slot_size;

static int ett_dect_nwk;

static dissector_handle_t dect_nwk_handle;

/*********************************************************************************
 * DECT DEFINITIONS
 *********************************************************************************/

/* Section 7.2 */
enum dect_nwk_proto_disc {
	DECT_NWK_PDISC_LCE		= 0x0,
	DECT_NWK_PDISC_CC		= 0x3,
	DECT_NWK_PDISC_CISS		= 0x4,
	DECT_NWK_PDISC_MM		= 0x5,
	DECT_NWK_PDISC_CLMS		= 0x6,
	DECT_NWK_PDISC_COMS		= 0x7,
};

/* Section 7.4.1 */
enum dect_nwk_cc_msg_type {
	DECT_NWK_CC_ALERTING		= 0x01,
	DECT_NWK_CC_CALL_PROC		= 0x02,
	DECT_NWK_CC_SETUP		= 0x05,
	DECT_NWK_CC_CONNECT		= 0x07,
	DECT_NWK_CC_SETUP_ACK		= 0x0d,
	DECT_NWK_CC_CONNECT_ACK		= 0x0f,
	DECT_NWK_CC_SERVICE_CHANGE	= 0x20,
	DECT_NWK_CC_SERVICE_ACCEPT	= 0x21,
	DECT_NWK_CC_SERVICE_REJECT	= 0x23,
	DECT_NWK_CC_RELEASE		= 0x4d,
	DECT_NWK_CC_RELEASE_COM		= 0x5a,
	DECT_NWK_CC_IWU_INFO		= 0x60,
	DECT_NWK_CC_NOTIFY		= 0x6e,
	DECT_NWK_CC_INFO		= 0x7b,
};

/* Section 7.4.2 */
enum dect_nwk_ss_msg_type {
	DECT_NWK_SS_CISS_RELEASE_COM	= 0x5a,
	DECT_NWK_SS_CISS_FACILITY	= 0x62,
	DECT_NWK_SS_CISS_REGISTER	= 0x64,

	DECT_NWK_SS_CRSS_HOLD		= 0x24,
	DECT_NWK_SS_CRSS_HOLD_ACK	= 0x28,
	DECT_NWK_SS_CRSS_HOLD_REJ	= 0x30,
	DECT_NWK_SS_CRSS_RETRIEVE	= 0x31,
	DECT_NWK_SS_CRSS_RETRIEVE_ACK	= 0x33,
	DECT_NWK_SS_CRSS_RETRIEVE_REJ	= 0x37,
#define DECT_NWK_SS_CRSS_FACILITY	DECT_NWK_SS_CISS_FACILITY
};

/* Section 7.4.3 */
enum dect_nwk_coms_msg_type {
	DECT_NWK_COMS_SETUP		= 0x05,
	DECT_NWK_COMS_CONNECT		= 0x07,
	DECT_NWK_COMS_NOTIFY		= 0x08,
	DECT_NWK_COMS_RELEASE		= 0x4d,
	DECT_NWK_COMS_RELEASE_COM	= 0x5a,
	DECT_NWK_COMS_INFO		= 0x7b,
	DECT_NWK_COMS_ACK		= 0x78,
};

/* Section 7.4.4 */
enum dect_nwk_clms_msg_type {
	DECT_NWK_CLMS_VARIABLE		= 0x01,
};

/* Section 7.4.5 */
enum dect_nwk_mm_msg_type {
	DECT_NWK_MM_AUTH_REQ		= 0x40,
	DECT_NWK_MM_AUTH_REPLY		= 0x41,
	DECT_NWK_MM_KEY_ALLOC		= 0x42,
	DECT_NWK_MM_AUTH_REJ		= 0x43,
	DECT_NWK_MM_ACC_RIGHTS_REQ	= 0x44,
	DECT_NWK_MM_ACC_RIGHTS_ACK	= 0x45,
	DECT_NWK_MM_ACC_RIGHTS_REJ	= 0x47,
	DECT_NWK_MM_ACC_RIGHTS_TERM_REQ	= 0x48,
	DECT_NWK_MM_ACC_RIGHTS_TERM_ACK	= 0x49,
	DECT_NWK_MM_ACC_RIGHTS_TERM_REJ	= 0x4b,
	DECT_NWK_MM_CIPH_REQ		= 0x4c,
	DECT_NWK_MM_CIPH_SUGGEST	= 0x4e,
	DECT_NWK_MM_CIPH_REJ		= 0x4f,
	DECT_NWK_MM_INFO_REQ		= 0x50,
	DECT_NWK_MM_INFO_ACK		= 0x51,
	DECT_NWK_MM_INFO_SUGGEST	= 0x52,
	DECT_NWK_MM_INFO_REJ		= 0x53,
	DECT_NWK_MM_LOCATE_REQ		= 0x54,
	DECT_NWK_MM_LOCATE_ACK		= 0x55,
	DECT_NWK_MM_DETACH		= 0x56,
	DECT_NWK_MM_LOCATE_REJ		= 0x57,
	DECT_NWK_MM_ID_REQ		= 0x58,
	DECT_NWK_MM_ID_REPLY		= 0x59,
	DECT_NWK_MM_IWU			= 0x5b,
	DECT_NWK_MM_TID_ASSIGN		= 0x5c,
	DECT_NWK_MM_TID_ASSIGN_ACK	= 0x5d,
	DECT_NWK_MM_TID_ASSIGN_REJ	= 0x5f,
	DECT_NWK_MM_NOTIFY		= 0x6e,
};

/* Section 7.4.6 */
enum dect_nwk_lce_msg_type {
	DECT_NWK_LCE_PAGE_RESP		= 0x71,
	DECT_NWK_LCE_PAGE_REJ		= 0x72,
};

/* Section 7.5.1 */
enum dect_nwk_s_ie_octet_identifier {
	DECT_NWK_S_IE_OCTET_FIRST = 0,
	DECT_NWK_S_IE_OCTET_A     = 1,
	DECT_NWK_S_IE_OCTET_B     = 2,
	DECT_NWK_S_IE_OCTET_C     = 3,
	DECT_NWK_S_IE_OCTET_D     = 4,
	DECT_NWK_S_IE_OCTET_E     = 5,
	DECT_NWK_S_IE_OCTET_F     = 6,
	DECT_NWK_S_IE_OCTET_G     = 7,
	DECT_NWK_S_IE_OCTET_H     = 8,
	DECT_NWK_S_IE_OCTET_I     = 9,
};

/* Section 7.5.3 */
enum dect_nwk_s_fl_ie_shift_codeset {
	DECT_NWK_S_FL_IE_SHIFT_CODESET_INITIAL        = 0x0,
	DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_0 = 0x4,
	DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_1 = 0x5,
	DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_2 = 0x6,
	DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_3 = 0x7,
};

/* Section 7.6.1 */
enum dect_nwk_s_fl_ie_type {
	DECT_NWK_S_IE_FL_SHIFT                = 0x1,
	DECT_NWK_S_IE_FL_CONTROL              = 0x2,
	DECT_NWK_S_IE_FL_REPEAT_INDICATOR     = 0x5,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_ELEMENT = 0x6,
};

enum dect_nwk_s_fl_ie_control_type {
	DECT_NWK_S_IE_FL_CONTROL_SENDING_COMPLETE  = 0x1,
	DECT_NWK_S_IE_FL_CONTROL_DELIMITER_REQUEST = 0x2,
	DECT_NWK_S_IE_FL_CONTROL_USE_TPUI          = 0x3
};

enum dect_nwk_s_fl_ie_double_octet_type {
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_BASIC_SERVICE     = 0x0,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_RELEASE_REASON    = 0x2,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_SIGNAL            = 0x4,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_TIMER_RESTART     = 0x5,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_TEST_HOOK_CONTROL = 0x6,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_SINGLE_DISPLAY    = 0x8,
	DECT_NWK_S_IE_FL_DOUBLE_OCTET_SINGLE_KEYPAD     = 0x9,
};

/* Section 7.6.3 */
enum dect_nwk_s_ie_fl_repeat_indicator_type {
	DECT_NWK_S_IE_FL_REPEAT_INDICATOR_NON_PRIORITIZED = 0x1,
	DECT_NWK_S_IE_FL_REPEAT_INDICATOR_PRIORITIZED     = 0x2,
};

/* Section 7.6.4 */
enum dect_nwk_s_ie_fl_basic_service_call_class {
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_LIA                   = 0x2,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_ULE                   = 0x3,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_MESSAGE               = 0x4,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_DECT_ISDN_IIP         = 0x7,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_NORMAL                = 0x8,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_INTERNAL              = 0x9,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_EMERGENCY             = 0xA,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_SERVICE               = 0xB,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_EXTERNAL_HANDOVER     = 0xC,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_SUPPLEMENTARY_SERVICE = 0xD,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_OA_M                  = 0xE,
};

enum dect_nwk_s_ie_fl_basic_service_type {
	DECT_NWK_S_IE_FL_BASIC_SERVICE_BASIC_SPEECH              = 0x0,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_DECT_GSM_IWP              = 0x4,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_LRMS                      = 0x5,
	/* Specification assigns 0b0110 to DECT UMTS IWP and GSM IWP SMS*/
	DECT_NWK_S_IE_FL_BASIC_SERVICE_DECT_UMTS_IWP_GSM_IWP_SMS = 0x6,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_WIDEBAND_SPEECH           = 0x8,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_SUOTA_CLASS_4_DPRS        = 0x9,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_SUOTA_CLASS_3_DPRS        = 0xA,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_DTAM_WIDEBAND_SPEECH      = 0xB,
	DECT_NWK_S_IE_FL_BASIC_SERVICE_OTHER                     = 0xF,
};

/* Section 7.6.7 */
enum dect_nwk_s_ie_fl_release_reason {
	DECT_NWK_S_IE_FL_RELEASE_REASON_NORMAL                                = 0x00,
	DECT_NWK_S_IE_FL_RELEASE_REASON_UNEXPECTED_MESSAGE                    = 0x01,
	DECT_NWK_S_IE_FL_RELEASE_REASON_UNKNOWN_TRANSACTION_IDENTIFIER        = 0x02,
	DECT_NWK_S_IE_FL_RELEASE_REASON_MANDATORY_INFORMATION_ELEMENT_MISSING = 0x03,
	DECT_NWK_S_IE_FL_RELEASE_REASON_INVALID_INFORMATION_ELEMENT_CONTENTS  = 0x04,
	DECT_NWK_S_IE_FL_RELEASE_REASON_INCOMPATIBLE_SERVICE                  = 0x05,
	DECT_NWK_S_IE_FL_RELEASE_REASON_SERVICE_NOT_IMPLEMENTED               = 0x06,
	DECT_NWK_S_IE_FL_RELEASE_REASON_NEGOTIATION_NOT_SUPPORTED             = 0x07,
	DECT_NWK_S_IE_FL_RELEASE_REASON_INVALID_ENTITY                        = 0x08,
	DECT_NWK_S_IE_FL_RELEASE_REASON_AUTHENTICATION_FAILED                 = 0x09,
	DECT_NWK_S_IE_FL_RELEASE_REASON_UNKNOWN_IDENTITY                      = 0x0A,
	DECT_NWK_S_IE_FL_RELEASE_REASON_NEGOTIATION_FAILED                    = 0x0B,
	DECT_NWK_S_IE_FL_RELEASE_REASON_COLLISION                             = 0x0C,
	DECT_NWK_S_IE_FL_RELEASE_REASON_TIMER_EXPIRY                          = 0x0D,
	DECT_NWK_S_IE_FL_RELEASE_REASON_PARTIAL_RELEASE                       = 0x0E,
	DECT_NWK_S_IE_FL_RELEASE_REASON_UNKNOWN                               = 0x0F,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_DETACHED                         = 0x10,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_NOT_IN_RANGE                     = 0x11,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_UNKNOWN                          = 0x12,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_ALREADY_ACTIVE                   = 0x13,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_BUSY                             = 0x14,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_REJECTION                        = 0x15,
	DECT_NWK_S_IE_FL_RELEASE_REASON_USER_CALL_MODIFY                      = 0x16,
	DECT_NWK_S_IE_FL_RELEASE_REASON_EXTERNAL_HANDOVER_NOT_SUPPORTED       = 0x21,
	DECT_NWK_S_IE_FL_RELEASE_REASON_NETWORK_PARAMETERS_MISSING            = 0x22,
	DECT_NWK_S_IE_FL_RELEASE_REASON_EXTERNAL_HANDOVER_RELEASE             = 0x23,
	DECT_NWK_S_IE_FL_RELEASE_REASON_OVERLOAD                              = 0x31,
	DECT_NWK_S_IE_FL_RELEASE_REASON_INSUFFICIENT_RESOURCES                = 0x32,
	DECT_NWK_S_IE_FL_RELEASE_REASON_INSUFFICIENT_BEARERS_AVAILABLE        = 0x33,
	DECT_NWK_S_IE_FL_RELEASE_REASON_IWU_CONGESTION                        = 0x34,
	DECT_NWK_S_IE_FL_RELEASE_REASON_SECURITY_ATTACK_ASSUMED               = 0x40,
	DECT_NWK_S_IE_FL_RELEASE_REASON_ENCRYPTION_ACTIVATION_FAILED          = 0x41,
	DECT_NWK_S_IE_FL_RELEASE_REASON_RE_KEYING_FAILED                      = 0x42,
	DECT_NWK_S_IE_FL_RELEASE_REASON_NO_CIPHER_KEY_AVAILABLE               = 0x43,
};

/* Section 7.6.8 */
enum dect_nwk_s_ie_fl_signal_value {
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_DIAL_TONE_ON = 0x00,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_RINGBACK_TONE_ON = 0x01,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_INTERCEPT_TONE_ON = 0x02,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_NETWORK_CONGESTION_TONE_ON = 0x03,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_BUSY_TONE_ON               = 0x04,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_CONFIRM_TONE_ON            = 0x05,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ANSWER_TONE_ON             = 0x06,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_CALL_WAITING_TONE_ON       = 0x07,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_OFF_HOOK_WARNING_TONE_ON   = 0x08,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_NEGATIVE_ACK_TONE          = 0x09,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_TONES_OFF                  = 0x3F,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_0      = 0x40,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_1      = 0x41,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_2      = 0x42,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_3      = 0x43,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_4      = 0x44,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_5      = 0x45,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_6      = 0x46,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_7      = 0x47,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_CONTINUOUS     = 0x48,
	DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_OFF               = 0x4F,
};

/* Section 7.6.9 */
enum dect_nwk_s_ie_fl_timer_restart_value {
	DECT_NWK_S_IE_FL_TIMER_RESTART_VALUE_RESTART_TIMER = 0x00,
	DECT_NWK_S_IE_FL_TIMER_RESTART_VALUE_STOP_TIMER = 0x01,
};

/* Section 7.6.10 */
enum dect_nwk_s_ie_fl_test_hook_control_hook_value {
	DECT_NWK_S_IE_FL_TEST_HOOK_CONTROL_HOOK_VALUE_ON_HOOK  = 0x00,
	DECT_NWK_S_IE_FL_TEST_HOOK_CONTROL_HOOK_VALUE_OFF_HOOK = 0x01,
};

/* Section 7.7.1 */
enum dect_nkw_s_ie_type {
	DECT_NWK_S_IE_INFO_TYPE                  = 0x01,
	DECT_NWK_S_IE_IDENTITY_TYPE              = 0x02,
	DECT_NWK_S_IE_PORTABLE_IDENTITY          = 0x05,
	DECT_NWK_S_IE_FIXED_IDENTITY             = 0x06,
	DECT_NWK_S_IE_LOCATION_AREA              = 0x07,
	DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY      = 0x09,
	DECT_NWK_S_IE_AUTH_TYPE                  = 0x0A,
	DECT_NWK_S_IE_ALLOCATION_TYPE            = 0x0B,
	DECT_NWK_S_IE_RAND                       = 0x0C,
	DECT_NWK_S_IE_RES                        = 0x0D,
	DECT_NWK_S_IE_RS                         = 0x0E,
	DECT_NWK_S_IE_IWU_ATTRIBUTES             = 0x12,
	DECT_NWK_S_IE_CALL_ATTRIBUES             = 0x13,
	DECT_NWK_S_IE_SERVICE_CHANGE_INFO        = 0x16,
	DECT_NWK_S_IE_CONNECTION_ATTRIBUTES      = 0x17,
	DECT_NWK_S_IE_CIPHER_INFO                = 0x19,
	DECT_NWK_S_IE_CALL_IDENTITY              = 0x1A,
	DECT_NWK_S_IE_CONNECTION_IDENTITY        = 0x1B,
	DECT_NWK_S_IE_FACILITY                   = 0x1C,
	DECT_NWK_S_IE_PROGRESS_INDICATOR         = 0x1E,
	DECT_NWK_S_IE_MMS_GENERIC_HEADER         = 0x20,
	DECT_NWK_S_IE_MMS_OBJECT_HEADER          = 0x21,
	DECT_NWK_S_IE_MMS_EXTENDED_HEADER        = 0x22,
	DECT_NWK_S_IE_TIME_DATE                  = 0x23,
	DECT_NWK_S_IE_MULTI_DISPLAY              = 0x28,
	DECT_NWK_S_IE_MULTI_KEYPAD               = 0x2C,
	DECT_NWK_S_IE_FEATURE_ACTIVATE           = 0x38,
	DECT_NWK_S_IE_FEATURE_INDICATE           = 0x39,
	DECT_NWK_S_IE_NETWORK_PARAMETER          = 0x41,
	DECT_NWK_S_IE_EXT_HO_INDICATOR           = 0x42,
	DECT_NWK_S_IE_ZAP_FIELD                  = 0x52,
	DECT_NWK_S_IE_SERVICE_CLASS              = 0x54,
	DECT_NWK_S_IE_KEY                        = 0x56,
	DECT_NWK_S_IE_REJECT_REASON              = 0x60,
	DECT_NWK_S_IE_SETUP_CAPABILITY           = 0x62,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY        = 0x63,
	DECT_NWK_S_IE_END_TO_END_COMPATIBILITY   = 0x64,
	DECT_NWK_S_IE_RATE_PARAMETERS            = 0x65,
	DECT_NWK_S_IE_TRANSIT_DELAY              = 0x66,
	DECT_NWK_S_IE_WINDOW_SIZE                = 0x67,
	DECT_NWK_S_IE_ULE_MAC_CONFIGURATION_INFO = 0x68,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER       = 0x6C,
	DECT_NWK_S_IE_CALLING_PARTY_NAME         = 0x6D,
	DECT_NWK_S_IE_CALLED_PARTY_NUMBER        = 0x70,
	DECT_NWK_S_IE_CALLED_PARTY_SUBADDR       = 0x71,
	DECT_NWK_S_IE_DURATION                   = 0x72,
	DECT_NWK_S_IE_CALLED_PARTY_NAME          = 0x73,
	DECT_NWK_S_IE_LIST_CHANGE_DETAILS        = 0x74,
	DECT_NWK_S_IE_SEGMENTED_INFO             = 0x75,
	DECT_NWK_S_IE_ALPHANUMERIC               = 0x76,
	DECT_NWK_S_IE_IWU_TO_IWU                 = 0x77,
	DECT_NWK_S_IE_MODEL_IDENTIFIER           = 0x78,
	DECT_NWK_S_IE_IWU_PACKET                 = 0x7A,
	DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY      = 0x7B,
	DECT_NWK_S_IE_CODEC_LIST                 = 0x7C,
	DECT_NWK_S_IE_EVENTS_NOTIFICATION        = 0x7D,
	DECT_NWK_S_IE_CALL_INFORMATION           = 0x7E,
	DECT_NWK_S_IE_ESCAPE_FOR_EXTENSION       = 0x7F,
};

/* Section 7.7.4 */
enum dect_nwk_s_ie_auth_type_authentication_algorithm {
	DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_DSAA        = 0x01,
	DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_DSAA2       = 0x02,
	DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_UMTS        = 0x20,
	DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_GSM         = 0x40,
	DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_PROPRIETARY = 0x7F,
};

enum dect_nwk_s_ie_auth_type_ak_type {
	DECT_NWK_S_IE_AUTH_TYPE_AK_TYPE_USER_AK             = 0x1,
	DECT_NWK_S_IE_AUTH_TYPE_AK_TYPE_USER_PERSONAL_ID    = 0x3,
	DECT_NWK_S_IE_AUTH_TYPE_AK_TYPE_AUTHENTICATION_CODE = 0x4,
};

enum dect_nwk_s_ie_auth_type_default_cipher_key_algorithm {
	DECT_NWK_S_IE_AUTH_TYPE_DEFAULT_CIPHER_KEY_ALGORITHM_DSC =  0x0,
	DECT_NWK_S_IE_AUTH_TYPE_DEFAULT_CIPHER_KEY_ALGORITHM_DSC2 = 0x1,
};

/* Section 7.7.9 */
enum dect_nwk_s_ie_calling_party_number_type {
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_UNKNOWN          = 0x0,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_INTERNATIONAL    = 0x1,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_NATIONAL         = 0x2,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_NETWORK_SPECIFIC = 0x3,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_SUBSCRIBER       = 0x4,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_ABBREVIATED      = 0x6,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_RESERVED         = 0x7,
};

enum dect_nwk_s_ie_calling_party_number_numbering_plan {
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_UNKNOWN  = 0x0,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_ISDN     = 0x1,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_DATA     = 0x3,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_TCP_IP   = 0x7,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_NATIONAL = 0x8,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_PRIVATE  = 0x9,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_SIP      = 0xA,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_INTERNET = 0xB,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_LAN_MAC  = 0xC,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_X400     = 0xD,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_PROFILE  = 0xE,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_RESERVED = 0xF,
};

enum dect_nwk_s_ie_calling_party_number_presentation {
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_ALLOWED              = 0x0,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_RESTRICTED           = 0x1,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_NUMBER_NOT_AVAILABLE = 0x2,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_RESERVED             = 0x3,
};

enum dect_nwk_s_ie_calling_party_number_screening {
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_USER_NOT_SCREENED    = 0x0,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_USER_VERIFIED_PASSED = 0x1,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_USER_VERIFIED_FAILED = 0x2,
	DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_NETWORK              = 0x3,
};

/* Section 7.7.10 */
enum dect_nwk_s_ie_cipher_info_algorithm {
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_DSC         = 0x01,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_DSC2        = 0x02,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_NO     = 0x28,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA1   = 0x29,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA2   = 0x2A,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA3   = 0x2B,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA4   = 0x2C,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA5   = 0x2D,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA6   = 0x2E,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA7   = 0x2F,
	DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_PROPRIETARY = 0x7F,
};

enum dect_nwk_s_ie_cipher_info_key_type {
	DECT_NWK_S_IE_CIPHER_INFO_KEY_TYPE_DERIVED = 0x9,
	DECT_NWK_S_IE_CIPHER_INFO_KEY_TYPE_STATIC  = 0xA,
};

/* Section 7.7.13 */
enum dect_nwk_s_ie_duration_lock_limits_type {
	DECT_NWK_S_IE_DURATION_LOCK_LIMITS_TEMPORARY2 = 0x5,
	DECT_NWK_S_IE_DURATION_LOCK_LIMITS_TEMPORARY  = 0x6,
	DECT_NWK_S_IE_DURATION_LOCK_LIMITS_NO         = 0x7,
};

enum dect_nwk_s_ie_duration_time_limits_type {
	DECT_NWK_S_IE_DURATION_TIME_LIMITS_ERASE     = 0x0,
	DECT_NWK_S_IE_DURATION_TIME_LIMITS_DEFINED_1 = 0x1,
	DECT_NWK_S_IE_DURATION_TIME_LIMITS_DEFINED_2 = 0x2,
	DECT_NWK_S_IE_DURATION_TIME_LIMITS_STANDARD  = 0x4,
	DECT_NWK_S_IE_DURATION_TIME_LIMITS_INFINITE  = 0xF,
};

/* Section 7.7.18 */
enum dect_nwk_s_ie_fixed_identity_type {
	DECT_NWK_S_IE_FIXED_IDENTITY_ARI              = 0x00,
	DECT_NWK_S_IE_FIXED_IDENTITY_ARI_PLUS_RPN     = 0x01,
	DECT_NWK_S_IE_FIXED_IDENTITY_ARI_PLUS_RPN_WRS = 0x02,
	DECT_NWK_S_IE_FIXED_IDENTITY_PARK             = 0x20,
};

enum dect_nwk_arc_type {
	DECT_NWK_ARC_TYPE_A = 0x0,
	DECT_NWK_ARC_TYPE_B = 0x1,
	DECT_NWK_ARC_TYPE_C = 0x2,
	DECT_NWK_ARC_TYPE_D = 0x3,
	DECT_NWK_ARC_TYPE_E = 0x4,
	DECT_NWK_ARC_TYPE_F = 0x5,
	DECT_NWK_ARC_TYPE_G = 0x6,
	DECT_NWK_ARC_TYPE_H = 0x7,
};

/* Section 7.7.23 */
enum dect_nwk_s_ie_iwu_to_iwu_protocol_discriminator_type {
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_USER_SPECIFIC     = 0x00,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_OSI_HIGH_LAYER    = 0x01,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_X263              = 0x02,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_LIST_ACCESS       = 0x03,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_IA5_CHARS         = 0x04,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_ULE_NON_CCM       = 0x05,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_SUOTA             = 0x06,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_V120              = 0x07,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_Q931_MESSAGE      = 0x08,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_Q931_IE           = 0x09,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_Q931_PARTIAL      = 0x0A,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_ULE_CCM_AUX0      = 0x0C,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_ULE_CCM_AUX1      = 0x0D,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_ULE_CCM_AUX2      = 0x0E,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_DTAM              = 0x0F,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_GSM_MESSAGE       = 0x10,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_GSM_IE            = 0x11,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_UMTS_GPRS_IE      = 0x12,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_UMTS_GPRS_MESSAGE = 0x13,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_LRMS              = 0x14,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_RLL_AP            = 0x15,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_WRS               = 0x16,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_DECT_ISDN_C_PLANE = 0x20,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_DECT_ISDN_U_PLANE = 0x21,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_DECT_ISDN_OPER    = 0x22,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_TERMINAL_DATA     = 0x23,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_DECT_IP           = 0x24,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_MPEG4             = 0x25,
	DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_UNKNOWN           = 0x2F,
};

enum dect_nwk_s_ie_iwu_to_iwu_discriminator_type {
	DECT_NWK_S_IE_IWU_TO_IWU_DISCRIMINATOR_TYPE_UNSPECIFIED = 0x00,
	DECT_NWK_S_IE_IWU_TO_IWU_DISCRIMINATOR_TYPE_EMC         = 0x01,
};

/* Section 7.7.25 */
enum dect_nwk_s_ie_location_area_eli_type {
	DECT_NWK_S_IE_LOCATION_AREA_ELI_TYPE_LI_REQ_NOT_INCLUDED = 0x7,
	DECT_NWK_S_IE_LOCATION_AREA_ELI_TYPE_LI                  = 0xF,
};

/* Section 7.7.28 */
enum dect_nwk_s_ie_nwk_assigned_identity_type {
	DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY_TMSI        = 0xE4,
	DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY_PROPRIETARY = 0xFF,
};

/* Section 7.7.30 */
enum dect_nwk_s_ie_portable_identity_type {
	DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI = 0x00,
	DECT_NWK_S_IE_PORTABLE_IDENTITY_IPEI = 0x10,
	DECT_NWK_S_IE_PORTABLE_IDENTITY_TPUI = 0x20,
};

enum dect_nwk_s_ie_portable_identity_tpui_assignment_type_coding {
	DECT_NWK_S_IE_PORTABLE_IDENTITY_TPUI_ASSIGNMENT_TYPE_TPUI                      = 0x0,
	DECT_NWK_S_IE_PORTABLE_IDENTITY_TPUI_ASSIGNMENT_TYPE_TPUI_WITH_NUMBER_ASSIGNED = 0x1,
};

enum dect_nwk_ipui_type {
	DECT_NWK_IPUI_TYPE_N = 0x0,
	DECT_NWK_IPUI_TYPE_O = 0x1,
	DECT_NWK_IPUI_TYPE_P = 0x2,
	DECT_NWK_IPUI_TYPE_Q = 0x3,
	DECT_NWK_IPUI_TYPE_R = 0x4,
	DECT_NWK_IPUI_TYPE_S = 0x5,
	DECT_NWK_IPUI_TYPE_T = 0x6,
	DECT_NWK_IPUI_TYPE_U = 0x7,
};

/* Section 7.7.41 */
enum dect_nwk_s_ie_terminal_capability_tone_capabilites {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_TONE_CAPABILITY_NA                            = 0x0,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_TONE_CAPABILITY_NO_TONE_CAPABILITY            = 0x1,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_TONE_CAPABILITY_DIAL_TONE_ONLY                = 0x2,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_TONE_CAPABILITY_E182_TONES_SUPPORTED          = 0x3,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_TONE_CAPABILITY_COMPLETE_DECT_TONES_SUPPORTED = 0x4,
};

enum dect_nwk_s_ie_terminal_capability_display_capabilities {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_DISPLAY_CAPABILITY_NA           = 0x0,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_DISPLAY_CAPABILITY_NO_DISPLAY   = 0x1,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_DISPLAY_CAPABILITY_NUMERIC      = 0x2,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_DISPLAY_CAPABILITY_NUMERIC_PLUS = 0x3,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_DISPLAY_CAPABILITY_ALPHANUMERIC = 0x4,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_DISPLAY_CAPABILITY_FULL_DISPLAY = 0x5,
};

enum dect_nwk_s_ie_terminal_capability_echo_parameters {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_ECHO_PARAMETER_NA                   = 0x0,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_ECHO_PARAMETER_MINIMUM_TCLW         = 0x1,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_ECHO_PARAMETER_TCLW_FULL            = 0x2,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_ECHO_PARAMETER_TCLW_VOIP_COMPATIBLE = 0x3,
};

enum dect_nwk_s_ie_terminal_capability_n_rej_capabilities {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_N_REJ_NA       = 0x0,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_N_REJ_NO       = 0x1,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_N_REJ_PROVIDED = 0x2,
};

enum dect_nwk_s_ie_terminal_capability_a_vol_capabilities {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_A_VOL_NA            = 0x0,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_A_VOL_NO_PP_A_VOL   = 0x1,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_A_VOL_PP_A_VOL_USED = 0x2,
};

enum dect_nwk_s_ie_terminal_capability_slot_type {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SLOT_TYPE_HALF_80  = 0x1,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SLOT_TYPE_LONG_640 = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SLOT_TYPE_LONG_672 = 0x04,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SLOT_TYPE_FULL     = 0x08,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SLOT_TYPE_DOUBLE   = 0x10,
};

enum dect_nwk_s_ie_terminal_capability_scrolling_behaviour_type {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SCROLLING_BEHAVIOUR_NOT_SPECIFIED = 0x00,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SCROLLING_BEHAVIOUR_TYPE_1 = 0x01,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SCROLLING_BEHAVIOUR_TYPE_2 = 0x02,
};

enum dect_nwk_s_ie_terminal_capability_profile_indicator_1 {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_CAP             = 0x01,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_GAP             = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_DECT_GSM        = 0x04,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_ISDN            = 0x08,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_LRMS            = 0x10,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_DPRS_STREAM     = 0x20,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_DPRS_ASYMMETRIC = 0x40,
};

enum dect_nwk_s_ie_terminal_capability_profile_indicator_2 {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_DPRS_CLASS_2        = 0x01,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_DATA_SERVICES       = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_ISDN                = 0x04,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_DECT_UMTS_BEARER    = 0x08,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_DECT_UMTS_SMS       = 0x10,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_DECT_UMTS_FACSIMILE = 0x20,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_RAP                 = 0x40,
};

enum dect_nwk_s_ie_terminal_capability_profile_indicator_3 {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_DECT_GSM   = 0x01,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_WRS        = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_SMS        = 0x04,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_DMAP       = 0x08,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_CTA        = 0x10,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_ETHERNET   = 0x20,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_TOKEN_RING = 0x40,
};

enum dect_nwk_s_ie_terminal_capability_profile_indicator_4 {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_IP    = 0x01,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_PPP   = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_V24  = 0x04,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_CF    = 0x08,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_IPQ   = 0x10,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_RAP_2 = 0x20,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_DPRS  = 0x40,
};

enum dect_nwk_s_ie_terminal_capability_profile_indicator_5 {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_2BZ      = 0x01,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_4BZ      = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_8BZ      = 0x04,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_16BZ     = 0x08,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_2A       = 0x10,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_4A       = 0x20,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_8A       = 0x40,
};
enum dect_nwk_s_ie_terminal_capability_profile_indicator_6 {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_DECT_UMTS      = 0x01,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_DECT_UMTS_GPRS = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_ODAP           = 0x04,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_F_MMS          = 0x08,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_GF             = 0x10,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_FAST_HOPPING   = 0x20,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_NO_EMISSION    = 0x40,
};

enum dect_nwk_s_ie_terminal_capability_profile_indicator_7 {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_MOD64              = 0x01,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_NG_DECT_1          = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_NG_DECT_3          = 0x04,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_HEADSET_MANAGEMENT = 0x08,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_RE_KEYING          = 0x10,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_ASSOCIATED_MELODY  = 0x20,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_NG_DECT_5          = 0x40,
};

enum dect_nwk_s_ie_terminal_capability_profile_indicator_8 {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_MUX_E_U              = 0x01,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_CHANNEL_IPF          = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_CHANNEL_SIPF         = 0x04,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_CATEGORY = 0x78,
};

enum dect_nwk_s_ie_terminal_capability_profile_indicator_9 {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_9_DPRS_3     = 0x01,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_9_DPRS_4     = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_9_DECT_ULE   = 0x1C,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_9_LIGHT_DATA = 0x20,
};

enum dect_nwk_s_ie_terminal_capability_profile_indicator_10 {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_10_DATE_TIME_RECOVERY   = 0x01,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_10_EXTENDED_LIST_CHANGE = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_10_SCREENING            = 0x04,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_10_WRS_2                = 0x08,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_10_WRS_ULE              = 0x10,
};

enum dect_nwk_s_ie_terminal_capability_profile_indicator_8_packet_data_categories {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_NO          = 0x0,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_CAT_1       = 0x1,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_CAT_2       = 0x2,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_CAT_3       = 0x3,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_CAT_4_8PSK  = 0x4,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_CAT_4_64QAM = 0x5,
};

enum dect_nwk_s_ie_terminal_capability_profile_indicator_9_dect_ule_versions {
	DECT_NWK_S_IE_TERMINA_CAPABILITY_PROFILE_INDICATOR_9_DECT_ULE_1_V111 = 0x1,
	DECT_NWK_S_IE_TERMINA_CAPABILITY_PROFILE_INDICATOR_9_DECT_ULE_1_V121 = 0x3,
	DECT_NWK_S_IE_TERMINA_CAPABILITY_PROFILE_INDICATOR_9_DECT_ULE_2      = 0x5,
	DECT_NWK_S_IE_TERMINA_CAPABILITY_PROFILE_INDICATOR_9_DECT_ULE_3      = 0x7,
};

enum dect_nwk_s_ie_terminal_capability_control_codes {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_CONTROL_CODES_NOT_SPECIFIED = 0x0,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_CONTROL_CODES_0CH           = 0x1,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_CONTROL_CODES_CODING_001    = 0x2,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_CONTROL_CODES_CODING_010    = 0x3,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_CONTROL_CODES_CODING_011    = 0x4,
};

enum dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1 {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_ESCAPE_TO_CHAR_SETS_1_LATIN_NO1 = 0x01,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_ESCAPE_TO_CHAR_SETS_1_LATIN_NO9 = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_ESCAPE_TO_CHAR_SETS_1_LATIN_NO5 = 0x04,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_ESCAPE_TO_CHAR_SETS_1_GREEK     = 0x08,
};

enum dect_nwk_s_ie_terminal_capability_blind_slot_indication {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_BLIND_SLOT_INDICATION_NO                            = 0x0,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_BLIND_SLOT_INDICATION_NOT_POSSIBLE_ADJACENT         = 0x1,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_BLIND_SLOT_INDICATION_NOT_POSSIBLE_EVERY_SECOND     = 0x2,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_BLIND_SLOT_INDICATION_LIMITATIONS_IN_FOLLOWING_BITS = 0x3,
};

enum dect_nwk_s_ie_terminal_capability_blind_slot_6 {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP0 = 0x10,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP1 = 0x08,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP2 = 0x04,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP3 = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP4 = 0x01,
};

enum dect_nwk_s_ie_terminal_capability_blind_slot_6a {
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP5 = 0x40,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP6 = 0x20,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP7 = 0x10,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP8 = 0x08,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP9 = 0x04,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP10 = 0x02,
	DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP11 = 0x01,
};

/* Section 7.7.45 */
enum dect_nwk_s_ie_escape_to_proprietary_discriminator_type {
	DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_UNSPECIFIED = 0x00,
	DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_EMC = 0x01,
};

/* Section 7.7.54 */
enum dect_nwk_s_ie_codec_list_negotiation_indicator_type {
	DECT_NWK_S_IE_CODEC_LIST_NEGOTIATION_INDICATOR_NOT_POSSIBLE      = 0x0,
	DECT_NWK_S_IE_CODEC_LIST_NEGOTIATION_INDICATOR_CODEC_NEGOTIATION = 0x1,
};

enum dect_nwk_s_ie_codec_list_codec_identifier_type {
	DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_USER_32      = 0x01,
	DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_G726_32      = 0x02,
	DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_G722_64      = 0x03,
	DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_G711_ALAW_64 = 0x04,
	DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_G711_ULAW_64 = 0x05,
	DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_G729_1_32    = 0x06,
	DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_MPEG4_32     = 0x07,
	DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_MPEG4_64     = 0x08,
	DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_USER_64      = 0x09,
};

enum dect_nwk_s_ie_codec_list_mac_and_dlc_service_type {
	DECT_NWK_S_IE_CODEC_LIST_MAC_AND_DLC_SERVICE_LU1_INA  = 0x0,
	DECT_NWK_S_IE_CODEC_LIST_MAC_AND_DLC_SERVICE_LU1_INB  = 0x1,
	DECT_NWK_S_IE_CODEC_LIST_MAC_AND_DLC_SERVICE_LU1_IPM  = 0x2,
	DECT_NWK_S_IE_CODEC_LIST_MAC_AND_DLC_SERVICE_LU1_IPQ  = 0x3,
	DECT_NWK_S_IE_CODEC_LIST_MAC_AND_DLC_SERVICE_LU7_INB  = 0x4,
	DECT_NWK_S_IE_CODEC_LIST_MAC_AND_DLC_SERVICE_LU12_INB = 0x5,
};

enum dect_nwk_s_ie_codec_list_c_plane_routing_type {
	DECT_NWK_S_IE_CODEC_LIST_C_PLANE_ROUTING_CS_ONLY                  = 0x0,
	DECT_NWK_S_IE_CODEC_LIST_C_PLANE_ROUTING_CS_PREFERRED_CF_ACCEPTED = 0x1,
	DECT_NWK_S_IE_CODEC_LIST_C_PLANE_ROUTING_CF_PREFERRED_CS_ACCEPTED = 0x2,
	DECT_NWK_S_IE_CODEC_LIST_C_PLANE_ROUTING_CF_ONLY                  = 0x4,
};

enum dect_nwk_s_ie_codec_list_slot_size_type {
	DECT_NWK_S_IE_CODEC_LIST_SLOT_SIZE_HALF     = 0x0,
	DECT_NWK_S_IE_CODEC_LIST_SLOT_SIZE_LONG_640 = 0x1,
	DECT_NWK_S_IE_CODEC_LIST_SLOT_SIZE_LONG_672 = 0x2,
	DECT_NWK_S_IE_CODEC_LIST_SLOT_SIZE_FULL     = 0x4,
	DECT_NWK_S_IE_CODEC_LIST_SLOT_SIZE_DOUBLE   = 0x5,
};

/* Annex D.2.2 */
enum dect_charset_control_codes {
	DECT_CHARSET_CANCEL_DTMF_TONE                          = 0x00,
	DECT_CHARSET_RETURN_HOME                               = 0x02,
	DECT_CHARSET_RETURN_END                                = 0x03,
	DECT_CHARSET_DIALLING_PAUSE                            = 0x05,
	DECT_CHARSET_MOVE_FORWARD_TO_NEXT_COLUMN_TAB_POSITION  = 0x06,
	DECT_CHARSET_MOVE_BACKWARD_TO_NEXT_COLUMN_TAB_POSITION = 0x07,
	DECT_CHARSET_MOVE_BACKWARD_ONE_COLUMN                  = 0x08,
	DECT_CHARSET_MOVE_FORWARD_ONE_COLUMN                   = 0x09,
	DECT_CHARSET_MOVE_DOWN_ONE_ROW                         = 0x0A,
	DECT_CHARSET_MOVE_UP_ONE_ROW                           = 0x0B,
	DECT_CHARSET_CLEAR_DISPLAY                             = 0x0C,
	DECT_CHARSET_RETURN_TO_START_OF_CURRENT_ROW            = 0x0D,
	DECT_CHARSET_FLASH_OFF                                 = 0x0E,
	DECT_CHARSET_FLASH_ON                                  = 0x0F,
	DECT_CHARSET_XON                                       = 0x11,
	DECT_CHARSET_GO_TO_PULSE_DIALLING                      = 0x12,
	DECT_CHARSET_XOFF                                      = 0x13,
	DECT_CHARSET_GO_TO_DTMF_DIALLING_DEFINED_TONE_LENGTH   = 0x14,
	DECT_CHARSET_REGISTER_RECALL                           = 0x15,
	DECT_CHARSET_GO_TO_DTMF_DIALLING_INFINITE_TONE_LENGTH  = 0x16,
	DECT_CHARSET_INTERNAL_CALL                             = 0x17,
	DECT_CHARSET_SERVICE_CALL                              = 0x18,
	DECT_CHARSET_CLEAR_TO_END_OF_DISPLAY                   = 0x19,
	DECT_CHARSET_CLEAR_TO_END_OF_LINE                      = 0x1A,
	DECT_CHARSET_ESC                                       = 0x1B,
	DECT_CHARSET_SUPPLEMENTARY_SERVICE                     = 0x1C,
};

/*********************************************************************************
 * DECT VALUE STRINGS
 *********************************************************************************/

/* Section 7.2 */
static const value_string nwk_pdisc_vals[] = {
	{ DECT_NWK_PDISC_LCE,		"Link Control Entity (LCE)" },
	{ DECT_NWK_PDISC_CC,		"Call Control (CC)" },
	{ DECT_NWK_PDISC_CISS,		"Call Independent Supplementary Services (CISS)" },
	{ DECT_NWK_PDISC_MM,		"Mobility Management (MM)" },
	{ DECT_NWK_PDISC_CLMS,		"ConnectionLess Message Service (CLMS)" },
	{ DECT_NWK_PDISC_COMS,		"Connection Oriented Message Service (COMS)" },
	{ 0, NULL }
};

/* Section 7.4.1 */
static const value_string nwk_cc_msgt_vals[] = {
	{ DECT_NWK_CC_ALERTING,		"CC-ALERTING" },
	{ DECT_NWK_CC_CALL_PROC,	"CC-CALL-PROC" },
	{ DECT_NWK_CC_SETUP,		"CC-SETUP" },
	{ DECT_NWK_CC_CONNECT,		"CC-CONNECT" },
	{ DECT_NWK_CC_SETUP_ACK,	"CC-SETUP-ACK" },
	{ DECT_NWK_CC_CONNECT_ACK,	"CC-CONNECT-ACK" },
	{ DECT_NWK_CC_SERVICE_CHANGE,	"CC-SERVICE-CHANGE" },
	{ DECT_NWK_CC_SERVICE_ACCEPT,	"CC-SERVICE-ACCEPT" },
	{ DECT_NWK_CC_SERVICE_REJECT,	"CC-SERVICE-REJECT" },
	{ DECT_NWK_CC_RELEASE,		"CC-RELEASE" },
	{ DECT_NWK_CC_RELEASE_COM,	"CC-RELEASE-COM" },
	{ DECT_NWK_CC_IWU_INFO,		"CC-IWU-INFO" },
	{ DECT_NWK_CC_NOTIFY,		"CC-NOTIFY" },
	{ DECT_NWK_CC_INFO,		"CC-INFO" },
	{ 0, NULL }
};

/* Section 7.4.2 */
static const value_string dect_nwk_ciss_message_type_vals[] = {
	{ DECT_NWK_SS_CISS_RELEASE_COM, "CISS-RELEASE-COM" },
	{ DECT_NWK_SS_CISS_FACILITY,    "FACILITY" },
	{ DECT_NWK_SS_CISS_REGISTER,    "CISS-REGISTER" },
	{ 0, NULL }
};

static const value_string dect_nwk_crss_message_type_vals[] = {
	{ DECT_NWK_SS_CRSS_HOLD,         "HOLD" },
	{ DECT_NWK_SS_CRSS_HOLD_ACK,     "HOLD-ACK" },
	{ DECT_NWK_SS_CRSS_HOLD_REJ,     "HOLD-REJECT" },
	{ DECT_NWK_SS_CRSS_RETRIEVE,     "RETRIEVE" },
	{ DECT_NWK_SS_CRSS_RETRIEVE_ACK, "RETRIEVE-ACK" },
	{ DECT_NWK_SS_CRSS_RETRIEVE_REJ, "RETRIEVE-REJECT" },
	{ DECT_NWK_SS_CRSS_FACILITY,     "FACILITY" },
	{ 0, NULL }
};

/* Section 7.4.3 */
static const value_string dect_nwk_coms_message_type_vals[] = {
	{ DECT_NWK_COMS_SETUP,       "COMS-SETUP" },
	{ DECT_NWK_COMS_CONNECT,     "COMS-CONNECT" },
	{ DECT_NWK_COMS_NOTIFY,      "COMS-NOTIFY" },
	{ DECT_NWK_COMS_RELEASE,     "COMS-RELEASE" },
	{ DECT_NWK_COMS_RELEASE_COM, "COMS-RELEASE-COM" },
	{ DECT_NWK_COMS_INFO,        "COMS-INFO" },
	{ DECT_NWK_COMS_ACK,         "COMS-ACK" },
	{ 0, NULL }
};

/* Section 7.4.4 */
static const value_string  dect_nwk_clms_message_type_vals[] = {
	{ DECT_NWK_CLMS_VARIABLE, "CLMS-VARIABLE" },
	{ 0, NULL }
};

/* Section 7.4.5 */
static const value_string nwk_mm_msgt_vals[] = {
	{ DECT_NWK_MM_AUTH_REQ,            "MM-AUTH-REQ" },
	{ DECT_NWK_MM_AUTH_REPLY,          "MM-AUTH-REPLY" },
	{ DECT_NWK_MM_KEY_ALLOC,           "MM-KEY-ALLOCATE" },
	{ DECT_NWK_MM_AUTH_REJ,            "MM-AUTH-REJECT" },
	{ DECT_NWK_MM_ACC_RIGHTS_REQ,      "MM-ACCESS-RIGHTS-REQUEST" },
	{ DECT_NWK_MM_ACC_RIGHTS_ACK,      "MM-ACCESS-RIGHTS-ACCEPT" },
	{ DECT_NWK_MM_ACC_RIGHTS_REJ,      "MM-ACCESS-RIGHTS-REJECT" },
	{ DECT_NWK_MM_ACC_RIGHTS_TERM_REQ, "MM-ACCESS-RIGHTS-TERMINATE-REQUEST" },
	{ DECT_NWK_MM_ACC_RIGHTS_TERM_ACK, "MM-ACCESS-RIGHTS-TERMINATE-ACCEPT" },
	{ DECT_NWK_MM_ACC_RIGHTS_TERM_REJ, "MM-ACCESS-RIGHTS-TERMINATE-REJECT" },
	{ DECT_NWK_MM_CIPH_REQ,            "MM-CIPHER-REQUEST" },
	{ DECT_NWK_MM_CIPH_SUGGEST,        "MM-CIPHER-SUGGEST" },
	{ DECT_NWK_MM_CIPH_REJ,            "MM-CIPHER-REJECT" },
	{ DECT_NWK_MM_INFO_REQ,            "MM-INFO-REQUEST" },
	{ DECT_NWK_MM_INFO_ACK,            "MM-INFO-ACCEPT" },
	{ DECT_NWK_MM_INFO_SUGGEST,        "MM-INFO-SUGGEST" },
	{ DECT_NWK_MM_INFO_REJ,            "MM-INFO-REJECT" },
	{ DECT_NWK_MM_LOCATE_REQ,          "MM-LOCATE-REQUEST" },
	{ DECT_NWK_MM_LOCATE_ACK,          "MM-LOCATE-ACCEPT" },
	{ DECT_NWK_MM_DETACH,              "MM-DETACH" },
	{ DECT_NWK_MM_LOCATE_REJ,          "MM-LOCATE-REJECT" },
	{ DECT_NWK_MM_ID_REQ,              "MM-IDENTITY-REQUEST" },
	{ DECT_NWK_MM_ID_REPLY,            "MM-IDENTITY-REPLY" },
	{ DECT_NWK_MM_IWU,                 "MM-IWU" },
	{ DECT_NWK_MM_TID_ASSIGN,          "MM-TEMPORARY-IDENTITY-ASSIGN" },
	{ DECT_NWK_MM_TID_ASSIGN_ACK,      "MM-TEMPORARY-IDENTITY-ASSIGN-ACK" },
	{ DECT_NWK_MM_TID_ASSIGN_REJ,      "MM-TEMPORARY-IDENTITY-ASSIGN-REJ" },
	{ DECT_NWK_MM_NOTIFY,              "MM-NOTIFY" },
	{ 0, NULL }
};

/* Section 7.4.6 */
static const value_string nwk_lce_msgt_vals[] = {
	{ DECT_NWK_LCE_PAGE_RESP,	"LCE-PAGE-RESPONSE" },
	{ DECT_NWK_LCE_PAGE_REJ, 	"LCE-PAGE-REJECT" },
	{ 0, NULL }
};

/* Section 7.5.3 */
static const true_false_string dect_nwk_s_ie_fl_shift_locking_tfs = {
	"non-locking",
	"locking"
};

static const value_string dect_nwk_s_ie_fl_shift_codeset_val[] = {
	{ DECT_NWK_S_FL_IE_SHIFT_CODESET_INITIAL, "Initial codeset" },
	{ DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_0, "Non-Standard codeset 0" },
	{ DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_1, "Non-Standard codeset 1" },
	{ DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_2, "Non-Standard codeset 2" },
	{ DECT_NWK_S_FL_IE_SHIFT_CODESET_NON_STANDARD_3, "Non-Standard codeset 3" },
	{ 0, NULL }
};

/* Section 7.6.1 */
static const value_string dect_nwk_s_ie_fl_type_val[] = {
	{ DECT_NWK_S_IE_FL_SHIFT,                "SHIFT" },
	{ DECT_NWK_S_IE_FL_CONTROL,              "CONTROL" },
	{ DECT_NWK_S_IE_FL_REPEAT_INDICATOR,     "REPEAT-INDICATOR" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_ELEMENT, "DOUBLE-OCTET-ELEMENT" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_fl_control_type_val[] = {
	{ DECT_NWK_S_IE_FL_CONTROL_SENDING_COMPLETE,  "SENDING-COMPLETE" },
	{ DECT_NWK_S_IE_FL_CONTROL_DELIMITER_REQUEST, "DELIMITER-REQUEST" },
	{ DECT_NWK_S_IE_FL_CONTROL_USE_TPUI,          "USE-TPUI" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_fl_double_octet_type_val[] = {
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_BASIC_SERVICE,     "BASIC-SERVICE" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_RELEASE_REASON,    "RELEASE-REASON" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_SIGNAL,            "SIGNAL" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_TIMER_RESTART,     "TIMER-RESTART" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_TEST_HOOK_CONTROL, "TEST-HOOK-CONTROL" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_SINGLE_DISPLAY,    "SINGLE-DISPLAY" },
	{ DECT_NWK_S_IE_FL_DOUBLE_OCTET_SINGLE_KEYPAD,     "SINGLE-KEYPAD" },
	{ 0, NULL }
};

/* Section 7.6.3 */
static const value_string dect_nwk_s_ie_fl_repeat_indicator_type_val[] = {
	{ DECT_NWK_S_IE_FL_REPEAT_INDICATOR_NON_PRIORITIZED, "Non prioritized list" },
	{ DECT_NWK_S_IE_FL_REPEAT_INDICATOR_PRIORITIZED,     "Prioritized list" },
	{ 0, NULL }
};

/* Section 7.6.4 */
static const value_string dect_nwk_s_ie_fl_basic_service_call_class_val[] = {
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_LIA,                   "Basic speech default setup attributes" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_ULE,                   "ULE service call setup"},
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_MESSAGE,               "Message call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_DECT_ISDN_IIP,         "DECT/ISDN IIP" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_NORMAL,                "Normal call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_INTERNAL,              "Internal call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_EMERGENCY,             "Emergency call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_SERVICE,               "Service call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_EXTERNAL_HANDOVER,     "External handover call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_SUPPLEMENTARY_SERVICE, "Supplementary service call setup" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_CALL_CLASS_OA_M,                  "OA&M call setup" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_fl_basic_service_type_val[] = {
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_BASIC_SPEECH,              "Basic speech default setup attributes" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_DECT_GSM_IWP,              "DECT GSM IWP profile (Phase 2)" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_LRMS,                      "LRMS (E-profile) service" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_DECT_UMTS_IWP_GSM_IWP_SMS, "DECT UMTS IWP or GSM IWP SMS" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_WIDEBAND_SPEECH,           "Wideband speech default setup attributes" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_SUOTA_CLASS_4_DPRS,        "Light data services: SUOTA, Class 4 DPRS management, default setup attributes" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_SUOTA_CLASS_3_DPRS,        "Light data services: SUOTA, Class 3 DPRS management, default setup attributes" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_DTAM_WIDEBAND_SPEECH,      "DTAM Wideband speech default setup attributes" },
	{ DECT_NWK_S_IE_FL_BASIC_SERVICE_OTHER,                     "Other" },
	{ 0, NULL }
};

/* Section 7.6.7 */
static const value_string dect_nwk_s_ie_fl_release_reason_val[] = {
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_NORMAL,                                "Normal" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_UNEXPECTED_MESSAGE,                    "Unexpected Message" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_UNKNOWN_TRANSACTION_IDENTIFIER,        "Unknown Transaction Identifier" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_MANDATORY_INFORMATION_ELEMENT_MISSING, "Mandatory information element missing" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_INVALID_INFORMATION_ELEMENT_CONTENTS,  "Invalid information element contents" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_INCOMPATIBLE_SERVICE,                  "Incompatible service" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_SERVICE_NOT_IMPLEMENTED,               "Service not implemented" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_NEGOTIATION_NOT_SUPPORTED,             "Negotiation not supported" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_INVALID_ENTITY,                        "Invalid identity" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_AUTHENTICATION_FAILED,                 "Authentication failed" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_UNKNOWN_IDENTITY,                      "Unknown identity" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_NEGOTIATION_FAILED,                    "Negotiation failed" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_COLLISION,                             "Collision" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_TIMER_EXPIRY,                          "Timer expiry" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_PARTIAL_RELEASE,                       "Partial release" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_UNKNOWN,                               "Unknown" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_DETACHED,                         "User detached" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_NOT_IN_RANGE,                     "User not in range" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_UNKNOWN,                          "User unknown" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_ALREADY_ACTIVE,                   "User already active" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_BUSY,                             "User busy" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_REJECTION,                        "User rejection" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_USER_CALL_MODIFY,                      "User call modify" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_EXTERNAL_HANDOVER_NOT_SUPPORTED,       "External Handover not supported" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_NETWORK_PARAMETERS_MISSING,            "Network Parameters missing" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_EXTERNAL_HANDOVER_RELEASE,             "External Handover release" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_OVERLOAD,                              "Overload" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_INSUFFICIENT_RESOURCES,                "Insufficient resources" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_INSUFFICIENT_BEARERS_AVAILABLE,        "Insufficient bearers available" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_IWU_CONGESTION,                        "IWU congestion" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_SECURITY_ATTACK_ASSUMED,               "Security attack assumed" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_ENCRYPTION_ACTIVATION_FAILED,          "Encryption activation failed" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_RE_KEYING_FAILED,                      "Re-Keying failed" },
	{ DECT_NWK_S_IE_FL_RELEASE_REASON_NO_CIPHER_KEY_AVAILABLE,               "No Cipher Key available" },
	{ 0, NULL }
};

/* Section 7.6.8 */
static const value_string dect_nwk_s_ie_fl_signal_value_val[] = {
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_DIAL_TONE_ON,               "Dial tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_RINGBACK_TONE_ON,           "Ring-back tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_INTERCEPT_TONE_ON,          "Intercept tone on " },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_NETWORK_CONGESTION_TONE_ON, "Network congestion tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_BUSY_TONE_ON,               "Busy tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_CONFIRM_TONE_ON,            "Confirm tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ANSWER_TONE_ON,             "Answer tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_CALL_WAITING_TONE_ON,       "Call waiting tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_OFF_HOOK_WARNING_TONE_ON,   "Off-hook warning tone on" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_NEGATIVE_ACK_TONE,          "Negative acknowledgement tone" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_TONES_OFF,                  "Tones off" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_0,      "Alerting on - pattern 0" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_1,      "Alerting on - pattern 1" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_2,      "Alerting on - pattern 2" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_3,      "Alerting on - pattern 3" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_4,      "Alerting on - pattern 4" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_5,      "Alerting on - pattern 5" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_6,      "Alerting on - pattern 6" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_PATTERN_7,      "Alerting on - pattern 7" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_ON_CONTINUOUS,     "Alerting on - continuous" },
	{ DECT_NWK_S_IE_FL_SIGNAL_VALUE_ALERTING_OFF,               "Alerting off" },
	{ 0, NULL }
};

/* Section 7.6.9 */
static const value_string dect_nwk_s_ie_fl_timer_restart_value_val[] = {
	{ DECT_NWK_S_IE_FL_TIMER_RESTART_VALUE_RESTART_TIMER, "Restart timer" },
	{ DECT_NWK_S_IE_FL_TIMER_RESTART_VALUE_STOP_TIMER,    "Stop timer" },
	{ 0, NULL }
};

/* Section 7.6.10 */
static const value_string dect_nwk_s_ie_fl_test_hook_control_hook_value_val[] = {
	{ DECT_NWK_S_IE_FL_TEST_HOOK_CONTROL_HOOK_VALUE_ON_HOOK,  "On-Hook" },
	{ DECT_NWK_S_IE_FL_TEST_HOOK_CONTROL_HOOK_VALUE_OFF_HOOK, "Off-Hook" },
	{ 0, NULL }
};

/* Section 7.7.1 */
static const value_string dect_nwk_s_ie_type_val[] = {
	{ DECT_NWK_S_IE_INFO_TYPE,                 "INFO-TYPE" },
	{ DECT_NWK_S_IE_IDENTITY_TYPE,             "IDENTITY-TYPE" },
	{ DECT_NWK_S_IE_PORTABLE_IDENTITY,         "PORTABLE-IDENTITY" },
	{ DECT_NWK_S_IE_FIXED_IDENTITY,            "FIXED-IDENTITY" },
	{ DECT_NWK_S_IE_LOCATION_AREA,             "LOCATION-AREA" },
	{ DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY,     "NWK-ASSIGNED-IDENTITY" },
	{ DECT_NWK_S_IE_AUTH_TYPE,                  "AUTH-TYPE" },
	{ DECT_NWK_S_IE_ALLOCATION_TYPE,            "ALLOCATION-TYPE" },
	{ DECT_NWK_S_IE_RAND,                       "RAND" },
	{ DECT_NWK_S_IE_RES,                        "RES" },
	{ DECT_NWK_S_IE_RS,                         "RS" },
	{ DECT_NWK_S_IE_IWU_ATTRIBUTES,             "IWU-ATTRIBUTES" },
	{ DECT_NWK_S_IE_CALL_ATTRIBUES,             "CALL-ATTRIBUTES" },
	{ DECT_NWK_S_IE_SERVICE_CHANGE_INFO,        "SERVICE-CHANGE-INFO" },
	{ DECT_NWK_S_IE_CONNECTION_ATTRIBUTES,      "CONNECTION-ATTRIBUTES" },
	{ DECT_NWK_S_IE_CIPHER_INFO,                "CIPHER-INFO" },
	{ DECT_NWK_S_IE_CALL_IDENTITY,              "CALL-IDENTITY" },
	{ DECT_NWK_S_IE_CONNECTION_IDENTITY,        "CONNECTION-IDENTITY" },
	{ DECT_NWK_S_IE_FACILITY,                   "FACILITY" },
	{ DECT_NWK_S_IE_PROGRESS_INDICATOR,         "PROGRESS-INDICATOR" },
	{ DECT_NWK_S_IE_MMS_GENERIC_HEADER,         "MMS-GENERIC-HEADER" },
	{ DECT_NWK_S_IE_MMS_OBJECT_HEADER,          "MMS-OBJECT-HEADER" },
	{ DECT_NWK_S_IE_MMS_EXTENDED_HEADER,        "MMS-EXTENDED-HEADER" },
	{ DECT_NWK_S_IE_TIME_DATE,                  "TIME-DATE" },
	{ DECT_NWK_S_IE_MULTI_DISPLAY,              "MULTI-DISPLAY" },
	{ DECT_NWK_S_IE_MULTI_KEYPAD,               "MULTI-KEYPAD" },
	{ DECT_NWK_S_IE_FEATURE_ACTIVATE,           "FEATURE-ACTIVATE" },
	{ DECT_NWK_S_IE_FEATURE_INDICATE,           "FEATURE-INDICATE" },
	{ DECT_NWK_S_IE_NETWORK_PARAMETER,          "NETWORK-PARAMETER" },
	{ DECT_NWK_S_IE_EXT_HO_INDICATOR,           "EXT-HO-INDICATOR" },
	{ DECT_NWK_S_IE_ZAP_FIELD,                  "ZAP-FIELD" },
	{ DECT_NWK_S_IE_SERVICE_CLASS,              "SERVICE-CLASS" },
	{ DECT_NWK_S_IE_KEY,                        "KEY" },
	{ DECT_NWK_S_IE_REJECT_REASON,              "REJECT-REASON" },
	{ DECT_NWK_S_IE_SETUP_CAPABILITY,           "SETUP-CAPABILITY" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY,        "TERMINAL-CAPABILITY" },
	{ DECT_NWK_S_IE_END_TO_END_COMPATIBILITY,   "END-TO-END-COMPATIBILITY" },
	{ DECT_NWK_S_IE_RATE_PARAMETERS,            "RATE-PARAMETERS" },
	{ DECT_NWK_S_IE_TRANSIT_DELAY,              "TRANSIT-DELAY" },
	{ DECT_NWK_S_IE_WINDOW_SIZE,                "WINDOWS-SIZE" },
	{ DECT_NWK_S_IE_ULE_MAC_CONFIGURATION_INFO, "ULE-MAC-CONFIGURATION-INFO" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER,       "CALLING-PARTY-NUMBER" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NAME,         "CALLING-PARTY-NAME" },
	{ DECT_NWK_S_IE_CALLED_PARTY_NUMBER,        "CALLED-PARTY-NUMBER" },
	{ DECT_NWK_S_IE_CALLED_PARTY_SUBADDR,       "CALLED-PARTY-SUBADDR" },
	{ DECT_NWK_S_IE_DURATION,                   "DURATION" },
	{ DECT_NWK_S_IE_CALLED_PARTY_NAME,          "CALLED-PARTY-NAME" },
	{ DECT_NWK_S_IE_LIST_CHANGE_DETAILS,        "LIST-CHANGE-DETAILS" },
	{ DECT_NWK_S_IE_SEGMENTED_INFO,             "SEGMENTED_INFO" },
	{ DECT_NWK_S_IE_ALPHANUMERIC,               "ALPHANUMERIC" },
	{ DECT_NWK_S_IE_IWU_TO_IWU,                 "IWU-TO-IWU" },
	{ DECT_NWK_S_IE_MODEL_IDENTIFIER,           "MODEL-IDENTIFIER" },
	{ DECT_NWK_S_IE_IWU_PACKET,                 "IWU-PACKET" },
	{ DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY,      "ESCAPE-TO-PROPRIETARY" },
	{ DECT_NWK_S_IE_CODEC_LIST,                 "CODEC-LIST" },
	{ DECT_NWK_S_IE_EVENTS_NOTIFICATION,        "EVENTS-NOTIFICATION" },
	{ DECT_NWK_S_IE_CALL_INFORMATION,           "CALL-INFORMATION" },
	{ DECT_NWK_S_IE_ESCAPE_FOR_EXTENSION,       "ESCAPE-FOR-EXTENSION" },
	{ 0, NULL }
};

/* Section 7.7.4 */
static const value_string dect_nwk_s_ie_auth_type_authentication_algorithm_val[] = {
	{ DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_DSAA,        "DECT standard authentication algorithm (DSAA)" },
	{ DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_DSAA2,       "DECT standard authentication algorithm #2 (DSAA2)" },
	{ DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_UMTS,        "GSM authentication algorithm" },
	{ DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_GSM,         "UMTS authentication algorithm" },
	{ DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_PROPRIETARY, "Escape to proprietary algorithm identifier" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_auth_type_ak_type_val[] = {
	{ DECT_NWK_S_IE_AUTH_TYPE_AK_TYPE_USER_AK,             "User authentication key" },
	{ DECT_NWK_S_IE_AUTH_TYPE_AK_TYPE_USER_PERSONAL_ID,    "User personal identity" },
	{ DECT_NWK_S_IE_AUTH_TYPE_AK_TYPE_AUTHENTICATION_CODE, "Authentication code" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_auth_type_default_cipher_key_algorithm_val[] = {
	{ DECT_NWK_S_IE_AUTH_TYPE_DEFAULT_CIPHER_KEY_ALGORITHM_DSC,  "DSC" },
	{ DECT_NWK_S_IE_AUTH_TYPE_DEFAULT_CIPHER_KEY_ALGORITHM_DSC2, "DSC2" },
	{ 0, NULL }
};

static const true_false_string dect_nwk_s_ie_auth_type_cipher_key_number_related_tfs = {
	"IPUI/PARK pair",
	"IPUI"
};

/* Section 7.7.9 */
static const value_string dect_nwk_s_ie_calling_party_number_type_val[] = {
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_UNKNOWN,          "Unknown" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_INTERNATIONAL,    "International number" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_NATIONAL,         "National number" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_NETWORK_SPECIFIC, "Network specific number" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_SUBSCRIBER,       "Subscriber number" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_ABBREVIATED,      "Abbreviated number" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_TYPE_RESERVED,         "Reserved for extension" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_calling_party_number_numbering_plan_val[] = {
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_UNKNOWN,  "Unknown" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_ISDN,     "ISDN/telephony plan" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_DATA,     "Data plan" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_TCP_IP,   "TCP/IP address" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_NATIONAL, "National standard plan" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_PRIVATE,  "Private plan" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_SIP,      "SIP addressing scheme, \"From:\" field" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_INTERNET, "Internet character format address" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_LAN_MAC,  "LAN MAC address" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_X400,     "Recommendation ITU-T X.400 address" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_PROFILE,  "Profile service specific alphanumeric identifier" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_NUMBERING_PLAN_RESERVED, "Reserved for extension" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_calling_party_number_presentation_val[] = {
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_ALLOWED,              "Presentation allowed" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_RESTRICTED,           "Presentation restricted" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_NUMBER_NOT_AVAILABLE, "Number not available" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_RESERVED,             "Reserved" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_calling_party_number_screening_val[] = {
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_USER_NOT_SCREENED,    "User-provided, not screened" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_USER_VERIFIED_PASSED, "User-provided, verified and passed" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_USER_VERIFIED_FAILED, "User-provided, verified and failed" },
	{ DECT_NWK_S_IE_CALLING_PARTY_NUMBER_PRESENTATION_NETWORK,              "Network provided" },
	{ 0, NULL }
};

/* Section 7.7.10 */
static const value_string dect_nwk_s_ie_cipher_info_algorithm_val[] = {
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_DSC,         "DECT Standard Cipher algorithm #1 (DSC)" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_DSC2,        "DECT Standard Cipher algorithm #2 (DSC2)" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_NO,     "GPRS ciphering not used" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA1,   "GPRS encryption algorithm GEA/1" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA2,   "GPRS encryption algorithm GEA/2" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA3,   "GPRS encryption algorithm GEA/3" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA4,   "GPRS encryption algorithm GEA/4" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA5,   "GPRS encryption algorithm GEA/5" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA6,   "GPRS encryption algorithm GEA/6" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_GPRS_GEA7,   "GPRS encryption algorithm GEA/7" },
	{ DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_PROPRIETARY, "Escape to proprietary algorithm identifier" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_cipher_info_key_type_val[] = {
	{ DECT_NWK_S_IE_CIPHER_INFO_KEY_TYPE_DERIVED, "Derived cipher key" },
	{ DECT_NWK_S_IE_CIPHER_INFO_KEY_TYPE_STATIC,  "Static cipher key" },
	{ 0, NULL }
};

/* Section 7.7.13 */
static const value_string dect_nwk_s_ie_duration_lock_limits_type_val[] = {
	{ DECT_NWK_S_IE_DURATION_LOCK_LIMITS_TEMPORARY2, "Temporary user limits 2" },
	{ DECT_NWK_S_IE_DURATION_LOCK_LIMITS_TEMPORARY,  "Temporary user limits" },
	{ DECT_NWK_S_IE_DURATION_LOCK_LIMITS_NO,         "No limits" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_duration_time_limits_type_val[] = {
	{ DECT_NWK_S_IE_DURATION_TIME_LIMITS_ERASE,     "Erase (time limit zero)" },
	{ DECT_NWK_S_IE_DURATION_TIME_LIMITS_DEFINED_1, "Defined time limit 1" },
	{ DECT_NWK_S_IE_DURATION_TIME_LIMITS_DEFINED_2, "Defined time limit 2" },
	{ DECT_NWK_S_IE_DURATION_TIME_LIMITS_STANDARD,  "Standard time limit" },
	{ DECT_NWK_S_IE_DURATION_TIME_LIMITS_INFINITE,  "Infinite" },
	{ 0, NULL }
};

/* Section 7.7.18 */
static const value_string dect_nwk_s_ie_fixed_identity_type_val[] = {
	{ DECT_NWK_S_IE_FIXED_IDENTITY_ARI,              "Access rights identity (ARI)" },
	{ DECT_NWK_S_IE_FIXED_IDENTITY_ARI_PLUS_RPN,     "Access rights identity plus radio fixed part number (ARI + RPN)" },
	{ DECT_NWK_S_IE_FIXED_IDENTITY_ARI_PLUS_RPN_WRS, "Access rights identity plus radio fixed part number for WRS (ARI + RPN for WRS)" },
	{ DECT_NWK_S_IE_FIXED_IDENTITY_PARK,             "Portable access rights key (PARK)" },
	{ 0, NULL }
};

static const value_string dect_nwk_arc_type_val[] = {
	{ DECT_NWK_ARC_TYPE_A, "A (small residential 1..7 RFPs" },
	{ DECT_NWK_ARC_TYPE_B, "B (LAN and multi-cell)" },
	{ DECT_NWK_ARC_TYPE_C, "C (public access)" },
	{ DECT_NWK_ARC_TYPE_D, "D (public with GSM/UMTS)" },
	{ DECT_NWK_ARC_TYPE_E, "E (PP-to-PP)"},
	{ 0, NULL }
};

/* Section 7.7.23 */
static const value_string dect_nwk_s_ie_iwu_to_iwu_protocol_discriminator_type_val[] = {
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_USER_SPECIFIC,     "User specific" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_OSI_HIGH_LAYER,    "OSI high layer protocols" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_X263,              "ITU-T X.263" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_LIST_ACCESS,       "List Access" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_IA5_CHARS,         "IA 5 characters" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_ULE_NON_CCM,       "ULE Configuration and Control (non CCM encrypted) service channel" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_SUOTA,             "Light data service, Software Upgrade Over The Air (SUOTA)" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_V120,              "ITU-T V.120 Rate adaption" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_Q931_MESSAGE,      "ITU-T Q.931, message" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_Q931_IE,           "ITU-T Q.931, information element(s)" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_Q931_PARTIAL,      "ITU-T Q.931, partial message" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_ULE_CCM_AUX0,      "ULE CCM encrypted service channel AUX0" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_ULE_CCM_AUX1,      "ULE CCM encrypted service channel AUX1" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_ULE_CCM_AUX2,      "ULE CCM encrypted service channel AUX2" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_DTAM,              "Digital Telephone Answering Machine (DTAM)" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_GSM_MESSAGE,       "GSM, message" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_GSM_IE,            "GSM, information element(s)" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_UMTS_GPRS_IE,      "UMTS/GPRS, information element(s)" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_UMTS_GPRS_MESSAGE, "UMTS/GPRS, messages" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_LRMS,              "LRMS" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_RLL_AP,            "RLL Access Profile" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_WRS,               "WRS" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_DECT_ISDN_C_PLANE, "DECT/ISDN Intermediate System C-plane specific" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_DECT_ISDN_U_PLANE, "DECT/ISDN Intermediate System U-plane specific" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_DECT_ISDN_OPER,    "DECT/ISDN Intermediate System Operation and Maintenance" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_TERMINAL_DATA,     "Terminal Data" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_DECT_IP,           "DECT access to IP Networks specific" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_MPEG4,             "MPEG-4 ER AAC-LD Configuration Description" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_UNKNOWN,           "Unknown" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_iwu_to_iwu_discriminator_type_val[] = {
	{ DECT_NWK_S_IE_IWU_TO_IWU_DISCRIMINATOR_TYPE_UNSPECIFIED, "Unspecified" },
	{ DECT_NWK_S_IE_IWU_TO_IWU_DISCRIMINATOR_TYPE_EMC,         "EMC" },
	{ 0, NULL }
};

/* Section 7.7.25 */
static const value_string dect_nwk_s_ie_location_area_eli_type_val[] = {
	{ DECT_NWK_S_IE_LOCATION_AREA_ELI_TYPE_LI_REQ_NOT_INCLUDED, "Location information is requested and not included" },
	{ DECT_NWK_S_IE_LOCATION_AREA_ELI_TYPE_LI,                  "Location information" },
	{ 0, NULL }
};

/* Section 7.7.28 */
static const value_string dect_nwk_s_ie_nwk_assigned_identity_type_val[] = {
	{ DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY_TMSI,        "Temporary Mobile Subscriber Identity (TMSI, P-TMSI)" },
	{ DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY_PROPRIETARY, "Proprietary (application specific)" },
	{ 0, NULL }
};

/* Section 7.7.30 */
static const value_string dect_nwk_s_ie_portable_identity_type_val[] = {
	{ DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI, "International Portable User Identity (IPUI)" },
	{ DECT_NWK_S_IE_PORTABLE_IDENTITY_IPEI, "International Portable Equipment Identity (IPEI)" },
	{ DECT_NWK_S_IE_PORTABLE_IDENTITY_TPUI, "Temporary Portable User Identity (TPUI)" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_portable_identity_tpui_assignment_type_val[] = {
	{ DECT_NWK_S_IE_PORTABLE_IDENTITY_TPUI_ASSIGNMENT_TYPE_TPUI,                      "TPUI" },
	{ DECT_NWK_S_IE_PORTABLE_IDENTITY_TPUI_ASSIGNMENT_TYPE_TPUI_WITH_NUMBER_ASSIGNED, "TPUI with number assigned" },
	{ 0, NULL }
};

/* Section 6.2 in ETSI EN 300 175-6 */
static const value_string dect_nwk_ipui_type_val[] = {
	{ DECT_NWK_IPUI_TYPE_N, "N (residential/default)" },
	{ DECT_NWK_IPUI_TYPE_O, "O (private)" },
	{ DECT_NWK_IPUI_TYPE_P, "P (public/public access service)" },
	{ DECT_NWK_IPUI_TYPE_Q, "Q (public/general)" },
	{ DECT_NWK_IPUI_TYPE_R, "R (public/IMSI)" },
	{ DECT_NWK_IPUI_TYPE_S, "S (PSTN/ISDN)" },
	{ DECT_NWK_IPUI_TYPE_T, "T (private extended)" },
	{ DECT_NWK_IPUI_TYPE_U, "U (public/general)" },
	{ 0, NULL }
};

/* Section 7.7.41 */
static const value_string dect_nwk_s_ie_terminal_capability_tone_capabilites_val[] = {
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_TONE_CAPABILITY_NA,                            "Not applicable" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_TONE_CAPABILITY_NO_TONE_CAPABILITY,            "No tone capability" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_TONE_CAPABILITY_DIAL_TONE_ONLY,                "Dial tone only" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_TONE_CAPABILITY_E182_TONES_SUPPORTED,          "Recommendation ITU-T E.182 tones supported" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_TONE_CAPABILITY_COMPLETE_DECT_TONES_SUPPORTED, "Complete DECT tones supported" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_terminal_capability_display_capabilities_val[] = {
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_DISPLAY_CAPABILITY_NA,           "Not applicable" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_DISPLAY_CAPABILITY_NO_DISPLAY,   "No Display" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_DISPLAY_CAPABILITY_NUMERIC,      "Numeric" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_DISPLAY_CAPABILITY_NUMERIC_PLUS, "Numeric-plus" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_DISPLAY_CAPABILITY_ALPHANUMERIC, "Alphanumeric" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_DISPLAY_CAPABILITY_FULL_DISPLAY, "Full display" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_terminal_capability_echo_parameters_val[] = {
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_ECHO_PARAMETER_NA,                   "Not applicable" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_ECHO_PARAMETER_MINIMUM_TCLW,         "Minimum TCLw" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_ECHO_PARAMETER_TCLW_FULL,            "TCLw > 46 dB (Full TCLw)" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_ECHO_PARAMETER_TCLW_VOIP_COMPATIBLE, "TCLw > 55 dB (VoIP compatible TCLw)" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_terminal_capability_n_rej_capabilities_val[] = {
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_N_REJ_NA,       "Not applicable" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_N_REJ_NO,       "No noise rejection" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_N_REJ_PROVIDED, "Noise rejection" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_terminal_capability_a_vol_capabilities_val[] = {
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_A_VOL_NA,            "Not applicable" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_A_VOL_NO_PP_A_VOL,   "No PP adaptive volume control" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_A_VOL_PP_A_VOL_USED, "PP adaptive volume control used" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_terminal_capability_scrolling_behaviour_type_val[] = {
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_SCROLLING_BEHAVIOUR_NOT_SPECIFIED, "Not specified" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_SCROLLING_BEHAVIOUR_TYPE_1,        "Type 1"},
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_SCROLLING_BEHAVIOUR_TYPE_2,        "Type 2"},
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_terminal_capability_profile_indicator_8_packet_data_categories_val[] = {
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_NO,          "No packet data supported or non categorized system" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_CAT_1,       "Cat 1 (low-end data devices)" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_CAT_2,       "Cat 2 (mid-end data devices)" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_CAT_3,       "Cat 3 (high-end data devices)" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_CAT_4_8PSK,  "Cat 4 (high-level modulation up to 8PSK)" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_CAT_4_64QAM, "Cat 4 (high-level modulation up to 64QAM" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_terminal_capability_profile_indicator_9_dect_ule_versions_val[] = {
	{ DECT_NWK_S_IE_TERMINA_CAPABILITY_PROFILE_INDICATOR_9_DECT_ULE_1_V111, "Phase 1 version v1.1.1" },
	{ DECT_NWK_S_IE_TERMINA_CAPABILITY_PROFILE_INDICATOR_9_DECT_ULE_1_V121, "Phase 1 version v1.2.1" },
	{ DECT_NWK_S_IE_TERMINA_CAPABILITY_PROFILE_INDICATOR_9_DECT_ULE_2,      "Phase 2" },
	{ DECT_NWK_S_IE_TERMINA_CAPABILITY_PROFILE_INDICATOR_9_DECT_ULE_3,      "Phase 3" },
	{ 0, NULL }
};

static const value_string  dect_nwk_s_ie_terminal_capability_control_codes_val[] =  {
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_CONTROL_CODES_NOT_SPECIFIED, "Not specified" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_CONTROL_CODES_0CH,           "0CH (clear display)" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_CONTROL_CODES_CODING_001,    "Coding 001 plus 0x08 to 0x0B and 0x0D" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_CONTROL_CODES_CODING_010,    "Coding 010 plus 0x02, 0x03, 0x06, 0x07, 0x19, 0x1A" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_CONTROL_CODES_CODING_011,    "Coding 011 plus 0x0E, 0x0F" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_terminal_capability_blind_slot_indication_val[] = {
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_BLIND_SLOT_INDICATION_NO,                            "No blind slots" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_BLIND_SLOT_INDICATION_NOT_POSSIBLE_ADJACENT,         "Setup is not possible on both slots adjacent to an active slot" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_BLIND_SLOT_INDICATION_NOT_POSSIBLE_EVERY_SECOND,     "Setup is not possible on every second slot" },
	{ DECT_NWK_S_IE_TERMINAL_CAPABILITY_BLIND_SLOT_INDICATION_LIMITATIONS_IN_FOLLOWING_BITS, "Limitations indicated in the following bits" },
	{ 0, NULL }
};

/* Section 7.7.45 */
static const value_string dect_nwk_s_ie_escape_to_proprietary_discriminator_type_val[] = {
	{ DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_UNSPECIFIED, "Unspecified" },
	{ DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_EMC,         "EMC" },
	{ 0, NULL }
};

static const true_false_string tfs_last_more = {
	"Last",
	"More"
};

/* Section 7.7.54 */
static const value_string dect_nwk_s_ie_codec_list_negotiation_indicator_type_val[] = {
	{ DECT_NWK_S_IE_CODEC_LIST_NEGOTIATION_INDICATOR_NOT_POSSIBLE,      "Negotiation not possible" },
	{ DECT_NWK_S_IE_CODEC_LIST_NEGOTIATION_INDICATOR_CODEC_NEGOTIATION, "Codec negotiation" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_codec_list_codec_identifier_type_val[] = {
	{ DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_USER_32,      "user specific, 32 kbit/s" },
	{ DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_G726_32,      "G.726 ADPCM, 32 kbit/s" },
	{ DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_G722_64,      "G.722, 64 kbit/s" },
	{ DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_G711_ALAW_64, "G.711 alaw, 64 kbit/s" },
	{ DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_G711_ULAW_64, "G.711 ulaw, 64 kbit/s" },
	{ DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_G729_1_32,    "G.729.1, 32 kbit/s" },
	{ DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_MPEG4_32,     "MPEG-4 ER AAC-LD, 32 kbit/s" },
	{ DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_MPEG4_64,     "MPEG-4 ER AAC-LD, 64 kbit/s" },
	{ DECT_NWK_S_IE_CODEC_LIST_CODEC_IDENTIFIER_USER_64,      "user specific, 64 kbit/s" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_codec_list_mac_and_dlc_service_type_val[] = {
	{ DECT_NWK_S_IE_CODEC_LIST_MAC_AND_DLC_SERVICE_LU1_INA,  "DLC service LU1, MAC service INA" },
	{ DECT_NWK_S_IE_CODEC_LIST_MAC_AND_DLC_SERVICE_LU1_INB,  "DLC service LU1, MAC service INB" },
	{ DECT_NWK_S_IE_CODEC_LIST_MAC_AND_DLC_SERVICE_LU1_IPM,  "DLC service LU1, MAC service IPM" },
	{ DECT_NWK_S_IE_CODEC_LIST_MAC_AND_DLC_SERVICE_LU1_IPQ,  "DLC service LU1, MAC service IPQ" },
	{ DECT_NWK_S_IE_CODEC_LIST_MAC_AND_DLC_SERVICE_LU7_INB,  "DLC service LU7, MAC service INB" },
	{ DECT_NWK_S_IE_CODEC_LIST_MAC_AND_DLC_SERVICE_LU12_INB, "DLC service LU12, MAC service INB" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_codec_list_c_plane_routing_type_val[] = {
	{ DECT_NWK_S_IE_CODEC_LIST_C_PLANE_ROUTING_CS_ONLY,                  "CS only" },
	{ DECT_NWK_S_IE_CODEC_LIST_C_PLANE_ROUTING_CS_PREFERRED_CF_ACCEPTED, "CS preferred / CF accepted" },
	{ DECT_NWK_S_IE_CODEC_LIST_C_PLANE_ROUTING_CF_PREFERRED_CS_ACCEPTED, "CF preferred / CS accepted" },
	{ DECT_NWK_S_IE_CODEC_LIST_C_PLANE_ROUTING_CF_ONLY,                  "CF only" },
	{ 0, NULL }
};

static const value_string dect_nwk_s_ie_codec_list_slot_size_type_val[] = {
	{ DECT_NWK_S_IE_CODEC_LIST_SLOT_SIZE_HALF,     "Half slot; j = 0" },
	{ DECT_NWK_S_IE_CODEC_LIST_SLOT_SIZE_LONG_640, "Long slot; j = 640" },
	{ DECT_NWK_S_IE_CODEC_LIST_SLOT_SIZE_LONG_672, "Long slot; j = 672" },
	{ DECT_NWK_S_IE_CODEC_LIST_SLOT_SIZE_FULL,     "Full slot" },
	{ DECT_NWK_S_IE_CODEC_LIST_SLOT_SIZE_DOUBLE,   "Double slot" },
	{ 0, NULL }
};

/* Annex D.2.2 */
static const value_string dect_charset_control_codes_val[] = {
	{ DECT_CHARSET_CANCEL_DTMF_TONE,                          "Null/cancel DTMF tone" },
	{ DECT_CHARSET_RETURN_HOME,                               "Return home" },
	{ DECT_CHARSET_RETURN_END,                                "Return end" },
	{ DECT_CHARSET_DIALLING_PAUSE,                            "Dialling pause" },
	{ DECT_CHARSET_MOVE_FORWARD_TO_NEXT_COLUMN_TAB_POSITION,  "Move forward to next column tab position" },
	{ DECT_CHARSET_MOVE_BACKWARD_TO_NEXT_COLUMN_TAB_POSITION, "Move backward to next column tab position" },
	{ DECT_CHARSET_MOVE_BACKWARD_ONE_COLUMN,                  "Move backward one column" },
	{ DECT_CHARSET_MOVE_FORWARD_ONE_COLUMN,                   "Move forward one column" },
	{ DECT_CHARSET_MOVE_DOWN_ONE_ROW,                         "Move down one row" },
	{ DECT_CHARSET_MOVE_UP_ONE_ROW,                           "Move up one row" },
	{ DECT_CHARSET_CLEAR_DISPLAY,                             "Clear display (and return home)" },
	{ DECT_CHARSET_RETURN_TO_START_OF_CURRENT_ROW,            "Return (to start of current row)" },
	{ DECT_CHARSET_FLASH_OFF,                                 "Flash off (see note 2)" },
	{ DECT_CHARSET_FLASH_ON,                                  "Flash on (see note 2)" },
	{ DECT_CHARSET_XON,                                       "XON (resume transmission)" },
	{ DECT_CHARSET_GO_TO_PULSE_DIALLING,                      "Go to pulse dialling" },
	{ DECT_CHARSET_XOFF,                                      "XOFF (stop transmission)" },
	{ DECT_CHARSET_GO_TO_DTMF_DIALLING_DEFINED_TONE_LENGTH,   "Go to DTMF dialling; defined tone length" },
	{ DECT_CHARSET_REGISTER_RECALL,                           "Register recall" },
	{ DECT_CHARSET_GO_TO_DTMF_DIALLING_INFINITE_TONE_LENGTH,  "Go to DTMF dialling; infinite tone length" },
	{ DECT_CHARSET_INTERNAL_CALL,                             "Internal call" },
	{ DECT_CHARSET_SERVICE_CALL,                              "Service call" },
	{ DECT_CHARSET_CLEAR_TO_END_OF_DISPLAY,                   "Clear to end of display" },
	{ DECT_CHARSET_CLEAR_TO_END_OF_LINE,                      "Clear to end of line" },
	{ DECT_CHARSET_ESC,                                       "ESC. ESCape in the IA5 sense" },
	{ DECT_CHARSET_SUPPLEMENTARY_SERVICE,                     "Supplementary service" },
	{ 0, NULL }
};

/* TOOD: value_string for other protocols */

#define DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_MASK 0x80
#define DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_SHIFT 7

#define DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_MASK 0x7F

#define DECT_NWK_S_IE_FIXED_LENGTH_MASK  0x80
#define DECT_NWK_S_IE_FIXED_LENGTH_SHIFT 7

#define DECT_NWK_S_IE_FL_TYPE_MASK 0x70
#define DECT_NWK_S_IE_FL_TYPE_SHIFT 4
#define DECT_NWK_S_IE_FL_DOUBLE_OCTET_TYPE_MASK 0x0F

#define DECT_NWK_S_IE_AUTH_TYPE_DEF_MASK 0x40
#define DECT_NWK_S_IE_AUTH_TYPE_DEF_SHIFT 6

#define DECT_NWK_S_IE_PORTABLE_IDENTITY_TYPE_MASK 0x7F
#define DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI_TYPE_MASK 0xF0
#define DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI_TYPE_SHIFT 4

#define DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_MASK 0x3F
#define DECT_NWK_S_IE_IWU_TO_IWU_DISCRIMINATOR_TYPE_MASK 0x7F

#define DECT_NWK_S_IE_LOCATION_AREA_LI_EXTENDED_INCLUDED_MASK 0x80
#define DECT_NWK_S_IE_LOCATION_AREA_LI_EXTENDED_INCLUDED_SHIFT 7
#define DECT_NWK_S_IE_LOCATION_AREA_ELI_TYPE_MASK 0xF0
#define DECT_NWK_S_IE_LOCATION_AREA_ELI_TYPE_SHIFT 4

#define DECT_NWK_S_IE_TERMINAL_CAPABILITY_STORED_DISPLAY_CHARACTERS_MASK 0x7F

#define DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_MASK 0x7F

#define DECT_NWK_S_IE_CODEC_LIST_LAST_CODEC_MASK 0x80
#define DECT_NWK_S_IE_CODEC_LIST_LAST_CODEC_SHIFT 7

/*********************************************************************************
 * DECT dissector code
 *********************************************************************************/

static proto_item* add_dect_nwk_dect_charset_tree_item(proto_tree *tree, packet_info *pinfo, int hfindex, tvbuff_t *tvb, int start, int length)
{
	const char *keypad_string, *current_char_ptr;
	uint8_t current_char_position;
	gunichar current_char;
	wmem_strbuf_t *keypad_information;

	keypad_string = tvb_get_string_enc(pinfo->pool, tvb, start, length, ENC_DECT_STANDARD_8BITS);
	current_char_ptr = keypad_string;

	keypad_information = wmem_strbuf_new_sized(pinfo->pool, length);
	for ( current_char_position = 0; current_char_position < length; current_char_position++ ) {
		current_char = g_utf8_get_char(current_char_ptr);
		if ( current_char < 0x20 ) {
			wmem_strbuf_append_printf(keypad_information, "<<%s>>", val_to_str(current_char, dect_charset_control_codes_val, "0x%02x"));
		} else {
			wmem_strbuf_append_unichar(keypad_information, current_char);
		}
		current_char_ptr = g_utf8_next_char(current_char_ptr);
	}

	return proto_tree_add_string_format_value(tree, hfindex, tvb, start, length, keypad_string ,"%s", wmem_strbuf_get_str(keypad_information));
}

static int dissect_dect_nwk_s_ie_auth_type(tvbuff_t *tvb, unsigned offset, proto_tree *tree, void _U_ *data)
{
	uint8_t authentication_algorithm;
	bool def;

	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_authentication_algorithm, tvb, offset, 1, ENC_NA);
	authentication_algorithm = tvb_get_uint8(tvb, offset);
	offset++;
	if ( authentication_algorithm == DECT_NWK_S_IE_AUTH_TYPE_AUTHENTICATION_ALGORITHM_PROPRIETARY ) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_proprietary_algorithm, tvb, offset, 1, ENC_NA);
		offset++;
	}
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_ak_type, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_ak_number, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_inc, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_def, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_txc, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_upc, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_cipher_key_number, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_cipher_key_number_related, tvb, offset, 1, ENC_NA);
	def = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_AUTH_TYPE_DEF_MASK ) >> DECT_NWK_S_IE_AUTH_TYPE_DEF_SHIFT;
	offset++;
	if( def ) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_default_cipher_key_index, tvb, offset, 2, ENC_NA);
		offset += 2;
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_auth_type_default_cipher_key_algorithm, tvb, offset, 1, ENC_NA);
		offset++;
	}
	return offset;
}

static int dissect_dect_nwk_s_ie_calling_party_number(tvbuff_t *tvb, unsigned offset, uint8_t ie_length, proto_tree *tree, void _U_ *data)
{
	bool octet_group_extension;
	uint8_t address_length;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_octet_group_extension, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_calling_party_number_type, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_calling_party_number_numbering_plan, tvb, offset, 1, ENC_NA);
	octet_group_extension = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_MASK ) >> DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_SHIFT;
	offset++;
	if ( !octet_group_extension ) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_octet_group_extension, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_calling_party_number_presentation, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_calling_party_number_screening, tvb, offset, 1, ENC_NA);
		offset++;
		address_length = ie_length - 2;
	} else {
		address_length = ie_length - 1;
	}
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_calling_party_number_address, tvb, offset, address_length, ENC_DECT_STANDARD_8BITS);
	return offset + address_length;
}

static int dissect_dect_nwk_s_ie_cipher_info(tvbuff_t *tvb, unsigned offset, proto_tree *tree, void _U_ *data)
{
	uint8_t algorithm;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_cipher_info_yn, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_cipher_info_algorithm, tvb, offset, 1, ENC_NA);
	algorithm = tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_MASK;
	offset++;
	if (algorithm == DECT_NWK_S_IE_CIPHER_INFO_ALGORITHM_PROPRIETARY) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_cipher_info_proprietary_algorithm, tvb, offset, 1, ENC_NA);
		offset++;
	}
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_cipher_info_key_type, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_cipher_info_key_number, tvb, offset, 1, ENC_NA);
	offset++;
	return offset;
}

static int dissect_dect_nwk_s_ie_duration(tvbuff_t *tvb, unsigned offset, uint8_t _U_ ie_length, packet_info _U_ *pinfo, proto_tree *tree, void _U_ *data) {
	bool octet_group_extension;

	proto_tree_add_item(tree, hf_dect_nwk_s_ie_octet_group_extension, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_duration_lock_limits, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_duration_time_limits, tvb, offset, 1, ENC_NA);
	octet_group_extension = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_MASK ) >> DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_SHIFT;
	offset++;

	if ( !octet_group_extension ) {
		/* Octet 3a does not have an group extension indicator, it is solely defined by the one in octet 3 */
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_duration_time_duration, tvb, offset, 1, ENC_NA);
		offset++;
	}

	return offset;
}

static int dissect_dect_nwk_s_ie_fixed_identity(tvbuff_t *tvb, unsigned offset, proto_tree *tree, void _U_ *data)
{
	uint8_t value_length;
	unsigned bit_offset, no_of_bits;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_fixed_identity_type, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_fixed_identity_value_length, tvb, offset, 1, ENC_NA);
	value_length = tvb_get_uint8(tvb, offset) & 0x7F;
	offset++;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_fixed_identity_arc, tvb, offset, 1, ENC_NA);
	bit_offset = ( offset * 8 ) + 4;
	no_of_bits = value_length - 4;
	proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_fixed_identity_ard, tvb, bit_offset, no_of_bits, ENC_NA);
	bit_offset += no_of_bits;
	offset += value_length / 8;
	if (value_length % 8) {
		no_of_bits = 8 - (value_length % 8);
		proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_fixed_identity_padding, tvb, bit_offset, no_of_bits, ENC_NA);
		offset++;
	}
	return offset;
}

static int dissect_dect_nwk_s_ie_iwu_to_iwu(tvbuff_t *tvb, unsigned offset, uint8_t ie_length, packet_info _U_ *pinfo, proto_tree *tree, void _U_ *data) {
	uint8_t protocol_discriminator, discriminator_type, remaining_length;

	proto_tree_add_item(tree, hf_dect_nwk_s_ie_iwu_to_iwu_sr, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_iwu_to_iwu_protocol_discriminator, tvb, offset, 1, ENC_NA);
	protocol_discriminator = tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_MASK;
	offset++;
	remaining_length = ie_length -1;

	proto_tree_add_item(tree, hf_dect_nwk_s_ie_iwu_to_iwu_information, tvb, offset, remaining_length, ENC_NA);
	if ( protocol_discriminator == DECT_NWK_S_IE_IWU_TO_IWU_PROTOCOL_DISCRIMINATOR_USER_SPECIFIC ) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_iwu_to_iwu_discriminator_type, tvb, offset, 1, ENC_NA);
		discriminator_type = tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_IWU_TO_IWU_DISCRIMINATOR_TYPE_MASK;
		offset++;
		remaining_length--;

		proto_tree_add_item(tree, hf_dect_nwk_s_ie_iwu_to_iwu_user_specific_contents, tvb, offset, remaining_length, ENC_NA);
		if ( discriminator_type == DECT_NWK_S_IE_IWU_TO_IWU_DISCRIMINATOR_TYPE_EMC ) {
			proto_tree_add_item(tree, hf_dect_nwk_s_ie_iwu_to_iwu_emc_discriminator, tvb, offset, 2, ENC_NA);
			offset += 2;
			remaining_length -= 2;
			proto_tree_add_item(tree, hf_dect_nwk_s_ie_iwu_to_iwu_proprietary_contents, tvb, offset, remaining_length, ENC_NA);
		}
	}

	return offset + remaining_length;
}

static int dissect_dect_nwk_s_ie_location_area(tvbuff_t *tvb, unsigned offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	uint8_t eli_type;
	bool li_extended_included;
	proto_tree *li_type_tree;
	proto_item *li_type_item;

	li_type_item = proto_tree_add_item(tree, hf_dect_nwk_s_ie_location_area_li_type, tvb, offset, 1, ENC_NA);
	li_type_tree = proto_item_add_subtree(li_type_item, ett_dect_nwk_s_ie_location_area_li_type);
	proto_tree_add_item(li_type_tree, hf_dect_nwk_s_ie_location_area_li_extended_included, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(li_type_tree, hf_dect_nwk_s_ie_location_area_la_level_included, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_location_area_la_level, tvb, offset, 1, ENC_NA);
	li_extended_included = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_LOCATION_AREA_LI_EXTENDED_INCLUDED_MASK ) >> DECT_NWK_S_IE_LOCATION_AREA_LI_EXTENDED_INCLUDED_SHIFT;
	offset++;

	if ( li_extended_included ) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_location_area_eli_type, tvb, offset, 1, ENC_NA);
		eli_type = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_LOCATION_AREA_ELI_TYPE_MASK ) >> DECT_NWK_S_IE_LOCATION_AREA_ELI_TYPE_SHIFT;
		offset++;
		if ( eli_type == DECT_NWK_S_IE_LOCATION_AREA_ELI_TYPE_LI ) {
			offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, E212_NONE, false);
			proto_tree_add_item(tree, hf_dect_nwk_s_ie_location_area_lac, tvb, offset, 2, ENC_NA);
			offset += 2;
			proto_tree_add_item(tree, hf_dect_nwk_s_ie_location_area_ci, tvb, offset, 2, ENC_NA);
			offset += 2;
		}
	}
	return offset;
}

static int dissect_dect_nwk_s_ie_nwk_assigned_identity(tvbuff_t *tvb, unsigned offset, proto_tree *tree, void _U_ *data)
{
	uint8_t value_length;
	unsigned bit_offset, no_of_bits;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_nwk_assigned_identity_type, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_nwk_assigned_identity_value_length, tvb, offset, 1, ENC_NA);
	value_length = tvb_get_uint8(tvb, offset) & 0x7F;
	offset++;
	bit_offset = offset * 8;
	proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_nwk_assigned_identity_value, tvb, bit_offset, value_length, ENC_NA);
	bit_offset += value_length;
	offset += value_length / 8;
	if (value_length % 8) {
		no_of_bits = 8 - (value_length % 8);
		proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_nwk_assigned_identity_padding, tvb, bit_offset, no_of_bits, ENC_NA);
		offset++;
	}
	return offset;
}

static int dissect_dect_nwk_s_ie_multi_display(tvbuff_t *tvb, unsigned offset, uint8_t ie_length, packet_info _U_ *pinfo, proto_tree *tree, void _U_ *data)
{
	add_dect_nwk_dect_charset_tree_item(tree, pinfo, hf_dect_nwk_s_ie_multi_display_information, tvb, offset, ie_length);
	offset += ie_length;

	return offset;
}

static int dissect_dect_nwk_s_ie_multi_keypad(tvbuff_t *tvb, unsigned offset, uint8_t ie_length, packet_info _U_ *pinfo, proto_tree *tree, void _U_ *data)
{
	add_dect_nwk_dect_charset_tree_item(tree, pinfo, hf_dect_nwk_s_ie_multi_keypad_information, tvb, offset, ie_length);
	offset += ie_length;

	return offset;
}

static int dissect_dect_nwk_s_ie_portable_identity(tvbuff_t *tvb, unsigned offset, proto_tree *tree, void _U_ *data)
{
	uint8_t value_length, identity_type, ipui_type;
	unsigned bit_offset, no_of_bits, overflow_bits_in_last_byte, no_of_bytes;
	bool bcd_last_byte_odd;
	identity_type = tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_PORTABLE_IDENTITY_TYPE_MASK;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_portable_identity_type, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_portable_identity_value_length, tvb, offset, 1, ENC_NA);
	value_length = tvb_get_uint8(tvb, offset) & 0x7F;
	overflow_bits_in_last_byte = value_length % 8;
	if (overflow_bits_in_last_byte) {
		no_of_bytes = value_length / 8 + 1;
		bcd_last_byte_odd = true;
	} else {
		no_of_bytes = value_length / 8;
		bcd_last_byte_odd = false;
	}
	offset++;
	bit_offset = ( offset * 8 ) + 4;
	switch(identity_type) {
		case DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI:
			ipui_type = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI_TYPE_MASK ) >> DECT_NWK_S_IE_PORTABLE_IDENTITY_IPUI_TYPE_SHIFT;
			proto_tree_add_item(tree, hf_dect_nwk_s_ie_portable_identity_put, tvb, offset, 1, ENC_NA);
			no_of_bits = value_length - 4;
			switch(ipui_type) {
				case DECT_NWK_IPUI_TYPE_N:
					proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_portable_identity_ipei, tvb, bit_offset, no_of_bits, ENC_NA);
					break;
				case DECT_NWK_IPUI_TYPE_O:
					proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_portable_identity_ipui_o_number, tvb, bit_offset, no_of_bits, ENC_NA);
					break;
				case DECT_NWK_IPUI_TYPE_P:
					proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_portable_identity_ipui_p_poc, tvb, bit_offset, 16, ENC_BIG_ENDIAN);
					proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_portable_identity_ipui_p_acc, tvb, bit_offset + 16, no_of_bits - 16, ENC_BIG_ENDIAN);
					break;
				case DECT_NWK_IPUI_TYPE_Q:
					proto_tree_add_item(tree, hf_dect_nwk_s_ie_portable_identity_ipui_q_bacn, tvb, offset, no_of_bytes,
						ENC_BCD_DIGITS_0_9 | ENC_BIG_ENDIAN | ENC_BCD_SKIP_FIRST | (bcd_last_byte_odd ? ENC_BCD_ODD_NUM_DIG : 0));
					break;
				case DECT_NWK_IPUI_TYPE_R:
					proto_tree_add_item(tree, hf_dect_nwk_s_ie_portable_identity_ipui_r_imsi, tvb, offset, no_of_bytes,
						ENC_BCD_DIGITS_0_9 | ENC_BIG_ENDIAN | ENC_BCD_SKIP_FIRST | (bcd_last_byte_odd ? ENC_BCD_ODD_NUM_DIG : 0));
					break;
				case DECT_NWK_IPUI_TYPE_S:
					proto_tree_add_item(tree, hf_dect_nwk_s_ie_portable_identity_ipui_s_number, tvb, offset, no_of_bytes,
						ENC_BCD_DIGITS_0_9 | ENC_BIG_ENDIAN | ENC_BCD_SKIP_FIRST | (bcd_last_byte_odd ? ENC_BCD_ODD_NUM_DIG : 0));
					break;
				case DECT_NWK_IPUI_TYPE_T:
					proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_portable_identity_ipui_t_eic, tvb, bit_offset, 16, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_dect_nwk_s_ie_portable_identity_ipui_t_number, tvb, offset + 2, no_of_bytes - 2,
						ENC_BCD_DIGITS_0_9 | ENC_BIG_ENDIAN | ENC_BCD_SKIP_FIRST | (bcd_last_byte_odd ? ENC_BCD_ODD_NUM_DIG : 0));
					break;
				case DECT_NWK_IPUI_TYPE_U:
					proto_tree_add_item(tree, hf_dect_nwk_s_ie_portable_identity_ipui_u_cacn, tvb, offset, no_of_bytes,
						ENC_BCD_DIGITS_0_9 | ENC_BIG_ENDIAN | ENC_BCD_SKIP_FIRST | (bcd_last_byte_odd ? ENC_BCD_ODD_NUM_DIG : 0));
					break;
			}

			bit_offset += no_of_bits;
			offset += value_length / 8;
			if (overflow_bits_in_last_byte) {
				no_of_bits = 8 - overflow_bits_in_last_byte;
				proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_portable_identity_padding, tvb, bit_offset, no_of_bits, ENC_NA);
				offset++;
			}
			break;
		case DECT_NWK_S_IE_PORTABLE_IDENTITY_IPEI:
			no_of_bits = value_length - 4;
			proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_portable_identity_ipei, tvb, bit_offset, no_of_bits, ENC_NA);
			offset += 5;
			break;
		case DECT_NWK_S_IE_PORTABLE_IDENTITY_TPUI:
			no_of_bits = value_length;
			proto_tree_add_item(tree, hf_dect_nwk_s_ie_portable_identity_tpui_assignment_type, tvb, offset, 1, ENC_NA);
			proto_tree_add_bits_item(tree, hf_dect_nwk_s_ie_portable_identity_tpui_value, tvb, bit_offset, no_of_bits, ENC_NA);
			offset += 3;
			break;
	}
	return offset;
}

static int dissect_dect_nwk_s_ie_terminal_capability(tvbuff_t *tvb, unsigned offset, uint8_t ie_length, packet_info _U_ *pinfo, proto_tree *tree, void _U_ *data)
{
	bool octet_group_extension;
	unsigned octet_identifier, next_element_offset;
	uint16_t stored_display_characters = 0;

	static int* const slot_type_flags[] = {
		&hf_dect_nwk_s_ie_terminal_capability_slot_type_double,
		&hf_dect_nwk_s_ie_terminal_capability_slot_type_full,
		&hf_dect_nwk_s_ie_terminal_capability_slot_type_long_672,
		&hf_dect_nwk_s_ie_terminal_capability_slot_type_long_640,
		&hf_dect_nwk_s_ie_terminal_capability_slot_type_half_80,
		NULL
	};

	static int* const profile_indicator_1_flags [] = {
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_cap,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_gap,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_dect_gsm,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_isdn,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_lrms,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_dprs_stream,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_dprs_asymmetric,
		NULL
	};

	static int* const profile_indicator_2_flags [] = {
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_dprs_class_2,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_data_services,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_isdn,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_dect_umts_bearer,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_dect_umts_sms,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_dect_umts_facsimile,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_rap,
		NULL
	};

	static int* const profile_indicator_3_flags[] = {
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_dect_gsm,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_wrs,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_sms,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_dmap,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_cta,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_ethernet,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_token_ring,
		NULL
	};

	static int* const profile_indicator_4_flags[] = {
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_ip,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_ppp,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_v24,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_cf,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_ipq,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_rap_2,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_dprs,
		NULL
	};

	static int* const profile_indicator_5_flags[] = {
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_2bz,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_4bz,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_8bz,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_16bz,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_2a,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_4a,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_8a,
		NULL
	};

	static int* const profile_indicator_6_flags[] = {
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_dect_umts,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_dect_umts_gprs,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_odap,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_f_mms,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_gf,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_fast_hopping,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_no_emission,
		NULL
	};

	static int* const profile_indicator_7_flags[] = {
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_mod64,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_ng_dect_1,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_ng_dect_3,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_headset_management,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_re_keying,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_associated_melody,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_ng_dect_5,
		NULL
	};

	static int* const profile_indicator_8_flags[] = {
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8_mux_e_u,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8_channel_ipf,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8_channel_sipf,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8_packet_data_category,
		NULL
	};

	static int* const profile_indicator_9_flags[] = {
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9_dprs_3,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9_dprs_4,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9_dect_ule,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9_light_data,
		NULL
	};

	static int* const profile_indicator_10_flags[] = {
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_date_time_recovery,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_extended_list_change,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_screening,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_wrs_2,
		&hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_wrs_ule,
		NULL
	};

	static int* const escape_to_char_sets_1_flags[] = {
		&hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1_latin_no1,
		&hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1_latin_no9,
		&hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1_latin_no5,
		&hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1_greek,
		NULL
	};

	static int* const blind_slot_6_flags[] = {
		&hf_dect_nwk_s_ie_terminal_capability_blind_slot_indication,
		&hf_dect_nwk_s_ie_terminal_capability_sp0,
		&hf_dect_nwk_s_ie_terminal_capability_sp1,
		&hf_dect_nwk_s_ie_terminal_capability_sp2,
		&hf_dect_nwk_s_ie_terminal_capability_sp3,
		&hf_dect_nwk_s_ie_terminal_capability_sp4,
		NULL
	};

	static int* const blind_slot_6a_flags[] = {
		&hf_dect_nwk_s_ie_terminal_capability_sp5,
		&hf_dect_nwk_s_ie_terminal_capability_sp6,
		&hf_dect_nwk_s_ie_terminal_capability_sp7,
		&hf_dect_nwk_s_ie_terminal_capability_sp8,
		&hf_dect_nwk_s_ie_terminal_capability_sp9,
		&hf_dect_nwk_s_ie_terminal_capability_sp10,
		&hf_dect_nwk_s_ie_terminal_capability_sp11,
		NULL
	};

	next_element_offset = offset + ie_length;

	octet_identifier = DECT_NWK_S_IE_OCTET_FIRST;
	do {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_octet_group_extension, tvb, offset, 1, ENC_NA);
		switch(octet_identifier) {
			case DECT_NWK_S_IE_OCTET_FIRST:
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_terminal_capability_tone_capabilities, tvb, offset, 1, ENC_NA);
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_terminal_capability_display_capabilities, tvb, offset, 1, ENC_NA);
				/* Octet 3a is intentionally missing according to the standard */
				octet_identifier++;
				break;
			case DECT_NWK_S_IE_OCTET_B:
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_terminal_capability_echo_parameter, tvb, offset, 1, ENC_NA);
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_terminal_capability_n_rej, tvb, offset, 1, ENC_NA);
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_terminal_capability_a_vol, tvb, offset, 1, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_C:
				proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_slot_type_capability, ett_dect_nwk_s_ie_element, slot_type_flags, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_D:
				stored_display_characters = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_TERMINAL_CAPABILITY_STORED_DISPLAY_CHARACTERS_MASK ) << 7;
				break;
			case DECT_NWK_S_IE_OCTET_E:
				stored_display_characters = stored_display_characters |	( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_TERMINAL_CAPABILITY_STORED_DISPLAY_CHARACTERS_MASK );
				proto_tree_add_uint(tree, hf_dect_nwk_s_ie_terminal_capability_stored_display_characters, tvb, offset-1, 2, stored_display_characters);
				break;
			case DECT_NWK_S_IE_OCTET_F:
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_terminal_capability_lines_in_display, tvb, offset, 1, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_G:
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_terminal_capability_chars_per_line, tvb, offset, 1, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_H:
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_terminal_capability_scrolling_behaviour, tvb, offset, 1, ENC_NA);
				break;
		}
		octet_group_extension = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_MASK ) >> DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_SHIFT;
		octet_identifier++;
		offset++;
	} while ( !octet_group_extension );

	octet_identifier = DECT_NWK_S_IE_OCTET_FIRST;
	do {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_octet_group_extension, tvb, offset, 1, ENC_NA);
		switch(octet_identifier) {
			case DECT_NWK_S_IE_OCTET_FIRST:
				proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1, ett_dect_nwk_s_ie_element,
					profile_indicator_1_flags, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_A:
				proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2, ett_dect_nwk_s_ie_element,
					profile_indicator_2_flags, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_B:
				proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3, ett_dect_nwk_s_ie_element,
					profile_indicator_3_flags, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_C:
				proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4, ett_dect_nwk_s_ie_element,
					profile_indicator_4_flags, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_D:
				proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5, ett_dect_nwk_s_ie_element,
					profile_indicator_5_flags, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_E:
				proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6, ett_dect_nwk_s_ie_element,
					profile_indicator_6_flags, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_F:
				proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7, ett_dect_nwk_s_ie_element,
					profile_indicator_7_flags, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_G:
				proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8, ett_dect_nwk_s_ie_element,
					profile_indicator_8_flags, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_H:
				proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9, ett_dect_nwk_s_ie_element,
					profile_indicator_9_flags, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_I:
				proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10, ett_dect_nwk_s_ie_element,
					profile_indicator_10_flags, ENC_NA);
				break;
		}
		octet_group_extension = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_MASK ) >> DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_SHIFT;
		octet_identifier++;
		offset++;
	} while ( !octet_group_extension );

	octet_identifier = DECT_NWK_S_IE_OCTET_FIRST;
	do {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_octet_group_extension, tvb, offset, 1, ENC_NA);
		switch(octet_identifier) {
			case DECT_NWK_S_IE_OCTET_FIRST:
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_terminal_capability_dsaa2, tvb, offset, 1, ENC_NA);
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_terminal_capability_dsc2, tvb, offset, 1, ENC_NA);
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_terminal_capability_control_codes, tvb, offset, 1, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_A:
				proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1, ett_dect_nwk_s_ie_element,
					escape_to_char_sets_1_flags, ENC_NA);
				break;
		}
		octet_group_extension = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_MASK ) >> DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_SHIFT;
		octet_identifier++;
		offset++;
	} while ( !octet_group_extension );

	/* Octet 6 is not always submitted according to standard */
	if (offset != next_element_offset) {
		octet_identifier = DECT_NWK_S_IE_OCTET_FIRST;
		do {
			proto_tree_add_item(tree, hf_dect_nwk_s_ie_octet_group_extension, tvb, offset, 1, ENC_NA);
			switch(octet_identifier) {
				case DECT_NWK_S_IE_OCTET_FIRST:
					proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_blind_slot_6, ett_dect_nwk_s_ie_element,
						blind_slot_6_flags, ENC_NA);
					break;
				case DECT_NWK_S_IE_OCTET_A:
					proto_tree_add_bitmask(tree, tvb, offset, hf_dect_nwk_s_ie_terminal_capability_blind_slot_6a, ett_dect_nwk_s_ie_element,
						blind_slot_6a_flags, ENC_NA);
					break;
			}
			octet_group_extension = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_MASK ) >> DECT_NWK_S_IE_OCTET_GROUP_EXTENSION_SHIFT;
			octet_identifier++;
			offset++;
		} while ( !octet_group_extension );
	}
	return offset;
}

static int dissect_dect_nwk_s_ie_escape_to_proprietary(tvbuff_t *tvb, unsigned offset, proto_tree *tree, void _U_ *data)
{
	uint8_t discriminator_type;
	proto_tree_add_item(tree, hf_dect_nwk_s_ie_escape_to_proprietary_discriminator_type, tvb, offset, 1, ENC_NA);
	discriminator_type = tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_MASK;
	offset++;
	if (discriminator_type == DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY_DISCRIMINATOR_TYPE_EMC) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_escape_to_proprietary_discriminator, tvb, offset, 2, ENC_NA);
		offset+=2;
	}
	/* FIXME: Content Handling */
	return offset;
}

static int dissect_dect_nwk_s_ie_model_identifier(tvbuff_t *tvb, unsigned offset, uint8_t ie_length, packet_info _U_ *pinfo, proto_tree *tree, void _U_ *data) {
	if ( ie_length == 3) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_model_identifier_manic, tvb, offset, 2, ENC_NA);
		offset += 2;
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_model_identifier_modic, tvb, offset, 1, ENC_NA);
		offset++;
	} else if ( ie_length == 20) {
		proto_tree_add_item(tree, hf_dect_nwk_s_ie_model_identifier_imeisv, tvb, offset, ie_length, ENC_NA);
		offset += ie_length;
	}

	return offset;
}

static int dissect_dect_nwk_s_ie_codec_list(tvbuff_t *tvb, unsigned offset, uint8_t _U_ ie_length, packet_info _U_ *pinfo, proto_tree *tree, void _U_ *data) {
	bool last_codec;
	unsigned octet_identifier;

	proto_tree_add_item(tree, hf_dect_nwk_s_ie_codec_list_negotiation_indicator, tvb, offset, 1, ENC_NA);
	offset++;

	last_codec = false;
	octet_identifier = DECT_NWK_S_IE_OCTET_FIRST;
	do {
		switch(octet_identifier) {
			case DECT_NWK_S_IE_OCTET_FIRST:
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_codec_list_codec_identifier, tvb, offset, 1, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_A:
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_codec_list_mac_and_dlc_service, tvb, offset, 1, ENC_NA);
				break;
			case DECT_NWK_S_IE_OCTET_B:
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_codec_list_last_codec, tvb, offset, 1, ENC_NA);
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_codec_list_c_plane_routing, tvb, offset, 1, ENC_NA);
				proto_tree_add_item(tree, hf_dect_nwk_s_ie_codec_list_slot_size, tvb, offset, 1, ENC_NA);
				last_codec = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_CODEC_LIST_LAST_CODEC_MASK ) >> DECT_NWK_S_IE_CODEC_LIST_LAST_CODEC_SHIFT;
				break;
		}
		octet_identifier = (octet_identifier + 1) % 3;
		offset++;
	} while ( !last_codec );

	return offset;
}

static int dissect_dect_nwk_s_ie(tvbuff_t *tvb, unsigned offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	bool fixed_length;
	uint8_t element_type, element_length, fl_ie_type, fl_ie_double_octet_type;
	proto_tree *field_tree;
	proto_tree *field_tree_item;

	fixed_length = (tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_FIXED_LENGTH_MASK) >> DECT_NWK_S_IE_FIXED_LENGTH_SHIFT;
	if(fixed_length) {
		fl_ie_type = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_FL_TYPE_MASK ) >> DECT_NWK_S_IE_FL_TYPE_SHIFT;
		fl_ie_double_octet_type = ( tvb_get_uint8(tvb, offset) & DECT_NWK_S_IE_FL_DOUBLE_OCTET_TYPE_MASK );
		if ( fl_ie_type == DECT_NWK_S_IE_FL_DOUBLE_OCTET_ELEMENT ) {
			element_length = 2;
			field_tree = proto_tree_add_subtree(tree, tvb, offset, element_length, ett_dect_nwk_s_ie_element, &field_tree_item, "Fixed length Element: ");
			proto_item_append_text(field_tree_item, "%s", val_to_str(fl_ie_double_octet_type, dect_nwk_s_ie_fl_double_octet_type_val, "Unknown: 0x%0x"));
			proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_type, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_double_octet_type, tvb, offset, 1, ENC_NA);
			offset++;
			switch (fl_ie_double_octet_type) {
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_BASIC_SERVICE:
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_basic_service_call_class, tvb, offset, 1, ENC_NA);
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_basic_service_type, tvb, offset, 1, ENC_NA);
					break;
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_RELEASE_REASON:
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_release_reason_code, tvb, offset, 1, ENC_NA);
					break;
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_SIGNAL:
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_signal_value, tvb, offset, 1, ENC_NA);
					break;
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_TIMER_RESTART:
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_timer_restart_value, tvb, offset, 1, ENC_NA);
					break;
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_TEST_HOOK_CONTROL:
					proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_test_hook_control_hook_value, tvb, offset, 1, ENC_NA);
					break;
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_SINGLE_DISPLAY:
					add_dect_nwk_dect_charset_tree_item(field_tree, pinfo, hf_dect_nwk_s_ie_fl_single_display_display_info, tvb, offset, 1);
					break;
				case DECT_NWK_S_IE_FL_DOUBLE_OCTET_SINGLE_KEYPAD:
					add_dect_nwk_dect_charset_tree_item(field_tree, pinfo, hf_dect_nwk_s_ie_fl_single_keypad_keypad_info, tvb, offset, 1);
					break;
			}
		} else {
			element_length = 1;
			field_tree = proto_tree_add_subtree(tree, tvb, offset, element_length, ett_dect_nwk_s_ie_element, &field_tree_item, "Fixed length Element: ");
			proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_type, tvb, offset, 1, ENC_NA);
			if ( fl_ie_type == DECT_NWK_S_IE_FL_CONTROL ) {
				proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_control_type, tvb, offset, 1, ENC_NA);
				proto_item_append_text(field_tree_item, "%s", val_to_str(fl_ie_double_octet_type, dect_nwk_s_ie_fl_control_type_val, "Unknown: 0x%0x"));
			} else {
				proto_item_append_text(field_tree_item, "%s", val_to_str(fl_ie_type, dect_nwk_s_ie_fl_type_val, "Unknown: 0x%0x"));
				switch (fl_ie_type) {
					case DECT_NWK_S_IE_FL_SHIFT:
						proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_shift_locking, tvb, offset, 1, ENC_NA);
						proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_shift_new_codeset, tvb, offset, 1, ENC_NA);
						break;
					case DECT_NWK_S_IE_FL_REPEAT_INDICATOR:
						proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl_repeat_indicator_type, tvb, offset, 1, ENC_NA);
						break;
				}
			}
		}
		offset ++;
	} else {
		element_type = ( tvb_get_uint8(tvb, offset) & 0x7F);
		element_length = tvb_get_uint8(tvb, offset + 1);
		field_tree = proto_tree_add_subtree(tree, tvb, offset, element_length + 2, ett_dect_nwk_s_ie_element, &field_tree_item, "Element: ");
		proto_item_append_text(field_tree_item, "%s", val_to_str(element_type, dect_nwk_s_ie_type_val, "Unknown: 0x%0x"));
		proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_fl, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_type, tvb, offset, 1, ENC_NA);
		offset++;
		proto_tree_add_item(field_tree, hf_dect_nwk_s_ie_length, tvb, offset, 1, ENC_NA);
		offset++;
		switch (element_type) {
			case DECT_NWK_S_IE_AUTH_TYPE:
				offset = dissect_dect_nwk_s_ie_auth_type(tvb, offset, field_tree, data);
				break;
			case DECT_NWK_S_IE_CALLING_PARTY_NUMBER:
				offset = dissect_dect_nwk_s_ie_calling_party_number(tvb, offset, element_length, field_tree, data);
				break;
			case DECT_NWK_S_IE_CIPHER_INFO:
				offset = dissect_dect_nwk_s_ie_cipher_info(tvb, offset, field_tree, data);
				break;
			case DECT_NWK_S_IE_DURATION:
				offset = dissect_dect_nwk_s_ie_duration(tvb, offset, element_length, pinfo, field_tree, data);
				break;
			case DECT_NWK_S_IE_FIXED_IDENTITY:
				offset = dissect_dect_nwk_s_ie_fixed_identity(tvb, offset, field_tree, data);
				break;
			case DECT_NWK_S_IE_IWU_TO_IWU:
				offset = dissect_dect_nwk_s_ie_iwu_to_iwu(tvb, offset, element_length, pinfo, field_tree, data);
				break;
			case DECT_NWK_S_IE_LOCATION_AREA:
				offset = dissect_dect_nwk_s_ie_location_area(tvb, offset, pinfo, field_tree, data);
				break;
			case DECT_NWK_S_IE_MULTI_DISPLAY:
				offset = dissect_dect_nwk_s_ie_multi_display(tvb, offset, element_length, pinfo, field_tree, data);
				break;
			case DECT_NWK_S_IE_MULTI_KEYPAD:
				offset = dissect_dect_nwk_s_ie_multi_keypad(tvb, offset, element_length, pinfo, field_tree, data);
				break;
			case DECT_NWK_S_IE_NWK_ASSIGNED_IDENTITY:
				offset = dissect_dect_nwk_s_ie_nwk_assigned_identity(tvb, offset, field_tree, data);
				break;
			case DECT_NWK_S_IE_PORTABLE_IDENTITY:
				offset = dissect_dect_nwk_s_ie_portable_identity(tvb, offset, field_tree, data);
				break;
			case DECT_NWK_S_IE_RAND:
				proto_tree_add_item(field_tree,hf_dect_nwk_s_ie_rand_rand_field, tvb, offset, element_length, ENC_NA);
				offset += element_length;
				break;
			case DECT_NWK_S_IE_RES:
				proto_tree_add_item(field_tree,hf_dect_nwk_s_ie_res_res_field, tvb, offset, element_length, ENC_NA);
				offset += element_length;
				break;
			case DECT_NWK_S_IE_RS:
				proto_tree_add_item(field_tree,hf_dect_nwk_s_ie_rs_rs_field, tvb, offset, element_length, ENC_NA);
				offset += element_length;
				break;
			case DECT_NWK_S_IE_TERMINAL_CAPABILITY:
				offset = dissect_dect_nwk_s_ie_terminal_capability(tvb, offset, element_length, pinfo, field_tree, data);
				break;
			case DECT_NWK_S_IE_ESCAPE_TO_PROPRIETARY:
				dissect_dect_nwk_s_ie_escape_to_proprietary(tvb, offset, field_tree, data);
				offset += element_length;
				break;
			case DECT_NWK_S_IE_MODEL_IDENTIFIER:
				offset = dissect_dect_nwk_s_ie_model_identifier(tvb, offset, element_length, pinfo, field_tree, data);
				break;
			case DECT_NWK_S_IE_CODEC_LIST:
				offset = dissect_dect_nwk_s_ie_codec_list(tvb, offset, element_length, pinfo, field_tree, data);
				break;
			default:
				offset += element_length;
				break;
		}
	}
	return offset;
}

static int dissect_dect_nwk_lce(tvbuff_t *tvb, uint8_t msg_type, unsigned offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{


	proto_tree_add_item(tree, hf_nwk_msg_type_lce, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(msg_type, nwk_lce_msgt_vals, "Unknown 0x%02x"));
	offset++;

	while(tvb_reported_length_remaining(tvb, offset)) {
		offset = dissect_dect_nwk_s_ie(tvb, offset, pinfo, tree, data);
	}

	/* TOOD: dissection of TLVs/IEs */

	return offset;
}

static int dissect_dect_nwk_cc(tvbuff_t *tvb, uint8_t msg_type, unsigned offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	/* According to Section 7.2 CC also contains CRSS messages */
	if ( msg_type == DECT_NWK_SS_CRSS_HOLD ||
			msg_type == DECT_NWK_SS_CRSS_HOLD_ACK ||
			msg_type == DECT_NWK_SS_CRSS_HOLD_REJ ||
			msg_type == DECT_NWK_SS_CRSS_RETRIEVE ||
			msg_type == DECT_NWK_SS_CRSS_RETRIEVE_ACK ||
			msg_type == DECT_NWK_SS_CRSS_RETRIEVE_REJ ||
			msg_type == DECT_NWK_SS_CISS_FACILITY ) {
		proto_tree_add_item(tree, hf_dect_nwk_message_type_crss, tvb, offset, 1, ENC_NA);
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(msg_type, dect_nwk_crss_message_type_vals, "Unknown 0x%02x"));
	} else {
		proto_tree_add_item(tree, hf_nwk_msg_type_cc, tvb, offset, 1, ENC_NA);
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(msg_type, nwk_cc_msgt_vals, "Unknown 0x%02x"));
	}
	offset++;

	while(tvb_reported_length_remaining(tvb, offset)) {
		offset = dissect_dect_nwk_s_ie(tvb, offset, pinfo, tree, data);
	}

	return offset;
}

static int dissect_dect_nwk_ciss(tvbuff_t *tvb, uint8_t msg_type, unsigned offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	proto_tree_add_item(tree, hf_dect_nwk_message_type_ciss, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(msg_type, dect_nwk_ciss_message_type_vals, "Unknown 0x%02x"));
	offset++;

	while(tvb_reported_length_remaining(tvb, offset)) {
		offset = dissect_dect_nwk_s_ie(tvb, offset, pinfo, tree, data);
	}

	return offset;
}

static int dissect_dect_nwk_coms(tvbuff_t *tvb, uint8_t msg_type, unsigned offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	proto_tree_add_item(tree, hf_dect_nwk_message_type_coms, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(msg_type, dect_nwk_coms_message_type_vals, "Unknown 0x%02x"));
	offset++;

	while(tvb_reported_length_remaining(tvb, offset)) {
		offset = dissect_dect_nwk_s_ie(tvb, offset, pinfo, tree, data);
	}

	return offset;
}


static int dissect_dect_nwk_clms(tvbuff_t *tvb, uint8_t msg_type, unsigned offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	proto_tree_add_item(tree, hf_dect_nwk_message_type_clms, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(msg_type, dect_nwk_clms_message_type_vals, "Unknown 0x%02x"));
	offset++;

	while(tvb_reported_length_remaining(tvb, offset)) {
		offset = dissect_dect_nwk_s_ie(tvb, offset, pinfo, tree, data);
	}

	return offset;
}

static int dissect_dect_nwk_mm(tvbuff_t *tvb, uint8_t msg_type, unsigned offset, packet_info *pinfo, proto_tree *tree, void _U_ *data)
{
	proto_tree_add_item(tree, hf_nwk_msg_type_mm, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(msg_type, nwk_mm_msgt_vals, "Unknown 0x%02x"));
	offset++;

	while(tvb_reported_length_remaining(tvb, offset)) {
		offset = dissect_dect_nwk_s_ie(tvb, offset, pinfo, tree, data);
	}
	/* TOOD: dissection of TLVs/IEs */

	return offset;
}


static int dissect_dect_nwk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	proto_tree *nwk_tree;
	proto_item *nwk_ti;
	uint8_t pdisc, msg_type;
	unsigned len;
	unsigned offset = 0;

	len = tvb_reported_length(tvb);

	col_append_str(pinfo->cinfo, COL_INFO, "(NWK) ");

	nwk_ti = proto_tree_add_item(tree, proto_dect_nwk, tvb, 0, len, ENC_NA);
	nwk_tree = proto_item_add_subtree(nwk_ti, ett_dect_nwk);

	proto_tree_add_item(nwk_tree, hf_nwk_ti, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(nwk_tree, hf_nwk_pdisc, tvb, 0, 1, ENC_NA);
	pdisc = tvb_get_uint8(tvb, 0) & 0x0F;
	msg_type = tvb_get_uint8(tvb, 1);

	switch (pdisc) {
	case DECT_NWK_PDISC_LCE:
		offset = dissect_dect_nwk_lce(tvb, msg_type, 1, pinfo, nwk_tree, data);
		break;
	case DECT_NWK_PDISC_CC:
		offset = dissect_dect_nwk_cc(tvb, msg_type, 1, pinfo, nwk_tree, data);
		break;
	case DECT_NWK_PDISC_MM:
		offset = dissect_dect_nwk_mm(tvb, msg_type, 1, pinfo, nwk_tree, data);
		break;
	case DECT_NWK_PDISC_CISS:
		offset = dissect_dect_nwk_ciss(tvb, msg_type, 1, pinfo, nwk_tree, data);
		break;
	case DECT_NWK_PDISC_CLMS:
		offset = dissect_dect_nwk_clms(tvb, msg_type, 1, pinfo, nwk_tree, data);
		break;
	case DECT_NWK_PDISC_COMS:
		offset = dissect_dect_nwk_coms(tvb, msg_type, 1, pinfo, nwk_tree, data);
		break;
	default:
		break;
	}

	/* whatever was not dissected: Use generic data dissector */
	if ( offset < tvb_captured_length(tvb) ) {
		tvbuff_t *payload = tvb_new_subset_remaining(tvb, offset);
		call_data_dissector(payload, pinfo, tree);
	}
	return tvb_captured_length(tvb);
}

/*
ETSI EN 300 175-6 V2.7.1 Annex C
IPEI will be displayed as EEEEE PPPPPPP C
where:
* EEEEE is the decimal representation of the first 16 bits
* PPPPPPP is the decimal representation of the last 20 bits
* C is calculated based on the digits by multiplying the digit with its position
  (starting with 1 on the leftmost one), and taking the sum of those multiply results
  modulo 11. If the result is 10 a '*' is displayed instead.
*/
static void fmt_dect_nwk_ipei(char *ipei_string, uint64_t ipei) {
	uint16_t emc, check_digit;
	uint32_t psn;
	uint64_t digit_divisor, ipei_digits;

	emc = ( ( ipei & 0xFFFF00000 ) >> 20 ) & 0xFFFF;
	psn = ipei & 0xFFFFF;

	digit_divisor = 100000000000;
	ipei_digits = emc * (uint64_t)10000000 + psn;
	check_digit = 0;
	for(uint8_t i = 1; i <= 12; i++) {
		check_digit += (uint16_t)( ( ipei_digits / digit_divisor ) * i );
		ipei_digits = ipei_digits % digit_divisor;
		digit_divisor /= 10;
	}
	check_digit = check_digit % 11;

	if ( check_digit == 10) {
		snprintf(ipei_string, 16, "%05d %07d *", emc, psn);
	} else {
		snprintf(ipei_string, 16, "%05d %07d %d", emc, psn, check_digit);
	}
}

void proto_register_dect_nwk(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_nwk_ti,
			{ "Transaction Identifier", "dect_nwk.ti", FT_UINT8, BASE_HEX,
				 NULL, 0xF0, NULL, HFILL
			}
		},
		{ &hf_nwk_pdisc,
			{ "Protocol Discriminator", "dect_nwk.pdisc", FT_UINT8, BASE_HEX,
				VALS(nwk_pdisc_vals), 0x0F, NULL, HFILL
			}
		},
		{ &hf_nwk_msg_type_cc,
			{ "Message Type", "dect_nwk.msg_type", FT_UINT8, BASE_HEX,
				VALS(nwk_cc_msgt_vals), 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_message_type_ciss,
			{ "Message Type", "dect_nwk.msg_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_ciss_message_type_vals), 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_message_type_crss,
			{ "Message Type", "dect_nwk.msg_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_crss_message_type_vals), 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_message_type_coms,
			{ "Message Type", "dect_nwk.msg_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_coms_message_type_vals), 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_message_type_clms,
			{ "Message Type", "dect_nwk.msg_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_clms_message_type_vals), 0x0, NULL, HFILL
			}
		},
		{ &hf_nwk_msg_type_mm,
			{ "Message Type", "dect_nwk.msg_type", FT_UINT8, BASE_HEX,
				VALS(nwk_mm_msgt_vals), 0x0, NULL, HFILL
			}
		},
		{ &hf_nwk_msg_type_lce,
			{ "Message Type", "dect_nwk.msg_type", FT_UINT8, BASE_HEX,
				VALS(nwk_lce_msgt_vals), 0x0, NULL, HFILL
			}
		},


		/* S Type common */
		{ &hf_dect_nwk_s_ie_fl,
			{ "Fixed Length", "dect_nwk.s.fixed_length", FT_BOOLEAN, 8,
				NULL, 0x80, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_type,
			{ "Message Type", "dect_nwk.s.ie.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_type_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_length,
			{ "Content Length", "dect_nwk.s.ie.length", FT_UINT8, BASE_DEC,
				NULL, 0x0, "Length indicator", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_octet_group_extension,
			{ "Extension", "dect_nwk.s.ie.group_extension", FT_BOOLEAN, 8,
				TFS(&tfs_last_more), 0x80, NULL, HFILL
			}
		},
		/* Fixed length elements */
		{ &hf_dect_nwk_s_ie_fl_type,
			{ "Message Type", "dect_nwk.s.ie.fl.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_type_val), 0x70, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fl_control_type,
			{ "CTRL Type", "dect_nwk.s.ie.fl.control_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_control_type_val), 0x0F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fl_double_octet_type,
			{ "Double Octet Type", "dect_nwk.s.ie.fl.double_octet_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_double_octet_type_val), 0x0F, NULL, HFILL
			}
		},
		/* Shift */
		{ &hf_dect_nwk_s_ie_fl_shift_locking,
			{ "Shift Procedure", "dect_nwk.s.ie.fl.shift.locking", FT_BOOLEAN, 8,
				TFS(&dect_nwk_s_ie_fl_shift_locking_tfs), 0x08, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fl_shift_new_codeset,
			{ "New Codeset", "dect_nwk.s.ie.fl.shift.new_codeset", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_shift_codeset_val), 0x07, NULL, HFILL
			}
		},
		/* Repeat indicator */
		{ &hf_dect_nwk_s_ie_fl_repeat_indicator_type,
			{ "Indicator Type", "dect_nwk.s.ie.fl.repeat_indicator.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_repeat_indicator_type_val), 0x0F, NULL, HFILL
			}
		},
		/* Basic service */
		{ &hf_dect_nwk_s_ie_fl_basic_service_call_class,
			{ "Call class", "dect_nwk.s.ie.fl.basic_service.call_class", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_basic_service_call_class_val), 0xF0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fl_basic_service_type,
			{ "Basic Service", "dect_nwk.s.ie.fl.basic_service", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_basic_service_type_val), 0x0F, NULL, HFILL
			}
		},
		/* Single display */
		{ &hf_dect_nwk_s_ie_fl_single_display_display_info,
			{ "Display Info", "dect_nwk.s.ie.fl.single_display.display_info", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Single keypad */
		{ &hf_dect_nwk_s_ie_fl_single_keypad_keypad_info,
			{ "Keypad Info", "dect_nwk.s.ie.fl.single_keypad.keypad_info", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Release reason */
		{ &hf_dect_nwk_s_ie_fl_release_reason_code,
			{ "Release Reason Code", "dect_nwk.s.ie.fl.release_reason.code", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_release_reason_val), 0x0, NULL, HFILL
			}
		},
		/* Signal */
		{ &hf_dect_nwk_s_ie_fl_signal_value,
			{ "Signal value", "dect_nwk.s.ie.fl.signal.value", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_signal_value_val), 0x0, NULL, HFILL
			}
		},
		/* Timer restart */
		{ &hf_dect_nwk_s_ie_fl_timer_restart_value,
			{ "Restart value", "dect_nwk.s.ie.fl.timer_restart.restart_value", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_timer_restart_value_val), 0x0, NULL, HFILL
			}
		},
		/* Test hook control */
		{ &hf_dect_nwk_s_ie_fl_test_hook_control_hook_value,
			{ "Hook value", "dect_nwk.s.ie.fl.test_hook_control.hook_value", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fl_test_hook_control_hook_value_val), 0x0, NULL, HFILL
			}
		},
		/* Auth type*/
		{ &hf_dect_nwk_s_ie_auth_type_authentication_algorithm,
			{ "Authentication algorithm", "dect_nwk.s.ie.auth_type.authentication_algorithm", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_auth_type_authentication_algorithm_val), 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_proprietary_algorithm,
			{ "Proprietary algorithm", "dect_nwk.s.ie.auth_type.proprietary_algorithm", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_ak_type,
			{ "AK Type", "dect_nwk.s.ie.auth_type.ak_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_auth_type_ak_type_val), 0xF0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_ak_number,
			{ "AK Number", "dect_nwk.s.ie.auth_type.ak_number", FT_UINT8, BASE_HEX,
				NULL, 0x0F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_inc,
			{ "INC", "dect_nwk.s.ie.auth_type.inc", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), 0x80, "Increment value of the ZAP field", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_def,
			{ "DEF", "dect_nwk.s.ie.auth_type.def", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), 0x40, "Use generated derived cipher key as default cipher key for early encryption", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_txc,
			{ "TXC", "dect_nwk.s.ie.auth_type.tx", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), 0x20, "Include derived cipher key in the AUTHENTICATION-REPLY message", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_upc,
			{ "UPC", "dect_nwk.s.ie.auth_type.upc", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), 0x10, "Store derived cipher key", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_cipher_key_number,
			{ "Cipher key number", "dect_nwk.s.ie.auth_type.cipher_key_number", FT_UINT8, BASE_HEX,
				NULL, 0x0F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_cipher_key_number_related,
			{ "Key related to", "dect_nwk.s.ie.auth_type.key_related_to", FT_BOOLEAN, 8,
				TFS(&dect_nwk_s_ie_auth_type_cipher_key_number_related_tfs), 0x08, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_default_cipher_key_index,
			{ "Default Cipher Key Index", "dect_nwk.s.ie.auth_type.default_cipher_key_index", FT_UINT16, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_auth_type_default_cipher_key_algorithm,
			{ "Default Cipher Key Algorithm", "dect_nwk.s.ie.auth_type.default_cipher_key_algorithm", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_auth_type_default_cipher_key_algorithm_val), 0x03, NULL, HFILL
			}
		},
		/* Calling party number */
		{ &hf_dect_nwk_s_ie_calling_party_number_type,
			{ "Type", "dect_nwk.s.ie.calling_party_number.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_calling_party_number_type_val), 0x70, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_calling_party_number_numbering_plan,
			{ "Numbering plan", "dect_nwk.s.ie.calling_party_number.numbering_plan", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_calling_party_number_numbering_plan_val), 0x0F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_calling_party_number_presentation,
			{ "Presentation", "dect_nwk.s.ie.calling_party_number.presentation", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_calling_party_number_presentation_val), 0x60, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_calling_party_number_screening,
			{ "Screening", "dect_nwk.s.ie.calling_party_number.screening", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_calling_party_number_screening_val), 0x03, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_calling_party_number_address,
			{ "Address", "dect_nwk.s.ie.calling_party_number.address", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Cipher info */
		{ &hf_dect_nwk_s_ie_cipher_info_yn,
			{ "Y/N", "dect_nwk.s.ie.cipher_info.yn", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
		},
		{ &hf_dect_nwk_s_ie_cipher_info_algorithm,
			{ "Algorithm", "dect_nwk.s.ie.cipher_info.algorithm", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_cipher_info_algorithm_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_cipher_info_proprietary_algorithm,
			{ "Proprietary algorithm", "dect_nwk.s.ie.cipher_info.proprietary_algorithm", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_cipher_info_key_type,
			{ "Key Type", "dect_nwk.s.ie.cipher_info.key_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_cipher_info_key_type_val), 0xF0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_cipher_info_key_number,
			{ "Key Number", "dect_nwk.s.ie.cipher_info.key_number", FT_UINT8, BASE_HEX,
				NULL, 0x0F, NULL, HFILL
			}
		},
		/* Duration */
		{ &hf_dect_nwk_s_ie_duration_lock_limits,
			{ "Lock Limits", "dect_nwk.s.ie.duration.lock_limits", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_duration_lock_limits_type_val), 0x70, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_duration_time_limits,
			{ "Time Limits", "dect_nwk.s.ie.duration.time_limits", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_duration_time_limits_type_val), 0x0F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_duration_time_duration,
			{ "Time duration", "dect_nwk.s.ie.duration.time_duration", FT_UINT8, BASE_DEC,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Fixed Identity */
		{ &hf_dect_nwk_s_ie_fixed_identity_type,
			{ "Type", "dect_nwk.s.ie.fixed_identity.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_fixed_identity_type_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fixed_identity_value_length,
			{ "Value Length", "dect_nwk.s.ie.fixed_identity.value_length", FT_UINT8, BASE_DEC,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fixed_identity_arc,
			{ "ARC", "dect_nwk.s.ie.fixed_identity.arc", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_arc_type_val), 0x70, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_fixed_identity_ard,
			{ "ARD", "dect_nwk.s.ie.fixed_identity.ard", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nwk_s_ie_fixed_identity_padding,
			{ "Padding", "dect_nwk.s.ie.fixed_identity.padding", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* IWU to IWU */
		{ &hf_dect_nwk_s_ie_iwu_to_iwu_sr,
			{ "S/R", "dect_nwk.s.ie.iwu_to_iwu.sr", FT_BOOLEAN, 8,
				NULL, 0x40, "Send/Reject", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_iwu_to_iwu_protocol_discriminator,
			{ "Protocol Discriminator", "dect_nwk.s.ie.iwu_to_iwu.protocol_discriminator", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_iwu_to_iwu_protocol_discriminator_type_val), 0x3F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_iwu_to_iwu_information,
			{ "Information", "dect_nwk.s.ie.iwu_to_iwu.information", FT_BYTES, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_iwu_to_iwu_discriminator_type,
			{ "Discriminator Type", "dect_nwk.s.ie.iwu_to_iwu.discriminator_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_iwu_to_iwu_discriminator_type_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_iwu_to_iwu_user_specific_contents,
			{ "User specific contents", "dect_nwk.s.ie.iwu_to_iwu.user_specific_contents", FT_BYTES, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_iwu_to_iwu_emc_discriminator,
			{ "EMC", "dect_nwk.s.ie.iwu_to_iwu.emc_discriminator", FT_UINT16, BASE_HEX,
				NULL, 0x0, "Discriminator (EMC)", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_iwu_to_iwu_proprietary_contents,
			{ "Proprietary", "dect_nwk.s.ie.iwu_to_iwu.proprietary_contents", FT_BYTES, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Location area */
		{ &hf_dect_nwk_s_ie_location_area_li_type,
			{ "LI-Type", "dect_nwk.s.ie.location_area.li_type", FT_UINT8, BASE_HEX,
				NULL, 0xC0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_location_area_li_extended_included,
			{ "Ext. LI included", "dect_nwk.s.ie.location_area.li_extended_included", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), 0x80, "Extended location information is included", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_location_area_la_level_included,
			{ "LA level included", "dect_nwk.s.ie.location_area.la_level_included", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), 0x40, "Location area level is included (LA level field is valid)", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_location_area_la_level,
			{ "Location area level", "dect_nwk.s.ie.location_area.la_level", FT_UINT8, BASE_DEC,
				NULL, 0x3F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_location_area_eli_type,
			{ "ELI-Type", "dect_nwk.s.ie.location_area.eli_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_location_area_eli_type_val), DECT_NWK_S_IE_LOCATION_AREA_ELI_TYPE_MASK, "Extended Location Information type", HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_location_area_lac,
			{ "LAC", "dect_nwk.s.ie.location_area.lac", FT_BYTES, BASE_NONE, NULL, 0x0, "Location Area Code", HFILL }
		},
		{ &hf_dect_nwk_s_ie_location_area_ci,
			{ "CI", "dect_nwk.s.ie.location_area.ci", FT_BYTES, BASE_NONE, NULL, 0x0, "Cell Identity", HFILL }
		},
		/* Multi-display */
		{ &hf_dect_nwk_s_ie_multi_display_information,
			{ "Display Information", "dect_nwk.s.ie.multi_display.information", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Multi-keypad */
		{ &hf_dect_nwk_s_ie_multi_keypad_information,
			{ "Keypad Information", "dect_nwk.s.ie.multi_keypad.information", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* NWK assigend Identity */
		{ &hf_dect_nwk_s_ie_nwk_assigned_identity_type,
			{ "Type", "dect_nwk.s.ie.nwk_assigned_identity.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_nwk_assigned_identity_type_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_nwk_assigned_identity_value_length,
			{ "Value Length", "dect_nwk.s.ie.nwk_assigned_identity.value_length", FT_UINT8, BASE_DEC,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_nwk_assigned_identity_value,
			{ "Value", "dect_nwk.s.ie.nwk_assigned_identity.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nwk_s_ie_nwk_assigned_identity_padding,
			{ "Padding", "dect_nwk.s.ie.nwk_assigned_identity.padding", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Portable Identity */
		{ &hf_dect_nwk_s_ie_portable_identity_type,
			{ "Type", "dect_nwk.s.ie.portable_identity.type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_portable_identity_type_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_portable_identity_value_length,
			{ "Value Length", "dect_nwk.s.ie.portable_identity.value_length", FT_UINT8, BASE_DEC,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_portable_identity_put,
			{ "PUT", "dect_nwk.s.ie.portable_identity.ipui.put", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_ipui_type_val), 0xF0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_portable_identity_ipei,
			{ "IPEI", "dect_nwk.s.ie.portable_identity.ipei", FT_UINT64, BASE_CUSTOM,
				CF_FUNC(&fmt_dect_nwk_ipei), 0x0, NULL, HFILL }
		},
		{ &hf_dect_nwk_s_ie_portable_identity_tpui_assignment_type,
			{ "Assignment Type", "dect_nwk.s.ie.portable_identity.tpui_assignment_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_portable_identity_tpui_assignment_type_val), 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nwk_s_ie_portable_identity_tpui_value,
			{ "TPUI value", "dect_nwk.s.ie.portable_identity.tpui_value", FT_UINT32, BASE_HEX,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nwk_s_ie_portable_identity_ipui_o_number,
			{ "Number", "dect_nwk.s.ie.portable_identity.ipui_o.number", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
		},
		{ &hf_dect_nwk_s_ie_portable_identity_ipui_p_poc,
			{ "POC", "dect_nwk.s.ie.portable_identity.ipui_p.poc", FT_UINT16, BASE_HEX,
				NULL, 0, "Public Operator Code", HFILL }
		},
		{ &hf_dect_nwk_s_ie_portable_identity_ipui_p_acc,
			{ "ACC", "dect_nwk.s.ie.portable_identity.ipui_p.acc", FT_BYTES, BASE_NONE,
			NULL, 0, "ACCount number", HFILL }
		},
		{ &hf_dect_nwk_s_ie_portable_identity_ipui_q_bacn,
			{ "BACN", "dect_nwk.s.ie.portable_identity.ipui_q.bacn", FT_STRING, BASE_NONE,
			NULL, 0, "Bank ACount Number", HFILL }
		},
		{ &hf_dect_nwk_s_ie_portable_identity_ipui_r_imsi,
			{ "IMSI", "dect_nwk.s.ie.portable_identity.ipui_r.imsi", FT_STRING, BASE_NONE,
			NULL, 0, "International Mobile Subscriber Identity", HFILL }
		},
		{ &hf_dect_nwk_s_ie_portable_identity_ipui_s_number,
			{ "Number", "dect_nwk.s.ie.portable_identity.ipui_s.number", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_dect_nwk_s_ie_portable_identity_ipui_t_eic,
			{ "EIC", "dect_nwk.s.ie.portable_identity.ipui_t.eic", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
		},
		{ &hf_dect_nwk_s_ie_portable_identity_ipui_t_number,
			{ "Number", "dect_nwk.s.ie.portable_identity.ipui_t.number", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_dect_nwk_s_ie_portable_identity_ipui_u_cacn,
			{ "CACN", "dect_nwk.s.ie.portable_identity.ipui_u.cacn", FT_STRING, BASE_NONE,
			NULL, 0, "Credit Card ACount Number", HFILL }
		},
		{ &hf_dect_nwk_s_ie_portable_identity_padding,
			{ "Padding", "dect_nwk.s.ie.portable_identity.padding", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* RAND */
		{ &hf_dect_nwk_s_ie_rand_rand_field,
			{ "RAND Field", "dect_nwk.s.ie.rand.rand_field", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* RES */
		{ &hf_dect_nwk_s_ie_res_res_field,
			{ "RES Field", "dect_nwk.s.ie.res.res_field", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* RS */
		{ &hf_dect_nwk_s_ie_rs_rs_field,
			{ "RS Field", "dect_nwk.s.ie.rs.rs_field", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* Terminal capability */
		{ &hf_dect_nwk_s_ie_terminal_capability_tone_capabilities,
			{ "tone capabilities", "dect_nwk.s.ie.terminal_capability.tone_capabilities", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_terminal_capability_tone_capabilites_val), 0x70, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_display_capabilities,
			{ "display capabilities", "dect_nwk.s.ie.terminal_capability.display_capabilities", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_terminal_capability_display_capabilities_val), 0x0F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_echo_parameter,
			{ "echo parameter", "dect_nwk.s.ie.terminal_capability.echo_parameter", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_terminal_capability_echo_parameters_val), 0x70, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_n_rej,
			{ "N-REJ", "dect_nwk.s.ie.terminal_capability.n_rej", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_terminal_capability_n_rej_capabilities_val), 0x0C, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_a_vol,
			{ "A-VOL", "dect_nwk.s.ie.terminal_capability.a_vol", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_terminal_capability_a_vol_capabilities_val), 0x03, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_slot_type_capability,
			{ "slot type capability", "dect_nwk.s.ie.terminal_capability.slot_type_capability", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_slot_type_half_80,
			{ "Half slot; j = 80", "dect_nwk.s.ie.terminal_capability.slot_type.half_80", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SLOT_TYPE_HALF_80, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_slot_type_long_640,
			{ "Long slot; j = 640", "dect_nwk.s.ie.terminal_capability.slot_type.long_640", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SLOT_TYPE_LONG_640, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_slot_type_long_672,
			{ "Long slot; j = 672", "dect_nwk.s.ie.terminal_capability.slot_type.long_672", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SLOT_TYPE_LONG_672, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_slot_type_full,
			{ "Full slot", "dect_nwk.s.ie.terminal_capability.slot_type.full", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SLOT_TYPE_FULL, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_slot_type_double,
			{ "Double slot", "dect_nwk.s.ie.terminal_capability.slot_type.double", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SLOT_TYPE_DOUBLE, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_stored_display_characters,
			{ "Stored display characters", "dect_nwk.s.ie.terminal_capability.stored_display_characters", FT_UINT16, BASE_DEC,
				NULL, 0x3FFF, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_lines_in_display,
			{ "Lines in display", "dect_nwk.s.ie.terminal_capability.lines_in_display", FT_UINT8, BASE_DEC,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_chars_per_line,
			{ "Characters/line", "dect_nwk.s.ie.terminal_capability.chars_per_line", FT_UINT8, BASE_DEC,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_scrolling_behaviour,
			{ "Scrolling behaviour", "dect_nwk.s.ie.terminal_capability.scrolling_behaviour", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_terminal_capability_scrolling_behaviour_type_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1,
			{ "Profile indicator 1", "dect_nwk.s.ie.terminal_capability.profile_indicator_1", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_cap,
			{ "CAP", "dect_nwk.s.ie.terminal_capability.profile_indicator_1.cap", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_CAP, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_gap,
			{ "GAP", "dect_nwk.s.ie.terminal_capability.profile_indicator_1.gap", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_GAP, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_dect_gsm,
			{ "DECT/GSM interworking profile", "dect_nwk.s.ie.terminal_capability.profile_indicator_1.dect_gsm", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_DECT_GSM, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_isdn,
			{ "ISDN End-system", "dect_nwk.s.ie.terminal_capability.profile_indicator_1.isdn", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_ISDN, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_lrms,
			{ "LRMS", "dect_nwk.s.ie.terminal_capability.profile_indicator_1.lrms", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_LRMS, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_dprs_stream,
			{ "DPRS Stream", "dect_nwk.s.ie.terminal_capability.profile_indicator_1.dprs_stream", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_DPRS_STREAM, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_1_dprs_asymmetric,
			{ "DPRS asymmetric bearers", "dect_nwk.s.ie.terminal_capability.profile_indicator_1.dprs_asymmetric", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_1_DPRS_ASYMMETRIC, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2,
			{ "Profile indicator 2", "dect_nwk.s.ie.terminal_capability.profile_indicator_2", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_dprs_class_2,
			{ "DPRS Class 2 management and B-Field procedures", "dect_nwk.s.ie.terminal_capability.profile_indicator_2.dprs_class_2", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_DPRS_CLASS_2, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_data_services,
			{ "Data Services Profile D, Class 2", "dect_nwk.s.ie.terminal_capability.profile_indicator_2.data_services", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_DATA_SERVICES, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_isdn,
			{ "ISDN Intermediate Access Profile", "dect_nwk.s.ie.terminal_capability.profile_indicator_2.isdn", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_ISDN, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_dect_umts_bearer,
			{ "DECT/UMTS-GSM interworking - UMTS-GSM Bearer service", "dect_nwk.s.ie.terminal_capability.profile_indicator_2.dect_umts_bearer", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_DECT_UMTS_BEARER, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_dect_umts_sms,
			{ "DECT/UMTS-GSM interworking - UMTS-GSM SMS service", "dect_nwk.s.ie.terminal_capability.profile_indicator_2.dect_umts_sms", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_DECT_UMTS_SMS, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_dect_umts_facsimile,
			{ "DECT/UMTS-GSM interworking - UMTS-GSM Facsimile", "dect_nwk.s.ie.terminal_capability.profile_indicator_2.dect_umts_facsimile", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_DECT_UMTS_FACSIMILE, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_2_rap,
			{ "RAP 1 Profile", "dect_nwk.s.ie.terminal_capability.profile_indicator_2.rap", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_2_RAP, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3,
			{ "Profile indicator 3", "dect_nwk.s.ie.terminal_capability.profile_indicator_3", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_dect_gsm,
			{ "DECT/GSM dual mode terminal", "dect_nwk.s.ie.terminal_capability.profile_indicator_3.dect_gsm", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_DECT_GSM, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_wrs,
			{ "\"V1\" WRS", "dect_nwk.s.ie.terminal_capability.profile_indicator_3.wrs", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_WRS, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_sms,
			{ "SMS over LRMS", "dect_nwk.s.ie.terminal_capability.profile_indicator_3.sms", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_SMS, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_dmap,
			{ "DMAP", "dect_nwk.s.ie.terminal_capability.profile_indicator_3.dmap", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_DMAP, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_cta,
			{ "Multiport CTA", "dect_nwk.s.ie.terminal_capability.profile_indicator_3.cta", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_CTA, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_ethernet,
			{ "Ethernet", "dect_nwk.s.ie.terminal_capability.profile_indicator_3.ethernet", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_ETHERNET, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_3_token_ring,
			{ "Token Ring", "dect_nwk.s.ie.terminal_capability.profile_indicator_3.token_ring", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_3_TOKEN_RING, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4,
			{ "Profile indicator 4", "dect_nwk.s.ie.terminal_capability.profile_indicator_4", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_ip,
			{ "IP", "dect_nwk.s.ie.terminal_capability.profile_indicator_4.ip", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_IP, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_ppp,
			{ "PPP", "dect_nwk.s.ie.terminal_capability.profile_indicator_4.ppp", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_PPP, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_v24,
			{ "V.24", "dect_nwk.s.ie.terminal_capability.profile_indicator_4.v24", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_V24, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_cf,
			{ "C F", "dect_nwk.s.ie.terminal_capability.profile_indicator_4.cf", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_CF, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_ipq,
			{ "I PQ", "dect_nwk.s.ie.terminal_capability.profile_indicator_4.ipq", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_IPQ, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_rap_2,
			{ "RAP 2 Profile", "dect_nwk.s.ie.terminal_capability.profile_indicator_4.rap_2", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_RAP_2, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_4_dprs,
			{ "Generic Media Encapsulation transport (DPRS)", "dect_nwk.s.ie.terminal_capability.profile_indicator_4.dprs", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_4_DPRS, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5,
			{ "Profile indicator 5", "dect_nwk.s.ie.terminal_capability.profile_indicator_5", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_2bz,
			{ "2-level modulation scheme (B+Z field)", "dect_nwk.s.ie.terminal_capability.profile_indicator_5.mod_2bz", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_2BZ, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_4bz,
			{ "4-level modulation scheme (B+Z field)", "dect_nwk.s.ie.terminal_capability.profile_indicator_5.mod_4bz", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_4BZ, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_8bz,
			{ "8-level modulation scheme (B+Z field)", "dect_nwk.s.ie.terminal_capability.profile_indicator_5.mod_8bz", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_8BZ, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_16bz,
			{ "16-level modulation scheme (B+Z field)", "dect_nwk.s.ie.terminal_capability.profile_indicator_5.mod_16bz", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_16BZ, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_2a,
			{ "2-level modulation scheme (A field)", "dect_nwk.s.ie.terminal_capability.profile_indicator_5.mod_2a", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_2A, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_4a,
			{ "4-level modulation scheme (A field)", "dect_nwk.s.ie.terminal_capability.profile_indicator_5.mod_4a", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_4A, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_5_mod_8a,
			{ "8-level modulation scheme (A field)", "dect_nwk.s.ie.terminal_capability.profile_indicator_5.mod_8a", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_5_MOD_8A, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6,
			{ "Profile indicator 6", "dect_nwk.s.ie.terminal_capability.profile_indicator_6", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_dect_umts,
			{ "DECT/UMTS interworking profile", "dect_nwk.s.ie.terminal_capability.profile_indicator_6.dect_umts", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_DECT_UMTS, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_dect_umts_gprs,
			{ "DECT/UMTS interworking - GPRS services", "dect_nwk.s.ie.terminal_capability.profile_indicator_6.dect_umts_gprs", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_DECT_UMTS_GPRS, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_odap,
			{ "Basic ODAP", "dect_nwk.s.ie.terminal_capability.profile_indicator_6.odap", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_ODAP, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_f_mms,
			{ "F-MMS Interworking profile", "dect_nwk.s.ie.terminal_capability.profile_indicator_6.f_mms", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_F_MMS, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_gf,
			{ "Channel GF", "dect_nwk.s.ie.terminal_capability.profile_indicator_6.gf", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_GF, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_fast_hopping,
			{ "PT with fast hopping radio", "dect_nwk.s.ie.terminal_capability.profile_indicator_6.fast_hopping", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_FAST_HOPPING, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_6_no_emission,
			{ "Capability to support \"no emission\" or U-NEMo mode", "dect_nwk.s.ie.terminal_capability.profile_indicator_6.no_emission", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_6_NO_EMISSION, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7,
			{ "Profile indicator 7", "dect_nwk.s.ie.terminal_capability.profile_indicator_7", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_mod64,
			{ "64-level modulation scheme (B+Z field)", "dect_nwk.s.ie.terminal_capability.profile_indicator_7.mod64", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_MOD64, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_ng_dect_1,
			{ "NG-DECT Part 1: Wideband voice", "dect_nwk.s.ie.terminal_capability.profile_indicator_7.ng_dect_1", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_NG_DECT_1, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_ng_dect_3,
			{ "NG-DECT Part 3", "dect_nwk.s.ie.terminal_capability.profile_indicator_7.ng_dect_3", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_NG_DECT_3, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_headset_management,
			{ "Headset management", "dect_nwk.s.ie.terminal_capability.profile_indicator_7.headset_management", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_HEADSET_MANAGEMENT, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_re_keying,
			{ "Re-keying and default cipher key early encryption mechanism", "dect_nwk.s.ie.terminal_capability.profile_indicator_7.re_keying", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_RE_KEYING, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_associated_melody,
			{ "associated melody per contact", "dect_nwk.s.ie.terminal_capability.profile_indicator_7.associated_melody", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_ASSOCIATED_MELODY, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_7_ng_dect_5,
			{ "NG-DECT Part 5", "dect_nwk.s.ie.terminal_capability.profile_indicator_7.ng_dect_5", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_7_NG_DECT_5, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8,
			{ "Profile indicator 8", "dect_nwk.s.ie.terminal_capability.profile_indicator_8", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8_mux_e_u,
			{ "E+U-type mux and channel I PF basic procedures", "dect_nwk.s.ie.terminal_capability.profile_indicator_8.mux_e_u", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_MUX_E_U, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8_channel_ipf,
			{ "Channel I PF advanced procedures", "dect_nwk.s.ie.terminal_capability.profile_indicator_8.channel_ipf", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_CHANNEL_IPF, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8_channel_sipf,
			{ "Channel SI PF", "dect_nwk.s.ie.terminal_capability.profile_indicator_8.channel_sipf", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_CHANNEL_SIPF, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_8_packet_data_category,
			{ "DPRS/NG-DECT Packet Data Category", "dect_nwk.s.ie.terminal_capability.profile_indicator_8.packet_data_category", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_terminal_capability_profile_indicator_8_packet_data_categories_val),
				DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_8_PACKET_DATA_CATEGORY, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9,
			{ "Profile indicator 9", "dect_nwk.s.ie.terminal_capability.profile_indicator_9", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9_dprs_3,
			{ "DPRS Class 3 management and A-field procedures", "dect_nwk.s.ie.terminal_capability.profile_indicator_9.dprs_3", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_9_DPRS_3, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9_dprs_4,
			{ "DPRS Class 4 management and A-field procedures", "dect_nwk.s.ie.terminal_capability.profile_indicator_9.dprs_4", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_9_DPRS_4, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9_dect_ule,
			{ "DECT ULE", "dect_nwk.s.ie.terminal_capability.profile_indicator_9.dect_ule", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_terminal_capability_profile_indicator_9_dect_ule_versions_val),
				DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_9_DECT_ULE, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_9_light_data,
			{ "Light data services", "dect_nwk.s.ie.terminal_capability.profile_indicator_9.light_data", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_9_LIGHT_DATA, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10,
			{ "Profile indicator 10", "dect_nwk.s.ie.terminal_capability.profile_indicator_10", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_date_time_recovery,
			{ "Date and Time recovery", "dect_nwk.s.ie.terminal_capability.profile_indicator_10.date_time_recovery", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_10_DATE_TIME_RECOVERY, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_extended_list_change,
			{ "Extended list change notification", "dect_nwk.s.ie.terminal_capability.profile_indicator_10.extended_list_change", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_10_EXTENDED_LIST_CHANGE, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_screening,
			{ "Screening", "dect_nwk.s.ie.terminal_capability.profile_indicator_10.screening", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_10_SCREENING, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_wrs_2,
			{ "\"V2\" WRS", "dect_nwk.s.ie.terminal_capability.profile_indicator_10.wrs_2", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_10_WRS_2, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_profile_indicator_10_wrs_ule,
			{ "WRS for ULE", "dect_nwk.s.ie.terminal_capability.profile_indicator_10.wrs_ule", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_PROFILE_INDICATOR_10_WRS_ULE, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_dsaa2,
			{ "DSAA2 supported", "dect_nwk.s.ie.terminal_capability.dsaa2", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), 0x40, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_dsc2,
			{ "DSC2 supported", "dect_nwk.s.ie.terminal_capability.dsc2", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), 0x20, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_control_codes,
			{ "Control Codes", "dect_nwk.s.ie.terminal_capability.control_codes", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_terminal_capability_control_codes_val), 0x07, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1,
			{ "escape to 8 bit character sets_1", "dect_nwk.s.ie.terminal_capability.escape_to_char_sets_1", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1_latin_no1,
			{ "ISO-8859-1", "dect_nwk.s.ie.terminal_capability.escape_to_char_sets_1.latin_no1", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_ESCAPE_TO_CHAR_SETS_1_LATIN_NO1, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1_latin_no9,
			{ "ISO-8859-15", "dect_nwk.s.ie.terminal_capability.escape_to_char_sets_1.latin_no9", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_ESCAPE_TO_CHAR_SETS_1_LATIN_NO9, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1_latin_no5,
			{ "ISO-8859-9", "dect_nwk.s.ie.terminal_capability.escape_to_char_sets_1.latin_no5", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_ESCAPE_TO_CHAR_SETS_1_LATIN_NO5, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_escape_to_char_sets_1_greek,
			{ "ISO-8859-7", "dect_nwk.s.ie.terminal_capability.escape_to_char_sets_1.greek", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_ESCAPE_TO_CHAR_SETS_1_GREEK, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_blind_slot_6,
			{ "Blind Slot Octet 6", "dect_nwk.s.ie.terminal_capability.blind_slot_6", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_blind_slot_indication,
			{ "Blind slot indication", "dect_nwk.s.ie.terminal_capability.blind_slot_indication", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_terminal_capability_blind_slot_indication_val), 0x60, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_sp0,
			{ "SP0", "dect_nwk.s.ie.terminal_capability.sp0", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_sp1,
			{ "SP1", "dect_nwk.s.ie.terminal_capability.sp1", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP1, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_sp2,
			{ "SP2", "dect_nwk.s.ie.terminal_capability.sp2", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP2, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_sp3,
			{ "SP3", "dect_nwk.s.ie.terminal_capability.sp3", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP3, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_sp4,
			{ "SP4", "dect_nwk.s.ie.terminal_capability.sp4", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP4, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_blind_slot_6a,
			{ "Blind Slot Octet 6a", "dect_nwk.s.ie.terminal_capability.blind_slot_6a", FT_UINT8, BASE_HEX,
				NULL, 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_sp5,
			{ "SP5", "dect_nwk.s.ie.terminal_capability.sp5", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP5, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_sp6,
			{ "SP6", "dect_nwk.s.ie.terminal_capability.sp6", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP6, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_sp7,
			{ "SP7", "dect_nwk.s.ie.terminal_capability.sp7", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP7, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_sp8,
			{ "SP8", "dect_nwk.s.ie.terminal_capability.sp8", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP8, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_sp9,
			{ "SP9", "dect_nwk.s.ie.terminal_capability.sp9", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP9, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_sp10,
			{ "SP10", "dect_nwk.s.ie.terminal_capability.sp10", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP10, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_terminal_capability_sp11,
			{ "SP11", "dect_nwk.s.ie.terminal_capability.sp11", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_NWK_S_IE_TERMINAL_CAPABILITY_SP11, NULL, HFILL
			}
		},
		/* Escape to proprietary */
		{ &hf_dect_nwk_s_ie_escape_to_proprietary_discriminator_type,
			{ "Discriminator type", "dect_nwk.s.ie.escape_to_proprietary.discriminator_type", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_escape_to_proprietary_discriminator_type_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_escape_to_proprietary_discriminator,
			{ "Discriminator", "dect_nwk.s.ie.escape_to_proprietary.discriminator", FT_UINT16, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Model identifier */
		{ &hf_dect_nwk_s_ie_model_identifier_manic,
			{ "MANIC", "dect_nwk.s.ie.model_identifier.manic", FT_BYTES, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_model_identifier_modic,
			{ "MODIC", "dect_nwk.s.ie.model_identifier.modic", FT_UINT8, BASE_DEC,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_model_identifier_imeisv,
			{ "EIMEISV", "dect_nwk.s.ie.model_identifier.imeisv", FT_BYTES, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* Codec list */
		{ &hf_dect_nwk_s_ie_codec_list_negotiation_indicator,
			{ "Negotiation indicator", "dect_nwk.s.ie.codec_list.negotiation_indicator", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_codec_list_negotiation_indicator_type_val), 0x70, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_codec_list_codec_identifier,
			{ "Codec identifier", "dect_nwk.s.ie.codec_list.codec_identifier", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_codec_list_codec_identifier_type_val), 0x7F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_codec_list_mac_and_dlc_service,
			{ "MAC and DLC service", "dect_nwk.s.ie.codec_list.mac_and_dlc_service", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_codec_list_mac_and_dlc_service_type_val), 0x0F, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_codec_list_last_codec,
			{ "Last codec", "dect_nwk.s.ie.codec_list.last_codec", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), 0x80, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_codec_list_c_plane_routing,
			{ "C-plane routing", "dect_nwk.s.ie.codec_list.c_plane_routing", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_codec_list_c_plane_routing_type_val), 0x70, NULL, HFILL
			}
		},
		{ &hf_dect_nwk_s_ie_codec_list_slot_size,
			{ "Slot size", "dect_nwk.s.ie.codec_list.slot_size", FT_UINT8, BASE_HEX,
				VALS(dect_nwk_s_ie_codec_list_slot_size_type_val), 0x0F, NULL, HFILL
			}
		},
	};

	static int *ett[] = {
		&ett_dect_nwk,
		&ett_dect_nwk_s_ie_element,
		&ett_dect_nwk_s_ie_location_area_li_type
	};

	/* Register protocol */
	proto_dect_nwk = proto_register_protocol("DECT NWK", "DECT-NWK", "dect_nwk");

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_dect_nwk, hf, array_length(hf));

	dect_nwk_handle = register_dissector("dect_nwk", dissect_dect_nwk, proto_dect_nwk);
}

void proto_reg_handoff_dect_nwk(void)
{
	dissector_add_uint("dect_dlc.sapi", 0, dect_nwk_handle);
	dissector_add_uint("dect_dlc.sapi", 3, dect_nwk_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
