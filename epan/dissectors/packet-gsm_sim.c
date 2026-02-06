/* packet-gsm_sim.c
 * Routines for packet dissection of GSM SIM APDUs (GSM TS 11.11)
 *
 *	GSM TS 11.11 / 3GPP TS 51.011
 * 	3GPP TS 31.102
 * Copyright 2010-2011 by Harald Welte <laforge@gnumonks.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>

#include <wiretap/wtap.h>

#include "packet-gsmtap.h"
#include "packet-sgp32.h"

void proto_register_gsm_sim(void);
void proto_reg_handoff_gsm_sim(void);

static int proto_gsm_sim;

/* ISO 7816-4 APDU */
static int hf_apdu_cla_coding;
static int hf_apdu_cla_coding_ext;
static int hf_apdu_cla_secure_messaging_ind;
static int hf_apdu_cla_secure_messaging_ind_ext;
static int hf_apdu_cla_log_chan;
static int hf_apdu_cla_log_chan_ext;
static int hf_apdu_ins;
static int hf_apdu_p1;
static int hf_apdu_p2;
static int hf_apdu_p3;
static int hf_apdu_lc;
static int hf_apdu_lc_ext;
static int hf_apdu_le;
static int hf_apdu_le_ext;
static int hf_apdu_data;
static int hf_apdu_sw;
static int hf_apdu_unknown;

static int hf_file_id;
static int hf_aid;
static int hf_bin_offset;
static int hf_referencing;
static int hf_sfi;
static int hf_record_nr;
static int hf_record_id;
static int hf_record_file;
static int hf_record_mode;
static int hf_auth_rand_len;
static int hf_auth_rand;
static int hf_auth_autn_len;
static int hf_auth_autn;
static int hf_auth_reference;
static int hf_auth_rfu;
static int hf_auth_context;
static int hf_auth_challenge;
static int hf_auth_response;
static int hf_auth_status;
static int hf_auth_res_len;
static int hf_auth_res;
static int hf_auth_ck_len;
static int hf_auth_ck;
static int hf_auth_ik_len;
static int hf_auth_ik;
static int hf_auth_kc_len;
static int hf_auth_kc;
static int hf_auth_auts_len;
static int hf_auth_auts;
static int hf_auth_gsm_rand;
static int hf_auth_gsm_sres_len;
static int hf_auth_gsm_sres;
static int hf_auth_gsm_kc_len;
static int hf_auth_gsm_kc;
static int hf_chan_op;
static int hf_chan_nr;

static int hf_select_type;
static int hf_select_session_control;
static int hf_select_unused_p2;
static int hf_select_return_data;
static int hf_select_selection;

static int hf_status_application_status;
static int hf_status_return_data;

static int hf_search_ef_identifier;
static int hf_search_mode;
static int hf_search_enhanced_type;
static int hf_search_enhanced_mode;
static int hf_search_enhanced_offset;
static int hf_search_enhanced_value;

static int hf_suspend_uicc_op;
static int hf_suspend_uicc_min_time_unit;
static int hf_suspend_uicc_min_time_length;
static int hf_suspend_uicc_max_time_unit;
static int hf_suspend_uicc_max_time_length;
static int hf_suspend_uicc_resume_token;

static int hf_store_data_block;
static int hf_store_data_encryption;
static int hf_store_data_structure;
static int hf_store_data_rfu;
static int hf_store_data_iso_case;
static int hf_store_data_block_nr;

/* Chapter 5.2 TS 11.14 and TS 31.111 */
static int hf_tprof_b1;
static int hf_tprof_b2;
static int hf_tprof_b3;
static int hf_tprof_b4;
static int hf_tprof_b5;
static int hf_tprof_b6;
static int hf_tprof_b7;
static int hf_tprof_b8;
static int hf_tprof_b9;
static int hf_tprof_b10;
static int hf_tprof_b11;
static int hf_tprof_b12;
static int hf_tprof_b13;
static int hf_tprof_b14;
static int hf_tprof_b15;
static int hf_tprof_b16;
static int hf_tprof_b17;
static int hf_tprof_b18;
static int hf_tprof_b19;
static int hf_tprof_b20;
static int hf_tprof_b21;
static int hf_tprof_b22;
static int hf_tprof_b23;
static int hf_tprof_b24;
static int hf_tprof_b25;
static int hf_tprof_b26;
static int hf_tprof_b27;
static int hf_tprof_b28;
static int hf_tprof_b29;
static int hf_tprof_b30;
static int hf_tprof_b31;
static int hf_tprof_b32;
static int hf_tprof_b33;
static int hf_tprof_b34;
static int hf_tprof_b35;
static int hf_tprof_b36;
static int hf_tprof_b37;
static int hf_tprof_b38;
static int hf_tprof_b39;
static int hf_tprof_unknown_byte;
/* First byte */
static int hf_tp_prof_dld;
static int hf_tp_sms_data_dld;
static int hf_tp_cb_data_dld;
static int hf_tp_menu_sel;
static int hf_tp_sms_data_dld_support;
static int hf_tp_timer_exp;
static int hf_tp_cc_sim_support;
static int hf_tp_cc_sim_support2;
/* Second byte (Other) */
static int hf_tp_cmd_res;
static int hf_tp_cc_sim;
static int hf_tp_cc_sim_support3;
static int hf_tp_mo_sms_sim;
static int hf_tp_cc_sim_support4;
static int hf_tp_ucs2_entry;
static int hf_tp_ucs2_display;
static int hf_tp_display_ext;
/* 3rd byte (Proactive SIM) */
static int hf_tp_pa_display_text;
static int hf_tp_pa_get_inkey;
static int hf_tp_pa_get_input;
static int hf_tp_pa_more_time;
static int hf_tp_pa_play_tone;
static int hf_tp_pa_poll_intv;
static int hf_tp_pa_polling_off;
static int hf_tp_pa_refresh;
/* 4th byte (Proactive SIM) */
static int hf_tp_pa_select_item;
static int hf_tp_pa_send_sms;
static int hf_tp_pa_send_ss;
static int hf_tp_pa_send_ussd;
static int hf_tp_pa_set_up_call;
static int hf_tp_pa_set_up_menu;
static int hf_tp_pa_prov_loci;
static int hf_tp_pa_prov_loci_nmr;
/* 5th byte (Event drive information) */
static int hf_tp_pa_evt_list;
static int hf_tp_ev_mt_call;
static int hf_tp_ev_call_connected;
static int hf_tp_ev_call_disconnected;
static int hf_tp_ev_location_status;
static int hf_tp_ev_user_activity;
static int hf_tp_ev_idle_screen;
static int hf_tp_ev_cardreader_status;
/* 6th byte (Event drive information extension) */
static int hf_tp_ev_lang_sel;
static int hf_tp_ev_brows_term;
static int hf_tp_ev_data_avail;
static int hf_tp_ev_chan_status;
static int hf_tp_ev_access_techno_change;
static int hf_tp_ev_disp_params_changed;
static int hf_tp_ev_local_conn;
static int hf_tp_ev_nwk_search_mode_change;
/* 7th byte (Multiple card proactive commands) */
static int hf_tp_pa_power_on;
static int hf_tp_pa_power_off;
static int hf_tp_pa_perform_card_apdu;
static int hf_tp_pa_get_reader_status;
static int hf_tp_pa_get_reader_status_id;
static int hf_tp_rfu;
/* 8th byte (Proactive SIM) */
static int hf_tp_pa_timer_start_stop;
static int hf_tp_pa_timer_get_current;
static int hf_tp_pa_prov_loci_date_tz;
static int hf_tp_pa_get_inkey_binary;
static int hf_tp_pa_set_up_idle_mode_text;
static int hf_tp_pa_run_at_command;
static int hf_tp_pa_2nd_alpha_setup_call;
static int hf_tp_pa_2nd_cc_sim_support;
/* 9th byte */
static int hf_tp_display_text;
static int hf_tp_send_dtmf_cmd;
static int hf_tp_pa_prov_loci_nmr2;
static int hf_tp_pa_prov_loci_lang;
static int hf_tp_pa_prov_loci_ta;
static int hf_tp_pa_lang_notif;
static int hf_tp_pa_launch_browser;
static int hf_tp_pa_prov_loci_access_techno;
/* 10th byte */
static int hf_tp_soft_key_support_select_item;
static int hf_tp_soft_key_support_set_up_menu;
static int hf_tp_rfu2;
/* 11th byte */
static int hf_tp_soft_key_info_max_nb;
/* 12th byte (Proactive SIM) */
static int hf_tp_pa_open_chan;
static int hf_tp_pa_close_chan;
static int hf_tp_pa_recv_data;
static int hf_tp_pa_send_data;
static int hf_tp_pa_get_chan_status;
static int hf_tp_pa_serv_search;
static int hf_tp_pa_get_serv_info;
static int hf_tp_pa_decl_serv;
/* 13th byte (Proactive SIM) */
static int hf_tp_bip_csd;
static int hf_tp_bip_gprs;
static int hf_tp_bip_bluetooth;
static int hf_tp_bip_irda;
static int hf_tp_bip_rs232;
static int hf_tp_num_chans;
/* 14th byte (Screen height) */
static int hf_tp_char_height;
static int hf_tp_nd;
static int hf_tp_nk;
static int hf_tp_sizing_supp;
/* 15th byte (Screen width) */
static int hf_tp_char_width;
static int hf_tp_var_fonts;
/* 16th byte (Screen effects) */
static int hf_tp_display_resize;
static int hf_tp_text_wrapping;
static int hf_tp_text_scrolling;
static int hf_tp_text_attributes;
static int hf_tp_rfu3;
static int hf_tp_width_red_menu;
/* 17th byte (Proactive SIM) */
static int hf_tp_bip_tcp_remote;
static int hf_tp_bip_udp_remote;
static int hf_tp_bip_tcp_server;
static int hf_tp_bip_tcp_local;
static int hf_tp_bip_udp_local;
static int hf_tp_bip_direct_com;
static int hf_tp_bip_eutran;
static int hf_tp_bip_hsdpa;
/* 18th byte */
static int hf_tp_pa_display_text_var_time_out;
static int hf_tp_pa_get_inkey_help;
static int hf_tp_bip_usb;
static int hf_tp_pa_get_inkey_var_time_out;
static int hf_tp_pa_prov_loci_esn;
static int hf_tp_cc_gprs;
static int hf_tp_pa_prov_loci_imeisv;
static int hf_tp_pa_prov_loci_search_mode_change;
/* 19th byte (TIA/EIA-136) */
static int hf_tp_tia_eia_version;
static int hf_tp_rfu4;
/* 20th byte (TIA/EIA/IS-820-A) */
static int hf_tp_tia_iea_is820a_reserved;
/* 21th byte (Extended Launch Browser Capability) */
static int hf_tp_ext_launch_browser_wml;
static int hf_tp_ext_launch_browser_xhtml;
static int hf_tp_ext_launch_browser_html;
static int hf_tp_ext_launch_browser_chtml;
static int hf_tp_rfu5;
/* 22th byte */
static int hf_tp_utran_ps_ext_params;
static int hf_tp_pa_prov_loci_batt_state;
static int hf_tp_pa_play_tone_melody;
static int hf_tp_mm_call_set_up_call;
static int hf_tp_toolkit_initiated_gba;
static int hf_tp_pa_retrieve_mm_msg;
static int hf_tp_pa_submit_mm_msg;
static int hf_tp_pa_display_mm_msg;
/* 23th byte */
static int hf_tp_pa_set_frames;
static int hf_tp_pa_get_frames_status;
static int hf_tp_mms_notif_download;
static int hf_tp_alpha_id_refresh_cmd;
static int hf_tp_geo_loc_report;
static int hf_tp_pa_prov_loci_meid;
static int hf_tp_pa_prov_loci_nmr_utran_eutran;
static int hf_tp_ussd_data_download;
/* 24th byte (Class "i") */
static int hf_tp_class_i_max_nb_frames;
static int hf_tp_rfu6;
/* 25th byte (Event driven information extensions) */
static int hf_tp_evt_browsing_status;
static int hf_tp_evt_mms_transfer_status;
static int hf_tp_evt_frame_info_changed;
static int hf_tp_evt_iwlan_access_status;
static int hf_tp_evt_nw_reject_geran_utran;
static int hf_tp_evt_hci_connectivity;
static int hf_tp_evt_nw_reject_eutran;
static int hf_tp_evt_mult_access_techno_change;
/* 26th byte (Event driven information extensions) */
static int hf_tp_evt_csg_cell_select;
static int hf_tp_evt_contactless_state_req;
static int hf_tp_rfu7;
/* 27th byte (Event driven information extensions) */
static int hf_tp_rfu8;
/* 28th byte (Text attributes) */
static int hf_tp_text_align_left;
static int hf_tp_text_align_centre;
static int hf_tp_text_align_right;
static int hf_tp_text_font_size_normal;
static int hf_tp_text_font_size_large;
static int hf_tp_text_font_size_small;
static int hf_tp_rfu9;
/* 29th byte (Text attributes) */
static int hf_tp_text_style_normal;
static int hf_tp_text_style_bold;
static int hf_tp_text_style_italic;
static int hf_tp_text_style_underlined;
static int hf_tp_text_style_strikethrough;
static int hf_tp_text_style_text_fg_colour;
static int hf_tp_text_style_text_bg_colour;
static int hf_tp_rfu10;
/* 30th byte */
static int hf_tp_bip_iwlan;
static int hf_tp_pa_prov_loci_wsid;
static int hf_tp_term_app;
static int hf_tp_steering_roaming_refresh;
static int hf_tp_pa_activate;
static int hf_tp_pa_geo_loc_req;
static int hf_tp_pa_prov_loci_broadcast_nw_info;
static int hf_tp_steering_roaming_iwlan_refresh;
/* 31th byte */
static int hf_tp_pa_contactless_state_changed;
static int hf_tp_csg_cell_discovery;
static int hf_tp_cnf_params_support_open_chan_server_mode;
static int hf_tp_com_ctrl_ims;
static int hf_tp_cat_over_modem_itf;
static int hf_tp_evt_incoming_data_ims;
static int hf_tp_evt_ims_registration;
static int hf_tp_pa_prof_env_cont;
/* 32th byte */
static int hf_tp_bip_ims;
static int hf_tp_pa_prov_loci_henb_ip_addr;
static int hf_tp_pa_prov_loci_henb_surround_macro;
static int hf_tp_launch_params_support_open_chan_server_mode;
static int hf_tp_direct_com_support_open_chan_server_mode;
static int hf_tp_pa_sec_prof_env_cont;
static int hf_tp_cat_serv_list_ecat_client;
static int hf_tp_support_refresh_enforcement_policy;
/* 33th byte */
static int hf_tp_support_dns_addr_req;
static int hf_tp_support_nw_access_name_reuse;
static int hf_tp_ev_poll_intv_nego;
static int hf_tp_prose_usage_info_reporting;
static int hf_tp_pa_prov_loci_rat;
static int hf_tp_evt_wlan_access_status;
static int hf_tp_wlan_bearer;
static int hf_tp_pa_prov_loci_wlan_id;
/* 34th byte */
static int hf_tp_uri_send_short_msg;
static int hf_tp_ims_uri_setup_call;
static int hf_tp_media_type_voice_setup_call;
static int hf_tp_media_type_video_setup_call;
static int hf_tp_pa_prov_loci_eutran_timing_advance_info;
static int hf_tp_refresh_euicc_profile_state_change;
static int hf_tp_ext_rej_cause_code_nw_reject_eutran;
static int hf_tp_deprecated_b34;
/* 35th byte */
static int hf_tp_pa_get_input_var_timeout;
static int hf_tp_data_conn_status_change_pdp;
static int hf_tp_data_conn_status_change_pdn;
static int hf_tp_refresh_app_update;
static int hf_tp_pa_lsi_proactive_session_request;
static int hf_tp_pa_lsi_uicc_platform_reset;
static int hf_tp_rfu11;
/* 36th byte */
static int hf_tp_data_conn_status_change_pdu;
static int hf_tp_evt_nw_reject_ng_ran;
static int hf_tp_non_ip_data_delivery;
static int hf_tp_prov_loci_slice_info;
static int hf_tp_refresh_sor_cmci_param;
static int hf_tp_evt_nw_reject_satellite_ng_ran;
static int hf_tp_cag_feature;
static int hf_tp_evt_slices_status_change;
/* 37th byte */
static int hf_tp_prov_loci_rejected_slice_info;
static int hf_tp_ext_info_pli;
static int hf_tp_chaining_pli_env_cmds;
static int hf_tp_5g_prose_usage_info_reporting;
static int hf_tp_rfu12;
/* 38th byte */
static int hf_tp_rfu13;
/* 39th byte */
static int hf_tp_pa_prov_loci_ng_ran_satellite_timing_advance_info;
static int hf_tp_rfu14;

static int hf_cat_ber_tag;

static int hf_related_to;
static int hf_response_in;
static int hf_response_to;
static int hf_response_time;

static int ett_sim;
static int ett_tprof_b1;
static int ett_tprof_b2;
static int ett_tprof_b3;
static int ett_tprof_b4;
static int ett_tprof_b5;
static int ett_tprof_b6;
static int ett_tprof_b7;
static int ett_tprof_b8;
static int ett_tprof_b9;
static int ett_tprof_b10;
static int ett_tprof_b11;
static int ett_tprof_b12;
static int ett_tprof_b13;
static int ett_tprof_b14;
static int ett_tprof_b15;
static int ett_tprof_b16;
static int ett_tprof_b17;
static int ett_tprof_b18;
static int ett_tprof_b19;
static int ett_tprof_b20;
static int ett_tprof_b21;
static int ett_tprof_b22;
static int ett_tprof_b23;
static int ett_tprof_b24;
static int ett_tprof_b25;
static int ett_tprof_b26;
static int ett_tprof_b27;
static int ett_tprof_b28;
static int ett_tprof_b29;
static int ett_tprof_b30;
static int ett_tprof_b31;
static int ett_tprof_b32;
static int ett_tprof_b33;
static int ett_tprof_b34;
static int ett_tprof_b35;
static int ett_tprof_b36;
static int ett_tprof_b37;
static int ett_tprof_b38;
static int ett_tprof_b39;
static int ett_auth_challenge;
static int ett_auth_response;

static expert_field ei_unknown_bytes;

static dissector_handle_t sub_handle_cap;
static dissector_handle_t sim_handle, sim_part_handle;

/* The response contains no channel number to compare to and the spec explicitly
 * prohibits interleaving of command/response pairs, regardless of logical channels.
 */
typedef struct gsm_sim_transaction {
	uint32_t cmd_frame;
	uint32_t rsp_frame;
	nstime_t cmd_time;
	uint8_t  cmd_ins;
	uint8_t  cmd_p1;
	uint8_t  cmd_p2;

	/* Related transaction used for GET RESPONSE and APDU reassembly. May point to self. */
	struct gsm_sim_transaction *related_trans;
} gsm_sim_transaction_t;

static wmem_tree_t *transactions;
static reassembly_table gsm_sim_reassembly_table;

static int hf_gsm_sim_fragments;
static int hf_gsm_sim_fragment;
static int hf_gsm_sim_fragment_overlap;
static int hf_gsm_sim_fragment_overlap_conflicts;
static int hf_gsm_sim_fragment_multiple_tails;
static int hf_gsm_sim_fragment_too_long_fragment;
static int hf_gsm_sim_fragment_error;
static int hf_gsm_sim_fragment_count;
static int hf_gsm_sim_reassembled_in;
static int hf_gsm_sim_reassembled_length;

static int ett_gsm_sim_fragment;
static int ett_gsm_sim_fragments;

static const fragment_items gsm_sim_frag_items = {
	/* Fragment subtrees */
	&ett_gsm_sim_fragment,
	&ett_gsm_sim_fragments,
	/* Fragment fields */
	&hf_gsm_sim_fragments,
	&hf_gsm_sim_fragment,
	&hf_gsm_sim_fragment_overlap,
	&hf_gsm_sim_fragment_overlap_conflicts,
	&hf_gsm_sim_fragment_multiple_tails,
	&hf_gsm_sim_fragment_too_long_fragment,
	&hf_gsm_sim_fragment_error,
	&hf_gsm_sim_fragment_count,
	/* Reassembled in field */
	&hf_gsm_sim_reassembled_in,
	/* Reassembled length field */
	&hf_gsm_sim_reassembled_length,
	/* Reassembled data field */
	NULL,
	/* Tag */
	"APDU fragments"
};

static int * const tprof_b1_fields[] = {
	&hf_tp_prof_dld,
	&hf_tp_sms_data_dld,
	&hf_tp_cb_data_dld,
	&hf_tp_menu_sel,
	&hf_tp_sms_data_dld_support,
	&hf_tp_timer_exp,
	&hf_tp_cc_sim_support,
	&hf_tp_cc_sim_support2,
	NULL
};

static int * const tprof_b2_fields[] = {
	&hf_tp_cmd_res,
	&hf_tp_cc_sim,
	&hf_tp_cc_sim_support3,
	&hf_tp_mo_sms_sim,
	&hf_tp_cc_sim_support4,
	&hf_tp_ucs2_entry,
	&hf_tp_ucs2_display,
	&hf_tp_display_ext,
	NULL
};

static int * const tprof_b3_fields[] = {
	&hf_tp_pa_display_text,
	&hf_tp_pa_get_inkey,
	&hf_tp_pa_get_input,
	&hf_tp_pa_more_time,
	&hf_tp_pa_play_tone,
	&hf_tp_pa_poll_intv,
	&hf_tp_pa_polling_off,
	&hf_tp_pa_refresh,
	NULL
};

static int * const tprof_b4_fields[] = {
	&hf_tp_pa_select_item,
	&hf_tp_pa_send_sms,
	&hf_tp_pa_send_ss,
	&hf_tp_pa_send_ussd,
	&hf_tp_pa_set_up_call,
	&hf_tp_pa_set_up_menu,
	&hf_tp_pa_prov_loci,
	&hf_tp_pa_prov_loci_nmr,
	NULL
};

static int * const tprof_b5_fields[] = {
	&hf_tp_pa_evt_list,
	&hf_tp_ev_mt_call,
	&hf_tp_ev_call_connected,
	&hf_tp_ev_call_disconnected,
	&hf_tp_ev_location_status,
	&hf_tp_ev_user_activity,
	&hf_tp_ev_idle_screen,
	&hf_tp_ev_cardreader_status,
	NULL
};

static int * const tprof_b6_fields[] = {
	&hf_tp_ev_lang_sel,
	&hf_tp_ev_brows_term,
	&hf_tp_ev_data_avail,
	&hf_tp_ev_chan_status,
	&hf_tp_ev_access_techno_change,
	&hf_tp_ev_disp_params_changed,
	&hf_tp_ev_local_conn,
	&hf_tp_ev_nwk_search_mode_change,
	NULL
};

static int * const tprof_b7_fields[] = {
	&hf_tp_pa_power_on,
	&hf_tp_pa_power_off,
	&hf_tp_pa_perform_card_apdu,
	&hf_tp_pa_get_reader_status,
	&hf_tp_pa_get_reader_status_id,
	&hf_tp_rfu,
	NULL
};

static int * const tprof_b8_fields[] = {
	&hf_tp_pa_timer_start_stop,
	&hf_tp_pa_timer_get_current,
	&hf_tp_pa_prov_loci_date_tz,
	&hf_tp_pa_get_inkey_binary,
	&hf_tp_pa_set_up_idle_mode_text,
	&hf_tp_pa_run_at_command,
	&hf_tp_pa_2nd_alpha_setup_call,
	&hf_tp_pa_2nd_cc_sim_support,
	NULL
};

static int * const tprof_b9_fields[] = {
	&hf_tp_display_text,
	&hf_tp_send_dtmf_cmd,
	&hf_tp_pa_prov_loci_nmr2,
	&hf_tp_pa_prov_loci_lang,
	&hf_tp_pa_prov_loci_ta,
	&hf_tp_pa_lang_notif,
	&hf_tp_pa_launch_browser,
	&hf_tp_pa_prov_loci_access_techno,
	NULL
};

static int * const tprof_b10_fields[] = {
	&hf_tp_soft_key_support_select_item,
	&hf_tp_soft_key_support_set_up_menu,
	&hf_tp_rfu2,
	NULL
};

static int * const tprof_b11_fields[] = {
	&hf_tp_soft_key_info_max_nb,
	NULL
};

static int * const tprof_b12_fields[] = {
	&hf_tp_pa_open_chan,
	&hf_tp_pa_close_chan,
	&hf_tp_pa_recv_data,
	&hf_tp_pa_send_data,
	&hf_tp_pa_get_chan_status,
	&hf_tp_pa_serv_search,
	&hf_tp_pa_get_serv_info,
	&hf_tp_pa_decl_serv,
	NULL
};

static int * const tprof_b13_fields[] = {
	&hf_tp_bip_csd,
	&hf_tp_bip_gprs,
	&hf_tp_bip_bluetooth,
	&hf_tp_bip_irda,
	&hf_tp_bip_rs232,
	&hf_tp_num_chans,
	NULL
};

static int * const tprof_b14_fields[] = {
	&hf_tp_char_height,
	&hf_tp_nd,
	&hf_tp_nk,
	&hf_tp_sizing_supp,
	NULL
};

static int * const tprof_b15_fields[] = {
	&hf_tp_char_width,
	&hf_tp_var_fonts,
	NULL
};

static int * const tprof_b16_fields[] = {
	&hf_tp_display_resize,
	&hf_tp_text_wrapping,
	&hf_tp_text_scrolling,
	&hf_tp_text_attributes,
	&hf_tp_rfu3,
	&hf_tp_width_red_menu,
	NULL
};
static int * const tprof_b17_fields[] = {
	&hf_tp_bip_tcp_remote,
	&hf_tp_bip_udp_remote,
	&hf_tp_bip_tcp_server,
	&hf_tp_bip_tcp_local,
	&hf_tp_bip_udp_local,
	&hf_tp_bip_direct_com,
	&hf_tp_bip_eutran,
	&hf_tp_bip_hsdpa,
	NULL
};
static int * const tprof_b18_fields[] = {
	&hf_tp_pa_display_text_var_time_out,
	&hf_tp_pa_get_inkey_help,
	&hf_tp_bip_usb,
	&hf_tp_pa_get_inkey_var_time_out,
	&hf_tp_pa_prov_loci_esn,
	&hf_tp_cc_gprs,
	&hf_tp_pa_prov_loci_imeisv,
	&hf_tp_pa_prov_loci_search_mode_change,
	NULL
};
static int * const tprof_b19_fields[] = {
	&hf_tp_tia_eia_version,
	&hf_tp_rfu4,
	NULL
};

static int * const tprof_b20_fields[] = {
	&hf_tp_tia_iea_is820a_reserved,
	NULL
};

static int * const tprof_b21_fields[] = {
	&hf_tp_ext_launch_browser_wml,
	&hf_tp_ext_launch_browser_xhtml,
	&hf_tp_ext_launch_browser_html,
	&hf_tp_ext_launch_browser_chtml,
	&hf_tp_rfu5,
	NULL
};

static int * const tprof_b22_fields[] = {
	&hf_tp_utran_ps_ext_params,
	&hf_tp_pa_prov_loci_batt_state,
	&hf_tp_pa_play_tone_melody,
	&hf_tp_mm_call_set_up_call,
	&hf_tp_toolkit_initiated_gba,
	&hf_tp_pa_retrieve_mm_msg,
	&hf_tp_pa_submit_mm_msg,
	&hf_tp_pa_display_mm_msg,
	NULL
};

static int * const tprof_b23_fields[] = {
	&hf_tp_pa_set_frames,
	&hf_tp_pa_get_frames_status,
	&hf_tp_mms_notif_download,
	&hf_tp_alpha_id_refresh_cmd,
	&hf_tp_geo_loc_report,
	&hf_tp_pa_prov_loci_meid,
	&hf_tp_pa_prov_loci_nmr_utran_eutran,
	&hf_tp_ussd_data_download,
	NULL
};

static int * const tprof_b24_fields[] = {
	&hf_tp_class_i_max_nb_frames,
	&hf_tp_rfu6,
	NULL
};

static int * const tprof_b25_fields[] = {
	&hf_tp_evt_browsing_status,
	&hf_tp_evt_mms_transfer_status,
	&hf_tp_evt_frame_info_changed,
	&hf_tp_evt_iwlan_access_status,
	&hf_tp_evt_nw_reject_geran_utran,
	&hf_tp_evt_hci_connectivity,
	&hf_tp_evt_nw_reject_eutran,
	&hf_tp_evt_mult_access_techno_change,
	NULL
};

static int * const tprof_b26_fields[] = {
	&hf_tp_evt_csg_cell_select,
	&hf_tp_evt_contactless_state_req,
	&hf_tp_rfu7,
	NULL
};

static int * const tprof_b27_fields[] = {
	&hf_tp_rfu8,
	NULL
};

static int * const tprof_b28_fields[] = {
	&hf_tp_text_align_left,
	&hf_tp_text_align_centre,
	&hf_tp_text_align_right,
	&hf_tp_text_font_size_normal,
	&hf_tp_text_font_size_large,
	&hf_tp_text_font_size_small,
	&hf_tp_rfu9,
	NULL
};

static int * const tprof_b29_fields[] = {
	&hf_tp_text_style_normal,
	&hf_tp_text_style_bold,
	&hf_tp_text_style_italic,
	&hf_tp_text_style_underlined,
	&hf_tp_text_style_strikethrough,
	&hf_tp_text_style_text_fg_colour,
	&hf_tp_text_style_text_bg_colour,
	&hf_tp_rfu10,
	NULL
};

static int * const tprof_b30_fields[] = {
	&hf_tp_bip_iwlan,
	&hf_tp_pa_prov_loci_wsid,
	&hf_tp_term_app,
	&hf_tp_steering_roaming_refresh,
	&hf_tp_pa_activate,
	&hf_tp_pa_geo_loc_req,
	&hf_tp_pa_prov_loci_broadcast_nw_info,
	&hf_tp_steering_roaming_iwlan_refresh,
	NULL
};

static int * const tprof_b31_fields[] = {
	&hf_tp_pa_contactless_state_changed,
	&hf_tp_csg_cell_discovery,
	&hf_tp_cnf_params_support_open_chan_server_mode,
	&hf_tp_com_ctrl_ims,
	&hf_tp_cat_over_modem_itf,
	&hf_tp_evt_incoming_data_ims,
	&hf_tp_evt_ims_registration,
	&hf_tp_pa_prof_env_cont,
	NULL
};

static int * const tprof_b32_fields[] = {
	&hf_tp_bip_ims,
	&hf_tp_pa_prov_loci_henb_ip_addr,
	&hf_tp_pa_prov_loci_henb_surround_macro,
	&hf_tp_launch_params_support_open_chan_server_mode,
	&hf_tp_direct_com_support_open_chan_server_mode,
	&hf_tp_pa_sec_prof_env_cont,
	&hf_tp_cat_serv_list_ecat_client,
	&hf_tp_support_refresh_enforcement_policy,
	NULL
};

static int * const tprof_b33_fields[] = {
	&hf_tp_support_dns_addr_req,
	&hf_tp_support_nw_access_name_reuse,
	&hf_tp_ev_poll_intv_nego,
	&hf_tp_prose_usage_info_reporting,
	&hf_tp_pa_prov_loci_rat,
	&hf_tp_evt_wlan_access_status,
	&hf_tp_wlan_bearer,
	&hf_tp_pa_prov_loci_wlan_id,
	NULL
};

static int * const tprof_b34_fields[] = {
	&hf_tp_uri_send_short_msg,
	&hf_tp_ims_uri_setup_call,
	&hf_tp_media_type_voice_setup_call,
	&hf_tp_media_type_video_setup_call,
	&hf_tp_pa_prov_loci_eutran_timing_advance_info,
	&hf_tp_refresh_euicc_profile_state_change,
	&hf_tp_ext_rej_cause_code_nw_reject_eutran,
	&hf_tp_deprecated_b34,
	NULL
};

static int * const tprof_b35_fields[] = {
	&hf_tp_pa_get_input_var_timeout,
	&hf_tp_data_conn_status_change_pdp,
	&hf_tp_data_conn_status_change_pdn,
	&hf_tp_refresh_app_update,
	&hf_tp_pa_lsi_proactive_session_request,
	&hf_tp_pa_lsi_uicc_platform_reset,
	&hf_tp_rfu11,
	NULL
};

static int * const tprof_b36_fields[] = {
	&hf_tp_data_conn_status_change_pdu,
	&hf_tp_evt_nw_reject_ng_ran,
	&hf_tp_non_ip_data_delivery,
	&hf_tp_prov_loci_slice_info,
	&hf_tp_refresh_sor_cmci_param,
	&hf_tp_evt_nw_reject_satellite_ng_ran,
	&hf_tp_cag_feature,
	&hf_tp_evt_slices_status_change,
	NULL
};

static int * const tprof_b37_fields[] = {
	&hf_tp_prov_loci_rejected_slice_info,
	&hf_tp_ext_info_pli,
	&hf_tp_chaining_pli_env_cmds,
	&hf_tp_5g_prose_usage_info_reporting,
	&hf_tp_rfu12,
	NULL
};

static int * const tprof_b38_fields[] = {
	&hf_tp_rfu13,
	NULL
};

static int * const tprof_b39_fields[] = {
	&hf_tp_pa_prov_loci_ng_ran_satellite_timing_advance_info,
	&hf_tp_rfu14,
	NULL
};

/* According to Section 7.2 of ETSI TS 101 220 / Chapter 7.2 */
/* BER-TLV tag CAT templates */
static const value_string ber_tlv_cat_tag_vals[] = {
	{ 0xcf, "Reserved for proprietary use (terminal->UICC)" },
	{ 0xd0, "Proactive Command" },
	{ 0xd1, "GSM/3GPP/3GPP2 - SMS-PP Download" },
	{ 0xd2, "GSM/3GPP/3GPP2 - Cell Broadcast Download" },
	{ 0xd3, "Menu selection" },
	{ 0xd4, "Call Control" },
	{ 0xd5, "GSM/3GPP - MO Short Message control" },
	{ 0xd6, "Event Download" },
	{ 0xd7, "Timer Expiration" },
	{ 0xd8, "Reserved for intra-UICC communication" },
	{ 0xd9, "3GPP - USSD Download" },
	{ 0xda, "MMS Transfer status" },
	{ 0xdb, "MMS notification download" },
	{ 0xdc, "Terminal application" },
	{ 0xdd, "3GPP - Geographical Location Reporting" },
	{ 0xde, "Envelope Container" },
	{ 0xdf, "3GPP - ProSe Report tag" },
	{ 0, NULL }
};

static const value_string chan_op_vals[] = {
	{ 0x00, "Open Channel" },
	{ 0x80, "Close Channel" },
	{ 0, NULL }
};

static const value_string suspend_uicc_vals[] = {
	{ 0x00, "Suspend the UICC" },
	{ 0x01, "Resume the UICC" },
	{ 0, NULL }
};

static const value_string suspend_time_unit_vals[] = {
	{ 0x00, "Seconds" },
	{ 0x01, "Minutes" },
	{ 0x02, "Hours" },
	{ 0x03, "Days" },
	{ 0x04, "10 Days" },
	{ 0, NULL }
};

static const value_string apdu_le_vals[] = {
	{ 0x00, "Any number in the range 1 to 256" },
	{ 0, NULL }
};

static const value_string apdu_le_vals_ext[] = {
	{ 0x00, "Any number in the range 1 to 65535" },
	{ 0, NULL }
};

static const value_string apdu_cla_coding_vals[] = {
	{ 0x00, "ISO/IEC 7816-4" },
	{ 0x08, "ETSI TS 102.221" },
	{ 0x0a, "ISO/IEC 7816-4 unless stated otherwise" },
	{ 0, NULL }
};

static const value_string apdu_cla_coding_ext_vals[] = {
	{ 0x01, "ISO/IEC 7816-4" },
	{ 0x03, "ETSI TS 102.221" },
	{ 0, NULL }
};

static const value_string apdu_cla_secure_messaging_ind_vals[] = {
	{ 0x00, "No SM used between terminal and card" },
	{ 0x01, "Proprietary SM format" },
	{ 0x02, "Command header not authenticated" },
	{ 0x03, "Command header authenticated" },
	{ 0, NULL }
};

static const true_false_string apdu_cla_secure_messaging_ind_ext_val = {
	"Command header not authenticated",
	"No SM used between terminal and card"
};

static const true_false_string apdu_auth_reference_val = {
	"Specific reference data (e.g. DF specific/application dependent KEY)",
	"Global reference data (e.g. MF specific KEY)"
};

static const value_string apdu_auth_context_vals[] = {
	{ 0x00, "GSM context" },
	{ 0x01, "3G/EPS/5G context" },
	{ 0x02, "VGCS/VBS context" },
	{ 0x04, "GBA context" },
	{ 0, NULL }
};

static const value_string apdu_auth_status_vals[] = {
	{ 0xDB, "Successful 3G authentication" },
	{ 0xDC, "Synchronisation failure" },
	{ 0, NULL }
};

/* Table 9 of GSM TS 11.11 */
static const value_string apdu_ins_vals[] = {
	{ 0xA4, "SELECT" },
	{ 0xF2, "STATUS" },
	{ 0xB0, "READ BINARY" },
	{ 0xD6, "UPDATE BINARY" },
	{ 0xB2, "READ RECORD" },
	{ 0xDC, "UPDATE RECORD" },
	{ 0xA2, "SEARCH RECORD" },
	{ 0x32, "INCREASE" },
	{ 0x20, "VERIFY CHV" },
	{ 0x24, "CHANGE CHV" },
	{ 0x26, "DISABLE CHV" },
	{ 0x28, "ENABLE CHV" },
	{ 0x2C, "UNBLOCK CHV" },
	{ 0x04, "INVALIDATE / REHABILITATE" },
	{ 0x44, "REHABILITATE / ACTIVATE" },
	{ 0x88, "RUN GSM ALGORITHM / AUTHENTICATE" },
	{ 0xFA, "SLEEP" },
	{ 0xC0, "GET RESPONSE" },
	{ 0x10, "TERMINAL PROFILE" },
	{ 0xC2, "ENVELOPE" },
	{ 0x12, "FETCH" },
	{ 0x14, "TERMINAL RESPONSE" },
	/* Only in TS 102 221 v9.2.0 */
	{ 0xCB, "RETRIEVE DATA" },
	{ 0xDB, "SET DATA" },
	{ 0x89, "RUN GSM ALGORITHM / AUTHENTICATE" },
	{ 0x84, "GET CHALLENGE" },
	{ 0xAA, "TERMINAL CAPABILITY" },
	{ 0x70, "MANAGE CHANNEL" },
	{ 0x73, "MANAGE SECURE CHANNEL" },
	{ 0x75, "TRANSACT DATA" },
	{ 0x76, "SUSPEND UICC" },
	/* TS 102 221 v15.11.0 */
	{ 0x78, "GET IDENTITY" },
	{ 0x7A, "EXCHANGE CAPABILITIES" },
	{ 0x7C, "MANAGE LSI" },
	/* GSMA SGP.02 v4.2 */
	{ 0xCA, "GET DATA" },
	/* TS TS 102 222 */
	{ 0xE0, "CREATE FILE" },
	{ 0xE4, "DELETE FILE" },
	{ 0xE6, "TERMINATE DF" },
	{ 0xE8, "TERMINATE EF" },
	{ 0xFE, "TERMINATE CARD USAGE" },
	/* GlobalPlatform Card Specification */
	{ 0xE2, "STORE DATA" },
	{ 0, NULL }
};

/* Section 7.3.7 */

static const value_string search_ef_identifier_vals[] = {
	{ 0, "Currently selected EF" },
	{ 31, "Reserved for future use" },
	{ 0, NULL}
};

static const value_string search_mode_vals[] = {
	{ 0x00, "Forward from first occurrence" },
	{ 0x01, "Backward from last occurrence" },
	{ 0x02, "Forward from next occurrence" },
	{ 0x03, "Backward from previous occurrence" },
	{ 0x04, "Forward from P1" },
	{ 0x05, "Backward from P1" },
	{ 0x06, "Enhanced search" },
	{ 0x07, "Proprietary search" },
	{ 0, NULL }
};

static const value_string search_enhanced_type[] = {
	{ 0x00, "The subsequent byte is an offset (start from that position)" },
	{ 0x01, "The subsequent byte is a value (start after the first occurrence)" },
	{ 0, NULL }
};

static const value_string search_enhanced_mode_vals[] = {
	{ 0x00, "Forward from first occurrence" },
	{ 0x01, "Backward from last occurrence" },
	{ 0x02, "Forward from next occurrence" },
	{ 0x03, "Backward from previous occurrence" },
	{ 0x04, "Forward from P1" },
	{ 0x05, "Backward from P1" },
	{ 0x06, "Forward from next record" },
	{ 0x07, "Backward from previous record" },
	{ 0, NULL }
};

/* Section 10.7 */


/* The FID space is not a global namespace, but a per-directory one. As such,
 * we should have code that tracks the currently selected (sub-)directory, and
 * decode the FID based on that knowledge.  As we don't do that yet, the
 * current work-around is to simply merge all of them into one value_string
 * array */

/* N.B. this combined value_string has lots of duplicate values... */

/* Files at the MF level */
static const value_string mf_dfs[] = {
	{ 0x3f00, "MF" },
	{ 0x7f10, "DF.TELECOM" },
	{ 0x7f20, "DF.GSM" },
	{ 0x7f22, "DF.IS-41" },
	{ 0x7f23, "DF.FP-CTS" },
	{ 0x7f25, "DF.CDMA" },
	{ 0x7f31, "DF.iDEN" },
	{ 0x7f80, "DF.PDC" },
	{ 0x7f90, "DF.TETRA" },
	{ 0x7fff, "ADF" },
#if 0
	{ 0, NULL }
};
static const value_string mf_efs[] = {
#endif
	{ 0x2f00, "EF.DIR" },
//	{ 0x2f05, "EF.ELP" },
	{ 0x2f05, "EF.PL" },
	{ 0x2f06, "EF.ARR" },
	{ 0x2f08, "EF.UMPC" },
	{ 0x2fe2, "EF.ICCID" },
#if 0
	{ 0, NULL }
};

/* Elementary files at the DF.TELECOM level */
static const value_string df_telecom_efs[] = {
#endif
	{ 0x6f06, "EF.ARR" },
	{ 0x6f3a, "EF.ADN" },
	{ 0x6f3b, "EF.FDN" },
	{ 0x6f3c, "EF.SMS" },
	{ 0x6f3d, "EF.CCP" },
	{ 0x6f40, "EF.MSISDN" },
	{ 0x6f42, "EF.SMSP" },
	{ 0x6f43, "EF.SMSS" },
	{ 0x6f44, "EF.LND" },
	{ 0x6f47, "EF.SMSR" },
	{ 0x6f49, "EF.SDN" },
	{ 0x6f4a, "EF.EXT1" },
	{ 0x6f4b, "EF.EXT2" },
	{ 0x6f4c, "EF.EXT3" },
	{ 0x6f4d, "EF.BDN" },
	{ 0x6f4e, "EF.EXT4" },
	{ 0x6f4f, "EF.ECCP" },
	{ 0x6f54, "EF.SUME" },
#if 0
	{ 0, NULL }
};

/* Elementary Files at the DF.GSM level */
static const value_string df_gsm_efs[] = {
#endif
	{ 0x6f05, "EF.LP" },
	{ 0x6f07, "EF.IMSI" },
	{ 0x6f20, "EF.Kc" },
	{ 0x6f30, "EF.PLMNsel" },
	{ 0x6f31, "EF.HPPLMN" },
	{ 0x6f37, "EF.ACMax" },
	{ 0x6f38, "EF.SST" },
	{ 0x6f39, "EF.ACM" },
	{ 0x6f3e, "EF.GID1" },
	{ 0x6f3f, "EF.GID2" },
	{ 0x6f41, "EF.PUCT" },
	{ 0x6f45, "EF.CBMI" },
	{ 0x6f46, "EF.SPN" },
	{ 0x6f74, "EF.BCCH" },
	{ 0x6f78, "EF.ACC" },
	{ 0x6f7b, "EF.FPLMN" },
	{ 0x6f7e, "EF.LOCI" },
	{ 0x6fad, "EF.AD" },
	{ 0x6fae, "EF.PHASE" },
	{ 0x6fb1, "EF.VGCS" },
	{ 0x6fb2, "EF.VGCSS" },
	{ 0x6fb3, "EF.VBS" },
	{ 0x6fb4, "EF.VBSS" },
	{ 0x6fb5, "EF.eMLPP" },
	{ 0x6fb6, "EF.AAeM" },
	{ 0x6fb7, "EF.ECC" },
	{ 0x6f50, "EF.CBMIR" },
	{ 0x6f51, "EF.NIA" },
	{ 0x6f52, "EF.KcGPRS" },
	{ 0x6f53, "EF.LOCIGPRS" },
	{ 0x6f54, "EF.SUME" },
	{ 0x6f60, "EF.PLMNwAcT" },
	{ 0x6f61, "EF.OPLMNwAcT" },
	{ 0x6f62, "EF.HPLMNAcT" },
	{ 0x6f63, "EF.CPBCCH" },
	{ 0x6f64, "EF.INVSCAN" },
#if 0
	{ 0, NULL }
};

static const value_string df_gsm_dfs[] = {
#endif
	{ 0x5f30, "DF.IRIDIUM" },
	{ 0x5f31, "DF.GLOBST" },
	{ 0x5f32, "DF.ICO" },
	{ 0x5f33, "DF.ACeS" },
	{ 0x5f3c, "DF.MExE" },
	{ 0x5f40, "DF.EIA/TIA-533/DF.WLAN" },
	{ 0x5f60, "DF.CTS" },
	{ 0x5f70, "DF.SoLSA" },
#if 0
	{ 0, NULL }
};

static const value_string adf_usim_dfs[] = {
#endif
	{ 0x5f3a, "DF.PHONEBOOK" },
	{ 0x5f3b, "DF.GSM-ACCESS" },
//	{ 0x5f3c, "DF.MexE" },
//	{ 0x5f70, "DF.SoLSA" },
//	{ 0x5f40, "DF.WLAN" },
	{ 0x5f50, "DF.HNB" },
	{ 0x5f90, "DF.ProSe" },
	{ 0x5fa0, "DF.ACDC" },
	{ 0x5fb0, "DF.TV" },
	{ 0x5fc0, "DF.5GS" },
#if 0
	{ 0, NULL }
};

static const value_string adf_usim_efs[] = {
#endif
	{ 0x6f00, "EF.5GAuthKeys" },
	{ 0x6f01, "EF.5GS3GPPAccessNASSecCtxt" },
	{ 0x6f02, "EF.5GSnon3GPPAccessNASSecCtxt" },
	{ 0x6f03, "EF.SCICI" },
	{ 0x6f04, "EF.UACAcessIdConfig" },
	{ 0x6f06, "EF.ARR" },
	{ 0x6f07, "EF.IMSI" },
	{ 0x6f08, "EF.Keys" },
	{ 0x6f09, "EF.KeysPS" },
	{ 0x6f2c, "EF.DCK" },
	{ 0x6f31, "EF.HPPLMN" },
	{ 0x6f32, "EF.CNL" },
	{ 0x6f37, "EF.ACMax" },
	{ 0x6f39, "EF.ACM" },
	{ 0x6f3b, "EF.FDN" },
	{ 0x6f3c, "EF.SMS" },
	{ 0x6f3e, "EF.GID1" },
	{ 0x6f3f, "EF.GID2" },
	{ 0x6f40, "EF.MSISDN" },
	{ 0x6f42, "EF.SMSP" },
	{ 0x6f43, "EF.SMSS" },
	{ 0x6f45, "EF.CBMI" },
	{ 0x6f46, "EF.SPN" },
	{ 0x6f47, "EF.SMSR" },
	{ 0x6f48, "EF.CBMID" },
	{ 0x6f4b, "EF.EXT2" },
	{ 0x6f4c, "EF.EXT3" },
	{ 0x6f4d, "EF.BDN" },
	{ 0x6f50, "EF.CBMIR" },
	{ 0x6f55, "EF.EXT4" },
	{ 0x6f56, "EF.EST" },
	{ 0x6f57, "EF.ACL" },
	{ 0x6f58, "EF.CMI" },
	{ 0x6f5b, "EF.START-HFN" },
	{ 0x6f5c, "EF.THRESHOLD" },
	{ 0x6f60, "EF.PLMNwAcT" },
	{ 0x6f61, "EF.OPLMNwAcT" },
	{ 0x6f62, "EF.HPLMNAcT" },
	{ 0x6f73, "EF.PSLOCI" },
	{ 0x6f78, "EF.ACC" },
	{ 0x6f7b, "EF.FPLMN" },
	{ 0x6f7e, "EF.LOCI" },
	{ 0x6f80, "EF.ICI" },
	{ 0x6f81, "EF.OCI" },
	{ 0x6f82, "EF.ICT" },
	{ 0x6f83, "EF.OCT" },
	{ 0x6fad, "EF.AD" },
	{ 0x6fb1, "EF.VGCS" },
	{ 0x6fb2, "EF.VGCSS" },
	{ 0x6fb3, "EF.VBS" },
	{ 0x6fb4, "EF.VBSS" },
	{ 0x6fb5, "EF.eMLPP" },
	{ 0x6fb6, "EF.AAeM" },
	{ 0x6fb7, "EF.ECC" },
	{ 0x6fc3, "EF.Hiddenkey" },
	{ 0x6fc4, "EF.NETPAR" },
	{ 0x6fc5, "EF.PNN" },
	{ 0x6fc6, "EF.OPL" },
	{ 0x6fc7, "EF.MBDN" },
	{ 0x6fc8, "EF.EXT6" },
	{ 0x6fc9, "EF.MBI" },
	{ 0x6fca, "EF.MWIS" },
	{ 0x6fcb, "EF.CFIS" },
	{ 0x6fcc, "EF.EXT7" },
	{ 0x6fcd, "EF.SPDI" },
	{ 0x6fce, "EF.MMSN" },
	{ 0x6fcf, "EF.EXT8" },
	{ 0x6fd0, "EF.MMSICP" },
	{ 0x6fd1, "EF.MMSUP" },
	{ 0x6fd2, "EF.MMSUCP" },
	{ 0x6fd3, "EF.NIA" },
	{ 0x6fd4, "EF.VGCSCA" },
	{ 0x6fd5, "EF.VBSCA" },
	{ 0x6fd6, "EF.GBAP" },
	{ 0x6fd7, "EF.MSK" },
	{ 0x6fd8, "EF.MUK" },
	{ 0x6fd9, "EF.EHPLMN" },
	{ 0x6fda, "EF.GBANL" },
	{ 0x6fdb, "EF.EHPLMNPI" },
	{ 0x6fdc, "EF.LRPLMNSI" },
	{ 0x6fdd, "EF.NAFKCA" },
	{ 0x6fde, "EF.SPNI" },
	{ 0x6fdf, "EF.PNNI" },
	{ 0x6fe2, "EF.NCP-IP" },
	{ 0x6fe3, "EF.EPSLOCI" },
	{ 0x6fe4, "EF.EPSNSC" },
	{ 0x6fe6, "EF.UFC" },
	{ 0x6fe7, "EF.UICCIARI" },
	{ 0x6fec, "EF.PWS" },
	{ 0x6fed, "EF.FDNURI" },
	{ 0x6fee, "EF.BDNURI" },
	{ 0x6fef, "EF.SDNURI" },
	{ 0x6ff0, "EF.IWL" },
	{ 0x6ff1, "EF.IPS" },
	{ 0x6ff2, "EF.IPD" },
	{ 0x6ff3, "EF.ePDGId" },
	{ 0x6ff4, "EF.ePDGSelection" },
	{ 0x6ff5, "EF.ePDGIdEm" },
	{ 0x6ff6, "EF.ePDGSelection" },
	{ 0x6ff7, "EF.FromPreferred" },
	{ 0x6ff9, "EF.3GPPPSDATAOFF" },
	{ 0x6ffa, "EF.3GPPPSDATAOFFservicelist" },
	{ 0x6ffb, "EF.TVCONFIG" },
	{ 0x6ffc, "EF.XCAPConfigData" },
	{ 0x6ffd, "EF.EARFCNList" },
	{ 0x6ffe, "EF.5GS3GPPLocationInformation" },
	{ 0x6fff, "EF.5GSnon3GPPLocationInformation" },
#if 0
	{ 0, NULL }
};

static const value_string adf_5gs_efs[] = {
#endif
	{ 0x4f01, "EF.5GS3GPPLOCI" },
	{ 0x4f02, "EF.5GSN3GPPLOCI" },
	{ 0x4f03, "EF.5GS3GPPNSC" },
	{ 0x4f04, "EF.5GSN3GPPNSC" },
	{ 0x4f05, "EF.5GAUTHKEYS" },
	{ 0x4f06, "EF.UAC_AIC" },
	{ 0x4f07, "EF.SUCI_Calc_Info" },
	{ 0x4f08, "EF.OPL5G" },
	{ 0x4f09, "EF.EFSUPI_NAI/EF.PBC" },
	{ 0x4f0a, "EF.Routing_Indicator/EF.PBC1" },
	{ 0x4f0b, "EF.URSP" },
	{ 0x4f0c, "EF.TN3GPPSNN" },
#if 0
	{ 0, NULL }
};

static const value_string df_phonebook_efs[] = {
#endif
//	{ 0x4f09, "EF.PBC" },
//	{ 0x4f0a, "EF.PBC1" },
	{ 0x4f11, "EF.ANRA" },
	{ 0x4f12, "EF.ANRA1" },
	{ 0x4f13, "EF.ANRB" },
	{ 0x4f14, "EF.ANRB1" },
	{ 0x4f15, "EF.ANRC" },
	{ 0x4f16, "EF.ANRC1" },
	{ 0x4f19, "EF.SNE" },
	{ 0x4f1a, "EF.SNE1" },
	{ 0x4f20, "EF.UID1" },
	{ 0x4f21, "EF.UID" },
	{ 0x4f22, "EF.FSC" },
	{ 0x4f23, "EF.CC" },
	{ 0x4f24, "EF.PUID" },
	{ 0x4f25, "EF.GRP1" },
	{ 0x4f26, "EF.GRP" },
	{ 0x4f30, "EF.PBR" },
	{ 0x4f3a, "EF.ADN" },
	{ 0x4f3b, "EF.ADN1" },
	{ 0x4f4a, "EF.EXT1" },
	{ 0x4f4b, "EF.AAS" },
	{ 0x4f4c, "EF.GAS" },
	{ 0x4f50, "EF.EMAIL" },
	{ 0x4f51, "EF.EMAIL1" },
	{ 0, NULL }
};

/* Section 9.4 of TS 11.11 */
static const value_string sw_vals[] = {
	/* we only list the non-wildcard commands here */
	{ 0x9000, "Normal ending of the command" },
	{ 0x9300, "SIM Application Toolkit is busy" },
	{ 0x9240, "Memory problem" },
	{ 0x9400, "No EF selected" },
	{ 0x9402, "Out of range (invalid address)" },
	{ 0x9404, "File ID not found" },
	{ 0x9408, "File is inconsistent with the command" },
	{ 0x9802, "No CHV initialized" },
	{ 0x9804, "Access condition not fulfilled / authentication failed" },
	{ 0x9808, "In contradiction with CHV status" },
	{ 0x9810, "In contradiction with invalidation status" },
	{ 0x9840, "Unsuccessful CHV verification, no attempt left / CHV blocked" },
	{ 0x9850, "Application errors: Increase cannot be performed, max value reached" },
	{ 0x6b00, "Incorrect parameter P1 or P2" },
	/* Section 10.2.1.3 of TS 102 221 */
	{ 0x6200, "Warning: No information given, state of volatile memory unchanged" },
	{ 0x6281, "Warning: Part of returned data may be corrupted" },
	{ 0x6282, "Warning: End of file/record reached before reading Le bytes" },
	{ 0x6283, "Warning: Selected file invalidated" },
	{ 0x6285, "Warning: Selected file in termination state" },
	{ 0x62f1, "Warning: More data available" },
	{ 0x62f2, "Warning: More data available and proactive command pending" },
	{ 0x62f3, "Warning: Response data available" },
	{ 0x63f1, "Warning: More data expected" },
	{ 0x63f2, "Warning: More data expected and proactive command pending" },
	/* Section 10.2.1.4 of TS 102 221 */
	{ 0x6400, "Execution error: No information given, memory unchanged" },
	{ 0x6500, "Execution error: No information given, memory changed" },
	{ 0x6581, "Execution error: Memory problem" },
	/* Section 10.2.1.5 of TS 102 221 */
	{ 0x6700, "Wrong length" },
	{ 0x6d00, "Instruction code not supported or invalid" },
	{ 0x6e00, "Class not supported" },
	{ 0x6f00, "Technical problem, no precise diagnosis" },
	/* Section 10.2.1.5.1 of TS 102 221 */
	{ 0x6800, "Function in CLA not supported" },
	{ 0x6881, "Function in CLA not supported: Logical channel not supported" },
	{ 0x6882, "Function in CLA not supported: Secure messaging not supported" },
	/* Section 10.2.1.5.2 of TS 102 221 */
	{ 0x6900, "Command not allowed" },
	{ 0x6981, "Command not allowed: Command incompatible with file structure" },
	{ 0x6982, "Command not allowed: Security status not satisfied" },
	{ 0x6983, "Command not allowed: Authentication/PIN method blocked" },
	{ 0x6984, "Command not allowed: Referenced data invalid" },
	{ 0x6985, "Command not allowed: Conditions of use not satisfied" },
	{ 0x6986, "Command not allowed: No EF selected" },
	{ 0x6989, "Command not allowed: Secure channel - security not satisfied" },
	/* Section 10.2.1.5.3 of TS 102 221 */
	{ 0x6a80, "Wrong parameters: Incorrect parameters in the data field" },
	{ 0x6a81, "Wrong parameters: Function not supported" },
	{ 0x6a82, "Wrong parameters: File not found" },
	{ 0x6a83, "Wrong parameters: Record not found" },
	{ 0x6a84, "Wrong parameters: Not enough memory space" },
	{ 0x6a86, "Wrong parameters: Incorrect P1 to P2" },
	{ 0x6a87, "Wrong parameters: Lc inconsistent with P1 to P2" },
	{ 0x6a88, "Wrong parameters: Referenced data not found" },
	/* Section 10.2.1.6 of TS 102 221 */
	{ 0x9862, "Application errors: Authentication error, application specific" },
	{ 0x9863, "Application errors: Security session or association expired" },
	{ 0x9864, "Application errors: Minimum UICC suspension time is too long" },
	{ 0, NULL }
};

static const value_string select_type_vals[] = {
	{ 0x00, "Select DF, EF or MF by file id" },
	{ 0x01, "Select child DF of the current DF" },
	{ 0x03, "Select parent DF of the current DF" },
	{ 0x04, "Selection by DF name (selection by AID)" },
	{ 0x08, "Select by path from MF" },
	{ 0x09, "Select by path from current DF" },
	{ 0, NULL }
};

static const value_string select_session_control_vals[] = {
	{ 0x00, "Activation/Reset" },
	{ 0x01, "Termination" },
	{ 0, NULL }
};

static const value_string select_return_data_vals[] = {
	{ 0x01, "Response FCP template" },
	{ 0x03, "No data returned" },
	{ 0, NULL }
};

static const value_string select_selection_vals[] = {
	{ 0x00, "First or only occurrence" },
	{ 0x01, "Last occurrence" },
	{ 0x02, "Next occurrence" },
	{ 0x03, "Previous occurrence" },
	{ 0, NULL }
};

static const value_string status_application_status_vals[] = {
	{ 0x00, "No indication" },
	{ 0x01, "Current application is initialized in the terminal" },
	{ 0x02, "The terminal will initiate the termination of the current application" },
	{ 0, NULL }
};

static const value_string status_return_data_vals[] = {
	{ 0x00, "Response parameters and data are identical to the response parameters and data of the SELECT command" },
	{ 0x01, "The DF name TLV-object of the currently selected application is returned" },
	{ 0x0C, "No data returned" },
	{ 0, NULL }
};

static const value_string record_file_vals[] = {
	{ 0, "Currently selected EF" },
	{ 0, NULL}
};

static const value_string record_mode_vals[] = {
	{ 0x02, "Next record" },
	{ 0x03, "Previous record" },
	{ 0x04, "Absolute/current mode, the record number is given in P1 with P1='00' denoting the current record" },
	{ 0, NULL }
};

static const true_false_string store_data_iso_case_tfs = {
	"ISO case 4 command (response data may be returned)",
	"ISO case 3 command (no response data expected)"
};

static const value_string store_data_structure_vals[] = {
	{ 0x00, "No general data structure information" },
	{ 0x01, "DGI format of the command data field" },
	{ 0x02, "BER-TLV format of the command data field" },
	{ 0x03, "RFU" },
	{ 0, NULL }
};

static const value_string store_data_encryption_vals[] = {
	{ 0x00, "No general encryption information or non-encrypted data" },
	{ 0x01, "Application dependent encryption of the data" },
	{ 0x02, "RFU" },
	{ 0x03, "Encrypted data" },
	{ 0, NULL }
};

static const true_false_string store_data_block_tfs = {
	"Last block",
	"More blocks"
};

static const char *get_sw_string(wmem_allocator_t *scope, uint16_t sw)
{
	uint8_t sw1 = sw >> 8;
	uint8_t sw2 = sw & 0xFF;

	switch (sw1) {
	case 0x91:
		return "Normal ending of command with info from proactive SIM";
	case 0x9e:
		return "Length of the response data given / SIM data download error";
	case 0x9f:
		return wmem_strdup_printf(scope, "Length of the response data, Length is %u", sw2 ? sw2 : 256);
	case 0x92:
		if ((sw & 0xf0) == 0x00)
			return "Command successful but after internal retry routine";
		break;
	case 0x61:
		return wmem_strdup_printf(scope, "Response ready, Response length is %u", sw2 ? sw2 : 256);
	case 0x67:
		if (sw2 == 0x00)
			return "Wrong length"; /* TS 102.221 / Section 10.2.1.5 */
		else
			return "Incorrect parameter P3"; /* TS 51.011 / Section 9.4.6 */
	case 0x6c:
		return wmem_strdup_printf(scope, "Terminal should repeat command, Length for repeated command is %u", sw2 ? sw2 : 256);
	case 0x6d:
		return "Unknown instruction code";
	case 0x6e:
		return "Wrong instruction class";
	case 0x6f:
		return "Technical problem with no diagnostic";
	}
	return val_to_str(scope, sw, sw_vals, "Unknown status word: %04x");
}

static int
dissect_bertlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	unsigned int pos = 0;
	proto_tree *top_tree = data ? (proto_tree *)data : tree;

	while (pos < tvb_reported_length(tvb)) {
		uint8_t tag;
		uint32_t len;
		tvbuff_t *subtvb;

		proto_tree_add_item(tree, hf_cat_ber_tag, tvb, pos, 1, ENC_BIG_ENDIAN);

		/* FIXME: properly follow BER coding rules */
		tag = tvb_get_uint8(tvb, pos++);
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(pinfo->pool, tag, ber_tlv_cat_tag_vals, "%02x "));
		len = tvb_get_uint8(tvb, pos++);
		switch (len) {
		case 0x81:
			len = tvb_get_uint8(tvb, pos++);
			break;
		case 0x82:
			len = tvb_get_ntohs(tvb, pos);
			pos += 2;
			break;
		case 0x83:
			len = tvb_get_ntoh24(tvb, pos);
			pos += 3;
			break;
		default:
			break;
		}

		subtvb = tvb_new_subset_length(tvb, pos, len);
		switch (tag) {
		case 0xD0:	/* proactive command */
		case 0xD1:	/* sms-pp download */
		case 0xD6:	/* event download */
		case 0xD7:	/* timer expiration */
			call_dissector_with_data(sub_handle_cap, subtvb, pinfo, top_tree, GUINT_TO_POINTER((unsigned)tag));
			break;
		}

		pos += len;
	}
	return tvb_captured_length(tvb);
}


#define ADD_TP_BYTE(byte) \
		if ((offset - start_offset) >= p3) break; \
		proto_tree_add_bitmask(sim_tree, tvb, offset++, hf_tprof_b##byte, ett_tprof_b##byte, tprof_b##byte##_fields, ENC_BIG_ENDIAN);

#define P1_OFFS		0
#define P2_OFFS		1
#define P3_OFFS		2
#define DATA_OFFS	3

static const value_string sfi_vals[] = {
	{ 0x01, "Emergency call codes" },
	{ 0x02, "Language indication" },
	{ 0x03, "Administrative data" },
	{ 0x04, "USIM service table" },
	{ 0x05, "Enabled services table" },
	{ 0x06, "Access control class" },
	{ 0x07, "IMSI" },
	{ 0x08, "Ciphering and integrity keys" },
	{ 0x09, "Ciphering and integrity keys for packet switched domain" },
	{ 0x0A, "User PLMN selector" },
	{ 0x0B, "Location information" },
	{ 0x0C, "Packet switched location information" },
	{ 0x0D, "Forbidden PLMNs" },
	{ 0x0E, "CBMID" },
	{ 0x0F, "Hyperframe number" },
	{ 0x10, "Maximum value of hyperframe number" },
	{ 0x11, "Operator PLMN selector" },
	{ 0x12, "Higher Priority PLMN search period" },
	{ 0x13, "Preferred HPLMN access technology" },
	{ 0x14, "Incoming call information" },
	{ 0x15, "Outgoing call information" },
	{ 0x16, "Capability configuration parameters 2" },
	{ 0x17, "Access Rule Reference" },
	{ 0x18, "EPS NAS Security Context" },
	{ 0x19, "PLMN Network Name" },
	{ 0x1A, "Operator Network List" },
	{ 0x1B, "Service Provider Display Information" },
	{ 0x1C, "Accumulated Call Meter" },
	{ 0x1D, "Equivalent HPLMN" },
	{ 0x1E, "EPS location information" },
	{ 0, NULL }
};

static const value_string sfi_referencing_vals[] = {
	{ 0x04, "SFI referencing used" },
	{ 0, NULL }
};

static int
dissect_auth_challenge(uint8_t context, tvbuff_t *tvb, proto_tree *tree, int offset, int length)
{
	proto_item *ti;
	proto_tree *sub_tree;
	uint32_t len;

	ti = proto_tree_add_item(tree, hf_auth_challenge, tvb, offset, length, ENC_NA);
	sub_tree = proto_item_add_subtree(ti, ett_auth_challenge);

	switch (context) {
	case 0x00: /* GSM context */
	case 0x01: /* 3G/EPS/5G context */
		proto_tree_add_item_ret_uint(sub_tree, hf_auth_rand_len, tvb, offset, 1, ENC_NA, &len);
		offset += 1;
		proto_tree_add_item(sub_tree, hf_auth_rand, tvb, offset, len, ENC_NA);
		offset += len;
		proto_tree_add_item_ret_uint(sub_tree, hf_auth_autn_len, tvb, offset, 1, ENC_NA, &len);
		offset += 1;
		proto_tree_add_item(sub_tree, hf_auth_autn, tvb, offset, len, ENC_NA);
		offset += len;
		break;
	default:
		/* XXX - Dissect according to authentication context */
		offset += length;
		break;
	}

	return offset;
}

static int
dissect_auth_response(uint8_t context, tvbuff_t *tvb, proto_tree *tree, int offset, int length)
{
	proto_item *ti;
	proto_tree *sub_tree;
	uint32_t status = 0;
	uint32_t len;

	if (context == 0x01) {
		/* 3G/EPS/5G context - put status outside the response tree */
		proto_tree_add_item_ret_uint(tree, hf_auth_status, tvb, offset, 1, ENC_NA, &status);
	}

	ti = proto_tree_add_item(tree, hf_auth_response, tvb, offset, length, ENC_NA);
	sub_tree = proto_item_add_subtree(ti, ett_auth_response);

	switch (context) {
	case 0x00: /* GSM context */
		proto_tree_add_item_ret_uint(sub_tree, hf_auth_gsm_sres_len, tvb, offset, 1, ENC_NA, &len);
		offset += 1;
		proto_tree_add_item(sub_tree, hf_auth_gsm_sres, tvb, offset, len, ENC_NA);
		offset += len;
		proto_tree_add_item_ret_uint(sub_tree, hf_auth_gsm_kc_len, tvb, offset, 1, ENC_NA, &len);
		offset += 1;
		proto_tree_add_item(sub_tree, hf_auth_gsm_kc, tvb, offset, len, ENC_NA);
		offset += len;
		break;
	case 0x01: /* 3G/EPS/5G context */
		offset += 1; /* Skip status byte already added above */
		if (status == 0xDB) {
			proto_tree_add_item_ret_uint(sub_tree, hf_auth_res_len, tvb, offset, 1, ENC_NA, &len);
			offset += 1;
			proto_tree_add_item(sub_tree, hf_auth_res, tvb, offset, len, ENC_NA);
			offset += len;
			proto_tree_add_item_ret_uint(sub_tree, hf_auth_ck_len, tvb, offset, 1, ENC_NA, &len);
			offset += 1;
			proto_tree_add_item(sub_tree, hf_auth_ck, tvb, offset, len, ENC_NA);
			offset += len;
			proto_tree_add_item_ret_uint(sub_tree, hf_auth_ik_len, tvb, offset, 1, ENC_NA, &len);
			offset += 1;
			proto_tree_add_item(sub_tree, hf_auth_ik, tvb, offset, len, ENC_NA);
			offset += len;
			proto_tree_add_item_ret_uint(sub_tree, hf_auth_kc_len, tvb, offset, 1, ENC_NA, &len);
			offset += 1;
			proto_tree_add_item(sub_tree, hf_auth_kc, tvb, offset, len, ENC_NA);
			offset += len;
		} else if (status == 0xDC) {
			proto_tree_add_item_ret_uint(sub_tree, hf_auth_auts_len, tvb, offset, 1, ENC_NA, &len);
			offset += 1;
			proto_tree_add_item(sub_tree, hf_auth_auts, tvb, offset, len, ENC_NA);
			offset += len;
		}
		break;
	default:
		/* XXX - Dissect according to authentication context */
		offset += length;
	}

	return offset;
}

static void
dissect_apdu_lc(proto_tree *tree, tvbuff_t *tvb, int offset, bool extended_len)
{
	if (extended_len) {
		proto_tree_add_item(tree, hf_apdu_lc_ext, tvb, offset, 3, ENC_BIG_ENDIAN);
	} else {
		proto_tree_add_item(tree, hf_apdu_lc, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
}

static void
dissect_apdu_le(proto_tree *tree, tvbuff_t *tvb, int offset, bool extended_len, bool first)
{
	if (extended_len) {
		proto_tree_add_item(tree, hf_apdu_le_ext, tvb, offset, first ? 3 : 2, ENC_BIG_ENDIAN);
	} else {
		proto_tree_add_item(tree, hf_apdu_le, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
}

static tvbuff_t *
gsm_sim_apdu_reassemble(tvbuff_t *tvb, int offset, packet_info *pinfo, gsm_sim_transaction_t *gsm_sim_trans,
			proto_tree *sim_tree, uint8_t *apdu_ins, uint8_t *apdu_p1, uint8_t *apdu_p2)
{
	unsigned tvb_len = tvb_reported_length(tvb);
	unsigned apdu_len = tvb_len - offset - 2;
	tvbuff_t *subtvb = NULL;
	uint8_t sw1;

	if (!gsm_sim_trans || gsm_sim_trans->rsp_frame != pinfo->num) {
		/* No transaction found, return the current tvb subset */
		return tvb_new_subset_length(tvb, offset, apdu_len);
	}

	/* Try reassembly if SW1 is "Response ready" or instruction is "GET RESPONSE" */
	sw1 = tvb_get_uint8(tvb, tvb_len - 2);
	if (sw1 == 0x61 || gsm_sim_trans->cmd_ins == 0xC0) {
		fragment_head *frag_msg;

		/* The APDU reassembly is using the command frame number as id. */
		frag_msg = fragment_add_seq_next(&gsm_sim_reassembly_table, tvb, offset, pinfo,
						 gsm_sim_trans->related_trans->cmd_frame, NULL,
						 apdu_len, sw1 == 0x61);
		subtvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled APDU",
						  frag_msg, &gsm_sim_frag_items, NULL, sim_tree);
	}

	if (!subtvb) {
		subtvb = tvb_new_subset_length(tvb, offset, apdu_len);
	}

	if (gsm_sim_trans != gsm_sim_trans->related_trans) {
		/* Use INS, P1 and P2 from the related command */
		*apdu_ins = gsm_sim_trans->related_trans->cmd_ins;
		*apdu_p1 = gsm_sim_trans->related_trans->cmd_p1;
		*apdu_p2 = gsm_sim_trans->related_trans->cmd_p2;
	}

	return subtvb;
}

static int
dissect_gsm_apdu(uint8_t ins, uint8_t p1, uint8_t p2, uint16_t p3, bool extended_len,
		 tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, proto_tree *sim_tree)
{
	uint16_t g16;
	tvbuff_t *subtvb;
	int i, start_offset;
	uint8_t first_byte = 0;
	const int data_offs = DATA_OFFS + (extended_len ? 2 : 0);

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(pinfo->pool, ins, apdu_ins_vals, "%02x"));

	switch (ins) {
	case 0xA4: /* SELECT */
		proto_tree_add_item(sim_tree, hf_select_type, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		if (p1 == 0x04) { /* Selection by DF name (selection by AID) */
			proto_tree_add_item(sim_tree, hf_select_session_control, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		} else {
			proto_tree_add_item(sim_tree, hf_select_unused_p2, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		}
		proto_tree_add_item(sim_tree, hf_select_return_data, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_select_selection, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		break;
	case 0xF2: /* STATUS */
		proto_tree_add_item(sim_tree, hf_status_application_status, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_status_return_data, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		break;
	case 0xB0: /* READ BINARY */
	case 0xD6: /* UPDATE BINARY */
		if (p1 & 0x80) {
			proto_tree_add_item(sim_tree, hf_referencing, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(sim_tree, hf_sfi, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
			col_append_fstr(pinfo->cinfo, COL_INFO, "Offset=%u ", p2);
			proto_tree_add_item(sim_tree, hf_bin_offset, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		} else {
			col_append_fstr(pinfo->cinfo, COL_INFO, "Offset=%u ", p1 << 8 | p2);
			proto_tree_add_item(sim_tree, hf_bin_offset, tvb, offset+P1_OFFS, 2, ENC_BIG_ENDIAN);
		}
		break;
	case 0xB2: /* READ RECORD */
	case 0xDC: /* UPDATE RECORD */
		col_append_fstr(pinfo->cinfo, COL_INFO, "RecordNr=%u ", p1);
		proto_tree_add_item(sim_tree, hf_record_nr, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_record_file, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_record_mode, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		break;
	case 0xA2: /* SEARCH RECORD */
		first_byte = tvb_get_uint8(tvb, offset+data_offs);
		if (((p2 & 0x04) == 0) || (((p2 & 0x07) == 0x06) && ((first_byte & 0x04) == 0))) {
			proto_tree_add_item(sim_tree, hf_record_id, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		} else {
			proto_tree_add_item(sim_tree, hf_record_nr, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		}
		proto_tree_add_item(sim_tree, hf_search_ef_identifier, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_search_mode, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		break;
	case 0x88: /* RUN GSM ALGORITHM / AUTHENTICATE */
		proto_tree_add_item(sim_tree, hf_apdu_p1, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		if (p2 != 0) {
			proto_tree_add_item(sim_tree, hf_auth_reference, tvb, offset+P2_OFFS, 1, ENC_NA);
			proto_tree_add_item(sim_tree, hf_auth_rfu, tvb, offset+P2_OFFS, 1, ENC_NA);
			proto_tree_add_item(sim_tree, hf_auth_context, tvb, offset+P2_OFFS, 1, ENC_NA);
		}
		break;
	case 0x70: /* MANAGE CHANNEL */
		proto_tree_add_item(sim_tree, hf_chan_op, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "Operation=%s ", val_to_str(pinfo->pool, p1, chan_op_vals, "%02x"));
		proto_tree_add_item(sim_tree, hf_chan_nr, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		if (p1 == 0 && p2 == 0) {
			/* Logical channels are assigned by the card when P2 is 0. */
			col_append_str(pinfo->cinfo, COL_INFO, "(assign channel) ");
		} else {
			col_append_fstr(pinfo->cinfo, COL_INFO, "(channel: %d) ", p2);
		}
		break;
	case 0x76: /* SUSPEND UICC */
		proto_tree_add_item(sim_tree, hf_suspend_uicc_op, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_apdu_p2, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		break;
	case 0xE2: /* STORE DATA */
		proto_tree_add_item(sim_tree, hf_store_data_block, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_store_data_encryption, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_store_data_structure, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_store_data_rfu, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_store_data_iso_case, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_store_data_block_nr, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		if (p1 & 0x80) {
			col_append_str(pinfo->cinfo, COL_INFO, "(last block) ");
		} else {
			col_append_str(pinfo->cinfo, COL_INFO, "(more blocks) ");
		}
		break;
	default:
		/* Generic P1 and P2 */
		proto_tree_add_item(sim_tree, hf_apdu_p1, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_apdu_p2, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		break;
	}

	switch (ins) {
	case 0xA4: /* SELECT */
		dissect_apdu_lc(sim_tree, tvb, offset+P3_OFFS, extended_len);
		if (p3 < 2) {
			offset += data_offs;
			break;
		}
		switch (p1) {
		case 0x03:	/* parent DF */
			col_append_str(pinfo->cinfo, COL_INFO, "Parent DF ");
			break;
		case 0x04:	/* select by AID */
			col_append_fstr(pinfo->cinfo, COL_INFO, "Application %s ",
					tvb_bytes_to_str(pinfo->pool, tvb, offset+data_offs, p3));
			proto_tree_add_item(sim_tree, hf_aid, tvb, offset+data_offs, p3, ENC_NA);
			break;

		case 0x09:	/* select by relative path */
			col_append_str(pinfo->cinfo, COL_INFO, ".");
			/* fallthrough */
		case 0x08:	/* select by absolute path */
			for (i = 0; i < p3; i += 2) {
				g16 = tvb_get_ntohs(tvb, offset+data_offs+i);
				col_append_fstr(pinfo->cinfo, COL_INFO, "/%s",
						val_to_str(pinfo->pool, g16, mf_dfs, "%04x"));
				proto_tree_add_item(sim_tree, hf_file_id, tvb, offset+data_offs+i, 2, ENC_BIG_ENDIAN);
			}
			col_append_str(pinfo->cinfo, COL_INFO, " ");
			break;
		default:
			g16 = tvb_get_ntohs(tvb, offset+data_offs);
			col_append_fstr(pinfo->cinfo, COL_INFO, "File %s ",
					val_to_str(pinfo->pool, g16, mf_dfs, "%04x"));
			proto_tree_add_item(sim_tree, hf_file_id, tvb, offset+data_offs, p3, ENC_BIG_ENDIAN);
			break;
		}
		offset += data_offs + p3;
		if (tvb_reported_length_remaining(tvb, offset)) {
			dissect_apdu_le(sim_tree, tvb, offset, extended_len, false);
			offset += (extended_len ? 2 : 1);
		}
		break;
	case 0xF2: /* STATUS */
		if (tvb_reported_length_remaining(tvb, offset+P3_OFFS)) {
			dissect_apdu_le(sim_tree, tvb, offset+P3_OFFS, extended_len, true);
		}
		offset += data_offs;
		break;
	case 0xB0: /* READ BINARY */
	case 0xB2: /* READ RECORD */
	case 0x12: /* FETCH */
	case 0x78: /* GET IDENTITY */
	case 0xC0: /* GET RESPONSE */
	case 0xCA: /* GET DATA */
		dissect_apdu_le(sim_tree, tvb, offset+P3_OFFS, extended_len, true);
		offset += data_offs;
		break;
	case 0xD6: /* UPDATE BINARY */
	case 0xDC: /* UPDATE RECORD */
		dissect_apdu_lc(sim_tree, tvb, offset+P3_OFFS, extended_len);
		proto_tree_add_item(sim_tree, hf_apdu_data, tvb, offset+data_offs, p3, ENC_NA);
		offset += data_offs + p3;
		break;
	case 0xA2: /* SEARCH RECORD */
		dissect_apdu_lc(sim_tree, tvb, offset+P3_OFFS, extended_len);
		offset += data_offs;
		if ((p2 & 0x07) == 0x06) { /* Enhanced search */
			proto_tree_add_item(sim_tree, hf_search_enhanced_type, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(sim_tree, hf_search_enhanced_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			if ((first_byte & 0xF8) == 0) {
				proto_tree_add_item(sim_tree, hf_search_enhanced_offset, tvb, offset++, 1, ENC_BIG_ENDIAN);
			} else {
				proto_tree_add_item(sim_tree, hf_search_enhanced_value, tvb, offset++, 1, ENC_BIG_ENDIAN);
			}
			p3 -= 2; /* Reduced by 2 bytes for the enhanced search indication */
		}
		proto_tree_add_item(sim_tree, hf_apdu_data, tvb, offset, p3, ENC_NA);
		offset += p3;
		if (tvb_reported_length_remaining(tvb, offset)) {
			dissect_apdu_le(sim_tree, tvb, offset, extended_len, false);
			offset += (extended_len ? 2 : 1);
		}
		break;
	case 0x32: /* INCREASE */
		offset += data_offs;
		break;
	case 0x20: /* VERIFY CHV */
	case 0x24: /* CHANGE CHV */
	case 0x26: /* DISABLE CHV */
	case 0x28: /* ENABLE CHV */
	case 0x2C: /* UNBLOCK CHV */
		col_append_fstr(pinfo->cinfo, COL_INFO, "CHV=%u ", p2);
		offset += data_offs;
		/* FIXME: actual PIN/PUK code */
		break;
	case 0x88: /* RUN GSM ALGORITHM / AUTHENTICATE */
		dissect_apdu_lc(sim_tree, tvb, offset+P3_OFFS, extended_len);
		offset += data_offs;

		if (p2 == 0) {
			/* GSM ALGORITHM */
			proto_tree_add_item(sim_tree, hf_auth_gsm_rand, tvb, offset, 16, ENC_NA);
			offset += 16;
		} else {
			dissect_auth_challenge(p2 & 0x07, tvb, sim_tree, offset, p3);
			offset += p3;
		}
		if (tvb_reported_length_remaining(tvb, offset)) {
			dissect_apdu_le(sim_tree, tvb, offset, extended_len, false);
			offset += (extended_len ? 2 : 1);
		}
		break;
	case 0x10: /* TERMINAL PROFILE */
		dissect_apdu_lc(sim_tree, tvb, offset+P3_OFFS, extended_len);
		offset += data_offs;
		start_offset = offset;
		ADD_TP_BYTE(1);
		ADD_TP_BYTE(2);
		ADD_TP_BYTE(3);
		ADD_TP_BYTE(4);
		ADD_TP_BYTE(5);
		ADD_TP_BYTE(6);
		ADD_TP_BYTE(7);
		ADD_TP_BYTE(8);
		ADD_TP_BYTE(9);
		ADD_TP_BYTE(10);
		ADD_TP_BYTE(11);
		ADD_TP_BYTE(12);
		ADD_TP_BYTE(13);
		ADD_TP_BYTE(14);
		ADD_TP_BYTE(15);
		ADD_TP_BYTE(16);
		ADD_TP_BYTE(17);
		ADD_TP_BYTE(18);
		ADD_TP_BYTE(19);
		ADD_TP_BYTE(20);
		ADD_TP_BYTE(21);
		ADD_TP_BYTE(22);
		ADD_TP_BYTE(23);
		ADD_TP_BYTE(24);
		ADD_TP_BYTE(25);
		ADD_TP_BYTE(26);
		ADD_TP_BYTE(27);
		ADD_TP_BYTE(28);
		ADD_TP_BYTE(29);
		ADD_TP_BYTE(30);
		ADD_TP_BYTE(31);
		ADD_TP_BYTE(32);
		ADD_TP_BYTE(33);
		ADD_TP_BYTE(34);
		ADD_TP_BYTE(35);
		ADD_TP_BYTE(36);
		ADD_TP_BYTE(37);
		ADD_TP_BYTE(38);
		ADD_TP_BYTE(39);
		while ((offset - start_offset) < p3) {
			proto_tree_add_item(sim_tree, hf_tprof_unknown_byte, tvb, offset++, 1, ENC_BIG_ENDIAN);
		}
		break;
	case 0x14: /* TERMINAL RESPONSE */
		dissect_apdu_lc(sim_tree, tvb, offset+P3_OFFS, extended_len);
		subtvb = tvb_new_subset_length(tvb, offset+data_offs, p3);
		call_dissector_with_data(sub_handle_cap, subtvb, pinfo, tree, GUINT_TO_POINTER(0x14));
		proto_tree_add_item(sim_tree, hf_apdu_data, tvb, offset+data_offs, p3, ENC_NA);
		offset += data_offs + p3;
		break;
	case 0x70: /* MANAGE CHANNEL */
		if (tvb_reported_length_remaining(tvb, offset+P3_OFFS)) {
			dissect_apdu_le(sim_tree, tvb, offset+P3_OFFS, extended_len, true);
		}
		offset += data_offs;
		break;
	case 0xC2: /* ENVELOPE */
		dissect_apdu_lc(sim_tree, tvb, offset+P3_OFFS, extended_len);
		subtvb = tvb_new_subset_length(tvb, offset+data_offs, p3);
		dissect_bertlv(subtvb, pinfo, sim_tree, tree);
		proto_tree_add_item(sim_tree, hf_apdu_data, tvb, offset+data_offs, p3, ENC_NA);
		offset += data_offs + p3;
		if (tvb_reported_length_remaining(tvb, offset)) {
			dissect_apdu_le(sim_tree, tvb, offset, extended_len, false);
			offset += (extended_len ? 2 : 1);
		}
		break;
	case 0x76: /* SUSPEND UICC */
		dissect_apdu_lc(sim_tree, tvb, offset+P3_OFFS, extended_len);
		if ((p1 & 0x01) == 0x00) {
			/* Suspend the UICC */
			col_append_str(pinfo->cinfo, COL_INFO, "(suspend) ");
			proto_tree_add_item(sim_tree, hf_suspend_uicc_min_time_unit, tvb, offset+data_offs, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(sim_tree, hf_suspend_uicc_min_time_length, tvb, offset+data_offs+1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(sim_tree, hf_suspend_uicc_max_time_unit, tvb, offset+data_offs+2, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(sim_tree, hf_suspend_uicc_max_time_length, tvb, offset+data_offs+3, 1, ENC_BIG_ENDIAN);
			dissect_apdu_le(sim_tree, tvb, offset+data_offs+4, extended_len, false);
			offset += (extended_len ? 2 : 1);
		} else {
			/* Resume the UICC */
			col_append_str(pinfo->cinfo, COL_INFO, "(resume) ");
			proto_tree_add_item(sim_tree, hf_suspend_uicc_resume_token, tvb, offset+data_offs, p3, ENC_NA);
		}
		offset += data_offs + p3;
		break;
	case 0xE2: /* STORE DATA */
		dissect_apdu_lc(sim_tree, tvb, offset+P3_OFFS, extended_len);
		subtvb = tvb_new_subset_length(tvb, offset+data_offs, p3);
		if (((p1 & 0x78) == 0x10) && is_sgp32_request(subtvb)) {
			dissect_sgp32_request(subtvb, pinfo, tree, NULL);
		}
		proto_tree_add_item(sim_tree, hf_apdu_data, tvb, offset+data_offs, p3, ENC_NA);
		offset += data_offs + p3;
		if (p1 & 0x80) {
			/* Le is mandatory for "Last block" and not present for "More blocks" */
			dissect_apdu_le(sim_tree, tvb, offset, extended_len, false);
			offset += (extended_len ? 2 : 1);
		}
		break;
	case 0x04: /* INVALIDATE */
	case 0x44: /* REHABILITATE */
	case 0xFA: /* SLEEP */
		/* FIXME: parse command */
	default:
		return -1;
	}

	return offset;
}

static int
dissect_rsp_apdu_tvb(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, proto_tree *sim_tree)
{
	uint16_t sw;
	proto_item *ti = NULL;
	unsigned tvb_len = tvb_reported_length(tvb);
	gsm_sim_transaction_t *gsm_sim_trans = NULL;
	wmem_tree_key_t key[4];
	uint32_t interface_id = 0;
	uint32_t layer_num = pinfo->curr_layer_num;
	uint32_t frame_num = pinfo->num;
	uint8_t ins = 0x00;
	uint8_t p1 = 0x00;
	uint8_t p2 = 0x00;
	bool response_only = true;

	/* Structure of response APDU: [Data] SW1 SW2 */

	if (!sim_tree) {
		ti = proto_tree_add_item(tree, proto_gsm_sim, tvb, 0, -1, ENC_NA);
		sim_tree = proto_item_add_subtree(ti, ett_sim);
	}

	if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID) {
		interface_id = pinfo->rec->rec_header.packet_header.interface_id;
	}

	key[0].length = 1;
	key[0].key = &interface_id;
	key[1].length = 1;
	key[1].key = &layer_num;
	key[2].length = 1;
	key[2].key = &frame_num;
	key[3].length = 0;
	key[3].key = NULL;

	/* Receive the largest key that is less than or equal to our frame number */
	gsm_sim_trans = (gsm_sim_transaction_t *)wmem_tree_lookup32_array_le(transactions, key);
	if (!PINFO_FD_VISITED(pinfo) && gsm_sim_trans && gsm_sim_trans->rsp_frame == 0) {
		if (gsm_sim_trans->cmd_ins == 0xC0) { /* GET RESPONSE */
			/* Make a reference to the first APDU this GET RESPONSE is related to */
			gsm_sim_transaction_t *prev_trans;
			frame_num = gsm_sim_trans->cmd_frame - 1;
			prev_trans = (gsm_sim_transaction_t *)wmem_tree_lookup32_array_le(transactions, key);
			if (prev_trans) {
				gsm_sim_trans->related_trans = prev_trans->related_trans;
			}
		}
		gsm_sim_trans->rsp_frame = pinfo->num;
	}

	if ((tvb_len-offset) > 2) {
		tvbuff_t *subtvb;
		unsigned apdu_len;
		uint8_t apdu_ins;

		/* Use INS, P1 and P2 from the command */
		if (gsm_sim_trans && gsm_sim_trans->rsp_frame == pinfo->num) {
			ins = gsm_sim_trans->cmd_ins;
			p1 = gsm_sim_trans->cmd_p1;
			p2 = gsm_sim_trans->cmd_p2;
		}

		apdu_len = tvb_len - offset - 2;
		apdu_ins = ins;

		subtvb = gsm_sim_apdu_reassemble(tvb, offset, pinfo, gsm_sim_trans, sim_tree, &apdu_ins, &p1, &p2);

		switch (apdu_ins) {
		case 0x12: /* FETCH */
			dissect_bertlv(subtvb, pinfo, sim_tree, tree);
			proto_tree_add_item(sim_tree, hf_apdu_data, tvb, offset, apdu_len, ENC_NA);
			response_only = false;
			break;
		case 0x76: /* SUSPEND UICC */
			proto_tree_add_item(sim_tree, hf_suspend_uicc_max_time_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(sim_tree, hf_suspend_uicc_max_time_length, tvb, offset+1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(sim_tree, hf_suspend_uicc_resume_token, tvb, offset+2, apdu_len - 2, ENC_NA);
			break;
		case 0x88: /* RUN GSM ALGORITHM / AUTHENTICATE */
			if (p2 == 0) {
				/* GSM ALGORITHM */
				proto_tree_add_item(sim_tree, hf_auth_gsm_sres, tvb, offset, 4, ENC_NA);
				proto_tree_add_item(sim_tree, hf_auth_gsm_kc, tvb, offset+4, 8, ENC_NA);
			} else {
				dissect_auth_response(p2 & 0x07, tvb, sim_tree, offset, apdu_len);
			}
			break;
		case 0xE2: /* STORE DATA */
			if (((p1 & 0x78) == 0x10) && is_sgp32_response(subtvb)) {
				dissect_sgp32_response(subtvb, pinfo, tree, NULL);
			}
			proto_tree_add_item(sim_tree, hf_apdu_data, tvb, offset, apdu_len, ENC_NA);
			break;
		case 0xF2: /* STATUS */
		case 0xA4: /* SELECT */
			/* FIXME: parse response */
		default:
			proto_tree_add_item(sim_tree, hf_apdu_data, tvb, offset, apdu_len, ENC_NA);
			break;
		}
	}
	offset = tvb_len - 2;

	/* obtain status word */
	sw = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint_format_value(sim_tree, hf_apdu_sw, tvb, offset, 2, sw,
					 "%04x %s", sw, get_sw_string(pinfo->pool, sw));
	/* XXX - Add a PI_RESPONSE_CODE expert info for a non normal sw */

	offset += 2;

	if (ti) {
		/* Always show status in info column when response only */
		if (response_only && ins) {
			col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ", "Response, %s, %s",
				     val_to_str(pinfo->pool, ins, apdu_ins_vals, "%02x"), get_sw_string(pinfo->pool, sw));
		} else if (response_only) {
			col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ", "Response, %s ", get_sw_string(pinfo->pool, sw));
		}
	} else {
		switch (sw >> 8) {
		case 0x90:
		case 0x91:
		case 0x92:
		case 0x9e:
		case 0x9f:
			break;
		default:
			col_append_fstr(pinfo->cinfo, COL_INFO, ": %s ", get_sw_string(pinfo->pool, sw));
			break;
		}
	}

	if (gsm_sim_trans && gsm_sim_trans->rsp_frame == pinfo->num) {
		nstime_t ns;

		if (gsm_sim_trans != gsm_sim_trans->related_trans) {
			ti = proto_tree_add_uint(sim_tree, hf_related_to, NULL, 0, 0,
						 gsm_sim_trans->related_trans->cmd_frame);
			proto_item_set_generated(ti);
		}

		if (gsm_sim_trans->cmd_frame != gsm_sim_trans->rsp_frame) {
			ti = proto_tree_add_uint(sim_tree, hf_response_to, NULL, 0, 0, gsm_sim_trans->cmd_frame);
			proto_item_set_generated(ti);

			nstime_delta(&ns, &pinfo->fd->abs_ts, &gsm_sim_trans->cmd_time);
			ti = proto_tree_add_time(sim_tree, hf_response_time, NULL, 0, 0, &ns);
			proto_item_set_generated(ti);
		}
	}

	return offset;
}

static int
dissect_cmd_apdu_tvb(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, bool isSIMtrace)
{
	uint8_t cla, ins, p1, p2;
	uint16_t p3;
	bool p3_present;
	bool extended_len = false;
	proto_item *ti;
	proto_tree *sim_tree;
	int rc = -1;
	gsm_sim_transaction_t *gsm_sim_trans;
	wmem_tree_key_t key[4];
	uint32_t interface_id = 0;
	uint32_t layer_num = pinfo->curr_layer_num;

	/* Structure of command APDU: CLA INS P1 P2 [Lc] [Data] [Le]
	 *
	 * Case 1: CLA INS P1 P2
	 * Case 2: CLA INS P1 P2 Le
	 * Case 3: CLA INS P1 P2 Lc Data
	 * Case 4: CLA INS P1 P2 Lc Data Le
	 */

	cla = tvb_get_uint8(tvb, offset);
	ins = tvb_get_uint8(tvb, offset+1);
	p1 = tvb_get_uint8(tvb, offset+2);
	p2 = tvb_get_uint8(tvb, offset+3);

	/* If isSIMtrace is true, then the tvb contains the command followed by
	 * the response. The response consists of response data followed by the
	 * 2 octet status word. Slice off the status word first.
	 */
	tvbuff_t *next_tvb = tvb;
	if (isSIMtrace) {
		/* We already retrieved ins, p1, p2, so tvb_len > 2 */
		next_tvb = tvb_new_subset_length(tvb, 0, tvb_reported_length(tvb) - 2);
	}

	if (tvb_reported_length_remaining(next_tvb, offset+4) >= 1) {
		p3 = tvb_get_uint8(next_tvb, offset+4);
		p3_present = true;

		if (p3 == 0 && tvb_reported_length_remaining(next_tvb, offset+5) >= 2) {
			/* Extended length */
			p3 = tvb_get_uint16(next_tvb, offset+5, ENC_BIG_ENDIAN);
			extended_len = true;
		}
	} else {
		/* Parameter 3 not present. */
		p3 = 0;
		p3_present = false;
	}

	if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID) {
		interface_id = pinfo->rec->rec_header.packet_header.interface_id;
	}

	key[0].length = 1;
	key[0].key = &interface_id;
	key[1].length = 1;
	key[1].key = &layer_num;
	key[2].length = 1;
	key[2].key = &pinfo->num;
	key[3].length = 0;
	key[3].key = NULL;

	if (PINFO_FD_VISITED(pinfo)) {
		gsm_sim_trans = (gsm_sim_transaction_t *)wmem_tree_lookup32_array(transactions, key);
	} else {
		/* This is the first time we see this packet, so create a new transaction */
		gsm_sim_trans = wmem_new(wmem_file_scope(), gsm_sim_transaction_t);
		gsm_sim_trans->cmd_frame = pinfo->num;
		gsm_sim_trans->rsp_frame = 0;
		gsm_sim_trans->cmd_time = pinfo->fd->abs_ts;
		gsm_sim_trans->cmd_ins = ins;
		gsm_sim_trans->cmd_p1 = p1;
		gsm_sim_trans->cmd_p2 = p2;
		gsm_sim_trans->related_trans = gsm_sim_trans; /* Default to self */

		wmem_tree_insert32_array(transactions, key, gsm_sim_trans);
	}

	ti = proto_tree_add_item(tree, proto_gsm_sim, tvb, 0, -1, ENC_NA);
	sim_tree = proto_item_add_subtree(ti, ett_sim);

	if ((cla & 0x50) == 0x40) {
		proto_tree_add_item(sim_tree, hf_apdu_cla_coding_ext, next_tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_apdu_cla_secure_messaging_ind_ext, next_tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_apdu_cla_log_chan_ext, next_tvb, offset, 1, ENC_BIG_ENDIAN);
	} else {
		proto_tree_add_item(sim_tree, hf_apdu_cla_coding, next_tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_apdu_cla_secure_messaging_ind, next_tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_apdu_cla_log_chan, next_tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	proto_tree_add_item(sim_tree, hf_apdu_ins, next_tvb, offset+1, 1, ENC_BIG_ENDIAN);
	offset += 2;

	if ((cla & 0x50) == 0x40) {
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ", "%s ",
				val_to_str(pinfo->pool, cla>>6, apdu_cla_coding_ext_vals, "%01x"));
	} else {
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ", "%s ",
				val_to_str(pinfo->pool, cla>>4, apdu_cla_coding_vals, "%01x"));
	}

	rc = dissect_gsm_apdu(ins, p1, p2, p3, extended_len, next_tvb, offset, pinfo, tree, sim_tree);

	if (rc == -1) {
		/* default dissector */
		offset += 2; /* P1 and P2 already handled */
		if (p3_present) {
			if (isSIMtrace) {
				/* For SIMtrace it's not possible to know if the APDU contains
				 * command "Lc Data" or command "Le" with response "Data".
				 */
				proto_tree_add_item(sim_tree, hf_apdu_p3, tvb, offset,
						    extended_len ? 3 : 1, ENC_BIG_ENDIAN);
				offset += (extended_len ? 3 : 1);
			} else if (tvb_reported_length_remaining(tvb, offset) <= (extended_len ? 3 : 1)) {
				/* Case 2 / 2E */
				dissect_apdu_le(sim_tree, tvb, offset, extended_len, true);
				offset += (extended_len ? 3 : 1);
			} else {
				/* Case 3 / 3E */
				dissect_apdu_lc(sim_tree, tvb, offset, extended_len);
				offset += (extended_len ? 3 : 1);
				proto_tree_add_item(sim_tree, hf_apdu_data, tvb, offset, p3, ENC_NA);
				offset += p3;
				if (tvb_reported_length_remaining(tvb, offset)) {
					/* Case 4 / 4E */
					dissect_apdu_le(sim_tree, tvb, offset, extended_len, false);
					offset += (extended_len ? 2 : 1);
				}
			}
		}
	} else {
		offset = rc;
	}

	if (isSIMtrace) {
		return dissect_rsp_apdu_tvb(tvb, offset, pinfo, tree, sim_tree);
	}

	if (tvb_reported_length_remaining(tvb, offset)) {
		ti = proto_tree_add_item(sim_tree, hf_apdu_unknown, tvb, offset,
					 tvb_reported_length_remaining(tvb, offset), ENC_NA);
		expert_add_info(pinfo, ti, &ei_unknown_bytes);
	}

	if (gsm_sim_trans && gsm_sim_trans->cmd_frame == pinfo->num && gsm_sim_trans->rsp_frame != 0) {

		if (gsm_sim_trans != gsm_sim_trans->related_trans) {
			ti = proto_tree_add_uint(sim_tree, hf_related_to, NULL, 0, 0,
						 gsm_sim_trans->related_trans->cmd_frame);
			proto_item_set_generated(ti);
		}

		ti = proto_tree_add_uint(sim_tree, hf_response_in, NULL, 0, 0, gsm_sim_trans->rsp_frame);
		proto_item_set_generated(ti);
	}

	return offset;
}

static int
dissect_gsm_sim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSM SIM");
	dissect_cmd_apdu_tvb(tvb, 0, pinfo, tree, true);
	return tvb_captured_length(tvb);
}

static int
dissect_gsm_sim_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSM SIM");
	dissect_cmd_apdu_tvb(tvb, 0, pinfo, tree, false);
	return tvb_captured_length(tvb);
}

static int
dissect_gsm_sim_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSM SIM");
	dissect_rsp_apdu_tvb(tvb, 0, pinfo, tree, NULL);
	return tvb_captured_length(tvb);
}

static int
dissect_gsm_sim_part(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	if (pinfo->p2p_dir == P2P_DIR_SENT)
		return dissect_gsm_sim_command(tvb, pinfo, tree, data);
	else if (pinfo->p2p_dir == P2P_DIR_RECV)
		return dissect_gsm_sim_response(tvb, pinfo, tree, data);

	return 0;
}

void
proto_register_gsm_sim(void)
{
	static hf_register_info hf[] = {
		{ &hf_apdu_cla_coding,
			{ "Class Coding", "gsm_sim.apdu.cla.coding",
			  FT_UINT8, BASE_HEX, VALS(apdu_cla_coding_vals), 0xf0,
			  "ISO 7816-4 APDU CLA (Class) Byte", HFILL }
		},
		{ &hf_apdu_cla_coding_ext,
			{ "Class Coding", "gsm_sim.apdu.cla.coding",
			  FT_UINT8, BASE_HEX, VALS(apdu_cla_coding_ext_vals), 0xc0,
			  "ISO 7816-4 APDU CLA (Class) Byte", HFILL }
		},
		{ &hf_apdu_cla_secure_messaging_ind,
			{ "Secure Messaging Indication", "gsm_sim.apdu.cla.secure_messaging_ind",
			  FT_UINT8, BASE_HEX, VALS(apdu_cla_secure_messaging_ind_vals), 0x0c,
			  "ISO 7816-4 APDU CLA (Class) Byte", HFILL }
		},
		{ &hf_apdu_cla_secure_messaging_ind_ext,
			{ "Secure Messaging Indication", "gsm_sim.apdu.cla.secure_messaging_ind.ext",
			  FT_BOOLEAN, 8, TFS(&apdu_cla_secure_messaging_ind_ext_val), 0x20,
			  "ISO 7816-4 APDU CLA (Class) Byte", HFILL }
		},
		{ &hf_apdu_cla_log_chan,
			{ "Logical Channel number", "gsm_sim.apdu.cla.log_chan",
			  FT_UINT8, BASE_DEC, NULL, 0x03,
			  "ISO 7816-4 APDU CLA (Class) Byte", HFILL }
		},
		{ &hf_apdu_cla_log_chan_ext,
			{ "Logical Channel number", "gsm_sim.apdu.cla.log_chan",
			  FT_UINT8, BASE_DEC, NULL, 0x0f,
			  "ISO 7816-4 APDU CLA (Class) Byte", HFILL }
		},
		{ &hf_apdu_ins,
			{ "Instruction", "gsm_sim.apdu.ins",
			  FT_UINT8, BASE_HEX, VALS(apdu_ins_vals), 0,
			  "ISO 7816-4 APDU INS (Instruction) Byte", HFILL }
		},
		{ &hf_apdu_p1,
			{ "Parameter 1", "gsm_sim.apdu.p1",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  "ISO 7816-4 APDU P1 (Parameter 1) Byte", HFILL }
		},
		{ &hf_apdu_p2,
			{ "Parameter 2", "gsm_sim.apdu.p2",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  "ISO 7816-4 APDU P2 (Parameter 2) Byte", HFILL }
		},
		{ &hf_apdu_p3,
			{ "Length (Parameter 3)", "gsm_sim.apdu.p3",
			 FT_UINT24, BASE_DEC, NULL, 0,
			 "ISO 7816-4 APDU P3 (Parameter 3) Byte", HFILL }
		},
		{ &hf_apdu_data,
			{ "APDU Payload", "gsm_sim.apdu.data",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "ISO 7816-4 APDU Data Payload", HFILL }
		},
		{ &hf_apdu_sw,
			{ "Status Word", "gsm_sim.apdu.sw",
			  FT_UINT16, BASE_HEX, VALS(sw_vals), 0,
			  "ISO 7816-4 APDU Status Word", HFILL }
		},
		{ &hf_apdu_unknown,
			{ "Unknown APDU Bytes", "gsm_sim.apdu.unknown",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_file_id,
			{ "File ID", "gsm_sim.file_id",
			  FT_UINT16, BASE_HEX, VALS(mf_dfs), 0,
			  "ISO 7816-4 File ID", HFILL }
		},
		{ &hf_aid,
			{ "Application ID", "gsm_sim.aid",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "ISO 7816-4 Application ID", HFILL }
		},
		{ &hf_bin_offset,
			{ "Offset", "gsm_sim.bin_offset",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  "Offset into binary file", HFILL }
		},
		{ &hf_referencing,
			{ "Referencing", "gsm_sim.referencing",
			  FT_UINT8, BASE_HEX, VALS(sfi_referencing_vals), 0xe0,
			  NULL, HFILL }
		},
		{ &hf_sfi,
			{ "SFI", "gsm_sim.sfi",
			  FT_UINT8, BASE_HEX, VALS(sfi_vals), 0x1f,
			  NULL, HFILL }
		},
		{ &hf_record_nr,
			{ "Record Number", "gsm_sim.record_nr",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_record_id,
			{ "Record Identifier", "gsm_sim.record_id",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL },
		},
		{ &hf_record_file,
			{ "File", "gsm_sim.record_file",
			FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS, VALS(record_file_vals), 0xF8,
			NULL, HFILL }
		},
		{ &hf_record_mode,
			{ "Mode", "gsm_sim.record_mode",
			FT_UINT8, BASE_HEX, VALS(record_mode_vals), 0x07,
			NULL, HFILL }
		},
		{ &hf_store_data_block,
			{ "Block chaining", "gsm_sim.store_data.block_chaining",
			  FT_BOOLEAN, 8, TFS(&store_data_block_tfs), 0x80,
			  "More/Last block", HFILL }
		},
		{ &hf_store_data_encryption,
			{ "Encryption", "gsm_sim.store_data.encryption",
			  FT_UINT8, BASE_HEX, VALS(store_data_encryption_vals), 0x60,
			  "General encryption information", HFILL }
		},
		{ &hf_store_data_structure,
			{ "Data structure", "gsm_sim.store_data.data_structure",
			  FT_UINT8, BASE_HEX, VALS(store_data_structure_vals), 0x18,
			  "General data structure information", HFILL }
		},
		{ &hf_store_data_rfu,
			{ "RFU", "gsm_sim.store_data.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0x06,
			  "Reserved for Future Use", HFILL }
		},
		{ &hf_store_data_iso_case,
			{ "ISO case", "gsm_sim.store_data.iso_case",
			  FT_BOOLEAN, 8, TFS(&store_data_iso_case_tfs), 0x01,
			  "ISO case 3/4 command indicator", HFILL }
		},
		{ &hf_store_data_block_nr,
			{ "Block number", "gsm_sim.store_data.block_nr",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_auth_reference,
			{ "Reference", "gsm_sim.auth_reference",
			  FT_BOOLEAN, 8, TFS(&apdu_auth_reference_val), 0x80,
			  "Authentication Reference", HFILL }
		},
		{ &hf_auth_rfu,
			{ "RFU", "gsm_sim.auth_rfu",
			  FT_UINT8, BASE_DEC, NULL, 0x78,
			  "Reserved for Future Use", HFILL }
		},
		{ &hf_auth_context,
			{ "Context", "gsm_sim.auth_context",
			  FT_UINT8, BASE_DEC, VALS(apdu_auth_context_vals), 0x07,
			  "Authentication Context", HFILL }
		},
		{ &hf_auth_challenge,
			{ "Challenge", "gsm_sim.auth_challenge",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "Authentication Challenge", HFILL }
		},
		{ &hf_auth_response,
			{ "Response", "gsm_sim.auth_response",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "Authentication Response", HFILL }
		},
		{ &hf_auth_rand_len,
			{ "Length of RAND", "gsm_sim.auth_rand_len",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "Length of Random Challenge", HFILL }
		},
		{ &hf_auth_rand,
			{ "RAND", "gsm_sim.auth_rand",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "Random Challenge", HFILL }
		},
		{ &hf_auth_autn_len,
			{ "Length of AUTN", "gsm_sim.auth_autn_len",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "Authentication Token Length", HFILL }
		},
		{ &hf_auth_autn,
			{ "AUTN", "gsm_sim.auth_autn",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "Authentication Token", HFILL }
		},
		{ &hf_auth_status,
			{ "Status", "gsm_sim.auth_status",
			  FT_UINT8, BASE_HEX, VALS(apdu_auth_status_vals), 0,
			  "Authentication Status", HFILL }
		},
		{ &hf_auth_res_len,
			{ "Length of RES", "gsm_sim.auth_res_len",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "Length of Response", HFILL }
		},
		{ &hf_auth_res,
			{ "RES", "gsm_sim.auth_res",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "Response", HFILL }
		},
		{ &hf_auth_ck_len,
			{ "Length of CK", "gsm_sim.auth_ck_len",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_auth_ck,
			{ "CK", "gsm_sim.auth_ck",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_auth_ik_len,
			{ "Length of IK", "gsm_sim.auth_ik_len",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_auth_ik,
			{ "IK", "gsm_sim.auth_ik",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_auth_kc_len,
			{ "Length of Kc", "gsm_sim.auth_kc_len",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_auth_kc,
			{ "Kc", "gsm_sim.auth_kc",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_auth_auts_len,
			{ "Length of AUTS", "gsm_sim.auth_auts_len",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_auth_auts,
			{ "AUTS", "gsm_sim.auth_auts",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_auth_gsm_rand,
			{ "Random Challenge", "gsm_sim.auth_rand",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "GSM Authentication Random Challenge", HFILL }
		},
		{ &hf_auth_gsm_sres_len,
			{ "Length of SRES", "gsm_sim.auth_sres_len",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_auth_gsm_sres,
			{ "SRES", "gsm_sim.auth_sres",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "GSM Authentication SRES Response", HFILL }
		},
		{ &hf_auth_gsm_kc_len,
			{ "Length of Kc", "gsm_sim.auth_kc_len",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_auth_gsm_kc,
			{ "Kc", "gsm_sim.auth_kc",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "GSM Authentication Kc result", HFILL }
		},
		{ &hf_chan_nr,
			{ "Channel Number", "gsm_sim.chan_nr",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "ISO 7816-4 Logical Channel Number", HFILL }
		},
		{ &hf_apdu_le,
			{ "Maximum Length of Expected Response", "gsm_sim.apdu.le",
			  FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS, VALS(apdu_le_vals), 0,
			  "ISO 7816-4 APDU Le Byte", HFILL }
		},
		{ &hf_apdu_le_ext,
			{ "Maximum Length of Expected Response", "gsm_sim.apdu.le",
			  FT_UINT24, BASE_DEC|BASE_SPECIAL_VALS, VALS(apdu_le_vals_ext), 0,
			  "ISO 7816-4 APDU Le Bytes - Extended", HFILL }
		},
		{ &hf_apdu_lc,
			{ "Length of Command", "gsm_sim.apdu.lc",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "ISO 7816-4 APDU Lc Byte", HFILL }
		},
		{ &hf_apdu_lc_ext,
			{ "Length of Command", "gsm_sim.apdu.lc",
			  FT_UINT24, BASE_DEC, NULL, 0,
			  "ISO 7816-4 APDU Lc Bytes - Extended", HFILL }
		},
		{ &hf_chan_op,
			{ "Channel Operation", "gsm_sim.chan_op",
			  FT_UINT8, BASE_HEX, VALS(chan_op_vals), 0,
			  "ISO 7816-4 Logical Channel Operation", HFILL }
		},
		{ &hf_select_type,
			{ "Type", "gsm_sim.select.type",
			  FT_UINT8, BASE_HEX, VALS(select_type_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_select_session_control,
			{ "Session Control", "gsm_sim.select.session_control",
			  FT_UINT8, BASE_HEX, VALS(select_session_control_vals), 0x60,
			  NULL, HFILL }
		},
		{ &hf_select_unused_p2,
			{ "Unused", "gsm_sim.select.unused",
			  FT_UINT8, BASE_HEX, NULL, 0x60,
			  NULL, HFILL }
		},
		{ &hf_select_return_data,
			{ "Return Data", "gsm_sim.select.return_data",
			  FT_UINT8, BASE_HEX, VALS(select_return_data_vals), 0x9C,
			  NULL, HFILL }
		},
		{ &hf_select_selection,
			{ "Selection", "gsm_sim.select.selection",
			  FT_UINT8, BASE_HEX, VALS(select_selection_vals), 0x03,
			  NULL, HFILL }
		},
		{ &hf_status_application_status,
			{ "Application Status", "gsm_sim.status.application_status",
			  FT_UINT8, BASE_HEX, VALS(status_application_status_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_status_return_data,
			{ "Return Data", "gsm_sim.status.return_data",
			  FT_UINT8, BASE_HEX, VALS(status_return_data_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_suspend_uicc_op,
			{ "Suspend Operation", "gsm_sim.suspend_uicc.op",
			  FT_UINT8, BASE_HEX, VALS(suspend_uicc_vals), 0,
			  "ISO 7816-4 Suspend UICC Operation", HFILL }
		},
		{ &hf_suspend_uicc_min_time_unit,
			{ "Minimum Time Unit", "gsm_sim.suspend_uicc.min_time_unit",
			  FT_UINT8, BASE_HEX, VALS(suspend_time_unit_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_suspend_uicc_min_time_length,
			{ "Minimum Length of Time", "gsm_sim.suspend_uicc.min_time_length",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "Length of time, expressed in units", HFILL }
		},
		{ &hf_suspend_uicc_max_time_unit,
			{ "Maximum Time Unit", "gsm_sim.suspend_uicc.max_time_unit",
			  FT_UINT8, BASE_HEX, VALS(suspend_time_unit_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_suspend_uicc_max_time_length,
			{ "Maximum Length of Time", "gsm_sim.suspend_uicc.max_time_length",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "Length of time, expressed in units", HFILL }
		},
		{ &hf_suspend_uicc_resume_token,
			{ "Resume Token", "gsm_sim.suspend_uicc.resume_token",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 1 */
		{ &hf_tprof_b1,
			{ "Terminal Profile Byte 1 (Download)", "gsm_sim.tp.b1",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_prof_dld,
			{ "Profile Download", "gsm_sim.tp.prof_dld",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  "TP Profile Download", HFILL }
		},
		{ &hf_tp_sms_data_dld,
			{ "SMS-PP Data Download", "gsm_sim.tp.sms_data_dld",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  "TP SMS-PP Data Download", HFILL }
		},
		{ &hf_tp_cb_data_dld,
			{ "CB Data Download", "gsm_sim.tp.cb_data_dld",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  "TP Cell Broadcast Data Download", HFILL }
		},
		{ &hf_tp_menu_sel,
			{ "Menu Selection", "gsm_sim.tp.menu_sel",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  "TP Menu Selection", HFILL }
		},
		{ &hf_tp_sms_data_dld_support,
			{ "SMS-PP data download is supported", "gsm_sim.tp.sms_data_dld_support",
			  FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
			  "TP SMS-PP data download is supported", HFILL }
		},
		{ &hf_tp_timer_exp,
			{ "Timer expiration", "gsm_sim.tp.timer_exp",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  "TP Timer expiration", HFILL }
		},
		{ &hf_tp_cc_sim_support,
			{ "Call Control by USIM is supported", "gsm_sim.tp.cc_sim_support",
			  FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
			  "TP Call Control by USIM is supported", HFILL }
		},
		{ &hf_tp_cc_sim_support2,
			{ "Call Control by USIM is supported", "gsm_sim.tp.cc_sim_support",
			  FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
			  "TP Call Control by USIM is supported", HFILL }
		},

		/* Terminal Profile Byte 2 */
		{ &hf_tprof_b2,
			{ "Terminal Profile Byte 2 (Other)", "gsm_sim.tp.b2",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_cmd_res,
			{ "Command result", "gsm_sim.tp.cmd_res",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  "TP Command result", HFILL }
		},
		{ &hf_tp_cc_sim,
			{ "Call Control by USIM", "gsm_sim.tp.cc_sim",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  "TP Call Control by SIM", HFILL }
		},
		{ &hf_tp_cc_sim_support3,
			{ "Call Control by USIM is supported", "gsm_sim.tp.cc_sim_support",
			  FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
			  "TP Call Control by USIM is supported", HFILL }
		},
		{ &hf_tp_mo_sms_sim,
			{ "MO SMS control by SIM", "gsm_sim.tp.mo_sms_sim",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  "TP MO short message control by SIM", HFILL }
		},
		{ &hf_tp_cc_sim_support4,
			{ "Call Control by USIM is supported", "gsm_sim.tp.cc_sim_support",
			  FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
			  "TP Call Control by USIM is supported", HFILL }
		},
		{ &hf_tp_ucs2_entry,
			{ "UCS2 Entry", "gsm_sim.tp.ucs2_entry",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  "TP UCS2 Entry", HFILL }
		},
		{ &hf_tp_ucs2_display,
			{ "UCS2 Display", "gsm_sim.tp.ucs2_display",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  "TP UCS2 Display", HFILL }
		},
		{ &hf_tp_display_ext,
			{ "Display of Extension Text", "gsm_sim.tp.display_ext",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  "TP Display of the Extension Text", HFILL }
		},

		/* Terminal Profile Byte 3 */
		{ &hf_tprof_b3,
			{ "Terminal Profile Byte 3 (Proactive SIM)", "gsm_sim.tp.b3",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_pa_display_text,
			{ "Proactive SIM: DISPLAY TEXT", "gsm_sim.tp.pa.display_text",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_get_inkey,
			{ "Proactive SIM: GET INKEY", "gsm_sim.tp.pa.get_inkey",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_get_input,
			{ "Proactive SIM: GET INPUT", "gsm_sim.tp.pa.get_input",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_more_time,
			{ "Proactive SIM: MORE TIME", "gsm_sim.tp.pa.more_time",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_play_tone,
			{ "Proactive SIM: PLAY TONE", "gsm_sim.tp.pa.play_tone",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_poll_intv,
			{ "Proactive SIM: POLL INTERVAL", "gsm_sim.tp.pa.poll_intv",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_polling_off,
			{ "Proactive SIM: POLLING OFF", "gsm_sim.tp.pa.polling_off",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_refresh,
			{ "Proactive SIM: REFRESH", "gsm_sim.tp.pa.refresh",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 4 */
		{ &hf_tprof_b4,
			{ "Terminal Profile Byte 4 (Proactive SIM)", "gsm_sim.tp.b4",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_pa_select_item,
			{ "Proactive SIM: SELECT ITEM", "gsm_sim.tp.pa.select_item",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_send_sms,
			{ "Proactive SIM: SEND SHORT MESSAGE", "gsm_sim.tp.pa.send_sms",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_send_ss,
			{ "Proactive SIM: SEND SS", "gsm_sim.tp.pa.send_ss",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_send_ussd,
			{ "Proactive SIM: SEND USSD", "gsm_sim.tp.pa.send_ussd",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_set_up_call,
			{ "Proactive SIM: SET UP CALL", "gsm_sim.tp.pa.set_up_call",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_set_up_menu,
			{ "Proactive SIM: SET UP MENU", "gsm_sim.tp.pa.set_up_menu",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION", "gsm_sim.tp.pa.prov_loci",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_nmr,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (NMR)", "gsm_sim.tp.pa.prov_loci_nmr",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 5 */
		{ &hf_tprof_b5,
			{ "Terminal Profile Byte 5 (Event driven information)", "gsm_sim.tp.b5",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_pa_evt_list,
			{ "Proactive SIM: SET UP EVENT LIST", "gsm_sim.tp.pa.set_up_evt_list",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_mt_call,
			{ "Event: MT call", "gsm_sim.tp.evt.mt_call",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_call_connected,
			{ "Event: Call connected", "gsm_sim.tp.evt.call_conn",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_call_disconnected,
			{ "Event: Call disconnected", "gsm_sim.tp.evt.call_disc",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_location_status,
			{ "Event: Location status", "gsm_sim.tp.evt.loc_status",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_user_activity,
			{ "Event: User activity", "gsm_sim.tp.evt.user_activity",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_idle_screen,
			{ "Event: Idle screen available", "gsm_sim.tp.evt.idle_screen",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_cardreader_status,
			{ "Event: Card reader status", "gsm_sim.tp.evt.card_status",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 6 */
		{ &hf_tprof_b6,
			{ "Terminal Profile Byte 6 (Event driven information extension)", "gsm_sim.tp.b6",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_ev_lang_sel,
			{ "Event: Language Selection", "gsm_sim.tp.evt.lang_sel",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_brows_term,
			{ "Event: Browser Termination", "gsm_sim.tp.evt.brows_term",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_data_avail,
			{ "Event: Data Available", "gsm_sim.tp.evt.data_avail",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_chan_status,
			{ "Event: Channel Status", "gsm_sim.tp.evt.chan_status",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_access_techno_change,
			{ "Event: Access Technology Change", "gsm_sim.tp.evt.access_techno_change",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_disp_params_changed,
			{ "Event: Display parameters changed", "gsm_sim.tp.evt.disp_params_changed",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_local_conn,
			{ "Event: Local Connection", "gsm_sim.tp.evt.local_conn",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_nwk_search_mode_change,
			{ "Event: Network Search Mode Change", "gsm_sim.tp.evt.nwk_search_mode_change",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 7 */
		{ &hf_tprof_b7,
			{ "Terminal Profile Byte 7 (Multiple card proactive commands)", "gsm_sim.tp.b7",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_pa_power_on,
			{ "Proactive SIM: POWER ON CARD", "gsm_sim.tp.pa.power_on_card",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_power_off,
			{ "Proactive SIM: POWER OFF CARD", "gsm_sim.tp.pa.power_off_card",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_perform_card_apdu,
			{ "Proactive SIM: PERFORM CARD APDU", "gsm_sim.tp.pa.perf_card_apdu",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_get_reader_status,
			{ "Proactive SIM: GET READER STATUS (status)", "gsm_sim.tp.pa.get_rdr_status",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_get_reader_status_id,
			{ "Proactive SIM: GET READER STATUS (identifier)", "gsm_sim.tp.pa.get_rdr_status_id",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_rfu,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0xe0,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 8 */
		{ &hf_tprof_b8,
			{ "Terminal Profile Byte 8 (Proactive SIM)", "gsm_sim.tp.b8",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_pa_timer_start_stop,
			{ "Proactive SIM: TIMER MANAGEMENT (start, stop)", "gsm_sim.tp.pa.timer_start_stop",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_timer_get_current,
			{ "Proactive SIM: TIMER MANAGEMENT (get current value)", "gsm_sim.tp.pa.timer_get_current",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_date_tz,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (date, time, tz)", "gsm_sim.tp.pa.prov_loci_date",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_get_inkey_binary,
			{ "Proactive SIM: GET INKEY", "gsm_sim.tp.pa.get_inkey_bin",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_set_up_idle_mode_text,
			{ "Proactive SIM: SET UP IDLE MODE TEXT", "gsm_sim.tp.pa.set_up_idle_text",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_run_at_command,
			{ "Proactive SIM: RUN AT COMMAND", "gsm_sim.tp.pa.run_at_command",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_2nd_alpha_setup_call,
			{ "Proactive SIM: SETUP CALL", "gsm_sim.tp.pa.2nd_alpha_id",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_2nd_cc_sim_support,
			{ "Proactive SIM: Call Control by USIM is supported", "gsm_sim.tp.pa.cc_sim_support",
			  FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 9 */
		{ &hf_tprof_b9,
			{ "Terminal Profile Byte 9", "gsm_sim.tp.b9",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_display_text,
			{ "DISPLAY TEXT", "gsm_sim.tp.display_text",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_send_dtmf_cmd,
			{ "SEND DTMF command", "gsm_sim.tp.send_dtmf_cmd",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_nmr2,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (NMR)", "gsm_sim.tp.pa.prov_loci_nmr",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_lang,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (language)", "gsm_sim.tp.pa.prov_loci_lang",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_ta,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (Timing Advance)", "gsm_sim.tp.pa.prov_loci_ta",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_lang_notif,
			{ "Proactive SIM: LANGUAGE NOTIFICATION", "gsm_sim.tp.pa.lang_notif",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_launch_browser,
			{ "Proactive SIM: LAUNCH BROWSER", "gsm_sim.tp.pa.launch_browser",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_access_techno,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (Access Technology)", "gsm_sim.tp.pa.prov_loci_access_techno",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 10 */
		{ &hf_tprof_b10,
			{ "Terminal Profile Byte 10 (Soft keys support)", "gsm_sim.tp.b10",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_soft_key_support_select_item,
			{ "Soft keys support for SELECT ITEM", "gsm_sim.tp.soft_key_support.select_item",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_soft_key_support_set_up_menu,
			{ "Soft Keys support for SET UP MENU", "gsm_sim.tp.soft_key_support.set_up_menu",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_rfu2,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0xfc,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 11 */
		{ &hf_tprof_b11,
			{ "Terminal Profile Byte 11 (Soft keys information)", "gsm_sim.tp.b11",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_soft_key_info_max_nb,
			{ "Maximum number of soft keys available", "gsm_sim.tp.soft_key_info.max_nb",
			  FT_UINT8, BASE_DEC, NULL, 0xff,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 12 */
		{ &hf_tprof_b12,
			{ "Terminal Profile Byte 12 (Bearer Independent protocol proactive commands, class \"e\")", "gsm_sim.tp.b12",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_pa_open_chan,
			{ "Proactive SIM: OPEN CHANNEL", "gsm_sim.tp.pa.open_chan",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_close_chan,
			{ "Proactive SIM: CLOSE CHANNEL", "gsm_sim.tp.pa.close_chan",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_recv_data,
			{ "Proactive SIM: RECEIVE DATA", "gsm_sim.tp.pa.recv_data",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_send_data,
			{ "Proactive SIM: SEND DATA", "gsm_sim.tp.pa.send_data",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_get_chan_status,
			{ "Proactive SIM: GET CHANNEL STATUS", "gsm_sim.tp.pa.get_chan_status",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_serv_search,
			{ "Proactive SIM: SERVICE SEARCH", "gsm_sim.tp.pa.serv_search",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_get_serv_info,
			{ "Proactive SIM: GET SERVICE INFORMATION", "gsm_sim.tp.pa.get_serv_info",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_decl_serv,
			{ "Proactive SIM: DECLARE SERVICE", "gsm_sim.tp.pa.decl_serv",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 13 */
		{ &hf_tprof_b13,
			{ "Terminal Profile Byte 13 (Bearer Independent protocol supported bearers, class \"e\")", "gsm_sim.tp.b13",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_bip_csd,
			{ "CSD bearer", "gsm_sim.tp.bip.csd",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_bip_gprs,
			{ "GPRS bearer", "gsm_sim.tp.bip.gprs",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_bip_bluetooth,
			{ "Bluetooth bearer", "gsm_sim.tp.bip.bluetooth",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_bip_irda,
			{ "IrDA bearer", "gsm_sim.tp.bip.irda",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_bip_rs232,
			{ "RS232 bearer", "gsm_sim.tp.bip.rs232",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_num_chans,
			{ "Number of Channels", "gsm_sim.tp.num_chans",
			  FT_UINT8, BASE_DEC, NULL, 0xe0,
			  NULL, HFILL }
		},


		/* Terminal Profile Byte 14 */
		{ &hf_tprof_b14,
			{ "Terminal Profile Byte 14 (Screen height)", "gsm_sim.tp.b14",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_char_height,
			{ "Display height (chars)", "gsm_sim.tp.display.height",
			  FT_UINT8, BASE_DEC, NULL, 0x1f,
			  NULL, HFILL },
		},
		{ &hf_tp_nd,
			{ "No display capability", "gsm_sim.tp.nd",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL },
		},
		{ &hf_tp_nk,
			{ "No keypad available", "gsm_sim.tp.nk",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL },
		},
		{ &hf_tp_sizing_supp,
			{ "Screen sizing parameters", "gsm_sim.tp.disp_sizing",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 15 */
		{ &hf_tprof_b15,
			{ "Terminal Profile Byte 15 (Screen width)", "gsm_sim.tp.b15",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_char_width,
			{ "Display width (chars)", "gsm_sim.tp.display.width",
			  FT_UINT8, BASE_DEC, NULL, 0x7f,
			  NULL, HFILL },
		},
		{ &hf_tp_var_fonts,
			{ "Variable size fonts", "gsm_sim.tp.var_fonts",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 16 */
		{ &hf_tprof_b16,
			{ "Terminal Profile Byte 16 (Screen effects)", "gsm_sim.tp.b16",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_display_resize,
			{ "Display resize", "gsm_sim.tp.display.resize",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL },
		},
		{ &hf_tp_text_wrapping,
			{ "Text Wrapping", "gsm_sim.tp.display.wrapping",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL },
		},
		{ &hf_tp_text_scrolling,
			{ "Text Scrolling", "gsm_sim.tp.display.scrolling",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL },
		},
		{ &hf_tp_text_attributes,
			{ "Text Attributes", "gsm_sim.tp.display.attributes",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL },
		},
		{ &hf_tp_rfu3,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0x10,
			  NULL, HFILL },
		},
		{ &hf_tp_width_red_menu,
			{ "Width reduction when in menu", "gsm_sim.tp.display.width_red_menu",
			  FT_UINT8, BASE_DEC, NULL, 0xe0,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 17 */
		{ &hf_tprof_b17,
			{ "Terminal Profile Byte 17 (Bearer independent protocol supported transport interface/bearers, class \"e\")", "gsm_sim.tp.b17",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_bip_tcp_remote,
			{ "TCP client mode remote connection", "gsm_sim.tp.bip.tcp_remote",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_bip_udp_remote,
			{ "UDP client mode remote connection", "gsm_sim.tp.bip.udp_remote",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_bip_tcp_server,
			{ "TCP server mode", "gsm_sim.tp.bip.tcp_server",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_bip_tcp_local,
			{ "TCP client mode local connection", "gsm_sim.tp.bip.tcp_local",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_bip_udp_local,
			{ "UDP client mode local connection", "gsm_sim.tp.bip.udp_local",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_bip_direct_com,
			{ "Direct communication channel", "gsm_sim.tp.bip.direct_com",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_bip_eutran,
			{ "E-UTRAN bearer", "gsm_sim.tp.bip.eutran",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_bip_hsdpa,
			{ "HSDPA bearer", "gsm_sim.tp.bip.hsdpa",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 18 */
		{ &hf_tprof_b18,
			{ "Terminal Profile Byte 18 (Bearer independent protocol)", "gsm_sim.tp.b18",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_pa_display_text_var_time_out,
			{ "Proactive SIM: DISPLAY TEXT (Variable Time out)", "gsm_sim.tp.pa.display_text_var_time_out",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_get_inkey_help,
			{ "Proactive SIM: GET INKEY (help is supported)", "gsm_sim.tp.pa.get_inkey_help",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_bip_usb,
			{ "USB bearer", "gsm_sim.tp.bip.usb",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_get_inkey_var_time_out,
			{ "Proactive SIM: GET INKEY (Variable Timeout)", "gsm_sim.tp.pa.get_inkey_var_time_out",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_esn,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (ESN)", "gsm_sim.tp.pa.prov_loci_esn",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_cc_gprs,
			{ "CALL CONTROL on GPRS", "gsm_sim.tp.cc_gprs",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_imeisv,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (IMEISV)", "gsm_sim.tp.pa.prov_loci_imeisv",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_search_mode_change,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (Search Mode change)", "gsm_sim.tp.pa.prov_loci_search_mode_change",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 19 */
		{ &hf_tprof_b19,
			{ "Terminal Profile Byte 19 (TIA/EIA-136-C facilities)", "gsm_sim.tp.b19",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_tia_eia_version,
			{ "TIA/EIA Version", "gsm_sim.tp.tia_eia_version",
			  FT_UINT8, BASE_DEC, NULL, 0x0f,
			  NULL, HFILL }
		},
		{ &hf_tp_rfu4,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0xf0,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 20 */
		{ &hf_tprof_b20,
			{ "Terminal Profile Byte 20 (TIA/EIA/IS-820-A facilities)", "gsm_sim.tp.b20",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_tia_iea_is820a_reserved,
			{ "Reserved", "gsm_sim.tp.tia_iea_is820a_reserved",
			  FT_UINT8, BASE_HEX, NULL, 0xff,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 21 */
		{ &hf_tprof_b21,
			{ "Terminal Profile Byte 21 (Extended Launch Browser Capability)", "gsm_sim.tp.b21",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_ext_launch_browser_wml,
			{ "WML", "gsm_sim.tp.ext_launch_browser.wml",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_ext_launch_browser_xhtml,
			{ "XHTML", "gsm_sim.tp.ext_launch_browser.xhtml",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_ext_launch_browser_html,
			{ "HTML", "gsm_sim.tp.ext_launch_browser.html",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_ext_launch_browser_chtml,
			{ "CHTML", "gsm_sim.tp.ext_launch_browser.chtml",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_rfu5,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0xf0,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 22 */
		{ &hf_tprof_b22,
			{ "Terminal Profile Byte 22", "gsm_sim.tp.b22",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_utran_ps_ext_params,
			{ "UTRAN PS with extended parameters", "gsm_sim.tp.utran_ps_ext_params",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_batt_state,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (battery state)", "gsm_sim.tp.pa.prov_loci_batt_state",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_play_tone_melody,
			{ "Proactive SIM: PLAY TONE (Melody tones and Themed tones supported)", "gsm_sim.tp.pa.play_tone_melody",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_mm_call_set_up_call,
			{ "Multi-media Calls in SET UP CALL", "gsm_sim.tp.mm_call_set_up_call",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_toolkit_initiated_gba,
			{ "Toolkit-initiated GBA", "gsm_sim.tp.toolkit_initiated_gba",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_retrieve_mm_msg,
			{ "Proactive SIM: RETRIEVE MULTIMEDIA MESSAGE", "gsm_sim.tp.pa.retrieve_mm_msg",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_submit_mm_msg,
			{ "Proactive SIM: SUBMIT MULTIMEDIA MESSAGE", "gsm_sim.tp.pa.submit_mm_msg",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_display_mm_msg,
			{ "Proactive SIM: DISPLAY MULTIMEDIA MESSAGE", "gsm_sim.tp.pa.display_mm_msg",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 23 */
		{ &hf_tprof_b23,
			{ "Terminal Profile Byte 23", "gsm_sim.tp.b23",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_pa_set_frames,
			{ "Proactive SIM: SET FRAMES", "gsm_sim.tp.pa.set_frames",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_get_frames_status,
			{ "Proactive SIM: GET FRAMES STATUS", "gsm_sim.tp.pa.get_frames_status",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_mms_notif_download,
			{ "MMS notification download", "gsm_sim.tp.mms_notif_download",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_alpha_id_refresh_cmd,
			{ "Alpha Identifier in REFRESH command", "gsm_sim.tp.alpha_id_refresh_cmd",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_geo_loc_report,
			{ "Geographical Location Reporting", "gsm_sim.tp.geo_loc_report",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_meid,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (MEID)", "gsm_sim.tp.pa.prov_loci_meid",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_nmr_utran_eutran,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (NMR(UTRAN/E-UTRAN))", "gsm_sim.tp.pa.prov_loci_nmr_utran_eutran",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_ussd_data_download,
			{ "USSD Data download and application mode", "gsm_sim.tp.ussd_data_download",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 24 */
		{ &hf_tprof_b24,
			{ "Terminal Profile Byte 24 (Class \"i\")", "gsm_sim.tp.b24",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_class_i_max_nb_frames,
			{ "Maximum number of frames supported", "gsm_sim.tp.class_i_max_nb_frames",
			  FT_UINT8, BASE_DEC, NULL, 0x0f,
			  NULL, HFILL }
		},
		{ &hf_tp_rfu6,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0xf0,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 25 */
		{ &hf_tprof_b25,
			{ "Terminal Profile Byte 25 (Event driven information extensions)", "gsm_sim.tp.b25",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_evt_browsing_status,
			{ "Event: Browsing status", "gsm_sim.tp.evt.browsing_status",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_mms_transfer_status,
			{ "Event: MMS Transfer status", "gsm_sim.tp.evt.mms_transfer_status",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_frame_info_changed,
			{ "Event: Frame Information changed", "gsm_sim.tp.evt.frame_info_changed",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_iwlan_access_status,
			{ "Event: I-WLAN Access status", "gsm_sim.tp.evt.iwlan_access_status",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_nw_reject_geran_utran,
			{ "Event: Network Rejection for GERAN/UTRAN", "gsm_sim.tp.evt.nw_reject_geran_utran",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_hci_connectivity,
			{ "Event: HCI connectivity", "gsm_sim.tp.evt.hci_connectivity",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_nw_reject_eutran,
			{ "Event: Network Rejection for E-UTRAN", "gsm_sim.tp.evt.reject_eutran",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_mult_access_techno_change,
			{ "Multiple access technologies supported in Event Access Technology Change and PROVIDE LOCAL INFORMATION",
			  "gsm_sim.tp.evt.mult_access_techno_change",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 26 */
		{ &hf_tprof_b26,
			{ "Terminal Profile Byte 26 (Event driven information extensions)", "gsm_sim.tp.b26",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_evt_csg_cell_select,
			{ "Event: CSG Cell Selection", "gsm_sim.tp.evt.csg_cell_select",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_contactless_state_req,
			{ "Event: Contactless state request", "gsm_sim.tp.evt.contactless_state_req",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_rfu7,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0xfc,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 27 */
		{ &hf_tprof_b27,
			{ "Terminal Profile Byte 27 (Event driven information extensions)", "gsm_sim.tp.b27",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_rfu8,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0xff,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 28 */
		{ &hf_tprof_b28,
			{ "Terminal Profile Byte 28 (Text attributes)", "gsm_sim.tp.b28",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_text_align_left,
			{ "Alignment left", "gsm_sim.tp.text.align_left",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_text_align_centre,
			{ "Alignment centre", "gsm_sim.tp.text.align_centre",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_text_align_right,
			{ "Alignment right", "gsm_sim.tp.text.align_right",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_text_font_size_normal,
			{ "Font size normal", "gsm_sim.tp.text.font_size_normal",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_text_font_size_large,
			{ "Font size large", "gsm_sim.tp.text.font_size_large",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_text_font_size_small,
			{ "Font size small", "gsm_sim.tp.text.font_size_small",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_rfu9,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0xc0,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 29 */
		{ &hf_tprof_b29,
			{ "Terminal Profile Byte 29 (Text attributes)", "gsm_sim.tp.b29",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_text_style_normal,
			{ "Style normal", "gsm_sim.tp.text.style_normal",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_text_style_bold,
			{ "Style bold", "gsm_sim.tp.text.style_bold",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_text_style_italic,
			{ "Style italic", "gsm_sim.tp.text.style_italic",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_text_style_underlined,
			{ "Style underlined", "gsm_sim.tp.text.style_underlined",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_text_style_strikethrough,
			{ "Style strikethrough", "gsm_sim.tp.text.style_strikethrough",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_text_style_text_fg_colour,
			{ "Style text foreground colour", "gsm_sim.tp.text.style_text_fg_colour",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_text_style_text_bg_colour,
			{ "Style text background colour", "gsm_sim.tp.text.style_text_bg_colour",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_rfu10,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0x80,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 30 */
		{ &hf_tprof_b30,
			{ "Terminal Profile Byte 30", "gsm_sim.tp.b30",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_bip_iwlan,
			{ "I-WLAN bearer", "gsm_sim.tp.bip.iwlan",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_wsid,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (WSID of the current I-WLAN connection)", "gsm_sim.tp.pa.prov_loci_wsid",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_term_app,
			{ "TERMINAL APPLICATIONS", "gsm_sim.tp.term_app",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_steering_roaming_refresh,
			{ "\"Steering of Roaming\" REFRESH", "gsm_sim.tp.steering_roaming_refresh",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_activate,
			{ "Proactive SIM: ACTIVATE", "gsm_sim.tp.pa.activate",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_geo_loc_req,
			{ "Proactive SIM: Geographical Location Request", "gsm_sim.tp.pa.geo_loc_req",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_broadcast_nw_info,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (Broadcast Network Information)", "gsm_sim.tp.pa.prov_loci_broadcast_nw_info",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_steering_roaming_iwlan_refresh,
			{ "\"Steering of Roaming for I-WLAN\" REFRESH", "gsm_sim.tp.steering_roaming_iwlan_refresh",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 31 */
		{ &hf_tprof_b31,
			{ "Terminal Profile Byte 31", "gsm_sim.tp.b31",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_pa_contactless_state_changed,
			{ "Proactive SIM: Contactless State Changed", "gsm_sim.tp.pa.contactless_state_changed",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_csg_cell_discovery,
			{ "CSG cell discovery", "gsm_sim.tp.csg_cell_discovery",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_cnf_params_support_open_chan_server_mode,
			{ "Confirmation parameters supported for OPEN CHANNEL in Terminal Server Mode", "gsm_sim.tp.cnf_params_support_open_chan_server_mode",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_com_ctrl_ims,
			{ "Communication Control for IMS", "gsm_sim.tp.com_ctrl_ims",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_cat_over_modem_itf,
			{ "CAT over the modem interface", "gsm_sim.tp.cat_over_modem_itf",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_incoming_data_ims,
			{ "Event: Incoming IMS Data", "gsm_sim.tp.evt.incoming_data_ims",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_ims_registration,
			{ "Event: IMS Registration", "gsm_sim.tp.evt.ims_registration",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prof_env_cont,
			{ "Proactive SIM: Profile Container, Envelope Container, COMMAND CONTAINER and ENCAPSULATED SESSION CONTROL", "gsm_sim.tp.pa.prof_env_cont",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 32 */
		{ &hf_tprof_b32,
			{ "Terminal Profile Byte 32", "gsm_sim.tp.b32",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_bip_ims,
			{ "IMS bearer", "gsm_sim.tp.bip.ims",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_henb_ip_addr,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (H(e)NB IP address)", "gsm_sim.tp.pa.prov_loci_henb_ip_addr",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_henb_surround_macro,
			{ "Proactive SIM: PROVIDE LOCAL INFORMATION (H(e)NB surrounding macrocells)", "gsm_sim.tp.pa.prov_loci_henb_surround_macro",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_launch_params_support_open_chan_server_mode,
			{ "Launch parameters supported for OPEN CHANNEL in Terminal Server Mode", "gsm_sim.tp.launch_params_support_open_chan_server_mode",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_direct_com_support_open_chan_server_mode,
			{ "Direct communication channel supported for OPEN CHANNEL in Terminal Server Mode", "gsm_sim.tp.direct_com_support_open_chan_server_mode",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_sec_prof_env_cont,
			{ "Proactive SIM: Security for Profile Container, Envelope Container, COMMAND CONTAINER and ENCAPSULATED SESSION CONTROL", "gsm_sim.tp.sec_prof_env_cont",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_cat_serv_list_ecat_client,
			{ "CAT service list for eCAT client", "gsm_sim.tp.serv_list_ecat_client",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_support_refresh_enforcement_policy,
			{ "Support of refresh enforcement policy", "gsm_sim.tp.refresh_enforcement_policy",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 33 */
		{ &hf_tprof_b33,
			{ "Terminal Profile Byte 33", "gsm_sim.tp.b33",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_support_dns_addr_req,
			{ "Support of DNS server address request for OPEN CHANNEL related to packet data service bearer", "gsm_sim.tp.support_dns_addr_req",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_support_nw_access_name_reuse,
			{ "Support of Network Access Name reuse indication for CLOSE CHANNEL related to packet data service bearer", "gsm_sim.tp.nw_access_name_reuse",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_ev_poll_intv_nego,
			{ "Event: Poll Interval Negotiation", "gsm_sim.tp.evt.poll_intv_nego",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_prose_usage_info_reporting,
			{ "ProSe usage information reporting", "gsm_sim.tp.evt.prose_usage_info_reporting",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_rat,
			{ "Proactive UICC: PROVIDE LOCAL INFORMATION (Supported Radio Access Technologies)", "gsm_sim.tp.pa.prov_loci_rat",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_wlan_access_status,
			{ "Event: WLAN Access status", "gsm_sim.tp.evt.wlan_access_status",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_wlan_bearer,
			{ "WLAN bearer support", "gsm_sim.tp.wlan_bearer",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_wlan_id,
			{ "Proactive UICC: PROVIDE LOCAL INFORMATION (WLAN identifier of the current WLAN connection)", "gsm_sim.tp.pa.prov_loci_wlan_id",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 34 */
		{ &hf_tprof_b34,
			{ "Terminal Profile Byte 34", "gsm_sim.tp.b34",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_uri_send_short_msg,
			{ "URI support for SEND SHORT MESSAGE", "gsm_sim.tp.uri_send_short_msg",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_ims_uri_setup_call,
			{ "IMS URI supported for SET UP CALL", "gsm_sim.tp.ims_uri_setup_call",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_media_type_voice_setup_call,
			{ "Media Type \"Voice\" supported for SET UP CALL and Call Control by USIM", "gsm_sim.tp.media_type_voice_setup_call",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_media_type_video_setup_call,
			{ "Media Type \"Video\" supported for SET UP CALL and Call Control by USIM", "gsm_sim.tp.media_type_video_setup_call",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_prov_loci_eutran_timing_advance_info,
			{ "Proactive UICC: PROVIDE LOCAL INFORMATION (E-UTRAN Timing Advance Information)", "gsm_sim.tp.pa.prov_loci_eutran_timing_advance_info",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_refresh_euicc_profile_state_change,
			{ "REFRESH with \"eUICC Profile State Change\" mode", "gsm_sim.tp.refresh_euicc_profile_state_change",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_ext_rej_cause_code_nw_reject_eutran,
			{ "Extended Rejection Cause Code in Event: Network Rejection for E-UTRAN", "gsm_sim.tp.ext_rej_cause_code_nw_reject_eutran",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_deprecated_b34,
			{ "Deprecated", "gsm_sim.tp.deprecated",
			  FT_UINT8, BASE_HEX, NULL, 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 35 */
		{ &hf_tprof_b35,
			{ "Terminal Profile Byte 35", "gsm_sim.tp.b35",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_pa_get_input_var_timeout,
			{ "Proactive UICC: GET INPUT (Variable Time out)", "gsm_sim.tp.pa.get_input_var_timeout",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_data_conn_status_change_pdp,
			{ "Data Connection Status Change Event support - PDP Connection", "gsm_sim.tp.data_conn_status_change_pdp",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_data_conn_status_change_pdn,
			{ "Data Connection Status Change Event support - PDN Connection", "gsm_sim.tp.data_conn_status_change_pdn",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_refresh_app_update,
			{ "REFRESH with \"Application Update\" mode", "gsm_sim.tp.refresh_app_update",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_lsi_proactive_session_request,
			{ "Proactive UICC: LSI COMMAND with \"Proactive Session Request\"", "gsm_sim.tp.pa.lsi_proactive_session_request",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_lsi_uicc_platform_reset,
			{ "Proactive UICC: LSI COMMAND with \"UICC Platform Reset\"", "gsm_sim.tp.pa.lsi_uicc_platform_reset",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_rfu11,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0xc0,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 36 */
		{ &hf_tprof_b36,
			{ "Terminal Profile Byte 36", "gsm_sim.tp.b36",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_data_conn_status_change_pdu,
			{ "Data Connection Status Change Event support - PDU Connection", "gsm_sim.tp.data_conn_status_change_pdu",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_nw_reject_ng_ran,
			{ "Event: Network Rejection for NG-RAN", "gsm_sim.tp.evt.nw_reject_ng_ran",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_non_ip_data_delivery,
			{ "Non-IP Data Delivery support", "gsm_sim.tp.non_ip_data_delivery",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_prov_loci_slice_info,
			{ "Support of PROVIDE LOCAL INFORMATION, Slice(s) information", "gsm_sim.tp.prov_loci_slice_info",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_refresh_sor_cmci_param,
			{ "REFRESH \"Steering of Roaming\" SOR-CMCI parameter support", "gsm_sim.tp.refresh_sor_cmci_param",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_nw_reject_satellite_ng_ran,
			{ "Event: Network Rejection for Satellite NG-RAN", "gsm_sim.tp.evt.nw_reject_satellite_ng_ran",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  NULL, HFILL }
		},
		{ &hf_tp_cag_feature,
			{ "Support of CAG feature", "gsm_sim.tp.cag_feature",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_evt_slices_status_change,
			{ "Event: Slices Status Change", "gsm_sim.tp.evt.slices_status_change",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 37 */
		{ &hf_tprof_b37,
			{ "Terminal Profile Byte 37", "gsm_sim.tp.b37",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_prov_loci_rejected_slice_info,
			{ "Support of PROVIDE LOCAL INFORMATION, Rejected Slice(s) Information", "gsm_sim.tp.prov_loci_rejected_slice_info",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_ext_info_pli,
			{ "Support of Extended information for PLI (Location Information), Event: Location Status, Event: Network Rejection", "gsm_sim.tp.ext_info_pli",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},
		{ &hf_tp_chaining_pli_env_cmds,
			{ "Support of chaining of PLI/Envelope commands", "gsm_sim.tp.chaining_pli_env_cmds",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  NULL, HFILL }
		},
		{ &hf_tp_5g_prose_usage_info_reporting,
			{ "5G ProSe usage information reporting", "gsm_sim.tp.5g_prose_usage_info_reporting",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  NULL, HFILL }
		},
		{ &hf_tp_rfu12,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0xf0,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 38 */
		{ &hf_tprof_b38,
			{ "Terminal Profile Byte 38", "gsm_sim.tp.b38",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_rfu13,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0xff,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 39 */
		{ &hf_tprof_b39,
			{ "Terminal Profile Byte 39", "gsm_sim.tp.b39",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_pa_prov_loci_ng_ran_satellite_timing_advance_info,
			{ "Proactive UICC: PROVIDE LOCAL INFORMATION (NG-RAN/Satellite NG-RAN Timing Advance Information)", "gsm_sim.tp.pa.prov_loci_ng_ran_satellite_timing_advance_info",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_rfu14,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0xfe,
			  NULL, HFILL },
		},

		{ &hf_tprof_unknown_byte,
			{ "Unknown Terminal Profile Byte", "gsm_sim.tp.unknown_byte",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},

		{ &hf_cat_ber_tag,
			{ "BER-TLV Tag", "gsm_sim.cat.ber_tlv_tag",
			  FT_UINT8, BASE_HEX, VALS(ber_tlv_cat_tag_vals), 0,
			  "Card Application Toolkit BER-TLV tag", HFILL },
		},

		{ &hf_search_ef_identifier,
			{ "EF Identifier", "gsm_sim.search_ef_identifier",
			FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS, VALS(search_ef_identifier_vals), 0xF8,
			NULL, HFILL },
		},
		{ &hf_search_mode,
			{ "Search Mode", "gsm_sim.search_mode",
			  FT_UINT8, BASE_HEX, VALS(search_mode_vals), 0x07,
			  NULL, HFILL },
		},
		{ &hf_search_enhanced_type,
			{ "Enhanced Search Type", "gsm_sim.search_enhanced_type",
			FT_UINT8, BASE_HEX, VALS(search_enhanced_type), 0xF8,
			NULL, HFILL },
		},
		{ &hf_search_enhanced_mode,
			{ "Enhanced Search Mode", "gsm_sim.search_enhanced_mode",
			FT_UINT8, BASE_HEX, VALS(search_enhanced_mode_vals), 0x07,
			NULL, HFILL },
		},
		{ &hf_search_enhanced_offset,
			{ "Enhanced Search Offset", "gsm_sim.search_enhanced_offset",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL },
		},
		{ &hf_search_enhanced_value,
			{ "Enhanced Search Value", "gsm_sim.search_enhanced_value",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL },
		},

		{ &hf_related_to,
			{ "Related To", "gsm_sim.related_to",
			  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
			  "This APDU is related to the command in this frame", HFILL }
		},
		{ &hf_response_in,
			{ "Response In", "gsm_sim.response_in",
			  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
			  "The response to this command is in this frame", HFILL }
		},
		{ &hf_response_to,
			{ "Response To", "gsm_sim.response_to",
			  FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
			  "This is the response to the command in this frame", HFILL }
		},
		{ &hf_response_time,
			{ "Response Time", "gsm_sim.response_time",
			  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
			  "The time between the command and the response", HFILL }
		},

		/* Fragment entries */
		{ &hf_gsm_sim_fragments,
			{ "APDU fragments", "gsm_sim.fragments", FT_NONE, BASE_NONE,
			  NULL, 0x00, NULL, HFILL }
		},
		{ &hf_gsm_sim_fragment,
			{ "APDU fragment", "gsm_sim.fragment", FT_FRAMENUM, BASE_NONE,
			  NULL, 0x00, NULL, HFILL }
		},
		{ &hf_gsm_sim_fragment_overlap,
			{ "APDU fragment overlap", "gsm_sim.fragment.overlap", FT_BOOLEAN,
			  BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_gsm_sim_fragment_overlap_conflicts,
			{ "APDU fragment overlapping with conflicting data",
			  "gsm_sim.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_gsm_sim_fragment_multiple_tails,
			{ "APDU has multiple tail fragments",
			  "gsm_sim.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_gsm_sim_fragment_too_long_fragment,
			{ "APDU fragment too long", "gsm_sim.fragment.too_long_fragment",
			  FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_gsm_sim_fragment_error,
			{ "APDU defragmentation error", "gsm_sim.fragment.error", FT_FRAMENUM,
			  BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_gsm_sim_fragment_count,
			{ "APDU fragment count", "gsm_sim.fragment.count", FT_UINT32, BASE_DEC,
			  NULL, 0x00, NULL, HFILL }
		},
		{ &hf_gsm_sim_reassembled_in,
			{ "Reassembled APDU in frame", "gsm_sim.reassembled.in", FT_FRAMENUM, BASE_NONE,
			  NULL, 0x00, "This APDU packet is reassembled in this frame", HFILL }
		},
		{ &hf_gsm_sim_reassembled_length,
			{ "Reassembled APDU length", "gsm_sim.reassembled.length", FT_UINT32, BASE_DEC,
			  NULL, 0x00, "The total length of the reassembled payload", HFILL }
		},
	};
	static int *ett[] = {
		&ett_sim,
		&ett_tprof_b1,
		&ett_tprof_b2,
		&ett_tprof_b3,
		&ett_tprof_b4,
		&ett_tprof_b5,
		&ett_tprof_b6,
		&ett_tprof_b7,
		&ett_tprof_b8,
		&ett_tprof_b9,
		&ett_tprof_b10,
		&ett_tprof_b11,
		&ett_tprof_b12,
		&ett_tprof_b13,
		&ett_tprof_b14,
		&ett_tprof_b15,
		&ett_tprof_b16,
		&ett_tprof_b17,
		&ett_tprof_b18,
		&ett_tprof_b19,
		&ett_tprof_b20,
		&ett_tprof_b21,
		&ett_tprof_b22,
		&ett_tprof_b23,
		&ett_tprof_b24,
		&ett_tprof_b25,
		&ett_tprof_b26,
		&ett_tprof_b27,
		&ett_tprof_b28,
		&ett_tprof_b29,
		&ett_tprof_b30,
		&ett_tprof_b31,
		&ett_tprof_b32,
		&ett_tprof_b33,
		&ett_tprof_b34,
		&ett_tprof_b35,
		&ett_tprof_b36,
		&ett_tprof_b37,
		&ett_tprof_b38,
		&ett_tprof_b39,
		&ett_auth_challenge,
		&ett_auth_response,
		&ett_gsm_sim_fragment,
		&ett_gsm_sim_fragments,
	};

	static ei_register_info ei[] = {
		{ &ei_unknown_bytes, { "gsm_sim.unknown_bytes", PI_PROTOCOL, PI_WARN, "Unknown bytes", EXPFILL }},
	};
	expert_module_t *expert_gsm_sim;

	proto_gsm_sim = proto_register_protocol("GSM SIM 11.11", "GSM SIM",
						 "gsm_sim");

	proto_register_field_array(proto_gsm_sim, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_gsm_sim = expert_register_protocol(proto_gsm_sim);
	expert_register_field_array(expert_gsm_sim, ei, array_length(ei));

	transactions = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
	reassembly_table_register (&gsm_sim_reassembly_table, &addresses_reassembly_table_functions);

	/* This dissector is for SIMtrace, which always combines the command
	 * & response APDUs into one packet before sending it to GSMTAP. Cf.
	 * https://github.com/yarrick/scsniff/issues/1#issuecomment-2295835330
	 */
	sim_handle = register_dissector("gsm_sim", dissect_gsm_sim, proto_gsm_sim);
	register_dissector("gsm_sim.command", dissect_gsm_sim_command, proto_gsm_sim);
	register_dissector("gsm_sim.response", dissect_gsm_sim_response, proto_gsm_sim);
	register_dissector("gsm_sim.bertlv", dissect_bertlv, proto_gsm_sim);
	sim_part_handle = register_dissector("gsm_sim.part", dissect_gsm_sim_part, proto_gsm_sim);
}

void
proto_reg_handoff_gsm_sim(void)
{
	dissector_add_for_decode_as("usbccid.subdissector", sim_part_handle);

	sub_handle_cap = find_dissector_add_dependency("etsi_cat", proto_gsm_sim);
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
