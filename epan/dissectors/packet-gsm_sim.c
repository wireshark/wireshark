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

#include "packet-gsmtap.h"

void proto_register_gsm_sim(void);
void proto_reg_handoff_gsm_sim(void);

static int proto_gsm_sim = -1;

/* ISO 7816-4 APDU */
static int hf_apdu_cla_coding = -1;
static int hf_apdu_cla_coding_ext = -1;
static int hf_apdu_cla_secure_messaging_ind = -1;
static int hf_apdu_cla_secure_messaging_ind_ext = -1;
static int hf_apdu_cla_log_chan = -1;
static int hf_apdu_cla_log_chan_ext = -1;
static int hf_apdu_ins = -1;
static int hf_apdu_p1 = -1;
static int hf_apdu_p2 = -1;
static int hf_apdu_p3 = -1;
static int hf_apdu_data = -1;
static int hf_apdu_sw = -1;

static int hf_file_id = -1;
static int hf_aid = -1;
static int hf_bin_offset = -1;
static int hf_record_nr = -1;
static int hf_auth_rand = -1;
static int hf_auth_sres = -1;
static int hf_auth_kc = -1;
static int hf_chan_op = -1;
static int hf_chan_nr = -1;
static int hf_le = -1;

/* Chapter 5.2 TS 11.14 and TS 31.111 */
static int hf_tprof_b1 = -1;
static int hf_tprof_b2 = -1;
static int hf_tprof_b3 = -1;
static int hf_tprof_b4 = -1;
static int hf_tprof_b5 = -1;
static int hf_tprof_b6 = -1;
static int hf_tprof_b7 = -1;
static int hf_tprof_b8 = -1;
static int hf_tprof_b9 = -1;
static int hf_tprof_b10 = -1;
static int hf_tprof_b11 = -1;
static int hf_tprof_b12 = -1;
static int hf_tprof_b13 = -1;
static int hf_tprof_b14 = -1;
static int hf_tprof_b15 = -1;
static int hf_tprof_b16 = -1;
static int hf_tprof_b17 = -1;
static int hf_tprof_b18 = -1;
static int hf_tprof_b19 = -1;
static int hf_tprof_b20 = -1;
static int hf_tprof_b21 = -1;
static int hf_tprof_b22 = -1;
static int hf_tprof_b23 = -1;
static int hf_tprof_b24 = -1;
static int hf_tprof_b25 = -1;
static int hf_tprof_b26 = -1;
static int hf_tprof_b27 = -1;
static int hf_tprof_b28 = -1;
static int hf_tprof_b29 = -1;
static int hf_tprof_b30 = -1;
static int hf_tprof_b31 = -1;
static int hf_tprof_b32 = -1;
static int hf_tprof_b33 = -1;
static int hf_tprof_unknown_byte = -1;
/* First byte */
static int hf_tp_prof_dld = -1;
static int hf_tp_sms_data_dld = -1;
static int hf_tp_cb_data_dld = -1;
static int hf_tp_menu_sel = -1;
static int hf_tp_sms_data_dld_support = -1;
static int hf_tp_timer_exp = -1;
static int hf_tp_cc_sim_support = -1;
static int hf_tp_cc_sim_support2 = -1;
/* Second byte (Other) */
static int hf_tp_cmd_res = -1;
static int hf_tp_cc_sim = -1;
static int hf_tp_cc_sim_support3 = -1;
static int hf_tp_mo_sms_sim = -1;
static int hf_tp_cc_sim_support4 = -1;
static int hf_tp_ucs2_entry = -1;
static int hf_tp_ucs2_display = -1;
static int hf_tp_display_ext = -1;
/* 3rd byte (Proactive SIM) */
static int hf_tp_pa_display_text = -1;
static int hf_tp_pa_get_inkey = -1;
static int hf_tp_pa_get_input = -1;
static int hf_tp_pa_more_time = -1;
static int hf_tp_pa_play_tone = -1;
static int hf_tp_pa_poll_intv = -1;
static int hf_tp_pa_polling_off = -1;
static int hf_tp_pa_refresh = -1;
/* 4th byte (Proactive SIM) */
static int hf_tp_pa_select_item = -1;
static int hf_tp_pa_send_sms = -1;
static int hf_tp_pa_send_ss = -1;
static int hf_tp_pa_send_ussd = -1;
static int hf_tp_pa_set_up_call = -1;
static int hf_tp_pa_set_up_menu = -1;
static int hf_tp_pa_prov_loci = -1;
static int hf_tp_pa_prov_loci_nmr = -1;
/* 5th byte (Event drive information) */
static int hf_tp_pa_evt_list = -1;
static int hf_tp_ev_mt_call = -1;
static int hf_tp_ev_call_connected = -1;
static int hf_tp_ev_call_disconnected = -1;
static int hf_tp_ev_location_status = -1;
static int hf_tp_ev_user_activity = -1;
static int hf_tp_ev_idle_screen = -1;
static int hf_tp_ev_cardreader_status = -1;
/* 6th byte (Event drive information extension) */
static int hf_tp_ev_lang_sel = -1;
static int hf_tp_ev_brows_term = -1;
static int hf_tp_ev_data_avail = -1;
static int hf_tp_ev_chan_status = -1;
static int hf_tp_ev_access_techno_change = -1;
static int hf_tp_ev_disp_params_changed = -1;
static int hf_tp_ev_local_conn = -1;
static int hf_tp_ev_nwk_search_mode_change = -1;
/* 7th byte (Multiple card proactive commands) */
static int hf_tp_pa_power_on = -1;
static int hf_tp_pa_power_off = -1;
static int hf_tp_pa_perform_card_apdu = -1;
static int hf_tp_pa_get_reader_status = -1;
static int hf_tp_pa_get_reader_status_id = -1;
static int hf_tp_rfu = -1;
/* 8th byte (Proactive SIM) */
static int hf_tp_pa_timer_start_stop = -1;
static int hf_tp_pa_timer_get_current = -1;
static int hf_tp_pa_prov_loci_date_tz = -1;
static int hf_tp_pa_get_inkey_binary = -1;
static int hf_tp_pa_set_up_idle_mode_text = -1;
static int hf_tp_pa_run_at_command = -1;
static int hf_tp_pa_2nd_alpha_setup_call = -1;
static int hf_tp_pa_2nd_cc_sim_support = -1;
/* 9th byte */
static int hf_tp_display_text = -1;
static int hf_tp_send_dtmf_cmd = -1;
static int hf_tp_pa_prov_loci_nmr2 = -1;
static int hf_tp_pa_prov_loci_lang = -1;
static int hf_tp_pa_prov_loci_ta = -1;
static int hf_tp_pa_lang_notif = -1;
static int hf_tp_pa_launch_browser = -1;
static int hf_tp_pa_prov_loci_access_techno = -1;
/* 10th byte */
static int hf_tp_soft_key_support_select_item = -1;
static int hf_tp_soft_key_support_set_up_menu = -1;
static int hf_tp_rfu2 = -1;
/* 11th byte */
static int hf_tp_soft_key_info_max_nb = -1;
/* 12th byte (Proactive SIM) */
static int hf_tp_pa_open_chan = -1;
static int hf_tp_pa_close_chan = -1;
static int hf_tp_pa_recv_data = -1;
static int hf_tp_pa_send_data = -1;
static int hf_tp_pa_get_chan_status = -1;
static int hf_tp_pa_serv_search = -1;
static int hf_tp_pa_get_serv_info = -1;
static int hf_tp_pa_decl_serv = -1;
/* 13th byte (Proactive SIM) */
static int hf_tp_bip_csd = -1;
static int hf_tp_bip_gprs = -1;
static int hf_tp_bip_bluetooth = -1;
static int hf_tp_bip_irda = -1;
static int hf_tp_bip_rs232 = -1;
static int hf_tp_num_chans = -1;
/* 14th byte (Screen height) */
static int hf_tp_char_height = -1;
static int hf_tp_nd = -1;
static int hf_tp_nk = -1;
static int hf_tp_sizing_supp = -1;
/* 15th byte (Screen width) */
static int hf_tp_char_width = -1;
static int hf_tp_var_fonts = -1;
/* 16th byte (Screen effects) */
static int hf_tp_display_resize = -1;
static int hf_tp_text_wrapping = -1;
static int hf_tp_text_scrolling = -1;
static int hf_tp_text_attributes = -1;
static int hf_tp_rfu3 = -1;
static int hf_tp_width_red_menu = -1;
/* 17th byte (Proactive SIM) */
static int hf_tp_bip_tcp_remote = -1;
static int hf_tp_bip_udp_remote = -1;
static int hf_tp_bip_tcp_server = -1;
static int hf_tp_bip_tcp_local = -1;
static int hf_tp_bip_udp_local = -1;
static int hf_tp_bip_direct_com = -1;
static int hf_tp_bip_eutran = -1;
static int hf_tp_bip_hsdpa = -1;
/* 18th byte */
static int hf_tp_pa_display_text_var_time_out = -1;
static int hf_tp_pa_get_inkey_help = -1;
static int hf_tp_bip_usb = -1;
static int hf_tp_pa_get_inkey_var_time_out = -1;
static int hf_tp_pa_prov_loci_esn = -1;
static int hf_tp_cc_gprs = -1;
static int hf_tp_pa_prov_loci_imeisv = -1;
static int hf_tp_pa_prov_loci_search_mode_change = -1;
/* 19th byte (TIA/EIA-136) */
static int hf_tp_tia_eia_version = -1;
static int hf_tp_rfu4 = -1;
/* 20th byte (TIA/EIA/IS-820-A) */
static int hf_tp_tia_iea_is820a_reserved = -1;
/* 21th byte (Extended Launch Browser Capability) */
static int hf_tp_ext_launch_browser_wml = -1;
static int hf_tp_ext_launch_browser_xhtml = -1;
static int hf_tp_ext_launch_browser_html = -1;
static int hf_tp_ext_launch_browser_chtml = -1;
static int hf_tp_rfu5 = -1;
/* 22th byte */
static int hf_tp_utran_ps_ext_params = -1;
static int hf_tp_pa_prov_loci_batt_state = -1;
static int hf_tp_pa_play_tone_melody = -1;
static int hf_tp_mm_call_set_up_call = -1;
static int hf_tp_toolkit_initiated_gba = -1;
static int hf_tp_pa_retrieve_mm_msg = -1;
static int hf_tp_pa_submit_mm_msg = -1;
static int hf_tp_pa_display_mm_msg = -1;
/* 23th byte */
static int hf_tp_pa_set_frames = -1;
static int hf_tp_pa_get_frames_status = -1;
static int hf_tp_mms_notif_download = -1;
static int hf_tp_alpha_id_refresh_cmd = -1;
static int hf_tp_geo_loc_report = -1;
static int hf_tp_pa_prov_loci_meid = -1;
static int hf_tp_pa_prov_loci_nmr_utran_eutran = -1;
static int hf_tp_ussd_data_download = -1;
/* 24th byte (Class "i") */
static int hf_tp_class_i_max_nb_frames = -1;
static int hf_tp_rfu6 = -1;
/* 25th byte (Event driven information extensions) */
static int hf_tp_evt_browsing_status = -1;
static int hf_tp_evt_mms_transfer_status = -1;
static int hf_tp_evt_frame_info_changed = -1;
static int hf_tp_evt_iwlan_access_status = -1;
static int hf_tp_evt_nw_reject_geran_utran = -1;
static int hf_tp_evt_hci_connectivity = -1;
static int hf_tp_evt_nw_reject_eutran = -1;
static int hf_tp_evt_mult_access_techno_change = -1;
/* 26th byte (Event driven information extensions) */
static int hf_tp_evt_csg_cell_select = -1;
static int hf_tp_evt_contactless_state_req = -1;
static int hf_tp_rfu7 = -1;
/* 27th byte (Event driven information extensions) */
static int hf_tp_rfu8 = -1;
/* 28th byte (Text attributes) */
static int hf_tp_text_align_left = -1;
static int hf_tp_text_align_centre = -1;
static int hf_tp_text_align_right = -1;
static int hf_tp_text_font_size_normal = -1;
static int hf_tp_text_font_size_large = -1;
static int hf_tp_text_font_size_small = -1;
static int hf_tp_rfu9 = -1;
/* 29th byte (Text attributes) */
static int hf_tp_text_style_normal = -1;
static int hf_tp_text_style_bold = -1;
static int hf_tp_text_style_italic = -1;
static int hf_tp_text_style_underlined = -1;
static int hf_tp_text_style_strikethrough = -1;
static int hf_tp_text_style_text_fg_colour = -1;
static int hf_tp_text_style_text_bg_colour = -1;
static int hf_tp_rfu10 = -1;
/* 30th byte */
static int hf_tp_bip_iwlan = -1;
static int hf_tp_pa_prov_loci_wsid = -1;
static int hf_tp_term_app = -1;
static int hf_tp_steering_roaming_refresh = -1;
static int hf_tp_pa_activate = -1;
static int hf_tp_pa_geo_loc_req = -1;
static int hf_tp_pa_prov_loci_broadcast_nw_info = -1;
static int hf_tp_steering_roaming_iwlan_refresh = -1;
/* 31th byte */
static int hf_tp_pa_contactless_state_changed = -1;
static int hf_tp_csg_cell_discovery = -1;
static int hf_tp_cnf_params_support_open_chan_server_mode = -1;
static int hf_tp_com_ctrl_ims = -1;
static int hf_tp_cat_over_modem_itf = -1;
static int hf_tp_evt_incoming_data_ims = -1;
static int hf_tp_evt_ims_registration = -1;
static int hf_tp_pa_prof_env_cont = -1;
/* 32th byte */
static int hf_tp_bip_ims = -1;
static int hf_tp_pa_prov_loci_henb_ip_addr = -1;
static int hf_tp_pa_prov_loci_henb_surround_macro = -1;
static int hf_tp_launch_params_support_open_chan_server_mode = -1;
static int hf_tp_direct_com_support_open_chan_server_mode = -1;
static int hf_tp_pa_sec_prof_env_cont = -1;
static int hf_tp_cat_serv_list_ecat_client = -1;
static int hf_tp_support_refresh_enforcement_policy = -1;
/* 33th byte */
static int hf_tp_support_dns_addr_req = -1;
static int hf_tp_support_nw_access_name_reuse = -1;
static int hf_tp_ev_poll_intv_nego = -1;
static int hf_tp_rfu11 = -1;

static int hf_cat_ber_tag = -1;

static int hf_seek_mode = -1;
static int hf_seek_type = -1;
static int hf_seek_rec_nr = -1;

static int ett_sim = -1;
static int ett_tprof_b1 = -1;
static int ett_tprof_b2 = -1;
static int ett_tprof_b3 = -1;
static int ett_tprof_b4 = -1;
static int ett_tprof_b5 = -1;
static int ett_tprof_b6 = -1;
static int ett_tprof_b7 = -1;
static int ett_tprof_b8 = -1;
static int ett_tprof_b9 = -1;
static int ett_tprof_b10 = -1;
static int ett_tprof_b11 = -1;
static int ett_tprof_b12 = -1;
static int ett_tprof_b13 = -1;
static int ett_tprof_b14 = -1;
static int ett_tprof_b15 = -1;
static int ett_tprof_b16 = -1;
static int ett_tprof_b17 = -1;
static int ett_tprof_b18 = -1;
static int ett_tprof_b19 = -1;
static int ett_tprof_b20 = -1;
static int ett_tprof_b21 = -1;
static int ett_tprof_b22 = -1;
static int ett_tprof_b23 = -1;
static int ett_tprof_b24 = -1;
static int ett_tprof_b25 = -1;
static int ett_tprof_b26 = -1;
static int ett_tprof_b27 = -1;
static int ett_tprof_b28 = -1;
static int ett_tprof_b29 = -1;
static int ett_tprof_b30 = -1;
static int ett_tprof_b31 = -1;
static int ett_tprof_b32 = -1;
static int ett_tprof_b33 = -1;

static dissector_handle_t sub_handle_cap;
static dissector_handle_t sim_handle, sim_part_handle;


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
	&hf_tp_rfu11,
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
	{ 0xd5, "GSM/3G - MO Short Message control" },
	{ 0xd6, "Event Download" },
	{ 0xd7, "Timer Expiration" },
	{ 0xd8, "Reserved for intra-UICC communication" },
	{ 0xd9, "3G - USSD Download" },
	{ 0xda, "MMS Transfer status" },
	{ 0xdb, "MMS notification download" },
	{ 0xdc, "Terminal application" },
	{ 0xdd, "3G - Geographical Location Reporting" },
	{ 0, NULL }
};

static const value_string chan_op_vals[] = {
	{ 0x00, "Open Channel" },
	{ 0x80, "Close Channel" },
	{ 0, NULL }
};

static const value_string apdu_cla_coding_vals[] = {
	{ 0x00,	"ISO/IEC 7816-4" },
	{ 0x08,	"ETSI TS 102.221" },
	{ 0x0a,	"ISO/IEC 7816-4 unless stated otherwise" },
	{ 0, NULL }
};

static const value_string apdu_cla_coding_ext_vals[] = {
	{ 0x01,	"ISO/IEC 7816-4" },
	{ 0x03,	"ETSI TS 102.221" },
	{ 0, NULL }
};

static const value_string apdu_cla_secure_messaging_ind_vals[] = {
	{ 0x00,	"No SM used between terminal and card" },
	{ 0x01,	"Proprietary SM format" },
	{ 0x02,	"Command header not authenticated" },
	{ 0x03,	"Command header authenticated" },
	{ 0, NULL }
};

static const true_false_string apdu_cla_secure_messaging_ind_ext_val = {
	"Command header not authenticated",
	"No SM used between terminal and card"
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
	/* TS 102 221 v15.11.0 */
	{ 0x78, "GET IDENTITY" },
	/* GSMA SGP.02 v4.2 */
	{ 0xCA, "GET DATA" },
	/* TS TS 102 222 */
	{ 0xE0, "CREATE FILE" },
	{ 0xE4, "DELETE FILE" },
	{ 0xE6, "TERMINATE DF" },
	{ 0xE8, "TERMINATE EF" },
	{ 0xFE, "TERMINATE CARD USAGE" },
	{ 0, NULL }
};

/* Section 9.2.7 */
static const value_string seek_type_vals[] = {
	{ 1, "update record pointer, no output" },
	{ 2, "update record pointer, return record number" },
	{ 0, NULL }
};

static const value_string seek_mode_vals[] = {
	{ 0x01, "from the beginning forward" },
	{ 0x02, "from the end backward" },
	{ 0x03, "from the next location forward" },
	{ 0x04, "from the previous location backward" },
	{ 0, NULL }
};

/* Section 10.7 */


/* The FID space is not a global namespace, but a per-directory one. As such,
 * we should have code that tracks the currently selected (sub-)directory, and
 * decode the FID based on that knowledge.  As we don't do that yet, the
 * current work-around is to simply merge all of them into one value_string
 * array */

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
	{ 0x2f05, "EF.ELP" },
	{ 0x2f06, "EF.PL" },
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
	{ 0x6ffe, "EF.ePDGSeEARFCNListlection" },
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
	{ 0x9850, "Increase cannot be performed, max value reached" },
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
	{ 0x9862, "Authentication error, application specific" },
	{ 0x9863, "Security session or association expired" },
	{ 0, NULL }
};

static const gchar *get_sw_string(guint16 sw)
{
	guint8 sw1 = sw >> 8;
	guint8 sw2 = sw & 0xFF;

	switch (sw1) {
	case 0x91:
		return "Normal ending of command with info from proactive SIM";
	case 0x9e:
		return "Length of the response data given / SIM data download error";
	case 0x9f:
		return wmem_strdup_printf(wmem_packet_scope(), "Length of the response data, Length is %u", sw2);
	case 0x92:
		if ((sw & 0xf0) == 0x00)
			return "Command successful but after internal retry routine";
		break;
	case 0x61:
		return wmem_strdup_printf(wmem_packet_scope(), "Response ready, Response length is %u", sw2);
	case 0x67:
		if (sw2 == 0x00)
			return "Wrong length"; /* TS 102.221 / Section 10.2.1.5 */
		else
			return "Incorrect parameter P3"; /* TS 51.011 / Section 9.4.6 */
	case 0x6c:
		return wmem_strdup_printf(wmem_packet_scope(), "Terminal should repeat command, Length for repeated command is %u", sw2);
	case 0x6d:
		return "Unknown instruction code";
	case 0x6e:
		return "Wrong instruction class";
	case 0x6f:
		return "Technical problem with no diagnostic";
	}
	return val_to_str(sw, sw_vals, "Unknown status word: %04x");
}

static int
dissect_bertlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	unsigned int pos = 0;

	while (pos < tvb_reported_length(tvb)) {
		guint8 tag;
		guint32 len;
		tvbuff_t *subtvb;

		proto_tree_add_item(tree, hf_cat_ber_tag, tvb, pos, 1, ENC_BIG_ENDIAN);

		/* FIXME: properly follow BER coding rules */
		tag = tvb_get_guint8(tvb, pos++);
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(tag, ber_tlv_cat_tag_vals, "%02x "));
		len = tvb_get_guint8(tvb, pos++);
		switch (len) {
		case 0x81:
			len = tvb_get_guint8(tvb, pos++);
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
			call_dissector_with_data(sub_handle_cap, subtvb, pinfo, tree, GUINT_TO_POINTER((guint)tag));
			break;
		}

		pos += len;
	}
	return tvb_captured_length(tvb);
}


#define ADD_TP_BYTE(byte) \
		if ((offset - start_offset) >= p3) break; \
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b##byte, ett_tprof_b##byte, tprof_b##byte##_fields, ENC_BIG_ENDIAN);

#define P1_OFFS		0
#define P2_OFFS		1
#define P3_OFFS		2
#define DATA_OFFS	3

static int
dissect_gsm_apdu(guint8 ins, guint8 p1, guint8 p2, guint8 p3, tvbuff_t *tvb,
		 int offset, packet_info *pinfo, proto_tree *tree, gboolean isSIMtrace)
{
	guint16 g16;
	tvbuff_t *subtvb;
	int i, start_offset;

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(ins, apdu_ins_vals, "%02x"));

	switch (ins) {
	case 0xA4: /* SELECT */
		if (p3 < 2)
			break;
		switch (p1) {
		case 0x03:	/* parent DF */
			col_append_str(pinfo->cinfo, COL_INFO, "Parent DF ");
			break;
		case 0x04:	/* select by AID */
			col_append_fstr(pinfo->cinfo, COL_INFO, "Application %s ",
					tvb_bytes_to_str(wmem_packet_scope(), tvb, offset+DATA_OFFS, p3));
			proto_tree_add_item(tree, hf_aid, tvb, offset+DATA_OFFS, p3, ENC_NA);
			break;

		case 0x09:	/* select by relative path */
			col_append_str(pinfo->cinfo, COL_INFO, ".");
			/* fallthrough */
		case 0x08:	/* select by absolute path */
			for (i = 0; i < p3; i += 2) {
				g16 = tvb_get_ntohs(tvb, offset+DATA_OFFS+i);
				col_append_fstr(pinfo->cinfo, COL_INFO, "/%s",
						val_to_str(g16, mf_dfs, "%04x"));
				proto_tree_add_item(tree, hf_file_id, tvb, offset+DATA_OFFS+i, 2, ENC_BIG_ENDIAN);
			}
			col_append_str(pinfo->cinfo, COL_INFO, " ");
			break;
		default:
			g16 = tvb_get_ntohs(tvb, offset+DATA_OFFS);
			col_append_fstr(pinfo->cinfo, COL_INFO, "File %s ",
					val_to_str(g16, mf_dfs, "%04x"));
			proto_tree_add_item(tree, hf_file_id, tvb, offset+DATA_OFFS, p3, ENC_BIG_ENDIAN);
			offset++;
			break;
		}
		/* FIXME: parse response */
		break;
	case 0xF2: /* STATUS */
		/* FIXME: parse response */
		break;
	case 0xB0: /* READ BINARY */
		col_append_fstr(pinfo->cinfo, COL_INFO, "Offset=%u ", p1 << 8 | p2);
		proto_tree_add_item(tree, hf_bin_offset, tvb, offset+P1_OFFS, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_le, tvb, offset+P3_OFFS, 1, ENC_BIG_ENDIAN);
		if (isSIMtrace) {
			proto_tree_add_item(tree, hf_apdu_data, tvb, offset+DATA_OFFS, p3, ENC_NA);
		}
		break;
	case 0xD6: /* UPDATE BINARY */
		col_append_fstr(pinfo->cinfo, COL_INFO, "Offset=%u ", p1 << 8 | p2);
		proto_tree_add_item(tree, hf_bin_offset, tvb, offset+P1_OFFS, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_apdu_data, tvb, offset+DATA_OFFS, p3, ENC_NA);
		break;
	case 0xB2: /* READ RECORD */
		col_append_fstr(pinfo->cinfo, COL_INFO, "RecordNr=%u ", p1);
		proto_tree_add_item(tree, hf_record_nr, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_le, tvb, offset+P3_OFFS, 1, ENC_BIG_ENDIAN);
		if (isSIMtrace) {
			proto_tree_add_item(tree, hf_apdu_data, tvb, offset+DATA_OFFS, p3, ENC_NA);
		}
		break;
	case 0xDC: /* UPDATE RECORD */
		col_append_fstr(pinfo->cinfo, COL_INFO, "RecordNr=%u ", p1);
		proto_tree_add_item(tree, hf_record_nr, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_apdu_data, tvb, offset+DATA_OFFS, p3, ENC_NA);
		break;
	case 0xA2: /* SEARCH RECORD */
		proto_tree_add_item(tree, hf_seek_mode, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_seek_type, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		offset += DATA_OFFS;
		proto_tree_add_item(tree, hf_apdu_data, tvb, offset, p3, ENC_NA);
		offset += p3;
		if ((p2 & 0xF0) == 0x20)
			proto_tree_add_item(tree, hf_seek_rec_nr, tvb, offset++, 1, ENC_BIG_ENDIAN);
		break;
	case 0x32: /* INCREASE */
		break;
	case 0x20: /* VERIFY CHV */
	case 0x24: /* CHANGE CHV */
	case 0x26: /* DISABLE CHV */
	case 0x28: /* ENABLE CHV */
	case 0x2C: /* UNBLOCK CHV */
		col_append_fstr(pinfo->cinfo, COL_INFO, "CHV=%u ", p2);
		offset += DATA_OFFS;
		/* FIXME: actual PIN/PUK code */
		break;
	case 0x88: /* RUN GSM ALGO */
		offset += DATA_OFFS;
		proto_tree_add_item(tree, hf_auth_rand, tvb, offset, 16, ENC_NA);
		offset += 16;
		if (isSIMtrace) {
			proto_tree_add_item(tree, hf_auth_sres, tvb, offset, 4, ENC_NA);
			offset += 4;
			proto_tree_add_item(tree, hf_auth_kc, tvb, offset, 8, ENC_NA);
			offset += 8;
		}
		break;
	case 0x10: /* TERMINAL PROFILE */
		offset += DATA_OFFS;
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
		while ((offset - start_offset) < p3) {
			proto_tree_add_item(tree, hf_tprof_unknown_byte, tvb, offset++, 1, ENC_BIG_ENDIAN);
		}
		break;
	case 0x12: /* FETCH */
		proto_tree_add_item(tree, hf_le, tvb, offset+P3_OFFS, 1, ENC_BIG_ENDIAN);
		if (isSIMtrace) {
			subtvb = tvb_new_subset_length(tvb, offset+DATA_OFFS, (p3 == 0) ? 256 : p3);
			dissect_bertlv(subtvb, pinfo, tree, NULL);
		}
		break;
	case 0x14: /* TERMINAL RESPONSE */
		subtvb = tvb_new_subset_length(tvb, offset+DATA_OFFS, p3);
		call_dissector_with_data(sub_handle_cap, subtvb, pinfo, tree, GUINT_TO_POINTER(0x14));
		break;
	case 0x70: /* MANAGE CHANNEL */
		proto_tree_add_item(tree, hf_chan_op, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "Operation=%s ",
				val_to_str(p1, chan_op_vals, "%02x"));
		proto_tree_add_item(tree, hf_chan_nr, tvb, offset+P2_OFFS, 1, ENC_BIG_ENDIAN);
		if (p1 == 0) { /* OPEN */
			proto_tree_add_item(tree, hf_le, tvb, offset+P3_OFFS, 1, ENC_BIG_ENDIAN);
		}
		if (p1 == 0 && p2 == 0) {
			/* Logical channels are assigned by the card when P2 is 0. */
			col_append_fstr(pinfo->cinfo, COL_INFO, "(assign channel) ");
		} else {
			col_append_fstr(pinfo->cinfo, COL_INFO, "(channel: %d) ", p2);
		}
		break;
	case 0x78: /* GET IDENTITY */
	case 0xC0: /* GET RESPONSE */
	case 0xCA: /* GET DATA */
		proto_tree_add_item(tree, hf_le, tvb, offset+P3_OFFS, 1, ENC_BIG_ENDIAN);
		if (isSIMtrace) {
			proto_tree_add_item(tree, hf_apdu_data, tvb, offset+DATA_OFFS, p3, ENC_NA);
		}
		break;
	case 0xC2: /* ENVELOPE */
		proto_tree_add_item(tree, hf_le, tvb, offset+P3_OFFS, 1, ENC_BIG_ENDIAN);
		subtvb = tvb_new_subset_length(tvb, offset+DATA_OFFS, p3);
		dissect_bertlv(subtvb, pinfo, tree, NULL);
		break;
	/* FIXME: Missing SLEEP */
	case 0x04: /* INVALIDATE */
	case 0x44: /* REHABILITATE */
	default:
		return -1;
	}

	return offset;
}

static gint
dissect_rsp_apdu_tvb(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, proto_tree *sim_tree)
{
	guint16 sw;
	proto_item *ti = NULL;
	guint tvb_len = tvb_reported_length(tvb);

	if (tree && !sim_tree) {
		ti = proto_tree_add_item(tree, proto_gsm_sim, tvb, 0, -1, ENC_NA);
		sim_tree = proto_item_add_subtree(ti, ett_sim);
	}

	if ((tvb_len-offset) > 2) {
		proto_tree_add_item(sim_tree, hf_apdu_data, tvb, offset, tvb_len - 2, ENC_NA);
	}
	offset = tvb_len - 2;

	/* obtain status word */
	sw = tvb_get_ntohs(tvb, offset);
	/* proto_tree_add_item(sim_tree, hf_apdu_sw, tvb, offset, 2, ENC_BIG_ENDIAN); */
	proto_tree_add_uint_format(sim_tree, hf_apdu_sw, tvb, offset, 2, sw,
							"Status Word: %04x %s", sw, get_sw_string(sw));
	offset += 2;

	if (ti) {
		/* Always show status in info column when response only */
		col_add_fstr(pinfo->cinfo, COL_INFO, "Response, %s ", get_sw_string(sw));
	} else {
		switch (sw >> 8) {
		case 0x90:
		case 0x91:
		case 0x92:
		case 0x9e:
		case 0x9f:
			break;
		default:
			col_append_fstr(pinfo->cinfo, COL_INFO, ": %s ", get_sw_string(sw));
			break;
		}
	}

	return offset;
}

static gint
dissect_cmd_apdu_tvb(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, gboolean isSIMtrace)
{
	guint8 cla, ins, p1, p2, p3;
	proto_item *ti;
	proto_tree *sim_tree = NULL;
	gint rc = -1;
	guint tvb_len = tvb_reported_length(tvb);

	cla = tvb_get_guint8(tvb, offset);
	ins = tvb_get_guint8(tvb, offset+1);
	p1 = tvb_get_guint8(tvb, offset+2);
	p2 = tvb_get_guint8(tvb, offset+3);

	if (tvb_reported_length_remaining(tvb, offset+3) > 1) {
		p3 = tvb_get_guint8(tvb, offset+4);
	} else {
		/* Parameter 3 not present. */
		p3 = 0;
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_gsm_sim, tvb, 0, -1, ENC_NA);
		sim_tree = proto_item_add_subtree(ti, ett_sim);

		if ((cla & 0x50) == 0x40) {
			proto_tree_add_item(sim_tree, hf_apdu_cla_coding_ext, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(sim_tree, hf_apdu_cla_secure_messaging_ind_ext, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(sim_tree, hf_apdu_cla_log_chan_ext, tvb, offset, 1, ENC_BIG_ENDIAN);
		} else {
			proto_tree_add_item(sim_tree, hf_apdu_cla_coding, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(sim_tree, hf_apdu_cla_secure_messaging_ind, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(sim_tree, hf_apdu_cla_log_chan, tvb, offset, 1, ENC_BIG_ENDIAN);
		}
		proto_tree_add_item(sim_tree, hf_apdu_ins, tvb, offset+1, 1, ENC_BIG_ENDIAN);
	}
	offset += 2;

	if ((cla & 0x50) == 0x40) {
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(cla>>6, apdu_cla_coding_ext_vals, "%01x"));
	} else {
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(cla>>4, apdu_cla_coding_vals, "%01x"));
	}

	rc = dissect_gsm_apdu(ins, p1, p2, p3, tvb, offset, pinfo, sim_tree, isSIMtrace);

	if (rc == -1 && sim_tree) {
		/* default dissector */
		proto_tree_add_item(sim_tree, hf_apdu_p1, tvb, offset+0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_apdu_p2, tvb, offset+1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_apdu_p3, tvb, offset+2, 1, ENC_BIG_ENDIAN);
		if (p3 && (p3 <= tvb_reported_length_remaining(tvb, offset+3))) {
			proto_tree_add_item(sim_tree, hf_apdu_data, tvb, offset+3, p3, ENC_NA);
		}
	}
	offset += 3+p3;

	if (isSIMtrace) {
		return dissect_rsp_apdu_tvb(tvb, tvb_len-2, pinfo, tree, sim_tree);
	}

	return offset;
}

static int
dissect_gsm_sim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSM SIM");
	dissect_cmd_apdu_tvb(tvb, 0, pinfo, tree, TRUE);
	return tvb_captured_length(tvb);
}

static int
dissect_gsm_sim_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSM SIM");
	dissect_cmd_apdu_tvb(tvb, 0, pinfo, tree, FALSE);
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
			  FT_UINT8, BASE_HEX, NULL, 0,
			  "ISO 7816-4 APDU P3 (Parameter 3) Byte", HFILL }
		},
		{ &hf_apdu_data,
			{ "APDU Payload", "gsm_sim.apdu.data",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "ISO 7816-4 APDU Data Payload", HFILL }
		},
		{ &hf_apdu_sw,
			{ "Status Word (SW1:SW2)", "gsm_sim.apdu.sw",
			  FT_UINT16, BASE_HEX, VALS(sw_vals), 0,
			  "ISO 7816-4 APDU Status Word", HFILL }
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
		{ &hf_record_nr,
			{ "Record number", "gsm_sim.record_nr",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "Offset into binary file", HFILL }
		},
		{ &hf_auth_rand,
			{ "Random Challenge", "gsm_sim.auth_rand",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "GSM Authentication Random Challenge", HFILL }
		},
		{ &hf_auth_sres,
			{ "SRES", "gsm_sim.auth_sres",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "GSM Authentication SRES Response", HFILL }
		},
		{ &hf_auth_kc,
			{ "Kc", "gsm_sim.auth_kc",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "GSM Authentication Kc result", HFILL }
		},
		{ &hf_chan_nr,
			{ "Channel Number", "gsm_sim.chan_nr",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "ISO 7816-4 Logical Channel Number", HFILL }
		},
		{ &hf_le,
			{ "Length of Expected Response Data", "gsm_sim.le",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_chan_op,
			{ "Channel Operation", "gsm_sim.chan_op",
			  FT_UINT8, BASE_HEX, VALS(chan_op_vals), 0,
			  "ISO 7816-4 Logical Channel Operation", HFILL }
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
		{ &hf_tp_rfu11,
			{ "RFU", "gsm_sim.tp.rfu",
			  FT_UINT8, BASE_HEX, NULL, 0xf8,
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

		{ &hf_seek_mode,
			{ "Seek Mode", "gsm_sim.seek_mode",
			  FT_UINT8, BASE_HEX, VALS(seek_mode_vals), 0x0F,
			  NULL, HFILL },
		},
		{ &hf_seek_type,
			{ "Seek Type", "gsm_sim.seek_type",
			  FT_UINT8, BASE_DEC, VALS(seek_type_vals), 0x0F,
			  NULL, HFILL },
		},
		{ &hf_seek_rec_nr,
			{ "Seek Record Number", "gsm_sim.seek_rec_nr",
			  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL },
		},
	};
	static gint *ett[] = {
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
		&ett_tprof_b33
	};

	proto_gsm_sim = proto_register_protocol("GSM SIM 11.11", "GSM SIM",
						 "gsm_sim");

	proto_register_field_array(proto_gsm_sim, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	sim_handle = register_dissector("gsm_sim", dissect_gsm_sim, proto_gsm_sim);
	register_dissector("gsm_sim.command", dissect_gsm_sim_command, proto_gsm_sim);
	register_dissector("gsm_sim.response", dissect_gsm_sim_response, proto_gsm_sim);
	register_dissector("gsm_sim.bertlv", dissect_bertlv, proto_gsm_sim);
	sim_part_handle = register_dissector("gsm_sim.part", dissect_gsm_sim_part, proto_gsm_sim);
}

void
proto_reg_handoff_gsm_sim(void)
{
	dissector_add_uint("gsmtap.type", GSMTAP_TYPE_SIM, sim_handle);

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
