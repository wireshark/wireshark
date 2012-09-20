/* packet-gsm_sim.c
 * Routines for packet dissection of GSM SIM APDUs (GSM TS 11.11)
 *
 *	GSM TS 11.11 / 3GPP TS 51.011
 * 	3GPP TS 31.102
 * Copyright 2010-2011 by Harald Welte <laforge@gnumonks.org>
 *
 * $Id$
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/lapd_sapi.h>
#include <epan/prefs.h>

static int proto_gsm_sim = -1;

/* ISO 7816-4 APDU */
static int hf_apdu_cla = -1;
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

/* Chapter 5.2 TS 11.14 */
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
/* First byte */
static int hf_tp_prof_dld = -1;
static int hf_tp_sms_data_dld = -1;
static int hf_tp_cb_data_dld = -1;
static int hf_tp_menu_sel = -1;
static int hf_tp_9e_err = -1;
static int hf_tp_timer_exp = -1;
static int hf_tp_ussd_cc = -1;
static int hf_tp_auto_redial = -1;
/* Second byte (Other) */
static int hf_tp_cmd_res = -1;
static int hf_tp_cc_sim = -1;
static int hf_tp_cc_sim_cellid = -1;
static int hf_tp_mo_sms_sim = -1;
static int hf_tp_alpha_id = -1;
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
/* 7th byte (Multiple card proactive commands) */
static int hf_tp_pa_power_on = -1;
static int hf_tp_pa_power_off = -1;
static int hf_tp_pa_perform_card_apdu = -1;
static int hf_tp_pa_get_reader_status = -1;
static int hf_tp_pa_get_reader_status_id = -1;
/* 8th byte (Proactive SIM) */
static int hf_tp_pa_timer_start_stop = -1;
static int hf_tp_pa_timer_get_current = -1;
static int hf_tp_pa_prov_loci_date_tz = -1;
static int hf_tp_pa_get_inkey_binary = -1;
static int hf_tp_pa_set_up_idle_mode_text = -1;
static int hf_tp_pa_run_at_command = -1;
static int hf_tp_pa_2nd_alpha_setup_call = -1;
static int hf_tp_pa_2nd_capability_param = -1;

/* 12th byte (Proactive SIM) */
static int hf_tp_pa_open_chan = -1;
static int hf_tp_pa_close_chan = -1;
static int hf_tp_pa_recv_data = -1;
static int hf_tp_pa_send_data = -1;
static int hf_tp_pa_get_chan_status = -1;

/* 13th byte (Proactive SIM) */
static int hf_tp_bip_csd = -1;
static int hf_tp_bip_gprs = -1;
static int hf_tp_num_chans = -1;

/* 14th byte (Screen height) */
static int hf_tp_char_height = -1;
static int hf_tp_sizing_supp = -1;

/* 15th byte (Screen width) */
static int hf_tp_char_width = -1;
static int hf_tp_var_fonts = -1;

/* 16th byte (Screen effects) */
static int hf_tp_display_resize = -1;
static int hf_tp_text_wrapping = -1;
static int hf_tp_text_scrolling = -1;
static int hf_tp_width_red_menu = -1;

/* 17th byte (Proactive SIM) */
static int hf_tp_bip_tcp = -1;
static int hf_tp_bip_udp = -1;

/* 19th byte (TIA/EIA-136) */
static int hf_tp_tia_eia_version = -1;

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

static dissector_handle_t sub_handle_cap;


static const int *tprof_b1_fields[] = {
	&hf_tp_prof_dld,
	&hf_tp_sms_data_dld,
	&hf_tp_cb_data_dld,
	&hf_tp_menu_sel,
	&hf_tp_9e_err,
	&hf_tp_timer_exp,
	&hf_tp_ussd_cc,
	&hf_tp_auto_redial,
	NULL
};

static const int *tprof_b2_fields[] = {
	&hf_tp_cmd_res,
	&hf_tp_cc_sim,
	&hf_tp_cc_sim_cellid,
	&hf_tp_mo_sms_sim,
	&hf_tp_alpha_id,
	&hf_tp_ucs2_entry,
	&hf_tp_ucs2_display,
	&hf_tp_display_ext,
	NULL
};

static const int *tprof_b3_fields[] = {
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

static const int *tprof_b4_fields[] = {
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

static const int *tprof_b5_fields[] = {
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

static const int *tprof_b6_fields[] = {
	&hf_tp_ev_lang_sel,
	&hf_tp_ev_brows_term,
	&hf_tp_ev_data_avail,
	&hf_tp_ev_chan_status,
	NULL
};

static const int *tprof_b7_fields[] = {
	&hf_tp_pa_power_on,
	&hf_tp_pa_power_off,
	&hf_tp_pa_perform_card_apdu,
	&hf_tp_pa_get_reader_status,
	&hf_tp_pa_get_reader_status_id,
	NULL
};

static const int *tprof_b8_fields[] = {
	&hf_tp_pa_timer_start_stop,
	&hf_tp_pa_timer_get_current,
	&hf_tp_pa_prov_loci_date_tz,
	&hf_tp_pa_get_inkey_binary,
	&hf_tp_pa_set_up_idle_mode_text,
	&hf_tp_pa_run_at_command,
	&hf_tp_pa_2nd_alpha_setup_call,
	&hf_tp_pa_2nd_capability_param,
	NULL
};

static const int *tprof_b9_fields[] = {
	/* FIXME: fill missing values */
	NULL
};

static const int *tprof_b10_fields[] = {
	/* FIXME: fill missing values */
	NULL
};

static const int *tprof_b11_fields[] = {
	/* FIXME: fill missing values */
	NULL
};

static const int *tprof_b12_fields[] = {
	&hf_tp_pa_open_chan,
	&hf_tp_pa_close_chan,
	&hf_tp_pa_recv_data,
	&hf_tp_pa_send_data,
	&hf_tp_pa_get_chan_status,
	NULL
};

static const int *tprof_b13_fields[] = {
	&hf_tp_bip_csd,
	&hf_tp_bip_gprs,
	&hf_tp_num_chans,
	NULL
};

static const int *tprof_b14_fields[] = {
	&hf_tp_char_height,
	&hf_tp_sizing_supp,
	NULL
};

static const int *tprof_b15_fields[] = {
	&hf_tp_char_width,
	&hf_tp_var_fonts,
	NULL
};

static const int *tprof_b16_fields[] = {
	&hf_tp_display_resize,
	&hf_tp_text_wrapping,
	&hf_tp_text_scrolling,
	&hf_tp_width_red_menu,
	NULL
};
static const int *tprof_b17_fields[] = {
	&hf_tp_bip_tcp,
	&hf_tp_bip_udp,
	NULL
};
static const int *tprof_b18_fields[] = {
	NULL
};
static const int *tprof_b19_fields[] = {
	&hf_tp_tia_eia_version,
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

static const value_string apdu_cla_vals[] = {
	{ 0xa0,	"GSM" },
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
	{ 0xA2, "SEEK" },
	{ 0x32, "INCREASE" },
	{ 0x20, "VERIFY CHV" },
	{ 0x24, "CHANGE CHV" },
	{ 0x26, "DISABLE CHV" },
	{ 0x28, "ENABLE CHV" },
	{ 0x2C, "UNBLOCK CHV" },
	{ 0x04, "INVALIDATE" },
	{ 0x44, "REHABILITATE" },
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
	{ 0x7f20, "DF.GSM" },
	{ 0x7f10, "DF.TELECOM" },
	{ 0x7f22, "DF.IS-41" },
	{ 0x7f23, "DF.FP-CTS" },
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
	{ 0x5f40, "DF.EIA/TIA-533" },
	{ 0x5f60, "DF.CTS" },
	{ 0x5f70, "DF.SoLSA" },
	{ 0x5f3c, "DF.MExE" },
#if 0
	{ 0, NULL }
};

static const value_string adf_usim_dfs[] = {
#endif
	{ 0x5f3a, "DF.PHONEBOOK" },
	{ 0x5f3b, "DF.GSM-ACCESS" },
	{ 0x5f3c, "DF.MExE" },
	{ 0x5f70, "DF.SoLSA" },
	{ 0x5f40, "DF.WLAN" },
#if 0
	{ 0, NULL }
};

static const value_string adf_usim_efs[] = {
#endif
	{ 0x6f05, "EF.LI" },
	{ 0x6f06, "EF.ARR" },
	{ 0x6f07, "EF.IMSI" },
	{ 0x6f08, "EF.Keys" },
	{ 0x6f09, "EF.KeysPS" },
	{ 0x6f2c, "EF.DCK" },
	{ 0x6f31, "EF.HPPLMN" },
	{ 0x6f32, "EF.CNL" },
	{ 0x6f37, "EF.ACMax" },
	{ 0x6f38, "EF.USI" },
	{ 0x6f39, "EF.ACM" },
	{ 0x6f3b, "EF.FDN" },
	{ 0x6f3c, "EF.SMS" },
	{ 0x6f3e, "EF.GID1" },
	{ 0x6f3f, "EF.GID2" },
	{ 0x6f40, "EF.MSISDN" },
	{ 0x6f41, "EF.PUCI" },
	{ 0x6f42, "EF.SMSP" },
	{ 0x6f43, "EF.SMSS" },
	{ 0x6f45, "EF.CBMI" },
	{ 0x6f46, "EF.SPN" },
	{ 0x6f47, "EF.SMSR" },
	{ 0x6f48, "EF.CBMID" },
	{ 0x6f49, "EF.SIN" },
	{ 0x6f4b, "EF.EXT2" },
	{ 0x6f4c, "EF.EXT3" },
	{ 0x6f4d, "EF.BDN" },
	{ 0x6f4e, "EF.EXT5" },
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
	{ 0x6fd9, "EF.EHPLMN" },
	{ 0x6f73, "EF.PSLOCI" },
	{ 0x6f78, "EF.ACC" },
	{ 0x6f7b, "EF.FPLMN" },
	{ 0x6f7e, "EF.LOCI" },
	{ 0x6f80, "EF.ICI" },
	{ 0x6f81, "EF.OCI" },
	{ 0x6f82, "EF.ICT" },
	{ 0x6f83, "EF.OCT" },
	{ 0x6fad, "EF.AD" },
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
	{ 0x6f4f, "EF.CCP2" },
	{ 0x6fb1, "EF.VGCS" },
	{ 0x6fb2, "EF.VGCSS" },
	{ 0x6fb3, "EF.VBS" },
	{ 0x6fb4, "EF.VBSS" },
	{ 0x6fd4, "EF.VGCSCA" },
	{ 0x6fd5, "EF.VBSCA" },
	{ 0x6fd6, "EF.GBAP" },
	{ 0x6fd7, "EF.MSK" },
	{ 0x6fd8, "EF.MUK" },
	{ 0x6fda, "EF.GBANL" },
#if 0
	{ 0, NULL }
};

static const value_string df_phonebook_efs[] = {
#endif
	{ 0x4f30, "EF.PBR" },
	{ 0x4f4a, "EF.EXT1" },
	{ 0x4f4b, "EF.AAS" },
	{ 0x4f4c, "EF.GAS" },
	{ 0x4f22, "EF.FSC" },
	{ 0x4f23, "EF.CC" },
	{ 0x4f24, "EF.PUID" },
	{ 0x4f3a, "EF.ADN" },
	{ 0x4f09, "EF.PBC" },
	{ 0x4f11, "EF.ANRA" },
	{ 0x4f13, "EF.ANRB" },
	{ 0x4f50, "EF.EMAIL" },
	{ 0x4f19, "EF.SNE" },
	{ 0x4f21, "EF.UID" },
	{ 0x4f26, "EF.GRP" },
	{ 0x4f15, "EF.ANRC" },
	{ 0x4f3b, "EF.ADN1" },
	{ 0x4f0a, "EF.PBC1" },
	{ 0x4f12, "EF.ANRA1" },
	{ 0x4f14, "EF.ANRB1" },
	{ 0x4f51, "EF.EMAIL1" },
	{ 0x4f1a, "EF.SNE1" },
	{ 0x4f20, "EF.UID1" },
	{ 0x4f25, "EF.GRP1" },
	{ 0x4f16, "EF.ANRC1" },
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
	{ 0x0404, "File ID not found" },
	{ 0x9408, "File is inconsistent with the command" },
	{ 0x9802, "No CHV initialized" },
	{ 0x9804, "Access condition not fulfilled / authentication failed" },
	{ 0x9808, "In contradiction with CHV status" },
	{ 0x9810, "In contradiction with invalidation status" },
	{ 0x9840, "Unsuccessful CHV verification, no attempt left / CHV blocked" },
	{ 0x9850, "Increase cannot be performed, max value reached" },
	{ 0x6b00, "Incorrect paramaeter P1 or P2" },
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

	switch (sw1) {
	case 0x91:
		return "Normal ending of command with info from proactive SIM";
	case 0x9e:
		return "Length of the response data given / SIM data download error";
	case 0x9f:
		return "Length of the response data";
	case 0x92:
		if ((sw & 0xf0) == 0x00)
			return "Command successful but after internal retry routine";
		break;
	case 0x67:
		return "Incorrect parameter P3";
	case 0x6d:
		return "Unknown instruction code";
	case 0x6e:
		return "Wrong instruction class";
	case 0x6f:
		return "Technical problem with no diacnostic";
	}
	return val_to_str(sw, sw_vals, "%04x");
}

static void
dissect_bertlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	unsigned int pos = 0;

	while (pos < tvb_length(tvb)) {
		guint8 tag, len;
		tvbuff_t *subtvb;

		proto_tree_add_item(tree, hf_cat_ber_tag, tvb, pos, 1, ENC_BIG_ENDIAN);

		/* FIXME: properly follow BER coding rules */
		tag = tvb_get_guint8(tvb, pos++);
		len = tvb_get_guint8(tvb, pos++);

		subtvb = tvb_new_subset(tvb, pos, len, len);
		switch (tag) {
		case 0xD0:	/* proactive command */
			call_dissector(sub_handle_cap, subtvb, pinfo, tree);
			break;
		}

		pos += len;
	}
}


#define P1_OFFS		0
#define P2_OFFS		1
#define P3_OFFS		2
#define DATA_OFFS	3

static int
dissect_gsm_apdu(guint8 ins, guint8 p1, guint8 p2, guint8 p3,
		 tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint8 g8;
	guint16 g16;
	tvbuff_t *subtvb;
	int i;

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(ins, apdu_ins_vals, "%02x"));

	switch (ins) {
	case 0xA4: /* SELECT */
		if (p3 < 2)
			break;
		switch (p1) {
		case 0x03:	/* parent DF */
			col_append_fstr(pinfo->cinfo, COL_INFO, "Parent DF ");
			break;
		case 0x04:	/* select by AID */
			col_append_fstr(pinfo->cinfo, COL_INFO, "Application %s ",
					tvb_bytes_to_str(tvb, offset+DATA_OFFS, p3));
			proto_tree_add_item(tree, hf_aid, tvb, offset+DATA_OFFS, p3, ENC_NA);
			break;

		case 0x09:	/* select by relative path */
			col_append_fstr(pinfo->cinfo, COL_INFO, ".");
			/* fallthrough */
		case 0x08:	/* select by absolute path */
			for (i = 0; i < p3; i += 2) {
				g16 = tvb_get_ntohs(tvb, offset+DATA_OFFS+i);
				col_append_fstr(pinfo->cinfo, COL_INFO, "/%s",
						val_to_str(g16, mf_dfs, "%04x"));
				proto_tree_add_item(tree, hf_file_id, tvb, offset+DATA_OFFS+i, 2, ENC_BIG_ENDIAN);
			}
			col_append_fstr(pinfo->cinfo, COL_INFO, " ");
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
	case 0xD6: /* UPDATE BINARY */
		col_append_fstr(pinfo->cinfo, COL_INFO, "Offset=%u ", p1 << 8 | p2);
		proto_tree_add_item(tree, hf_bin_offset, tvb, offset+P1_OFFS, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_apdu_data, tvb, offset+DATA_OFFS, p3, ENC_NA);
		break;
	case 0xB2: /* READ RECORD */
	case 0xDC: /* READ RECORD */
		col_append_fstr(pinfo->cinfo, COL_INFO, "RecordNr=%u ", p1);
		proto_tree_add_item(tree, hf_record_nr, tvb, offset+P1_OFFS, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_apdu_data, tvb, offset+DATA_OFFS, p3, ENC_NA);
		break;
	case 0xA2: /* SEEK */
		proto_tree_add_item(tree, hf_seek_mode, tvb, offset+P2_OFFS, 1, ENC_NA);
		proto_tree_add_item(tree, hf_seek_type, tvb, offset+P2_OFFS, 1, ENC_NA);
		offset += DATA_OFFS;
		proto_tree_add_item(tree, hf_apdu_data, tvb, offset, p3, ENC_NA);
		offset += p3;
		if ((p2 & 0xF0) == 0x20)
			proto_tree_add_item(tree, hf_seek_rec_nr, tvb, offset++, 1, ENC_NA);
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
		proto_tree_add_item(tree, hf_auth_rand, tvb, offset+DATA_OFFS, 16, ENC_NA);
		offset += 16;
		proto_tree_add_item(tree, hf_auth_sres, tvb, offset, 4, ENC_NA);
		offset += 4;
		proto_tree_add_item(tree, hf_auth_kc, tvb, offset, 8, ENC_NA);
		offset += 8;
		break;
	case 0x10: /* TERMINAL PROFILE */
		offset += DATA_OFFS;
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b1, ett_tprof_b1, tprof_b1_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b2, ett_tprof_b2, tprof_b2_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b3, ett_tprof_b3, tprof_b3_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b4, ett_tprof_b4, tprof_b4_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b5, ett_tprof_b5, tprof_b5_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b6, ett_tprof_b6, tprof_b6_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b7, ett_tprof_b7, tprof_b7_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b8, ett_tprof_b8, tprof_b8_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b9, ett_tprof_b9, tprof_b9_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b10, ett_tprof_b10, tprof_b10_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b11, ett_tprof_b11, tprof_b11_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b12, ett_tprof_b12, tprof_b12_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b13, ett_tprof_b13, tprof_b13_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b14, ett_tprof_b14, tprof_b14_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b15, ett_tprof_b15, tprof_b15_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b16, ett_tprof_b16, tprof_b16_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b17, ett_tprof_b17, tprof_b17_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b18, ett_tprof_b18, tprof_b18_fields, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, offset++, hf_tprof_b19, ett_tprof_b19, tprof_b19_fields, ENC_BIG_ENDIAN);
		break;
	case 0x12: /* FETCH */
		subtvb = tvb_new_subset(tvb, offset+DATA_OFFS, p3, p3);
		dissect_bertlv(subtvb, pinfo, tree);
		break;
	case 0x14: /* TERMINAL RESPONSE */
		subtvb = tvb_new_subset(tvb, offset+DATA_OFFS, p3, p3);
		call_dissector(sub_handle_cap, subtvb, pinfo, tree);
		break;
	case 0x70: /* MANAGE CHANNEL */
		proto_tree_add_item(tree, hf_chan_op, tvb, offset-3, 1, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "Operation=%s ",
				val_to_str(p1, chan_op_vals, "%02x"));
		switch (p1) {
		case 0x00: /* OPEN */
			/* Logical channels are assigned by the card, so in 'open' they are
			 * in the DATA, whereas in close their number is in P2 */
			proto_tree_add_item(tree, hf_chan_nr, tvb, offset+DATA_OFFS, 1, ENC_BIG_ENDIAN);
			g8 = tvb_get_guint8(tvb, offset+DATA_OFFS);
			col_append_fstr(pinfo->cinfo, COL_INFO, "Channel=%d ", g8);
			break;
		case 0x80: /* CLOSE */
			proto_tree_add_item(tree, hf_chan_nr, tvb, offset-2, 1, ENC_BIG_ENDIAN);
			col_append_fstr(pinfo->cinfo, COL_INFO, "Channel=%d ", p2);
			break;
		}
		break;
	/* FIXME: Missing SLEEP, GET RESPONSE, ENVELOPE */
	case 0x04: /* INVALIDATE */
	case 0x44: /* REHABILITATE */
	default:
		return -1;
	}

	return offset;
}

static int
dissect_apdu_tvb(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint8 cla, ins, p1, p2, p3;
	guint16 sw;
	proto_item *ti;
	proto_tree *sim_tree = NULL;
	int rc = -1;
	guint tvb_len = tvb_length(tvb);

	cla = tvb_get_guint8(tvb, offset);
	ins = tvb_get_guint8(tvb, offset+1);
	p1 = tvb_get_guint8(tvb, offset+2);
	p2 = tvb_get_guint8(tvb, offset+3);
	p3 = tvb_get_guint8(tvb, offset+4);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_gsm_sim, tvb, 0, -1, ENC_NA);
		sim_tree = proto_item_add_subtree(ti, ett_sim);

		proto_tree_add_item(sim_tree, hf_apdu_cla, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_apdu_ins, tvb, offset+1, 1, ENC_BIG_ENDIAN);
	}
	offset += 2;

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(cla, apdu_cla_vals, "%02x"));

	/* if (cla == 0xA0) */
		rc = dissect_gsm_apdu(ins, p1, p2, p3, tvb, offset, pinfo, sim_tree);

	if (rc == -1 && sim_tree) {
		/* default dissector */
		proto_tree_add_item(sim_tree, hf_apdu_p1, tvb, offset+0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_apdu_p2, tvb, offset+1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_apdu_p3, tvb, offset+2, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(sim_tree, hf_apdu_data, tvb, offset+3, p3, ENC_NA);
	}
	offset += 3;

	/* obtain status word */
	sw = tvb_get_ntohs(tvb, tvb_len-2);
	/* proto_tree_add_item(sim_tree, hf_apdu_sw, tvb, tvb_len-2, 2, ENC_BIG_ENDIAN); */
	proto_tree_add_uint_format(sim_tree, hf_apdu_sw, tvb, tvb_len-2, 2, sw,
				   "Status Word: %04x %s", sw, get_sw_string(sw));

	switch (sw >> 8) {
	case 0x61:
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
	return offset;
}

static void
dissect_gsm_sim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_apdu_tvb(tvb, 0, pinfo, tree);
}

void
proto_reg_handoff_gsm_sim(void);

void
proto_register_gsm_sim(void)
{
	static hf_register_info hf[] = {
		{ &hf_apdu_cla,
			{ "Class", "gsm_sim.apdu.cla",
			  FT_UINT8, BASE_HEX, VALS(apdu_cla_vals), 0,
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
			  "TP Profile Downolad", HFILL }
		},
		{ &hf_tp_sms_data_dld,
			{ "SMS-PP Data Download", "gsm_sim.tp.sms_data_dld",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  "TP SMS-PP Data Downolad", HFILL }
		},
		{ &hf_tp_cb_data_dld,
			{ "CB Data Download", "gsm_sim.tp.cb_data_dld",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  "TP Cell Broadcast Data Downolad", HFILL }
		},
		{ &hf_tp_menu_sel,
			{ "Menu Selection", "gsm_sim.tp.menu_sel",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  "TP Menu Selection", HFILL }
		},
		{ &hf_tp_9e_err,
			{ "Menu Selection", "gsm_sim.tp.9e_err",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  "TP 9EXX response code for SIM data download error", HFILL }
		},
		{ &hf_tp_timer_exp,
			{ "Timer expiration", "gsm_sim.tp.timer_exp",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
			  "TP Timer expiration", HFILL }
		},
		{ &hf_tp_ussd_cc,
			{ "USSD string data in Call Control", "gsm_sim.tp.ussd_cc",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  "TP USSD string data object in Call Control", HFILL }
		},
		{ &hf_tp_auto_redial,
			{ "Envelope CC during automatic redial", "gsm_sim.tp.auto_redial",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  "TP Envelope CC always sent to SIM during automatic redial", HFILL }
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
			{ "Call Control by SIM", "gsm_sim.tp.cc_sim",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  "TP Call Control by SIM", HFILL }
		},
		{ &hf_tp_cc_sim_cellid,
			{ "Cell ID in Call Control by SIM", "gsm_sim.tp.cc_sim_cellid",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
			  "TP Cell ID included in Call Control by SIM", HFILL }
		},
		{ &hf_tp_mo_sms_sim,
			{ "MO SMS control by SIM", "gsm_sim.tp.mo_sms_sim",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
			  "TP MO short message control by SIM", HFILL }
		},
		{ &hf_tp_alpha_id,
			{ "Alpha identifier according 9.1.3", "gsm_sim.tp.alpha_id",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
			  "TP Handling of alpha identifier according to 9.1.3", HFILL }
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
			{ "Event: Cardreader status", "gsm_sim.tp.evt.card_status",
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
			{ "Proactive SIM: Binary choice in GET INKEY", "gsm_sim.tp.pa.get_inkey_bin",
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
			{ "Proactive SIM: 2nd alpha identifier in SET UP CALL", "gsm_sim.tp.pa.2nd_alpha_id",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
			  NULL, HFILL }
		},
		{ &hf_tp_pa_2nd_capability_param,
			{ "Proactive SIM: 2nd capability config param", "gsm_sim.tp.pa.2nd_capa_conf",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 9 */
		{ &hf_tprof_b9,
			{ "Terminal Profile Byte 9", "gsm_sim.tp.b9",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 10 */
		{ &hf_tprof_b10,
			{ "Terminal Profile Byte 10", "gsm_sim.tp.b10",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 11 */
		{ &hf_tprof_b11,
			{ "Terminal Profile Byte 11", "gsm_sim.tp.b11",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 12 */
		{ &hf_tprof_b12,
			{ "Terminal Profile Byte 12", "gsm_sim.tp.b12",
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

		/* Terminal Profile Byte 13 */
		{ &hf_tprof_b13,
			{ "Terminal Profile Byte 13 (Bearer Independent protocol)", "gsm_sim.tp.b13",
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
		{ &hf_tp_sizing_supp,
			{ "Screen Sizing", "gsm_sim.tp.disp_sizing",
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
			  FT_UINT8, BASE_DEC, NULL, 0x3f,
			  NULL, HFILL },
		},
		{ &hf_tp_var_fonts,
			{ "Variable-size fonts", "gsm_sim.tp.var_fonts",
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
		{ &hf_tp_width_red_menu,
			{ "Width reduction when in menu", "gsm_sim.tp.display.width_red_menu",
			  FT_UINT8, BASE_DEC, NULL, 0xe0,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 17 */
		{ &hf_tprof_b17,
			{ "Terminal Profile Byte 17 (Bearer independent protocol)", "gsm_sim.tp.b17",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_bip_tcp,
			{ "TCP transport", "gsm_sim.tp.bip.tcp",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
			  NULL, HFILL }
		},
		{ &hf_tp_bip_udp,
			{ "UDP transport", "gsm_sim.tp.bip.udp",
			  FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
			  NULL, HFILL }
		},

		/* Terminal Profile Byte 18 */
		{ &hf_tprof_b18,
			{ "Terminal Profile Byte 18 (Bearer independent protocol)", "gsm_sim.tp.b18",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},

		/* Terminal Profile Byte 19 */
		{ &hf_tprof_b19,
			{ "Terminal Profile Byte 19", "gsm_sim.tp.b19",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_tp_tia_eia_version,
			{ "TIA/EIA Version", "gsm_sim.tp.tia_eia_version",
			  FT_UINT8, BASE_DEC, NULL, 0x0f,
			  NULL, HFILL }
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
	};

	proto_gsm_sim = proto_register_protocol("GSM SIM 11.11", "GSM SIM",
						 "gsm_sim");

	proto_register_field_array(proto_gsm_sim, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("gsm_sim", dissect_gsm_sim, proto_gsm_sim);
}

/* This function is called once at startup and every time the user hits
 * 'apply' in the preferences dialogue */
void
proto_reg_handoff_gsm_sim(void)
{
	static gboolean initialized = FALSE;

	if (!initialized) {
		dissector_handle_t dtap_handle;
		dtap_handle = find_dissector("gsm_sim");
		dissector_add_uint("gsmtap.type", 4, dtap_handle);

		sub_handle_cap = find_dissector("etsi_cat");
	} else {
		/* preferences have been changed */
	}
}
