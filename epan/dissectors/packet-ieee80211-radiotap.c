/*
 *  packet-ieee80211-radiotap.c
 *	Decode packets with a Radiotap header
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <errno.h>

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <wsutil/pint.h>
#include <epan/crc32-tvb.h>
#include <wsutil/802_11-utils.h>
#include <epan/tap.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/arptypes.h>
#include "packet-ieee80211.h"
#include "packet-ieee80211-radiotap-iter.h"

void proto_register_radiotap(void);
void proto_reg_handoff_radiotap(void);

/* protocol */
static int proto_radiotap;

static int hf_radiotap_version;
static int hf_radiotap_pad;
static int hf_radiotap_length;
static int hf_radiotap_present;

static int hf_radiotap_tlv_type;
static int hf_radiotap_tlv_datalen;
static int hf_radiotap_unknown_tlv_data;

static int hf_radiotap_mactime;
/* static int hf_radiotap_channel; */
static int hf_radiotap_channel_frequency;
static int hf_radiotap_channel_flags;
static int hf_radiotap_channel_flags_700mhz;
static int hf_radiotap_channel_flags_800mhz;
static int hf_radiotap_channel_flags_900mhz;
static int hf_radiotap_channel_flags_turbo;
static int hf_radiotap_channel_flags_cck;
static int hf_radiotap_channel_flags_ofdm;
static int hf_radiotap_channel_flags_2ghz;
static int hf_radiotap_channel_flags_5ghz;
static int hf_radiotap_channel_flags_passive;
static int hf_radiotap_channel_flags_dynamic;
static int hf_radiotap_channel_flags_gfsk;
static int hf_radiotap_channel_flags_gsm;
static int hf_radiotap_channel_flags_sturbo;
static int hf_radiotap_channel_flags_half;
static int hf_radiotap_channel_flags_quarter;
static int hf_radiotap_rxflags;
static int hf_radiotap_rxflags_badplcp;
static int hf_radiotap_txflags;
static int hf_radiotap_txflags_fail;
static int hf_radiotap_txflags_cts;
static int hf_radiotap_txflags_rts;
static int hf_radiotap_txflags_noack;
static int hf_radiotap_txflags_noseqno;
static int hf_radiotap_txflags_order;
static int hf_radiotap_xchannel_channel;
static int hf_radiotap_xchannel_frequency;
static int hf_radiotap_xchannel_flags;
static int hf_radiotap_xchannel_flags_turbo;
static int hf_radiotap_xchannel_flags_cck;
static int hf_radiotap_xchannel_flags_ofdm;
static int hf_radiotap_xchannel_flags_2ghz;
static int hf_radiotap_xchannel_flags_5ghz;
static int hf_radiotap_xchannel_flags_passive;
static int hf_radiotap_xchannel_flags_dynamic;
static int hf_radiotap_xchannel_flags_gfsk;
static int hf_radiotap_xchannel_flags_gsm;
static int hf_radiotap_xchannel_flags_sturbo;
static int hf_radiotap_xchannel_flags_half;
static int hf_radiotap_xchannel_flags_quarter;
static int hf_radiotap_xchannel_flags_ht20;
static int hf_radiotap_xchannel_flags_ht40u;
static int hf_radiotap_xchannel_flags_ht40d;
#if 0
static int hf_radiotap_xchannel_maxpower;
#endif
static int hf_radiotap_fhss_hopset;
static int hf_radiotap_fhss_pattern;
static int hf_radiotap_datarate;
static int hf_radiotap_antenna;
static int hf_radiotap_dbm_antsignal;
static int hf_radiotap_db_antsignal;
static int hf_radiotap_dbm_antnoise;
static int hf_radiotap_db_antnoise;
static int hf_radiotap_tx_attenuation;
static int hf_radiotap_db_tx_attenuation;
static int hf_radiotap_txpower;
static int hf_radiotap_data_retries;
static int hf_radiotap_vendor_ns;
static int hf_radiotap_ven_oui;
static int hf_radiotap_ven_subns;
static int hf_radiotap_ven_skip;
static int hf_radiotap_ven_item;
static int hf_radiotap_ven_data;
static int hf_radiotap_mcs;
static int hf_radiotap_mcs_known;
static int hf_radiotap_mcs_have_bw;
static int hf_radiotap_mcs_have_index;
static int hf_radiotap_mcs_have_gi;
static int hf_radiotap_mcs_have_format;
static int hf_radiotap_mcs_have_fec;
static int hf_radiotap_mcs_have_stbc;
static int hf_radiotap_mcs_have_ness;
static int hf_radiotap_mcs_ness_bit1;
static int hf_radiotap_mcs_bw;
static int hf_radiotap_mcs_index;
static int hf_radiotap_mcs_gi;
static int hf_radiotap_mcs_format;
static int hf_radiotap_mcs_fec;
static int hf_radiotap_mcs_stbc;
static int hf_radiotap_mcs_ness_bit0;
static int hf_radiotap_ampdu;
static int hf_radiotap_ampdu_ref;
static int hf_radiotap_ampdu_flags;
static int hf_radiotap_ampdu_flags_report_zerolen;
static int hf_radiotap_ampdu_flags_is_zerolen;
static int hf_radiotap_ampdu_flags_last_known;
static int hf_radiotap_ampdu_flags_is_last;
static int hf_radiotap_ampdu_flags_delim_crc_error;
static int hf_radiotap_ampdu_delim_crc;
static int hf_radiotap_ampdu_flags_eof_known;
static int hf_radiotap_ampdu_flags_eof;
static int hf_radiotap_vht;
static int hf_radiotap_vht_known;
static int hf_radiotap_vht_have_stbc;
static int hf_radiotap_vht_have_txop_ps;
static int hf_radiotap_vht_have_gi;
static int hf_radiotap_vht_have_sgi_nsym_da;
static int hf_radiotap_vht_have_ldpc_extra;
static int hf_radiotap_vht_have_bf;
static int hf_radiotap_vht_have_bw;
static int hf_radiotap_vht_have_gid;
static int hf_radiotap_vht_have_p_aid;
static int hf_radiotap_vht_stbc;
static int hf_radiotap_vht_txop_ps;
static int hf_radiotap_vht_gi;
static int hf_radiotap_vht_sgi_nsym_da;
static int hf_radiotap_vht_ldpc_extra;
static int hf_radiotap_vht_bf;
static int hf_radiotap_vht_bw;
static int hf_radiotap_vht_nsts[4];
static int hf_radiotap_vht_mcs[4];
static int hf_radiotap_vht_nss[4];
static int hf_radiotap_vht_coding[4];
static int hf_radiotap_vht_datarate[4];
static int hf_radiotap_vht_gid;
static int hf_radiotap_vht_p_aid;
static int hf_radiotap_vht_user;
static int hf_radiotap_timestamp;
static int hf_radiotap_timestamp_ts;
static int hf_radiotap_timestamp_accuracy;
static int hf_radiotap_timestamp_unit;
static int hf_radiotap_timestamp_spos;
static int hf_radiotap_timestamp_flags_32bit;
static int hf_radiotap_timestamp_flags_accuracy;

/* "Present" flags */
static int hf_radiotap_present_word;
static int hf_radiotap_present_tsft;
static int hf_radiotap_present_flags;
static int hf_radiotap_present_rate;
static int hf_radiotap_present_channel;
static int hf_radiotap_present_fhss;
static int hf_radiotap_present_dbm_antsignal;
static int hf_radiotap_present_dbm_antnoise;
static int hf_radiotap_present_lock_quality;
static int hf_radiotap_present_tx_attenuation;
static int hf_radiotap_present_db_tx_attenuation;
static int hf_radiotap_present_dbm_tx_power;
static int hf_radiotap_present_antenna;
static int hf_radiotap_present_db_antsignal;
static int hf_radiotap_present_db_antnoise;
static int hf_radiotap_present_hdrfcs;
static int hf_radiotap_present_rxflags;
static int hf_radiotap_present_txflags;
static int hf_radiotap_present_data_retries;
static int hf_radiotap_present_xchannel;
static int hf_radiotap_present_mcs;
static int hf_radiotap_present_ampdu;
static int hf_radiotap_present_vht;
static int hf_radiotap_present_timestamp;
static int hf_radiotap_present_he;
static int hf_radiotap_present_he_mu;
static int hf_radiotap_present_0_length_psdu;
static int hf_radiotap_present_l_sig;
static int hf_radiotap_present_tlv;
static int hf_radiotap_present_reserved;
static int hf_radiotap_present_rtap_ns;
static int hf_radiotap_present_vendor_ns;
static int hf_radiotap_present_ext;

/* "present.flags" flags */
static int hf_radiotap_flags;
static int hf_radiotap_flags_cfp;
static int hf_radiotap_flags_preamble;
static int hf_radiotap_flags_wep;
static int hf_radiotap_flags_frag;
static int hf_radiotap_flags_fcs;
static int hf_radiotap_flags_datapad;
static int hf_radiotap_flags_badfcs;
static int hf_radiotap_flags_shortgi;

static int hf_radiotap_quality;
static int hf_radiotap_fcs;
static int hf_radiotap_fcs_bad;

/* HE Info fields */
static int hf_radiotap_he_ppdu_format;
static int hf_radiotap_he_bss_color_known;
static int hf_radiotap_he_beam_change_known;
static int hf_radiotap_he_ul_dl_known;
static int hf_radiotap_he_data_mcs_known;
static int hf_radiotap_he_data_dcm_known;
static int hf_radiotap_he_coding_known;
static int hf_radiotap_he_ldpc_extra_symbol_segment_known;
static int hf_radiotap_he_stbc_known;
static int hf_radiotap_he_spatial_reuse_1_known;
static int hf_radiotap_he_spatial_reuse_2_known;
static int hf_radiotap_he_spatial_reuse_3_known;
static int hf_radiotap_he_spatial_reuse_4_known;
static int hf_radiotap_he_data_bw_ru_allocation_known;
static int hf_radiotap_he_doppler_known;
static int hf_radiotap_he_pri_sec_80_mhz_known;
static int hf_radiotap_he_gi_known;
static int hf_radiotap_he_num_ltf_symbols_known;
static int hf_radiotap_he_pre_fec_padding_factor_known;
static int hf_radiotap_he_txbf_known;
static int hf_radiotap_he_pe_disambiguity_known;
static int hf_radiotap_he_txop_known;
static int hf_radiotap_he_midamble_periodicity_known;
static int hf_radiotap_he_ru_allocation_offset;
static int hf_radiotap_he_ru_allocation_offset_known;
static int hf_radiotap_he_pri_sec_80_mhz;
static int hf_radiotap_he_bss_color;
static int hf_radiotap_he_bss_color_unknown;
static int hf_radiotap_he_beam_change;
static int hf_radiotap_he_beam_change_unknown;
static int hf_radiotap_he_ul_dl;
static int hf_radiotap_he_ul_dl_unknown;
static int hf_radiotap_he_data_mcs;
static int hf_radiotap_he_data_mcs_unknown;
static int hf_radiotap_he_data_dcm;
static int hf_radiotap_he_data_dcm_unknown;
static int hf_radiotap_he_coding;
static int hf_radiotap_he_coding_unknown;
static int hf_radiotap_he_ldpc_extra_symbol_segment;
static int hf_radiotap_he_ldpc_extra_symbol_segment_unknown;
static int hf_radiotap_he_stbc;
static int hf_radiotap_he_stbc_unknown;
static int hf_radiotap_spatial_reuse;
static int hf_radiotap_spatial_reuse_unknown;
static int hf_radiotap_he_su_reserved;
static int hf_radiotap_spatial_reuse_1;
static int hf_radiotap_spatial_reuse_1_unknown;
static int hf_radiotap_spatial_reuse_2;
static int hf_radiotap_spatial_reuse_2_unknown;
static int hf_radiotap_spatial_reuse_3;
static int hf_radiotap_spatial_reuse_3_unknown;
static int hf_radiotap_spatial_reuse_4;
static int hf_radiotap_spatial_reuse_4_unknown;
static int hf_radiotap_sta_id_user_captured;
static int hf_radiotap_he_mu_reserved;
static int hf_radiotap_data_bandwidth_ru_allocation;
static int hf_radiotap_data_bandwidth_ru_allocation_unknown;
static int hf_radiotap_gi;
static int hf_radiotap_gi_unknown;
static int hf_radiotap_ltf_symbol_size;
static int hf_radiotap_ltf_symbol_size_unknown;
static int hf_radiotap_num_ltf_symbols;
static int hf_radiotap_num_ltf_symbols_unknown;
static int hf_radiotap_d5_reserved_b11;
static int hf_radiotap_pre_fec_padding_factor;
static int hf_radiotap_pre_fec_padding_factor_unknown;
static int hf_radiotap_txbf;
static int hf_radiotap_txbf_unknown;
static int hf_radiotap_pe_disambiguity;
static int hf_radiotap_pe_disambiguity_unknown;
static int hf_radiotap_he_nsts;
static int hf_radiotap_he_doppler_value;
static int hf_radiotap_he_doppler_value_unknown;
static int hf_radiotap_he_d6_reserved_00e0;
static int hf_radiotap_he_txop_value;
static int hf_radiotap_he_txop_value_unknown;
static int hf_radiotap_midamble_periodicity;
static int hf_radiotap_midamble_periodicity_unknown;
static int hf_radiotap_he_info_data_1;
static int hf_radiotap_he_info_data_2;
static int hf_radiotap_he_info_data_3;
static int hf_radiotap_he_info_data_4;
static int hf_radiotap_he_info_data_5;
static int hf_radiotap_he_info_data_6;
static int hf_radiotap_he_mu_sig_b_mcs;
static int hf_radiotap_he_mu_sig_b_mcs_unknown;
static int hf_radiotap_he_mu_sig_b_mcs_known;
static int hf_radiotap_he_mu_sig_b_dcm;
static int hf_radiotap_he_mu_sig_b_dcm_unknown;
static int hf_radiotap_he_mu_sig_b_dcm_known;
static int hf_radiotap_he_mu_chan2_center_26_tone_ru_bit_known;
static int hf_radiotap_he_mu_chan2_center_26_tone_ru_bit_unknown;
static int hf_radiotap_he_mu_chan1_rus_known;
static int hf_radiotap_he_mu_chan1_rus_unknown;
static int hf_radiotap_he_mu_chan2_rus_known;
static int hf_radiotap_he_mu_chan2_rus_unknown;
static int hf_radiotap_he_mu_reserved_f1_b10_b11;
static int hf_radiotap_he_mu_chan1_center_26_tone_ru_bit_known;
static int hf_radiotap_he_mu_chan1_center_26_tone_ru_bit_unknown;
static int hf_radiotap_he_mu_chan1_center_26_tone_ru_value;
static int hf_radiotap_he_mu_sig_b_compression_known;
static int hf_radiotap_he_mu_sig_b_compression_unknown;
static int hf_radiotap_he_mu_sig_b_compression_from_sig_a;
static int hf_radiotap_he_mu_sig_b_syms_mu_mimo_users_known;
static int hf_radiotap_he_mu_sig_b_syms_mu_mimo_users_unknown;
static int hf_radiotap_he_mu_info_flags_1;
static int hf_radiotap_he_mu_bw_from_bw_in_sig_a;
static int hf_radiotap_he_mu_bw_from_bw_in_sig_a_unknown;
static int hf_radiotap_he_mu_bw_from_bw_in_sig_a_known;
static int hf_radiotap_he_mu_sig_b_syms_mu_mimo_users;
static int hf_radiotap_he_mu_preamble_puncturing;
static int hf_radiotap_he_mu_preamble_puncturing_unknown;
static int hf_radiotap_he_mu_preamble_puncturing_known;
static int hf_radiotap_he_mu_chan2_center_26_tone_ru_value;
static int hf_radiotap_he_mu_reserved_f2_b12_b15;
static int hf_radiotap_he_mu_info_flags_2;
static int hf_radiotap_he_mu_chan1_rus_0;
static int hf_radiotap_he_mu_chan1_rus_0_unknown;
static int hf_radiotap_he_mu_chan1_rus_1;
static int hf_radiotap_he_mu_chan1_rus_1_unknown;
static int hf_radiotap_he_mu_chan1_rus_2;
static int hf_radiotap_he_mu_chan1_rus_2_unknown;
static int hf_radiotap_he_mu_chan1_rus_3;
static int hf_radiotap_he_mu_chan1_rus_3_unknown;
static int hf_radiotap_he_mu_chan2_rus_0;
static int hf_radiotap_he_mu_chan2_rus_0_unknown;
static int hf_radiotap_he_mu_chan2_rus_1;
static int hf_radiotap_he_mu_chan2_rus_1_unknown;
static int hf_radiotap_he_mu_chan2_rus_2;
static int hf_radiotap_he_mu_chan2_rus_2_unknown;
static int hf_radiotap_he_mu_chan2_rus_3;
static int hf_radiotap_he_mu_chan2_rus_3_unknown;

/* 0-length-psdu */
static int hf_radiotap_0_length_psdu_type;

/* L-SIG */
static int hf_radiotap_l_sig_data_1;
static int hf_radiotap_l_sig_rate_known;
static int hf_radiotap_l_sig_length_known;
static int hf_radiotap_l_sig_reserved;
static int hf_radiotap_l_sig_data_2;
static int hf_radiotap_l_sig_rate;
static int hf_radiotap_l_sig_length;

/* U-SIG */
static int hf_radiotap_u_sig_common;
static int hf_radiotap_usig_phy_version_identifier_known;
static int hf_radiotap_usig_bw_known;
static int hf_radiotap_usig_ul_dl_known;
static int hf_radiotap_usig_bss_color_known;
static int hf_radiotap_usig_txop_known;
static int hf_radiotap_usig_bad_u_sig_crc;
static int hf_radiotap_usig_validate_bits_checked;
static int hf_radiotap_usig_validate_bits_ok;
static int hf_radiotap_usig_reserved;
static int hf_radiotap_usig_phy_version_id;
static int hf_radiotap_usig_bw;
static int hf_radiotap_usig_ul_dl;
static int hf_radiotap_usig_bss_color;
static int hf_radiotap_usig_txop;
static int hf_radiotap_usig_value_mu_ppdu;
static int hf_radiotap_usig_eht_mu_b20_b24;
static int hf_radiotap_usig_eht_mu_b20_b24_not_known;
static int hf_radiotap_usig_eht_mu_b25;
static int hf_radiotap_usig_eht_mu_b25_not_known;
static int hf_radiotap_usig_ppdu_type_and_comp_mode;
static int hf_radiotap_usig_validate1;
static int hf_radiotap_usig_validate1_not_known;
static int hf_radiotap_usig_punctured_channel_info;
static int hf_radiotap_usig_punctured_channel_info_not_known;
static int hf_radiotap_usig_validate2;
static int hf_radiotap_usig_validate2_not_known;
static int hf_radiotap_usig_eht_sig_mcs;
static int hf_radiotap_usig_eht_sig_mcs_not_known;
static int hf_radiotap_usig_number_eht_sig_symbols;
static int hf_radiotap_usig_number_eht_sig_symbols_not_known;
static int hf_radiotap_usig_crc;
static int hf_radiotap_usig_crc_not_known;
static int hf_radiotap_usig_tail;
static int hf_radiotap_usig_tail_not_known;
static int hf_radiotap_u_sig_mask;
static int hf_radiotap_usig_value_tb_ppdu;
static int hf_radiotap_usig_eht_tb_b20_b25;
static int hf_radiotap_usig_eht_tb_b20_b25_not_known;
static int hf_radiotap_usig_eht_tb_validate1;
static int hf_radiotap_usig_eht_tb_validate1_not_known;
static int hf_radiotap_usig_eht_tb_spatial_reuse_1;
static int hf_radiotap_usig_eht_tb_spatial_reuse_1_not_known;
static int hf_radiotap_usig_eht_tb_spatial_reuse_2;
static int hf_radiotap_usig_eht_tb_spatial_reuse_2_not_known;
static int hf_radiotap_usig_eht_tb_disregard;
static int hf_radiotap_usig_eht_tb_disregard_not_known;
static int hf_radiotap_usig_eht_tb_crc;
static int hf_radiotap_usig_eht_tb_crc_not_known;
static int hf_radiotap_usig_eht_tb_tail;
static int hf_radiotap_usig_eht_tb_tail_not_known;

/* EHT */
static int hf_radiotap_eht_known;
static int hf_radiotap_eht_reserved_1;
static int hf_radiotap_eht_spatial_reuse_known;
static int hf_radiotap_eht_guard_interval_known;
static int hf_radiotap_eht_reserved_8;
static int hf_radiotap_eht_number_ltf_symbols_known;
static int hf_radiotap_eht_ldpc_extra_symbol_segment_known;
static int hf_radiotap_eht_pre_fec_padding_factor_known;
static int hf_radiotap_eht_pe_disambiguity_known;
static int hf_radiotap_eht_disregard_known;
static int hf_radiotap_eht_reserved1;
static int hf_radiotap_eht_reserved_2;
static int hf_radiotap_eht_crc1_known;
static int hf_radiotap_eht_tail1_known;
static int hf_radiotap_eht_crc2_known;
static int hf_radiotap_eht_tail2_known;
static int hf_radiotap_eht_nss_known;
static int hf_radiotap_eht_beamformed_known;
static int hf_radiotap_eht_number_non_ofdma_users_known;
static int hf_radiotap_eht_user_encoding_block_crc_known;
static int hf_radiotap_eht_user_encoding_block_tail_known;
static int hf_radiotap_eht_ru_mru_size_known;
static int hf_radiotap_eht_ru_mru_index_known;
static int hf_radiotap_eht_tb_ru_allocation_known;
static int hf_radiotap_eht_primary_80mhz_channel_pos_known;
static int hf_radiotap_eht_reserved_fc;
static int hf_radiotap_eht_data0;
static int hf_radiotap_eht_data0_reserved1;
static int hf_radiotap_eht_data0_spatial_reuse;
static int hf_radiotap_eht_data0_spatial_reuse_not_known;
static int hf_radiotap_eht_data0_gi;
static int hf_radiotap_eht_data0_gi_not_known;
static int hf_radiotap_eht_data0_ltf_symbol_size;
static int hf_radiotap_eht_data0_number_ltf_symbols;
static int hf_radiotap_eht_data0_number_ltf_symbols_not_known;
static int hf_radiotap_eht_data0_ldpc_extra_symbol_segment;
static int hf_radiotap_eht_data0_ldpc_extra_symbol_segment_not_known;
static int hf_radiotap_eht_data0_pre_fec_padding_factor;
static int hf_radiotap_eht_data0_pre_fec_padding_factor_not_known;
static int hf_radiotap_eht_data0_pe_disambiguity;
static int hf_radiotap_eht_data0_pe_disambiguity_not_known;
static int hf_radiotap_eht_data0_disregard;
static int hf_radiotap_eht_data0_disregard_not_known;
static int hf_radiotap_eht_data0_crc1;
static int hf_radiotap_eht_data0_crc1_not_known;
static int hf_radiotap_eht_data0_tail1;
static int hf_radiotap_eht_data0_tail1_not_known;
static int hf_radiotap_eht_data1;
static int hf_radiotap_eht_data1_ru_mru_size;
static int hf_radiotap_eht_data1_ru_mru_size_not_known;
static int hf_radiotap_eht_data1_ru_mru_index;
static int hf_radiotap_eht_data1_ru_mru_index_not_known;
static int hf_radiotap_eht_data1_ru_alloc_c1_1_1;
static int hf_radiotap_eht_data1_ru_alloc_c1_1_1_not_known;
static int hf_radiotap_eht_data1_ru_alloc_c1_1_1_known;
static int hf_radiotap_eht_data1_reserved;
static int hf_radiotap_eht_data1_primary_80_mhz_chan_pos;
static int hf_radiotap_eht_data1_primary_80_mhz_chan_pos_not_known;
static int hf_radiotap_eht_data2;
static int hf_radiotap_eht_data2_ru_alloc_c2_1_1;
static int hf_radiotap_eht_data2_ru_alloc_c2_1_1_not_known;
static int hf_radiotap_eht_data2_ru_alloc_c2_1_1_known;
static int hf_radiotap_eht_data2_ru_alloc_c1_1_2;
static int hf_radiotap_eht_data2_ru_alloc_c1_1_2_not_known;
static int hf_radiotap_eht_data2_ru_alloc_c1_1_2_known;
static int hf_radiotap_eht_data2_ru_alloc_c2_1_2;
static int hf_radiotap_eht_data2_ru_alloc_c2_1_2_not_known;
static int hf_radiotap_eht_data2_ru_alloc_c2_1_2_known;
static int hf_radiotap_eht_data2_reserved;
static int hf_radiotap_eht_data3;
static int hf_radiotap_eht_data3_ru_alloc_c1_2_1;
static int hf_radiotap_eht_data3_ru_alloc_c1_2_1_not_known;
static int hf_radiotap_eht_data3_ru_alloc_c1_2_1_known;
static int hf_radiotap_eht_data3_ru_alloc_c2_2_1;
static int hf_radiotap_eht_data3_ru_alloc_c2_2_1_not_known;
static int hf_radiotap_eht_data3_ru_alloc_c2_2_1_known;
static int hf_radiotap_eht_data3_ru_alloc_c1_2_2;
static int hf_radiotap_eht_data3_ru_alloc_c1_2_2_not_known;
static int hf_radiotap_eht_data3_ru_alloc_c1_2_2_known;
static int hf_radiotap_eht_data3_reserved;
static int hf_radiotap_eht_data4;
static int hf_radiotap_eht_data4_ru_alloc_c2_2_2;
static int hf_radiotap_eht_data4_ru_alloc_c2_2_2_not_known;
static int hf_radiotap_eht_data4_ru_alloc_c2_2_2_known;
static int hf_radiotap_eht_data4_ru_alloc_c1_2_3;
static int hf_radiotap_eht_data4_ru_alloc_c1_2_3_not_known;
static int hf_radiotap_eht_data4_ru_alloc_c1_2_3_known;
static int hf_radiotap_eht_data4_ru_alloc_c2_2_3;
static int hf_radiotap_eht_data4_ru_alloc_c2_2_3_not_known;
static int hf_radiotap_eht_data4_ru_alloc_c2_2_3_known;
static int hf_radiotap_eht_data4_reserved;
static int hf_radiotap_eht_data5;
static int hf_radiotap_eht_data5_ru_alloc_c1_2_4;
static int hf_radiotap_eht_data5_ru_alloc_c1_2_4_not_known;
static int hf_radiotap_eht_data5_ru_alloc_c1_2_4_known;
static int hf_radiotap_eht_data5_ru_alloc_c2_2_4;
static int hf_radiotap_eht_data5_ru_alloc_c2_2_4_not_known;
static int hf_radiotap_eht_data5_ru_alloc_c2_2_4_known;
static int hf_radiotap_eht_data5_ru_alloc_c1_2_5;
static int hf_radiotap_eht_data5_ru_alloc_c1_2_5_not_known;
static int hf_radiotap_eht_data5_ru_alloc_c1_2_5_known;
static int hf_radiotap_eht_data5_reserved;
static int hf_radiotap_eht_data6;
static int hf_radiotap_eht_data6_ru_alloc_c2_2_5;
static int hf_radiotap_eht_data6_ru_alloc_c2_2_5_not_known;
static int hf_radiotap_eht_data6_ru_alloc_c2_2_5_known;
static int hf_radiotap_eht_data6_ru_alloc_c1_2_6;
static int hf_radiotap_eht_data6_ru_alloc_c1_2_6_not_known;
static int hf_radiotap_eht_data6_ru_alloc_c1_2_6_known;
static int hf_radiotap_eht_data6_ru_alloc_c2_2_6;
static int hf_radiotap_eht_data6_ru_alloc_c2_2_6_not_known;
static int hf_radiotap_eht_data6_ru_alloc_c2_2_6_known;
static int hf_radiotap_eht_data6_reserved;
static int hf_radiotap_eht_data7;
static int hf_radiotap_eht_data7_crc2;
static int hf_radiotap_eht_data7_tail2;
static int hf_radiotap_eht_data7_rsvd;
static int hf_radiotap_eht_data7_nss;
static int hf_radiotap_eht_data7_beamformed;
static int hf_radiotap_eht_data7_number_non_ofdma_users;
static int hf_radiotap_eht_data7_number_non_ofdma_users_not_known;
static int hf_radiotap_eht_data7_user_encode_crc;
static int hf_radiotap_eht_data7_user_encode_tail;
static int hf_radiotap_eht_data7_rsvd2;
static int hf_radiotap_eht_data8;
static int hf_radiotap_eht_data8_ru_alloc_ps_160;
static int hf_radiotap_eht_data8_ru_alloc_b0;
static int hf_radiotap_eht_data8_ru_alloc_b7_b1;
static int hf_radiotap_eht_data8_rsvd;
static int hf_radiotap_eht_user_info;
static int hf_radiotap_eht_ui_sta_id_known;
static int hf_radiotap_eht_ui_mcs_known;
static int hf_radiotap_eht_ui_coding_known;
static int hf_radiotap_eht_ui_rsvd_known;
static int hf_radiotap_eht_ui_nss_known;
static int hf_radiotap_eht_ui_beamforming_known;
static int hf_radiotap_eht_ui_spatial_config_known;
static int hf_radiotap_eht_ui_data_captured;
static int hf_radiotap_eht_ui_sta_id;
static int hf_radiotap_eht_ui_sta_id_not_known;
static int hf_radiotap_eht_ui_coding;
static int hf_radiotap_eht_ui_coding_not_known;
static int hf_radiotap_eht_ui_mcs;
static int hf_radiotap_eht_ui_mcs_not_known;
static int hf_radiotap_eht_ui_nss;
static int hf_radiotap_eht_ui_nss_not_known;
static int hf_radiotap_eht_ui_reserved;
static int hf_radiotap_eht_ui_reserved_not_known;
static int hf_radiotap_eht_ui_beamforming;
static int hf_radiotap_eht_ui_beamforming_not_known;
static int hf_radiotap_eht_ui_spatial_config;
static int hf_radiotap_eht_ui_rsvd1;


static const value_string eht_data_ru_mru_size_vals[] = {
	{ IEEE80211_RADIOTAP_EHT_RU_26, "26-tone RU" },
	{ IEEE80211_RADIOTAP_EHT_RU_52, "52-tone RU" },
	{ IEEE80211_RADIOTAP_EHT_RU_106, "106-tone RU" },
	{ IEEE80211_RADIOTAP_EHT_RU_242, "242-tone RU"},
	{ IEEE80211_RADIOTAP_EHT_RU_484, "484-tone RU"},
	{ IEEE80211_RADIOTAP_EHT_RU_996, "996-tone RU"},
	{ IEEE80211_RADIOTAP_EHT_RU_2_TIMES_996, "2x996-tone RU"},
	{ IEEE80211_RADIOTAP_EHT_RU_4_TIMES_994, "4x996-tone RU"},
	{ IEEE80211_RADIOTAP_EHT_RU_52_PLUS_26, "52+26-tone RU"},
	{ IEEE80211_RADIOTAP_EHT_RU_106_PLUS_26, "106+26-tone RU"},
	{ IEEE80211_RADIOTAP_EHT_RU_484_PLUS_242, "484+242-tone RU"},
	{ IEEE80211_RADIOTAP_EHT_RU_996_PLUS_484, "996+484-tone RU"},
	{ IEEE80211_RADIOTAP_EHT_RU_996_PLUS_484_242, "996+484+242-tone RU"},
	{ IEEE80211_RADIOTAP_EHT_RU_2_TIMES_996_PLUS_484, "2x996+484-tone RU"},
	{ IEEE80211_RADIOTAP_EHT_RU_3_TIMES_996, "3x996-tone RU"},
	{ IEEE80211_RADIOTAP_EHT_RU_3_TIMES_996_PLUS_484, "3x996+484-tone RU"},
	{ 0,  NULL}
};

/* S1G */
static int hf_radiotap_s1g_known;
static int hf_radiotap_s1g_s1g_ppdu_format_known;
static int hf_radiotap_s1g_response_indication_known;
static int hf_radiotap_s1g_guard_interval_known;
static int hf_radiotap_s1g_nss_known;
static int hf_radiotap_s1g_bandwidth_known;
static int hf_radiotap_s1g_mcs_known;
static int hf_radiotap_s1g_color_known;
static int hf_radiotap_s1g_uplink_indication_known;
static int hf_radiotap_s1g_reserved_1;
static int hf_radiotap_s1g_data_1;
static int hf_radiotap_s1g_s1g_ppdu_format;
static int hf_radiotap_s1g_response_indication;
static int hf_radiotap_s1g_reserved_2;
static int hf_radiotap_s1g_guard_interval;
static int hf_radiotap_s1g_nss;
static int hf_radiotap_s1g_bandwidth;
static int hf_radiotap_s1g_mcs;
static int hf_radiotap_s1g_data_2;
static int hf_radiotap_s1g_color;
static int hf_radiotap_s1g_uplink_indication;
static int hf_radiotap_s1g_rssi;
static int hf_radiotap_s1g_reserved_3;

static int ett_radiotap;
static int ett_radiotap_tlv;
static int ett_radiotap_present;
static int ett_radiotap_present_word;
static int ett_radiotap_flags;
static int ett_radiotap_rxflags;
static int ett_radiotap_txflags;
static int ett_radiotap_channel_flags;
static int ett_radiotap_xchannel_flags;
static int ett_radiotap_vendor;
static int ett_radiotap_mcs;
static int ett_radiotap_mcs_known;
static int ett_radiotap_ampdu;
static int ett_radiotap_ampdu_flags;
static int ett_radiotap_vht;
static int ett_radiotap_vht_known;
static int ett_radiotap_vht_user;
static int ett_radiotap_timestamp;
static int ett_radiotap_timestamp_flags;
static int ett_radiotap_he_info;
static int ett_radiotap_he_info_data_1;
static int ett_radiotap_he_info_data_2;
static int ett_radiotap_he_info_data_3;
static int ett_radiotap_he_info_data_4;
static int ett_radiotap_he_info_data_5;
static int ett_radiotap_he_info_data_6;
static int ett_radiotap_he_mu_info;
static int ett_radiotap_he_mu_info_flags_1;
static int ett_radiotap_he_mu_info_flags_2;
static int ett_radiotap_he_mu_chan_rus;
static int ett_radiotap_0_length_psdu;
static int ett_radiotap_l_sig;
static int ett_radiotap_l_sig_data_1;
static int ett_radiotap_l_sig_data_2;
static int ett_radiotap_unknown_tlv;

/* U-SIG */
static int ett_radiotap_u_sig;
static int ett_radiotap_u_sig_common;
static int ett_radiotap_u_sig_value;

/* S1G */
static int ett_radiotap_s1g;
static int ett_radiotap_s1g_known;
static int ett_radiotap_s1g_data_1;
static int ett_radiotap_s1g_data_2;

/* EHT */
static int ett_radiotap_eht;
static int ett_radiotap_eht_known;
static int ett_radiotap_eht_data;
static int ett_radiotap_eht_user_info;
static int ett_radiotap_eht_user_info_i;

static expert_field ei_radiotap_invalid_header_length;
static expert_field ei_radiotap_data_past_header;
static expert_field ei_radiotap_present;
static expert_field ei_radiotap_invalid_data_rate;

static dissector_handle_t ieee80211_radio_handle;

static capture_dissector_handle_t ieee80211_cap_handle;
static capture_dissector_handle_t ieee80211_datapad_cap_handle;

static dissector_table_t vendor_dissector_table;

/* Settings */
static bool radiotap_bit14_fcs;
static bool radiotap_interpret_high_rates_as_mcs;

#define USE_FCS_BIT        0
#define ASSUME_FCS_PRESENT 1
#define ASSUME_FCS_ABSENT  2
static const enum_val_t fcs_handling[] = {
	{ "use_fcs_bit", "Use the FCS bit", USE_FCS_BIT },
	{ "assume_fcs_present",  "Assume all packets have an FCS at the end", ASSUME_FCS_PRESENT },
	{ "assume_fcs_absent",  "Assume all packets don't have an FCS at the end", ASSUME_FCS_ABSENT },
	{ NULL, NULL, 0 }
};
static int radiotap_fcs_handling = USE_FCS_BIT;

#define BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define BITNO_8(x)  (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define BITNO_4(x)  (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define BITNO_2(x)  (((x) & 2) ? 1 : 0)
#define BIT(n)	(1U << n)

/* not officially defined (yet) */
#define IEEE80211_RADIOTAP_F_SHORTGI	0x80
#define IEEE80211_RADIOTAP_XCHANNEL	18

/* Official specifcation:
 *
 * http://www.radiotap.org/
 *
 * Unofficial and historical specifications:
 * http://madwifi-project.org/wiki/DevDocs/RadiotapHeader
 * NetBSD's ieee80211_radiotap.h file
 */

/*
 * Useful combinations of channel characteristics.
 */
#define	IEEE80211_CHAN_FHSS \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
#define	IEEE80211_CHAN_DSSS \
	(IEEE80211_CHAN_2GHZ)
#define	IEEE80211_CHAN_A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_B \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define	IEEE80211_CHAN_PUREG \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_G \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)
#define	IEEE80211_CHAN_108A \
	(IEEE80211_CHAN_A | IEEE80211_CHAN_TURBO)
#define	IEEE80211_CHAN_108G \
	(IEEE80211_CHAN_G | IEEE80211_CHAN_TURBO)
#define	IEEE80211_CHAN_108PUREG \
	(IEEE80211_CHAN_PUREG | IEEE80211_CHAN_TURBO)
#define	IEEE80211_CHAN_ST \
	(IEEE80211_CHAN_108A | IEEE80211_CHAN_STURBO)

#define MAX_MCS_VHT_INDEX	9
#define MAX_VHT_NSS             8

/*
 * Maps a VHT bandwidth index to ieee80211_vhtinfo.rates index.
 */
static const int ieee80211_vht_bw2rate_index[] = {
		/*  20Mhz total */	0,
		/*  40Mhz total */	1, 0, 0,
		/*  80Mhz total */	2, 1, 1, 0, 0, 0, 0,
		/* 160Mhz total */	3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0
};

struct mcs_vht_valid {
	bool valid[4][MAX_VHT_NSS]; /* indexed by bandwidth and NSS-1 */
};

static const struct mcs_vht_valid ieee80211_vhtvalid[MAX_MCS_VHT_INDEX+1] = {
		/* MCS  0  */
		{
			{	/* 20 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 40 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 80 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 160 Mhz */ { true,  true,  true,  true,  true,  true,  true,  true },
			}
		},
		/* MCS  1  */
		{
			{	/* 20 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 40 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 80 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 160 Mhz */ { true,  true,  true,  true,  true,  true,  true,  true },
			}
		},
		/* MCS  2  */
		{
			{	/* 20 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 40 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 80 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 160 Mhz */ { true,  true,  true,  true,  true,  true,  true,  true },
			}
		},
		/* MCS  3  */
		{
			{	/* 20 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 40 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 80 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 160 Mhz */ { true,  true,  true,  true,  true,  true,  true,  true },
			}
		},
		/* MCS  4  */
		{
			{	/* 20 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 40 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 80 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 160 Mhz */ { true,  true,  true,  true,  true,  true,  true,  true },
			}
		},
		/* MCS  5  */
		{
			{	/* 20 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 40 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 80 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 160 Mhz */ { true,  true,  true,  true,  true,  true,  true,  true },
			}
		},
		/* MCS  6  */
		{
			{	/* 20 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 40 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 80 Mhz */  { true,  true,  false, true,  true,  true,  false, true },
				/* 160 Mhz */ { true,  true,  true,  true,  true,  true,  true,  true },
			}
		},
		/* MCS  7  */
		{
			{	/* 20 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 40 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 80 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 160 Mhz */ { true,  true,  true,  true,  true,  true,  true,  true },
			}
		},
		/* MCS  8  */
		{
			{	/* 20 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 40 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 80 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 160 Mhz */ { true,  true,  true,  true,  true,  true,  true,  true },
			}
		},
		/* MCS  9  */
		{
			{	/* 20 Mhz */  { false, false, true,  false, false, true,  false, false },
				/* 40 Mhz */  { true,  true,  true,  true,  true,  true,  true,  true },
				/* 80 Mhz */  { true,  true,  true,  true,  true,  false, true,  true },
				/* 160 Mhz */ { true,  true,  false, true,  true,  true,  true,  true },
			}
		}
};

struct mcs_vht_info {
	const char *modulation;
	const char *coding_rate;
	float       rates[4][2]; /* indexed by bandwidth and GI length */
};

static const struct mcs_vht_info ieee80211_vhtinfo[MAX_MCS_VHT_INDEX+1] = {
		/* MCS  0  */
		{	"BPSK",		"1/2",
				{		/* 20 Mhz */  {    6.5f,		/* SGI */    7.2f, },
						/* 40 Mhz */  {   13.5f,		/* SGI */   15.0f, },
						/* 80 Mhz */  {   29.3f,		/* SGI */   32.5f, },
						/* 160 Mhz */ {   58.5f,		/* SGI */   65.0f, }
				}
		},
		/* MCS  1  */
		{	"QPSK",		"1/2",
				{		/* 20 Mhz */  {   13.0f,		/* SGI */   14.4f, },
						/* 40 Mhz */  {   27.0f,		/* SGI */   30.0f, },
						/* 80 Mhz */  {   58.5f,		/* SGI */   65.0f, },
						/* 160 Mhz */ {  117.0f,		/* SGI */  130.0f, }
				}
		},
		/* MCS  2  */
		{	"QPSK",		"3/4",
				{		/* 20 Mhz */  {   19.5f,		/* SGI */   21.7f, },
						/* 40 Mhz */  {   40.5f,		/* SGI */   45.0f, },
						/* 80 Mhz */  {   87.8f,		/* SGI */   97.5f, },
						/* 160 Mhz */ {  175.5f,		/* SGI */  195.0f, }
				}
		},
		/* MCS  3  */
		{	"16-QAM",	"1/2",
				{		/* 20 Mhz */  {   26.0f,		/* SGI */   28.9f, },
						/* 40 Mhz */  {   54.0f,		/* SGI */   60.0f, },
						/* 80 Mhz */  {  117.0f,		/* SGI */  130.0f, },
						/* 160 Mhz */ {  234.0f,		/* SGI */  260.0f, }
				}
		},
		/* MCS  4  */
		{	"16-QAM",	"3/4",
				{		/* 20 Mhz */  {   39.0f,		/* SGI */   43.3f, },
						/* 40 Mhz */  {   81.0f,		/* SGI */   90.0f, },
						/* 80 Mhz */  {  175.5f,		/* SGI */  195.0f, },
						/* 160 Mhz */ {  351.0f,		/* SGI */  390.0f, }
				}
		},
		/* MCS  5  */
		{	"64-QAM",	"2/3",
				{		/* 20 Mhz */  {   52.0f,		/* SGI */   57.8f, },
						/* 40 Mhz */  {  108.0f,		/* SGI */  120.0f, },
						/* 80 Mhz */  {  234.0f,		/* SGI */  260.0f, },
						/* 160 Mhz */ {  468.0f,		/* SGI */  520.0f, }
				}
		},
		/* MCS  6  */
		{	"64-QAM",	"3/4",
				{		/* 20 Mhz */  {   58.5f,		/* SGI */   65.0f, },
						/* 40 Mhz */  {  121.5f,		/* SGI */  135.0f, },
						/* 80 Mhz */  {  263.3f,		/* SGI */  292.5f, },
						/* 160 Mhz */ {  526.5f,		/* SGI */  585.0f, }
				}
		},
		/* MCS  7  */
		{	"64-QAM",	"5/6",
				{		/* 20 Mhz */  {   65.0f,		/* SGI */   72.2f, },
						/* 40 Mhz */  {  135.0f,		/* SGI */  150.0f, },
						/* 80 Mhz */  {  292.5f,		/* SGI */  325.0f, },
						/* 160 Mhz */ {  585.0f,		/* SGI */  650.0f, }
				}
		},
		/* MCS  8  */
		{	"256-QAM",	"3/4",
				{		/* 20 Mhz */  {   78.0f,		/* SGI */   86.7f, },
						/* 40 Mhz */  {  162.0f,		/* SGI */  180.0f, },
						/* 80 Mhz */  {  351.0f,		/* SGI */  390.0f, },
						/* 160 Mhz */ {  702.0f,		/* SGI */  780.0f, }
				}
		},
		/* MCS  9  */
		{	"256-QAM",	"5/6",
				{		/* 20 Mhz */  {   86.7f,		/* SGI */   96.3f, },
						/* 40 Mhz */  {  180.0f,		/* SGI */  200.0f, },
						/* 80 Mhz */  {  390.0f,		/* SGI */  433.3f, },
						/* 160 Mhz */ {  780.0f,		/* SGI */  866.7f, }
				}
		}
};

/* In order by value */
static const value_string vht_bandwidth[] = {
	{ IEEE80211_RADIOTAP_VHT_BW_20,    "20 MHz" },
	{ IEEE80211_RADIOTAP_VHT_BW_40,    "40 MHz" },
	{ IEEE80211_RADIOTAP_VHT_BW_20L,   "20 MHz lower" },
	{ IEEE80211_RADIOTAP_VHT_BW_20U,   "20 MHz upper" },
	{ IEEE80211_RADIOTAP_VHT_BW_80,    "80 MHz" },
	{ IEEE80211_RADIOTAP_VHT_BW_40L,   "40 MHz lower" },
	{ IEEE80211_RADIOTAP_VHT_BW_40U,   "40 MHz upper" },
	{ IEEE80211_RADIOTAP_VHT_BW_20LL,  "20 MHz, channel 1/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_20LU,  "20 MHz, channel 2/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_20UL,  "20 MHz, channel 3/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_20UU,  "20 MHz, channel 4/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_160,   "160 MHz" },
	{ IEEE80211_RADIOTAP_VHT_BW_80L,   "80 MHz lower" },
	{ IEEE80211_RADIOTAP_VHT_BW_80U,   "80 MHz upper" },
	{ IEEE80211_RADIOTAP_VHT_BW_40LL,  "40 MHz, channel 1/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_40LU,  "40 MHz, channel 2/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_40UL,  "40 MHz, channel 3/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_40UU,  "40 MHz, channel 4/4" },
	{ IEEE80211_RADIOTAP_VHT_BW_20LLL, "20 MHz, channel 1/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20LLU, "20 MHz, channel 2/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20LUL, "20 MHz, channel 3/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20LUU, "20 MHz, channel 4/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20ULL, "20 MHz, channel 5/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20ULU, "20 MHz, channel 6/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20UUL, "20 MHz, channel 7/8" },
	{ IEEE80211_RADIOTAP_VHT_BW_20UUU, "20 MHz, channel 8/8" },
	{ 0, NULL }
};
static value_string_ext vht_bandwidth_ext = VALUE_STRING_EXT_INIT(vht_bandwidth);

static const value_string mcs_bandwidth[] = {
	{ IEEE80211_RADIOTAP_MCS_BW_20,  "20 MHz" },
	{ IEEE80211_RADIOTAP_MCS_BW_40,  "40 MHz" },
	{ IEEE80211_RADIOTAP_MCS_BW_20L, "20 MHz lower" },
	{ IEEE80211_RADIOTAP_MCS_BW_20U, "20 MHz upper" },
	{0, NULL}
};

static const value_string mcs_format[] = {
	{ 0, "mixed" },
	{ 1, "greenfield" },
	{0, NULL},
};

static const value_string mcs_fec[] = {
	{ 0, "BCC" },
	{ 1, "LDPC" },
	{0, NULL}
};

static const value_string mcs_gi[] = {
	{ 0, "long" },
	{ 1, "short" },
	{0, NULL}
};

static const true_false_string preamble_type = {
	"Short",
	"Long",
};

static const value_string timestamp_unit[] = {
	{ IEEE80211_RADIOTAP_TS_UNIT_MSEC, "msec" },
	{ IEEE80211_RADIOTAP_TS_UNIT_USEC, "usec" },
	{ IEEE80211_RADIOTAP_TS_UNIT_NSEC, "nsec" },
	{ 0, NULL }
};

static const value_string timestamp_spos[] = {
	{ IEEE80211_RADIOTAP_TS_SPOS_MPDU, "first MPDU bit/symbol" },
	{ IEEE80211_RADIOTAP_TS_SPOS_ACQ, "signal acquisition" },
	{ IEEE80211_RADIOTAP_TS_SPOS_EOF, "end of frame" },
	{ IEEE80211_RADIOTAP_TS_SPOS_UNDEF, "undefined" },
	{ 0, NULL }
};

/* S1G */
static const value_string s1g_ppdu_format[] = {
	{ 0, "S1G 1M" },
	{ 1, "S1G Short" },
	{ 2, "S1G Long" },
	{ 0, NULL},
};

static const value_string s1g_response_indication[] = {
	{ 0, "No response" },
	{ 1, "NDP response" },
	{ 2, "Normal response" },
	{ 3, "Long response" },
	{ 0, NULL},
};

static const value_string s1g_guard_interval[] = {
	{ 0, "Long GI" },
	{ 1, "Short GI" },
	{ 0, NULL},
};

static const value_string s1g_nss[] = {
	{ 0, "1" },
	{ 1, "2" },
	{ 2, "3" },
	{ 3, "4" },
	{ 0, NULL},
};

static const value_string s1g_bandwidth[] = {
	{ 0, "1MHz channel" },
	{ 1, "2MHz channel" },
	{ 2, "4MHz channel" },
	{ 3, "8MHz channel" },
	{ 4, "16MHz channel" },
	{ 0, NULL},
};

static const value_string s1g_mcs[] = {
	{ 0, "0" },
	{ 1, "1" },
	{ 2, "2" },
	{ 3, "3" },
	{ 4, "4" },
	{ 5, "5" },
	{ 6, "6" },
	{ 7, "7" },
	{ 8, "8" },
	{ 9, "9" },
	{ 10, "10" },
	{ 0, NULL},
};

static const value_string s1g_color[] = {
	{ 0, "0" },
	{ 1, "1" },
	{ 2, "2" },
	{ 3, "3" },
	{ 4, "4" },
	{ 5, "5" },
	{ 6, "6" },
	{ 7, "7" },
	{ 0, NULL},
};

static const range_string tlv_type_rvals[] = {
	{ 0, IEEE80211_RADIOTAP_TLV_S1G - 1, "Bit-defined types" },
	{ IEEE80211_RADIOTAP_TLV_S1G, IEEE80211_RADIOTAP_TLV_S1G,     "S1G" },
	{ IEEE80211_RADIOTAP_TLV_U_SIG, IEEE80211_RADIOTAP_TLV_U_SIG, "U-SIG" },
	{ IEEE80211_RADIOTAP_TLV_EHT, IEEE80211_RADIOTAP_TLV_EHT, "EHT" },
	{ 0, 0, NULL },
};

/*
 * The NetBSD ieee80211_radiotap man page
 * (http://netbsd.gw.com/cgi-bin/man-cgi?ieee80211_radiotap+9+NetBSD-current)
 * says:
 *
 *    Radiotap capture fields must be naturally aligned.  That is, 16-, 32-,
 *    and 64-bit fields must begin on 16-, 32-, and 64-bit boundaries, respec-
 *    tively.  In this way, drivers can avoid unaligned accesses to radiotap
 *    capture fields.  radiotap-compliant drivers must insert padding before a
 *    capture field to ensure its natural alignment.  radiotap-compliant packet
 *    dissectors, such as tcpdump(8), expect the padding.
 */

static bool
capture_radiotap(const unsigned char * pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
	uint16_t it_len;
	uint32_t present, xpresent;
	uint8_t rflags;
	const struct ieee80211_radiotap_header *hdr;

	if (!BYTES_ARE_IN_FRAME(offset, len,
				sizeof(struct ieee80211_radiotap_header))) {
		return false;
	}
	hdr = (const struct ieee80211_radiotap_header *)pd;
	it_len = pletoh16(&hdr->it_len);
	if (!BYTES_ARE_IN_FRAME(offset, len, it_len))
		return false;

	if (it_len > len) {
		/* Header length is bigger than total packet length */
		return false;
	}

	if (it_len < sizeof(struct ieee80211_radiotap_header)) {
		/* Header length is shorter than fixed-length portion of header */
		return false;
	}

	present = pletoh32(&hdr->it_present);
	offset += (int)sizeof(struct ieee80211_radiotap_header);
	it_len -= (int)sizeof(struct ieee80211_radiotap_header);

	/* skip over other present bitmaps */
	xpresent = present;
	while (xpresent & BIT(IEEE80211_RADIOTAP_EXT)) {
		if (!BYTES_ARE_IN_FRAME(offset, 4, it_len)) {
			return false;
		}
		xpresent = pletoh32(pd + offset);
		offset += 4;
		it_len -= 4;
	}

	rflags = 0;

	/*
	 * IEEE80211_RADIOTAP_TSFT is the lowest-order bit,
	 * just skip over it.
	 */
	if (present & BIT(IEEE80211_RADIOTAP_TSFT)) {
		/* align it properly */
		if (offset & 7) {
			int pad = 8 - (offset & 7);
			offset += pad;
			it_len -= pad;
		}

		if (it_len < 8) {
			/* No room in header for this field. */
			return false;
		}
		/* That field is present, and it's 8 bytes long. */
		offset += 8;
		it_len -= 8;
	}

	/*
	 * IEEE80211_RADIOTAP_FLAGS is the next bit.
	 */
	if (present & BIT(IEEE80211_RADIOTAP_FLAGS)) {
		if (it_len < 1) {
			/* No room in header for this field. */
			return false;
		}
		/* That field is present; fetch it. */
		if (!BYTES_ARE_IN_FRAME(offset, len, 1)) {
			return false;
		}
		rflags = pd[offset];
	}

	/* 802.11 header follows */
	if (rflags & IEEE80211_RADIOTAP_F_DATAPAD)
		return call_capture_dissector(ieee80211_datapad_cap_handle, pd, offset + it_len, len, cpinfo, pseudo_header);

	return call_capture_dissector(ieee80211_cap_handle, pd, offset + it_len, len, cpinfo, pseudo_header);
}

static void
add_tlv_items(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset -= 4;

	proto_tree_add_item(tree, hf_radiotap_tlv_type, tvb,
			    offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_radiotap_tlv_datalen, tvb,
			    offset, 2, ENC_LITTLE_ENDIAN);
}

static const true_false_string tfs_known_unknown = {
	"Known",
	"Unknown"
};

static int * const data1_headers[] = {
	&hf_radiotap_he_ppdu_format,
	&hf_radiotap_he_bss_color_known,
	&hf_radiotap_he_beam_change_known,
	&hf_radiotap_he_ul_dl_known,
	&hf_radiotap_he_data_mcs_known,
	&hf_radiotap_he_data_dcm_known,
	&hf_radiotap_he_coding_known,
	&hf_radiotap_he_ldpc_extra_symbol_segment_known,
	&hf_radiotap_he_stbc_known,
	&hf_radiotap_he_spatial_reuse_1_known,
	&hf_radiotap_he_spatial_reuse_2_known,
	&hf_radiotap_he_spatial_reuse_3_known,
	&hf_radiotap_he_spatial_reuse_4_known,
	&hf_radiotap_he_data_bw_ru_allocation_known,
	&hf_radiotap_he_doppler_known,
	NULL
};

static const value_string he_pdu_format_vals[] = {
	{ IEEE80211_RADIOTAP_HE_PPDU_FORMAT_HE_SU,     "HE_SU" },
	{ IEEE80211_RADIOTAP_HE_PPDU_FORMAT_HE_EXT_SU, "HE_EXT_SU" },
	{ IEEE80211_RADIOTAP_HE_PPDU_FORMAT_HE_MU,     "HE_MU" },
	{ IEEE80211_RADIOTAP_HE_PPDU_FORMAT_HE_TRIG,   "HE_TRIG" },
	{ 0, NULL }
};

static int * const data2_headers[] = {
	&hf_radiotap_he_pri_sec_80_mhz_known,
	&hf_radiotap_he_gi_known,
	&hf_radiotap_he_num_ltf_symbols_known,
	&hf_radiotap_he_pre_fec_padding_factor_known,
	&hf_radiotap_he_txbf_known,
	&hf_radiotap_he_pe_disambiguity_known,
	&hf_radiotap_he_txop_known,
	&hf_radiotap_he_midamble_periodicity_known,
	&hf_radiotap_he_ru_allocation_offset,
	&hf_radiotap_he_ru_allocation_offset_known,
	&hf_radiotap_he_pri_sec_80_mhz,
	NULL
};

static const true_false_string tfs_pri_sec_80_mhz = {
	"secondary",
	"primary"
};

static const value_string he_coding_vals[] = {
	{ 0, "BCC" },
	{ 1, "LDPC" },
	{ 0, NULL }
};

static const value_string he_data_bw_ru_alloc_vals[] = {
	{ 0, "20" },
	{ 1, "40" },
	{ 2, "80" },
	{ 3, "160/80+80" },
	{ 4, "26-tone RU" },
	{ 5, "52-tone RU" },
	{ 6, "106-tone RU" },
	{ 7, "242-tone RU" },
	{ 8, "484-tone RU" },
	{ 9, "996-tone RU" },
	{ 10, "2x996-tone RU" },
	{ 11, "reserved" },
	{ 12, "reserved" },
	{ 13, "reserved" },
	{ 14, "reserved" },
	{ 15, "reserved" },
	{ 0, NULL }
};

static const value_string he_gi_vals[] = {
	{ 0, "0.8us" },
	{ 1, "1.6us" },
	{ 2, "3.2us" },
	{ 3, "reserved" },
	{ 0, NULL }
};

static const value_string he_ltf_symbol_size_vals[] = {
	{ 0, "unknown" },
	{ 1, "1x" },
	{ 2, "2x" },
	{ 3, "4x" },
	{ 0, NULL }
};

static const value_string he_num_ltf_symbols_vals[] = {
	{ 0, "1x" },
	{ 1, "2x" },
	{ 2, "4x" },
	{ 3, "6x" },
	{ 4, "8x" },
	{ 5, "reserved" },
	{ 6, "reserved" },
	{ 7, "reserved" },
	{ 0, NULL }
};

static const value_string he_nsts_vals[] = {
	{ 0, "Unknown" },
	{ 1, "1 space-time stream" },
	{ 2, "2 space-time streams" },
	{ 3, "3 space-time streams" },
	{ 4, "4 space-time streams" },
	{ 5, "5 space-time streams" },
	{ 6, "6 space-time streams" },
	{ 7, "7 space-time streams" },
	{ 8, "8 space-time streams" },
	{ 9, "9 space-time streams" },
	{ 10, "10 space-time streams" },
	{ 11, "11 space-time streams" },
	{ 12, "12 space-time streams" },
	{ 13, "13 space-time streams" },
	{ 14, "14 space-time streams" },
	{ 15, "15 space-time streams" },
	{ 0, NULL }
};

static const value_string he_midamble_periodicity_vals[] = {
	{ 0, "10" },
	{ 1, "20" },
	{ 0, NULL }
};

static void
dissect_radiotap_he_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	int offset, struct ieee_802_11ax *info_11ax, bool is_tlv)
{
	uint16_t ppdu_format = tvb_get_letohs(tvb, offset) &
		IEEE80211_RADIOTAP_HE_PPDU_FORMAT_MASK;
	proto_tree *he_info_tree = NULL;
	bool bss_color_known = false;
	bool beam_change_known = false;
	bool ul_dl_known = false;
	bool data_mcs_known = false;
	bool data_dcm_known = false;
	bool coding_known = false;
	bool ldpc_extra_symbol_segment_known = false;
	bool stbc_known = false;
	bool spatial_reuse_1_known = false;
	bool spatial_reuse_2_known = false;
	bool spatial_reuse_3_known = false;
	bool spatial_reuse_4_known = false;
	bool data_bw_ru_alloc_known = false;
	bool doppler_known = false;
	bool gi_known = false;
	bool num_ltf_symbols_known = false;
	bool ltf_symbol_size_known = false;
	bool pre_fec_padding_factor_known = false;
	bool txbf_known = false;
	bool pe_disambiguity_known = false;
	bool txop_known = false;
	bool midamble_periodicity_known = false;
	uint16_t data1 = tvb_get_letohs(tvb, offset);
	uint16_t data2 = 0;
	uint16_t data3 = 0;
	uint16_t data5 = 0;
	uint16_t data6 = 0;

	uint8_t ltf_symbol_size = 0;

	/*
	 * This is set differetly for each packet, depending on
	 * which values in data3 are known.  It thus will not
	 * work if it's static.
	 */
	int *data3_headers[] = {
		&hf_radiotap_he_bss_color,
		&hf_radiotap_he_beam_change,
		&hf_radiotap_he_ul_dl,
		&hf_radiotap_he_data_mcs,
		&hf_radiotap_he_data_dcm,
		&hf_radiotap_he_coding,
		&hf_radiotap_he_ldpc_extra_symbol_segment,
		&hf_radiotap_he_stbc,
		NULL
	};

	/*
	 * Same story but for data4.
	 */
	int *data4_he_trig_headers[] = {
		&hf_radiotap_spatial_reuse_1,
		&hf_radiotap_spatial_reuse_2,
		&hf_radiotap_spatial_reuse_3,
		&hf_radiotap_spatial_reuse_4,
		NULL
	};
	int *data4_he_su_and_he_ext_su_headers[] = {
		&hf_radiotap_spatial_reuse,
		&hf_radiotap_he_su_reserved,
		NULL
	};
	int *data4_he_mu_headers[] = {
		&hf_radiotap_spatial_reuse,
		&hf_radiotap_sta_id_user_captured,
		&hf_radiotap_he_mu_reserved,
		NULL
	};
	int *data5_headers[] = {
		&hf_radiotap_data_bandwidth_ru_allocation,
		&hf_radiotap_gi,
		&hf_radiotap_ltf_symbol_size,
		&hf_radiotap_num_ltf_symbols,
		&hf_radiotap_d5_reserved_b11,
		&hf_radiotap_pre_fec_padding_factor,
		&hf_radiotap_txbf,
		&hf_radiotap_pe_disambiguity,
		NULL
	};

	/*
	 * Same story, but for data6.
	 */
	int *data6_headers[] = {
		&hf_radiotap_he_nsts,
		&hf_radiotap_he_doppler_value,
		&hf_radiotap_he_d6_reserved_00e0,
		&hf_radiotap_he_txop_value,
		&hf_radiotap_midamble_periodicity,
		NULL
	};

	/*
	 * Determine what is known.
	 */
	if (data1 & IEEE80211_RADIOTAP_HE_BSS_COLOR_KNOWN)
		bss_color_known = true;
	if (data1 & IEEE80211_RADIOTAP_HE_BEAM_CHANGE_KNOWN)
		beam_change_known = true;
	if (data1 & IEEE80211_RADIOTAP_HE_UL_DL_KNOWN)
		ul_dl_known = true;
	if (data1 & IEEE80211_RADIOTAP_HE_DATA_MCS_KNOWN)
		data_mcs_known = true;
	if (data1 & IEEE80211_RADIOTAP_HE_DATA_DCM_KNOWN)
		data_dcm_known = true;
	if (data1 & IEEE80211_RADIOTAP_HE_CODING_KNOWN)
		coding_known = true;
	if (data1 & IEEE80211_RADIOTAP_HE_LDPC_EXTRA_SYMBOL_SEGMENT_KNOWN)
		ldpc_extra_symbol_segment_known = true;
	if (data1 & IEEE80211_RADIOTAP_HE_STBC_KNOWN)
		stbc_known = true;
	if (data1 & IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_KNOWN)
		spatial_reuse_1_known = true;
	if (data1 & IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_2_KNOWN)
		spatial_reuse_2_known = true;
	if (data1 & IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_3_KNOWN)
		spatial_reuse_3_known = true;
	if (data1 & IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_4_KNOWN)
		spatial_reuse_4_known = true;
	if (data1 & IEEE80211_RADIOTAP_HE_DATA_BW_RU_ALLOCATION_KNOWN)
		data_bw_ru_alloc_known = true;
	if (data1 & IEEE80211_RADIOTAP_HE_DOPPLER_KNOWN)
		doppler_known = true;

	he_info_tree = proto_tree_add_subtree(tree, tvb, offset, 12,
		ett_radiotap_he_info, NULL, "HE information");

	if (is_tlv) {
		add_tlv_items(he_info_tree, tvb, offset);
	}

	/* Add the bitmasks for each of D1 through D6 */
	proto_tree_add_bitmask(he_info_tree, tvb, offset,
		hf_radiotap_he_info_data_1, ett_radiotap_he_info_data_1,
		data1_headers, ENC_LITTLE_ENDIAN);
	offset += 2;

	data2 = tvb_get_letohs(tvb, offset);
	proto_tree_add_bitmask(he_info_tree, tvb, offset,
		hf_radiotap_he_info_data_2, ett_radiotap_he_info_data_2,
		data2_headers, ENC_LITTLE_ENDIAN);
	offset += 2;

	/*
	 * Second lot of what is known
	 */
	if (data2 & IEEE80211_RADIOTAP_HE_GI_KNOWN)
		gi_known = true;
	if (data2 & IEEE80211_RADIOTAP_HE_NUM_LTF_SYMBOLS_KNOWN)
		num_ltf_symbols_known = true;
	if (data2 & IEEE80211_RADIOTAP_HE_PRE_FEC_PADDING_FACTOR_KNOWN)
		pre_fec_padding_factor_known = true;
	if (data2 & IEEE80211_RADIOTAP_HE_TXBF_KNOWN)
		txbf_known = true;
	if (data2 & IEEE80211_RADIOTAP_HE_PE_DISAMBIGUITY_KNOWN)
		pe_disambiguity_known = true;
	if (data2 & IEEE80211_RADIOTAP_HE_TXOP_KNOWN)
		txop_known = true;
	if (data2 & IEEE80211_RADIOTAP_HE_MIDAMBLE_PERIODICITY_KNOWN)
		midamble_periodicity_known = true;

	/*
	 * Set those fields that should be reserved
	 */
	if (!bss_color_known)
		data3_headers[0] = &hf_radiotap_he_bss_color_unknown;
	if (!beam_change_known)
		data3_headers[1] = &hf_radiotap_he_beam_change_unknown;
	if (!ul_dl_known)
		data3_headers[2] = &hf_radiotap_he_ul_dl_unknown;
	if (!data_mcs_known)
		data3_headers[3] = &hf_radiotap_he_data_mcs_unknown;
	if (!data_dcm_known)
		data3_headers[4] = &hf_radiotap_he_data_dcm_unknown;
	if (!coding_known)
		data3_headers[5] = &hf_radiotap_he_coding_unknown;
	if (!ldpc_extra_symbol_segment_known)
		data3_headers[6] = &hf_radiotap_he_ldpc_extra_symbol_segment_unknown;
	if (!stbc_known)
		data3_headers[7] = &hf_radiotap_he_stbc_unknown;

	data3 = tvb_get_letohs(tvb, offset);
	if (data_mcs_known) {
		info_11ax->has_mcs_index = true;
		info_11ax->mcs = (data3 & IEEE80211_RADIOTAP_HE_DATA_MCS_MASK) >> 8;
	}
	proto_tree_add_bitmask(he_info_tree, tvb, offset,
		hf_radiotap_he_info_data_3, ett_radiotap_he_info_data_3,
		data3_headers, ENC_LITTLE_ENDIAN);
	offset += 2;

	if (ppdu_format == IEEE80211_RADIOTAP_HE_PPDU_FORMAT_HE_SU ||
		ppdu_format == IEEE80211_RADIOTAP_HE_PPDU_FORMAT_HE_EXT_SU) {
		if (!spatial_reuse_1_known)
			data4_he_su_and_he_ext_su_headers[0] =
				&hf_radiotap_spatial_reuse_unknown;
		proto_tree_add_bitmask(he_info_tree, tvb, offset,
			hf_radiotap_he_info_data_4, ett_radiotap_he_info_data_4,
			data4_he_su_and_he_ext_su_headers, ENC_LITTLE_ENDIAN);
	} else if (ppdu_format == IEEE80211_RADIOTAP_HE_PPDU_FORMAT_HE_TRIG) {
		if (!spatial_reuse_1_known)
			data4_he_trig_headers[0] =
				&hf_radiotap_spatial_reuse_1_unknown;
		if (!spatial_reuse_2_known)
			data4_he_trig_headers[1] =
				&hf_radiotap_spatial_reuse_2_unknown;
		if (!spatial_reuse_3_known)
			data4_he_trig_headers[2] =
				&hf_radiotap_spatial_reuse_3_unknown;
		if (!spatial_reuse_4_known)
			data4_he_trig_headers[3] =
				&hf_radiotap_spatial_reuse_4_unknown;
		proto_tree_add_bitmask(he_info_tree, tvb, offset,
			hf_radiotap_he_info_data_4, ett_radiotap_he_info_data_4,
			data4_he_trig_headers, ENC_LITTLE_ENDIAN);
	} else {
		if (!spatial_reuse_1_known)
			data4_he_mu_headers[0] =
				&hf_radiotap_spatial_reuse_unknown;
		proto_tree_add_bitmask(he_info_tree, tvb, offset,
			hf_radiotap_he_info_data_4, ett_radiotap_he_info_data_4,
			data4_he_mu_headers, ENC_LITTLE_ENDIAN);
	}

	//data4 = tvb_get_letohs(tvb, offset);
	offset += 2;

	/*
	 * The LTF Symbol Size field is zero if LFT Symbol size is unknown
	 */
	ltf_symbol_size = (tvb_get_letohs(tvb, offset) >> 6) & 0x03;
	if (ltf_symbol_size != 0)
		ltf_symbol_size_known = true;
	if (!data_bw_ru_alloc_known)
		data5_headers[0] = &hf_radiotap_data_bandwidth_ru_allocation_unknown;
	if (!gi_known)
		data5_headers[1] = &hf_radiotap_gi_unknown;
	if (!ltf_symbol_size_known)
		data5_headers[2] = &hf_radiotap_ltf_symbol_size_unknown;
	if (!num_ltf_symbols_known)
		data5_headers[3] = &hf_radiotap_num_ltf_symbols_unknown;
	if (!pre_fec_padding_factor_known)
		data5_headers[5] = &hf_radiotap_pre_fec_padding_factor_unknown;
	if (!txbf_known)
		data5_headers[6] = &hf_radiotap_txbf_unknown;
	if (!pe_disambiguity_known)
		data5_headers[7] = &hf_radiotap_pe_disambiguity_unknown;
	data5 = tvb_get_letohs(tvb, offset);
	if (gi_known) {
		info_11ax->has_gi = true;
		info_11ax->gi = (data5 & IEEE80211_RADIOTAP_HE_GI_MASK) >> 4;
	}
	if (data_bw_ru_alloc_known) {
		info_11ax->has_bwru = true;
		info_11ax->bwru = (data5 & IEEE80211_RADIOTAP_HE_DATA_BANDWIDTH_RU_ALLOC_MASK);
	}
	proto_tree_add_bitmask(he_info_tree, tvb, offset,
		hf_radiotap_he_info_data_5, ett_radiotap_he_info_data_5,
		data5_headers, ENC_LITTLE_ENDIAN);
	offset += 2;

	if (!doppler_known)
		data6_headers[1] = &hf_radiotap_he_doppler_value_unknown;
	if (!txop_known)
		data6_headers[3] = &hf_radiotap_he_txop_value_unknown;
	if (!midamble_periodicity_known)
		data6_headers[4] = &hf_radiotap_midamble_periodicity_unknown;
	proto_tree_add_bitmask(he_info_tree, tvb, offset,
		hf_radiotap_he_info_data_6, ett_radiotap_he_info_data_6,
		data6_headers, ENC_LITTLE_ENDIAN);
	data6 = tvb_get_letohs(tvb, offset);

	info_11ax->nsts = data6 & IEEE80211_RADIOTAP_HE_NSTS_MASK;

}

static void
not_captured_custom(char *result, uint32_t value _U_)
{
	snprintf(result, ITEM_LABEL_LENGTH,
		"NOT CAPTURED BY CAPTURE SOFTWARE");
}

static void
he_sig_b_symbols_custom(char *result, uint32_t value)
{
	snprintf(result, ITEM_LABEL_LENGTH, "%d", value+1);
}

static void
dissect_radiotap_he_mu_info(tvbuff_t *tvb, packet_info *pinfo _U_,
		proto_tree *tree, int offset, bool is_tlv)
{
	proto_tree *he_mu_info_tree = NULL;
	uint16_t flags1 = tvb_get_letohs(tvb, offset);
	bool sig_b_mcs_known = false;
	bool sig_b_dcm_known = false;
	proto_tree *mu_chan1_rus = NULL;
	proto_tree *mu_chan2_rus = NULL;
	int mu_rus_chan1_rus_0 = -1;
	int mu_rus_chan1_rus_1 = -1;
	int mu_rus_chan1_rus_2 = -1;
	int mu_rus_chan1_rus_3 = -1;
	int mu_rus_chan2_rus_0 = -1;
	int mu_rus_chan2_rus_1 = -1;
	int mu_rus_chan2_rus_2 = -1;
	int mu_rus_chan2_rus_3 = -1;
	bool mu_chan2_center_26_tone_ru_bit_known = false;
	bool mu_chan1_rus_known = false;
	bool mu_chan2_rus_known = false;
	bool mu_chan1_center_26_tone_ru_bit_known = false;
	bool mu_sig_b_compression_known = false;
	bool mu_symbol_cnt_or_user_cnt_known = false;
	bool mu_preamble_puncturing_known = false;
	bool mu_bw_from_bw_sig_a_known = false;
	uint8_t bw_from_sig_a = 0;
	uint16_t flags2;

	/*
	 * This is set differetly for each packet, depending on
	 * which values in flags1 are known.  It thus will not
	 * work if it's static.
	 */
	int *flags1_headers[] = {
		&hf_radiotap_he_mu_sig_b_mcs,
		&hf_radiotap_he_mu_sig_b_mcs_known,
		&hf_radiotap_he_mu_sig_b_dcm,
		&hf_radiotap_he_mu_sig_b_dcm_known,
		&hf_radiotap_he_mu_chan2_center_26_tone_ru_bit_known,
		&hf_radiotap_he_mu_chan1_rus_known,
		&hf_radiotap_he_mu_chan2_rus_known,
		&hf_radiotap_he_mu_reserved_f1_b10_b11,
		&hf_radiotap_he_mu_chan1_center_26_tone_ru_bit_known,
		&hf_radiotap_he_mu_chan1_center_26_tone_ru_value,
		&hf_radiotap_he_mu_sig_b_compression_known,
		&hf_radiotap_he_mu_sig_b_syms_mu_mimo_users_known,
		NULL
	};

	/*
	 * Same story but for flags2.
	 */
	int *flags2_headers[] = {
		&hf_radiotap_he_mu_bw_from_bw_in_sig_a,
		&hf_radiotap_he_mu_bw_from_bw_in_sig_a_known,
		&hf_radiotap_he_mu_sig_b_compression_from_sig_a,
		&hf_radiotap_he_mu_sig_b_syms_mu_mimo_users,
		&hf_radiotap_he_mu_preamble_puncturing,
		&hf_radiotap_he_mu_preamble_puncturing_known,
		&hf_radiotap_he_mu_chan2_center_26_tone_ru_value,
		&hf_radiotap_he_mu_reserved_f2_b12_b15,
		NULL
	};

	if (flags1 & IEEE80211_RADIOTAP_HE_MU_SIG_B_MCS_KNOWN)
		sig_b_mcs_known = true;
	if (flags1 & IEEE80211_RADIOTAP_HE_MU_SIG_B_DCM_KNOWN)
		sig_b_dcm_known = true;
	if (flags1 & IEEE80211_RADIOTAP_HE_MU_CHAN2_CENTER_26_TONE_RU_BIT_KNOWN)
		mu_chan2_center_26_tone_ru_bit_known = true;
	if (flags1 & IEEE80211_RADIOTAP_HE_MU_CHAN1_RUS_KNOWN)
		mu_chan1_rus_known = true;
	if (flags1 & IEEE80211_RADIOTAP_HE_MU_CHAN2_RUS_KNOWN)
		mu_chan2_rus_known = true;
	if (flags1 & IEEE80211_RADIOTAP_HE_MU_CHAN1_CENTER_26_TONE_RU_BIT_KNOWN)
		mu_chan1_center_26_tone_ru_bit_known = true;
	if (flags1 & IEEE80211_RADIOTAP_HE_MU_SIG_B_COMPRESSION_KNOWN)
		mu_sig_b_compression_known = true;
	if (flags1 & IEEE80211_RADIOTAP_HE_MU_SYMBOL_CNT_OR_USER_CNT_KNOWN)
		mu_symbol_cnt_or_user_cnt_known = true;

	if (!sig_b_mcs_known) {
		flags1_headers[1] = &hf_radiotap_he_mu_sig_b_mcs_unknown;
	} else {
		flags1_headers[1] = &hf_radiotap_he_mu_sig_b_mcs_known;
	}
	if (!sig_b_dcm_known) {
		flags1_headers[3] = &hf_radiotap_he_mu_sig_b_dcm_unknown;
	} else {
		flags1_headers[3] = &hf_radiotap_he_mu_sig_b_dcm_known;
	}
	if (!mu_chan2_center_26_tone_ru_bit_known) {
		flags1_headers[4] = &hf_radiotap_he_mu_chan2_center_26_tone_ru_bit_unknown;
	} else {
		flags1_headers[4] = &hf_radiotap_he_mu_chan2_center_26_tone_ru_bit_known;
	}
	if (!mu_chan1_rus_known) {
		flags1_headers[5] = &hf_radiotap_he_mu_chan1_rus_unknown;
	} else {
		flags1_headers[5] = &hf_radiotap_he_mu_chan1_rus_known;
	}
	if (!mu_chan2_rus_known) {
		flags1_headers[6] = &hf_radiotap_he_mu_chan2_rus_unknown;
	} else {
		flags1_headers[6] = &hf_radiotap_he_mu_chan2_rus_known;
	}
	if (!mu_chan1_center_26_tone_ru_bit_known) {
		flags1_headers[8] = &hf_radiotap_he_mu_chan1_center_26_tone_ru_bit_unknown;
	} else {
		flags1_headers[8] = &hf_radiotap_he_mu_chan1_center_26_tone_ru_bit_known;
	}
	if (!mu_symbol_cnt_or_user_cnt_known) {
		flags1_headers[11] = &hf_radiotap_he_mu_sig_b_syms_mu_mimo_users_unknown;
	} else {
		flags1_headers[11] = &hf_radiotap_he_mu_sig_b_syms_mu_mimo_users_known;
	}

	if (!mu_chan1_center_26_tone_ru_bit_known) {
		flags1_headers[9] = &hf_radiotap_he_mu_chan1_center_26_tone_ru_bit_unknown;
	} else {
		flags1_headers[9] = &hf_radiotap_he_mu_chan1_center_26_tone_ru_value;
	}
	if (!mu_symbol_cnt_or_user_cnt_known) {
		flags1_headers[11] = &hf_radiotap_he_mu_sig_b_syms_mu_mimo_users_unknown;
	} else {
		flags1_headers[11] = &hf_radiotap_he_mu_sig_b_syms_mu_mimo_users_known;
	}

	flags2 = tvb_get_letohs(tvb, offset + 2);
	if (flags2 & IEEE80211_RADIOTAP_HE_MU_BW_FROM_BW_IN_SIG_A_KNOWN)
		mu_bw_from_bw_sig_a_known = true;
	if (flags2 & IEEE80211_RADIOTAP_HE_MU_PREAMBLE_PUNCTURING_KNOWN)
		mu_preamble_puncturing_known = true;

	if (!mu_bw_from_bw_sig_a_known) {
		flags2_headers[0] = &hf_radiotap_he_mu_bw_from_bw_in_sig_a_unknown;
	} else {
		flags2_headers[0] = &hf_radiotap_he_mu_bw_from_bw_in_sig_a;
	}
	if (!mu_sig_b_compression_known) {
		flags2_headers[2] = &hf_radiotap_he_mu_sig_b_compression_unknown;
	} else {
		flags2_headers[2] = &hf_radiotap_he_mu_sig_b_compression_from_sig_a;
	}
	if (!mu_symbol_cnt_or_user_cnt_known) {
		flags2_headers[3] = &hf_radiotap_he_mu_sig_b_syms_mu_mimo_users_unknown;
	} else {
		flags2_headers[3] = &hf_radiotap_he_mu_sig_b_syms_mu_mimo_users;
	}
	if (!mu_preamble_puncturing_known) {
		flags2_headers[4] = &hf_radiotap_he_mu_preamble_puncturing_unknown;
	} else {
		flags2_headers[4] = &hf_radiotap_he_mu_preamble_puncturing;
	}
	if (!mu_chan2_center_26_tone_ru_bit_known) {
		flags2_headers[6] = &hf_radiotap_he_mu_chan2_center_26_tone_ru_bit_unknown;
	} else {
		flags2_headers[6] = &hf_radiotap_he_mu_chan2_center_26_tone_ru_value;
	}

	bw_from_sig_a = flags2 & IEEE80211_RADIOTAP_HE_MU_BW_FROM_BW_IN_SIG_A_MASK;

	/*
	 * We have to hold of on displaying stuff until we have figured
	 * everything out because the display of fields in flags1 depends
	 *  on bandwidth from flags2.
	 */

	/* Set the header fields depending on the bw and known fields */
	if (bw_from_sig_a < 3) {
		if (mu_chan1_rus_known) {
			mu_rus_chan1_rus_0 = hf_radiotap_he_mu_chan1_rus_0;
			mu_rus_chan1_rus_1 = hf_radiotap_he_mu_chan1_rus_1;
			mu_rus_chan1_rus_2 = hf_radiotap_he_mu_chan1_rus_2;
			mu_rus_chan1_rus_3 = hf_radiotap_he_mu_chan1_rus_3;
		} else {
			mu_rus_chan1_rus_0 = hf_radiotap_he_mu_chan1_rus_0_unknown;
			mu_rus_chan1_rus_1 = hf_radiotap_he_mu_chan1_rus_1_unknown;
			mu_rus_chan1_rus_2 = hf_radiotap_he_mu_chan1_rus_2_unknown;
			mu_rus_chan1_rus_3 = hf_radiotap_he_mu_chan1_rus_3_unknown;
		}
		if (mu_chan2_rus_known) {
			mu_rus_chan2_rus_0 = hf_radiotap_he_mu_chan2_rus_0;
			mu_rus_chan2_rus_1 = hf_radiotap_he_mu_chan2_rus_1;
			mu_rus_chan2_rus_2 = hf_radiotap_he_mu_chan2_rus_2;
			mu_rus_chan2_rus_3 = hf_radiotap_he_mu_chan2_rus_3;
		} else {
			mu_rus_chan2_rus_0 = hf_radiotap_he_mu_chan2_rus_0_unknown;
			mu_rus_chan2_rus_1 = hf_radiotap_he_mu_chan2_rus_1_unknown;
			mu_rus_chan2_rus_2 = hf_radiotap_he_mu_chan2_rus_2_unknown;
			mu_rus_chan2_rus_3 = hf_radiotap_he_mu_chan2_rus_3_unknown;
		}
	} else {
		mu_rus_chan1_rus_0 = hf_radiotap_he_mu_chan1_rus_0;
		mu_rus_chan1_rus_1 = hf_radiotap_he_mu_chan1_rus_1;
		mu_rus_chan1_rus_2 = hf_radiotap_he_mu_chan1_rus_2;
		mu_rus_chan1_rus_3 = hf_radiotap_he_mu_chan1_rus_3;
		mu_rus_chan2_rus_0 = hf_radiotap_he_mu_chan2_rus_0;
		mu_rus_chan2_rus_1 = hf_radiotap_he_mu_chan2_rus_1;
		mu_rus_chan2_rus_2 = hf_radiotap_he_mu_chan2_rus_2;
		mu_rus_chan2_rus_3 = hf_radiotap_he_mu_chan2_rus_3;
	}

	he_mu_info_tree = proto_tree_add_subtree(tree, tvb, offset, 12,
		ett_radiotap_he_mu_info, NULL, "HE-MU information");

	if (is_tlv) {
		add_tlv_items(he_mu_info_tree, tvb, offset);
	}

	proto_tree_add_bitmask(he_mu_info_tree, tvb, offset,
				hf_radiotap_he_mu_info_flags_1,
				ett_radiotap_he_mu_info_flags_1,
				flags1_headers, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(he_mu_info_tree, tvb, offset,
				hf_radiotap_he_mu_info_flags_2,
				ett_radiotap_he_mu_info_flags_2,
				flags2_headers, ENC_LITTLE_ENDIAN);
	offset += 2;

	mu_chan1_rus = proto_tree_add_subtree(he_mu_info_tree, tvb, offset, 4,
				ett_radiotap_he_mu_chan_rus, NULL,
				"Channel 1 RUs");

	proto_tree_add_item(mu_chan1_rus, mu_rus_chan1_rus_0, tvb, offset, 1,
				ENC_NA);
	offset++;

	proto_tree_add_item(mu_chan1_rus, mu_rus_chan1_rus_1, tvb, offset, 1,
				ENC_NA);
	offset++;

	proto_tree_add_item(mu_chan1_rus, mu_rus_chan1_rus_2, tvb, offset, 1,
				ENC_NA);
	offset++;

	proto_tree_add_item(mu_chan1_rus, mu_rus_chan1_rus_3, tvb, offset, 1,
				ENC_NA);
	offset++;

	mu_chan2_rus = proto_tree_add_subtree(he_mu_info_tree, tvb, offset, 4,
				ett_radiotap_he_mu_chan_rus, NULL,
				"Channel 2 RUs");

	proto_tree_add_item(mu_chan2_rus, mu_rus_chan2_rus_0, tvb, offset, 1,
				ENC_NA);
	offset++;

	proto_tree_add_item(mu_chan2_rus, mu_rus_chan2_rus_1, tvb, offset, 1,
				ENC_NA);
	offset++;

	proto_tree_add_item(mu_chan2_rus, mu_rus_chan2_rus_2, tvb, offset, 1,
				ENC_NA);
	offset++;

	proto_tree_add_item(mu_chan2_rus, mu_rus_chan2_rus_3, tvb, offset, 1,
				ENC_NA);
}

static const range_string zero_length_psdu_rsvals[] = {
	{ 0, 0, "sounding PPDU" },
	{ 1, 1, "reserved" },
	{ 2, 254, "reserved" },
	{ 255, 255, "vendor-specific" },
	{ 0, 0, NULL }
};

static void
dissect_radiotap_0_length_psdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	int offset, struct ieee_802_11_phdr *phdr)
{
	proto_tree *zero_len_tree = NULL;
	uint32_t psdu_type;

	zero_len_tree = proto_tree_add_subtree(tree, tvb, offset,
		tvb_captured_length_remaining(tvb, offset),
		ett_radiotap_0_length_psdu, NULL, "0-length PSDU");

	proto_tree_add_item_ret_uint(zero_len_tree, hf_radiotap_0_length_psdu_type,
		tvb, offset, 1, ENC_NA, &psdu_type);

	switch (psdu_type) {

	case 0:
		phdr->has_zero_length_psdu_type = true;
		phdr->zero_length_psdu_type = PHDR_802_11_SOUNDING_PSDU;
		break;

	case 1:
		phdr->has_zero_length_psdu_type = true;
		phdr->zero_length_psdu_type = PHDR_802_11_DATA_NOT_CAPTURED;
		break;

	case 0xff:
		phdr->has_zero_length_psdu_type = true;
		phdr->zero_length_psdu_type = PHDR_802_11_0_LENGTH_PSDU_VENDOR_SPECIFIC;
		break;
	}
}

static int * const l_sig_data1_headers[] = {
	&hf_radiotap_l_sig_rate_known,
	&hf_radiotap_l_sig_length_known,
	&hf_radiotap_l_sig_reserved,
	NULL
};

static int * const l_sig_data2_headers[] = {
	&hf_radiotap_l_sig_rate,
	&hf_radiotap_l_sig_length,
	NULL
};

static void
dissect_radiotap_l_sig(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	int offset)
{
	proto_tree *l_sig_tree = NULL;

	l_sig_tree = proto_tree_add_subtree(tree, tvb, offset, 4,
		ett_radiotap_l_sig, NULL, "L-SIG");

	proto_tree_add_bitmask(l_sig_tree, tvb, offset,
		hf_radiotap_l_sig_data_1, ett_radiotap_l_sig_data_1,
		l_sig_data1_headers, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(l_sig_tree, tvb, offset,
		hf_radiotap_l_sig_data_2, ett_radiotap_l_sig_data_2,
		l_sig_data2_headers, ENC_LITTLE_ENDIAN);
}

static int * const usig_common_headers[] = {
	&hf_radiotap_usig_phy_version_identifier_known,
	&hf_radiotap_usig_bw_known,
	&hf_radiotap_usig_ul_dl_known,
	&hf_radiotap_usig_bss_color_known,
	&hf_radiotap_usig_txop_known,
	&hf_radiotap_usig_bad_u_sig_crc,
	&hf_radiotap_usig_validate_bits_checked,
	&hf_radiotap_usig_validate_bits_ok,
	&hf_radiotap_usig_reserved,
	&hf_radiotap_usig_phy_version_id,
	&hf_radiotap_usig_bw,
	&hf_radiotap_usig_ul_dl,
	&hf_radiotap_usig_bss_color,
	&hf_radiotap_usig_txop,
	NULL
};

static const value_string eht_u_sig_bw_vals[] = {
	{ 0, "20 MHz" },
	{ 1, "40 MHz" },
	{ 2, "80 MHz" },
	{ 3, "160 MHz" },
	{ 4, "320 MHz-1" },
	{ 5, "320 MHz-2" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

static int * usig_eht_mu_ppdu_headers[] = {
	&hf_radiotap_usig_eht_mu_b20_b24,
	&hf_radiotap_usig_eht_mu_b25,
	&hf_radiotap_usig_ppdu_type_and_comp_mode,
	&hf_radiotap_usig_validate1,
	&hf_radiotap_usig_punctured_channel_info,
	&hf_radiotap_usig_validate2,
	&hf_radiotap_usig_eht_sig_mcs,
	&hf_radiotap_usig_number_eht_sig_symbols,
	&hf_radiotap_usig_crc,
	&hf_radiotap_usig_tail,
	NULL
};

static int * usig_eht_tb_ppdu_headers[] = {
	&hf_radiotap_usig_eht_tb_b20_b25,
	&hf_radiotap_usig_ppdu_type_and_comp_mode,
	&hf_radiotap_usig_eht_tb_validate1,
	&hf_radiotap_usig_eht_tb_spatial_reuse_1,
	&hf_radiotap_usig_eht_tb_spatial_reuse_2,
	&hf_radiotap_usig_eht_tb_disregard,
	&hf_radiotap_usig_eht_tb_crc,
	&hf_radiotap_usig_eht_tb_tail,
	NULL
};

/* U-SIG mask definition */
/* MU PPDU only */
#define U_SIG_U_SIG_1_B20_B24       0x0000001f
#define U_SIG_U_SIG_1_B25           0x00000020
#define U_SIG_U_SIG_2_B3_B7         0x00003e00
#define U_SIG_U_SIG_2_B8            0x00004000
#define U_SIG_U_SIG_2_B9_B10        0x00018000

/* TB PPDU only */
#define U_SIG_U_SIG_1_B20_B25       0x0000003f
#define U_SIG_U_SIG_2_B3_B6         0x00001e00
#define U_SIG_U_SIG_2_B7_B10        0x0001e000

#define U_SIG_U_SIG_2_B0_B1         0x000000c0
#define U_SIG_U_SIG_2_B2            0x00000100
#define U_SIG_U_SIG_2_B11_B15       0x003e0000
#define U_SIG_U_SIG_2_B16_B19       0x03c00000
#define U_SIG_U_SIG_2_B20_B25       0xfc000000

/*
 * Will never be called via old style bits
 */
static void
dissect_radiotap_u_sig(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                       int offset, struct ieee_802_11_phdr *phdr _U_,
                       bool is_tlv _U_)
{
	proto_tree *u_sig_tree = NULL;
	uint8_t ul_dl = 0;
	uint8_t type_and_comp = 0;
	uint32_t mask;
	bool bw_known = false;
	struct ieee_802_11be *info_11be = &phdr->phy_info.info_11be;
	uint32_t usig_common = tvb_get_letohs(tvb, offset);

	phdr->phy = PHDR_802_11_PHY_11BE;

	u_sig_tree = proto_tree_add_subtree(tree, tvb, offset, 12,
					    ett_radiotap_u_sig, NULL,
					    "U-SIG");

	add_tlv_items(u_sig_tree, tvb, offset);

	ul_dl = (tvb_get_uint8(tvb, offset + 2) & 0x04) >> 2;
	proto_tree_add_bitmask(u_sig_tree, tvb, offset,
			       hf_radiotap_u_sig_common,
			       ett_radiotap_u_sig_common,
			       usig_common_headers, ENC_LITTLE_ENDIAN);

	bw_known = usig_common & IEEE80211_RADIOTAP_USIG_BW_KNOWN;
	if (bw_known) {
		info_11be->has_bandwidth = true;
		info_11be->bandwidth = (usig_common & IEEE80211_RADIOTAP_USIG_BW) >> IEEE80211_RADIOTAP_USIG_BW_SHIFT;
	}
	offset += 4;

	/*
	 * Now handle the Value and Mask ...
	 */
	mask = tvb_get_letohl(tvb, offset + 4);
	type_and_comp = (tvb_get_uint8(tvb, offset) & 0xc0) >> 6;

	if ((ul_dl == 0 && (type_and_comp == 0 || type_and_comp == 1 ||
		   type_and_comp == 2)) ||
		(ul_dl == 1 && type_and_comp == 1)) {
		if ((mask & U_SIG_U_SIG_1_B20_B24) != U_SIG_U_SIG_1_B20_B24) {
			usig_eht_mu_ppdu_headers[0] =
				&hf_radiotap_usig_eht_mu_b20_b24_not_known;
		}
		if ((mask & U_SIG_U_SIG_1_B25) != U_SIG_U_SIG_1_B25) {
			usig_eht_mu_ppdu_headers[1] =
				&hf_radiotap_usig_eht_mu_b25_not_known;
		}
		if ((mask & U_SIG_U_SIG_2_B2) != U_SIG_U_SIG_2_B2) {
			usig_eht_mu_ppdu_headers[3] =
				&hf_radiotap_usig_validate1_not_known;
		}
		if ((mask & U_SIG_U_SIG_2_B3_B7) != U_SIG_U_SIG_2_B3_B7) {
			usig_eht_mu_ppdu_headers[4] =
				&hf_radiotap_usig_punctured_channel_info_not_known;
		}
		if ((mask & U_SIG_U_SIG_2_B8) != U_SIG_U_SIG_2_B8) {
			usig_eht_mu_ppdu_headers[5] =
				&hf_radiotap_usig_validate2_not_known;
		}
		if ((mask & U_SIG_U_SIG_2_B9_B10) != U_SIG_U_SIG_2_B9_B10) {
			usig_eht_mu_ppdu_headers[6] =
				&hf_radiotap_usig_eht_sig_mcs_not_known;
		}
		if ((mask & U_SIG_U_SIG_2_B11_B15) != U_SIG_U_SIG_2_B11_B15) {
			usig_eht_mu_ppdu_headers[7] =
				&hf_radiotap_usig_number_eht_sig_symbols_not_known;
		}
		if ((mask & U_SIG_U_SIG_2_B16_B19) != U_SIG_U_SIG_2_B16_B19) {
			usig_eht_mu_ppdu_headers[8] =
				&hf_radiotap_usig_crc_not_known;
		}
		if ((mask & U_SIG_U_SIG_2_B20_B25) != U_SIG_U_SIG_2_B20_B25) {
			usig_eht_mu_ppdu_headers[9] =
				&hf_radiotap_usig_tail_not_known;
		}
		proto_tree_add_bitmask(u_sig_tree, tvb, offset,
				       hf_radiotap_usig_value_mu_ppdu,
				       ett_radiotap_u_sig_value,
				       usig_eht_mu_ppdu_headers,
				       ENC_LITTLE_ENDIAN);
	} else {
		if ((mask & U_SIG_U_SIG_1_B20_B25) != U_SIG_U_SIG_1_B20_B25) {
			usig_eht_tb_ppdu_headers[0] =
				&hf_radiotap_usig_eht_tb_b20_b25_not_known;
		}
		if ((mask & U_SIG_U_SIG_2_B2) != U_SIG_U_SIG_2_B2) {
			usig_eht_tb_ppdu_headers[2] =
				&hf_radiotap_usig_eht_tb_validate1_not_known;
		}
		if ((mask & U_SIG_U_SIG_2_B3_B6) != U_SIG_U_SIG_2_B3_B6) {
			usig_eht_tb_ppdu_headers[3] =
				&hf_radiotap_usig_eht_tb_spatial_reuse_1_not_known;
		}
		if ((mask & U_SIG_U_SIG_2_B7_B10) != U_SIG_U_SIG_2_B7_B10) {
			usig_eht_tb_ppdu_headers[4] =
				&hf_radiotap_usig_eht_tb_spatial_reuse_2_not_known;
		}
		if ((mask & U_SIG_U_SIG_2_B11_B15) != U_SIG_U_SIG_2_B11_B15) {
			usig_eht_tb_ppdu_headers[5] =
				&hf_radiotap_usig_eht_tb_disregard_not_known;
		}
		if ((mask & U_SIG_U_SIG_2_B16_B19) != U_SIG_U_SIG_2_B16_B19) {
			usig_eht_tb_ppdu_headers[6] =
				&hf_radiotap_usig_eht_tb_crc_not_known;
		}
		if ((mask & U_SIG_U_SIG_2_B20_B25) != U_SIG_U_SIG_2_B20_B25) {
			usig_eht_tb_ppdu_headers[7] =
				&hf_radiotap_usig_eht_tb_tail_not_known;
		}
		proto_tree_add_bitmask(u_sig_tree, tvb, offset,
				       hf_radiotap_usig_value_tb_ppdu,
				       ett_radiotap_u_sig_value,
				       usig_eht_tb_ppdu_headers,
				       ENC_LITTLE_ENDIAN);
	}
	offset += 4;

	proto_tree_add_item(u_sig_tree, hf_radiotap_u_sig_mask, tvb, offset, 4,
			    ENC_LITTLE_ENDIAN);
}

/*
 * Will never be called via old style bits
 */
static int * const eht_known_headers[] = {
	&hf_radiotap_eht_reserved_1,
	&hf_radiotap_eht_spatial_reuse_known,
	&hf_radiotap_eht_guard_interval_known,
	&hf_radiotap_eht_reserved_8,
	&hf_radiotap_eht_number_ltf_symbols_known,
	&hf_radiotap_eht_ldpc_extra_symbol_segment_known,
	&hf_radiotap_eht_pre_fec_padding_factor_known,
	&hf_radiotap_eht_pe_disambiguity_known,
	&hf_radiotap_eht_disregard_known,
	&hf_radiotap_eht_reserved1,
	&hf_radiotap_eht_reserved_2,
	&hf_radiotap_eht_crc1_known,
	&hf_radiotap_eht_tail1_known,
	&hf_radiotap_eht_crc2_known,
	&hf_radiotap_eht_tail2_known,
	&hf_radiotap_eht_nss_known,
	&hf_radiotap_eht_beamformed_known,
	&hf_radiotap_eht_number_non_ofdma_users_known,
	&hf_radiotap_eht_user_encoding_block_crc_known,
	&hf_radiotap_eht_user_encoding_block_tail_known,
	&hf_radiotap_eht_ru_mru_size_known,
	&hf_radiotap_eht_ru_mru_index_known,
	&hf_radiotap_eht_tb_ru_allocation_known,
	&hf_radiotap_eht_primary_80mhz_channel_pos_known,
	&hf_radiotap_eht_reserved_fc,
        NULL
};

#define EHT_USER_INFO_STA_ID_KNOWN                0x01
#define EHT_USER_INFO_MCS_KNOWN                   0x02
#define EHT_USER_INFO_CODING_KNOWN                0x04
#define EHT_USER_INFO_RESERVED_KNOWN              0x08
#define EHT_USER_INFO_NSS_KNOWN                   0x10
#define EHT_USER_INFO_BEAMFORMING_KNOWN           0x20
#define EHT_USER_INFO_SPATIAL_CONFIGURATION_KNOWN 0x40

#define EHT_USER_INFO_STA_ID_MASK                0x0007FF00
#define EHT_USER_INFO_STA_ID_SHIFT               8

#define EHT_USER_INFO_MCS_MASK                   0x00F00000
#define EHT_USER_INFO_MCS_SHIFT                  20

#define EHT_USER_INFO_NSS_MASK                   0x0F000000
#define EHT_USER_INFO_NSS_SHIFT                  24

static void
dissect_eht_user_info(proto_tree *tree, tvbuff_t *tvb, int offset, struct ieee_802_11be *info_11be)
{
	proto_item *item = NULL;
	proto_tree *sub_tree = NULL;
	uint32_t known = tvb_get_letohl(tvb, offset);

	item = proto_tree_add_item(tree, hf_radiotap_eht_user_info,
			           tvb, offset, 4, ENC_LITTLE_ENDIAN);
	sub_tree = proto_item_add_subtree(item, ett_radiotap_eht_user_info_i);

	proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_sta_id_known, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_mcs_known, tvb, offset,
			    4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_coding_known, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_rsvd_known, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_nss_known, tvb, offset,
			    4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_beamforming_known, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_spatial_config_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_data_captured, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	if (known & EHT_USER_INFO_STA_ID_KNOWN) {
		proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_sta_id, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
		if (info_11be->num_users < 4) {
			info_11be->user[info_11be->num_users].sta_id_known = true;
			info_11be->user[info_11be->num_users].sta_id =
							(known & EHT_USER_INFO_STA_ID_MASK) >> EHT_USER_INFO_STA_ID_SHIFT;
		}
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_ui_sta_id_not_known, tvb,
				offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}
	if (known & EHT_USER_INFO_CODING_KNOWN) {
		proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_coding, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_ui_coding_not_known, tvb,
				offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}
	if (known & EHT_USER_INFO_MCS_KNOWN) {
		proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_mcs, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
		if (info_11be->num_users < 4) {
			info_11be->user[info_11be->num_users].mcs_known = true;
			info_11be->user[info_11be->num_users].mcs =
						(known & EHT_USER_INFO_MCS_MASK) >> EHT_USER_INFO_MCS_SHIFT;
		}
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_ui_mcs_not_known, tvb,
				offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	/* Overlap */
	if (known & EHT_USER_INFO_NSS_KNOWN) {
		proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_nss, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
		if (info_11be->num_users < 4) {
			info_11be->user[info_11be->num_users].nsts_known = true;
			info_11be->user[info_11be->num_users].nsts =
						((known & EHT_USER_INFO_NSS_MASK) >> EHT_USER_INFO_NSS_SHIFT) + 1;
		}
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_ui_nss_not_known, tvb,
				offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}
	if (known & EHT_USER_INFO_RESERVED_KNOWN) {
		proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_reserved, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_ui_reserved_not_known, tvb,
				offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}
	if (known & EHT_USER_INFO_BEAMFORMING_KNOWN) {
		proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_beamforming,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_ui_beamforming_not_known, tvb,
				offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}
	if (known & EHT_USER_INFO_SPATIAL_CONFIGURATION_KNOWN) {
		proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_spatial_config,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		/* Overlap field, don't add in not known case */
	}
	/* End overlap */

	proto_tree_add_item(sub_tree, hf_radiotap_eht_ui_rsvd1, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	info_11be->num_users ++;
}

static void
dissect_radiotap_eht(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    int offset, struct ieee_802_11_phdr *phdr _U_,
                    bool is_tlv _U_)
{
	proto_tree *eht_tree = NULL;
	uint32_t known = 0;
	uint32_t ru_alloc_1_known;
	uint32_t ru_x_alloc;
	uint16_t len = tvb_get_uint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);
	proto_item *data = NULL, *item = NULL;
	proto_tree *sub_tree = NULL, *user_info_tree = NULL;
	bool data_ru_mru_size_known = false;
	bool gi_known = false;
	uint32_t data0;
	uint32_t data1;

	phdr->phy = PHDR_802_11_PHY_11BE;
	struct ieee_802_11be *info_11be = &phdr->phy_info.info_11be;

	eht_tree = proto_tree_add_subtree(tree, tvb, offset, len,
					  ett_radiotap_eht, NULL,
					  "EHT");

	add_tlv_items(eht_tree, tvb, offset);

	known = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(eht_tree, tvb, offset,
			       hf_radiotap_eht_known,
			       ett_radiotap_eht_known,
			       eht_known_headers, ENC_LITTLE_ENDIAN);
	offset += 4;

	data = proto_tree_add_item(eht_tree, hf_radiotap_eht_data0, tvb, offset,
				   4, ENC_LITTLE_ENDIAN);

	sub_tree = proto_item_add_subtree(data, ett_radiotap_eht_data);

	proto_tree_add_item(sub_tree,
			    hf_radiotap_eht_data0_reserved1,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	if (known & IEEE80211_RADIOTAP_EHT_SPATIAL_REUSE_KNOWN) {
		proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data0_spatial_reuse,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data0_spatial_reuse_not_known,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	if (known & IEEE80211_RADIOTAP_EHT_GUARD_INTERVAL_KNOWN) {
		proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data0_gi,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
				gi_known = true;
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data0_gi_not_known,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree,
		hf_radiotap_eht_data0_ltf_symbol_size,
		tvb, offset, 4, ENC_LITTLE_ENDIAN);

	if (known & IEEE80211_RADIOTAP_EHT_NUMBER_LTF_SYMBOLS_KNOWN) {
		proto_tree_add_item(sub_tree,
				    hf_radiotap_eht_data0_number_ltf_symbols,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
	item = proto_tree_add_item(sub_tree,
				   hf_radiotap_eht_data0_number_ltf_symbols_not_known,
				   tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	if (known & IEEE80211_RADIOTAP_EHT_LDPC_EXTRA_SYMBOL_SEGMENT_KNOWN) {
		proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data0_ldpc_extra_symbol_segment,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data0_ldpc_extra_symbol_segment_not_known,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	if (known & IEEE80211_RADIOTAP_EHT_PRE_FEC_PADDING_FACTOR_KNOWN) {
		proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data0_pre_fec_padding_factor,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data0_pre_fec_padding_factor_not_known,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	if (known & IEEE80211_RADIOTAP_EHT_PE_DISAMBIGUITY_KNOWN) {
		proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data0_pe_disambiguity,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data0_pe_disambiguity_not_known,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	if (known & IEEE80211_RADIOTAP_EHT_DISREGARD_KNOWN) {
		proto_tree_add_item(sub_tree,
				    hf_radiotap_eht_data0_disregard,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data0_disregard_not_known,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	if (known & IEEE80211_RADIOTAP_EHT_CRC1_KNOWN) {
		proto_tree_add_item(sub_tree,
				    hf_radiotap_eht_data0_crc1,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data0_crc1_not_known,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	if (known & IEEE80211_RADIOTAP_EHT_TAIL1_KNOWN) {
		proto_tree_add_item(sub_tree,
				    hf_radiotap_eht_data0_tail1,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data0_tail1_not_known,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	data0 = tvb_get_letohs(tvb, offset);
	if (gi_known) {
		info_11be->has_gi = true;
		info_11be->gi = (data0 & IEEE80211_RADIOTAP_EHT_GI_MASK) >> IEEE80211_RADIOTAP_EHT_GI_SHIFT;
	}

	offset += 4;

	ru_alloc_1_known = (tvb_get_letohl(tvb, offset) >> 22) & 0x01;

	data = proto_tree_add_item(eht_tree, hf_radiotap_eht_data1, tvb, offset,
				   4, ENC_LITTLE_ENDIAN);

	sub_tree = proto_item_add_subtree(data, ett_radiotap_eht_data);

	if (known & IEEE80211_RADIOTAP_EHT_RU_MRU_SIZE_KNOWN) {
		proto_tree_add_item(sub_tree,
				    hf_radiotap_eht_data1_ru_mru_size,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		data_ru_mru_size_known = true;
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data1_ru_mru_size_not_known,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	if (known & IEEE80211_RADIOTAP_EHT_RU_MRU_INDEX_KNOWN) {
		proto_tree_add_item(sub_tree,
				    hf_radiotap_eht_data1_ru_mru_index,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data1_ru_mru_index_not_known,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	if (ru_alloc_1_known) {
		proto_tree_add_item(sub_tree,
				    hf_radiotap_eht_data1_ru_alloc_c1_1_1,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
				hf_radiotap_eht_data1_ru_alloc_c1_1_1_not_known,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree,
			    hf_radiotap_eht_data1_ru_alloc_c1_1_1_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(sub_tree,
			    hf_radiotap_eht_data1_reserved,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	if (known & IEEE80211_RADIOTAP_EHT_PRIMARY_80MHZ_CHANNEL_POS_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data1_primary_80_mhz_chan_pos,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data1_primary_80_mhz_chan_pos_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}
	data1 = tvb_get_letohs(tvb, offset);
	if (data_ru_mru_size_known) {
		info_11be->has_ru_mru_size = true;
		info_11be->ru_mru_size = (data1 & IEEE80211_RADIOTAP_EHT_RU_MRU_SIZE_MASK);
	}

	offset += 4;

#define RU_ALLOC_X_KNOWN          0x00000200
#define RU_ALLOC_X_PLUS_1_KNOWN   0x00080000
#define RU_ALLOC_X_PLUS_2_KNOWN   0x20000000

	ru_x_alloc = tvb_get_letohl(tvb, offset);
	data = proto_tree_add_item(eht_tree, hf_radiotap_eht_data2, tvb, offset,
				   4, ENC_LITTLE_ENDIAN);
	sub_tree = proto_item_add_subtree(data, ett_radiotap_eht_data);

	if (ru_x_alloc & RU_ALLOC_X_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data2_ru_alloc_c2_1_1,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data2_ru_alloc_c2_1_1_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data2_ru_alloc_c2_1_1_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	if (ru_x_alloc & RU_ALLOC_X_PLUS_1_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data2_ru_alloc_c1_1_2,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data2_ru_alloc_c1_1_2_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data2_ru_alloc_c1_1_2_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	if (ru_x_alloc & RU_ALLOC_X_PLUS_2_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data2_ru_alloc_c2_1_2,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data2_ru_alloc_c2_1_2_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data2_ru_alloc_c2_1_2_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data2_reserved, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	ru_x_alloc = tvb_get_letohl(tvb, offset);
	data = proto_tree_add_item(eht_tree, hf_radiotap_eht_data3, tvb, offset,
				   4, ENC_LITTLE_ENDIAN);

	sub_tree = proto_item_add_subtree(data, ett_radiotap_eht_data);

	if (ru_x_alloc & RU_ALLOC_X_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data3_ru_alloc_c1_2_1,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data3_ru_alloc_c1_2_1_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data3_ru_alloc_c1_2_1_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	if (ru_x_alloc & RU_ALLOC_X_PLUS_1_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data3_ru_alloc_c2_2_1,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data3_ru_alloc_c2_2_1_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data3_ru_alloc_c2_2_1_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	if (ru_x_alloc & RU_ALLOC_X_PLUS_2_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data3_ru_alloc_c1_2_2,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data3_ru_alloc_c1_2_2_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data3_ru_alloc_c1_2_2_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data3_reserved, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);

	offset += 4;

	ru_x_alloc = tvb_get_letohl(tvb, offset);
	data = proto_tree_add_item(eht_tree, hf_radiotap_eht_data4, tvb, offset,
				   4, ENC_LITTLE_ENDIAN);

	sub_tree = proto_item_add_subtree(data, ett_radiotap_eht_data);

	if (ru_x_alloc & RU_ALLOC_X_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data4_ru_alloc_c2_2_2,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data4_ru_alloc_c2_2_2_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data4_ru_alloc_c2_2_2_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	if (ru_x_alloc & RU_ALLOC_X_PLUS_1_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data4_ru_alloc_c1_2_3,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data4_ru_alloc_c1_2_3_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data4_ru_alloc_c1_2_3_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	if (ru_x_alloc & RU_ALLOC_X_PLUS_2_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data4_ru_alloc_c2_2_3,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data4_ru_alloc_c2_2_3_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data4_ru_alloc_c2_2_3_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data4_reserved, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);

	offset += 4;

	ru_x_alloc = tvb_get_letohl(tvb, offset);
	data = proto_tree_add_item(eht_tree, hf_radiotap_eht_data5, tvb, offset,
				   4, ENC_LITTLE_ENDIAN);

	sub_tree = proto_item_add_subtree(data, ett_radiotap_eht_data);

	if (ru_x_alloc & RU_ALLOC_X_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data5_ru_alloc_c1_2_4,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data5_ru_alloc_c1_2_4_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data5_ru_alloc_c1_2_4_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	if (ru_x_alloc & RU_ALLOC_X_PLUS_1_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data5_ru_alloc_c2_2_4,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data5_ru_alloc_c2_2_4_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data5_ru_alloc_c2_2_4_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	if (ru_x_alloc & RU_ALLOC_X_PLUS_2_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data5_ru_alloc_c1_2_5,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data5_ru_alloc_c1_2_5_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data5_ru_alloc_c1_2_5_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data5_reserved, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);

	offset += 4;

	ru_x_alloc = tvb_get_letohl(tvb, offset);
	data = proto_tree_add_item(eht_tree, hf_radiotap_eht_data6, tvb, offset,
				   4, ENC_LITTLE_ENDIAN);

	sub_tree = proto_item_add_subtree(data, ett_radiotap_eht_data);

	if (ru_x_alloc & RU_ALLOC_X_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data6_ru_alloc_c2_2_5,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data6_ru_alloc_c2_2_5_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data6_ru_alloc_c2_2_5_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	if (ru_x_alloc & RU_ALLOC_X_PLUS_1_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data6_ru_alloc_c1_2_6,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data6_ru_alloc_c1_2_6_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data6_ru_alloc_c1_2_6_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	if (ru_x_alloc & RU_ALLOC_X_PLUS_2_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data6_ru_alloc_c2_2_6,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data6_ru_alloc_c2_2_6_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data6_ru_alloc_c2_2_6_known,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data6_reserved, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);

	offset += 4;

	data = proto_tree_add_item(eht_tree, hf_radiotap_eht_data7, tvb, offset,
				   4, ENC_LITTLE_ENDIAN);
	sub_tree = proto_item_add_subtree(data, ett_radiotap_eht_data);

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data7_crc2, tvb, offset,
			    4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_data7_tail2, tvb, offset,
			    4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_data7_rsvd, tvb, offset,
			    4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_data7_nss, tvb, offset,
			    4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_data7_beamformed, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	if (known & IEEE80211_RADIOTAP_EHT_NUMBER_NON_OFDMA_USERS_KNOWN) {
		proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data7_number_non_ofdma_users,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		item = proto_tree_add_item(sub_tree,
			hf_radiotap_eht_data7_number_non_ofdma_users_not_known,
			tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_item_append_text(item, " (Not known)");
	}
	proto_tree_add_item(sub_tree, hf_radiotap_eht_data7_user_encode_crc,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_data7_user_encode_tail,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_data7_rsvd2, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	data = proto_tree_add_item(eht_tree, hf_radiotap_eht_data8, tvb, offset,
				   4, ENC_LITTLE_ENDIAN);
	sub_tree = proto_item_add_subtree(data, ett_radiotap_eht_data);

	proto_tree_add_item(sub_tree, hf_radiotap_eht_data8_ru_alloc_ps_160,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_data8_ru_alloc_b0,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_data8_ru_alloc_b7_b1,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub_tree, hf_radiotap_eht_data8_rsvd, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* known + data[9] */
	len -= 10 * 4;

        /*
         * Now, are there any user-info entries?
         */
	info_11be->num_users = 0;
	if (tvb_captured_length_remaining(tvb, offset) && len > 0) {
		user_info_tree = proto_tree_add_subtree(eht_tree, tvb, offset,
			4, ett_radiotap_eht_user_info, NULL,
			"User Info");
		while (tvb_captured_length_remaining(tvb, offset) && len > 0) {
			dissect_eht_user_info(user_info_tree, tvb, offset, info_11be);
			offset += 4;
			len -= 4;
		}
	}
}

static int * const s1g_known_headers[] = {
	&hf_radiotap_s1g_s1g_ppdu_format_known,
	&hf_radiotap_s1g_response_indication_known,
	&hf_radiotap_s1g_guard_interval_known,
	&hf_radiotap_s1g_nss_known,
	&hf_radiotap_s1g_bandwidth_known,
	&hf_radiotap_s1g_mcs_known,
	&hf_radiotap_s1g_color_known,
	&hf_radiotap_s1g_uplink_indication_known,
	&hf_radiotap_s1g_reserved_1,
	NULL
};

static int * const s1g_data1_headers[] = {
	&hf_radiotap_s1g_s1g_ppdu_format,
	&hf_radiotap_s1g_response_indication,
	&hf_radiotap_s1g_reserved_2,
	&hf_radiotap_s1g_guard_interval,
	&hf_radiotap_s1g_nss,
	&hf_radiotap_s1g_bandwidth,
	&hf_radiotap_s1g_mcs,
	NULL
};

static int * const s1g_data2_headers[] = {
	&hf_radiotap_s1g_color,
	&hf_radiotap_s1g_uplink_indication,
	&hf_radiotap_s1g_reserved_3,
	&hf_radiotap_s1g_rssi,
	NULL
};

static void
dissect_radiotap_s1g(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        int offset, struct ieee_802_11_phdr *phdr, bool is_tlv _U_)
{
	proto_tree *s1g_tree = NULL;

	phdr->phy = PHDR_802_11_PHY_11AH;
	s1g_tree = proto_tree_add_subtree(tree, tvb, offset, 6,
					  ett_radiotap_s1g, NULL, "S1G");

	add_tlv_items(s1g_tree, tvb, offset);

	proto_tree_add_bitmask(s1g_tree, tvb, offset,
			hf_radiotap_s1g_known, ett_radiotap_s1g_known,
			s1g_known_headers, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(s1g_tree, tvb, offset,
			hf_radiotap_s1g_data_1, ett_radiotap_s1g_data_1,
			s1g_data1_headers, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(s1g_tree, tvb, offset,
			hf_radiotap_s1g_data_2, ett_radiotap_s1g_data_2,
			s1g_data2_headers, ENC_LITTLE_ENDIAN);
}

static void
dissect_radiotap_tsft(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	int offset, struct ieee_802_11_phdr *phdr)
{
	phdr->tsf_timestamp = tvb_get_letoh64(tvb, offset);
	phdr->has_tsf_timestamp = true;
	proto_tree_add_uint64(tree, hf_radiotap_mactime, tvb, offset, 8,
			      phdr->tsf_timestamp);
}

static void
dissect_radiotap_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	int offset, uint8_t *rflags, struct ieee_802_11_phdr *phdr)
{
	proto_tree *ft;
	proto_tree *flags_tree;

	*rflags = tvb_get_uint8(tvb, offset);
	if (*rflags & IEEE80211_RADIOTAP_F_DATAPAD)
		phdr->datapad = true;
	switch (radiotap_fcs_handling) {

	case USE_FCS_BIT:
		if (*rflags & IEEE80211_RADIOTAP_F_FCS)
			phdr->fcs_len = 4;
		else
			phdr->fcs_len = 0;
		break;

	case ASSUME_FCS_PRESENT:
		phdr->fcs_len = 4;
		break;

	case ASSUME_FCS_ABSENT:
		phdr->fcs_len = 0;
		break;
	}
	ft = proto_tree_add_item(tree, hf_radiotap_flags, tvb, offset,
				1, ENC_LITTLE_ENDIAN);
	flags_tree = proto_item_add_subtree(ft, ett_radiotap_flags);

	proto_tree_add_item(flags_tree, hf_radiotap_flags_cfp, tvb, offset,
				1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(flags_tree, hf_radiotap_flags_preamble, tvb, offset,
				1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(flags_tree, hf_radiotap_flags_wep, tvb, offset, 1,
				ENC_LITTLE_ENDIAN);
	proto_tree_add_item(flags_tree, hf_radiotap_flags_frag, tvb, offset, 1,
				ENC_LITTLE_ENDIAN);
	proto_tree_add_item(flags_tree, hf_radiotap_flags_fcs, tvb, offset, 1,
				ENC_LITTLE_ENDIAN);
	proto_tree_add_item(flags_tree, hf_radiotap_flags_datapad, tvb, offset,
				1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(flags_tree, hf_radiotap_flags_badfcs, tvb, offset,
				1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(flags_tree, hf_radiotap_flags_shortgi, tvb, offset,
				1, ENC_LITTLE_ENDIAN);
}

static void
dissect_radiotap_rate(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	int offset, struct ieee_802_11_phdr *phdr)
{
	uint32_t rate;

	rate = tvb_get_uint8(tvb, offset);
	/*
	 * XXX On FreeBSD rate & 0x80 means we have an MCS. On
	 * Linux and AirPcap it does not.  (What about
	 * macOS, NetBSD, OpenBSD, and DragonFly BSD?)
	 *
	 * This is an issue either for proprietary extensions
	 * to 11a or 11g, which do exist, or for 11n
	 * implementations that stuff a rate value into
	 * this field, which also appear to exist.
	 */
	if (radiotap_interpret_high_rates_as_mcs &&
			rate >= 0x80 && rate <= (0x80+76)) {
		/*
		 * XXX - we don't know the channel width
		 * or guard interval length, so we can't
		 * convert this to a data rate.
		 *
		 * If you want us to show a data rate,
		 * use the MCS field, not the Rate field;
		 * the MCS field includes not only the
		 * MCS index, it also includes bandwidth
		 * and guard interval information.
		 *
		 * XXX - can we get the channel width
		 * from XChannel and the guard interval
		 * information from Flags, at least on
		 * FreeBSD?
		 */
		proto_tree_add_uint(tree, hf_radiotap_mcs_index, tvb, offset,
				1, rate & 0x7f);
	} else {
		col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%d.%d",
			     rate / 2, rate & 1 ? 5 : 0);
		proto_tree_add_float_format(tree, hf_radiotap_datarate,
					    tvb, offset, 1, (float)rate / 2,
					    "Data Rate: %.1f Mb/s",
					    (float)rate / 2);
		phdr->has_data_rate = true;
		phdr->data_rate = rate;
	}
}

static void
dissect_radiotap_channel(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	int offset, struct ieee_802_11_phdr *phdr)
{
	uint32_t    freq;
	uint16_t    cflags;

	freq = tvb_get_letohs(tvb, offset);
	if (freq != 0) {
		/*
		 * XXX - some captures have 0, which is
		 * obviously bogus.
		 */
		int calc_channel;

		phdr->has_frequency = true;
		phdr->frequency = freq;
		calc_channel = ieee80211_mhz_to_chan(freq);
		if (calc_channel != -1) {
			phdr->has_channel = true;
			phdr->channel = calc_channel;
		}
	}
	memset(&phdr->phy_info, 0, sizeof(phdr->phy_info));
	cflags = tvb_get_letohs(tvb, offset + 2);
	switch (cflags & IEEE80211_CHAN_ALLTURBO) {

	case IEEE80211_CHAN_FHSS:
		phdr->phy = PHDR_802_11_PHY_11_FHSS;
		break;

	case IEEE80211_CHAN_DSSS:
		phdr->phy = PHDR_802_11_PHY_11_DSSS;
		break;

	case IEEE80211_CHAN_A:
		phdr->phy = PHDR_802_11_PHY_11A;
		phdr->phy_info.info_11a.has_turbo_type = true;
		phdr->phy_info.info_11a.turbo_type = PHDR_802_11A_TURBO_TYPE_NORMAL;
		break;

	case IEEE80211_CHAN_B:
		phdr->phy = PHDR_802_11_PHY_11B;
		break;

	case IEEE80211_CHAN_PUREG:
	case IEEE80211_CHAN_G:
		/*
		 * One of those means, in theory, that there should
		 * only be ERP-OFDM traffic, and the other means that
		 * there could be both ERP-DSSS and ERP-OFDM traffic.
		 *
		 * For now, we treat it as 11g; later, we'll check
		 * the rate and, if it's a DSSS rate, mark it as 11b,
		 * instead.
		 */
		phdr->phy = PHDR_802_11_PHY_11G;
		phdr->phy_info.info_11g.has_mode = true;
		phdr->phy_info.info_11g.mode = PHDR_802_11G_MODE_NORMAL;
		break;

	case IEEE80211_CHAN_108A:
		phdr->phy = PHDR_802_11_PHY_11A;
		phdr->phy_info.info_11a.has_turbo_type = true;
		/* We assume non-STURBO is dynamic turbo */
		phdr->phy_info.info_11a.turbo_type = PHDR_802_11A_TURBO_TYPE_DYNAMIC_TURBO;
		break;

	case IEEE80211_CHAN_108PUREG:
		phdr->phy = PHDR_802_11_PHY_11G;
		phdr->phy_info.info_11g.has_mode = true;
		phdr->phy_info.info_11g.mode = PHDR_802_11G_MODE_SUPER_G;
		break;
	}

	/*
	 * XXX - special-case 11ad; there's no field to explicitly indicate
	 * an 11ad packet.  Anything with a frequency in the 802.11ad range
	 * is treated as 11ad.
	 */
	if (IS_80211AD(freq)) {
		phdr->phy = PHDR_802_11_PHY_11AD;
	}

	/* XXX - Control frames are transmitted in legacy mode using the basic
	 * rate, and in the 6 GHz band will get called PHY_11A (assuming the
	 * 5 GHz bit is set), even though that the use of that band indicates
	 * 802.11ax or 802.11be certified devices, which is confusing for some
	 * users. (#17393)
	 */

	if (tree) {
		char	   *chan_str;
		static int * const channel_flags[] = {
			&hf_radiotap_channel_flags_700mhz,
			&hf_radiotap_channel_flags_800mhz,
			&hf_radiotap_channel_flags_900mhz,
			&hf_radiotap_channel_flags_turbo,
			&hf_radiotap_channel_flags_cck,
			&hf_radiotap_channel_flags_ofdm,
			&hf_radiotap_channel_flags_2ghz,
			&hf_radiotap_channel_flags_5ghz,
			&hf_radiotap_channel_flags_passive,
			&hf_radiotap_channel_flags_dynamic,
			&hf_radiotap_channel_flags_gfsk,
			&hf_radiotap_channel_flags_gsm,
			&hf_radiotap_channel_flags_sturbo,
			&hf_radiotap_channel_flags_half,
			&hf_radiotap_channel_flags_quarter,
			NULL
		};

		chan_str = ieee80211_mhz_to_str(freq);
		col_add_fstr(pinfo->cinfo,
			     COL_FREQ_CHAN, "%s", chan_str);
		proto_tree_add_uint_format_value(tree,
					   hf_radiotap_channel_frequency,
					   tvb, offset, 2, freq,
					   "%s",
					   chan_str);
		g_free(chan_str);

		/* We're already 2-byte aligned. */
		proto_tree_add_bitmask(tree, tvb, offset + 2,
				hf_radiotap_channel_flags,
				ett_radiotap_channel_flags,
				channel_flags, ENC_LITTLE_ENDIAN);
	}
}

static void
dissect_radiotap_fhss(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	int offset, struct ieee_802_11_phdr *phdr)
{
	/*
	 * Just in case we didn't have a Channel field or
	 * it said this was something other than 11 legacy
	 * FHSS.
	 */
	phdr->phy = PHDR_802_11_PHY_11_FHSS;
	phdr->phy_info.info_11_fhss.has_hop_set = true;
	phdr->phy_info.info_11_fhss.hop_set = tvb_get_uint8(tvb, offset);
	phdr->phy_info.info_11_fhss.has_hop_pattern = true;
	phdr->phy_info.info_11_fhss.hop_pattern = tvb_get_uint8(tvb, offset + 1);
	proto_tree_add_item(tree, hf_radiotap_fhss_hopset, tvb, offset, 1,
			    ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_radiotap_fhss_pattern, tvb, offset + 1, 1,
			    ENC_LITTLE_ENDIAN);
}

static void
dissect_radiotap_dbm_antsignal(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree, int offset, struct ieee_802_11_phdr *phdr)
{
	int8_t dbm = tvb_get_int8(tvb, offset);

	phdr->has_signal_dbm = true;
	phdr->signal_dbm = dbm;
	col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", dbm);
	proto_tree_add_int(tree, hf_radiotap_dbm_antsignal, tvb, offset, 1, dbm);

}

static void
dissect_radiotap_dbm_antnoise(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree, int offset, struct ieee_802_11_phdr *phdr)
{
	int dbm = tvb_get_int8(tvb, offset);

	phdr->has_noise_dbm = true;
	phdr->noise_dbm = dbm;
	if (tree) {
		proto_tree_add_int(tree, hf_radiotap_dbm_antnoise, tvb, offset,
				1, dbm);
	}
}

static void
dissect_radiotap_db_antsignal(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree, int offset, struct ieee_802_11_phdr *phdr)
{
	uint8_t db = tvb_get_uint8(tvb, offset);

	phdr->has_signal_db = true;
	phdr->signal_db = db;
	col_add_fstr(pinfo->cinfo, COL_RSSI, "%u dB", db);
	proto_tree_add_uint(tree, hf_radiotap_db_antsignal, tvb, offset, 1, db);
}

static void
dissect_radiotap_db_antnoise(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree, int offset, struct ieee_802_11_phdr *phdr)
{
	unsigned db = tvb_get_uint8(tvb, offset);

	phdr->has_noise_db = true;
	phdr->noise_db = db;
	if (tree) {
		proto_tree_add_uint(tree, hf_radiotap_db_antnoise, tvb, offset,
				1, db);
	}
}

static void
dissect_radiotap_rx_flags(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree, int offset, proto_item **hdr_fcs_ti,
	int *hdr_fcs_offset, int *sent_fcs)
{
	if (radiotap_bit14_fcs) {
		if (tree) {
			*sent_fcs   = tvb_get_ntohl(tvb, offset);
			*hdr_fcs_ti = proto_tree_add_uint(tree,
							 hf_radiotap_fcs, tvb,
							 offset, 4, *sent_fcs);
			*hdr_fcs_offset = offset;
		}
	} else {
		static int * const rxflags[] = {
			&hf_radiotap_rxflags_badplcp,
			NULL
		};

		proto_tree_add_bitmask(tree, tvb, offset,
				hf_radiotap_rxflags, ett_radiotap_rxflags,
				rxflags, ENC_LITTLE_ENDIAN);
	}
}


static void
dissect_radiotap_tx_flags(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree, int offset)
{
	static int * const txflags[] = {
		&hf_radiotap_txflags_fail,
		&hf_radiotap_txflags_cts,
		&hf_radiotap_txflags_rts,
		&hf_radiotap_txflags_noack,
		&hf_radiotap_txflags_noseqno,
		&hf_radiotap_txflags_order,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset,
			hf_radiotap_txflags, ett_radiotap_txflags,
			txflags, ENC_LITTLE_ENDIAN);
}

static void
dissect_radiotap_xchannel(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree, int offset, struct ieee_802_11_phdr *phdr)
{
	uint32_t    xcflags = tvb_get_letohl(tvb, offset);
	uint32_t    freq;

	switch (xcflags & IEEE80211_CHAN_ALLTURBO) {

	case IEEE80211_CHAN_FHSS:
		phdr->phy = PHDR_802_11_PHY_11_FHSS;
		break;

	case IEEE80211_CHAN_DSSS:
		phdr->phy = PHDR_802_11_PHY_11_DSSS;
		break;

	case IEEE80211_CHAN_A:
		phdr->phy = PHDR_802_11_PHY_11A;
		phdr->phy_info.info_11a.has_turbo_type = true;
		phdr->phy_info.info_11a.turbo_type = PHDR_802_11A_TURBO_TYPE_NORMAL;
		break;

	case IEEE80211_CHAN_B:
		phdr->phy = PHDR_802_11_PHY_11B;
		break;

	case IEEE80211_CHAN_PUREG:
	case IEEE80211_CHAN_G:
		phdr->phy = PHDR_802_11_PHY_11G;
		phdr->phy_info.info_11g.has_mode = true;
		phdr->phy_info.info_11g.mode = PHDR_802_11G_MODE_NORMAL;
		break;

	case IEEE80211_CHAN_108A:
		phdr->phy = PHDR_802_11_PHY_11A;
		phdr->phy_info.info_11a.has_turbo_type = true;
		/* We assume non-STURBO is dynamic turbo */
		phdr->phy_info.info_11a.turbo_type = PHDR_802_11A_TURBO_TYPE_DYNAMIC_TURBO;
		break;

	case IEEE80211_CHAN_108PUREG:
		phdr->phy = PHDR_802_11_PHY_11G;
		phdr->phy_info.info_11g.has_mode = true;
		phdr->phy_info.info_11g.mode = PHDR_802_11G_MODE_SUPER_G;
		break;

	case IEEE80211_CHAN_ST:
		phdr->phy = PHDR_802_11_PHY_11A;
		phdr->phy_info.info_11a.has_turbo_type = true;
		phdr->phy_info.info_11a.turbo_type = PHDR_802_11A_TURBO_TYPE_STATIC_TURBO;
		break;

	case IEEE80211_CHAN_A|IEEE80211_CHAN_HT20:
	case IEEE80211_CHAN_A|IEEE80211_CHAN_HT40D:
	case IEEE80211_CHAN_A|IEEE80211_CHAN_HT40U:
	case IEEE80211_CHAN_G|IEEE80211_CHAN_HT20:
	case IEEE80211_CHAN_G|IEEE80211_CHAN_HT40U:
	case IEEE80211_CHAN_G|IEEE80211_CHAN_HT40D:
		phdr->phy = PHDR_802_11_PHY_11N;
		break;
	}
	freq = tvb_get_letohs(tvb, offset + 4);
	if (freq != 0) {
		/*
		 * XXX - some captures have 0, which is
		 * obviously bogus.
		 */
		phdr->has_frequency = true;
		phdr->frequency = freq;

		/*
		 * XXX - special-case 11ad; there's no field to explicitly
		 * indicate an 11ad packet.  Anything with a frequency in
		 * the 802.11ad range is treated as 11ad.
		 */
		if (IS_80211AD(freq))
			phdr->phy = PHDR_802_11_PHY_11AD;
	}
	phdr->has_channel = true;
	phdr->channel = tvb_get_uint8(tvb, offset + 6);
	if (tree) {
		static int * const xchannel_flags[] = {
			&hf_radiotap_xchannel_flags_turbo,
			&hf_radiotap_xchannel_flags_cck,
			&hf_radiotap_xchannel_flags_ofdm,
			&hf_radiotap_xchannel_flags_2ghz,
			&hf_radiotap_xchannel_flags_5ghz,
			&hf_radiotap_xchannel_flags_passive,
			&hf_radiotap_xchannel_flags_dynamic,
			&hf_radiotap_xchannel_flags_gfsk,
			&hf_radiotap_xchannel_flags_gsm,
			&hf_radiotap_xchannel_flags_sturbo,
			&hf_radiotap_xchannel_flags_half,
			&hf_radiotap_xchannel_flags_quarter,
			&hf_radiotap_xchannel_flags_ht20,
			&hf_radiotap_xchannel_flags_ht40u,
			&hf_radiotap_xchannel_flags_ht40d,
			NULL
		};

		proto_tree_add_item(tree, hf_radiotap_xchannel_channel,
					tvb, offset + 6, 1,
					ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_radiotap_xchannel_frequency,
					tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);

		proto_tree_add_bitmask(tree, tvb, offset, hf_radiotap_xchannel_flags,
					ett_radiotap_xchannel_flags,
					xchannel_flags, ENC_LITTLE_ENDIAN);


#if 0
		proto_tree_add_uint(tree, hf_radiotap_xchannel_maxpower,
					tvb, offset + 7, 1, maxpower);
#endif
	}
}

static void
dissect_radiotap_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree, int offset, struct ieee_802_11_phdr *phdr _U_)
{
	proto_item *it_root;
	proto_tree *ts_tree, *flg_tree;

	it_root = proto_tree_add_item(tree, hf_radiotap_timestamp, tvb, offset,
			12, ENC_NA);
	ts_tree = proto_item_add_subtree(it_root, ett_radiotap_timestamp);

	proto_tree_add_item(ts_tree, hf_radiotap_timestamp_ts, tvb, offset, 8,
			ENC_LITTLE_ENDIAN);
	if (tvb_get_letohs(tvb, offset + 11) & IEEE80211_RADIOTAP_TS_FLG_ACCURACY)
		proto_tree_add_item(ts_tree, hf_radiotap_timestamp_accuracy,
				tvb, offset + 8, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ts_tree, hf_radiotap_timestamp_unit, tvb,
			offset + 10, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ts_tree, hf_radiotap_timestamp_spos, tvb,
			offset + 10, 1, ENC_LITTLE_ENDIAN);
	flg_tree = proto_item_add_subtree(ts_tree, ett_radiotap_timestamp_flags);
	proto_tree_add_item(flg_tree, hf_radiotap_timestamp_flags_32bit, tvb,
			offset + 11, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(flg_tree, hf_radiotap_timestamp_flags_accuracy, tvb,
			offset + 11, 1, ENC_LITTLE_ENDIAN);
}

static int
dissect_radiotap(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* unused_data _U_)
{
	proto_tree *radiotap_tree     = NULL;
	proto_item *length_item       = NULL;
	proto_item *present_item      = NULL;
	proto_tree *present_tree      = NULL;
	proto_item *present_word_item = NULL;
	proto_tree *present_word_tree = NULL;
	proto_item *ti                = NULL;
	proto_item *hidden_item;
	int         offset;
	tvbuff_t   *next_tvb;
	uint8_t     version;
	unsigned    length;
	proto_item *rate_ti;
	bool        have_rflags       = false;
	uint8_t     rflags            = 0;
	/* backward compat with bit 14 == fcs in header */
	proto_item *hdr_fcs_ti        = NULL;
	int         hdr_fcs_offset    = 0;
	uint32_t    sent_fcs          = 0;
	uint32_t    calc_fcs;
	int         err               = -ENOENT;
	void       *data;
	struct ieee80211_radiotap_iterator  iter;
	struct ieee_802_11_phdr phdr;
	unsigned char	 *bmap_start;
	unsigned	  n_bitmaps;
	unsigned	  i;
	bool      rtap_ns;
	bool      rtap_ns_next;
	unsigned	  rtap_ns_offset;
	unsigned	  rtap_ns_offset_next;
	bool      zero_length_psdu = false;
	uint32_t  ven_ns_id;
	tvbuff_t  *ven_data_tvb;

	/* our non-standard overrides */
	static struct radiotap_override overrides[] = {
		{IEEE80211_RADIOTAP_XCHANNEL, 4, 8},	/* xchannel */

		/* keep last */
		{14, 4, 4},	/* FCS in header */
	};
	unsigned n_overrides = array_length(overrides);

	if (!radiotap_bit14_fcs)
		n_overrides--;

	/* We don't have any 802.11 metadata yet. */
	memset(&phdr, 0, sizeof(phdr));
	phdr.fcs_len = -1;
	phdr.decrypted = false;
	phdr.datapad = false;
	phdr.phy = PHDR_802_11_PHY_UNKNOWN;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WLAN");
	col_clear(pinfo->cinfo, COL_INFO);

	version = tvb_get_uint8(tvb, 0);
	length = tvb_get_letohs(tvb, 2);

	col_add_fstr(pinfo->cinfo, COL_INFO, "Radiotap Capture v%u, Length %u",
		     version, length);

	/* Dissect the packet */
	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_radiotap,
						    tvb, 0, length,
						    "Radiotap Header v%u, Length %u",
						    version, length);
		radiotap_tree = proto_item_add_subtree(ti, ett_radiotap);
		proto_tree_add_uint(radiotap_tree, hf_radiotap_version,
				    tvb, 0, 1, version);
		proto_tree_add_item(radiotap_tree, hf_radiotap_pad,
				    tvb, 1, 1, ENC_LITTLE_ENDIAN);
		length_item = proto_tree_add_uint(radiotap_tree, hf_radiotap_length,
						  tvb, 2, 2, length);
	}

	/*
	 * The length is the length of the entire radiotap header, so it
	 * must be at least 8, for the version, padding, length, and first
	 * presence flags word.
	 */
	if (length < 8) {
		expert_add_info(pinfo, length_item,
		    &ei_radiotap_invalid_header_length);
		return tvb_captured_length(tvb);
	}

	data = tvb_memdup(pinfo->pool, tvb, 0, length);

	if (ieee80211_radiotap_iterator_init(&iter, (struct ieee80211_radiotap_header *)data, length, NULL)) {
		if (tree)
			proto_item_append_text(ti, " (invalid)");
		/* maybe the length was correct anyway ... */
		goto hand_off_to_80211;
	}

	iter.overrides = overrides;
	iter.n_overrides = n_overrides;

	/*
	 * Check the "present flags" bitmaps, and add them if we're
	 * building a tree.
	 */
	bmap_start = (unsigned char *)data + 4;
	n_bitmaps = (unsigned)(iter.this_arg - bmap_start) / 4;
	rtap_ns_next = true;
	rtap_ns_offset_next = 0;
	present_item = proto_tree_add_item(radiotap_tree,
	    hf_radiotap_present, tvb, 4, n_bitmaps * 4, ENC_NA);
	present_tree = proto_item_add_subtree(present_item,
	    ett_radiotap_present);

	for (i = 0; i < n_bitmaps; i++) {
		uint32_t bmap = pletoh32(bmap_start + 4 * i);

		rtap_ns_offset = rtap_ns_offset_next;
		rtap_ns_offset_next += 32;

		offset = 4 * i;

		present_word_item =
		    proto_tree_add_item(present_tree,
		      hf_radiotap_present_word,
		      tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);

		present_word_tree =
		    proto_item_add_subtree(present_word_item,
		      ett_radiotap_present_word);

		rtap_ns = rtap_ns_next;

		/* Evaluate what kind of namespaces will come next */
		if (bmap & BIT(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE)) {
			rtap_ns_next = true;
			rtap_ns_offset_next = 0;
		}
		if (bmap & BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE))
			rtap_ns_next = false;
		if ((bmap & (BIT(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE) |
			     BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE)))
			== (BIT(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE) |
			    BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE))) {
			expert_add_info_format(pinfo, present_word_item,
			    &ei_radiotap_present,
			    "Both radiotap and vendor namespace specified in bitmask word %u",
			    i);
			goto malformed;
		}

		if (!rtap_ns)
			goto always_bits;

		/* Currently, we don't know anything about bits >= 32 */
		if (rtap_ns_offset)
			goto always_bits;

		if (tree) {
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_tsft, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_flags, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_rate, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_channel, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_fhss, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_dbm_antsignal,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_dbm_antnoise,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_lock_quality,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_tx_attenuation,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_db_tx_attenuation,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_dbm_tx_power,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_antenna, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_db_antsignal,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_db_antnoise,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			if (radiotap_bit14_fcs) {
				proto_tree_add_item(present_word_tree,
						    hf_radiotap_present_hdrfcs,
						    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			} else {
				proto_tree_add_item(present_word_tree,
						    hf_radiotap_present_rxflags,
						    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			}
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_txflags, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_data_retries, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_xchannel, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);

			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_mcs, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_ampdu, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_vht, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_timestamp, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_he, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_he_mu, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_0_length_psdu,
					    tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_l_sig, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);

			ti = proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_reserved, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_tlv, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
		}
 always_bits:
		if (tree) {
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_rtap_ns, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_vendor_ns, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(present_word_tree,
					    hf_radiotap_present_ext, tvb,
					    offset + 4, 4, ENC_LITTLE_ENDIAN);
		}
	}

	while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
		proto_tree *item_tree = radiotap_tree;

		offset = (int)((unsigned char *) iter.this_arg - (unsigned char *) data);

		if (iter.this_arg_index == IEEE80211_RADIOTAP_VENDOR_NAMESPACE
		    && tree && !iter.tlv_mode) {
			proto_tree *ven_tree;
			proto_item *vt;
			const char *manuf_name;
			uint8_t subns;

			manuf_name = tvb_get_manuf_name(tvb, offset);
			subns = tvb_get_uint8(tvb, offset+3);

			vt = proto_tree_add_bytes_format_value(item_tree,
							 hf_radiotap_vendor_ns,
							 tvb, offset,
							 iter.this_arg_size,
							 NULL,
							 "%s-%d",
							 manuf_name, subns);
			ven_tree = proto_item_add_subtree(vt, ett_radiotap_vendor);
			/*
			 * This is defined on the Radiotap site as an array
			 * of 3 octets, containing an OUI, but we show fields
			 * of that sort as a 24-bit big-endian field, so
			 * ENC_BIG_ENDIAN is correct here.
			 */
			proto_tree_add_item(ven_tree, hf_radiotap_ven_oui,
					    tvb, offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(ven_tree, hf_radiotap_ven_subns,
					    tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
			/* Get OUI and sub namespace as UINT32 */
			ven_ns_id = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
			if (iter.tlv_mode) {
				proto_tree_add_item(ven_tree, hf_radiotap_ven_item, tvb,
						    offset + 4, 2, ENC_LITTLE_ENDIAN);
				ven_data_tvb = tvb_new_subset_length(tvb, offset + 8, iter.this_arg_size - 8);
			} else {
				proto_tree_add_item(ven_tree, hf_radiotap_ven_skip, tvb,
						    offset + 4, 2, ENC_LITTLE_ENDIAN);
				ven_data_tvb = tvb_new_subset_length(tvb, offset + 6, iter.this_arg_size - 6);
			}
			if (!dissector_try_uint_new(vendor_dissector_table, ven_ns_id, ven_data_tvb, pinfo, ven_tree, true, NULL)) {
				proto_tree_add_item(ven_tree, hf_radiotap_ven_data, ven_data_tvb, 0, -1, ENC_NA);
			}
		}

		if (!iter.is_radiotap_ns)
			continue;

		switch (iter.this_arg_index) {

		case IEEE80211_RADIOTAP_TSFT:
			dissect_radiotap_tsft(tvb, pinfo, item_tree, offset,
					&phdr);
			break;

		case IEEE80211_RADIOTAP_FLAGS:
			have_rflags = true;
			dissect_radiotap_flags(tvb, pinfo, item_tree, offset,
					&rflags, &phdr);
			break;

		case IEEE80211_RADIOTAP_RATE:
			dissect_radiotap_rate(tvb, pinfo, item_tree, offset,
					&phdr);
			break;

		case IEEE80211_RADIOTAP_CHANNEL:
			dissect_radiotap_channel(tvb, pinfo, item_tree, offset,
					&phdr);
			break;

		case IEEE80211_RADIOTAP_FHSS:
			dissect_radiotap_fhss(tvb, pinfo, item_tree, offset,
					&phdr);
			break;

		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
			dissect_radiotap_dbm_antsignal(tvb, pinfo, item_tree,
					offset, &phdr);
			break;

		case IEEE80211_RADIOTAP_DBM_ANTNOISE:
			dissect_radiotap_dbm_antnoise(tvb, pinfo, item_tree,
					offset, &phdr);
			break;

		case IEEE80211_RADIOTAP_LOCK_QUALITY:
			proto_tree_add_item(item_tree,
						    hf_radiotap_quality, tvb,
						    offset, 2, ENC_LITTLE_ENDIAN);
			break;

		case IEEE80211_RADIOTAP_TX_ATTENUATION:
			proto_tree_add_item(item_tree,
					    hf_radiotap_tx_attenuation, tvb,
					    offset, 2, ENC_LITTLE_ENDIAN);
			break;

		case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
			proto_tree_add_item(item_tree,
					    hf_radiotap_db_tx_attenuation, tvb,
					    offset, 2, ENC_LITTLE_ENDIAN);
			break;

		case IEEE80211_RADIOTAP_DBM_TX_POWER:
			proto_tree_add_item(item_tree,
						   hf_radiotap_txpower, tvb,
						   offset, 1, ENC_NA);
			break;

		case IEEE80211_RADIOTAP_ANTENNA:
			proto_tree_add_item(item_tree,
						    hf_radiotap_antenna, tvb,
						    offset, 1, ENC_NA);
			break;

		case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
			dissect_radiotap_db_antsignal(tvb, pinfo, item_tree,
					offset, &phdr);
			break;

		case IEEE80211_RADIOTAP_DB_ANTNOISE:
			dissect_radiotap_db_antnoise(tvb, pinfo, item_tree,
					offset, &phdr);
			break;

		case IEEE80211_RADIOTAP_RX_FLAGS:
			dissect_radiotap_rx_flags(tvb, pinfo, item_tree,
						offset, &hdr_fcs_ti,
						&hdr_fcs_offset, &sent_fcs);
			break;

		case IEEE80211_RADIOTAP_TX_FLAGS:
			dissect_radiotap_tx_flags(tvb, pinfo, item_tree,
						offset);
			break;

		case IEEE80211_RADIOTAP_DATA_RETRIES:
			proto_tree_add_item(item_tree,
				hf_radiotap_data_retries, tvb,
				offset, 1, ENC_LITTLE_ENDIAN);
			break;

		case IEEE80211_RADIOTAP_XCHANNEL:
			dissect_radiotap_xchannel(tvb, pinfo, item_tree,
						offset, &phdr);
			break;

		case IEEE80211_RADIOTAP_MCS: {
			proto_tree *mcs_tree = NULL;
			uint8_t	    mcs_known, mcs_flags;
			uint8_t	    mcs;
			unsigned	    bandwidth;
			unsigned	    gi_length;
			bool        can_calculate_rate;

			/*
			 * Start out assuming that we can calculate the rate;
			 * if we are missing any of the MCS index, channel
			 * width, or guard interval length, we can't.
			 */
			can_calculate_rate = true;

			mcs_known = tvb_get_uint8(tvb, offset);
			/*
			 * If there's actually any data here, not an
			 * empty field, this is 802.11n - unless we've
			 * seen a frequency >= 60 GHz and already set
			 * it to 802.11ad.
			 */
			if (mcs_known != 0 &&
			    phdr.phy != PHDR_802_11_PHY_11AD) {
				phdr.phy = PHDR_802_11_PHY_11N;
				memset(&phdr.phy_info.info_11n, 0, sizeof(phdr.phy_info.info_11n));
			}

			mcs_flags = tvb_get_uint8(tvb, offset + 1);
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_MCS) {
				mcs = tvb_get_uint8(tvb, offset + 2);
				phdr.phy_info.info_11n.has_mcs_index = true;
				phdr.phy_info.info_11n.mcs_index = mcs;
			} else {
				mcs = 0;
				can_calculate_rate = false;	/* no MCS index */
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
				phdr.phy_info.info_11n.has_bandwidth = true;
				phdr.phy_info.info_11n.bandwidth = (mcs_flags & IEEE80211_RADIOTAP_MCS_BW_MASK);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_GI) {
				gi_length = (mcs_flags & IEEE80211_RADIOTAP_MCS_SGI) ?
				    1 : 0;
				phdr.phy_info.info_11n.has_short_gi = true;
				phdr.phy_info.info_11n.short_gi = gi_length;
			} else {
				gi_length = 0;
				can_calculate_rate = false;	/* no GI width */
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FMT) {
				phdr.phy_info.info_11n.has_greenfield = true;
				phdr.phy_info.info_11n.greenfield = (mcs_flags & IEEE80211_RADIOTAP_MCS_FMT_GF) != 0;
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FEC) {
				phdr.phy_info.info_11n.has_fec = true;
				phdr.phy_info.info_11n.fec = (mcs_flags & IEEE80211_RADIOTAP_MCS_FEC_LDPC) ? 1 : 0;
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_STBC) {
				phdr.phy_info.info_11n.has_stbc_streams = true;
				phdr.phy_info.info_11n.stbc_streams = (mcs_flags & IEEE80211_RADIOTAP_MCS_STBC_MASK) >> IEEE80211_RADIOTAP_MCS_STBC_SHIFT;
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_NESS) {
				phdr.phy_info.info_11n.has_ness = true;
				/* This is stored a bit weirdly */
				phdr.phy_info.info_11n.ness =
				    ((mcs_known & IEEE80211_RADIOTAP_MCS_NESS_BIT1) >> 6) |
				    ((mcs_flags & IEEE80211_RADIOTAP_MCS_NESS_BIT0) >> 7);
			}

			if (tree) {
				proto_item *it;
				static int * const mcs_haves_with_ness_bit1[] = {
					&hf_radiotap_mcs_have_bw,
					&hf_radiotap_mcs_have_index,
					&hf_radiotap_mcs_have_gi,
					&hf_radiotap_mcs_have_format,
					&hf_radiotap_mcs_have_fec,
					&hf_radiotap_mcs_have_stbc,
					&hf_radiotap_mcs_have_ness,
					&hf_radiotap_mcs_ness_bit1,
					NULL
				};
				static int * const mcs_haves_without_ness_bit1[] = {
					&hf_radiotap_mcs_have_bw,
					&hf_radiotap_mcs_have_index,
					&hf_radiotap_mcs_have_gi,
					&hf_radiotap_mcs_have_format,
					&hf_radiotap_mcs_have_fec,
					&hf_radiotap_mcs_have_stbc,
					&hf_radiotap_mcs_have_ness,
					NULL
				};

				it = proto_tree_add_item(item_tree, hf_radiotap_mcs,
							 tvb, offset, 3, ENC_NA);
				mcs_tree = proto_item_add_subtree(it, ett_radiotap_mcs);

				if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_NESS)
					proto_tree_add_bitmask(mcs_tree, tvb, offset, hf_radiotap_mcs_known, ett_radiotap_mcs_known, mcs_haves_with_ness_bit1, ENC_LITTLE_ENDIAN);
				else
					proto_tree_add_bitmask(mcs_tree, tvb, offset, hf_radiotap_mcs_known, ett_radiotap_mcs_known, mcs_haves_without_ness_bit1, ENC_LITTLE_ENDIAN);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
				bandwidth = ((mcs_flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_40) ?
				    1 : 0;
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_bw,
							    tvb, offset + 1, 1, mcs_flags);
			} else {
				bandwidth = 0;
				can_calculate_rate = false;	/* no bandwidth */
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_GI) {
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_gi,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FMT) {
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_format,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FEC) {
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_fec,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_STBC) {
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_stbc,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_NESS) {
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_ness_bit0,
							    tvb, offset + 1, 1, mcs_flags);
			}
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_MCS) {
				proto_tree_add_uint(mcs_tree, hf_radiotap_mcs_index,
							    tvb, offset + 2, 1, mcs);
			}

			/*
			 * If we have the MCS index, channel width, and
			 * guard interval length, and the MCS index is
			 * valid, we can compute the rate.  If the resulting
			 * rate is non-zero, report it.  (If it's zero,
			 * it's an MCS/channel width/GI combination that
			 * 802.11n doesn't support.)
			 */
			if (can_calculate_rate && mcs <= MAX_MCS_INDEX
					&& ieee80211_ht_Dbps[mcs] != 0) {
				float rate = ieee80211_htrate(mcs, bandwidth, gi_length);
				col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%.1f", rate);
				if (tree) {
					rate_ti = proto_tree_add_float_format(item_tree,
						hf_radiotap_datarate,
						tvb, offset, 3, rate,
						"Data Rate: %.1f Mb/s", rate);
					proto_item_set_generated(rate_ti);
				}
			}
			break;
		}
		case IEEE80211_RADIOTAP_AMPDU_STATUS: {
			proto_item *it;
			proto_tree *ampdu_tree = NULL, *ampdu_flags_tree;
			uint16_t	    ampdu_flags;

			phdr.has_aggregate_info = 1;
			phdr.aggregate_flags = 0;
			phdr.aggregate_id = tvb_get_letohl(tvb, offset);

			ampdu_flags = tvb_get_letohs(tvb, offset + 4);
			if (ampdu_flags & IEEE80211_RADIOTAP_AMPDU_IS_LAST)
				phdr.aggregate_flags |= PHDR_802_11_LAST_PART_OF_A_MPDU;
			if (ampdu_flags & IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_ERR)
				phdr.aggregate_flags |= PHDR_802_11_A_MPDU_DELIM_CRC_ERROR;

			if (tree) {
				it = proto_tree_add_item(item_tree, hf_radiotap_ampdu,
							 tvb, offset, 8, ENC_NA);
				ampdu_tree = proto_item_add_subtree(it, ett_radiotap_ampdu);

				proto_tree_add_item(ampdu_tree, hf_radiotap_ampdu_ref,
						    tvb, offset, 4, ENC_LITTLE_ENDIAN);

				it = proto_tree_add_item(ampdu_tree, hf_radiotap_ampdu_flags,
							 tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				ampdu_flags_tree = proto_item_add_subtree(it, ett_radiotap_ampdu_flags);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_report_zerolen,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_is_zerolen,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_last_known,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_is_last,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_delim_crc_error,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_eof,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ampdu_flags_tree, hf_radiotap_ampdu_flags_eof_known,
						    tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
			}
			if (ampdu_flags & IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_KNOWN) {
				if (ampdu_tree)
					proto_tree_add_item(ampdu_tree, hf_radiotap_ampdu_delim_crc,
							    tvb, offset + 6, 1, ENC_NA);
			}
			break;
		}
		case IEEE80211_RADIOTAP_VHT: {
			proto_item *it, *it_root = NULL;
			proto_tree *vht_tree	 = NULL, *vht_known_tree = NULL, *user_tree = NULL;
			uint16_t	    known;
			uint8_t	    vht_flags, bw, mcs_nss;
			unsigned	    bandwidth	 = 0;
			unsigned	    gi_length	 = 0;
			unsigned	    nss		 = 0;
			unsigned	    mcs		 = 0;
			bool        can_calculate_rate;
			unsigned	    user;

			/*
			 * Start out assuming that we can calculate the rate;
			 * if we are missing any of the MCS index, channel
			 * width, or guard interval length, we can't.
			 */
			can_calculate_rate = true;

			known = tvb_get_letohs(tvb, offset);
			/*
			 * If there's actually any data here, not an
			 * empty field, this is 802.11ac.
			 */
			if (known != 0) {
				phdr.phy = PHDR_802_11_PHY_11AC;
			}
			vht_flags = tvb_get_uint8(tvb, offset + 2);
			if (tree) {
				it_root = proto_tree_add_item(item_tree, hf_radiotap_vht,
						tvb, offset, 12, ENC_NA);
				vht_tree = proto_item_add_subtree(it_root, ett_radiotap_vht);
				it = proto_tree_add_item(vht_tree, hf_radiotap_vht_known,
						tvb, offset, 2, ENC_NA);
				vht_known_tree = proto_item_add_subtree(it, ett_radiotap_vht_known);

				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_stbc,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_txop_ps,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_gi,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_sgi_nsym_da,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_ldpc_extra,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_bf,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_bw,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_gid,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(vht_known_tree, hf_radiotap_vht_have_p_aid,
						tvb, offset, 2, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_STBC) {
				phdr.phy_info.info_11ac.has_stbc = true;
				phdr.phy_info.info_11ac.stbc = (vht_flags & IEEE80211_RADIOTAP_VHT_STBC) != 0;
				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_stbc,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_TXOP_PS) {
				phdr.phy_info.info_11ac.has_txop_ps_not_allowed = true;
				phdr.phy_info.info_11ac.txop_ps_not_allowed = (vht_flags & IEEE80211_RADIOTAP_VHT_TXOP_PS) != 0;
				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_txop_ps,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_GI) {
				gi_length = (vht_flags & IEEE80211_RADIOTAP_VHT_SGI) ? 1 : 0;
				phdr.phy_info.info_11ac.has_short_gi = true;
				phdr.phy_info.info_11ac.short_gi = gi_length;
				if (vht_tree) {
					proto_tree_add_item(vht_tree, hf_radiotap_vht_gi,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
				}
			} else {
				can_calculate_rate = false;	/* no GI width */
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_SGI_NSYM_DA) {
				phdr.phy_info.info_11ac.has_short_gi_nsym_disambig = true;
				phdr.phy_info.info_11ac.short_gi_nsym_disambig = (vht_flags & IEEE80211_RADIOTAP_VHT_SGI_NSYM_DA) != 0;
				if (vht_tree) {
					it = proto_tree_add_item(vht_tree, hf_radiotap_vht_sgi_nsym_da,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
					if ((vht_flags & IEEE80211_RADIOTAP_VHT_SGI_NSYM_DA) &&
						(known & IEEE80211_RADIOTAP_VHT_HAVE_GI) &&
						!(vht_flags & IEEE80211_RADIOTAP_VHT_SGI))
						proto_item_append_text(it, " (invalid)");
				}
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_LDPC_EXTRA) {
				phdr.phy_info.info_11ac.has_ldpc_extra_ofdm_symbol = true;
				phdr.phy_info.info_11ac.ldpc_extra_ofdm_symbol = (vht_flags & IEEE80211_RADIOTAP_VHT_LDPC_EXTRA) != 0;
				if (vht_tree) {
					proto_tree_add_item(vht_tree, hf_radiotap_vht_ldpc_extra,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
				}
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_BF) {
				phdr.phy_info.info_11ac.has_beamformed = true;
				phdr.phy_info.info_11ac.beamformed = (vht_flags & IEEE80211_RADIOTAP_VHT_BF) != 0;
				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_bf,
							tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_BW) {
				bw = tvb_get_uint8(tvb, offset + 3) & IEEE80211_RADIOTAP_VHT_BW_MASK;
				phdr.phy_info.info_11ac.has_bandwidth = true;
				phdr.phy_info.info_11ac.bandwidth = bw;
				if (bw < array_length(ieee80211_vht_bw2rate_index))
					bandwidth = ieee80211_vht_bw2rate_index[bw];
				else
					can_calculate_rate = false; /* unknown bandwidth */

				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_bw,
							tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
			} else {
				can_calculate_rate = false;	/* no bandwidth */
			}

			phdr.phy_info.info_11ac.has_fec = true;
			phdr.phy_info.info_11ac.fec = tvb_get_uint8(tvb, offset + 8);

			for (user = 0; user < 4; user++) {
				mcs_nss = tvb_get_uint8(tvb, offset + 4 + user);
				nss = (mcs_nss & IEEE80211_RADIOTAP_VHT_NSS);
				mcs = (mcs_nss & IEEE80211_RADIOTAP_VHT_MCS) >> 4;
				phdr.phy_info.info_11ac.mcs[user] = mcs;
				phdr.phy_info.info_11ac.nss[user] = nss;

				if (nss) {
					/*
					 * OK, there's some data here.
					 * If we haven't already flagged this
					 * as VHT, do so.
					 */
					if (phdr.phy != PHDR_802_11_PHY_11AC) {
						phdr.phy = PHDR_802_11_PHY_11AC;
					}
					if (vht_tree) {
						it = proto_tree_add_item(vht_tree, hf_radiotap_vht_user,
							tvb, offset + 4, 5, ENC_NA);
						proto_item_append_text(it, " %d: MCS %u", user, mcs);
						user_tree = proto_item_add_subtree(it, ett_radiotap_vht_user);

						it = proto_tree_add_item(user_tree, hf_radiotap_vht_mcs[user],
							tvb, offset + 4 + user, 1,
							ENC_LITTLE_ENDIAN);
						if (mcs > MAX_MCS_VHT_INDEX) {
							proto_item_append_text(it, " (invalid)");
						} else {
							proto_item_append_text(it, " (%s %s)",
								ieee80211_vhtinfo[mcs].modulation,
								ieee80211_vhtinfo[mcs].coding_rate);
						}

						proto_tree_add_item(user_tree, hf_radiotap_vht_nss[user],
							tvb, offset + 4 + user, 1, ENC_LITTLE_ENDIAN);
						if (known & IEEE80211_RADIOTAP_VHT_HAVE_STBC) {
							unsigned nsts;
							proto_item *nsts_ti;

							if (vht_flags & IEEE80211_RADIOTAP_VHT_STBC)
								nsts = 2 * nss;
							else
								nsts = nss;
							nsts_ti = proto_tree_add_uint(user_tree, hf_radiotap_vht_nsts[user],
								tvb, offset + 4 + user, 1, nsts);
							proto_item_set_generated(nsts_ti);
						}
						proto_tree_add_item(user_tree, hf_radiotap_vht_coding[user],
							tvb, offset + 8, 1,ENC_LITTLE_ENDIAN);
					}

					if (can_calculate_rate && mcs <= MAX_MCS_VHT_INDEX &&
					    nss <= MAX_VHT_NSS ) {
						float rate = ieee80211_vhtinfo[mcs].rates[bandwidth][gi_length] * nss;
						if (rate != 0.0f ) {
							rate_ti = proto_tree_add_float_format(user_tree,
									hf_radiotap_vht_datarate[user],
									tvb, offset, 12, rate,
									"Data Rate: %.1f Mb/s", rate);
							proto_item_set_generated(rate_ti);
							if (ieee80211_vhtvalid[mcs].valid[bandwidth][nss-1] == false)
								expert_add_info(pinfo, rate_ti, &ei_radiotap_invalid_data_rate);

						}
					}
				}
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_GID) {
				phdr.phy_info.info_11ac.has_group_id = true;
				phdr.phy_info.info_11ac.group_id = tvb_get_uint8(tvb, offset + 9);
				if (vht_tree)
					proto_tree_add_item(vht_tree, hf_radiotap_vht_gid,
							tvb, offset+9, 1, ENC_LITTLE_ENDIAN);
			}

			if (known & IEEE80211_RADIOTAP_VHT_HAVE_PAID) {
				phdr.phy_info.info_11ac.has_partial_aid = true;
				phdr.phy_info.info_11ac.partial_aid = tvb_get_letohs(tvb, offset + 10);
				if (vht_tree) {
					proto_tree_add_item(vht_tree, hf_radiotap_vht_p_aid,
							tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
				}
			}

			break;
		}
		case IEEE80211_RADIOTAP_TIMESTAMP: {
			dissect_radiotap_timestamp(tvb, pinfo, item_tree,
					offset, &phdr);
			break;
		}
		case IEEE80211_RADIOTAP_HE:
			/*
			 * Presumably this is (whatever draft of) 802.11ax.
			 * Also, presumably, you won't get the HE_MU field
			 * without this field.
			 */
			phdr.phy = PHDR_802_11_PHY_11AX;
			dissect_radiotap_he_info(tvb, pinfo, radiotap_tree,
					offset, &phdr.phy_info.info_11ax,
					iter.tlv_mode);
			break;
		case IEEE80211_RADIOTAP_HE_MU:
			dissect_radiotap_he_mu_info(tvb, pinfo, item_tree,
					offset, iter.tlv_mode);
			break;
		case IEEE80211_RADIOTAP_0_LENGTH_PSDU:
			dissect_radiotap_0_length_psdu(tvb, pinfo, item_tree, offset, &phdr);
			zero_length_psdu = true;
			break;
		case IEEE80211_RADIOTAP_L_SIG:
			dissect_radiotap_l_sig(tvb, pinfo, item_tree, offset);
			break;
		case IEEE80211_RADIOTAP_TLVS:
			/* used for padding */
			break;
		case IEEE80211_RADIOTAP_TLV_S1G:
			dissect_radiotap_s1g(tvb, pinfo, item_tree, offset,
					     &phdr, iter.tlv_mode);
			break;
                case IEEE80211_RADIOTAP_TLV_U_SIG:
                        dissect_radiotap_u_sig(tvb, pinfo, item_tree, offset,
                                               &phdr, iter.tlv_mode);
                        break;
		case IEEE80211_RADIOTAP_TLV_EHT:
                        dissect_radiotap_eht(tvb, pinfo, item_tree, offset,
                                             &phdr, iter.tlv_mode);
                        break;
		default:
			if (iter.tlv_mode) {
				proto_tree *unknown_tlv;

				unknown_tlv = proto_tree_add_subtree(tree, tvb,
						offset,
						length + 4,
						ett_radiotap_unknown_tlv,
						NULL, "Unknown TLV");
				proto_tree_add_item(unknown_tlv,
						hf_radiotap_tlv_type, tvb,
						offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;

				proto_tree_add_item(unknown_tlv,
						hf_radiotap_tlv_datalen, tvb,
						offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;

				proto_tree_add_item(unknown_tlv,
						hf_radiotap_unknown_tlv_data,
						tvb, offset, length, ENC_NA);
			} else {
				proto_tree_add_item(item_tree,
						hf_radiotap_unknown_tlv_data,
						tvb, offset,
						iter.this_arg_size, ENC_NA);
			}
			break;
		}
	}

	if (err != -ENOENT) {
		expert_add_info(pinfo, present_item,
		    &ei_radiotap_data_past_header);
 malformed:
		proto_item_append_text(ti, " (malformed)");
	}

	/*
	 * Is there any more there?
	 */
	if (zero_length_psdu) {
		return tvb_captured_length(tvb);
	}

 hand_off_to_80211:
	/*
	 * The comment in the radiotap.org page about the suggested
	 * xchannel field says:
	 *
	 *  As used, this field conflates channel properties (which
	 *  need not be stored per packet but are more or less fixed)
	 *  with packet properties (like the modulation).
	 *
	 * The channel field, in practice, seems to be used, in some
	 * cases, to indicate channel properties (from which the packet
	 * modulation cannot be inferred) and, in other cases, to
	 * indicate the packet's modulation.
	 *
	 * There is even a capture in which the channel field indicates
	 * that the channel is an OFDM channel with a center frequency
	 * of 2452 MHz, and the data rate field indicates a 1 Mb/s rate,
	 * which means you can't rely on the CCK/OFDM/dynamic CCK/OFDM
	 * bits in the channel field to indicate anything. (There are
	 * also captures in which a 1 Mb/s packet has the CCK flag set,
	 * so it clearly doesn't indicate how the packet was transmitted.)
	 *
	 * That makes the channel field unusable either for determining
	 * the channel type or for determining the packet modulation,
	 * as it cannot be determined how it's being used.  The xchannel
	 * field might well be used inconsistently as well.
	 *
	 * Fortunately, there are other ways to determine the packet
	 * modulation:
	 *
	 *  if there's an FHSS flag, the packet was transmitted
	 *  using the 802.11 legacy FHSS modulation;
	 *
	 *  otherwise:
	 *
	 *    if there's an HE field, the packet was transmitted
	 *    using one of the 11ax HE PHY's specified modulations;
	 *
	 *    otherwise, if there's a VHT field, the packet was
	 *    transmitted using one of the 11ac VHT PHY's specified
	 *    modulations;
	 *
	 *    otherwise, if there's an MCS field, the packet was
	 *    transmitted using one of the 11n HT PHY's specified
	 *    modulations;
	 *
	 *    otherwise:
	 *
	 *      if the data rate is 1 Mb/s or 2 Mb/s, the packet was
	 *      transmitted using the 802.11 legacy DSSS modulation
	 *      (we ignore the IR PHY - was it ever implemented?);
	 *
	 *      if the data rate is 5 Mb/s or 11 Mb/s, the packet
	 *      was transmitted using the 802.11b DSSS/CCK modulation
	 *      (or the now-obsolete DSSS/PBCC modulation; *if* we can
	 *      rely on the channel/xchannel field's "CCK channel" and
	 *      "Dynamic CCK-OFDM channel" flags, the absence of either
	 *      flag would presumably indicate DSSS/PBCC);
	 *
	 *      if the data rate is 22 Mb/s or 33 Mb/s, the packet was
	 *      transmitted using the 802.11b DSSS/PBCC modulation (as
	 *      those speeds aren't supported by DSSS/CCK);
	 *
	 *      if the data rate is one of the OFDM rates for the 11a
	 *      OFDM PHY and the OFDM part of the 11g ERP PHY, the
	 *      packet was transmitted with the 11g/11a OFDM modulation.
	 *
	 * We've already handled the HE, VHT, and MCS fields, and may
	 * have attempted to use the channel and xchannel fields to
	 * guess the modulation.  That guess might get the wrong answer
	 * for 11g "Dynamic CCK-OFDM" channels.
	 *
	 * If we have the data rate, we use it to:
	 *
	 *  fix up the 11g channels;
	 *
	 *  determine the modulation if we haven't been able to
	 *  determine it any other way.
	 */
	if (phdr.has_data_rate) {
		if (phdr.phy == PHDR_802_11_PHY_UNKNOWN) {
			/*
			 * We don't know they PHY, but we do have the
			 * data rate; try to guess it based on the
			 * data rate and center frequency.
			 */
			if (RATE_IS_DSSS(phdr.data_rate)) {
				/* 11b */
				phdr.phy = PHDR_802_11_PHY_11B;
			} else if (RATE_IS_OFDM(phdr.data_rate)) {
				/* 11a or 11g, depending on the band. */
				if (phdr.has_frequency) {
					if (FREQ_IS_BG(phdr.frequency)) {
						/* 11g */
						phdr.phy = PHDR_802_11_PHY_11G;
					} else {
						/* 11a */
						phdr.phy = PHDR_802_11_PHY_11A;
					}
				}
			}
		} else if (phdr.phy == PHDR_802_11_PHY_11G) {
			if (RATE_IS_DSSS(phdr.data_rate)) {
				/* DSSS, so 11b. */
				phdr.phy = PHDR_802_11_PHY_11B;
			}
		}
	}

	switch (phdr.phy) {

	case PHDR_802_11_PHY_11B:
		/*
		 * We now know it's 11b, so set the "short preamble"
		 * property.
		 */
		if (have_rflags) {
			phdr.phy_info.info_11b.has_short_preamble = true;
			phdr.phy_info.info_11b.short_preamble =
			    (rflags & IEEE80211_RADIOTAP_F_SHORTPRE) ? true : false;
		} else
			phdr.phy_info.info_11b.has_short_preamble = false;
		break;

	case PHDR_802_11_PHY_11N:
		/*
		 * This doesn't supply "short GI" information,
		 * so use the 0x80 bit in the Flags field,
		 * if we have it; it's "Currently unspecified
		 * but used" for that purpose, according to
		 * the radiotap.org page for that field.
		 */
		if (!phdr.phy_info.info_11n.has_short_gi && have_rflags) {
			phdr.phy_info.info_11n.has_short_gi = true;
			if (rflags & 0x80)
				phdr.phy_info.info_11n.short_gi = 1;
			else
				phdr.phy_info.info_11n.short_gi = 0;
		}
		break;
	}

	/* Grab the rest of the frame. */
	next_tvb = tvb_new_subset_remaining(tvb, length);

	/* If we had an in-header FCS, check it.
	 * This can only happen if the backward-compat configuration option
	 * is chosen by the user. */
	if (hdr_fcs_ti) {
		unsigned captured_length = tvb_captured_length(next_tvb);
		unsigned reported_length = tvb_reported_length(next_tvb);
		unsigned fcs_len = (phdr.fcs_len > 0) ? phdr.fcs_len : 0;

		/* It would be very strange for the header to have an FCS for the
		 * frame *and* the frame to have the FCS at the end, but it's possible, so
		 * take that into account by using the FCS length recorded in pinfo. */

		/* Watch out for [erroneously] short frames */
		if (captured_length >= reported_length &&
		    captured_length > fcs_len) {
			calc_fcs =
			    crc32_802_tvb(next_tvb, tvb_captured_length(next_tvb) - fcs_len);

			/* By virtue of hdr_fcs_ti being set, we know that 'tree' is set,
			 * so there's no need to check it here. */
			if (calc_fcs == sent_fcs) {
				proto_item_append_text(hdr_fcs_ti,
						       " [correct]");
			} else {
				proto_item_append_text(hdr_fcs_ti,
						       " [incorrect, should be 0x%08x]",
						       calc_fcs);
				hidden_item =
				    proto_tree_add_boolean(radiotap_tree,
							   hf_radiotap_fcs_bad,
							   tvb, hdr_fcs_offset,
							   4, true);
				proto_item_set_hidden(hidden_item);
			}
		} else {
			proto_item_append_text(hdr_fcs_ti,
					       " [cannot verify - not enough data]");
		}
	}

	/* dissect the 802.11 packet next */
	call_dissector_with_data(ieee80211_radio_handle, next_tvb, pinfo,
	    tree, &phdr);

	return tvb_captured_length(tvb);
}

void proto_register_radiotap(void)
{

	static hf_register_info hf[] = {
		{&hf_radiotap_version,
		 {"Header revision", "radiotap.version",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Version of radiotap header format", HFILL}},

		{&hf_radiotap_pad,
		 {"Header pad", "radiotap.pad",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Padding", HFILL}},

		{&hf_radiotap_length,
		 {"Header length", "radiotap.length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Length of header including version, pad, length and data fields", HFILL}},

		{&hf_radiotap_present,
		 {"Present flags", "radiotap.present",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  "Bitmask indicating which fields are present", HFILL}},

		{&hf_radiotap_present_word,
		 {"Present flags word", "radiotap.present.word",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Word from present flags bitmask", HFILL}},

		{&hf_radiotap_tlv_type,
		 {"TLV type", "radiotap.tlv.type",
		  FT_UINT32, BASE_DEC|BASE_RANGE_STRING, RVALS(tlv_type_rvals),
		  0x0, NULL, HFILL}},

		{&hf_radiotap_tlv_datalen,
		 {"TLV datalen", "radiotap.tlv.datalen",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_unknown_tlv_data,
		 {"unknown TLV data", "radiotap.tlv.unknown_data",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

#define RADIOTAP_MASK(name)	BIT(IEEE80211_RADIOTAP_ ##name)

		/* Boolean 'present' flags */
		{&hf_radiotap_present_tsft,
		 {"TSFT", "radiotap.present.tsft",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(TSFT),
		  "Specifies if the Time Synchronization Function Timer field is present", HFILL}},

		{&hf_radiotap_present_flags,
		 {"Flags", "radiotap.present.flags",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(FLAGS),
		  "Specifies if the channel flags field is present", HFILL}},

		{&hf_radiotap_present_rate,
		 {"Rate", "radiotap.present.rate",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(RATE),
		  "Specifies if the transmit/receive rate field is present", HFILL}},

		{&hf_radiotap_present_channel,
		 {"Channel", "radiotap.present.channel",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(CHANNEL),
		  "Specifies if the transmit/receive frequency field is present", HFILL}},

		{&hf_radiotap_present_fhss,
		 {"FHSS", "radiotap.present.fhss",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(FHSS),
		  "Specifies if the hop set and pattern is present for frequency hopping radios", HFILL}},

		{&hf_radiotap_present_dbm_antsignal,
		 {"dBm Antenna Signal", "radiotap.present.dbm_antsignal",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(DBM_ANTSIGNAL),
		  "Specifies if the antenna signal strength in dBm is present", HFILL}},

		{&hf_radiotap_present_dbm_antnoise,
		 {"dBm Antenna Noise", "radiotap.present.dbm_antnoise",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(DBM_ANTNOISE),
		  "Specifies if the RF noise power at antenna field is present", HFILL}},

		{&hf_radiotap_present_lock_quality,
		 {"Lock Quality", "radiotap.present.lock_quality",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(LOCK_QUALITY),
		  "Specifies if the signal quality field is present", HFILL}},

		{&hf_radiotap_present_tx_attenuation,
		 {"TX Attenuation", "radiotap.present.tx_attenuation",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(TX_ATTENUATION),
		  "Specifies if the transmit power distance from max power field is present", HFILL}},

		{&hf_radiotap_present_db_tx_attenuation,
		 {"dB TX Attenuation", "radiotap.present.db_tx_attenuation",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(DB_TX_ATTENUATION),
		  "Specifies if the transmit power distance from max power (in dB) field is present", HFILL}},

		{&hf_radiotap_present_dbm_tx_power,
		 {"dBm TX Power", "radiotap.present.dbm_tx_power",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(DBM_TX_POWER),
		  "Specifies if the transmit power (in dBm) field is present", HFILL}},

		{&hf_radiotap_present_antenna,
		 {"Antenna", "radiotap.present.antenna",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(ANTENNA),
		  "Specifies if the antenna number field is present", HFILL}},

		{&hf_radiotap_present_db_antsignal,
		 {"dB Antenna Signal", "radiotap.present.db_antsignal",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(DB_ANTSIGNAL),
		  "Specifies if the RF signal power at antenna in dB field is present", HFILL}},

		{&hf_radiotap_present_db_antnoise,
		 {"dB Antenna Noise", "radiotap.present.db_antnoise",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(DB_ANTNOISE),
		  "Specifies if the RF signal power at antenna in dBm field is present", HFILL}},

		{&hf_radiotap_present_rxflags,
		 {"RX flags", "radiotap.present.rxflags",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(RX_FLAGS),
		  "Specifies if the RX flags field is present", HFILL}},

		{&hf_radiotap_present_txflags,
		 {"TX flags", "radiotap.present.txflags",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(TX_FLAGS),
		  "Specifies if the TX flags field is present", HFILL}},

		{&hf_radiotap_present_hdrfcs,
		 {"FCS in header", "radiotap.present.fcs",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(RX_FLAGS),
		  "Specifies if the FCS field is present", HFILL}},

		{ &hf_radiotap_present_data_retries,
		 {"data retries", "radiotap.present.data_retries",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(DATA_RETRIES),
		  "Specifies if the data retries field is present", HFILL}},

		{&hf_radiotap_present_xchannel,
		 {"Channel+", "radiotap.present.xchannel",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(XCHANNEL),
		  "Specifies if the extended channel info field is present", HFILL}},

		{&hf_radiotap_present_mcs,
		 {"MCS information", "radiotap.present.mcs",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(MCS),
		  "Specifies if the MCS field is present", HFILL}},

		{&hf_radiotap_present_ampdu,
		 {"A-MPDU Status", "radiotap.present.ampdu",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(AMPDU_STATUS),
		  "Specifies if the A-MPDU status field is present", HFILL}},

		{&hf_radiotap_present_vht,
		 {"VHT information", "radiotap.present.vht",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(VHT),
		  "Specifies if the VHT field is present", HFILL}},

		{&hf_radiotap_present_timestamp,
		 {"frame timestamp", "radiotap.present.timestamp",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(TIMESTAMP),
		  "Specifies if the timestamp field is present", HFILL}},

		{&hf_radiotap_present_he,
		 {"HE information", "radiotap.present.he",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(HE),
		  "Specifies if the HE field is present", HFILL}},

		{&hf_radiotap_present_he_mu,
		 {"HE-MU information", "radiotap.present.he_mu",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(HE_MU),
		  "Specifies if the HE field is present", HFILL}},

		{&hf_radiotap_present_0_length_psdu,
		 {"0 Length PSDU", "radiotap.present.0_length.psdu",
		   FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(0_LENGTH_PSDU),
		   "Specifies whether or not the 0-Length PSDU field is present", HFILL}},

		{&hf_radiotap_present_l_sig,
		 {"L-SIG", "radiotap.present.l_sig",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(L_SIG),
		  "Specifies whether or not the L-SIG field is present", HFILL}},

		{&hf_radiotap_present_tlv,
		 {"TLVs", "radiotap.present.tlv",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(TLVS),
		  "Specifies switch to TLV fields", HFILL}},

		{&hf_radiotap_present_reserved,
		 {"Reserved", "radiotap.present.reserved",
		  FT_UINT32, BASE_HEX, NULL, IEEE80211_RADIOTAP_NOTDEFINED,
		  "Not (yet) defined present flags (Must be zero)", HFILL}},

		{&hf_radiotap_present_rtap_ns,
		 {"Radiotap NS next", "radiotap.present.rtap_ns",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(RADIOTAP_NAMESPACE),
		  "Specifies a reset to the radiotap namespace", HFILL}},

		{&hf_radiotap_present_vendor_ns,
		 {"Vendor NS next", "radiotap.present.vendor_ns",
		  FT_BOOLEAN, 32, NULL, RADIOTAP_MASK(VENDOR_NAMESPACE),
		  "Specifies that the next bitmap is in a vendor namespace", HFILL}},

		{&hf_radiotap_present_ext,
		 {"Ext", "radiotap.present.ext",
		  FT_BOOLEAN, 32, TFS(&tfs_present_absent), RADIOTAP_MASK(EXT),
		  "Specifies if there are any extensions to the header present", HFILL}},

		/* Boolean 'present.flags' flags */
		{&hf_radiotap_flags,
		 {"Flags", "radiotap.flags",
		  FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{&hf_radiotap_flags_cfp,
		 {"CFP", "radiotap.flags.cfp",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_CFP,
		  "Sent/Received during CFP", HFILL}},

		{&hf_radiotap_flags_preamble,
		 {"Preamble", "radiotap.flags.preamble",
		  FT_BOOLEAN, 8, TFS(&preamble_type),
		  IEEE80211_RADIOTAP_F_SHORTPRE,
		  "Sent/Received with short preamble", HFILL}},

		{&hf_radiotap_flags_wep,
		 {"WEP", "radiotap.flags.wep",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_WEP,
		  "Sent/Received with WEP encryption", HFILL}},

		{&hf_radiotap_flags_frag,
		 {"Fragmentation", "radiotap.flags.frag",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_FRAG,
		  "Sent/Received with fragmentation", HFILL}},

		{&hf_radiotap_flags_fcs,
		 {"FCS at end", "radiotap.flags.fcs",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_FCS,
		  "Frame includes FCS at end", HFILL}},

		{&hf_radiotap_flags_datapad,
		 {"Data Pad", "radiotap.flags.datapad",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_DATAPAD,
		  "Frame has padding between 802.11 header and payload", HFILL}},

		{&hf_radiotap_flags_badfcs,
		 {"Bad FCS", "radiotap.flags.badfcs",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_BADFCS,
		  "Frame received with bad FCS", HFILL}},

		{&hf_radiotap_flags_shortgi,
		 {"Short GI", "radiotap.flags.shortgi",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_F_SHORTGI,
		  "Frame Sent/Received with HT short Guard Interval", HFILL}},

		{&hf_radiotap_mactime,
		 {"MAC timestamp", "radiotap.mactime",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Value in microseconds of the MAC's Time Synchronization Function timer"
		  " when the first bit of the MPDU arrived at the MAC.",
		  HFILL}},

		{&hf_radiotap_quality,
		 {"Signal Quality", "radiotap.quality",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Signal quality (unitless measure)", HFILL}},

		{&hf_radiotap_fcs,
		 {"802.11 FCS", "radiotap.fcs",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Frame check sequence of this frame", HFILL}},

#if 0
		{&hf_radiotap_channel,
		 {"Channel", "radiotap.channel",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "802.11 channel number that this frame was sent/received on", HFILL}},
#endif

		{&hf_radiotap_channel_frequency,
		 {"Channel frequency", "radiotap.channel.freq",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Channel frequency in megahertz that this frame was sent/received on", HFILL}},

		{&hf_radiotap_channel_flags,
		 {"Channel flags", "radiotap.channel.flags",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_channel_flags_turbo,
		 {"Turbo", "radiotap.channel.flags.turbo",
		  FT_BOOLEAN, 16, NULL, 0x0010, "Channel Flags Turbo", HFILL}},

		{&hf_radiotap_channel_flags_700mhz,
		 {"700 MHz spectrum", "radiotap.channel.flags.700mhz",
		  FT_BOOLEAN, 16, NULL, 0x0001, "Channel Flags Turbo", HFILL}},

		{&hf_radiotap_channel_flags_800mhz,
		 {"800 MHz spectrum", "radiotap.channel.flags.800mhz",
		  FT_BOOLEAN, 16, NULL, 0x0002, "Channel Flags Turbo", HFILL}},

		{&hf_radiotap_channel_flags_900mhz,
		 {"900 MHz spectrum", "radiotap.channel.flags.900mhz",
		  FT_BOOLEAN, 16, NULL, 0x0004, "Channel Flags Turbo", HFILL}},

		{&hf_radiotap_channel_flags_cck,
		 {"Complementary Code Keying (CCK)", "radiotap.channel.flags.cck",
		  FT_BOOLEAN, 16, NULL, 0x0020,
		  "Channel Flags Complementary Code Keying (CCK) Modulation", HFILL}},

		{&hf_radiotap_channel_flags_ofdm,
		 {"Orthogonal Frequency-Division Multiplexing (OFDM)", "radiotap.channel.flags.ofdm",
		  FT_BOOLEAN, 16, NULL, 0x0040,
		  "Channel Flags Orthogonal Frequency-Division Multiplexing (OFDM)", HFILL}},

		{&hf_radiotap_channel_flags_2ghz,
		 {"2 GHz spectrum", "radiotap.channel.flags.2ghz",
		  FT_BOOLEAN, 16, NULL, 0x0080, "Channel Flags 2 GHz spectrum", HFILL}},

		{&hf_radiotap_channel_flags_5ghz,
		 {"5 GHz spectrum", "radiotap.channel.flags.5ghz",
		  FT_BOOLEAN, 16, NULL, 0x0100, "Channel Flags 5 GHz spectrum", HFILL}},

		{&hf_radiotap_channel_flags_passive,
		 {"Passive", "radiotap.channel.flags.passive",
		  FT_BOOLEAN, 16, NULL, 0x0200,
		  "Channel Flags Passive", HFILL}},

		{&hf_radiotap_channel_flags_dynamic,
		 {"Dynamic CCK-OFDM", "radiotap.channel.flags.dynamic",
		  FT_BOOLEAN, 16, NULL, 0x0400,
		  "Channel Flags Dynamic CCK-OFDM Channel", HFILL}},

		{&hf_radiotap_channel_flags_gfsk,
		 {"Gaussian Frequency Shift Keying (GFSK)", "radiotap.channel.flags.gfsk",
		  FT_BOOLEAN, 16, NULL, 0x0800,
		  "Channel Flags Gaussian Frequency Shift Keying (GFSK) Modulation", HFILL}},

		{&hf_radiotap_channel_flags_gsm,
		 {"GSM (900MHz)", "radiotap.channel.flags.gsm",
		  FT_BOOLEAN, 16, NULL, 0x1000,
		  "Channel Flags GSM", HFILL}},

		{&hf_radiotap_channel_flags_sturbo,
		 {"Static Turbo", "radiotap.channel.flags.sturbo",
		  FT_BOOLEAN, 16, NULL, 0x2000,
		  "Channel Flags Status Turbo", HFILL}},

		{&hf_radiotap_channel_flags_half,
		 {"Half Rate Channel (10MHz Channel Width)", "radiotap.channel.flags.half",
		  FT_BOOLEAN, 16, NULL, 0x4000,
		  "Channel Flags Half Rate", HFILL}},

		{&hf_radiotap_channel_flags_quarter,
		 {"Quarter Rate Channel (5MHz Channel Width)", "radiotap.channel.flags.quarter",
		  FT_BOOLEAN, 16, NULL, 0x8000,
		  "Channel Flags Quarter Rate", HFILL}},

		{&hf_radiotap_rxflags,
		 {"RX flags", "radiotap.rxflags",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_rxflags_badplcp,
		 {"Bad PLCP", "radiotap.rxflags.badplcp",
		  FT_BOOLEAN, 24, NULL, IEEE80211_RADIOTAP_F_RX_BADPLCP,
		  "Frame with bad PLCP", HFILL}},

		{&hf_radiotap_txflags,
		 {"TX flags", "radiotap.txflags",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_txflags_fail,
		 {"Fail", "radiotap.rxflags.fail",
		  FT_BOOLEAN, 24, NULL, IEEE80211_RADIOTAP_F_TX_FAIL,
		  "Transmission failed due to excessive retries", HFILL}},

		{&hf_radiotap_txflags_cts,
		 {"CTS", "radiotap.rxflags.cts",
		  FT_BOOLEAN, 24, NULL, IEEE80211_RADIOTAP_F_TX_CTS,
		  "Transmission used CTS-to-self protection", HFILL}},

		{&hf_radiotap_txflags_rts,
		 {"RTS/CTS", "radiotap.rxflags.rts",
		  FT_BOOLEAN, 24, NULL, IEEE80211_RADIOTAP_F_TX_RTS,
		  "Transmission used RTS/CTS handshake", HFILL}},

		{&hf_radiotap_txflags_noack,
		 {"No ACK", "radiotap.rxflags.noack",
		  FT_BOOLEAN, 24, NULL, IEEE80211_RADIOTAP_F_TX_NOACK,
		  "Transmission shall not expect an ACK frame", HFILL}},

		{&hf_radiotap_txflags_noseqno,
		 {"Has Seqnum", "radiotap.rxflags.noseqno",
		  FT_BOOLEAN, 24, NULL, IEEE80211_RADIOTAP_F_TX_NOSEQNO,
		  "Frame includes a pre-configured sequence number", HFILL}},

		{&hf_radiotap_txflags_order,
		 {"Order", "radiotap.rxflags.order",
		  FT_BOOLEAN, 24, NULL, IEEE80211_RADIOTAP_F_TX_ORDER,
		  "Frame must not be reordered relative to others with this flag", HFILL}},

		{&hf_radiotap_xchannel_channel,
		 {"Channel number", "radiotap.xchannel.channel",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_xchannel_frequency,
		 {"Channel frequency", "radiotap.xchannel.freq",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_xchannel_flags,
		 {"Channel flags", "radiotap.xchannel.flags",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_xchannel_flags_turbo,
		 {"Turbo", "radiotap.xchannel.flags.turbo",
		  FT_BOOLEAN, 24, NULL, 0x000010,
		  "Channel Flags Turbo", HFILL}},

		{&hf_radiotap_xchannel_flags_cck,
		 {"Complementary Code Keying (CCK)", "radiotap.xchannel.flags.cck",
		  FT_BOOLEAN, 24, NULL, 0x000020,
		  "Channel Flags Complementary Code Keying (CCK) Modulation", HFILL}},

		{&hf_radiotap_xchannel_flags_ofdm,
		 {"Orthogonal Frequency-Division Multiplexing (OFDM)", "radiotap.xchannel.flags.ofdm",
		  FT_BOOLEAN, 24, NULL, 0x000040,
		  "Channel Flags Orthogonal Frequency-Division Multiplexing (OFDM)", HFILL}},

		{&hf_radiotap_xchannel_flags_2ghz,
		 {"2 GHz spectrum", "radiotap.xchannel.flags.2ghz",
		  FT_BOOLEAN, 24, NULL, 0x000080,
		  "Channel Flags 2 GHz spectrum", HFILL}},

		{&hf_radiotap_xchannel_flags_5ghz,
		 {"5 GHz spectrum", "radiotap.xchannel.flags.5ghz",
		  FT_BOOLEAN, 24, NULL, 0x000100,
		  "Channel Flags 5 GHz spectrum", HFILL}},

		{&hf_radiotap_xchannel_flags_passive,
		 {"Passive", "radiotap.channel.xtype.passive",
		  FT_BOOLEAN, 24, NULL, 0x000200,
		  "Channel Flags Passive", HFILL}},

		{&hf_radiotap_xchannel_flags_dynamic,
		 {"Dynamic CCK-OFDM", "radiotap.xchannel.flags.dynamic",
		  FT_BOOLEAN, 24, NULL, 0x000400,
		  "Channel Flags Dynamic CCK-OFDM Channel", HFILL}},

		{&hf_radiotap_xchannel_flags_gfsk,
		 {"Gaussian Frequency Shift Keying (GFSK)",
		  "radiotap.xchannel.flags.gfsk",
		  FT_BOOLEAN, 24, NULL, 0x000800,
		  "Channel Flags Gaussian Frequency Shift Keying (GFSK) Modulation",
		  HFILL}},

		{&hf_radiotap_xchannel_flags_gsm,
		 {"GSM (900MHz)", "radiotap.xchannel.flags.gsm",
		  FT_BOOLEAN, 24, NULL, 0x001000,
		  "Channel Flags GSM", HFILL}},

		{&hf_radiotap_xchannel_flags_sturbo,
		 {"Static Turbo", "radiotap.xchannel.flags.sturbo",
		  FT_BOOLEAN, 24, NULL, 0x002000,
		  "Channel Flags Status Turbo", HFILL}},

		{&hf_radiotap_xchannel_flags_half,
		 {"Half Rate Channel (10MHz Channel Width)", "radiotap.xchannel.flags.half",
		  FT_BOOLEAN, 24, NULL, 0x004000,
		  "Channel Flags Half Rate", HFILL}},

		{&hf_radiotap_xchannel_flags_quarter,
		 {"Quarter Rate Channel (5MHz Channel Width)", "radiotap.xchannel.flags.quarter",
		  FT_BOOLEAN, 24, NULL, 0x008000,
		  "Channel Flags Quarter Rate", HFILL}},

		{&hf_radiotap_xchannel_flags_ht20,
		 {"HT Channel (20MHz Channel Width)", "radiotap.xchannel.flags.ht20",
		  FT_BOOLEAN, 24, NULL, 0x010000,
		  "Channel Flags HT/20", HFILL}},

		{&hf_radiotap_xchannel_flags_ht40u,
		 {"HT Channel (40MHz Channel Width with Extension channel above)", "radiotap.xchannel.flags.ht40u",
		  FT_BOOLEAN, 24, NULL, 0x020000,
		  "Channel Flags HT/40+", HFILL}},

		{&hf_radiotap_xchannel_flags_ht40d,
		 {"HT Channel (40MHz Channel Width with Extension channel below)", "radiotap.xchannel.flags.ht40d",
		  FT_BOOLEAN, 24, NULL, 0x040000,
		  "Channel Flags HT/40-", HFILL}},
#if 0
		{&hf_radiotap_xchannel_maxpower,
		 {"Max transmit power", "radiotap.xchannel.maxpower",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
#endif
		{&hf_radiotap_fhss_hopset,
		 {"FHSS Hop Set", "radiotap.fhss.hopset",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Frequency Hopping Spread Spectrum hopset", HFILL}},

		{&hf_radiotap_fhss_pattern,
		 {"FHSS Pattern", "radiotap.fhss.pattern",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Frequency Hopping Spread Spectrum hop pattern", HFILL}},

		{&hf_radiotap_datarate,
		 {"Data rate (Mb/s)", "radiotap.datarate",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  "Speed this frame was sent/received at", HFILL}},

		{&hf_radiotap_antenna,
		 {"Antenna", "radiotap.antenna",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Antenna number this frame was sent/received over (starting at 0)", HFILL}},

		{&hf_radiotap_dbm_antsignal,
		 {"Antenna signal", "radiotap.dbm_antsignal",
		  FT_INT8, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0x0,
		  "RF signal power at the antenna expressed as decibels"
		  " from one milliwatt", HFILL}},

		{&hf_radiotap_db_antsignal,
		 {"dB antenna signal", "radiotap.db_antsignal",
		  FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0x0,
		  "RF signal power at the antenna expressed as decibels"
		  " from a fixed, arbitrary value", HFILL}},

		{&hf_radiotap_dbm_antnoise,
		 {"Antenna noise", "radiotap.dbm_antnoise",
		  FT_INT8, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0x0,
		  "RF noise power at the antenna expressed as decibels"
		  " from one milliwatt", HFILL}},

		{&hf_radiotap_db_antnoise,
		 {"dB antenna noise", "radiotap.db_antnoise",
		  FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0x0,
		  "RF noise power at the antenna expressed as decibels"
		  " from a fixed, arbitrary value", HFILL}},

		{&hf_radiotap_tx_attenuation,
		 {"TX attenuation", "radiotap.txattenuation",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Transmit power expressed as unitless distance from max power"
		  " set at factory calibration (0 is max power)", HFILL}},

		{&hf_radiotap_db_tx_attenuation,
		 {"dB TX attenuation", "radiotap.db_txattenuation",
		  FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0x0,
		  "Transmit power expressed as decibels from max power"
		  " set at factory calibration (0 is max power)", HFILL}},

		{&hf_radiotap_txpower,
		 {"Transmit power", "radiotap.txpower",
		  FT_INT8, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0x0,
		  "Transmit power at the antenna port expressed as decibels"
		  " from one milliwatt", HFILL}},

		{ &hf_radiotap_data_retries,
		 {"data retries", "radiotap.data_retries",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Number of data retries a transmitted frame used", HFILL} },

		{&hf_radiotap_mcs,
		 {"MCS information", "radiotap.mcs",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_mcs_known,
		 {"Known MCS information", "radiotap.mcs.known",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Bit mask indicating what MCS information is present", HFILL}},

		{&hf_radiotap_mcs_have_bw,
		 {"Bandwidth", "radiotap.mcs.have_bw",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_BW,
		  "Bandwidth information present", HFILL}},

		{&hf_radiotap_mcs_have_index,
		 {"MCS index", "radiotap.mcs.have_index",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_MCS,
		  "MCS index information present", HFILL}},

		{&hf_radiotap_mcs_have_gi,
		 {"Guard interval", "radiotap.mcs.have_gi",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_GI,
		  "Sent/Received guard interval information present", HFILL}},

		{&hf_radiotap_mcs_have_format,
		 {"Format", "radiotap.mcs.have_format",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_FMT,
		  "Format information present", HFILL}},

		{&hf_radiotap_mcs_have_fec,
		 {"FEC type", "radiotap.mcs.have_fec",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_FEC,
		  "Forward error correction type information present", HFILL}},

		{&hf_radiotap_mcs_have_stbc,
		 {"STBC streams", "radiotap.mcs.have_stbc",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_STBC,
		  "Space Time Block Coding streams information present", HFILL}},

		{&hf_radiotap_mcs_have_ness,
		 {"Number of extension spatial streams", "radiotap.mcs.have_ness",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_MCS_HAVE_NESS,
		  "Number of extension spatial streams information present", HFILL}},

		{&hf_radiotap_mcs_ness_bit1,
		 {"Number of extension spatial streams bit 1", "radiotap.mcs.ness_bit1",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_MCS_NESS_BIT1,
		  "Bit 1 of number of extension spatial streams information", HFILL}},

		{&hf_radiotap_mcs_bw,
		 {"Bandwidth", "radiotap.mcs.bw",
		  FT_UINT8, BASE_DEC, VALS(mcs_bandwidth),
		  IEEE80211_RADIOTAP_MCS_BW_MASK, NULL, HFILL}},

		{&hf_radiotap_mcs_gi,
		 {"Guard interval", "radiotap.mcs.gi",
		  FT_UINT8, BASE_DEC, VALS(mcs_gi), IEEE80211_RADIOTAP_MCS_SGI,
		  "Sent/Received guard interval", HFILL}},

		{&hf_radiotap_mcs_format,
		 {"Format", "radiotap.mcs.format",
		  FT_UINT8, BASE_DEC, VALS(mcs_format), IEEE80211_RADIOTAP_MCS_FMT_GF,
		  NULL, HFILL}},

		{&hf_radiotap_mcs_fec,
		 {"FEC type", "radiotap.mcs.fec",
		  FT_UINT8, BASE_DEC, VALS(mcs_fec), IEEE80211_RADIOTAP_MCS_FEC_LDPC,
		  "Forward error correction type", HFILL}},

		{&hf_radiotap_mcs_stbc,
		 {"STBC streams", "radiotap.mcs.stbc",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_MCS_STBC_MASK,
		  "Number of Space Time Block Code streams", HFILL}},

		{&hf_radiotap_mcs_ness_bit0,
		 {"Number of extension spatial streams bit 0", "radiotap.mcs.ness_bit0",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_MCS_NESS_BIT0,
		  "Bit 0 of number of extension spatial streams information", HFILL}},

		{&hf_radiotap_mcs_index,
		 {"MCS index", "radiotap.mcs.index",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu,
		 {"A-MPDU status", "radiotap.ampdu",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_ref,
		 {"A-MPDU reference number", "radiotap.ampdu.reference",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_flags,
		 {"A-MPDU flags", "radiotap.ampdu.flags",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "A-MPDU status flags", HFILL}},

		{&hf_radiotap_ampdu_flags_report_zerolen,
		 {"Driver reports 0-length subframes in this A-MPDU", "radiotap.ampdu.flags.report_zerolen",
		  FT_BOOLEAN, 16, NULL, IEEE80211_RADIOTAP_AMPDU_REPORT_ZEROLEN,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_flags_is_zerolen,
		 {"This is a 0-length subframe", "radiotap.ampdu.flags.is_zerolen",
		  FT_BOOLEAN, 16, NULL, IEEE80211_RADIOTAP_AMPDU_IS_ZEROLEN,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_flags_last_known,
		 {"Last subframe of this A-MPDU is known", "radiotap.ampdu.flags.lastknown",
		  FT_BOOLEAN, 16, NULL, IEEE80211_RADIOTAP_AMPDU_LAST_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_flags_is_last,
		 {"This is the last subframe of this A-MPDU", "radiotap.ampdu.flags.last",
		  FT_BOOLEAN, 16, NULL, IEEE80211_RADIOTAP_AMPDU_IS_LAST,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_flags_delim_crc_error,
		 {"Delimiter CRC error on this subframe", "radiotap.ampdu.flags.delim_crc_error",
		  FT_BOOLEAN, 16, NULL, IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_ERR,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_flags_eof,
		 {"EOF on this subframe", "radiotap.ampdu.flags.eof",
		  FT_BOOLEAN, 16, NULL, IEEE80211_RADIOTAP_AMPDU_EOF,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_flags_eof_known,
		 {"EOF of this A-MPDU is known", "radiotap.ampdu.flags.eof_known",
		  FT_BOOLEAN, 16, NULL, IEEE80211_RADIOTAP_AMPDU_EOF_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_ampdu_delim_crc,
		 {"A-MPDU subframe delimiter CRC", "radiotap.ampdu.delim_crc",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_vht,
		 {"VHT information", "radiotap.vht",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_vht_known,
		 {"Known VHT information", "radiotap.vht.known",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Bit mask indicating what VHT information is present", HFILL}},

		{&hf_radiotap_vht_user,
		 {"User", "radiotap.vht.user",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_vht_have_stbc,
		 {"STBC", "radiotap.vht.have_stbc",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_STBC,
		  "Space Time Block Coding information present", HFILL}},

		{&hf_radiotap_vht_have_txop_ps,
		 {"TXOP_PS_NOT_ALLOWED", "radiotap.vht.have_txop_ps",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_TXOP_PS,
		  "TXOP_PS_NOT_ALLOWED information present", HFILL}},

		{&hf_radiotap_vht_have_gi,
		 {"Guard interval", "radiotap.vht.have_gi",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_GI,
		  "Short/Long guard interval information present", HFILL}},

		{&hf_radiotap_vht_have_sgi_nsym_da,
		 {"SGI Nsym disambiguation", "radiotap.vht.have_sgi_nsym_da",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_SGI_NSYM_DA,
		  "Short guard interval Nsym disambiguation information present", HFILL}},

		{&hf_radiotap_vht_have_ldpc_extra,
		 {"LDPC extra OFDM symbol", "radiotap.vht.ldpc_extra",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_LDPC_EXTRA,
		  NULL, HFILL}},

		{&hf_radiotap_vht_have_bf,
		 {"Beamformed", "radiotap.vht.have_beamformed",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_BF,
		  NULL, HFILL}},

		{&hf_radiotap_vht_have_bw,
		 {"Bandwidth", "radiotap.mcs.have_bw",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_BW,
		  NULL, HFILL}},

		{&hf_radiotap_vht_have_gid,
		 {"Group ID", "radiotap.mcs.have_gid",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_GID,
		  NULL, HFILL}},

		{&hf_radiotap_vht_have_p_aid,
		 {"Partial AID", "radiotap.mcs.have_paid",
		  FT_BOOLEAN, 16, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_VHT_HAVE_PAID,
		  NULL, HFILL}},

		{&hf_radiotap_vht_stbc,
		 {"STBC", "radiotap.vht.stbc",
		  FT_BOOLEAN, 8, TFS(&tfs_on_off), IEEE80211_RADIOTAP_VHT_STBC,
		  "Space Time Block Coding flag", HFILL}},

		{&hf_radiotap_vht_txop_ps,
		 {"TXOP_PS_NOT_ALLOWED", "radiotap.vht.txop_ps",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_VHT_TXOP_PS,
		  "Flag indicating whether STAs may doze during TXOP", HFILL}},

		{&hf_radiotap_vht_gi,
		 {"Guard interval", "radiotap.vht.gi",
		  FT_UINT8, BASE_DEC, VALS(mcs_gi), IEEE80211_RADIOTAP_VHT_SGI,
		  "Short/Long guard interval", HFILL}},

		{&hf_radiotap_vht_sgi_nsym_da,
		 {"SGI Nsym disambiguation", "radiotap.vht.sgi_nsym_da",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_VHT_SGI_NSYM_DA,
		  "Short Guard Interval Nsym disambiguation", HFILL}},

		{&hf_radiotap_vht_ldpc_extra,
		 {"LDPC extra OFDM symbol", "radiotap.vht.ldpc_extra",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_VHT_LDPC_EXTRA,
		  NULL, HFILL}},

		{&hf_radiotap_vht_bf,
		 {"Beamformed", "radiotap.vht.beamformed",
		  FT_BOOLEAN, 8, NULL, IEEE80211_RADIOTAP_VHT_BF,
		  NULL, HFILL}},

		{&hf_radiotap_vht_bw,
		 {"Bandwidth", "radiotap.vht.bw",
		  FT_UINT8, BASE_DEC | BASE_EXT_STRING, &vht_bandwidth_ext, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_vht_nsts[0],
		 {"Space-time streams 0", "radiotap.vht.nsts.0",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Number of Space-time streams", HFILL}},

		{&hf_radiotap_vht_nsts[1],
		 {"Space-time streams 1", "radiotap.vht.nsts.1",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Number of Space-time streams", HFILL}},

		{&hf_radiotap_vht_nsts[2],
		 {"Space-time streams 2", "radiotap.vht.nsts.2",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Number of Space-time streams", HFILL}},

		{&hf_radiotap_vht_nsts[3],
		 {"Space-time streams 3", "radiotap.vht.nsts.3",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Number of Space-time streams", HFILL}},

		{&hf_radiotap_vht_mcs[0],
		 {"MCS index 0", "radiotap.vht.mcs.0",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_MCS,
		  "MCS index", HFILL}},

		{&hf_radiotap_vht_mcs[1],
		 {"MCS index 1", "radiotap.vht.mcs.1",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_MCS,
		  "MCS index", HFILL}},

		{&hf_radiotap_vht_mcs[2],
		 {"MCS index 2", "radiotap.vht.mcs.2",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_MCS,
		  "MCS index", HFILL}},

		{&hf_radiotap_vht_mcs[3],
		 {"MCS index 3", "radiotap.vht.mcs.3",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_MCS,
		  "MCS index", HFILL}},

		{&hf_radiotap_vht_nss[0],
		 {"Spatial streams 0", "radiotap.vht.nss.0",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_NSS,
		  "Number of spatial streams", HFILL}},

		{&hf_radiotap_vht_nss[1],
		 {"Spatial streams 1", "radiotap.vht.nss.1",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_NSS,
		  "Number of spatial streams", HFILL}},

		{&hf_radiotap_vht_nss[2],
		 {"Spatial streams 2", "radiotap.vht.nss.2",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_NSS,
		  "Number of spatial streams", HFILL}},

		{&hf_radiotap_vht_nss[3],
		 {"Spatial streams 3", "radiotap.vht.nss.3",
		  FT_UINT8, BASE_DEC, NULL, IEEE80211_RADIOTAP_VHT_NSS,
		  "Number of spatial streams", HFILL}},

		{&hf_radiotap_vht_coding[0],
		 {"Coding 0", "radiotap.vht.coding.0",
		  FT_UINT8, BASE_DEC, VALS(mcs_fec), 0x01,
		  "Coding", HFILL}},

		{&hf_radiotap_vht_coding[1],
		 {"Coding 1", "radiotap.vht.coding.1",
		  FT_UINT8, BASE_DEC, VALS(mcs_fec), 0x02,
		  "Coding", HFILL}},

		{&hf_radiotap_vht_coding[2],
		 {"Coding 2", "radiotap.vht.coding.2",
		  FT_UINT8, BASE_DEC, VALS(mcs_fec), 0x04,
		  "Coding", HFILL}},

		{&hf_radiotap_vht_coding[3],
		 {"Coding 3", "radiotap.vht.coding.3",
		  FT_UINT8, BASE_DEC, VALS(mcs_fec), 0x08,
		  "Coding", HFILL}},

		{&hf_radiotap_vht_datarate[0],
		 {"Data rate (Mb/s) 0", "radiotap.vht.datarate.0",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  "Speed this frame was sent/received at", HFILL}},

		{&hf_radiotap_vht_datarate[1],
		 {"Data rate (Mb/s) 1", "radiotap.vht.datarate.1",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  "Speed this frame was sent/received at", HFILL}},

		{&hf_radiotap_vht_datarate[2],
		 {"Data rate (Mb/s) 2", "radiotap.vht.datarate.2",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  "Speed this frame was sent/received at", HFILL}},

		{&hf_radiotap_vht_datarate[3],
		 {"Data rate (Mb/s) 3", "radiotap.vht.datarate.3",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  "Speed this frame was sent/received at", HFILL}},

		{&hf_radiotap_vht_gid,
		 {"Group Id", "radiotap.vht.gid",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_vht_p_aid,
		 {"Partial AID", "radiotap.vht.paid",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_timestamp,
		 {"timestamp information", "radiotap.timestamp",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_timestamp_ts,
		 {"timestamp", "radiotap.timestamp.ts",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_timestamp_accuracy,
		 {"accuracy", "radiotap.timestamp.accuracy",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_timestamp_unit,
		 {"time unit", "radiotap.timestamp.unit",
		  FT_UINT8, BASE_DEC, VALS(timestamp_unit),
		  IEEE80211_RADIOTAP_TS_UNIT_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_timestamp_spos,
		 {"sampling position", "radiotap.timestamp.samplingpos",
		  FT_UINT8, BASE_DEC, VALS(timestamp_spos),
		  IEEE80211_RADIOTAP_TS_SPOS_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_timestamp_flags_32bit,
		 {"32-bit counter", "radiotap.timestamp.flags.32bit",
		  FT_BOOLEAN, 8, TFS(&tfs_yes_no), IEEE80211_RADIOTAP_TS_FLG_32BIT,
		  NULL, HFILL}},

		{&hf_radiotap_timestamp_flags_accuracy,
		 {"accuracy field", "radiotap.timestamp.flags.accuracy",
		  FT_BOOLEAN, 8, TFS(&tfs_present_absent), IEEE80211_RADIOTAP_TS_FLG_ACCURACY,
		  NULL, HFILL}},

		{&hf_radiotap_vendor_ns,
		 {"Vendor namespace", "radiotap.vendor_namespace",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_ven_oui,
		 {"Vendor OUI", "radiotap.vendor_oui",
		  FT_UINT24, BASE_OUI, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_radiotap_ven_subns,
		 {"Vendor sub namespace", "radiotap.vendor_subns",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Vendor-specified sub namespace", HFILL}},

		{&hf_radiotap_ven_skip,
		 {"Vendor data length", "radiotap.vendor_data_len",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Length of vendor-specified data", HFILL}},

		{&hf_radiotap_ven_item,
		 {"Vendor data item type", "radiotap.vendor_data_item_type",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Item type of vendor-specific data", HFILL}},

		{&hf_radiotap_ven_data,
		 {"Vendor data", "radiotap.vendor_data",
		  FT_NONE, BASE_NONE, NULL, 0x0,
		  "Vendor-specified data", HFILL}},

		/* Special variables */
		{&hf_radiotap_fcs_bad,
		 {"Bad FCS", "radiotap.fcs_bad",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		  "Specifies if this frame has a bad frame check sequence", HFILL}},

		{&hf_radiotap_he_info_data_1,
		 {"HE Data 1", "radiotap.he.data_1",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Data 1 of the HE Info field", HFILL}},

		{&hf_radiotap_he_ppdu_format,
		 {"PPDU Format", "radiotap.he.data_1.ppdu_format",
		  FT_UINT16, BASE_HEX, VALS(he_pdu_format_vals),
		  IEEE80211_RADIOTAP_HE_PPDU_FORMAT_MASK, NULL, HFILL}},

		{&hf_radiotap_he_bss_color_known,
		 {"BSS Color known", "radiotap.he.data_1.bss_color_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_BSS_COLOR_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_beam_change_known,
		 {"Beam Change known", "radiotap.he.data_1.beam_change_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_BEAM_CHANGE_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_ul_dl_known,
		 {"UL/DL known", "radiotap.he.data_1.ul_dl_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_UL_DL_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_data_mcs_known,
		 {"data MCS known", "radiotap.he.data_1.data_mcs_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_DATA_MCS_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_data_dcm_known,
		 {"data DCM known", "radiotap.he.data_1.data_dcm_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_DATA_DCM_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_coding_known,
		 {"Coding known", "radiotap.he.data_1.coding_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_CODING_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_ldpc_extra_symbol_segment_known,
		 {"LDPC extra symbol segment known", "radiotap.he.data_1.ldpc_extra_symbol_segment_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_LDPC_EXTRA_SYMBOL_SEGMENT_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_stbc_known,
		 {"STBC known", "radiotap.he.data_1.stbc_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_STBC_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_spatial_reuse_1_known,
		 {"Spatial Reuse 1 known", "radiotap.he.data_1.spatial_reuse_1_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_spatial_reuse_2_known,
		 {"Spatial Reuse 2 known", "radiotap.he.data_1.spatial_reuse_2_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_2_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_spatial_reuse_3_known,
		 {"Spatial Reuse 3 known", "radiotap.he.data_1.spatial_reuse_3_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_3_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_spatial_reuse_4_known,
		 {"Spatial Reuse 4 known", "radiotap.he.data_1.spatial_reuse_4_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_4_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_data_bw_ru_allocation_known,
		 {"data BW/RU allocation known", "radiotap.he.data_1.data_bw_ru_allocation_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_DATA_BW_RU_ALLOCATION_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_doppler_known,
		 {"Doppler known", "radiotap.he.data_1.doppler_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_DOPPLER_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_info_data_2,
		 {"HE Data 2", "radiotap.he.data_2",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Data 1 of the HE Info field", HFILL}},

		{&hf_radiotap_he_pri_sec_80_mhz_known,
		 {"pri/sec 80 MHz known", "radiotap.he.data_2.pri_sec_80_mhz_known",
		  FT_BOOLEAN, 16, NULL, IEEE80211_RADIOTAP_HE_PRI_SEC_80_MHZ_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_he_gi_known,
		 {"GI known", "radiotap.he.data_2.gi_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown), IEEE80211_RADIOTAP_HE_GI_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_he_num_ltf_symbols_known,
		 {"LTF symbols known", "radiotap.he.data_2.num_ltf_symbols_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown), IEEE80211_RADIOTAP_HE_NUM_LTF_SYMBOLS_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_he_pre_fec_padding_factor_known,
		 {"Pre-FEC Padding Factor known", "radiotap.he.data_2.pre_fec_padding_factor_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown), IEEE80211_RADIOTAP_HE_PRE_FEC_PADDING_FACTOR_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_he_txbf_known,
		 {"TxBF known", "radiotap.he.data_2.txbf_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown), IEEE80211_RADIOTAP_HE_TXBF_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_he_pe_disambiguity_known,
		 {"PE Disambiguity known", "radiotap.he.data_2.pe_disambiguity_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown), IEEE80211_RADIOTAP_HE_PE_DISAMBIGUITY_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_he_txop_known,
		 {"TXOP known", "radiotap.he.data_2.txop_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown), IEEE80211_RADIOTAP_HE_TXOP_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_he_midamble_periodicity_known,
		 {"midamble periodicity known", "radiotap.he.data_2.midamble_periodicity_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown), IEEE80211_RADIOTAP_HE_MIDAMBLE_PERIODICITY_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_he_ru_allocation_offset,
		 {"RU allocation offset", "radiotap.he.data_2.ru_allocation_offset",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_RU_ALLOCATION_OFFSET,
		  NULL, HFILL}},

		{&hf_radiotap_he_ru_allocation_offset_known,
		 {"RU allocation offset known", "radiotap.he.data_2.ru_allocation_offset_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
			IEEE80211_RADIOTAP_HE_RU_ALLOCATION_OFFSET_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_he_pri_sec_80_mhz,
		 {"pri/sec 80 MHz", "radiotap.he.data_2.pri_sec_80_mhz",
		  FT_BOOLEAN, 16, TFS(&tfs_pri_sec_80_mhz),
			IEEE80211_RADIOTAP_HE_PRI_SEC_80_MHZ,
		  NULL, HFILL}},

		{&hf_radiotap_he_bss_color,
		 {"BSS Color", "radiotap.he.data_3.bss_color",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_BSS_COLOR_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_he_bss_color_unknown,
		 {"BSS Color unknown", "radiotap.he.data_3.bss_color_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_BSS_COLOR_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_he_beam_change,
		 {"Beam Change", "radiotap.he.data_3.beam_change",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_BEAM_CHANGE,
		  NULL, HFILL}},

		{&hf_radiotap_he_beam_change_unknown,
		 {"Beam Change unknown", "radiotap.he.data_3.beam_change_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_BEAM_CHANGE,
		  NULL, HFILL}},

		{&hf_radiotap_he_ul_dl,
		 {"UL/DL", "radiotap.he.data_3.ul_dl",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_UL_DL,
		  NULL, HFILL}},

		{&hf_radiotap_he_ul_dl_unknown,
		 {"UL/DL unknown", "radiotap.he.data_3.ul_dl_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_UL_DL,
		  NULL, HFILL}},

		{&hf_radiotap_he_data_mcs,
		 {"data MCS", "radiotap.he.data_3.data_mcs",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_DATA_MCS_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_he_data_mcs_unknown,
		 {"data MCS unknown", "radiotap.he.data_3.data_mcs_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_DATA_MCS_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_he_data_dcm,
		 {"data DCM", "radiotap.he.data_3.data_dcm",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_DATA_DCM,
		  NULL, HFILL}},

		{&hf_radiotap_he_data_dcm_unknown,
		 {"data DCM unknown", "radiotap.he.data_3.data_dcm_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_DATA_DCM,
		  NULL, HFILL}},

		{&hf_radiotap_he_coding,
		 {"Coding", "radiotap.he.data_3.coding",
		  FT_UINT16, BASE_HEX, VALS(he_coding_vals),
		  IEEE80211_RADIOTAP_HE_CODING, NULL, HFILL}},

		{&hf_radiotap_he_coding_unknown,
		 {"Coding unknown", "radiotap.he.data_3.coding_unknown",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_HE_CODING, NULL, HFILL}},

		{&hf_radiotap_he_ldpc_extra_symbol_segment,
		 {"LDPC extra symbol segment", "radiotap.he.data_3.ldpc_extra_symbol_segment",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_LDPC_EXTRA_SYMBOL_SEGMENT,
		  NULL, HFILL}},

		{&hf_radiotap_he_ldpc_extra_symbol_segment_unknown,
		 {"LDPC extra symbol segment unknown",
		   "radiotap.he.data_3.ldpc_extra_symbol_segment_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_LDPC_EXTRA_SYMBOL_SEGMENT,
		  NULL, HFILL}},

		{&hf_radiotap_he_stbc,
		 {"STBC", "radiotap.he.data_3.stbc",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_STBC,
		  NULL, HFILL}},

		{&hf_radiotap_he_stbc_unknown,
		 {"STBC unknown", "radiotap.he.data_3.stbc_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_STBC,
		  NULL, HFILL}},

		{&hf_radiotap_he_info_data_3,
		 {"HE Data 3", "radiotap.he.data_3",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Data 1 of the HE Info field", HFILL}},

		{&hf_radiotap_spatial_reuse,
		 {"Spatial Reuse", "radiotap.he.data_4.spatial_reuse",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_spatial_reuse_unknown,
		 {"Spatial Reuse unknown", "radiotap.he.data_4.spatial_reuse_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_he_su_reserved,
		 {"Reserved", "radiotap.he.data_4.reserved_d4_fff0",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_D4_FFF0,
		  NULL, HFILL}},

		{&hf_radiotap_spatial_reuse_1,
		 {"Spatial Reuse 1", "radiotap.he.data_4.spatial_reuse_1",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_1_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_spatial_reuse_1_unknown,
		 {"Spatial Reuse 1 unknown", "radiotap.he.data_4.spatial_reuse_1_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_1_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_spatial_reuse_2,
		 {"Spatial Reuse 2", "radiotap.he.data_4.spatial_reuse_2",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_2_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_spatial_reuse_2_unknown,
		 {"Spatial Reuse 2 unknown", "radiotap.he.data_4.spatial_reuse_2_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_2_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_spatial_reuse_3,
		 {"Spatial Reuse 3", "radiotap.he.data_4.spatial_reuse_3",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_3_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_spatial_reuse_3_unknown,
		 {"Spatial Reuse 3 unknown", "radiotap.he.data_4.spatial_reuse_3_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_3_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_spatial_reuse_4,
		 {"Spatial Reuse 4", "radiotap.he.data_4.spatial_reuse_4",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_4_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_spatial_reuse_4_unknown,
		 {"Spatial Reuse 4 unknown", "radiotap.he.data_4.spatial_reuse_4_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_4_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_sta_id_user_captured,
		 {"STA-ID of user data captured for", "radiotap.he.data_4.sta_id_user",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_STA_ID_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_he_mu_reserved,
		 {"Reserved", "radiotap.he.data_4.reserved_d4_b15",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_RESERVED_D4_B15,
		  NULL, HFILL}},

		{&hf_radiotap_he_info_data_4,
		 {"HE Data 4", "radiotap.he.data_4",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Data 1 of the HE Info field", HFILL}},

		{&hf_radiotap_data_bandwidth_ru_allocation,
		 {"data Bandwidth/RU allocation", "radiotap.he.data_5.data_bw_ru_allocation",
		  FT_UINT16, BASE_HEX, VALS(he_data_bw_ru_alloc_vals),
		  IEEE80211_RADIOTAP_HE_DATA_BANDWIDTH_RU_ALLOC_MASK, NULL, HFILL}},

		{&hf_radiotap_data_bandwidth_ru_allocation_unknown,
		 {"data Bandwidth/RU allocation unknown",
		   "radiotap.he.data_5.data_bw_ru_allocation_unknown",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_HE_DATA_BANDWIDTH_RU_ALLOC_MASK, NULL, HFILL}},

		{&hf_radiotap_gi,
		 {"GI", "radiotap.he.data_5.gi",
		 FT_UINT16, BASE_HEX, VALS(he_gi_vals), IEEE80211_RADIOTAP_HE_GI_MASK,
		 NULL, HFILL}},

		{&hf_radiotap_gi_unknown,
		 {"GI unknown", "radiotap.he.data_5.gi_unknown",
		 FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_GI_MASK,
		 NULL, HFILL}},

		{&hf_radiotap_ltf_symbol_size,
		 {"LTF symbol size", "radiotap.he.data_5.ltf_symbol_size",
		 FT_UINT16, BASE_HEX, VALS(he_ltf_symbol_size_vals),
		 IEEE80211_RADIOTAP_HE_LTF_SYMBOL_SIZE, NULL, HFILL}},

		{&hf_radiotap_ltf_symbol_size_unknown,
		 {"LTF symbol size unknown", "radiotap.he.data_5.ltf_symbol_size_unknown",
		 FT_UINT16, BASE_HEX, NULL,
		 IEEE80211_RADIOTAP_HE_LTF_SYMBOL_SIZE, NULL, HFILL}},

		{&hf_radiotap_num_ltf_symbols,
		 {"LTF symbols", "radiotap.he.num_ltf_symbols",
		  FT_UINT16, BASE_HEX, VALS(he_num_ltf_symbols_vals),
		  IEEE80211_RADIOTAP_HE_NUM_LTF_SYMBOLS_MASK, NULL, HFILL}},

		{&hf_radiotap_num_ltf_symbols_unknown,
		 {"LTF symbols unknown", "radiotap.he.num_ltf_symbols_unknown",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_HE_NUM_LTF_SYMBOLS_MASK, NULL, HFILL}},

		{&hf_radiotap_d5_reserved_b11,
		 {"reserved", "radiotap.he.data_5.reserved_d5_b11",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_RESERVED_D5_B11,
		  NULL, HFILL}},

		{&hf_radiotap_pre_fec_padding_factor,
		 {"Pre-FEC Padding Factor", "radiotap.he.pre_fec_padding_factor",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_PRE_FEC_PADDING_FACTOR_MASK,
		 NULL, HFILL}},

		{&hf_radiotap_pre_fec_padding_factor_unknown,
		 {"Pre-FEC Padding Factor unknown", "radiotap.he.pre_fec_padding_factor_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_PRE_FEC_PADDING_FACTOR_MASK,
		 NULL, HFILL}},

		{&hf_radiotap_txbf,
		 {"TxBF", "radiotap.he.txbf",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_TXBF,
		  NULL, HFILL}},

		{&hf_radiotap_txbf_unknown,
		 {"TxBF unknown", "radiotap.he.txbf_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_TXBF,
		  NULL, HFILL}},

		{&hf_radiotap_pe_disambiguity,
		 {"PE Disambiguity", "radiotap.he.pe_disambiguity",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_PE_DISAMBIGUITY,
		  NULL, HFILL}},

		{&hf_radiotap_pe_disambiguity_unknown,
		 {"PE Disambiguity unknown", "radiotap.he.pe_disambiguity_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_PE_DISAMBIGUITY,
		  NULL, HFILL}},

		{&hf_radiotap_he_info_data_5,
		 {"HE Data 5", "radiotap.he.data_5",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Data 1 of the HE Info field", HFILL}},

		{&hf_radiotap_he_nsts,
		 {"NSTS", "radiotap.he.data_6.nsts",
		  FT_UINT16, BASE_HEX, VALS(he_nsts_vals),IEEE80211_RADIOTAP_HE_NSTS_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_he_doppler_value,
		 {"Doppler value", "radiotap.he.data_6.doppler_value",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_DOPLER_VALUE,
		  NULL, HFILL}},

		{&hf_radiotap_he_doppler_value_unknown,
		 {"Doppler value unknown", "radiotap.he.data_6.doppler_value_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_DOPLER_VALUE,
		  NULL, HFILL}},

		{&hf_radiotap_he_d6_reserved_00e0,
		 {"Reserved", "radiotap.he.data_6.reserved_d6_00e0",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_RESERVED_D6_00E0,
		  NULL, HFILL}},

		{&hf_radiotap_he_txop_value,
		 {"TXOP value", "radiotap.he.data_6.txop_value",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_TXOP_VALUE_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_he_txop_value_unknown,
		 {"TXOP value unknown", "radiotap.he.data_6.txop_value_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_TXOP_VALUE_MASK,
		  NULL, HFILL}},

		{&hf_radiotap_midamble_periodicity,
		 {"midamble periodicity", "radiotap.he.data_6.midamble_periodicity",
		  FT_UINT16, BASE_HEX, VALS(he_midamble_periodicity_vals),
		  IEEE80211_RADIOTAP_HE_MIDAMBLE_PERIODICITY, NULL, HFILL}},

		{&hf_radiotap_midamble_periodicity_unknown,
		 {"midamble periodicity unknown",
		   "radiotap.he.data_6.midamble_periodicity_unknown",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_HE_MIDAMBLE_PERIODICITY, NULL, HFILL}},

		{&hf_radiotap_he_info_data_6,
		 {"HE Data 6", "radiotap.he.data_6",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Data 1 of the HE Info field", HFILL}},

		{&hf_radiotap_he_mu_sig_b_mcs,
		 {"SIG-B MCS (from SIG-A)", "radiotap.he_mu.sig_b_mcs",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_HE_MU_SIG_B_MCS_MASK, NULL, HFILL}},

		{&hf_radiotap_he_mu_sig_b_mcs_unknown,
		 {"SIG-B MCS (from SIG-A) unknown",
		  "radiotap.he_mu.sig_b_mcs_unknown",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_HE_MU_SIG_B_MCS_MASK, NULL, HFILL}},

		{&hf_radiotap_he_mu_sig_b_mcs_known,
		 {"SIG-B MCS known", "radiotap.he_mu.sig_b_mcs_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_MU_SIG_B_MCS_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_mu_sig_b_dcm,
		 {"SIG-B DCM (from SIG-A)", "radiotap.he_mu.sig_b_dcm",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_MU_SIG_B_DCM,
		  NULL, HFILL}},

		{&hf_radiotap_he_mu_sig_b_dcm_unknown,
		 {"SIG-B DCM (from SIG-A) unknown",
		  "radiotap.he_mu.sig_b_dcm_unknown",
		  FT_UINT16, BASE_HEX, NULL, IEEE80211_RADIOTAP_HE_MU_SIG_B_DCM,
		  NULL, HFILL}},

		{&hf_radiotap_he_mu_sig_b_dcm_known,
		 {"SIG-B DCM known", "radiotap.he_mu.sig_b_dmc_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_MU_SIG_B_DCM_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan2_center_26_tone_ru_bit_known,
		 {"Channel2 center 26-tone RU bit known", "radiotap.he_mu.chan2_center_26_tone_ru_bit_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_MU_CHAN2_CENTER_26_TONE_RU_BIT_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan2_center_26_tone_ru_bit_unknown,
		 {"Channel2 center 26-tone RU bit known", "radiotap.he_mu.chan2_center_26_tone_ru_bit_unknown",
		  FT_UINT16, BASE_CUSTOM, CF_FUNC(not_captured_custom),
		  IEEE80211_RADIOTAP_HE_MU_CHAN2_CENTER_26_TONE_RU_BIT_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan1_rus_known,
		 {"Channel 1 RUs known", "radiotap.he_mu.chan1_rus_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_MU_CHAN1_RUS_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan1_rus_unknown,
		 {"Channel 1 RUs unknown", "radiotap.he_mu.chan1_rus_unknown",
		  FT_UINT16, BASE_CUSTOM, CF_FUNC(not_captured_custom),
		  IEEE80211_RADIOTAP_HE_MU_CHAN1_RUS_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan2_rus_known,
		 {"Channel 2 RUs known", "radiotap.he_mu.chan2_rus_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_MU_CHAN2_RUS_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan2_rus_unknown,
		 {"Channel 2 RUs unknown", "radiotap.he_mu.chan2_rus_unknown",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_MU_CHAN2_RUS_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_mu_reserved_f1_b10_b11,
		 {"Reserved", "radiotap.he_mu.reserved_f1_b10_b11",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_HE_MU_RESERVED_F1_B10_B11, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan1_center_26_tone_ru_bit_known,
		 {"Channel1 center 26-tone RU bit known", "radiotap.he_mu.chan1_center_26_tone_ru_bit_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_MU_CHAN1_CENTER_26_TONE_RU_BIT_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan1_center_26_tone_ru_bit_unknown,
		 {"Channel1 center 26-tone RU bit known", "radiotap.he_mu.chan1_center_26_tone_ru_bit_unknown",
		  FT_UINT16, BASE_CUSTOM, CF_FUNC(not_captured_custom),
		  IEEE80211_RADIOTAP_HE_MU_CHAN1_CENTER_26_TONE_RU_BIT_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan1_center_26_tone_ru_value,
		 {"Channel1 center 26-tone RU value", "radiotap.he_mu.chan1_center_26_tone_ru_value",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_HE_MU_CHAN1_CENTER_26_TONE_RU_VALUE, NULL, HFILL}},

		{&hf_radiotap_he_mu_sig_b_syms_mu_mimo_users_known,
		 {"# of HE-SIG-B Symbols/MU-MINO users known",
		  "radiotap.he_mu.symbol_cnt_or_user_cnt_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_MU_SYMBOL_CNT_OR_USER_CNT_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_he_mu_info_flags_1,
		 {"HE-MU Flags 1", "radiotap.he_mu.flags_1",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Flags 1 of the HE-MU Info field", HFILL}},

		{&hf_radiotap_he_mu_bw_from_bw_in_sig_a,
		 {"bandwidth from Bandwidth field in SIG-A",
			"radiotap.he_mu.bw_from_sig_a",
		  FT_UINT16, BASE_DEC, NULL,
		  IEEE80211_RADIOTAP_HE_MU_BW_FROM_BW_IN_SIG_A_MASK, NULL, HFILL}},

		{&hf_radiotap_he_mu_bw_from_bw_in_sig_a_unknown,
		 {"bandwidth from Bandwidth field in SIG-A unknown",
			"radiotap.he_mu.bw_from_sig_a_unknown",
		  FT_UINT16, BASE_DEC, NULL,
		  IEEE80211_RADIOTAP_HE_MU_BW_FROM_BW_IN_SIG_A_MASK, NULL, HFILL}},

		{&hf_radiotap_he_mu_bw_from_bw_in_sig_a_known,
		 {"bandwidth from Bandwidth field in SIG-A known",
			"radiotap.he_mu.bw_from_sig_a_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_MU_BW_FROM_BW_IN_SIG_A_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_mu_sig_b_compression_from_sig_a,
		 {"SIG-B compression from SIG-A", "radiotap.he_mu.sig_b_compression",
		  FT_BOOLEAN, 16, NULL,
		  IEEE80211_RADIOTAP_HE_MU_SIG_B_COMPRESSION_FROM_SIG_A,
		  NULL, HFILL}},

		{&hf_radiotap_he_mu_sig_b_compression_known,
		 {"SIG-B compression known", "radiotap.he_mu.sig_b_compression_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_MU_SIG_B_COMPRESSION_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_mu_sig_b_compression_unknown,
		 {"SIG-B compression unknown", "radiotap.he_mu.sig_b_compression_unknown",
		  FT_UINT16, BASE_CUSTOM, CF_FUNC(not_captured_custom),
		  IEEE80211_RADIOTAP_HE_MU_SIG_B_COMPRESSION_FROM_SIG_A, NULL, HFILL}},

		{&hf_radiotap_he_mu_sig_b_syms_mu_mimo_users,
		 {"# of HE-SIG-B Symbols or # of MU-MIMO Users",
		  "radiotap.he_mu.sig_b_syms_or_mu_mimo_users",
		  FT_UINT16, BASE_CUSTOM, CF_FUNC(he_sig_b_symbols_custom),
		  IEEE80211_RADIOTAP_HE_MU_SYMBOL_CNT_OR_USER_CNT, NULL, HFILL}},

		{&hf_radiotap_he_mu_sig_b_syms_mu_mimo_users_unknown,
		 {"# of HE-SIG-B Symbols or # of MU-MIMO Users unknown",
		  "radiotap.he_mu.sig_b_syms_or_mu_mimo_users_unknown",
		  FT_UINT16, BASE_DEC, NULL,
		  IEEE80211_RADIOTAP_HE_MU_SYMBOL_CNT_OR_USER_CNT, NULL, HFILL}},

		{&hf_radiotap_he_mu_preamble_puncturing,
		 {"preamble puncturing from Bandwidth field in HE-SIG-A",
		  "radiotap.he_mu.preamble_puncturing",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_HE_MU_PREAMBLE_PUNCTURING_MASK, NULL, HFILL}},

		{&hf_radiotap_he_mu_preamble_puncturing_unknown,
		 {"preamble puncturing from Bandwidth field in HE-SIG-A unknown",
		  "radiotap.he_mu.preamble_puncturing",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_HE_MU_PREAMBLE_PUNCTURING_MASK, NULL, HFILL}},

		{&hf_radiotap_he_mu_preamble_puncturing_known,
		 {"preamble puncturing from Bandwidth field in HE-SIG-A known",
		  "radiotap.he_mu.preamble_puncturing_known",
		  FT_BOOLEAN, 16, TFS(&tfs_known_unknown),
		  IEEE80211_RADIOTAP_HE_MU_PREAMBLE_PUNCTURING_KNOWN, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan2_center_26_tone_ru_value,
		 {"Chan2 Center 26 Tone RU Value",
		  "radiotap.he_mu.chan2_center_26_tone_ru_value",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_HE_MU_CHAN2_CENTER_26_TONE_RU_VALUE,
		  NULL, HFILL }},

		{&hf_radiotap_he_mu_reserved_f2_b12_b15,
		 {"Reserved", "radiotap.he_mu.reserved_f2_b12_b15",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_HE_MU_RESERVED_F2_B12_B15, NULL, HFILL}},

		{&hf_radiotap_he_mu_info_flags_2,
		 {"HE-MU Flags 2", "radiotap.he_mu.flags_2",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Flags 2 of the HE-MU Info field", HFILL}},

		{&hf_radiotap_he_mu_chan1_rus_0,
		 {"Chan1 RU[0] index", "radiotap.he_mu.chan1_rus_0_index",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan1_rus_0_unknown,
		 {"Chan1 RU[0] index unknown",
		  "radiotap.he_mu.chan1_rus_0_index_unknown",
		  FT_UINT8, BASE_CUSTOM, CF_FUNC(not_captured_custom),
		  0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan1_rus_1,
		 {"Chan1 RU[1] index", "radiotap.he_mu.chan1_rus_1_index",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan1_rus_1_unknown,
		 {"Chan1 RU[1] index unknown",
		  "radiotap.he_mu.chan1_rus_1_index_unknown",
		  FT_UINT8, BASE_CUSTOM, CF_FUNC(not_captured_custom),
		  0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan1_rus_2,
		 {"Chan1 RU[2] index", "radiotap.he_mu.chan1_rus_2_index",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan1_rus_2_unknown,
		 {"Chan1 RU[2] index unknown",
		  "radiotap.he_mu.chan1_rus_2_index_unknown",
		  FT_UINT8, BASE_CUSTOM, CF_FUNC(not_captured_custom),
		  0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan1_rus_3,
		 {"Chan1 RU[3] index", "radiotap.he_mu.chan1_rus_3_index",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan1_rus_3_unknown,
		 {"Chan1 RU[3] index unknown",
		  "radiotap.he_mu.chan1_rus_3_index_unknown",
		  FT_UINT8, BASE_CUSTOM, CF_FUNC(not_captured_custom),
		  0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan2_rus_0,
		 {"Chan2 RU[0] index", "radiotap.he_mu.chan2_rus_0_index",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan2_rus_0_unknown,
		 {"Chan2 RU[0] index unknown",
		  "radiotap.he_mu.chan2_rus_0_index_unknown",
		  FT_UINT8, BASE_CUSTOM,
		  CF_FUNC(not_captured_custom), 0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan2_rus_1,
		 {"Chan2 RU[1] index", "radiotap.he_mu.chan2_rus_1_index",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan2_rus_1_unknown,
		 {"Chan2 RU[1] index unknown",
		  "radiotap.he_mu.chan2_rus_1_index_unknown",
		  FT_UINT8, BASE_CUSTOM,
		  CF_FUNC(not_captured_custom), 0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan2_rus_2,
		 {"Chan2 RU[2] index", "radiotap.he_mu.chan2_rus_2_index",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan2_rus_2_unknown,
		 {"Chan2 RU[2] index unknown",
		  "radiotap.he_mu.chan2_rus_2_index_unknown",
		  FT_UINT8, BASE_CUSTOM,
		  CF_FUNC(not_captured_custom), 0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan2_rus_3,
		 {"Chan2 RU[3] index", "radiotap.he_mu.chan2_rus_3_index",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{&hf_radiotap_he_mu_chan2_rus_3_unknown,
		 {"Chan2 RU[3] index unknown",
		  "radiotap.he_mu.chan2_rus_3_index_unknown",
		  FT_UINT8, BASE_CUSTOM,
		  CF_FUNC(not_captured_custom), 0x0, NULL, HFILL}},

		{&hf_radiotap_0_length_psdu_type,
		 {"Type", "radiotap.0_len_psdu.type",
		  FT_UINT8, BASE_HEX|BASE_RANGE_STRING,
		  RVALS(zero_length_psdu_rsvals), 0x0, NULL, HFILL}},

		{&hf_radiotap_l_sig_data_1,
		 {"Data1", "radiotap.l_sig.data1",
		  FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},

		{&hf_radiotap_l_sig_rate_known,
		 {"rate known", "radiotap.l_sig.rate_known",
		  FT_BOOLEAN, 16, NULL,
		  IEEE80211_RADIOTAP_L_SIG_RATE_KNOWN, NULL, HFILL}},

		{&hf_radiotap_l_sig_length_known,
		 {"length known", "radiotap.l_sig.length_known",
		  FT_BOOLEAN, 16, NULL,
		  IEEE80211_RADIOTAP_L_SIG_LENGTH_KNOWN, NULL, HFILL}},

		{&hf_radiotap_l_sig_reserved,
		 {"reserved", "radiotap.l_sig.reserved",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_L_SIG_RESERVED_MASK, NULL, HFILL}},

		{&hf_radiotap_l_sig_data_2,
		 {"Data2", "radiotap.l_sig.data2",
		  FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{&hf_radiotap_l_sig_rate,
		 {"rate", "radiotap.l_sig.rate",
		  FT_UINT16, BASE_DEC, NULL,
		  IEEE80211_RADIOTAP_L_SIG_RATE_MASK, NULL, HFILL}},

		{&hf_radiotap_l_sig_length,
		 {"length", "radiotap.l_sig.length",
		  FT_UINT16, BASE_DEC, NULL,
		  IEEE80211_RADIOTAP_L_SIG_LENGTH_MASK, NULL, HFILL}},

		{&hf_radiotap_u_sig_common,
		 {"U-SIG common", "radiotap.u_sig.common",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_usig_phy_version_identifier_known,
		 {"PHY version identifier known",
		  "radiotap.u_sig.common.phy_version_identifier_known",
		  FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL }},

		{&hf_radiotap_usig_bw_known,
		 {"BW known", "radiotap.u_sig.common.bw_known",
		  FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL }},

		{&hf_radiotap_usig_ul_dl_known,
		 {"UL/DL known", "radiotap.u_sig.common.ul_dl_known",
		  FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL }},

		{&hf_radiotap_usig_bss_color_known,
		 {"BSS Color known", "radiotap.u_sig.common.bss_color_known",
		  FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL }},

		{&hf_radiotap_usig_txop_known,
		 {"TXOP known", "radiotap.u_sig.common.txop_known",
		  FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL }},

		{&hf_radiotap_usig_bad_u_sig_crc,
		 {"Bad U-SIG CRC", "radiotap.u_sig.common.bad_u_sig_crc",
		  FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL }},

		{&hf_radiotap_usig_validate_bits_checked,
		 {"Validate bits checked", "radiotap.u_sig.common.validate_bits_checked",
		  FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL }},

		{&hf_radiotap_usig_validate_bits_ok,
		 {"Validate bits OK", "radiotap.u_sig.common.validate_bits_ok",
		  FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL }},

		{&hf_radiotap_usig_reserved,
		 {"Reserved", "radiotap.u_sig.common.reserved",
		  FT_UINT32, BASE_HEX, NULL, 0x00000fc0, NULL, HFILL }},

		{&hf_radiotap_usig_phy_version_id,
		 {"Phy version identifier",
		  "radiotap.u_sig.common.phy_version_identifier",
		  FT_UINT32, BASE_DEC, NULL, 0x00007000, NULL, HFILL }},

		{&hf_radiotap_usig_bw,
		 {"BW", "radiotap.u_sig.common.bw",
		  FT_UINT32, BASE_HEX, VALS(eht_u_sig_bw_vals), 0x00038000,
		  NULL, HFILL }},

		{&hf_radiotap_usig_ul_dl,
		 {"UL/DL", "radiotap.u_sig.common.ul_dl",
		  FT_BOOLEAN, 32, NULL, 0x00040000, NULL, HFILL }},

		{&hf_radiotap_usig_bss_color,
		 {"BSS Color", "radiotap.u_sig.common.bss_color",
		  FT_UINT32, BASE_DEC, NULL, 0x01f80000, NULL, HFILL }},

		{&hf_radiotap_usig_txop,
		 {"TXOP", "radiotap.u_sig.common.txop",
		  FT_UINT32, BASE_DEC, NULL, 0xfe000000, NULL, HFILL }},

		{&hf_radiotap_u_sig_mask,
		 {"mask", "radiotap.u_sig.mask",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_usig_value_mu_ppdu,
		 {"EHT MU PPDU", "radiotap.u_sig.value.mu_ppdu",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_usig_eht_mu_b20_b24,
		 {"U-SIG-1 B20-B24",
		  "radiotap.u_sig.value.mu_ppdu.u_sig_1_b20_b24",
		  FT_UINT32, BASE_HEX, NULL, 0x0000001f, NULL, HFILL }},

		{&hf_radiotap_usig_eht_mu_b20_b24_not_known,
		 {"U-SIG-1 B20-B24 not known",
		  "radiotap.u_sig.value.mu_ppdu.u_sig_1_b20_b24_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x0000001f, NULL, HFILL }},

		{&hf_radiotap_usig_eht_mu_b25,
		 {"U-SIG-1 B25", "radiotap.u_sig.value.mu_ppdu.u_sig_1_b25",
		  FT_UINT32, BASE_HEX, NULL, 0x00000020, NULL, HFILL }},

		{&hf_radiotap_usig_eht_mu_b25_not_known,
		 {"U-SIG-1 B25 not known",
		  "radiotap.u_sig.value.mu_ppdu.u_sig_1_b25_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x00000020, NULL, HFILL }},

		{&hf_radiotap_usig_ppdu_type_and_comp_mode,
		 {"PPDU Type and Compression Mode",
		  "radiotap.u_sig.value.ppdu_type_and_compression_mode",
		  FT_UINT32, BASE_HEX, NULL, 0x000000c0, NULL, HFILL }},

		{&hf_radiotap_usig_validate1,
		 {"Validate", "radiotap.u_sig.value.mu_ppdu.validate1",
		  FT_UINT32, BASE_HEX, NULL, 0x00000100, NULL, HFILL }},

		{&hf_radiotap_usig_validate1_not_known,
		 {"Validate not known",
		  "radiotap.u_sig.value.mu_ppdu.validate1_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x00000100, NULL, HFILL }},

		{&hf_radiotap_usig_punctured_channel_info,
		 {"Punctured Channel Information",
		  "radiotap.u_sig.value.mu_ppdu.punctured_channel_information",
		  FT_UINT32, BASE_HEX, NULL, 0x00003e00, NULL, HFILL }},

		{&hf_radiotap_usig_punctured_channel_info_not_known,
		 {"Punctured Channel Information not known",
		  "radiotap.u_sig.value.mu_ppdu.punctured_channel_information_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x00003e00, NULL, HFILL }},

		{&hf_radiotap_usig_validate2,
		 {"Validate", "radiotap.u_sig.value.mu_ppdu.validate2",
		  FT_UINT32, BASE_HEX, NULL, 0x00004000, NULL, HFILL }},

		{&hf_radiotap_usig_validate2_not_known,
		 {"Validate not known",
		  "radiotap.u_sig.value.mu_ppdu.validate2_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x00004000, NULL, HFILL }},

		{&hf_radiotap_usig_eht_sig_mcs,
		 {"EHT-SIG MCS", "radiotap.u_sig.value.mu_ppdu.eht_sig_mcs",
		  FT_UINT32, BASE_HEX, NULL, 0x00018000, NULL, HFILL }},

		{&hf_radiotap_usig_eht_sig_mcs_not_known,
		 {"EHT-SIG MCS not known",
		  "radiotap.u_sig.value.mu_ppdu.eht_sig_mcs_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x00018000, NULL, HFILL }},

		{&hf_radiotap_usig_number_eht_sig_symbols,
		 {"Number of EHT-SIG Symbols",
		  "radiotap.u_sig.value.mu_ppdu.number_of_eht_sig_symbols",
		  FT_UINT32, BASE_HEX, NULL, 0x003e0000, NULL, HFILL }},

		{&hf_radiotap_usig_number_eht_sig_symbols_not_known,
		 {"Number of EHT-SIG Symbols not known",
		  "radiotap.u_sig.value.mu_ppdu.number_of_eht_sig_symbols_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x003e0000, NULL, HFILL }},

		{&hf_radiotap_usig_crc,
		 {"CRC", "radiotap.u_sig.value.mu_ppdu.crc",
		  FT_UINT32, BASE_HEX, NULL, 0x03c00000, NULL, HFILL }},

		{&hf_radiotap_usig_crc_not_known,
		 {"CRC not known", "radiotap.u_sig.value.mu_ppdu.crc_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x03c00000, NULL, HFILL }},

		{&hf_radiotap_usig_tail,
		 {"Tail", "radiotap.u_sig.value.mu_ppdu.tail",
		  FT_UINT32, BASE_HEX, NULL, 0xfc000000, NULL, HFILL }},

		{&hf_radiotap_usig_tail_not_known,
		 {"Tail not known", "radiotap.u_sig.value.mu_ppdu.tail_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0xfc000000, NULL, HFILL }},

		{&hf_radiotap_usig_value_tb_ppdu,
		 {"EHT TB PPDU", "radiotap.u_sig.value.tb_ppdu",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_b20_b25,
		 {"Disregard", "radiotap.u_sig.value.tb_ppdu.disregard",
		  FT_UINT32, BASE_HEX, NULL, 0x0000003f, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_b20_b25_not_known,
		 {"Disregard not known",
		  "radiotap.u_sig.value.tb_ppdu.disregard_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x0000003f, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_validate1,
		 {"Validate", "radiotap.u_sig.value.tb_ppdu.validate1",
		  FT_UINT32, BASE_HEX, NULL, 0x00000100, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_validate1_not_known,
		 {"Validate not known",
		  "radiotap.u_sig.value.tb_ppdu.validate1_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x00000100, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_spatial_reuse_1,
		 {"Spatial Reuse 1",
		  "radiotap.u_sig.value.tb_ppdu.spatial_reuse_1",
		  FT_UINT32, BASE_HEX, NULL, 0x00001e00, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_spatial_reuse_1_not_known,
		 {"Spatial Reuse 1 not known",
		  "radiotap.u_sig.value.tb_ppdu.spatial_reuse_1_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x00001e00, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_spatial_reuse_2,
		 {"Spatial Reuse 2",
		  "radiotap.u_sig.value.tb_ppdu.spatial_reuse_2",
		  FT_UINT32, BASE_HEX, NULL, 0x0001e000, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_spatial_reuse_2_not_known,
		 {"Spatial Reuse 2 not known",
		  "radiotap.u_sig.value.tb_ppdu.spatial_reuse_2_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x0001e000, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_disregard,
		 {"Disregard", "radiotap.u_sig.value.tb_ppdu.disregard",
		  FT_UINT32, BASE_HEX, NULL, 0x003e0000, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_disregard_not_known,
		 {"Disregard not known",
		  "radiotap.u_sig.value.tb_ppdu.disregard_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x003e0000, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_crc,
		 {"CRC", "radiotap.u_sig.value.tb_ppdu.crc",
		  FT_UINT32, BASE_HEX, NULL, 0x03c00000, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_crc_not_known,
		 {"CRC not known", "radiotap.u_sig.value.tb_ppdu.crc_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x03c00000, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_tail,
		 {"Tail", "radiotap.u_sig.value.tb_ppdu.tail",
		  FT_UINT32, BASE_HEX, NULL, 0xfc000000, NULL, HFILL }},

		{&hf_radiotap_usig_eht_tb_tail_not_known,
		 {"Tail not known",
		  "radiotap.u_sig.value.tb_ppdu.tail_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0xfc000000, NULL, HFILL }},

		{&hf_radiotap_eht_known,
		 {"known", "radiotap.eht.known",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_eht_reserved_1,
		 {"Reserved",
		  "radiotap.eht.known.reserved_1",
		  FT_UINT32, BASE_HEX, NULL, 0x00000001, NULL, HFILL }},

		{&hf_radiotap_eht_spatial_reuse_known,
		 {"Spatial Reuse Known",
		  "radiotap.eht.known.spatial_reuse_known",
		  FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL }},

		{&hf_radiotap_eht_guard_interval_known,
		 {"Guard Interval Known",
		  "radiotap.eht.known.guard_interval_known",
		  FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL }},

		{&hf_radiotap_eht_reserved_8,
		 {"Reserved",
		  "radiotap.eht.known.reserved_8",
		  FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL }},

		{&hf_radiotap_eht_number_ltf_symbols_known,
		 {"Number of LTF symbols Known",
		  "radiotap.eht.known.number_ltf_symbols_known",
		  FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL }},

		{&hf_radiotap_eht_ldpc_extra_symbol_segment_known,
		 {"LDPC Extra Symbol Segment Known",
		  "radiotap.eht.known.ldpc_extra_symbol_segment_known",
		  FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL }},

		{&hf_radiotap_eht_pre_fec_padding_factor_known,
		 {"Pre-FEC Padding Factor Known",
		  "radiotap.eht.known.pre_fec_padding_factor_known",
		  FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL }},

		{&hf_radiotap_eht_pe_disambiguity_known,
		 {"PE Disambiguity Known",
		  "radiotap.eht.known.pe_disambiguity_known",
		  FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL }},

		{&hf_radiotap_eht_disregard_known,
		 {"EHT Disregard Known",
		  "radiotap.eht.known.eht_disregard_known",
		  FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL }},

		{&hf_radiotap_eht_reserved1,
		 {"Reserved",
		  "radiotap.eht.known.reserved1",
		  FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL }},

		{&hf_radiotap_eht_reserved_2,
		 {"Reserved",
		  "radiotap.eht.known.reserved_2",
		  FT_UINT32, BASE_HEX, NULL, 0x00001c00, NULL, HFILL }},

		{&hf_radiotap_eht_crc1_known,
		 {"CRC1 Known",
		  "radiotap.eht.known.crc1_known",
		  FT_BOOLEAN, 32, NULL, 0x00002000, NULL, HFILL }},

		{&hf_radiotap_eht_tail1_known,
		 {"Tail1 Known",
		  "radiotap.eht.known.tail1_known",
		  FT_BOOLEAN, 32, NULL, 0x00004000, NULL, HFILL }},

		{&hf_radiotap_eht_crc2_known,
		 {"CRC2 Known",
		  "radiotap.eht.known.crc2_known",
		  FT_BOOLEAN, 32, NULL, 0x00008000, NULL, HFILL }},

		{&hf_radiotap_eht_tail2_known,
		 {"Tail2 known", "radiotap.eht.known.tail2_known",
		  FT_BOOLEAN, 32, NULL, 0x00010000, NULL, HFILL }},

		{&hf_radiotap_eht_nss_known,
		 {"NSS Known",
		  "radiotap.eht.known.nss_known",
		  FT_BOOLEAN, 32, NULL, 0x00020000, NULL, HFILL }},

		{&hf_radiotap_eht_beamformed_known,
		 {"Beamformed Known",
		  "radiotap.eht.known.beamformed_known",
		  FT_BOOLEAN, 32, NULL, 0x00040000, NULL, HFILL }},

		{&hf_radiotap_eht_number_non_ofdma_users_known,
		 {"Number of Non-OFDMA Users Known",
		  "radiotap.eht.known.number_of_non_ofdma_users_known",
		  FT_BOOLEAN, 32, NULL, 0x00080000, NULL, HFILL }},

		{&hf_radiotap_eht_user_encoding_block_crc_known,
		 {"User Encoding Block CRC Known",
		  "radiotap.eht.known.user_encoding_block_crc_known",
		  FT_BOOLEAN, 32, NULL, 0x00100000, NULL, HFILL }},

		{&hf_radiotap_eht_user_encoding_block_tail_known,
		{"User Encoding Block Tail Known",
		  "radiotap.eht.known.user_encoding_block_tail_known",
		  FT_BOOLEAN, 32, NULL, 0x00200000, NULL, HFILL }},

		{&hf_radiotap_eht_ru_mru_size_known,
		 {"RU/MRU Size Known",
		  "radiotap.eht.known.ru_mru_size_known",
		  FT_BOOLEAN, 32, NULL, 0x00400000, NULL, HFILL }},

		{&hf_radiotap_eht_ru_mru_index_known,
		 {"RU/MRU Index Known",
		  "radiotap.eht.known.ru_mru_index_known",
		  FT_BOOLEAN, 32, NULL, 0x00800000, NULL, HFILL }},

		{&hf_radiotap_eht_tb_ru_allocation_known,
		 {"TB RU Allocation Known",
		  "radiotap.eht.known.tb_ru_known",
		  FT_BOOLEAN, 32, NULL, 0x01000000, NULL, HFILL }},

		{&hf_radiotap_eht_primary_80mhz_channel_pos_known,
		 {"Primary 80MHz Channel Position Known",
		  "radiotap.eht.know.primary_80mhz_channel_position_known",
		  FT_BOOLEAN, 32, NULL, 0x02000000, NULL, HFILL }},

		{&hf_radiotap_eht_reserved_fc,
		 {"Reserved",
		  "radiotap.eht.known.reserved_fc",
		  FT_UINT32, BASE_HEX, NULL, 0xfc000000, NULL, HFILL }},

		{&hf_radiotap_eht_data0,
		 {"data[0]", "radiotap.eht.data_0",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_eht_data0_reserved1,
		 {"Reserved",
		  "radiotap.eht.data_0.reserved1",
		  FT_UINT32, BASE_HEX, NULL, 0x00000007, NULL, HFILL }},

		{&hf_radiotap_eht_data0_spatial_reuse,
		 {"Spatial Reuse",
		  "radiotap.eht.data_0.spatial_reuse",
		  FT_UINT32, BASE_DEC, NULL, 0x00000078, NULL, HFILL }},

		{&hf_radiotap_eht_data0_spatial_reuse_not_known,
		 {"Spatial Reuse",
		  "radiotap.eht.data_0.spatial_reuse_not_known",
		  FT_UINT32, BASE_DEC, NULL, 0x00000078, NULL, HFILL }},

		{&hf_radiotap_eht_data0_gi,
		 {"GI",
		  "radiotap.eht.data_0.gi",
		  FT_UINT32, BASE_DEC, VALS(he_gi_vals), 0x00000180, NULL, HFILL }},

		{&hf_radiotap_eht_data0_gi_not_known,
		 {"GI",
		  "radiotap.eht.data_0.gi_not_known",
		  FT_UINT32, BASE_DEC, NULL, 0x00000180, NULL, HFILL }},

		{&hf_radiotap_eht_data0_ltf_symbol_size,
		 {"LTF symbol size",
		  "radiotap.eht.data_0.ltf_symbol_size",
		  FT_UINT32, BASE_DEC, VALS(he_ltf_symbol_size_vals), 0x00000600, NULL, HFILL }},

		{&hf_radiotap_eht_data0_number_ltf_symbols,
		 {"Number of LTF symbols",
		  "radiotap.eht.data_0.number_ltf_symbols",
		  FT_UINT32, BASE_DEC, VALS(he_num_ltf_symbols_vals), 0x00003800, NULL, HFILL }},

		{&hf_radiotap_eht_data0_number_ltf_symbols_not_known,
		 {"Number of LTF symbols",
		  "radiotap.eht.data_0.number_ltf_symbols_not_known",
		  FT_UINT32, BASE_DEC, NULL, 0x00003800, NULL, HFILL }},

		{&hf_radiotap_eht_data0_ldpc_extra_symbol_segment,
		 {"LDPC extra symbol segment",
		  "radiotap.eht.data_0.ldpc_extra_symbol_segment",
		  FT_BOOLEAN, 32, NULL, 0x00004000, NULL, HFILL }},

		{&hf_radiotap_eht_data0_ldpc_extra_symbol_segment_not_known,
		 {"LDPC extra symbol segment",
		  "radiotap.eht.data_0.ldpc_extra_symbol_segment_not_known",
		  FT_BOOLEAN, 32, NULL, 0x00004000, NULL, HFILL }},

		{&hf_radiotap_eht_data0_pre_fec_padding_factor,
		 {"Pre-FEC padding factor",
		  "radiotap.eht.data_0.pre_fec_padding_factor",
		  FT_UINT32, BASE_DEC, NULL, 0x00018000, NULL, HFILL }},

		{&hf_radiotap_eht_data0_pre_fec_padding_factor_not_known,
		 {"Pre-FEC padding factor",
		  "radiotap.eht.data_0.pre_fec_padding_factor_not_known",
		  FT_UINT32, BASE_DEC, NULL, 0x00018000, NULL, HFILL }},

		{&hf_radiotap_eht_data0_pe_disambiguity,
		 {"PE Disambiguity",
		  "radiotap.eht.data_0.pe_disambiguity",
		  FT_UINT32, BASE_DEC, NULL, 0x00020000, NULL, HFILL }},

		{&hf_radiotap_eht_data0_pe_disambiguity_not_known,
		 {"PE Disambiguity",
		  "radiotap.eht.data_0.pe_disambiguity_not_known",
		  FT_UINT32, BASE_DEC, NULL, 0x00020000, NULL, HFILL }},

		{&hf_radiotap_eht_data0_disregard,
		 {"Disregard",
		  "radiotap.eht.data_0.disregard",
		  FT_UINT32, BASE_DEC, NULL, 0x003C0000, NULL, HFILL }},

		{&hf_radiotap_eht_data0_disregard_not_known,
		 {"Disregard",
		  "radiotap.eht.data_0.disregard_not_known",
		  FT_UINT32, BASE_DEC, NULL, 0x003C0000, NULL, HFILL }},

		{&hf_radiotap_eht_data0_crc1,
		 {"CRC1",
		  "radiotap.eht.data_0.crc1",
		  FT_UINT32, BASE_DEC, NULL, 0x03C00000, NULL, HFILL }},

		{&hf_radiotap_eht_data0_crc1_not_known,
		 {"CRC1",
		  "radiotap.eht.data_0.crc1_not_known",
		  FT_UINT32, BASE_DEC, NULL, 0x03C00000, NULL, HFILL }},

		{&hf_radiotap_eht_data0_tail1,
		 {"Tail1",
		  "radiotap.eht.data_0.tail1",
		  FT_UINT32, BASE_DEC, NULL, 0xFC000000, NULL, HFILL }},

		{&hf_radiotap_eht_data0_tail1_not_known,
		 {"Tail1",
		  "radiotap.eht.data_0.tail1_not_known",
		  FT_UINT32, BASE_DEC, NULL, 0xFC000000, NULL, HFILL }},

		{&hf_radiotap_eht_data1,
		 {"data[1]", "radiotap.eht.data_1",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_eht_data1_ru_mru_size,
		 {"RU/MRU Size",
		  "radiotap.eht.data_1.ru_mru_size",
		  FT_UINT32, BASE_DEC, VALS(eht_data_ru_mru_size_vals), 0x0000001F, NULL, HFILL }},

		{&hf_radiotap_eht_data1_ru_mru_size_not_known,
		 {"RU/MRU Size",
		  "radiotap.eht.data_1.ru_mru_size_not_known",
		  FT_UINT32, BASE_DEC, NULL, 0x0000001F, NULL, HFILL }},

		{&hf_radiotap_eht_data1_ru_mru_index,
		 {"RU/MRU index",
		  "radiotap.eht.data_1.ru_mru_index",
		  FT_UINT32, BASE_DEC, NULL, 0x00001FE0, NULL, HFILL }},

		{&hf_radiotap_eht_data1_ru_mru_index_not_known,
		 {"RU/MRU index",
		  "radiotap.eht.data_1.ru_mru_index_not_known",
		  FT_UINT32, BASE_DEC, NULL, 0x00001FE0, NULL, HFILL }},

		{&hf_radiotap_eht_data1_ru_alloc_c1_1_1,
		 {"Content Channel 1 RU Allocation 1::1",
		  "radiotap.eht.data_1.content_channel_1_ru_allocation_1_1",
		  FT_UINT32, BASE_HEX, NULL, 0x003FE000, NULL, HFILL }},

		{&hf_radiotap_eht_data1_ru_alloc_c1_1_1_not_known,
		 {"Content Channel 1 RU Allocation 1::1",
		  "radiotap.eht.data_1.content_channel_1_ru_allocation_1_1_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x003FE000, NULL, HFILL }},

		{&hf_radiotap_eht_data1_ru_alloc_c1_1_1_known,
		 {"Content Channel 1 RU Allocation 1::1 known",
		  "radiotap.eht.data_1.content_channel_1_ru_allocation_1_1_known",
		  FT_BOOLEAN, 32, NULL, 0x00400000, NULL, HFILL }},

		{&hf_radiotap_eht_data1_reserved,
		 {"Reserved",
		  "radiotap.eht.data_1.reserved",
		  FT_UINT32, BASE_HEX, NULL, 0x3f000000, NULL, HFILL }},

		{&hf_radiotap_eht_data1_primary_80_mhz_chan_pos,
		 {"Primary 80 MHz Channel Position",
		  "radiotap.eht.data_1.primary_80_mhz_channel_position",
		  FT_UINT32, BASE_HEX, NULL, 0xc0000000, NULL, HFILL }},

		{&hf_radiotap_eht_data1_primary_80_mhz_chan_pos_not_known,
		 {"Primary 80 MHz Channel Position",
		  "radiotap.eht.data_1.primary_80_mhz_channel_position_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0xc0000000, NULL, HFILL }},

		{&hf_radiotap_eht_data2,
		 {"data[2]", "radiotap.eht.data_2",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_eht_data2_ru_alloc_c2_1_1,
		 {"Content Channel 2 RU Allocation 1::1",
		  "radiotap.eht.data_2.content_channel_2_ru_allocation_1_1",
		  FT_UINT32, BASE_HEX, NULL, 0x000001ff, NULL, HFILL }},

		{&hf_radiotap_eht_data2_ru_alloc_c2_1_1_not_known,
		 {"Content Channel 2 RU Allocation 1::1",
		  "radiotap.eht.data_2.content_channel_2_ru_allocation_1_1_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x000001ff, NULL, HFILL }},

		{&hf_radiotap_eht_data2_ru_alloc_c2_1_1_known,
		 {"Content Channel 2 RU Allocation 1::1 known",
		  "radiotap.eht.data_2.content_channel_2_ru_allocation_1_1_known",
		  FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL }},

		{&hf_radiotap_eht_data2_ru_alloc_c1_1_2,
		 {"Content Channel 1 RU Allocation 1::2",
		  "radiotap.eht.data_2.content_channel_1_ru_allocation_1_2",
		  FT_UINT32, BASE_HEX, NULL, 0x0007fc00, NULL, HFILL }},

		{&hf_radiotap_eht_data2_ru_alloc_c1_1_2_not_known,
		 {"Content Channel 1 RU Allocation 1::2",
		  "radiotap.eht.data_2.content_channel_1_ru_allocation_1_2_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x0007fc00, NULL, HFILL }},

		{&hf_radiotap_eht_data2_ru_alloc_c1_1_2_known,
		 {"Content Channel 1 RU Allocation 1::2 known",
		  "radiotap.eht.data_2.content_channel_1_ru_allocation_1_2_known",
		  FT_BOOLEAN, 32, NULL, 0x00080000, NULL, HFILL }},

		{&hf_radiotap_eht_data2_ru_alloc_c2_1_2,
		 {"Content Channel 2 RU Allocation 1::2",
		  "radiotap.eht.data_2.content_channel_2_ru_allocation_1_2",
		  FT_UINT32, BASE_HEX, NULL, 0x1ff00000, NULL, HFILL }},

		{&hf_radiotap_eht_data2_ru_alloc_c2_1_2_not_known,
		 {"Content Channel 2 RU Allocation 1::2",
		  "radiotap.eht.data_2.content_channel_2_ru_allocation_1_2_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x1ff00000, NULL, HFILL }},

		{&hf_radiotap_eht_data2_ru_alloc_c2_1_2_known,
		 {"Content Channel 2 RU Allocation 1::2 known",
		  "radiotap.eht.data_2.content_channel_2_ru_allocation_1_2_known",
		  FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL }},

		{&hf_radiotap_eht_data2_reserved,
		 {"Reserved", "radiotap.eht.data_2.reserved",
		  FT_UINT32, BASE_HEX, NULL, 0xc0000000, NULL, HFILL }},

		{&hf_radiotap_eht_data3,
		 {"data[3]", "radiotap.eht.data_3",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_eht_data3_ru_alloc_c1_2_1,
		 {"Content Channel 1 RU Allocation 2::1",
		  "radiotap.eht.data_3.content_channel_1_ru_allocation_2_1",
		  FT_UINT32, BASE_HEX, NULL, 0x000001ff, NULL, HFILL }},

		{&hf_radiotap_eht_data3_ru_alloc_c1_2_1_not_known,
		 {"Content Channel 1 RU Allocation 2::1",
		  "radiotap.eht.data_3.content_channel_1_ru_allocation_2_1_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x000001ff, NULL, HFILL }},

		{&hf_radiotap_eht_data3_ru_alloc_c1_2_1_known,
		 {"Content Channel 1 RU Allocation 2::1 known",
		  "radiotap.eht.data_3.content_channel_1_ru_allocation_2_1_known",
		  FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL }},

		{&hf_radiotap_eht_data3_ru_alloc_c2_2_1,
		 {"Content Channel 2 RU Allocation 2::1",
		  "radiotap.eht.data_3.content_channel_2_ru_allocation_2_1",
		  FT_UINT32, BASE_HEX, NULL, 0x0007fc00, NULL, HFILL }},

		{&hf_radiotap_eht_data3_ru_alloc_c2_2_1_not_known,
		 {"Content Channel 2 RU Allocation 2::1",
		  "radiotap.eht.data_3.content_channel_2_ru_allocation_2_1_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x0007fc00, NULL, HFILL }},

		{&hf_radiotap_eht_data3_ru_alloc_c2_2_1_known,
		 {"Content Channel 2 RU Allocation 2::1 known",
		  "radiotap.eht.data_3.content_channel_2_ru_allocation_2_1_known",
		  FT_BOOLEAN, 32, NULL, 0x00080000, NULL, HFILL }},

		{&hf_radiotap_eht_data3_ru_alloc_c1_2_2,
		 {"Content Channel 1 RU Allocation 2::2",
		  "radiotap.eht.data_3.content_channel_1_ru_allocation_2_2",
		  FT_UINT32, BASE_HEX, NULL, 0x1ff00000, NULL, HFILL }},

		{&hf_radiotap_eht_data3_ru_alloc_c1_2_2_not_known,
		 {"Content Channel 1 RU Allocation 2::2",
		  "radiotap.eht.data_3.content_channel_1_ru_allocation_2_2_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x1ff00000, NULL, HFILL }},

		{&hf_radiotap_eht_data3_ru_alloc_c1_2_2_known,
		 {"Content Channel 1 RU Allocation 2::2 known",
		  "radiotap.eht.data_3.content_channel_1_ru_allocation_2_2_known",
		  FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL }},

		{&hf_radiotap_eht_data3_reserved,
		 {"Reserved", "radiotap.eht.data_3.reserved",
		  FT_UINT32, BASE_HEX, NULL, 0xc0000000, NULL, HFILL }},

		{&hf_radiotap_eht_data4,
		 {"data[4]", "radiotap.eht.data_4",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_eht_data4_ru_alloc_c2_2_2,
		 {"Content Channel 2 RU Allocation 2::2",
		  "radiotap.eht.data_4.content_channel_2_ru_allocation_2_2",
		  FT_UINT32, BASE_HEX, NULL, 0x000001ff, NULL, HFILL }},

		{&hf_radiotap_eht_data4_ru_alloc_c2_2_2_not_known,
		 {"Content Channel 2 RU Allocation 2::2",
		  "radiotap.eht.data_4.content_channel_2_ru_allocation_2_2_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x000001ff, NULL, HFILL }},

		{&hf_radiotap_eht_data4_ru_alloc_c2_2_2_known,
		 {"Content Channel 2 RU Allocation 2::2 known",
		  "radiotap.eht.data_4.content_channel_2_ru_allocation_2_2_known",
		  FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL }},

		{&hf_radiotap_eht_data4_ru_alloc_c1_2_3,
		 {"Content Channel 1 RU Allocation 2::3",
		  "radiotap.eht.data_4.content_channel_1_ru_allocation_2_3",
		  FT_UINT32, BASE_HEX, NULL, 0x0007fc00, NULL, HFILL }},

		{&hf_radiotap_eht_data4_ru_alloc_c1_2_3_not_known,
		 {"Content Channel 1 RU Allocation 2::3",
		  "radiotap.eht.data_4.content_channel_1_ru_allocation_2_3_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x0007fc00, NULL, HFILL }},

		{&hf_radiotap_eht_data4_ru_alloc_c1_2_3_known,
		 {"Content Channel 1 RU Allocation 2::3 known",
		  "radiotap.eht.data_4.content_channel_1_ru_allocation_2_3_known",
		  FT_BOOLEAN, 32, NULL, 0x00080000, NULL, HFILL }},

		{&hf_radiotap_eht_data4_ru_alloc_c2_2_3,
		 {"Content Channel 2 RU Allocation 2::3",
		  "radiotap.eht.data_4.content_channel_2_ru_allocation_2_3",
		  FT_UINT32, BASE_HEX, NULL, 0x1ff00000, NULL, HFILL }},

		{&hf_radiotap_eht_data4_ru_alloc_c2_2_3_not_known,
		 {"Content Channel 2 RU Allocation 2::3",
		  "radiotap.eht.data_4.content_channel_2_ru_allocation_2_3_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x1ff00000, NULL, HFILL }},

		{&hf_radiotap_eht_data4_ru_alloc_c2_2_3_known,
		 {"Content Channel 2 RU Allocation 2::3 known",
		  "radiotap.eht.data_4.content_channel_2_ru_allocation_2_3_known",
		  FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL }},

		{&hf_radiotap_eht_data4_reserved,
		 {"Reserved", "radiotap.eht.data_4.reserved",
		  FT_UINT32, BASE_HEX, NULL, 0xc0000000, NULL, HFILL }},

		{&hf_radiotap_eht_data5,
		 {"data[5]", "radiotap.eht.data_5",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_eht_data5_ru_alloc_c1_2_4,
		 {"Content Channel 1 RU Allocation 2::4",
		  "radiotap.eht.data_5.content_channel_1_ru_allocation_2_4",
		  FT_UINT32, BASE_HEX, NULL, 0x000001ff, NULL, HFILL }},

		{&hf_radiotap_eht_data5_ru_alloc_c1_2_4_not_known,
		 {"Content Channel 1 RU Allocation 2::4",
		  "radiotap.eht.data_5.content_channel_1_ru_allocation_2_4_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x000001ff, NULL, HFILL }},

		{&hf_radiotap_eht_data5_ru_alloc_c1_2_4_known,
		 {"Content Channel 1 RU Allocation 2::4 known",
		  "radiotap.eht.data_5.content_channel_1_ru_allocation_2_4_known",
		  FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL }},

		{&hf_radiotap_eht_data5_ru_alloc_c2_2_4,
		 {"Content Channel 2 RU Allocation 2::4",
		  "radiotap.eht.data_5.content_channel_2_ru_allocation_2_4",
		  FT_UINT32, BASE_HEX, NULL, 0x0007fc00, NULL, HFILL }},

		{&hf_radiotap_eht_data5_ru_alloc_c2_2_4_not_known,
		 {"Content Channel 2 RU Allocation 2::4",
		  "radiotap.eht.data_5.content_channel_2_ru_allocation_2_4_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x0007fc00, NULL, HFILL }},

		{&hf_radiotap_eht_data5_ru_alloc_c2_2_4_known,
		 {"Content Channel 2 RU Allocation 2::4 known",
		  "radiotap.eht.data_5.content_channel_2_ru_allocation_2_4_known",
		  FT_BOOLEAN, 32, NULL, 0x00080000, NULL, HFILL }},

		{&hf_radiotap_eht_data5_ru_alloc_c1_2_5,
		 {"Content Channel 1 RU Allocation 2::5",
		  "radiotap.eht.data_5.content_channel_1_ru_allocation_2_5",
		  FT_UINT32, BASE_HEX, NULL, 0x1ff00000, NULL, HFILL }},

		{&hf_radiotap_eht_data5_ru_alloc_c1_2_5_not_known,
		 {"Content Channel 1 RU Allocation 2::5",
		  "radiotap.eht.data_5.content_channel_1_ru_allocation_2_5_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x1ff00000, NULL, HFILL }},

		{&hf_radiotap_eht_data5_ru_alloc_c1_2_5_known,
		 {"Content Channel 1 RU Allocation 2::5 known",
		  "radiotap.eht.data_5.content_channel_1_ru_allocation_2_5_known",
		  FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL }},

		{&hf_radiotap_eht_data5_reserved,
		 {"Reserved", "radiotap.eht.data_5.reserved",
		  FT_UINT32, BASE_HEX, NULL, 0xc0000000, NULL, HFILL }},

		{&hf_radiotap_eht_data6,
		 {"data[6]", "radiotap.eht.data_6",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_eht_data6_ru_alloc_c2_2_5,
		 {"Content Channel 2 RU Allocation 2::5",
		  "radiotap.eht.data_6.content_channel_2_ru_allocation_2_5",
		  FT_UINT32, BASE_HEX, NULL, 0x000001ff, NULL, HFILL }},

		{&hf_radiotap_eht_data6_ru_alloc_c2_2_5_not_known,
		 {"Content Channel 2 RU Allocation 2::5",
		  "radiotap.eht.data_6.content_channel_2_ru_allocation_2_5_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x000001ff, NULL, HFILL }},

		{&hf_radiotap_eht_data6_ru_alloc_c2_2_5_known,
		 {"Content Channel 2 RU Allocation 2::5 known",
		  "radiotap.eht.data_6.content_channel_2_ru_allocation_2_5_known",
		  FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL }},

		{&hf_radiotap_eht_data6_ru_alloc_c1_2_6,
		 {"Content Channel 1 RU Allocation 2::6",
		  "radiotap.eht.data_6.content_channel_1_ru_allocation_2_6",
		  FT_UINT32, BASE_HEX, NULL, 0x0007fc00, NULL, HFILL }},

		{&hf_radiotap_eht_data6_ru_alloc_c1_2_6_not_known,
		 {"Content Channel 1 RU Allocation 2::6",
		  "radiotap.eht.data_6.content_channel_1_ru_allocation_2_6_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x0007fc00, NULL, HFILL }},

		{&hf_radiotap_eht_data6_ru_alloc_c1_2_6_known,
		 {"Content Channel 1 RU Allocation 2::6 known",
		  "radiotap.eht.data_6.content_channel_1_ru_allocation_2_6_known",
		  FT_BOOLEAN, 32, NULL, 0x00080000, NULL, HFILL }},

		{&hf_radiotap_eht_data6_ru_alloc_c2_2_6,
		 {"Content Channel 2 RU Allocation 2::6",
		  "radiotap.eht.data_6.content_channel_2_ru_allocation_2_6",
		  FT_UINT32, BASE_HEX, NULL, 0x1ff00000, NULL, HFILL }},

		{&hf_radiotap_eht_data6_ru_alloc_c2_2_6_not_known,
		 {"Content Channel 2 RU Allocation 2::6",
		  "radiotap.eht.data_6.content_channel_2_ru_allocation_2_6_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x1ff00000, NULL, HFILL }},

		{&hf_radiotap_eht_data6_ru_alloc_c2_2_6_known,
		 {"Content Channel 2 RU Allocation 2::6 known",
		  "radiotap.eht.data_6.content_channel_2_ru_allocation_2_6_known",
		  FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL }},

		{&hf_radiotap_eht_data6_reserved,
		 {"Reserved", "radiotap.eht.data_6.reserved",
		  FT_UINT32, BASE_HEX, NULL, 0xc0000000, NULL, HFILL }},

		{&hf_radiotap_eht_data7,
		 {"data[7]", "radiotap.eht.data_7",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_eht_data7_crc2,
		 {"CRC2 (OFDMA Only: For RU Allocation-2)",
		  "radiotap.eht.data_7.crc2",
		  FT_UINT32, BASE_HEX, NULL, 0x0000000f, NULL, HFILL }},

		{&hf_radiotap_eht_data7_tail2,
		 {"Tail2 (OFDMA Only: after RU Allocation-2)",
		  "radiotap.eht.data_7.tail2",
		  FT_UINT32, BASE_HEX, NULL, 0x000003f0, NULL, HFILL }},

		{&hf_radiotap_eht_data7_rsvd,
		 {"reserved", "radiotap.eht.data_7.reserved1",
		  FT_UINT32, BASE_HEX, NULL, 0x00000c00, NULL, HFILL }},

		{&hf_radiotap_eht_data7_nss,
		 {"NSS (EHT sounding)", "radiotap.eht.data_7.nss_eht_sounding",
		  FT_UINT32, BASE_HEX, NULL, 0x0000f000, NULL, HFILL }},

		{&hf_radiotap_eht_data7_beamformed,
		 {"Beamformed (EHT sounding)",
		  "radiotap.eht.data_7.beamformed_eht_sounding",
		  FT_BOOLEAN, 32, NULL, 0x00010000, NULL, HFILL }},

		{&hf_radiotap_eht_data7_number_non_ofdma_users,
		 {"Number Of Non-OFDMA Users",
		  "radiotap.eht.data_7.number_of_non_ofdma_users",
		  FT_UINT32, BASE_DEC, NULL, 0x000e0000, NULL, HFILL }},

		{&hf_radiotap_eht_data7_number_non_ofdma_users_not_known,
		 {"Number Of Non-OFDMA Users",
		  "radiotap.eht.data_7.number_of_non_ofdma_users_not_known",
		  FT_UINT32, BASE_DEC, NULL, 0x000e0000, NULL, HFILL }},

		{&hf_radiotap_eht_data7_user_encode_crc,
		 {"User Encoding Block CRC",
		  "radiotap.eht.data_7.user_encoding_block_crc",
		  FT_UINT32, BASE_HEX, NULL, 0x00f00000, NULL, HFILL }},

		{&hf_radiotap_eht_data7_user_encode_tail,
		 {"User Encoding Block Tail",
		  "radiotap.eht.data_7.user_encoding_block_tail",
		  FT_UINT32, BASE_HEX, NULL, 0x3f000000, NULL, HFILL }},

		{&hf_radiotap_eht_data7_rsvd2,
		 {"Reserved", "radiotap.eht.data_7.reserved2",
		  FT_UINT32, BASE_HEX, NULL, 0xC0000000, NULL, HFILL }},

		{&hf_radiotap_eht_data8,
		 {"data[8]", "radiotap.eht.data_8",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_eht_data8_ru_alloc_ps_160,
		 {"RU Allocation (TB Format): PS 160",
		  "radiotap.eht.data_8.ru_allocation_tb_format_ps_160",
		  FT_UINT32, BASE_HEX, NULL, 0x00000001, NULL, HFILL }},

		{&hf_radiotap_eht_data8_ru_alloc_b0,
		 {"RU Allocation (TB Format): B0",
		  "radiotap.eht.data_8.ru_allocation_tb_format_b0",
		  FT_UINT32, BASE_HEX, NULL, 0x00000002, NULL, HFILL }},

		{&hf_radiotap_eht_data8_ru_alloc_b7_b1,
		 {"RU Allocation (TB Format): B7-B1",
		  "radiotap.eht.data_8.ru_allocation_tb_format_b7_b1",
		  FT_UINT32, BASE_HEX, NULL, 0x000001fc, NULL, HFILL }},

		{&hf_radiotap_eht_data8_rsvd,
		 {"Reserved",
		  "radiotap.eht.data_8.reserved1",
		  FT_UINT32, BASE_HEX, NULL, 0xfffffe00, NULL, HFILL }},

		{&hf_radiotap_eht_user_info,
		 {"user_info", "radiotap.eht.user_info",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{&hf_radiotap_eht_ui_sta_id_known,
		 {"STA-ID known", "radiotap.eht.user_info.sta_id_known",
		  FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL }},

		{&hf_radiotap_eht_ui_mcs_known,
		 {"MCS known", "radiotap.eht.user_info.mcs_known",
		  FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL }},

		{&hf_radiotap_eht_ui_coding_known,
		 {"Coding known", "radiotap.eht.user_info.coding_known",
		  FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL }},

		{&hf_radiotap_eht_ui_rsvd_known,
		 {"Reserved known", "radiotap.eht.user_info.reserved_known",
		  FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL }},

		{&hf_radiotap_eht_ui_nss_known,
		 {"NSS known", "radiotap.eht.user_info.nss_known",
		  FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL }},

		{&hf_radiotap_eht_ui_beamforming_known,
		 {"Beamforming known",
		  "radiotap.eht.user_info.beamforming_known",
		  FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL }},

		{&hf_radiotap_eht_ui_spatial_config_known,
		 {"Spatial Configuration known",
		  "radiotap.eht.user_info.spatial_configuration_known",
		  FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL }},

		{&hf_radiotap_eht_ui_data_captured,
		 {"Data captured for this user",
		  "radiotap.eht.user_info.data_captured_for_this_user",
		  FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL }},

		{&hf_radiotap_eht_ui_sta_id,
		 {"STA-ID", "radiotap.eht.user_info.sta_id",
		  FT_UINT32, BASE_HEX, NULL, 0x0007ff00, NULL, HFILL }},

		{&hf_radiotap_eht_ui_sta_id_not_known,
		 {"STA-ID", "radiotap.eht.user_info.sta_id_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x0007ff00, NULL, HFILL }},

		{&hf_radiotap_eht_ui_coding,
		 {"Coding", "radiotap.eht.user_info.coding",
		  FT_UINT32, BASE_HEX, VALS(he_coding_vals), 0x00080000, NULL, HFILL }},

		{&hf_radiotap_eht_ui_coding_not_known,
		 {"Coding", "radiotap.eht.user_info.coding_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x00080000, NULL, HFILL }},

		{&hf_radiotap_eht_ui_mcs,
		 {"MCS", "radiotap.eht.user_info.mcs",
		  FT_UINT32, BASE_HEX, NULL, 0x00f00000, NULL, HFILL }},

		{&hf_radiotap_eht_ui_mcs_not_known,
		 {"MCS", "radiotap.eht.user_info.mcs_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x00f00000, NULL, HFILL }},

		{&hf_radiotap_eht_ui_nss,
		 {"NSS", "radiotap.eht.user_info.nss",
		  FT_UINT32, BASE_HEX, NULL, 0x0f000000, NULL, HFILL }},

		{&hf_radiotap_eht_ui_nss_not_known,
		 {"NSS", "radiotap.eht.user_info.nss_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x0f000000, NULL, HFILL }},

		{&hf_radiotap_eht_ui_reserved,
		 {"Reserved", "radiotap.eht.user_info.reserved",
		  FT_UINT32, BASE_HEX, NULL, 0x10000000, NULL, HFILL }},

		{&hf_radiotap_eht_ui_reserved_not_known,
		 {"Reserved", "radiotap.eht.user_info.reserved_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x10000000, NULL, HFILL }},

		{&hf_radiotap_eht_ui_beamforming,
		 {"Beamforming", "radiotap.eht.user_info.beamforming",
		  FT_UINT32, BASE_HEX, NULL, 0x20000000, NULL, HFILL }},

		{&hf_radiotap_eht_ui_beamforming_not_known,
		 {"Beamforming", "radiotap.eht.user_info.beamforming_not_known",
		  FT_UINT32, BASE_HEX, NULL, 0x20000000, NULL, HFILL }},

		{&hf_radiotap_eht_ui_spatial_config,
		 {"Spatial Configuration",
		  "radiotap.eht.user_info.spatial_configuration",
		  FT_UINT32, BASE_HEX, NULL, 0x3f000000, NULL, HFILL }},

		{&hf_radiotap_eht_ui_rsvd1,
		 {"Reserved", "radiotap.eht.user_info.reserved1",
		  FT_UINT32, BASE_HEX, NULL, 0xc0000000, NULL, HFILL }},

		{&hf_radiotap_s1g_known,
		 {"Known", "radiotap.s1g.known",
		  FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},

		{&hf_radiotap_s1g_s1g_ppdu_format_known,
		 {"S1G PPDU Format Known", "radiotap.s1g.s1g_ppdu_format_known",
		  FT_BOOLEAN, 16, NULL,
		  IEEE80211_RADIOTAP_TLV_S1G_S1G_PPDU_FORMAT_KNOWN, NULL, HFILL}},

		{&hf_radiotap_s1g_response_indication_known,
		 {"Response Indication Known", "radiotap.s1g.response_indication_known",
		  FT_BOOLEAN, 16, NULL,
		  IEEE80211_RADIOTAP_TLV_S1G_RESPONSE_INDICATION_KNOWN, NULL, HFILL}},

		{&hf_radiotap_s1g_guard_interval_known,
		 {"Guard Interval Known", "radiotap.s1g.guard_interval_known",
		  FT_BOOLEAN, 16, NULL,
		  IEEE80211_RADIOTAP_TLV_S1G_GUARD_INTERVAL_KNOWN, NULL, HFILL}},

		{&hf_radiotap_s1g_nss_known,
		 {"NSS Known", "radiotap.s1g.nss_known",
		  FT_BOOLEAN, 16, NULL,
		  IEEE80211_RADIOTAP_TLV_S1G_NSS_KNOWN, NULL, HFILL}},

		{&hf_radiotap_s1g_bandwidth_known,
		 {"Bandwidth Known", "radiotap.s1g.bandwidth_known",
		  FT_BOOLEAN, 16, NULL,
		  IEEE80211_RADIOTAP_TLV_S1G_BANDWIDTH_KNOWN, NULL, HFILL}},

		{&hf_radiotap_s1g_mcs_known,
		 {"MCS Known", "radiotap.s1g.mcs_known",
		  FT_BOOLEAN, 16, NULL,
		  IEEE80211_RADIOTAP_TLV_S1G_MCS_KNOWN, NULL, HFILL}},

		{&hf_radiotap_s1g_color_known,
		 {"Color Known", "radiotap.s1g.color_known",
		  FT_BOOLEAN, 16, NULL,
		  IEEE80211_RADIOTAP_TLV_S1G_COLOR_KNOWN, NULL, HFILL}},

		{&hf_radiotap_s1g_uplink_indication_known,
		 {"Uplink Indication Known",
		  "radiotap.s1g.uplink_indication_known",
		  FT_BOOLEAN, 16, NULL,
		  IEEE80211_RADIOTAP_TLV_S1G_UPLINK_INDICATION_KNOWN,
		  NULL, HFILL}},

		{&hf_radiotap_s1g_reserved_1,
		 {"Reserved 1", "radiotap.s1g.reserved_1",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_TLV_S1G_RESERVED_1, NULL, HFILL}},

		{&hf_radiotap_s1g_data_1,
		 {"Data1", "radiotap.s1g.data_1",
		  FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},

		{&hf_radiotap_s1g_s1g_ppdu_format,
		 {"S1G PPDU Format", "radiotap.s1g.s1g_ppdu_format",
		  FT_UINT16, BASE_DEC, VALS(s1g_ppdu_format),
		  IEEE80211_RADIOTAP_TLV_S1G_S1G_PPDU_FORMAT, NULL, HFILL}},

		{&hf_radiotap_s1g_response_indication,
		 {"Response Indication", "radiotap.s1g.response_indication",
		  FT_UINT16, BASE_DEC, VALS(s1g_response_indication),
		  IEEE80211_RADIOTAP_TLV_S1G_RESPONSE_INDICATION, NULL, HFILL}},

		{&hf_radiotap_s1g_reserved_2,
		 {"Reserved 2", "radiotap.s1g.reserved_2",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_TLV_S1G_RESERVED_2, NULL, HFILL}},

		{&hf_radiotap_s1g_guard_interval,
		 {"Guard Interval", "radiotap.s1g.guard_interval",
		  FT_UINT16, BASE_DEC, VALS(s1g_guard_interval),
		  IEEE80211_RADIOTAP_TLV_S1G_GUARD_INTERVAL, NULL, HFILL}},

		{&hf_radiotap_s1g_nss,
		 {"NSS", "radiotap.s1g.nss",
		  FT_UINT16, BASE_DEC, VALS(s1g_nss),
		  IEEE80211_RADIOTAP_TLV_S1G_NSS, NULL, HFILL}},

		{&hf_radiotap_s1g_bandwidth,
		 {"Bandwidth", "radiotap.s1g.bandwidth",
		  FT_UINT16, BASE_DEC, VALS(s1g_bandwidth),
		 IEEE80211_RADIOTAP_TLV_S1G_BANDWIDTH, NULL, HFILL}},

		{&hf_radiotap_s1g_mcs,
		 {"MCS", "radiotap.s1g.mcs",
		  FT_UINT16, BASE_DEC, VALS(s1g_mcs),
		  IEEE80211_RADIOTAP_TLV_S1G_MCS, NULL, HFILL}},

		{&hf_radiotap_s1g_data_2,
		 {"Data2", "radiotap.s1g.data_2",
		  FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},

		{&hf_radiotap_s1g_color,
		 {"Color", "radiotap.s1g.color",
		  FT_UINT16, BASE_DEC, VALS(s1g_color),
		  IEEE80211_RADIOTAP_TLV_S1G_COLOR, NULL, HFILL}},

		{&hf_radiotap_s1g_uplink_indication,
		 {"Uplink Indication", "radiotap.s1g.uplink_indication",
		  FT_BOOLEAN, 16, NULL,
		  IEEE80211_RADIOTAP_TLV_S1G_UPLINK_INDICATION, NULL, HFILL}},

		{&hf_radiotap_s1g_reserved_3,
		 {"Reserved 3", "radiotap.s1g.reserved_3",
		  FT_UINT16, BASE_HEX, NULL,
		  IEEE80211_RADIOTAP_TLV_S1G_RESERVED_3, NULL, HFILL}},

		{&hf_radiotap_s1g_rssi,
		 {"RSSI", "radiotap.s1g.rssi",
		  FT_INT16, BASE_DEC, NULL,
		  IEEE80211_RADIOTAP_TLV_S1G_RSSI, NULL, HFILL}},
	};
	static int *ett[] = {
		&ett_radiotap,
		&ett_radiotap_tlv,
		&ett_radiotap_present,
		&ett_radiotap_present_word,
		&ett_radiotap_flags,
		&ett_radiotap_rxflags,
		&ett_radiotap_txflags,
		&ett_radiotap_channel_flags,
		&ett_radiotap_xchannel_flags,
		&ett_radiotap_vendor,
		&ett_radiotap_mcs,
		&ett_radiotap_mcs_known,
		&ett_radiotap_ampdu,
		&ett_radiotap_ampdu_flags,
		&ett_radiotap_vht,
		&ett_radiotap_vht_known,
		&ett_radiotap_vht_user,
		&ett_radiotap_timestamp,
		&ett_radiotap_timestamp_flags,
		&ett_radiotap_he_info,
		&ett_radiotap_he_info_data_1,
		&ett_radiotap_he_info_data_2,
		&ett_radiotap_he_info_data_3,
		&ett_radiotap_he_info_data_4,
		&ett_radiotap_he_info_data_5,
		&ett_radiotap_he_info_data_6,
		&ett_radiotap_he_mu_info,
		&ett_radiotap_he_mu_info_flags_1,
		&ett_radiotap_he_mu_info_flags_2,
		&ett_radiotap_he_mu_chan_rus,
		&ett_radiotap_0_length_psdu,
		&ett_radiotap_l_sig,
		&ett_radiotap_l_sig_data_1,
		&ett_radiotap_l_sig_data_2,
		&ett_radiotap_u_sig,
		&ett_radiotap_u_sig_common,
		&ett_radiotap_u_sig_value,
		&ett_radiotap_eht,
		&ett_radiotap_eht_known,
		&ett_radiotap_eht_data,
		&ett_radiotap_eht_user_info,
		&ett_radiotap_eht_user_info_i,
		&ett_radiotap_s1g,
		&ett_radiotap_s1g_known,
		&ett_radiotap_s1g_data_1,
		&ett_radiotap_s1g_data_2,
		&ett_radiotap_unknown_tlv,
	};
	static ei_register_info ei[] = {
		{ &ei_radiotap_invalid_header_length, { "radiotap.length.invalid", PI_MALFORMED, PI_ERROR, "The radiotap header length is less than 8 bytes", EXPFILL }},
		{ &ei_radiotap_present, { "radiotap.present.radiotap_and_vendor", PI_MALFORMED, PI_ERROR, "Both radiotap and vendor namespace specified in bitmask word", EXPFILL }},
		{ &ei_radiotap_data_past_header, { "radiotap.data_past_header", PI_MALFORMED, PI_ERROR, "Radiotap data goes past the end of the radiotap header", EXPFILL }},
		{ &ei_radiotap_invalid_data_rate, { "radiotap.vht.datarate.invalid", PI_PROTOCOL, PI_WARN, "Data rate invalid", EXPFILL }},
	};

	module_t *radiotap_module;
	expert_module_t* expert_radiotap;

	proto_radiotap =
	    proto_register_protocol("IEEE 802.11 Radiotap Capture header", "802.11 Radiotap", "radiotap");
	proto_register_field_array(proto_radiotap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_radiotap = expert_register_protocol(proto_radiotap);
	expert_register_field_array(expert_radiotap, ei, array_length(ei));
	register_dissector("radiotap", dissect_radiotap, proto_radiotap);

	/* Subdissector table for vendor namespace, the key is OUI with sub namespace (4 bytes) */
	vendor_dissector_table = register_dissector_table("radiotap.vendor",
		"Vendor namespace", proto_radiotap, FT_UINT32, BASE_HEX);

	radiotap_module = prefs_register_protocol(proto_radiotap, NULL);
	prefs_register_bool_preference(radiotap_module, "bit14_fcs_in_header",
				       "Assume bit 14 means FCS in header",
				       "Radiotap has a bit to indicate whether the FCS is still on the frame or not. "
				       "Some generators (e.g. AirPcap) use a non-standard radiotap flag 14 to put "
				       "the FCS into the header.",
				       &radiotap_bit14_fcs);

	prefs_register_bool_preference(radiotap_module, "interpret_high_rates_as_mcs",
				       "Interpret high rates as MCS",
				       "Some generators use rates with bit 7 set to indicate an MCS, e.g. BSD. "
					   "others (Linux, AirPcap) do not.",
				       &radiotap_interpret_high_rates_as_mcs);

	prefs_register_enum_preference(radiotap_module, "fcs_handling",
				       "Whether and how to override the FCS bit",
				       "Whether to use the FCS bit, assume the FCS is always present, "
					   "or assume the FCS is never present.",
				       &radiotap_fcs_handling,
				       fcs_handling, false);
}

void proto_reg_handoff_radiotap(void)
{
	dissector_handle_t radiotap_handle;
	capture_dissector_handle_t radiotap_cap_handle;

	/* handle for 802.11+radio information dissector */
	ieee80211_radio_handle = find_dissector_add_dependency("wlan_radio", proto_radiotap);

	radiotap_handle = find_dissector_add_dependency("radiotap", proto_radiotap);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_RADIOTAP,
			   radiotap_handle);

	/*
	 * The radiotap and 802.11 headers aren't stripped off for
	 * monitor-mode packets in Linux cooked captures, so dissect
	 * those frames.
	 */
	dissector_add_uint("sll.hatype", ARPHRD_IEEE80211_RADIOTAP,
			   radiotap_handle);

	radiotap_cap_handle = create_capture_dissector_handle(capture_radiotap, proto_radiotap);
	capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_RADIOTAP, radiotap_cap_handle);

	ieee80211_cap_handle = find_capture_dissector("ieee80211");
	ieee80211_datapad_cap_handle = find_capture_dissector("ieee80211_datapad");
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
