/* Routines for LTE MAC disassembly
 *
 * Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/uat.h>
#include <epan/proto_data.h>
#include "packet-mac-lte.h"
#include "packet-rlc-lte.h"

void proto_register_mac_lte(void);
void proto_reg_handoff_mac_lte(void);

/* Described in:
 * 3GPP TS 36.321 Evolved Universal Terrestrial Radio Access (E-UTRA)
 *                Medium Access Control (MAC) protocol specification v14.3.0
 */

/* TODO:
 * - use proto_tree_add_bitmask..() APIs for sets of bits where possible
 */

/* Initialize the protocol and registered fields. */
int proto_mac_lte;

static int mac_lte_tap;

static dissector_handle_t rlc_lte_handle;
static dissector_handle_t lte_rrc_bcch_dl_sch_handle;
static dissector_handle_t lte_rrc_bcch_dl_sch_br_handle;
static dissector_handle_t lte_rrc_bcch_dl_sch_nb_handle;
static dissector_handle_t lte_rrc_bcch_bch_handle;
static dissector_handle_t lte_rrc_bcch_bch_nb_handle;
static dissector_handle_t lte_rrc_pcch_handle;
static dissector_handle_t lte_rrc_pcch_nb_handle;
static dissector_handle_t lte_rrc_ul_ccch_handle;
static dissector_handle_t lte_rrc_ul_ccch_nb_handle;
static dissector_handle_t lte_rrc_dl_ccch_handle;
static dissector_handle_t lte_rrc_dl_ccch_nb_handle;
static dissector_handle_t lte_rrc_sbcch_sl_bch_handle;
static dissector_handle_t lte_rrc_sc_mcch_handle;


/* Decoding context */
static int hf_mac_lte_context;
static int hf_mac_lte_context_radio_type;
static int hf_mac_lte_context_direction;
static int hf_mac_lte_context_rnti;
static int hf_mac_lte_context_rnti_type;
static int hf_mac_lte_context_ueid;
static int hf_mac_lte_context_sysframe_number;
static int hf_mac_lte_context_subframe_number;
static int hf_mac_lte_context_grant_subframe_number;
static int hf_mac_lte_context_predefined_frame;
static int hf_mac_lte_context_length;
static int hf_mac_lte_context_ul_grant_size;
static int hf_mac_lte_context_bch_transport_channel;
static int hf_mac_lte_context_retx_count;
static int hf_mac_lte_context_retx_reason;
static int hf_mac_lte_context_crc_status;
static int hf_mac_lte_context_carrier_id;

static int hf_mac_lte_context_rapid;
static int hf_mac_lte_context_rach_attempt_number;

/* Inferred context */
static int hf_mac_lte_ues_ul_per_tti;
static int hf_mac_lte_ues_dl_per_tti;


/* Extra PHY context */
static int hf_mac_lte_context_phy_ul;
static int hf_mac_lte_context_phy_ul_modulation_type;
static int hf_mac_lte_context_phy_ul_tbs_index;
static int hf_mac_lte_context_phy_ul_resource_block_length;
static int hf_mac_lte_context_phy_ul_resource_block_start;
static int hf_mac_lte_context_phy_ul_harq_id;
static int hf_mac_lte_context_phy_ul_ndi;

static int hf_mac_lte_context_phy_dl;
static int hf_mac_lte_context_phy_dl_dci_format;
static int hf_mac_lte_context_phy_dl_resource_allocation_type;
static int hf_mac_lte_context_phy_dl_aggregation_level;
static int hf_mac_lte_context_phy_dl_mcs_index;
static int hf_mac_lte_context_phy_dl_redundancy_version_index;
static int hf_mac_lte_context_phy_dl_retx;
static int hf_mac_lte_context_phy_dl_resource_block_length;
static int hf_mac_lte_context_phy_dl_harq_id;
static int hf_mac_lte_context_phy_dl_ndi;
static int hf_mac_lte_context_phy_dl_tb;


/* Out-of-band events */
static int hf_mac_lte_oob_send_preamble;
static int hf_mac_lte_number_of_srs;

/* MAC SCH/MCH header fields */
static int hf_mac_lte_ulsch;
static int hf_mac_lte_ulsch_header;
static int hf_mac_lte_dlsch;
static int hf_mac_lte_dlsch_header;
static int hf_mac_lte_sch_subheader;
static int hf_mac_lte_mch;
static int hf_mac_lte_mch_header;
static int hf_mac_lte_mch_subheader;
static int hf_mac_lte_slsch;
static int hf_mac_lte_slsch_header;
static int hf_mac_lte_slsch_subheader;

static int hf_mac_lte_sch_reserved;
static int hf_mac_lte_sch_format2;
static int hf_mac_lte_lcid;
static int hf_mac_lte_dlsch_lcid;
static int hf_mac_lte_ulsch_lcid;
static int hf_mac_lte_sch_extended;
static int hf_mac_lte_sch_format;
static int hf_mac_lte_sch_reserved2;
static int hf_mac_lte_sch_elcid;
static int hf_mac_lte_sch_length;
static int hf_mac_lte_mch_reserved;
static int hf_mac_lte_mch_format2;
static int hf_mac_lte_mch_lcid;
static int hf_mac_lte_mch_extended;
static int hf_mac_lte_mch_format;
static int hf_mac_lte_mch_length;
static int hf_mac_lte_slsch_version;
static int hf_mac_lte_slsch_reserved;
static int hf_mac_lte_slsch_src_l2_id;
static int hf_mac_lte_slsch_dst_l2_id;
static int hf_mac_lte_slsch_dst_l2_id2;
static int hf_mac_lte_slsch_reserved2;
static int hf_mac_lte_slsch_extended;
static int hf_mac_lte_slsch_lcid;
static int hf_mac_lte_slsch_format;
static int hf_mac_lte_slsch_length;

static int hf_mac_lte_sch_header_only;
static int hf_mac_lte_mch_header_only;
static int hf_mac_lte_slsch_header_only;

/* Data */
static int hf_mac_lte_sch_sdu;
static int hf_mac_lte_mch_sdu;
static int hf_mac_lte_bch_pdu;
static int hf_mac_lte_pch_pdu;
static int hf_mac_lte_slbch_pdu;
static int hf_mac_lte_slsch_sdu;
static int hf_mac_lte_predefined_pdu;
static int hf_mac_lte_raw_pdu;
static int hf_mac_lte_padding_data;
static int hf_mac_lte_padding_length;


/* RAR fields */
static int hf_mac_lte_rar;
static int hf_mac_lte_rar_headers;
static int hf_mac_lte_rar_header;
static int hf_mac_lte_rar_extension;
static int hf_mac_lte_rar_t;
static int hf_mac_lte_rar_bi;
static int hf_mac_lte_rar_bi_nb;
static int hf_mac_lte_rar_rapid;
static int hf_mac_lte_rar_no_of_rapids;
static int hf_mac_lte_rar_reserved;
static int hf_mac_lte_rar_body;
static int hf_mac_lte_rar_reserved2;
static int hf_mac_lte_rar_ta;
static int hf_mac_lte_rar_ul_grant_ce_mode_b;
static int hf_mac_lte_rar_ul_grant;
static int hf_mac_lte_rar_ul_grant_hopping;
static int hf_mac_lte_rar_ul_grant_fsrba;
static int hf_mac_lte_rar_ul_grant_tmcs;
static int hf_mac_lte_rar_ul_grant_tcsp;
static int hf_mac_lte_rar_ul_grant_ul_delay;
static int hf_mac_lte_rar_ul_grant_cqi_request;
static int hf_mac_lte_rar_ul_grant_msg3_pusch_nb_idx_ce_mode_a;
static int hf_mac_lte_rar_ul_grant_msg3_pusch_res_alloc_ce_mode_a;
static int hf_mac_lte_rar_ul_grant_nb_rep_msg3_pusch_ce_mode_a;
static int hf_mac_lte_rar_ul_grant_mcs_ce_mode_a;
static int hf_mac_lte_rar_ul_grant_tpc_ce_mode_a;
static int hf_mac_lte_rar_ul_grant_csi_request_ce_mode_a;
static int hf_mac_lte_rar_ul_grant_ul_delay_ce_mode_a;
static int hf_mac_lte_rar_ul_grant_msg3_msg4_mpdcch_nb_idx;
static int hf_mac_lte_rar_ul_grant_padding_ce_mode_a;
static int hf_mac_lte_rar_ul_grant_msg3_pusch_nb_idx_ce_mode_b;
static int hf_mac_lte_rar_ul_grant_msg3_pusch_res_alloc_ce_mode_b;
static int hf_mac_lte_rar_ul_grant_nb_rep_msg3_pusch_ce_mode_b;
static int hf_mac_lte_rar_ul_grant_tbs_ce_mode_b;
static int hf_mac_lte_rar_ul_grant_ul_subcarrier_spacing;
static int hf_mac_lte_rar_ul_grant_subcarrier_indication;
static int hf_mac_lte_rar_ul_grant_scheduling_delay;
static int hf_mac_lte_rar_ul_grant_msg3_repetition_number;
static int hf_mac_lte_rar_ul_grant_mcs_index;
static int hf_mac_lte_rar_ul_grant_padding_nb_mode;
static int hf_mac_lte_rar_temporary_crnti;

/* Common channel control values */
static int hf_mac_lte_control_bsr;
static int hf_mac_lte_control_bsr_lcg_id;
static int hf_mac_lte_control_short_bsr_buffer_size;
static int hf_mac_lte_control_long_bsr_buffer_size_0;
static int hf_mac_lte_control_long_bsr_buffer_size_1;
static int hf_mac_lte_control_long_bsr_buffer_size_2;
static int hf_mac_lte_control_long_bsr_buffer_size_3;
static int hf_mac_lte_control_short_ext_bsr_buffer_size;
static int hf_mac_lte_control_long_ext_bsr_buffer_size_0;
static int hf_mac_lte_control_long_ext_bsr_buffer_size_1;
static int hf_mac_lte_control_long_ext_bsr_buffer_size_2;
static int hf_mac_lte_control_long_ext_bsr_buffer_size_3;
static int hf_mac_lte_bsr_size_median;
static int hf_mac_lte_control_crnti;
static int hf_mac_lte_control_timing_advance;
static int hf_mac_lte_control_timing_advance_group_id;
static int hf_mac_lte_control_timing_advance_command;
static int hf_mac_lte_control_timing_advance_value_reserved;
static int hf_mac_lte_control_timing_advance_value;
static int hf_mac_lte_control_as_rai;
static int hf_mac_lte_control_as_rai_reserved;
static int hf_mac_lte_control_as_rai_quality_report;
static int hf_mac_lte_control_ue_contention_resolution;
static int hf_mac_lte_control_ue_contention_resolution_identity;
static int hf_mac_lte_control_ue_contention_resolution_msg3;
static int hf_mac_lte_control_ue_contention_resolution_msg3_matched;
static int hf_mac_lte_control_ue_contention_resolution_time_since_msg3;
static int hf_mac_lte_control_msg3_to_cr;

static int hf_mac_lte_control_power_headroom;
static int hf_mac_lte_control_power_headroom_reserved;
static int hf_mac_lte_control_power_headroom_level;
static int hf_mac_lte_control_dual_conn_power_headroom;
static int hf_mac_lte_control_dual_conn_power_headroom_c7;
static int hf_mac_lte_control_dual_conn_power_headroom_c6;
static int hf_mac_lte_control_dual_conn_power_headroom_c5;
static int hf_mac_lte_control_dual_conn_power_headroom_c4;
static int hf_mac_lte_control_dual_conn_power_headroom_c3;
static int hf_mac_lte_control_dual_conn_power_headroom_c2;
static int hf_mac_lte_control_dual_conn_power_headroom_c1;
static int hf_mac_lte_control_dual_conn_power_headroom_c15;
static int hf_mac_lte_control_dual_conn_power_headroom_c14;
static int hf_mac_lte_control_dual_conn_power_headroom_c13;
static int hf_mac_lte_control_dual_conn_power_headroom_c12;
static int hf_mac_lte_control_dual_conn_power_headroom_c11;
static int hf_mac_lte_control_dual_conn_power_headroom_c10;
static int hf_mac_lte_control_dual_conn_power_headroom_c9;
static int hf_mac_lte_control_dual_conn_power_headroom_c8;
static int hf_mac_lte_control_dual_conn_power_headroom_c23;
static int hf_mac_lte_control_dual_conn_power_headroom_c22;
static int hf_mac_lte_control_dual_conn_power_headroom_c21;
static int hf_mac_lte_control_dual_conn_power_headroom_c20;
static int hf_mac_lte_control_dual_conn_power_headroom_c19;
static int hf_mac_lte_control_dual_conn_power_headroom_c18;
static int hf_mac_lte_control_dual_conn_power_headroom_c17;
static int hf_mac_lte_control_dual_conn_power_headroom_c16;
static int hf_mac_lte_control_dual_conn_power_headroom_c31;
static int hf_mac_lte_control_dual_conn_power_headroom_c30;
static int hf_mac_lte_control_dual_conn_power_headroom_c29;
static int hf_mac_lte_control_dual_conn_power_headroom_c28;
static int hf_mac_lte_control_dual_conn_power_headroom_c27;
static int hf_mac_lte_control_dual_conn_power_headroom_c26;
static int hf_mac_lte_control_dual_conn_power_headroom_c25;
static int hf_mac_lte_control_dual_conn_power_headroom_c24;

static int hf_mac_lte_control_dual_conn_power_headroom_reserved;
static int hf_mac_lte_control_dual_conn_power_headroom_power_backoff;
static int hf_mac_lte_control_dual_conn_power_headroom_value;
static int hf_mac_lte_control_dual_conn_power_headroom_level;
static int hf_mac_lte_control_dual_conn_power_headroom_reserved2;
static int hf_mac_lte_control_dual_conn_power_headroom_pcmaxc;
static int hf_mac_lte_control_ext_power_headroom;
static int hf_mac_lte_control_ext_power_headroom_c7;
static int hf_mac_lte_control_ext_power_headroom_c6;
static int hf_mac_lte_control_ext_power_headroom_c5;
static int hf_mac_lte_control_ext_power_headroom_c4;
static int hf_mac_lte_control_ext_power_headroom_c3;
static int hf_mac_lte_control_ext_power_headroom_c2;
static int hf_mac_lte_control_ext_power_headroom_c1;
static int hf_mac_lte_control_ext_power_headroom_reserved;
static int hf_mac_lte_control_ext_power_headroom_power_backoff;
static int hf_mac_lte_control_ext_power_headroom_value;
static int hf_mac_lte_control_ext_power_headroom_level;
static int hf_mac_lte_control_ext_power_headroom_reserved2;
static int hf_mac_lte_control_ext_power_headroom_pcmaxc;
static int hf_mac_lte_control_activation_deactivation;
static int hf_mac_lte_control_activation_deactivation_c7;
static int hf_mac_lte_control_activation_deactivation_c6;
static int hf_mac_lte_control_activation_deactivation_c5;
static int hf_mac_lte_control_activation_deactivation_c4;
static int hf_mac_lte_control_activation_deactivation_c3;
static int hf_mac_lte_control_activation_deactivation_c2;
static int hf_mac_lte_control_activation_deactivation_c1;
static int hf_mac_lte_control_activation_deactivation_reserved;
static int hf_mac_lte_control_activation_deactivation_c15;
static int hf_mac_lte_control_activation_deactivation_c14;
static int hf_mac_lte_control_activation_deactivation_c13;
static int hf_mac_lte_control_activation_deactivation_c12;
static int hf_mac_lte_control_activation_deactivation_c11;
static int hf_mac_lte_control_activation_deactivation_c10;
static int hf_mac_lte_control_activation_deactivation_c9;
static int hf_mac_lte_control_activation_deactivation_c8;
static int hf_mac_lte_control_activation_deactivation_c23;
static int hf_mac_lte_control_activation_deactivation_c22;
static int hf_mac_lte_control_activation_deactivation_c21;
static int hf_mac_lte_control_activation_deactivation_c20;
static int hf_mac_lte_control_activation_deactivation_c19;
static int hf_mac_lte_control_activation_deactivation_c18;
static int hf_mac_lte_control_activation_deactivation_c17;
static int hf_mac_lte_control_activation_deactivation_c16;
static int hf_mac_lte_control_activation_deactivation_c31;
static int hf_mac_lte_control_activation_deactivation_c30;
static int hf_mac_lte_control_activation_deactivation_c29;
static int hf_mac_lte_control_activation_deactivation_c28;
static int hf_mac_lte_control_activation_deactivation_c27;
static int hf_mac_lte_control_activation_deactivation_c26;
static int hf_mac_lte_control_activation_deactivation_c25;
static int hf_mac_lte_control_activation_deactivation_c24;
static int hf_mac_lte_control_mch_scheduling_info;
static int hf_mac_lte_control_mch_scheduling_info_lcid;
static int hf_mac_lte_control_mch_scheduling_info_stop_mtch;
static int hf_mac_lte_control_sidelink_bsr;
static int hf_mac_lte_control_sidelink_bsr_destination_idx_odd;
static int hf_mac_lte_control_sidelink_bsr_lcg_id_odd;
static int hf_mac_lte_control_sidelink_bsr_buffer_size_odd;
static int hf_mac_lte_control_sidelink_bsr_destination_idx_even;
static int hf_mac_lte_control_sidelink_bsr_lcg_id_even;
static int hf_mac_lte_control_sidelink_bsr_buffer_size_even;
static int hf_mac_lte_control_sidelink_reserved;
static int hf_mac_lte_control_data_vol_power_headroom;
static int hf_mac_lte_control_data_vol_power_headroom_reserved;
static int hf_mac_lte_control_data_vol_power_headroom_level;
static int hf_mac_lte_control_data_vol_power_headroom_level_4_bits;
static int hf_mac_lte_control_data_vol_power_headroom_data_vol;
static int hf_mac_lte_control_recommended_bit_rate;
static int hf_mac_lte_control_recommended_bit_rate_lcid;
static int hf_mac_lte_control_recommended_bit_rate_dir;
static int hf_mac_lte_control_recommended_bit_rate_bit_rate;
static int hf_mac_lte_control_recommended_bit_rate_reserved;
static int hf_mac_lte_control_recommended_bit_rate_query;
static int hf_mac_lte_control_recommended_bit_rate_query_lcid;
static int hf_mac_lte_control_recommended_bit_rate_query_dir;
static int hf_mac_lte_control_recommended_bit_rate_query_bit_rate;
static int hf_mac_lte_control_recommended_bit_rate_query_reserved;
static int hf_mac_lte_control_activation_deactivation_csi_rs;
static int hf_mac_lte_control_activation_deactivation_csi_rs_a8;
static int hf_mac_lte_control_activation_deactivation_csi_rs_a7;
static int hf_mac_lte_control_activation_deactivation_csi_rs_a6;
static int hf_mac_lte_control_activation_deactivation_csi_rs_a5;
static int hf_mac_lte_control_activation_deactivation_csi_rs_a4;
static int hf_mac_lte_control_activation_deactivation_csi_rs_a3;
static int hf_mac_lte_control_activation_deactivation_csi_rs_a2;
static int hf_mac_lte_control_activation_deactivation_csi_rs_a1;
static int hf_mac_lte_control_activation_deactivation_pdcp_dup;
static int hf_mac_lte_control_activation_deactivation_pdcp_dup_d8;
static int hf_mac_lte_control_activation_deactivation_pdcp_dup_d7;
static int hf_mac_lte_control_activation_deactivation_pdcp_dup_d6;
static int hf_mac_lte_control_activation_deactivation_pdcp_dup_d5;
static int hf_mac_lte_control_activation_deactivation_pdcp_dup_d4;
static int hf_mac_lte_control_activation_deactivation_pdcp_dup_d3;
static int hf_mac_lte_control_activation_deactivation_pdcp_dup_d2;
static int hf_mac_lte_control_activation_deactivation_pdcp_dup_d1;
static int hf_mac_lte_control_hibernation;
static int hf_mac_lte_control_hibernation_c7;
static int hf_mac_lte_control_hibernation_c6;
static int hf_mac_lte_control_hibernation_c5;
static int hf_mac_lte_control_hibernation_c4;
static int hf_mac_lte_control_hibernation_c3;
static int hf_mac_lte_control_hibernation_c2;
static int hf_mac_lte_control_hibernation_c1;
static int hf_mac_lte_control_hibernation_reserved;
static int hf_mac_lte_control_hibernation_c15;
static int hf_mac_lte_control_hibernation_c14;
static int hf_mac_lte_control_hibernation_c13;
static int hf_mac_lte_control_hibernation_c12;
static int hf_mac_lte_control_hibernation_c11;
static int hf_mac_lte_control_hibernation_c10;
static int hf_mac_lte_control_hibernation_c9;
static int hf_mac_lte_control_hibernation_c8;
static int hf_mac_lte_control_hibernation_c23;
static int hf_mac_lte_control_hibernation_c22;
static int hf_mac_lte_control_hibernation_c21;
static int hf_mac_lte_control_hibernation_c20;
static int hf_mac_lte_control_hibernation_c19;
static int hf_mac_lte_control_hibernation_c18;
static int hf_mac_lte_control_hibernation_c17;
static int hf_mac_lte_control_hibernation_c16;
static int hf_mac_lte_control_hibernation_c31;
static int hf_mac_lte_control_hibernation_c30;
static int hf_mac_lte_control_hibernation_c29;
static int hf_mac_lte_control_hibernation_c28;
static int hf_mac_lte_control_hibernation_c27;
static int hf_mac_lte_control_hibernation_c26;
static int hf_mac_lte_control_hibernation_c25;
static int hf_mac_lte_control_hibernation_c24;
static int hf_mac_lte_control_aul_confirmation;
static int hf_mac_lte_control_aul_confirmation_c7;
static int hf_mac_lte_control_aul_confirmation_c6;
static int hf_mac_lte_control_aul_confirmation_c5;
static int hf_mac_lte_control_aul_confirmation_c4;
static int hf_mac_lte_control_aul_confirmation_c3;
static int hf_mac_lte_control_aul_confirmation_c2;
static int hf_mac_lte_control_aul_confirmation_c1;
static int hf_mac_lte_control_aul_confirmation_reserved;
static int hf_mac_lte_control_aul_confirmation_c15;
static int hf_mac_lte_control_aul_confirmation_c14;
static int hf_mac_lte_control_aul_confirmation_c13;
static int hf_mac_lte_control_aul_confirmation_c12;
static int hf_mac_lte_control_aul_confirmation_c11;
static int hf_mac_lte_control_aul_confirmation_c10;
static int hf_mac_lte_control_aul_confirmation_c9;
static int hf_mac_lte_control_aul_confirmation_c8;
static int hf_mac_lte_control_aul_confirmation_c23;
static int hf_mac_lte_control_aul_confirmation_c22;
static int hf_mac_lte_control_aul_confirmation_c21;
static int hf_mac_lte_control_aul_confirmation_c20;
static int hf_mac_lte_control_aul_confirmation_c19;
static int hf_mac_lte_control_aul_confirmation_c18;
static int hf_mac_lte_control_aul_confirmation_c17;
static int hf_mac_lte_control_aul_confirmation_c16;
static int hf_mac_lte_control_aul_confirmation_c31;
static int hf_mac_lte_control_aul_confirmation_c30;
static int hf_mac_lte_control_aul_confirmation_c29;
static int hf_mac_lte_control_aul_confirmation_c28;
static int hf_mac_lte_control_aul_confirmation_c27;
static int hf_mac_lte_control_aul_confirmation_c26;
static int hf_mac_lte_control_aul_confirmation_c25;
static int hf_mac_lte_control_aul_confirmation_c24;



static int hf_mac_lte_dl_harq_resend_original_frame;
static int hf_mac_lte_dl_harq_resend_time_since_previous_frame;
static int hf_mac_lte_dl_harq_resend_next_frame;
static int hf_mac_lte_dl_harq_resend_time_until_next_frame;

static int hf_mac_lte_ul_harq_resend_original_frame;
static int hf_mac_lte_ul_harq_resend_time_since_previous_frame;
static int hf_mac_lte_ul_harq_resend_next_frame;
static int hf_mac_lte_ul_harq_resend_time_until_next_frame;

static int hf_mac_lte_grant_answering_sr;
static int hf_mac_lte_failure_answering_sr;
static int hf_mac_lte_sr_leading_to_failure;
static int hf_mac_lte_sr_leading_to_grant;
static int hf_mac_lte_sr_time_since_request;
static int hf_mac_lte_sr_time_until_answer;

static int hf_mac_lte_drx_config;
static int hf_mac_lte_drx_config_frame_num;
static int hf_mac_lte_drx_config_previous_frame_num;
static int hf_mac_lte_drx_config_long_cycle;
static int hf_mac_lte_drx_config_cycle_offset;
static int hf_mac_lte_drx_config_onduration_timer;
static int hf_mac_lte_drx_config_inactivity_timer;
static int hf_mac_lte_drx_config_retransmission_timer;
static int hf_mac_lte_drx_config_short_cycle;
static int hf_mac_lte_drx_config_short_cycle_timer;

static int hf_mac_lte_drx_state;
static int hf_mac_lte_drx_state_long_cycle_offset;
/* static int hf_mac_lte_drx_state_long_cycle_on; */
static int hf_mac_lte_drx_state_short_cycle_offset;
/* static int hf_mac_lte_drx_state_short_cycle_on; */
static int hf_mac_lte_drx_state_inactivity_remaining;
static int hf_mac_lte_drx_state_onduration_remaining;
static int hf_mac_lte_drx_state_retransmission_remaining;
static int hf_mac_lte_drx_state_rtt_remaining;
static int hf_mac_lte_drx_state_short_cycle_remaining;

/* Subtrees. */
static int ett_mac_lte;
static int ett_mac_lte_context;
static int ett_mac_lte_phy_context;
static int ett_mac_lte_ulsch_header;
static int ett_mac_lte_dlsch_header;
static int ett_mac_lte_mch_header;
static int ett_mac_lte_sch_subheader;
static int ett_mac_lte_mch_subheader;
static int ett_mac_lte_slsch_header;
static int ett_mac_lte_slsch_subheader;
static int ett_mac_lte_rar_headers;
static int ett_mac_lte_rar_header;
static int ett_mac_lte_rar_body;
static int ett_mac_lte_rar_ul_grant;
static int ett_mac_lte_bsr;
static int ett_mac_lte_bch;
static int ett_mac_lte_pch;
static int ett_mac_lte_activation_deactivation;
static int ett_mac_lte_contention_resolution;
static int ett_mac_lte_timing_advance;
static int ett_mac_lte_power_headroom;
static int ett_mac_lte_dual_conn_power_headroom;
static int ett_mac_lte_dual_conn_power_headroom_cell;
static int ett_mac_lte_extended_power_headroom;
static int ett_mac_lte_extended_power_headroom_cell;
static int ett_mac_lte_mch_scheduling_info;
static int ett_mac_lte_oob;
static int ett_mac_lte_drx_config;
static int ett_mac_lte_drx_state;
static int ett_mac_lte_sidelink_bsr;
static int ett_mac_lte_data_vol_power_headroom;
static int ett_mac_lte_recommended_bit_rate;
static int ett_mac_lte_recommended_bit_rate_query;
static int ett_mac_lte_activation_deactivation_csi_rs;
static int ett_mac_lte_activation_deactivation_pdcp_dup;
static int ett_mac_lte_hibernation;
static int ett_mac_lte_aul_confirmation;

static expert_field ei_mac_lte_context_rnti_type;
static expert_field ei_mac_lte_lcid_unexpected;
static expert_field ei_mac_lte_ul_mac_frame_retx;
static expert_field ei_mac_lte_oob_sr_failure;
static expert_field ei_mac_lte_control_timing_advance_command_correction_needed;
static expert_field ei_mac_lte_sch_header_only_truncated;
static expert_field ei_mac_lte_mch_header_only_truncated;
static expert_field ei_mac_lte_slsch_header_only_truncated;
static expert_field ei_mac_lte_control_timing_advance_command_no_correction;
static expert_field ei_mac_lte_rar_timing_advance_not_zero_note;
static expert_field ei_mac_lte_padding_data_start_and_end;
static expert_field ei_mac_lte_bch_pdu;
static expert_field ei_mac_lte_rach_preamble_sent_note;
static expert_field ei_mac_lte_pch_pdu;
static expert_field ei_mac_lte_ul_harq_resend_next_frame;
static expert_field ei_mac_lte_control_bsr_multiple;
static expert_field ei_mac_lte_padding_data_multiple;
static expert_field ei_mac_lte_context_sysframe_number;
static expert_field ei_mac_lte_rar_bi_present;
static expert_field ei_mac_lte_control_element_size_invalid;
static expert_field ei_mac_lte_bsr_warn_threshold_exceeded;
static expert_field ei_mac_lte_too_many_subheaders;
static expert_field ei_mac_lte_oob_send_sr;
static expert_field ei_mac_lte_orig_tx_ul_frame_not_found;
static expert_field ei_mac_lte_control_ue_contention_resolution_msg3_matched;
static expert_field ei_mac_lte_sr_results_not_grant_or_failure_indication;
static expert_field ei_mac_lte_context_crc_status;
static expert_field ei_mac_lte_sr_invalid_event;
static expert_field ei_mac_lte_control_subheader_after_data_subheader;
static expert_field ei_mac_lte_rar_bi_not_first_subheader;
static expert_field ei_mac_lte_context_length;
static expert_field ei_mac_lte_reserved_not_zero;
static expert_field ei_mac_lte_rar_timing_advance_not_zero_warn;
static expert_field ei_mac_lte_dlsch_lcid;
static expert_field ei_mac_lte_padding_data_before_control_subheader;
static expert_field ei_mac_lte_rach_preamble_sent_warn;
static expert_field ei_mac_lte_no_per_frame_data;
static expert_field ei_mac_lte_sch_invalid_length;
static expert_field ei_mac_lte_mch_invalid_length;
static expert_field ei_mac_lte_invalid_sc_mcch_sc_mtch_subheader_multiplexing;
static expert_field ei_mac_lte_unknown_udp_framing_tag;


/* Constants and value strings */

static const value_string radio_type_vals[] =
{
    { FDD_RADIO,      "FDD"},
    { TDD_RADIO,      "TDD"},
    { 0, NULL }
};


static const value_string direction_vals[] =
{
    { DIRECTION_UPLINK,      "Uplink"},
    { DIRECTION_DOWNLINK,    "Downlink"},
    { 0, NULL }
};


static const value_string rnti_type_vals[] =
{
    { NO_RNTI,     "NO-RNTI"},
    { P_RNTI,      "P-RNTI"},
    { RA_RNTI,     "RA-RNTI"},
    { C_RNTI,      "C-RNTI"},
    { SI_RNTI,     "SI-RNTI"},
    { SPS_RNTI,    "SPS-RNTI"},
    { M_RNTI,      "M-RNTI"},
    { SL_BCH_RNTI, "SL-BCH-RNTI"},
    { SL_RNTI,     "SL-RNTI"},
    { SC_RNTI,     "SC-RNTI"},
    { G_RNTI,      "G-RNTI"},
    { 0, NULL }
};

static const value_string bch_transport_channel_vals[] =
{
    { SI_RNTI,      "DL-SCH"},
    { NO_RNTI,      "BCH"},
    { 0, NULL }
};

static const value_string crc_status_vals[] =
{
    { crc_success,                "OK"},
    { crc_fail,                   "Failed"},
    { crc_high_code_rate,         "High Code Rate"},
    { crc_pdsch_lost,             "PDSCH Lost"},
    { crc_duplicate_nonzero_rv,   "Duplicate_nonzero_rv"},
    { crc_false_dci,              "False DCI"},
    { 0, NULL }
};

static const value_string carrier_id_vals[] =
{
    { carrier_id_primary,       "Primary"},
    { carrier_id_secondary_1,   "Secondary-1"},
    { carrier_id_secondary_2,   "Secondary-2"},
    { carrier_id_secondary_3,   "Secondary-3"},
    { carrier_id_secondary_4,   "Secondary-4"},
    { carrier_id_secondary_5,   "Secondary-5"},
    { carrier_id_secondary_6,   "Secondary-6"},
    { carrier_id_secondary_7,   "Secondary-7"},
    { 0, NULL }
};

static const value_string dci_format_vals[] =
{
    {  0, "0"},
    {  1, "1"},
    {  2, "1A"},
    {  3, "1B"},
    {  4, "1C"},
    {  5, "1D"},
    {  6, "2"},
    {  7, "2A"},
    {  8, "3/3A"},
    {  9, "2B"},
    { 10, "2C"},
    { 11, "2D"},
    { 12, "4"},
    { 13, "6-0A"},
    { 14, "6-1A"},
    { 15, "6-2"},
    { 16, "N0"},
    { 17, "N1"},
    { 18, "N2"},
    {  0, NULL }
};

static const value_string aggregation_level_vals[] =
{
    { 0, "1"},
    { 1, "2"},
    { 2, "4"},
    { 3, "8"},
    { 4, "16"},
    { 5, "24"},
    { 0, NULL }
};

static const value_string modulation_type_vals[] =
{
    { 2, "QPSK"},
    { 4, "QAM16"},
    { 6, "QAM64"},
    { 0, NULL }
};

static const value_string as_rai_vals[] =
{
    { 0, "No RAI information"},
    { 1, "No subsequent DL and UL data transmission is expected"},
    { 2, "A single subsequent DL transmission is expected"},
    { 3, "Reserved"},
    { 0, NULL }
};


static const true_false_string scell_ph_tfs = {
    "Reported",
    "Not reported"
};

static const true_false_string power_backoff_tfs = {
    "Applied",
    "Not applied"
};

static const true_false_string ph_value_tfs = {
    "Based on reference format",
    "Based on real transmission"
};

static const true_false_string dormant_activate_tfs = {
    "Make dormant",
    "Activate"
};


#define EXT_LOGICAL_CHANNEL_ID_LCID            0x10
#define DCQR_COMMAND_LCID                      0x11
#define ACTIVATION_DEACTIVATION_PDCP_DUP_LCID  0x12
#define HIBERNATION_1_OCTET_LCID               0x13
#define HIBERNATION_4_OCTETS_LCID              0x14
#define ACTIVATION_DEACTIVATION_CSI_RS_LCID    0x15
#define RECOMMENDED_BIT_RATE_LCID              0x16
#define SC_PTM_STOP_INDICATION_LCID            0x17
#define ACTIVATION_DEACTIVATION_4_BYTES_LCID   0x18
#define SC_MCCH_SC_MTCH_LCID                   0x19
#define LONG_DRX_COMMAND_LCID                  0x1a
#define ACTIVATION_DEACTIVATION_LCID           0x1b
#define UE_CONTENTION_RESOLUTION_IDENTITY_LCID 0x1c
#define TIMING_ADVANCE_LCID                    0x1d
#define DRX_COMMAND_LCID                       0x1e
#define PADDING_LCID                           0x1f

static const value_string dlsch_lcid_vals[] =
{
    { 0,                                      "CCCH"},
    { 1,                                      "1"},
    { 2,                                      "2"},
    { 3,                                      "3"},
    { 4,                                      "4"},
    { 5,                                      "5"},
    { 6,                                      "6"},
    { 7,                                      "7"},
    { 8,                                      "8"},
    { 9,                                      "9"},
    { 10,                                     "10"},
    { EXT_LOGICAL_CHANNEL_ID_LCID,            "Extended logical channel ID field"},
    { DCQR_COMMAND_LCID,                      "DCQR Command"},
    { ACTIVATION_DEACTIVATION_PDCP_DUP_LCID,  "Activation/Deactivation of PDCP Duplication"},
    { HIBERNATION_1_OCTET_LCID,               "Hibernation (1 octet)"},
    { HIBERNATION_4_OCTETS_LCID,              "Hibernation (4 octets)"},
    { ACTIVATION_DEACTIVATION_CSI_RS_LCID,    "Activation/Deactivation of CSI-RS"},
    { RECOMMENDED_BIT_RATE_LCID,              "Recommended Bit Rate"},
    { SC_PTM_STOP_INDICATION_LCID,            "SC-PTM Stop Indication"},
    { ACTIVATION_DEACTIVATION_4_BYTES_LCID,   "Activation/Deactivation"},
    { SC_MCCH_SC_MTCH_LCID,                   "SC-MCCH/SC-MTCH"},
    { LONG_DRX_COMMAND_LCID,                  "Long DRX Command"},
    { ACTIVATION_DEACTIVATION_LCID,           "Activation/Deactivation"},
    { UE_CONTENTION_RESOLUTION_IDENTITY_LCID, "UE Contention Resolution Identity"},
    { TIMING_ADVANCE_LCID,                    "Timing Advance"},
    { DRX_COMMAND_LCID,                       "DRX Command"},
    { PADDING_LCID,                           "Padding" },
    { 0, NULL }
};

#define TIMING_ADVANCE_REPORT_LCID           0x0f
#define DCQR_AND_AS_RAI_LCID                 0x11
#define AUL_CONFIRMATION_4_OCTETS            0x12
#define AUL_CONFIRMATION_1_OCTET             0x13
#define RECOMMENDED_BIT_RATE_QUERY_LCID      0x14
#define SPS_CONFIRMATION_LCID                0x15
#define TRUNCATED_SIDELINK_BSR_LCID          0x16
#define SIDELINK_BSR_LCID                    0x17
#define DUAL_CONN_POWER_HEADROOM_REPORT_LCID 0x18
#define EXTENDED_POWER_HEADROOM_REPORT_LCID  0x19
#define POWER_HEADROOM_REPORT_LCID           0x1a
#define CRNTI_LCID                           0x1b
#define TRUNCATED_BSR_LCID                   0x1c
#define SHORT_BSR_LCID                       0x1d
#define LONG_BSR_LCID                        0x1e

static const value_string ulsch_lcid_vals[] =
{
    { 0,                                    "CCCH"},
    { 1,                                    "1"},
    { 2,                                    "2"},
    { 3,                                    "3"},
    { 4,                                    "4"},
    { 5,                                    "5"},
    { 6,                                    "6"},
    { 7,                                    "7"},
    { 8,                                    "8"},
    { 9,                                    "9"},
    { 10,                                   "10"},
    { 11,                                   "CCCH (Category 0)"},
    { 12,                                   "CCCH (frequency hopping for unicast)"},
    { 13,                                   "CCCH and Extended Power Headroom Report"},
    { 14,                                   "Reserved"},
    { TIMING_ADVANCE_REPORT_LCID,           "Timing Advance Report"},
    { EXT_LOGICAL_CHANNEL_ID_LCID,          "Extended logical channel ID field"},
    { DCQR_AND_AS_RAI_LCID,                 "DCQR and AS RAI"},
    { AUL_CONFIRMATION_4_OCTETS,            "AUL confirmation (4 octets)"},
    { AUL_CONFIRMATION_1_OCTET,             "AUL confirmation (1 octet)"},
    { RECOMMENDED_BIT_RATE_QUERY_LCID,      "Recommended Bit Rate Query"},
    { SPS_CONFIRMATION_LCID,                "SPS Confirmation"},
    { TRUNCATED_SIDELINK_BSR_LCID,          "Truncated Sidelink BSR"},
    { SIDELINK_BSR_LCID,                    "Sidelink BSR"},
    { DUAL_CONN_POWER_HEADROOM_REPORT_LCID, "Dual Connectivity Power Headroom Report"},
    { EXTENDED_POWER_HEADROOM_REPORT_LCID,  "Extended Power Headroom Report"},
    { POWER_HEADROOM_REPORT_LCID,           "Power Headroom Report"},
    { CRNTI_LCID,                           "C-RNTI"},
    { TRUNCATED_BSR_LCID,                   "Truncated BSR"},
    { SHORT_BSR_LCID,                       "Short BSR"},
    { LONG_BSR_LCID,                        "Long BSR"},
    { PADDING_LCID,                         "Padding" },
    { 0, NULL }
};

#define MCH_SCHEDULING_INFO_LCID 0x1e

static const value_string mch_lcid_vals[] =
{
    { 0,                            "MCCH"},
    { 1,                            "1"},
    { 2,                            "2"},
    { 3,                            "3"},
    { 4,                            "4"},
    { 5,                            "5"},
    { 6,                            "6"},
    { 7,                            "7"},
    { 8,                            "8"},
    { 9,                            "9"},
    { 10,                           "10"},
    { 11,                           "11"},
    { 12,                           "12"},
    { 13,                           "13"},
    { 14,                           "14"},
    { 15,                           "15"},
    { 16,                           "16"},
    { 17,                           "17"},
    { 18,                           "18"},
    { 19,                           "19"},
    { 20,                           "20"},
    { 21,                           "21"},
    { 22,                           "22"},
    { 23,                           "23"},
    { 24,                           "24"},
    { 25,                           "25"},
    { 26,                           "26"},
    { 27,                           "27"},
    { 28,                           "28"},
    { 29,                           "Reserved"},
    { MCH_SCHEDULING_INFO_LCID,     "MCH Scheduling Information"},
    { PADDING_LCID,                 "Padding" },
    { 0, NULL }
};


/* Does this LCID relate to CCCH? */
static bool is_ccch_lcid(uint8_t lcid, uint8_t direction)
{
    if (lcid==0) {
        return true;
    }
    else {
        /* Extra UL CCCH LCIDs */
        return (direction == DIRECTION_UPLINK) && (lcid>=11 && lcid<=13);
    }
}

/* Does this LCID represent variable-length data SDU?
   N.B. assuming that all CCCH LCIDs do have associated SDU */
static bool is_data_lcid(uint8_t lcid, uint8_t direction)
{
    return lcid<=10 || is_ccch_lcid(lcid, direction);
}



static const value_string slsch_lcid_vals[] =
{
    { 0,            "Reserved"},
    { 1,            "1"},
    { 2,            "2"},
    { 3,            "3"},
    { 4,            "4"},
    { 5,            "5"},
    { 6,            "6"},
    { 7,            "7"},
    { 8,            "8"},
    { 9,            "9"},
    { 10,           "10"},
    { 28,           "PC5-S messages that are not protected"},
    { 29,           "PC5-S messages \"Direct Security Mode Command\" and \"Direct Security Mode Complete\""},
    { 30,           "Other PC5-S messages that are protected"},
    { PADDING_LCID, "Padding" },
    { 0, NULL }
};

static const true_false_string format_vals =
{
    "Data length is >= 128 bytes",
    "Data length is < 128 bytes"
};

static const true_false_string format2_vals =
{
    "Data length is >= 32768 bytes",
    "Data length is < 32768 bytes"
};

static const value_string rar_type_vals[] =
{
    { 0,      "Backoff Indicator present"},
    { 1,      "RAPID present"},
    { 0, NULL }
};


static const value_string rar_bi_vals[] =
{
    { 0,      "0"},
    { 1,      "10"},
    { 2,      "20"},
    { 3,      "30"},
    { 4,      "40"},
    { 5,      "60"},
    { 6,      "80"},
    { 7,      "120"},
    { 8,      "160"},
    { 9,      "240"},
    { 10,     "320"},
    { 11,     "480"},
    { 12,     "960"},
    { 0, NULL }
};


static const value_string rar_bi_nb_vals[] =
{
    { 0,      "0"},
    { 1,      "256"},
    { 2,      "512"},
    { 3,      "1024"},
    { 4,      "2048"},
    { 5,      "4096"},
    { 6,      "8192"},
    { 7,      "16384"},
    { 8,      "32768"},
    { 9,      "65536"},
    { 10,     "131072"},
    { 11,     "262144"},
    { 12,     "524288"},
    { 0, NULL }
};


static const value_string rar_ul_grant_tcsp_vals[] =
{
    { 0, "-6 dB"},
    { 1, "-4 dB" },
    { 2, "-2 dB" },
    { 3, "0 dB" },
    { 4, "2 dB" },
    { 5, "4 dB" },
    { 6, "6 dB" },
    { 7, "8 dB" },
    { 0, NULL }
};


static const value_string rar_ul_grant_msg3_pusch_nb_idx_ce_mode_b_vals[] =
{
    { 0, "NBrar mod Nnb"},
    { 1, "(NBrar+1) mod Nnb"},
    { 2, "(NBrar+2) mod Nnb"},
    { 3, "(NBrar+3) mod Nnb"},
    { 0, NULL}
};


static const value_string rar_ul_grant_msg3_msg4_mpdcch_nb_idx_vals[] =
{
    { 0, "NBrar mod Nnb2"},
    { 1, "(NBrar+1) mod Nnb2"},
    { 2, "(NBrar+2) mod Nnb2"},
    { 3, "(NBrar+3) mod Nnb2"},
    { 0, NULL}
};


static const value_string rar_ul_grant_nb_rep_msg3_pusch_ce_mode_a_vals[] =
{
    { 0, "Ya/8"},
    { 1, "Ya/4"},
    { 2, "Ya/2"},
    { 3, "Ya"},
    { 0, NULL}
};


static const value_string rar_ul_grant_nb_rep_msg3_pusch_ce_mode_b_vals[] =
{
    { 0, "Yb/128"},
    { 1, "Yb/64"},
    { 2, "Yb/32"},
    { 3, "Yb/16"},
    { 4, "Yb/8"},
    { 5, "Yb/4"},
    { 6, "Yb/2"},
    { 7, "Yb"},
    { 0, NULL}
};


static const true_false_string ul_subcarrier_spacing_val =
{
    "15 kHz",
    "3.75 kHz"
};


static const value_string scheduling_delay_vals[]=
{
    { 0, "k0 = 8"},
    { 1, "k0 = 16"},
    { 2, "k0 = 32"},
    { 3, "k0 = 64"},
    { 0, NULL}
};


static const value_string msg3_rep_nb_vals[] =
{
    { 0, "1"},
    { 1, "2"},
    { 2, "4"},
    { 3, "8"},
    { 4, "16"},
    { 5, "32"},
    { 6, "64"},
    { 7, "128"},
    { 0, NULL}
};


static const value_string buffer_size_vals[] =
{
    { 0,      "BS = 0"},
    { 1,      "0 < BS <= 10"},
    { 2,      "10 < BS <= 12"},
    { 3,      "12 < BS <= 14"},
    { 4,      "14 < BS <= 17"},
    { 5,      "17 < BS <= 19"},
    { 6,      "19 < BS <= 22"},
    { 7,      "22 < BS <= 26"},
    { 8,      "26 < BS <= 31"},
    { 9,      "31 < BS <= 36"},
    { 10,     "36 < BS <= 42"},
    { 11,     "42 < BS <= 49"},
    { 12,     "49 < BS <= 57"},
    { 13,     "57 < BS <= 67"},
    { 14,     "67 < BS <= 78"},
    { 15,     "78 < BS <= 91"},
    { 16,     "91 < BS <= 107"},
    { 17,     "107 < BS <= 125"},
    { 18,     "125 < BS <= 146"},
    { 19,     "146 < BS <= 171"},
    { 20,     "171 < BS <= 200"},
    { 21,     "200 < BS <= 234"},
    { 22,     "234 < BS <= 274"},
    { 23,     "274 < BS <= 321"},
    { 24,     "321 < BS <= 376"},
    { 25,     "376 < BS <= 440"},
    { 26,     "440 < BS <= 515"},
    { 27,     "515 < BS <= 603"},
    { 28,     "603 < BS <= 706"},
    { 29,     "706 < BS <= 826"},
    { 30,     "826 < BS <= 967"},
    { 31,     "967 < BS <= 1132"},
    { 32,     "1132 < BS <= 1326"},
    { 33,     "1326 < BS <= 1552"},
    { 34,     "1552 < BS <= 1817"},
    { 35,     "1817 < BS <= 2127"},
    { 36,     "2127 < BS <= 2490"},
    { 37,     "2490 < BS <= 2915"},
    { 38,     "2915 < BS <= 3413"},
    { 39,     "3413 < BS <= 3995"},
    { 40,     "3995 < BS <= 4677"},
    { 41,     "4677 < BS <= 5476"},
    { 42,     "5476 < BS <= 6411"},
    { 43,     "6411 < BS <= 7505"},
    { 44,     "7505 < BS <= 8787"},
    { 45,     "8787 < BS <= 10276"},
    { 46,     "10287 < BS <= 12043"},
    { 47,     "12043 < BS <= 14099"},
    { 48,     "14099 < BS <= 16507"},
    { 49,     "16507 < BS <= 19325"},
    { 50,     "19325 < BS <= 22624"},
    { 51,     "22624 < BS <= 26487"},
    { 52,     "26487 < BS <= 31009"},
    { 53,     "31009 < BS <= 36304"},
    { 54,     "36304 < BS <= 42502"},
    { 55,     "42502 < BS <= 49759"},
    { 56,     "49759 < BS <= 58255"},
    { 57,     "58255 < BS <= 68201"},
    { 58,     "68201 < BS <= 79846"},
    { 59,     "79846 < BS <= 93479"},
    { 60,     "93479 < BS <= 109439"},
    { 61,     "109439 < BS <= 128125"},
    { 62,     "128125 < BS <= 150000"},
    { 63,     "BS > 150000"},
    { 0, NULL }
};
static value_string_ext buffer_size_vals_ext = VALUE_STRING_EXT_INIT(buffer_size_vals);

static uint32_t buffer_size_median[64] = {
    0,  /* BS = 0 */
    5,  /* 0 < BS <= 10 */
    11, /* 10 < BS <= 12 */
    13, /* 12 < BS <= 14 */
    15, /* 14 < BS <= 17 */
    18, /* 17 < BS <= 19 */
    21, /* 19 < BS <= 22 */
    24, /* 22 < BS <= 26 */
    29, /* 26 < BS <= 31 */
    34, /* 31 < BS <= 36 */
    39, /* 36 < BS <= 42 */
    46, /* 42 < BS <= 49 */
    53, /* 49 < BS <= 57 */
    62, /* 57 < BS <= 67 */
    74, /* 67 < BS <= 78 */
    85, /* 78 < BS <= 91 */
    99, /* 91 < BS <= 107 */
    116, /* 107 < BS <= 125 */
    135, /* 125 < BS <= 146 */
    159, /* 146 < BS <= 171 */
    185, /* 171 < BS <= 200 */
    217, /* 200 < BS <= 234 */
    254, /* 234 < BS <= 274 */
    297, /* 274 < BS <= 321 */
    348, /* 321 < BS <= 376 */
    408, /* 376 < BS <= 440 */
    477, /* 440 < BS <= 515 */
    559, /* 515 < BS <= 603 */
    654, /* 603 < BS <= 706 */
    766, /* 706 < BS <= 826 */
    896, /* 826 < BS <= 967 */
    1049, /* 967 < BS <= 1132 */
    1229, /* 1132 < BS <= 1326 */
    1439, /* 1326 < BS <= 1552 */
    1684, /* 1552 < BS <= 1817 */
    1972, /* 1817 < BS <= 2127 */
    2308, /* 2127 < BS <= 2490 */
    2702, /* 2490 < BS <= 2915 */
    3164, /* 2915 < BS <= 3413 */
    3704, /* 3413 < BS <= 3995 */
    4336, /* 3995 < BS <= 4677 */
    5076, /* 4677 < BS <= 5476 */
    5943, /* 5476 < BS <= 6411 */
    6958, /* 6411 < BS <= 7505 */
    8146, /* 7505 < BS <= 8787 */
    9531, /* 8787 < BS <= 10276 */
    11165, /* 10287 < BS <= 12043 */
    13071, /* 12043 < BS <= 14099 */
    15303, /* 14099 < BS <= 16507 */
    19716, /* 16507 < BS <= 19325 */
    20974, /* 19325 < BS <= 22624 */
    24555, /* 22624 < BS <= 26487 */
    28748, /* 26487 < BS <= 31009 */
    33656, /* 31009 < BS <= 36304 */
    39403, /* 36304 < BS <= 42502 */
    46130, /* 42502 < BS <= 49759 */
    54007, /* 49759 < BS <= 58255 */
    63228, /* 58255 < BS <= 68201 */
    74023, /* 68201 < BS <= 79846 */
    86662, /* 79846 < BS <= 93479 */
    101459, /* 93479 < BS <= 109439 */
    118782, /* 109439 < BS <= 128125 */
    139062, /* 128125 < BS <= 150000 */
    150001  /* BS > 150000 */
};

static const value_string ext_buffer_size_vals[] =
{
    { 0,      "BS = 0"},
    { 1,      "0 < BS <= 10"},
    { 2,      "10 < BS <= 13"},
    { 3,      "13 < BS <= 16"},
    { 4,      "16 < BS <= 19"},
    { 5,      "19 < BS <= 23"},
    { 6,      "23 < BS <= 29"},
    { 7,      "29 < BS <= 35"},
    { 8,      "35 < BS <= 43"},
    { 9,      "43 < BS <= 53"},
    { 10,     "53 < BS <= 65"},
    { 11,     "65 < BS <= 80"},
    { 12,     "80 < BS <= 98"},
    { 13,     "98 < BS <= 120"},
    { 14,     "120 < BS <= 147"},
    { 15,     "147 < BS <= 181"},
    { 16,     "181 < BS <= 223"},
    { 17,     "223 < BS <= 274"},
    { 18,     "274 < BS <= 337"},
    { 19,     "337 < BS <= 414"},
    { 20,     "414 < BS <= 509"},
    { 21,     "509 < BS <= 625"},
    { 22,     "625 < BS <= 769"},
    { 23,     "769 < BS <= 945"},
    { 24,     "945 < BS <= 1162"},
    { 25,     "1162 < BS <= 1429"},
    { 26,     "1429 < BS <= 1757"},
    { 27,     "1757 < BS <= 2161"},
    { 28,     "2161 < BS <= 2657"},
    { 29,     "2657 < BS <= 3267"},
    { 30,     "3267 < BS <= 4017"},
    { 31,     "4017 < BS <= 4940"},
    { 32,     "4940 < BS <= 6074"},
    { 33,     "6074 < BS <= 7469"},
    { 34,     "7469 < BS <= 9185"},
    { 35,     "9185 < BS <= 11294"},
    { 36,     "11294 < BS <= 13888"},
    { 37,     "13888 < BS <= 17077"},
    { 38,     "17077 < BS <= 20999"},
    { 39,     "20999 < BS <= 25822"},
    { 40,     "25822 < BS <= 31752"},
    { 41,     "31752 < BS <= 39045"},
    { 42,     "39045 < BS <= 48012"},
    { 43,     "48012 < BS <= 59039"},
    { 44,     "59039 < BS <= 72598"},
    { 45,     "72598 < BS <= 89272"},
    { 46,     "89272 < BS <= 109774"},
    { 47,     "109774 < BS <= 134986"},
    { 48,     "134986 < BS <= 165989"},
    { 49,     "165989 < BS <= 204111"},
    { 50,     "204111 < BS <= 250990"},
    { 51,     "250990 < BS <= 308634"},
    { 52,     "308634 < BS <= 379519"},
    { 53,     "379519 < BS <= 466683"},
    { 54,     "466683 < BS <= 573866"},
    { 55,     "573866 < BS <= 705666"},
    { 56,     "705666 < BS <= 867737"},
    { 57,     "867737 < BS <= 1067031"},
    { 58,     "1067031 < BS <= 1312097"},
    { 59,     "1312097 < BS <= 1613447"},
    { 60,     "1613447 < BS <= 1984009"},
    { 61,     "1984009 < BS <= 2439678"},
    { 62,     "2439678 < BS <= 3000000"},
    { 63,     "BS > 3000000"},
    { 0, NULL }
};
static value_string_ext ext_buffer_size_vals_ext = VALUE_STRING_EXT_INIT(ext_buffer_size_vals);

static uint32_t ext_buffer_size_median[64] = {
    0,  /* BS = 0 */
    5,  /* 0 < BS <= 10 */
    12, /* 10 < BS <= 13 */
    15, /* 13 < BS <= 16 */
    18, /* 16 < BS <= 19 */
    21, /* 19 < BS <= 23 */
    26, /* 23 < BS <= 29 */
    32, /* 29 < BS <= 35 */
    39, /* 35 < BS <= 43 */
    48, /* 43 < BS <= 53 */
    59, /* 53 < BS <= 65 */
    73, /* 65 < BS <= 80 */
    89, /* 80 < BS <= 98 */
    109, /* 98 < BS <= 120 */
    134, /* 120 < BS <= 147 */
    164, /* 147 < BS <= 181 */
    202, /* 181 < BS <= 223 */
    249, /* 223 < BS <= 274 */
    306, /* 274 < BS <= 337 */
    376, /* 337 < BS <= 414 */
    462, /* 414 < BS <= 509 */
    567, /* 509 < BS <= 625 */
    697, /* 625 < BS <= 769 */
    857, /* 769 < BS <= 945 */
    1054, /* 945 < BS <= 1162 */
    1296, /* 1162 < BS <= 1429 */
    1593, /* 1429 < BS <= 1757 */
    1959, /* 1757 < BS <= 2161 */
    2409, /* 2161 < BS <= 2657 */
    2962, /* 2657 < BS <= 3267 */
    5142, /* 3267 < BS <= 4017 */
    4479, /* 4017 < BS <= 4940 */
    5507, /* 4940 < BS <= 6074 */
    6772, /* 6074 < BS <= 7469 */
    8327, /* 7469 < BS <= 9185 */
    10240, /* 9185 < BS <= 11294 */
    12591, /* 11294 < BS <= 13888 */
    15483, /* 13888 < BS <= 17077 */
    19038, /* 17077 < BS <= 20999 */
    23411, /* 20999 < BS <= 25822 */
    28787, /* 25822 < BS <= 31752 */
    35399, /* 31752 < BS <= 39045 */
    43529, /* 39045 < BS <= 48012 */
    53526, /* 48012 < BS <= 59039 */
    65819, /* 59039 < BS <= 72598 */
    80935, /* 72598 < BS <= 89272 */
    99523, /* 89272 < BS <= 109774 */
    122380, /* 109774 < BS <= 134986 */
    150488, /* 134986 < BS <= 165989 */
    185050, /* 165989 < BS <= 204111 */
    227551, /* 204111 < BS <= 250990 */
    279812, /* 250990 < BS <= 308634 */
    344077, /* 308634 < BS <= 379519 */
    423101, /* 379519 < BS <= 466683 */
    520275, /* 466683 < BS <= 573866 */
    705748, /* 573866 < BS <= 705666 */
    786702, /* 705666 < BS <= 867737 */
    967384, /* 867737 < BS <= 1067031 */
    1189564, /* 1067031 < BS <= 1312097 */
    1462772, /* 1312097 < BS <= 1613447 */
    1798728, /* 1613447 < BS <= 1984009 */
    2211844, /* 1984009 < BS <= 2439678 */
    2719839, /* 2439678 < BS <= 3000000 */
    3000001  /* BS > 3000000 */
};

static const value_string power_headroom_vals[] =
{
    { 0,      "-23 <= PH < -22"},
    { 1,      "-22 <= PH < -21"},
    { 2,      "-21 <= PH < -20"},
    { 3,      "-20 <= PH < -19"},
    { 4,      "-19 <= PH < -18"},
    { 5,      "-18 <= PH < -17"},
    { 6,      "-17 <= PH < -16"},
    { 7,      "-16 <= PH < -15"},
    { 8,      "-15 <= PH < -14"},
    { 9,      "-14 <= PH < -13"},
    { 10,     "-13 <= PH < -12"},
    { 11,     "-12 <= PH < -11"},
    { 12,     "-11 <= PH < -10"},
    { 13,     "-10 <= PH < -9"},
    { 14,     "-9 <= PH < -8"},
    { 15,     "-8 <= PH < -7"},
    { 16,     "-7 <= PH < -6"},
    { 17,     "-6 <= PH < -5"},
    { 18,     "-5 <= PH < -4"},
    { 19,     "-4 <= PH < -3"},
    { 20,     "-3 <= PH < -2"},
    { 21,     "-2 <= PH < -1"},
    { 22,     "-1 <= PH < 0"},
    { 23,     "0 <= PH < 1"},
    { 24,     "1 <= PH < 2"},
    { 25,     "2 <= PH < 3"},
    { 26,     "3 <= PH < 4"},
    { 27,     "4 <= PH < 5"},
    { 28,     "5 <= PH < 6"},
    { 29,     "6 <= PH < 7"},
    { 30,     "7 <= PH < 8"},
    { 31,     "8 <= PH < 9"},
    { 32,     "9 <= PH < 10"},
    { 33,     "10 <= PH < 11"},
    { 34,     "11 <= PH < 12"},
    { 35,     "12 <= PH < 13"},
    { 36,     "13 <= PH < 14"},
    { 37,     "14 <= PH < 15"},
    { 38,     "15 <= PH < 16"},
    { 39,     "16 <= PH < 17"},
    { 40,     "17 <= PH < 18"},
    { 41,     "18 <= PH < 19"},
    { 42,     "19 <= PH < 20"},
    { 43,     "20 <= PH < 21"},
    { 44,     "21 <= PH < 22"},
    { 45,     "22 <= PH < 23"},
    { 46,     "23 <= PH < 24"},
    { 47,     "24 <= PH < 25"},
    { 48,     "25 <= PH < 26"},
    { 49,     "26 <= PH < 27"},
    { 50,     "27 <= PH < 28"},
    { 51,     "28 <= PH < 29"},
    { 52,     "29 <= PH < 30"},
    { 53,     "30 <= PH < 31"},
    { 54,     "31 <= PH < 32"},
    { 55,     "32 <= PH < 33"},
    { 56,     "33 <= PH < 34"},
    { 57,     "34 <= PH < 35"},
    { 58,     "34 <= PH < 36"},
    { 59,     "36 <= PH < 37"},
    { 60,     "37 <= PH < 38"},
    { 61,     "38 <= PH < 39"},
    { 62,     "39 <= PH < 40"},
    { 63,     "PH >= 40"},
    { 0, NULL }
};
static value_string_ext power_headroom_vals_ext = VALUE_STRING_EXT_INIT(power_headroom_vals);

static const value_string pcmaxc_vals[] =
{
    { 0,      "Pcmax,c < -29"},
    { 1,      "-29 <= Pcmax,c < -28"},
    { 2,      "-28 <= Pcmax,c < -27"},
    { 3,      "-27 <= Pcmax,c < -26"},
    { 4,      "-26 <= Pcmax,c < -25"},
    { 5,      "-25 <= Pcmax,c < -24"},
    { 6,      "-24 <= Pcmax,c < -23"},
    { 7,      "-23 <= Pcmax,c < -22"},
    { 8,      "-22 <= Pcmax,c < -21"},
    { 9,      "-21 <= Pcmax,c < -20"},
    { 10,     "-20 <= Pcmax,c < -19"},
    { 11,     "-19 <= Pcmax,c < -18"},
    { 12,     "-18 <= Pcmax,c < -17"},
    { 13,     "-17 <= Pcmax,c < -16"},
    { 14,     "-16 <= Pcmax,c < -15"},
    { 15,     "-15 <= Pcmax,c < -14"},
    { 16,     "-14 <= Pcmax,c < -13"},
    { 17,     "-13 <= Pcmax,c < -12"},
    { 18,     "-12 <= Pcmax,c < -11"},
    { 19,     "-11 <= Pcmax,c < -10"},
    { 20,     "-10 <= Pcmax,c < -9"},
    { 21,     "-9 <= Pcmax,c < -8"},
    { 22,     "-8 <= Pcmax,c < -7"},
    { 23,     "-7 <= Pcmax,c < -6"},
    { 24,     "-6 <= Pcmax,c < -5"},
    { 25,     "-5 <= Pcmax,c < -4"},
    { 26,     "-4 <= Pcmax,c < -3"},
    { 27,     "-3 <= Pcmax,c < -2"},
    { 28,     "-2 <= Pcmax,c < -1"},
    { 29,     "-1 <= Pcmax,c < 0"},
    { 30,     "0 <= Pcmax,c < 1"},
    { 31,     "1 <= Pcmax,c < 2"},
    { 32,     "2 <= Pcmax,c < 3"},
    { 33,     "3 <= Pcmax,c < 4"},
    { 34,     "4 <= Pcmax,c < 5"},
    { 35,     "5 <= Pcmax,c < 6"},
    { 36,     "6 <= Pcmax,c < 7"},
    { 37,     "7 <= Pcmax,c < 8"},
    { 38,     "8 <= Pcmax,c < 9"},
    { 39,     "9 <= Pcmax,c < 10"},
    { 40,     "10 <= Pcmax,c < 11"},
    { 41,     "11 <= Pcmax,c < 12"},
    { 42,     "12 <= Pcmax,c < 13"},
    { 43,     "13 <= Pcmax,c < 14"},
    { 44,     "14 <= Pcmax,c < 15"},
    { 45,     "15 <= Pcmax,c < 16"},
    { 46,     "16 <= Pcmax,c < 17"},
    { 47,     "17 <= Pcmax,c < 18"},
    { 48,     "18 <= Pcmax,c < 19"},
    { 49,     "19 <= Pcmax,c < 20"},
    { 50,     "20 <= Pcmax,c < 21"},
    { 51,     "21 <= Pcmax,c < 22"},
    { 52,     "22 <= Pcmax,c < 23"},
    { 53,     "23 <= Pcmax,c < 24"},
    { 54,     "24 <= Pcmax,c < 25"},
    { 55,     "25 <= Pcmax,c < 26"},
    { 56,     "26 <= Pcmax,c < 27"},
    { 57,     "27 <= Pcmax,c < 28"},
    { 58,     "28 <= Pcmax,c < 29"},
    { 59,     "29 <= Pcmax,c < 30"},
    { 60,     "30 <= Pcmax,c < 31"},
    { 61,     "31 <= Pcmax,c < 32"},
    { 62,     "32 <= Pcmax,c < 33"},
    { 63,     "33 <= Pcmax,c"},
    { 0, NULL }
};
static value_string_ext pcmaxc_vals_ext = VALUE_STRING_EXT_INIT(pcmaxc_vals);

static const value_string data_vol_power_headroom_level_vals[] =
{
    { 0, "POWER_HEADROOM_0"},
    { 1, "POWER_HEADROOM_1"},
    { 2, "POWER_HEADROOM_2"},
    { 3, "POWER_HEADROOM_3"},
    { 0, NULL }
};

static const value_string data_vol_extended_power_headroom_level_vals[] =
{
    { 0,  "POWER_HEADROOM_0"},
    { 1,  "POWER_HEADROOM_1"},
    { 2,  "POWER_HEADROOM_2"},
    { 3,  "POWER_HEADROOM_3"},
    { 4,  "POWER_HEADROOM_4"},
    { 5,  "POWER_HEADROOM_5"},
    { 6,  "POWER_HEADROOM_6"},
    { 7,  "POWER_HEADROOM_7"},
    { 8,  "POWER_HEADROOM_8"},
    { 9,  "POWER_HEADROOM_9"},
    { 10, "POWER_HEADROOM_10"},
    { 11, "POWER_HEADROOM_11"},
    { 12, "POWER_HEADROOM_12"},
    { 13, "POWER_HEADROOM_13"},
    { 14, "POWER_HEADROOM_14"},
    { 15, "POWER_HEADROOM_15"},
    { 0, NULL }
};


static const value_string data_vol_power_headroom_data_vol_vals[] =
{
    { 0,  "DV = 0"},
    { 1,  "0 < DV <= 10"},
    { 2,  "10 < DV <= 14"},
    { 3,  "14 < DV <= 19"},
    { 4,  "19 < DV <= 26"},
    { 5,  "26 < DV <= 36"},
    { 6,  "36 < DV <= 49"},
    { 7,  "49 < DV <= 67"},
    { 8,  "67 < DV <= 91"},
    { 9,  "91 < DV <= 125"},
    { 10, "125 < DV <= 171"},
    { 11, "171 < DV <= 234"},
    { 12, "234 < DV <= 321"},
    { 13, "321 < DV <= 768"},
    { 14, "768 < DV <= 1500"},
    { 15, "DV > 1500"},
    { 0, NULL }
};

static const value_string bit_rate_vals[] =
{
    { 0, "no bit rate recommendation"},
    { 1, "0 kbit/s"},
    { 2, "8 kbit/s"},
    { 3, "10 kbit/s"},
    { 4, "12 kbit/s"},
    { 5, "16 kbit/s"},
    { 6, "20 kbit/s"},
    { 7, "24 kbit/s"},
    { 8, "28 kbit/s"},
    { 9, "32 kbit/s"},
    { 10, "36 kbit/s"},
    { 11, "40 kbit/s"},
    { 12, "48 kbit/s"},
    { 13, "56 kbit/s"},
    { 14, "72 kbit/s"},
    { 15, "88 kbit/s"},
    { 16, "104 kbit/s"},
    { 17, "120 kbit/s"},
    { 18, "140 kbit/s"},
    { 19, "160 kbit/s"},
    { 20, "180 kbit/s"},
    { 21, "200 kbit/s"},
    { 22, "220 kbit/s"},
    { 23, "240 kbit/s"},
    { 24, "260 kbit/s"},
    { 25, "280 kbit/s"},
    { 26, "300 kbit/s"},
    { 27, "350 kbit/s"},
    { 28, "400 kbit/s"},
    { 29, "450 kbit/s"},
    { 30, "500 kbit/s"},
    { 31, "600 kbit/s"},
    { 32, "700 kbit/s"},
    { 33, "800 kbit/s"},
    { 34, "900 kbit/s"},
    { 35, "1000 kbit/s"},
    { 36, "1100 kbit/s"},
    { 37, "1200 kbit/s"},
    { 38, "1300 kbit/s"},
    { 39, "1400 kbit/s"},
    { 40, "1500 kbit/s"},
    { 41, "1750 kbit/s"},
    { 42, "2000 kbit/s"},
    { 43, "2250 kbit/s"},
    { 44, "2500 kbit/s"},
    { 45, "2750 kbit/s"},
    { 46, "3000 kbit/s"},
    { 47, "3500 kbit/s"},
    { 48, "4000 kbit/s"},
    { 49, "4500 kbit/s"},
    { 50, "5000 kbit/s"},
    { 51, "5500 kbit/s"},
    { 52, "6000 kbit/s"},
    { 53, "6500 kbit/s"},
    { 54, "7000 kbit/s"},
    { 55, "7500 kbit/s"},
    { 56, "8000 kbit/s"},
    { 0, NULL }
};
static value_string_ext bit_rate_vals_ext = VALUE_STRING_EXT_INIT(bit_rate_vals);

static const value_string header_only_vals[] =
{
    { 0,      "MAC PDU Headers and body present"},
    { 1,      "MAC PDU Headers only"},
    { 0, NULL }
};

static const value_string predefined_frame_vals[] =
{
    { 0,      "Real MAC PDU present - will dissect"},
    { 1,      "Predefined frame present - will not dissect"},
    { 0, NULL }
};

static const value_string ul_retx_grant_vals[] =
{
    { 0,      "PDCCH ReTx"},
    { 1,      "PHICH NACK"},
    { 0, NULL }
};

/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/

/* If this PDU has been NACK'd (by HARQ) more than a certain number of times,
   we trigger an expert warning. */
static int global_mac_lte_retx_counter_trigger = 3;

/* By default try to decode transparent data (BCH, PCH and CCCH) data using LTE RRC dissector */
static bool global_mac_lte_attempt_rrc_decode = true;

/* Whether should attempt to dissect frames failing CRC check */
static bool global_mac_lte_dissect_crc_failures;

/* Whether should attempt to decode lcid 1&2 SDUs as srb1/2 (i.e. AM RLC) */
static bool global_mac_lte_attempt_srb_decode = true;

/* Whether should attempt to decode MCH LCID 0 as MCCH */
static bool global_mac_lte_attempt_mcch_decode;

/* Whether should call RLC dissector to decode MTCH LCIDs */
static bool global_mac_lte_call_rlc_for_mtch;

/* Where to take LCID -> DRB mappings from */
enum lcid_drb_source {
    FromStaticTable, FromConfigurationProtocol
};
static int global_mac_lte_lcid_drb_source = (int)FromStaticTable;

/* Threshold for warning in expert info about high BSR values */
static int global_mac_lte_bsr_warn_threshold = 50; /* default is 19325 -> 22624 */

/* Whether or not to track SRs and related frames */
static bool global_mac_lte_track_sr = true;

/* Which layer info to show in the info column */
enum layer_to_show {
    ShowPHYLayer, ShowMACLayer, ShowRLCLayer
};

/* Which layer's details to show in Info column */
static int      global_mac_lte_layer_to_show = (int)ShowRLCLayer;

/* Whether to decode Contention Resolution body as UL CCCH */
static bool global_mac_lte_decode_cr_body;

/* Whether to record config and try to show DRX state for each configured UE */
static bool global_mac_lte_show_drx;

/* Whether to record config and try to show DRX state for each configured UE */
static bool global_mac_lte_show_BSR_median;


/* When showing RLC info, count PDUs so can append info column properly */
static uint8_t  s_number_of_rlc_pdus_shown;

/***********************************************************************/
/* How to dissect lcid 3-10 (presume drb logical channels)             */

static const value_string drb_lcid_vals[] = {
    { 3,  "LCID 3"},
    { 4,  "LCID 4"},
    { 5,  "LCID 5"},
    { 6,  "LCID 6"},
    { 7,  "LCID 7"},
    { 8,  "LCID 8"},
    { 9,  "LCID 9"},
    { 10, "LCID 10"},
    { 0, NULL }
};

typedef enum rlc_channel_type_t {
    rlcRaw,
    rlcTM,
    rlcUM5,
    rlcUM10,
    rlcAM,
    rlcAMulExtLiField,
    rlcAMdlExtLiField,
    rlcAMextLiField,
    rlcAMul16,
    rlcAMdl16,
    rlcAM16,
    rlcAMul16ulExtLiField,
    rlcAMdl16ulExtLiField,
    rlcAM16ulExtLiField,
    rlcAMul16dlExtLiField,
    rlcAMdl16dlExtLiField,
    rlcAM16dlExtLiField,
    rlcAMul16extLiField,
    rlcAMdl16extLiField,
    rlcAM16extLiField,
} rlc_channel_type_t;

static const value_string rlc_channel_type_vals[] = {
    { rlcTM                , "TM"},
    { rlcUM5               , "UM, SN Len=5"},
    { rlcUM10              , "UM, SN Len=10"},
    { rlcAM                , "AM"},
    { rlcAMulExtLiField    , "AM, UL Extended LI Field"},
    { rlcAMdlExtLiField    , "AM, DL Extended LI Field"},
    { rlcAMextLiField      , "AM, UL/DL Extended LI Field"},
    { rlcAMul16            , "AM, UL SN Len=16"},
    { rlcAMdl16            , "AM, DL SN Len=16"},
    { rlcAM16              , "AM, SN Len=16"},
    { rlcAMul16ulExtLiField, "AM, UL SN Len=16, UL Extended LI Field"},
    { rlcAMdl16ulExtLiField, "AM, DL SN Len=16, UL Extended LI Field"},
    { rlcAM16ulExtLiField  , "AM, SN Len=16, UL Extended LI Field"},
    { rlcAMul16dlExtLiField, "AM, UL SN Len=16, DL Extended LI Field"},
    { rlcAMdl16dlExtLiField, "AM, DL SN Len=16, DL Extended LI Field"},
    { rlcAM16dlExtLiField  , "AM, SN Len=16, DL Extended LI Field"},
    { rlcAMul16extLiField  , "AM, UL SN Len=16, UL/DL Extended LI Field"},
    { rlcAMdl16extLiField  , "AM, DL SN Len=16, UL/DL Extended LI Field"},
    { rlcAM16extLiField    , "AM, SN Len=16, UL/DL Extended LI Field"},
    { 0, NULL }
};


/* Mapping type */
typedef struct lcid_drb_mapping_t {
    uint16_t lcid;
    int     drbid;
    rlc_channel_type_t channel_type;
} lcid_drb_mapping_t;

/* Mapping entity */
static lcid_drb_mapping_t *lcid_drb_mappings;
static unsigned num_lcid_drb_mappings;

UAT_VS_DEF(lcid_drb_mappings, lcid, lcid_drb_mapping_t, uint16_t, 3, "LCID 3")
UAT_SIGNED_DEC_CB_DEF(lcid_drb_mappings, drbid, lcid_drb_mapping_t)
UAT_VS_DEF(lcid_drb_mappings, channel_type, lcid_drb_mapping_t, rlc_channel_type_t, rlcAM, "AM")

/* UAT object */
static uat_t* lcid_drb_mappings_uat;

/* Dynamic mappings (set by configuration protocol)
   LCID is the index into the array of these */
typedef struct dynamic_lcid_drb_mapping_t {
    bool valid;
    int      drbid;
    rlc_channel_type_t channel_type;
    uint8_t  ul_priority;
} dynamic_lcid_drb_mapping_t;

typedef struct ue_dynamic_drb_mappings_t {
    dynamic_lcid_drb_mapping_t mapping[39];  /* Index is LCID */
    uint8_t drb_to_lcid_mappings[33];         /* Also map drbid -> lcid */
} ue_dynamic_drb_mappings_t;

static GHashTable *mac_lte_ue_channels_hash;


extern int proto_rlc_lte;

/***************************************************************/



/***************************************************************/
/* Keeping track of Msg3 bodies so they can be compared with   */
/* Contention Resolution bodies.                               */

typedef struct Msg3Data {
    uint8_t  data[6];
    nstime_t msg3Time;
    uint32_t framenum;
} Msg3Data;


/* This table stores (RNTI -> Msg3Data*).  Will be populated when
   Msg3 frames are first read.  */
static GHashTable *mac_lte_msg3_hash;

typedef enum ContentionResolutionStatus {
    NoMsg3,
    Msg3Match,
    Msg3NoMatch
} ContentionResolutionStatus;

typedef struct ContentionResolutionResult {
    ContentionResolutionStatus status;
    unsigned                   msg3FrameNum;
    unsigned                   msSinceMsg3;
} ContentionResolutionResult;


/* This table stores (CRFrameNum -> CRResult).  It is assigned during the first
   pass and used thereafter */
static GHashTable *mac_lte_cr_result_hash;

/* This table stores msg3 frame -> CR frame.  It is assigned during the first pass
 * and shown in later passes */
static GHashTable *mac_lte_msg3_cr_hash;

/**************************************************************************/



/****************************************************************/
/* Keeping track of last DL frames per C-RNTI so can guess when */
/* there has been a HARQ retransmission                         */
/* TODO: this should be simplified now that harq-id & ndi are   */
/* being logged!                                                */

/* Could be bigger, but more than enough to flag suspected resends */
#define MAX_EXPECTED_PDU_LENGTH 2048

typedef struct LastFrameData {
    bool inUse;
    uint32_t framenum;
    bool ndi;
    nstime_t received_time;
    int      length;
    uint8_t  data[MAX_EXPECTED_PDU_LENGTH];
} LastFrameData;

typedef struct DLHarqBuffers {
    LastFrameData harqid[2][15];  /* 2 blocks (1 for each antenna) needed for DL */
} DLHarqBuffers;


/* This table stores (RNTI -> DLHARQBuffers*).  Will be populated when
   DL frames are first read.  */
static GHashTable *mac_lte_dl_harq_hash;

typedef struct DLHARQResult {
    bool        previousSet, nextSet;
    unsigned    previousFrameNum;
    unsigned    timeSincePreviousFrame;
    unsigned    nextFrameNum;
    unsigned    timeToNextFrame;
} DLHARQResult;


/* This table stores (FrameNumber -> *DLHARQResult).  It is assigned during the first
   pass and used thereafter */
static GHashTable *mac_lte_dl_harq_result_hash;

/**************************************************************************/


/*****************************************************************/
/* Keeping track of last UL frames per C-RNTI so can verify when */
/* told that a frame is a retx                                   */

typedef struct ULHarqBuffers {
    LastFrameData harqid[8];
} ULHarqBuffers;


/* This table stores (RNTI -> ULHarqBuffers*).  Will be populated when
   UL frames are first read.  */
static GHashTable *mac_lte_ul_harq_hash;

typedef struct ULHARQResult {
    bool        previousSet, nextSet;
    unsigned    previousFrameNum;
    unsigned    timeSincePreviousFrame;
    unsigned    nextFrameNum;
    unsigned    timeToNextFrame;
} ULHARQResult;


/* This table stores (FrameNum -> ULHARQResult).  It is assigned during the first
   pass and used thereafter */
/* TODO: add ueid/rnti to key... */
static GHashTable *mac_lte_ul_harq_result_hash;

/**************************************************************************/


/**************************************************************************/
/* Tracking of Scheduling Requests (SRs).                                 */
/* Keep track of:                                                         */
/* - last grant before SR                                                 */
/* - SR failures following request                                        */
/* - grant following SR                                                   */

typedef enum SREvent {
    SR_Grant,
    SR_Request,
    SR_Failure
} SREvent;

static const value_string sr_event_vals[] =
{
    { SR_Grant,        "Grant"},
    { SR_Request,      "SR Request"},
    { SR_Failure,      "SR Failure"},
    { 0,               NULL}
};

typedef enum SRStatus {
    None,
    SR_Outstanding,
    SR_Failed
} SRStatus;

static const value_string sr_status_vals[] =
{
    { None,                "Receiving grants"},
    { SR_Outstanding,      "SR Request outstanding"},
    { SR_Failed,           "SR has Failed"},
    { 0,                   NULL}
};


typedef struct SRState {
    SRStatus status;
    uint32_t lastSRFramenum;
    uint32_t lastGrantFramenum;
    nstime_t requestTime;
} SRState;


/* This table keeps track of the SR state for each UE.
   (RNTI -> SRState) */
static GHashTable *mac_lte_ue_sr_state;


typedef enum SRResultType {
    GrantAnsweringSR,
    FailureAnsweringSR,
    SRLeadingToGrant,
    SRLeadingToFailure,
    InvalidSREvent
} SRResultType;


typedef struct SRResult {
    SRResultType type;
    uint32_t     frameNum;
    uint32_t     timeDifference;

    /* These 2 are only used with InvalidSREvent */
    SRStatus     status;
    SREvent      event;
} SRResult;

/* Entries in this table are created during the first pass
   It maps (SRFrameNum -> SRResult) */
static GHashTable *mac_lte_sr_request_hash;

/**************************************************************************/


typedef struct drx_running_state_t
{
    bool         firstCycleStartSet;

    /* Cycle information */
    bool         inShortCycle;

    /* Timers */
    nstime_t     currentTime;  /* absolute time of last PDU. Used to detect whole
                                  missing SFN cycle */

    uint64_t     currentTicks;
    uint16_t     currentSFN;
    uint16_t     currentSF;

    /* These timers are absolute times when these events expire */
    uint64_t     onDurationTimer;
    uint64_t     inactivityTimer;
    uint64_t     RTT[8];
    uint64_t     retransmissionTimer[8];
    uint64_t     shortCycleTimer;

} drx_running_state_t;

/* Have 2 states for each PDU.  One for before the PDU/event, and one after.
   Only then can show if we don't think it should have been active at that point... */
typedef struct drx_state_t {
    drx_config_t          config;
    drx_running_state_t   state_before;
    drx_running_state_t   state_after;
} drx_state_t;

typedef struct ue_parameters_t
{
    bool use_ext_bsr_sizes;
    bool use_simult_pucch_pusch_pcell;
    bool use_simult_pucch_pusch_pscell;
    bool drx_state_valid;
    drx_state_t drx_state;
} ue_parameters_t;

/* Entries in this table are maintained during the first pass
   It maps (UEId -> ue_parameters_t). */
static GHashTable *mac_lte_ue_parameters;


/**************************************************************************/
/* DRX State                                                              */
/* Config for current cycle/timer state for a configured UE               */


typedef struct drx_state_key_t {
    uint32_t frameNumber;
    unsigned   pdu_instance;
} drx_state_key_t;

/* Entries in this table are written during the first pass
   It maps (drx_state_key_t -> drx_state_t), so state at that point may be shown. */
static GHashTable *mac_lte_drx_frame_result;

static int mac_lte_framenum_instance_hash_equal(const void *v, const void *v2)
{
    const drx_state_key_t *p1 = (const drx_state_key_t*)v;
    const drx_state_key_t *p2 = (const drx_state_key_t*)v2;

    return ((p1->frameNumber == p2->frameNumber) &&
            (p1->pdu_instance == p2->pdu_instance));
}

static unsigned mac_lte_framenum_instance_hash_func(const void *v)
{
    const drx_state_key_t *p1 = (const drx_state_key_t*)v;

    return p1->frameNumber + (p1->pdu_instance >> 8);
}




/* Initialise the UE DRX state */
static void init_drx_ue_state(drx_state_t *drx_state, bool at_init)
{
    int i;
    drx_state->state_before.inShortCycle = false;
    if (at_init) {
        drx_state->state_before.onDurationTimer = UINT64_C(0);
    }
    drx_state->state_before.inactivityTimer = UINT64_C(0);
    for (i=0; i < 8; i++) {
        drx_state->state_before.RTT[i] = UINT64_C(0);
        drx_state->state_before.retransmissionTimer[i] = UINT64_C(0);
    }
    drx_state->state_before.shortCycleTimer = UINT64_C(0);
}

typedef enum drx_timer_type_t {
    drx_onduration_timer,
    drx_inactivity_timer,
    drx_rtt_timer,
    drx_retx_timer,
    drx_short_cycle_timer
} drx_timer_type_t;

/* Start the specified timer.  Use the time period in the config */
static void mac_lte_drx_start_timer(drx_state_t *p_state, drx_timer_type_t timer_type, uint8_t timer_id)
{
    /* Get current time in ms */
    uint64_t *pTimer;
    uint16_t timerLength;

    /* Get pointer to timer value, and fetch from config how much to add to it */
    switch (timer_type) {
        case drx_onduration_timer:
            pTimer = &(p_state->state_before.onDurationTimer);
            timerLength = p_state->config.onDurationTimer;
            break;
        case drx_inactivity_timer:
            pTimer = &(p_state->state_before.inactivityTimer);
            timerLength = p_state->config.inactivityTimer;
            break;
        case drx_rtt_timer:
            pTimer = &(p_state->state_before.RTT[timer_id]);
            timerLength = 8;
            break;
        case drx_retx_timer:
            pTimer = &(p_state->state_before.retransmissionTimer[timer_id]);
            timerLength = p_state->config.retransmissionTimer;
            break;
        case drx_short_cycle_timer:
        default:
            pTimer = &(p_state->state_before.shortCycleTimer);
            timerLength = p_state->config.shortCycle * p_state->config.shortCycleTimer;
            break;
    }

    /* Set timer */
    *pTimer = p_state->state_before.currentTicks + timerLength;
}

/* Stop the specified timer.  */
static void mac_lte_drx_stop_timer(drx_state_t *p_state, drx_timer_type_t timer_type, uint8_t timer_id)
{
    /* Set indicated timer value to 0 */
    switch (timer_type) {
        case drx_onduration_timer:
            p_state->state_before.onDurationTimer = UINT64_C(0);
            break;
        case drx_inactivity_timer:
            p_state->state_before.inactivityTimer = UINT64_C(0);
            break;
        case drx_rtt_timer:
            p_state->state_before.RTT[timer_id] = UINT64_C(0);
            break;
        case drx_retx_timer:
            p_state->state_before.retransmissionTimer[timer_id] = UINT64_C(0);
            break;
        case drx_short_cycle_timer:
            p_state->state_before.shortCycleTimer = UINT64_C(0);
            break;
    }
}

/* Has the specified timer expired?  */
static bool mac_lte_drx_has_timer_expired(drx_state_t *p_state, drx_timer_type_t timer_type, uint8_t timer_id,
                                          bool    before_event,
                                          uint64_t *time_until_expires)
{
    uint64_t *pTimer = NULL;
    drx_running_state_t *state_to_use;

    if (before_event) {
        state_to_use = &p_state->state_before;
    }
    else {
        state_to_use = &p_state->state_after;
    }


    /* Get pointer to timer value */
    switch (timer_type) {
        case drx_onduration_timer:
            pTimer = &(state_to_use->onDurationTimer);
            break;
        case drx_inactivity_timer:
            pTimer = &(state_to_use->inactivityTimer);
            break;
        case drx_rtt_timer:
            pTimer = &(state_to_use->RTT[timer_id]);
            break;
        case drx_retx_timer:
            pTimer = &(state_to_use->retransmissionTimer[timer_id]);
            break;
        case drx_short_cycle_timer:
            pTimer = &(state_to_use->shortCycleTimer);
            break;

        default:
            return false;
    }

    /* TODO: verify using SFN/SF ? */
    if (state_to_use->currentTicks == *pTimer) {
        *time_until_expires = 0;
        return true;
    }

    if (state_to_use->currentTicks > *pTimer) {
        *time_until_expires = 0;
    }
    else {
        *time_until_expires = *pTimer - state_to_use->currentTicks;
    }

    return false;
}


/* Handling of triggers that can prompt changes in state */

static void mac_lte_drx_new_ulsch_data(uint16_t ueid)
{
    /* Look up state of this UE */
    ue_parameters_t *ue_params = (ue_parameters_t *)g_hash_table_lookup(mac_lte_ue_parameters,
                                                                        GUINT_TO_POINTER((unsigned)ueid));

    /* Start inactivity timer */
    if ((ue_params != NULL) && ue_params->drx_state_valid) {
        mac_lte_drx_start_timer(&ue_params->drx_state, drx_inactivity_timer, 0);
    }
}

static void mac_lte_drx_new_dlsch_data(uint16_t ueid)
{
    /* Look up state of this UE */
    ue_parameters_t *ue_params = (ue_parameters_t *)g_hash_table_lookup(mac_lte_ue_parameters,
                                                                        GUINT_TO_POINTER((unsigned)ueid));

    /* Start retransmission timer */
    if ((ue_params != NULL) && ue_params->drx_state_valid) {
        mac_lte_drx_start_timer(&ue_params->drx_state, drx_inactivity_timer, 0);
    }
}

static void mac_lte_drx_dl_crc_error(uint16_t ueid)
{
    /* Look up state of this UE */
    ue_parameters_t *ue_params = (ue_parameters_t *)g_hash_table_lookup(mac_lte_ue_parameters,
                                                                        GUINT_TO_POINTER((unsigned)ueid));

    /* Start timer */
    if ((ue_params != NULL) && ue_params->drx_state_valid) {
        mac_lte_drx_start_timer(&ue_params->drx_state, drx_retx_timer, 0);
    }
}

/* A DRX control element has been received */
static void mac_lte_drx_control_element_received(uint16_t ueid)
{
    /* Look up state of this UE */
    ue_parameters_t *ue_params = (ue_parameters_t *)g_hash_table_lookup(mac_lte_ue_parameters,
                                                                        GUINT_TO_POINTER((unsigned)ueid));

    /* Start timers */
    if ((ue_params != NULL) && ue_params->drx_state_valid) {
        mac_lte_drx_stop_timer(&ue_params->drx_state, drx_onduration_timer, 0);
        mac_lte_drx_stop_timer(&ue_params->drx_state, drx_inactivity_timer, 0);
    }
}


/* Update the DRX state of the UE based on previous info and current time.
   This is called every time a UE with DRX configured has an UL or DL PDU */
static void update_drx_info(packet_info *pinfo, mac_lte_info *p_mac_lte_info)
{
    int harq_id;
    uint64_t time_until_expires;

    /* Look up state of this UE */
    ue_parameters_t *ue_params = (ue_parameters_t *)g_hash_table_lookup(mac_lte_ue_parameters,
                                                                        GUINT_TO_POINTER((unsigned)p_mac_lte_info->ueid));

    if ((ue_params != NULL) && ue_params->drx_state_valid) {
        /* We loop until we find this subframe */
        drx_state_t *ue_state = &ue_params->drx_state;
        uint16_t SFN = p_mac_lte_info->sysframeNumber;
        uint16_t SF = p_mac_lte_info->subframeNumber;

        /* Make sure the first time reference has been set */
        if (!ue_state->state_before.firstCycleStartSet) {
            /* Set current time to now */
            ue_state->state_before.currentSFN = SFN;
            ue_state->state_before.currentSF = SF;

            ue_state->state_before.currentTicks = SFN*10 + SF;

            ue_state->state_before.firstCycleStartSet = true;
        }

        /* Will loop around these checks, once for each subframe between previous
           currentTime for this UE, and the time now!!! */
        /* It *should* be possible to just deal with the elapsed time all at once,
           but much harder to get right, so loop. */

        /* If > ~10s since last PDU, just zero all timers (except onDuration) */
        if ((pinfo->abs_ts.secs - ue_state->state_before.currentTime.secs) >= 9) {
            init_drx_ue_state(ue_state, false);
        }

        while ((ue_state->state_before.currentSFN != SFN) || (ue_state->state_before.currentSF != SF)) {
            uint16_t subframes = ue_state->state_before.currentSFN*10 + ue_state->state_before.currentSF;

            /* Check for timers that have expired and change state accordingly */

            /* Short -> long transition */
            if (ue_state->state_before.inShortCycle) {
                if (mac_lte_drx_has_timer_expired(ue_state, drx_short_cycle_timer, 0, true, &time_until_expires)) {
                    ue_state->state_before.inShortCycle = false;
                }
            }

            /* See if onDuration timer should be started */

            if (!ue_state->state_before.inShortCycle) {
                if ((subframes % ue_state->config.longCycle) == ue_state->config.cycleOffset) {
                    mac_lte_drx_start_timer(ue_state, drx_onduration_timer, 0);
                }
            }
            else {
                if ((subframes % ue_state->config.shortCycle) == (ue_state->config.cycleOffset % ue_state->config.shortCycle)) {
                    mac_lte_drx_start_timer(ue_state, drx_onduration_timer, 0);
                }
            }

            /* Check for HARQ RTT Timer expiring.
               In practice only one could expire in any given subframe... */
            for (harq_id = 0 ; harq_id < 8; harq_id++) {
                if (mac_lte_drx_has_timer_expired(ue_state, drx_rtt_timer, harq_id, true, &time_until_expires)) {
                    /* Start the Retransmission timer */
                    mac_lte_drx_start_timer(ue_state, drx_retx_timer, harq_id);
                }
            }

            /* Reception of DRX command is dealt with separately at the moment... */

            /* Inactivity timer expired */
            if (mac_lte_drx_has_timer_expired(ue_state, drx_inactivity_timer, 0, true, &time_until_expires)) {
                if (ue_state->config.shortCycleConfigured) {
                    ue_state->state_before.inShortCycle = true;
                    mac_lte_drx_start_timer(ue_state, drx_short_cycle_timer, 0);
                }
            }


            /* Move subframe along by one */
            if (ue_state->state_before.currentSF == 9) {
                ue_state->state_before.currentSF = 0;
                if (ue_state->state_before.currentSFN == 1023) {
                    ue_state->state_before.currentSFN = 0;
                }
                else {
                    ue_state->state_before.currentSFN++;
                }
            }
            else {
                ue_state->state_before.currentSF++;
            }

            ue_state->state_before.currentTicks++;
        }

        /* Set current time to now */
        ue_state->state_before.currentTime = pinfo->abs_ts;
    }
}

/* Convenience function to get a pointer for the hash_func to work with */
static void *get_drx_result_hash_key(uint32_t frameNumber,
                                        unsigned pdu_instance,
                                        bool do_persist)
{
    static drx_state_key_t key;
    drx_state_key_t *p_key;

    /* Only allocate a struct when will be adding entry */
    if (do_persist) {
        p_key = wmem_new0(wmem_file_scope(), drx_state_key_t);
    }
    else {
        memset(&key, 0, sizeof(drx_state_key_t));
        p_key = &key;
    }

    /* Fill in details, and return pointer */
    p_key->frameNumber = frameNumber;
    p_key->pdu_instance = pdu_instance;

    return p_key;
}


/* Set DRX information to display for the current MAC frame.
   Only called on first pass through frames. */
static void set_drx_info(packet_info *pinfo, mac_lte_info *p_mac_lte_info, bool before_event, unsigned pdu_instance)
{
    /* Look up state of this UE */
    ue_parameters_t *ue_params = (ue_parameters_t *)g_hash_table_lookup(mac_lte_ue_parameters,
                                                                        GUINT_TO_POINTER((unsigned)p_mac_lte_info->ueid));
    drx_state_t *frame_result;

    if ((ue_params != NULL) && ue_params->drx_state_valid) {
        /* Should only need to allocate frame_result and add to the result table when
           before PDU is processed */
        if (before_event) {
            /* Copy UE snapshot for this frame, and add to result table */
            frame_result = wmem_new(wmem_file_scope(), drx_state_t);

            /* Deep-copy this snapshot for this frame */
            *frame_result = ue_params->drx_state;

            /* And store in table */
            g_hash_table_insert(mac_lte_drx_frame_result, get_drx_result_hash_key(pinfo->num, pdu_instance, true), frame_result);
        }
        else {
            /* After update, so just copy ue_state 'state' info after part of frame */
            frame_result = (drx_state_t*)g_hash_table_lookup(mac_lte_drx_frame_result,
                                                             get_drx_result_hash_key(pinfo->num, pdu_instance, false));
            if (frame_result != NULL) {
                /* Deep-copy updated state from UE */
                frame_result->state_after = ue_params->drx_state.state_before;
            }
        }
    }
}

/* Show DRX information associated with this MAC frame */
static void show_drx_info(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                          mac_lte_info *p_mac_lte_info, bool before_event, unsigned pdu_instance)
{
    drx_state_t         *frame_state;
    drx_running_state_t *state_to_show;
    uint64_t            time_until_expires;
    unsigned            n;

    /* Look up entry by frame number in result table */
    frame_state = (drx_state_t *)g_hash_table_lookup(mac_lte_drx_frame_result,
                                                     get_drx_result_hash_key(pinfo->num, pdu_instance, false));

    /* Show available information */
    if (frame_state != NULL) {
        proto_tree *drx_config_tree, *drx_state_tree;
        proto_item *drx_config_ti, *drx_state_ti, *ti;

        /* Show config only if 'before */
        if (before_event) {
            /************************************/
            /* Create config subtree            */
            drx_config_ti = proto_tree_add_string_format(tree, hf_mac_lte_drx_config,
                                                  tvb, 0, 0, "", "DRX Config");
            drx_config_tree = proto_item_add_subtree(drx_config_ti, ett_mac_lte_drx_config);
            proto_item_set_generated(drx_config_ti);

            /* Link back to configuration (RRC) frame */
            ti = proto_tree_add_uint(drx_config_tree, hf_mac_lte_drx_config_frame_num, tvb,
                                     0, 0, frame_state->config.frameNum);
            proto_item_set_generated(ti);

            /* Link back to any previous config frame (only from current config frame) */
            if ((frame_state->config.frameNum == pinfo->num) &&
                (frame_state->config.previousFrameNum != 0)) {
                    ti = proto_tree_add_uint(drx_config_tree, hf_mac_lte_drx_config_previous_frame_num, tvb,
                                             0, 0, frame_state->config.previousFrameNum);
                    proto_item_set_generated(ti);
            }

            /* Config fields */
            ti = proto_tree_add_uint(drx_config_tree, hf_mac_lte_drx_config_long_cycle, tvb,
                                     0, 0, frame_state->config.longCycle);
            proto_item_set_generated(ti);
            ti = proto_tree_add_uint(drx_config_tree, hf_mac_lte_drx_config_cycle_offset, tvb,
                                     0, 0, frame_state->config.cycleOffset);
            proto_item_set_generated(ti);
            ti = proto_tree_add_uint(drx_config_tree, hf_mac_lte_drx_config_onduration_timer, tvb,
                                     0, 0, frame_state->config.onDurationTimer);
            proto_item_set_generated(ti);
            ti = proto_tree_add_uint(drx_config_tree, hf_mac_lte_drx_config_inactivity_timer, tvb,
                                     0, 0, frame_state->config.inactivityTimer);
            proto_item_set_generated(ti);
            ti = proto_tree_add_uint(drx_config_tree, hf_mac_lte_drx_config_retransmission_timer, tvb,
                                     0, 0, frame_state->config.retransmissionTimer);
            proto_item_set_generated(ti);

            if (frame_state->config.shortCycleConfigured) {
                ti = proto_tree_add_uint(drx_config_tree, hf_mac_lte_drx_config_short_cycle, tvb,
                                         0, 0, frame_state->config.shortCycle);
                proto_item_set_generated(ti);

                ti = proto_tree_add_uint(drx_config_tree, hf_mac_lte_drx_config_short_cycle_timer, tvb,
                                         0, 0, frame_state->config.shortCycleTimer);
                proto_item_set_generated(ti);
            }

            proto_item_append_text(drx_config_ti, " (Long-cycle=%u cycle-offset=%u onDuration=%u)",
                                   frame_state->config.longCycle, frame_state->config.cycleOffset,
                                   frame_state->config.onDurationTimer);
            if (frame_state->config.shortCycleConfigured) {
                proto_item_append_text(drx_config_ti, " (Short-cycle=%u Short-cycle-timer=%u)",
                                       frame_state->config.shortCycle, frame_state->config.shortCycleTimer);
            }
        }

        /*************************************/
        /* Create state subtree              */
        drx_state_ti = proto_tree_add_string_format(tree, hf_mac_lte_drx_state,
                                                    tvb, 0, 0, "",
                                                    (before_event) ? "DRX State Before" : "DRX State After");
        /* Get appropriate state pointer to use below */
        if (before_event) {
            state_to_show = &frame_state->state_before;
        }
        else {
            state_to_show = &frame_state->state_after;
        }

        drx_state_tree = proto_item_add_subtree(drx_state_ti, ett_mac_lte_drx_state);
        proto_item_set_generated(drx_state_ti);

        /* Show cycle information */

        if (!state_to_show->inShortCycle) {
            /* Show where we are in current long cycle */
            uint16_t offset_into_long_cycle = ((p_mac_lte_info->sysframeNumber*10) + p_mac_lte_info->subframeNumber) %
                                              frame_state->config.longCycle;
            ti = proto_tree_add_uint(drx_state_tree, hf_mac_lte_drx_state_long_cycle_offset, tvb,
                                     0, 0, offset_into_long_cycle);
            proto_item_set_generated(ti);
        }
        else {
            /* Show where we are inside short cycle */
            uint16_t offset_into_short_cycle = ((p_mac_lte_info->sysframeNumber*10) + p_mac_lte_info->subframeNumber) %
                                                frame_state->config.shortCycle;

            ti = proto_tree_add_uint(drx_state_tree, hf_mac_lte_drx_state_short_cycle_offset, tvb,
                                     0, 0, offset_into_short_cycle);
            proto_item_set_generated(ti);

            /* Is short-cycle-timer running? */
            if (!mac_lte_drx_has_timer_expired(frame_state, drx_short_cycle_timer, 0, before_event, &time_until_expires)) {
                if (time_until_expires) {
                    ti = proto_tree_add_uint(drx_state_tree, hf_mac_lte_drx_state_short_cycle_remaining, tvb,
                                             0, 0, (uint16_t)time_until_expires);
                    proto_item_set_generated(ti);
                }
            }
        }

        /* Show which timers are still running and how long they have to go.
           TODO: Complain if it looks like DRX looks like it should be on
           TODO: if PDU is a retranmission, would be good to check to see if DRX
                 would have been on for original Tx! */

        /* Is onduration timer running? */
        if (!mac_lte_drx_has_timer_expired(frame_state, drx_onduration_timer, 0, before_event, &time_until_expires)) {
            if (time_until_expires) {
                ti = proto_tree_add_uint(drx_state_tree, hf_mac_lte_drx_state_onduration_remaining, tvb,
                                         0, 0, (uint16_t)time_until_expires);
                proto_item_set_generated(ti);
            }
        }

        /* Is inactivity timer running? */
        if (!mac_lte_drx_has_timer_expired(frame_state, drx_inactivity_timer, 0, before_event, &time_until_expires)) {
            if (time_until_expires) {
                ti = proto_tree_add_uint(drx_state_tree, hf_mac_lte_drx_state_inactivity_remaining, tvb,
                                         0, 0, (uint16_t)time_until_expires);
                proto_item_set_generated(ti);
            }
        }

        /* Are any of the Retransmission timers running? */
        for (n=0; n < 8; n++) {
            if (!mac_lte_drx_has_timer_expired(frame_state, drx_retx_timer, n, before_event, &time_until_expires)) {
                if (time_until_expires) {
                    ti = proto_tree_add_uint(drx_state_tree, hf_mac_lte_drx_state_retransmission_remaining, tvb,
                                             0, 0, (uint16_t)time_until_expires);
                    proto_item_set_generated(ti);
                    proto_item_append_text(ti, " (harqid=%u)", n);
                }
            }
        }

        /* Are any of the RTT timers running? */
        for (n=0; n < 8; n++) {
            if (!mac_lte_drx_has_timer_expired(frame_state, drx_rtt_timer, n, before_event, &time_until_expires)) {
                if (time_until_expires) {
                    ti = proto_tree_add_uint(drx_state_tree, hf_mac_lte_drx_state_rtt_remaining, tvb,
                                             0, 0, (uint16_t)time_until_expires);
                    proto_item_set_generated(ti);
                    proto_item_append_text(ti, " (harqid=%u)", n);
                }
            }
        }
    }
}


/**************************************************************************/


/* Info we might learn from SIB2 to label RAPIDs seen in PRACH and RARs */
static bool     s_rapid_ranges_configured;
static unsigned s_rapid_ranges_groupA;
static unsigned s_rapid_ranges_RA;

/* Return string description of rapid */
static const char *get_mac_lte_rapid_description(uint8_t rapid)
{
    if (!s_rapid_ranges_configured) {
        return "";
    }
    else {
        if (rapid < s_rapid_ranges_groupA) {
            return "[GroupA]";
        }
        else if (rapid < s_rapid_ranges_RA) {
            return "[GroupB]";
        }
        else {
            return "[Non-RA]";
        }
    }
}

/**************************************************************************/
/* Tracking of extended BSR sizes configuration                           */

static void
get_mac_lte_ue_ext_bsr_sizes(mac_lte_info *p_mac_lte_info)
{
    gpointer p_orig_key, p_ue_params;

    /* Use the _extended function to check the key presence and avoid overriding a
       value already set by the framing protocol while no RRC value is configured */
    if (g_hash_table_lookup_extended(mac_lte_ue_parameters,
                                     GUINT_TO_POINTER((unsigned)p_mac_lte_info->ueid),
                                     &p_orig_key, &p_ue_params)) {
        p_mac_lte_info->isExtendedBSRSizes = ((ue_parameters_t *)p_ue_params)->use_ext_bsr_sizes;
    }
}

/**************************************************************************/
/* Tracking of simultaneous PUCCH/PUSCH configuration                     */

static void
get_mac_lte_ue_simult_pucch_pusch(mac_lte_info *p_mac_lte_info)
{
    gpointer p_orig_key, p_ue_params;

    /* Use the _extended function to check the key presence and avoid overriding a
       value already set by the framing protocol while no RRC value is configured */
    if (g_hash_table_lookup_extended(mac_lte_ue_parameters,
                                     GUINT_TO_POINTER((unsigned)p_mac_lte_info->ueid),
                                     &p_orig_key, &p_ue_params)) {
        p_mac_lte_info->isSimultPUCCHPUSCHPCell = ((ue_parameters_t *)p_ue_params)->use_simult_pucch_pusch_pcell;
        p_mac_lte_info->isSimultPUCCHPUSCHPSCell = ((ue_parameters_t *)p_ue_params)->use_simult_pucch_pusch_pscell;
    }
}

/* Forward declarations */
static int dissect_mac_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void*);

static uint8_t get_mac_lte_channel_priority(uint16_t ueid _U_, uint8_t lcid,
                                           uint8_t direction);


static void
call_with_catch_all(dissector_handle_t handle, tvbuff_t* tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Call it (catch exceptions so that stats will be updated) */
    if (handle) {
        TRY {
            call_dissector_only(handle, tvb, pinfo, tree, NULL);
        }
        CATCH_ALL {
        }
        ENDTRY
    }
}

/* Dissect context fields in the format described in packet-mac-lte.h.
   Return true if the necessary information was successfully found */
bool dissect_mac_lte_context_fields(struct mac_lte_info  *p_mac_lte_info, tvbuff_t *tvb,
                                        packet_info *pinfo, proto_tree *tree, int *p_offset)
{
    int     offset = *p_offset;
    uint8_t tag = 0;

    /* Read fixed fields */
    p_mac_lte_info->radioType = tvb_get_uint8(tvb, offset++);
    p_mac_lte_info->direction = tvb_get_uint8(tvb, offset++);

    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        p_mac_lte_info->detailed_phy_info.ul_info.present = false;
    }
    else {
        p_mac_lte_info->detailed_phy_info.dl_info.present = false;
    }

    p_mac_lte_info->rntiType = tvb_get_uint8(tvb, offset++);

    p_mac_lte_info->sfnSfInfoPresent = false; /* Set this to true later if the relative tag is read */

    /* Initialize RNTI with a default value in case optional field is not present */
    switch (p_mac_lte_info->rntiType) {
        case SC_RNTI:
            p_mac_lte_info->rnti = 0xFFFB;
            break;
        case M_RNTI:
            p_mac_lte_info->rnti = 0xFFFD;
            break;
        case P_RNTI:
            p_mac_lte_info->rnti = 0xFFFE;
            break;
        case SI_RNTI:
            p_mac_lte_info->rnti = 0xFFFF;
            break;
        case RA_RNTI:
        case C_RNTI:
        case SPS_RNTI:
        case SL_RNTI:
        case G_RNTI:
            p_mac_lte_info->rnti = 0x0001;
            break;
        default:
            break;
    }

    /* Read optional fields */
    while (tag != MAC_LTE_PAYLOAD_TAG) {
        /* Process next tag */
        tag = tvb_get_uint8(tvb, offset++);
        switch (tag) {
            case MAC_LTE_RNTI_TAG:
                p_mac_lte_info->rnti = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case MAC_LTE_UEID_TAG:
                p_mac_lte_info->ueid = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case MAC_LTE_FRAME_SUBFRAME_TAG:
                {
                    p_mac_lte_info->sfnSfInfoPresent = true;
                    uint16_t sfn_sf = tvb_get_ntohs(tvb, offset);
                    p_mac_lte_info->sysframeNumber = (sfn_sf >> 4) & 0x03ff;
                    p_mac_lte_info->subframeNumber = sfn_sf & 0x000f;
                    offset += 2;
                }
                break;
            case MAC_LTE_PREDEFINED_DATA_TAG:
                p_mac_lte_info->isPredefinedData = tvb_get_uint8(tvb, offset);
                offset++;
                break;
            case MAC_LTE_RETX_TAG:
                p_mac_lte_info->reTxCount = tvb_get_uint8(tvb, offset);
                offset++;
                break;
            case MAC_LTE_CRC_STATUS_TAG:
                p_mac_lte_info->crcStatusValid = true;
                p_mac_lte_info->crcStatus =
                    (mac_lte_crc_status)tvb_get_uint8(tvb, offset);
                offset++;
                break;
            case MAC_LTE_EXT_BSR_SIZES_TAG:
                p_mac_lte_info->isExtendedBSRSizes = true;
                break;
            case MAC_LTE_SEND_PREAMBLE_TAG:
                p_mac_lte_info->oob_event = ltemac_send_preamble;
                p_mac_lte_info->rapid = tvb_get_uint8(tvb, offset);
                offset++;
                p_mac_lte_info->rach_attempt_number = tvb_get_uint8(tvb, offset);
                offset++;
                break;
            case MAC_LTE_CARRIER_ID_TAG:
                p_mac_lte_info->carrierId =
                    (mac_lte_carrier_id)tvb_get_uint8(tvb, offset);
                offset++;
                break;
            case MAC_LTE_PHY_TAG:
                {
                    int len, offset1;

                    len = tvb_get_uint8(tvb, offset++);
                    offset1 = offset;
                    if (p_mac_lte_info->direction == DIRECTION_DOWNLINK) {
                        if (len < 10)
                            goto next;
                        p_mac_lte_info->detailed_phy_info.dl_info.present = true;
                        p_mac_lte_info->detailed_phy_info.dl_info.dci_format =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->detailed_phy_info.dl_info.resource_allocation_type =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->detailed_phy_info.dl_info.aggregation_level =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->detailed_phy_info.dl_info.mcs_index =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->detailed_phy_info.dl_info.redundancy_version_index =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->detailed_phy_info.dl_info.resource_block_length =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->detailed_phy_info.dl_info.harq_id =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->detailed_phy_info.dl_info.ndi =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->detailed_phy_info.dl_info.transport_block =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->dl_retx =
                            (mac_lte_dl_retx)tvb_get_uint8(tvb, offset);
                    } else {
                        if (len < 6)
                            goto next;
                        p_mac_lte_info->detailed_phy_info.ul_info.present = true;
                        p_mac_lte_info->detailed_phy_info.ul_info.modulation_type =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->detailed_phy_info.ul_info.tbs_index =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->detailed_phy_info.ul_info.resource_block_length =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->detailed_phy_info.ul_info.resource_block_start =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->detailed_phy_info.ul_info.harq_id =
                            tvb_get_uint8(tvb, offset);
                        offset++;
                        p_mac_lte_info->detailed_phy_info.ul_info.ndi =
                            tvb_get_uint8(tvb, offset);
                    }
                next:
                    offset = offset1 + len;
                }
                break;
            case MAC_LTE_SIMULT_PUCCH_PUSCH_PCELL_TAG:
                p_mac_lte_info->isSimultPUCCHPUSCHPCell = true;
                break;
            case MAC_LTE_SIMULT_PUCCH_PUSCH_PSCELL_TAG:
                p_mac_lte_info->isSimultPUCCHPUSCHPSCell = true;
                break;
            case MAC_LTE_CE_MODE_TAG:
                p_mac_lte_info->ceMode =
                    (mac_lte_ce_mode)tvb_get_uint8(tvb, offset);
                offset++;
                break;
            case MAC_LTE_NB_MODE_TAG:
                p_mac_lte_info->nbMode =
                    (mac_lte_nb_mode)tvb_get_uint8(tvb, offset);
                offset++;
                break;
            case MAC_LTE_N_UL_RB_TAG:
                {
                    uint8_t nUlRb = tvb_get_uint8(tvb, offset);
                    offset++;
                    switch (nUlRb) {
                        case 6:
                        case 15:
                        case 25:
                        case 50:
                        case 75:
                        case 100:
                            p_mac_lte_info->nUlRb = nUlRb;
                            break;
                        default:
                            break;
                    }
                }
                break;
                case MAC_LTE_SR_TAG:
                    {
                        int n;
                        // Read number of entries.
                        uint16_t no_entries = tvb_get_ntohs(tvb, offset);
                        offset += 2;
                        if ((no_entries == 0) || (no_entries > MAX_SRs)) {
                            return false;
                        }
                        else {
                            p_mac_lte_info->oob_event = ltemac_send_sr;
                            p_mac_lte_info->number_of_srs = no_entries;
                        }

                        // Read each entry.
                        for (n=0; n < no_entries; n++) {
                            p_mac_lte_info->oob_ueid[n] = tvb_get_ntohs(tvb, offset);
                            offset += 2;
                            p_mac_lte_info->oob_rnti[n] = tvb_get_ntohs(tvb, offset);
                            offset += 2;
                        }
                    }
                    break;

            case MAC_LTE_PAYLOAD_TAG:
                /* Have reached data, so set payload length and get out of loop */
                /* TODO: this is not correct if there is padding which isn't in frame */
                p_mac_lte_info->length= tvb_reported_length_remaining(tvb, offset);
                continue;

            default:
                /* It must be a recognised tag */
                {
                    proto_item *ti;
                    proto_tree *subtree;

                    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC-LTE");
                    col_clear(pinfo->cinfo, COL_INFO);
                    ti = proto_tree_add_item(tree, proto_mac_lte, tvb, offset, tvb_reported_length(tvb), ENC_NA);
                    subtree = proto_item_add_subtree(ti, ett_mac_lte);
                    proto_tree_add_expert(subtree, pinfo, &ei_mac_lte_unknown_udp_framing_tag,
                                          tvb, offset-1, 1);
                }
                wmem_free(wmem_file_scope(), p_mac_lte_info);
                return false;
        }
    }

    /* Pass out where offset is now */
    *p_offset = offset;

    return true;
}

/* Heuristic dissector looks for supported framing protocol (see wiki page)  */
static bool dissect_mac_lte_heur(tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree, void *data _U_)
{
    int                  offset = 0;
    struct mac_lte_info  *p_mac_lte_info;
    tvbuff_t             *mac_tvb;

    /* Needs to be at least as long as:
       - the signature string
       - fixed header bytes
       - tag for data
       - at least one byte of MAC PDU payload */
    if (tvb_captured_length_remaining(tvb, offset) < (int)(strlen(MAC_LTE_START_STRING)+3+2)) {
        return false;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, MAC_LTE_START_STRING, strlen(MAC_LTE_START_STRING)) != 0) {
        return false;
    }
    offset += (int)strlen(MAC_LTE_START_STRING);

    /* If redissecting, use previous info struct (if available) */
    p_mac_lte_info = (mac_lte_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_mac_lte, 0);
    if (p_mac_lte_info == NULL) {
        /* Allocate new info struct for this frame */
        p_mac_lte_info = wmem_new0(wmem_file_scope(), struct mac_lte_info);
        /* Dissect the fields to populate p_mac_lte */
        if (!dissect_mac_lte_context_fields(p_mac_lte_info, tvb, pinfo, tree, &offset)) {
            return true;
        }
        /* Store info in packet */
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mac_lte, 0, p_mac_lte_info);
    }
    else {
        offset = tvb_reported_length(tvb) - p_mac_lte_info->length;
    }

    /**************************************/
    /* OK, now dissect as MAC LTE         */

    /* Create tvb that starts at actual MAC PDU */
    mac_tvb = tvb_new_subset_remaining(tvb, offset);
    dissect_mac_lte(mac_tvb, pinfo, tree, NULL);

    return true;
}


/* Write the given formatted text to:
   - the info column (if pinfo != NULL)
   - 1 or 2 other labels (optional)
*/
static void write_pdu_label_and_info(proto_item *ti1, proto_item *ti2,
                                     packet_info *pinfo, const char *format, ...) G_GNUC_PRINTF(4, 5);
static void write_pdu_label_and_info(proto_item *ti1, proto_item *ti2,
                                     packet_info *pinfo, const char *format, ...)
{
    #define MAX_INFO_BUFFER 256
    static char info_buffer[MAX_INFO_BUFFER];
    va_list ap;

    if ((ti1 == NULL) && (ti2 == NULL) && (pinfo == NULL)) {
        return;
    }

    va_start(ap, format);
    vsnprintf(info_buffer, MAX_INFO_BUFFER, format, ap);
    va_end(ap);

    /* Add to indicated places */
    if (pinfo != NULL) {
        col_append_str(pinfo->cinfo, COL_INFO, info_buffer);
    }
    if (ti1 != NULL) {
        proto_item_append_text(ti1, "%s", info_buffer);
    }
    if (ti2 != NULL) {
        proto_item_append_text(ti2, "%s", info_buffer);
    }
}

/* Version of function above, where no vsnprintf() call needed */
static void write_pdu_label_and_info_literal(proto_item *ti1, proto_item *ti2,
                                             packet_info *pinfo, const char *info_buffer)
{
    if ((ti1 == NULL) && (ti2 == NULL) && (pinfo == NULL)) {
        return;
    }

    /* Add to indicated places */
    if (pinfo != NULL) {
        col_append_str(pinfo->cinfo, COL_INFO, info_buffer);
    }
    if (ti1 != NULL) {
        proto_item_append_text(ti1, "%s", info_buffer);
    }
    if (ti2 != NULL) {
        proto_item_append_text(ti2, "%s", info_buffer);
    }
}



/* Show extra PHY parameters (if present) */
static void show_extra_phy_parameters(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
                                      struct mac_lte_info *p_mac_lte_info)
{
    proto_item *phy_ti;
    proto_tree *phy_tree;
    proto_item *ti;

    if (global_mac_lte_layer_to_show == ShowPHYLayer) {
        /* Clear the info column */
        col_clear(pinfo->cinfo, COL_INFO);
    }

    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        if (p_mac_lte_info->detailed_phy_info.ul_info.present) {

            /* Create root */
            phy_ti = proto_tree_add_string_format(tree, hf_mac_lte_context_phy_ul,
                                                  tvb, 0, 0, "", "UL PHY Context");
            phy_tree = proto_item_add_subtree(phy_ti, ett_mac_lte_phy_context);
            proto_item_set_generated(phy_ti);

            /* Add items */
            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_modulation_type,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.modulation_type);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_tbs_index,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.tbs_index);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_resource_block_length,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.resource_block_length);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_resource_block_start,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.resource_block_start);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_harq_id,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.harq_id);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_ndi,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.ndi);
            proto_item_set_generated(ti);


            proto_item_append_text(phy_ti, " (");

            write_pdu_label_and_info(phy_ti, NULL,
                                     (global_mac_lte_layer_to_show == ShowPHYLayer) ? pinfo : NULL,
                                     "UL: UEId=%u RNTI=%u %s Tbs_Index=%u RB_len=%u RB_start=%u",
                                     p_mac_lte_info->ueid,
                                     p_mac_lte_info->rnti,
                                     val_to_str_const(p_mac_lte_info->detailed_phy_info.ul_info.modulation_type,
                                                      modulation_type_vals, "Unknown"),
                                     p_mac_lte_info->detailed_phy_info.ul_info.tbs_index,
                                     p_mac_lte_info->detailed_phy_info.ul_info.resource_block_length,
                                     p_mac_lte_info->detailed_phy_info.ul_info.resource_block_start);

            proto_item_append_text(phy_ti, ")");

            /* Don't want columns to be replaced now */
            if (global_mac_lte_layer_to_show == ShowPHYLayer) {
                col_set_writable(pinfo->cinfo, -1, false);
            }
        }
    }
    else {
        if (p_mac_lte_info->detailed_phy_info.dl_info.present) {

            /* Create root */
            phy_ti = proto_tree_add_string_format(tree, hf_mac_lte_context_phy_dl,
                                                  tvb, 0, 0, "", "DL PHY Context");
            phy_tree = proto_item_add_subtree(phy_ti, ett_mac_lte_phy_context);
            proto_item_set_generated(phy_ti);

            /* Add items */
            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_dci_format,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.dci_format);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_resource_allocation_type,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.resource_allocation_type);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_aggregation_level,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.aggregation_level);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_mcs_index,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.mcs_index);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_redundancy_version_index,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.redundancy_version_index);
            proto_item_set_generated(ti);

            ti = proto_tree_add_boolean(phy_tree, hf_mac_lte_context_phy_dl_retx,
                                        tvb, 0, 0,
                                        p_mac_lte_info->dl_retx);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_resource_block_length,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.resource_block_length);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_harq_id,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.harq_id);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_ndi,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.ndi);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_tb,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.transport_block);
            proto_item_set_generated(ti);


            proto_item_append_text(phy_ti, " (");

            write_pdu_label_and_info(phy_ti, NULL,
                                     (global_mac_lte_layer_to_show == ShowPHYLayer) ? pinfo : NULL,
                                     "DL: UEId=%u RNTI=%u DCI_Format=%s Res_Alloc=%u Aggr_Level=%s MCS=%u RV=%u "
                                     "Res_Block_len=%u HARQ_id=%u NDI=%u",
                                     p_mac_lte_info->ueid,
                                     p_mac_lte_info->rnti,
                                     val_to_str_const(p_mac_lte_info->detailed_phy_info.dl_info.dci_format,
                                                      dci_format_vals, "Unknown"),
                                     p_mac_lte_info->detailed_phy_info.dl_info.resource_allocation_type,
                                     val_to_str_const(p_mac_lte_info->detailed_phy_info.dl_info.aggregation_level,
                                                      aggregation_level_vals, "Unknown"),
                                     p_mac_lte_info->detailed_phy_info.dl_info.mcs_index,
                                     p_mac_lte_info->detailed_phy_info.dl_info.redundancy_version_index,
                                     p_mac_lte_info->detailed_phy_info.dl_info.resource_block_length,
                                     p_mac_lte_info->detailed_phy_info.dl_info.harq_id,
                                     p_mac_lte_info->detailed_phy_info.dl_info.ndi);
            proto_item_append_text(phy_ti, ")");

            /* Don't want columns to be replaced now */
            if (global_mac_lte_layer_to_show == ShowPHYLayer) {
                col_set_writable(pinfo->cinfo, -1, false);
            }
        }
    }
}


/* Dissect a single Random Access Response body */
static int dissect_rar_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              proto_item *pdu_ti,
                              int offset, uint8_t rapid, mac_lte_info *p_mac_lte_info)
{
    uint32_t      reserved;
    unsigned     start_body_offset = offset;
    proto_item  *ti;
    proto_item  *rar_body_ti;
    proto_tree  *rar_body_tree;
    proto_tree  *ul_grant_tree;
    proto_item  *ul_grant_ti;
    uint32_t     timing_advance;
    uint32_t     ul_grant;
    uint32_t     temp_crnti;
    const char *rapid_description;
    uint32_t     bits_offset;

    /* Create tree for this Body */
    rar_body_ti = proto_tree_add_item(tree,
                                      hf_mac_lte_rar_body,
                                      tvb, offset, 0, ENC_ASCII);
    rar_body_tree = proto_item_add_subtree(rar_body_ti, ett_mac_lte_rar_body);

    /* Dissect an RAR entry */

    /* Check reserved bit */
    ti = proto_tree_add_item_ret_uint(rar_body_tree, hf_mac_lte_rar_reserved2, tvb, offset, 1,
                                      ENC_BIG_ENDIAN, &reserved);
    if (reserved != 0) {
            expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero, "RAR body Reserved bit not zero (found 0x02%x)", reserved);
    }

    /* Timing Advance */
    ti = proto_tree_add_item_ret_uint(rar_body_tree, hf_mac_lte_rar_ta, tvb, offset, 2, ENC_BIG_ENDIAN, &timing_advance);
    if (timing_advance != 0) {
        if (timing_advance <= 31) {
            expert_add_info_format(pinfo, ti, &ei_mac_lte_rar_timing_advance_not_zero_note,
                               "RAR Timing advance not zero (%u)", timing_advance);
        } else {
            expert_add_info_format(pinfo, ti, &ei_mac_lte_rar_timing_advance_not_zero_warn,
                               "RAR Timing advance not zero (%u)", timing_advance);
        }
    }
    offset++;

    /* UL Grant */
    if (p_mac_lte_info->ceMode == ce_mode_b) {
        ul_grant = tvb_get_ntohs(tvb, offset) & 0x0fff;
        ul_grant_ti = proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_ul_grant_ce_mode_b, tvb, offset, 2, ENC_BIG_ENDIAN);
    } else {
        ul_grant = (tvb_get_ntohl(tvb, offset) & 0x0fffff00) >> 8;
        ul_grant_ti = proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_ul_grant, tvb, offset, 3, ENC_BIG_ENDIAN);
    }

    /* Break these 12/20 bits down as described in 36.213, section 6.2 */
    /* Create subtree for UL grant break-down */
    ul_grant_tree = proto_item_add_subtree(ul_grant_ti, ett_mac_lte_rar_ul_grant);

    if (p_mac_lte_info->nbMode == no_nb_mode) {
        switch (p_mac_lte_info->ceMode) {
            case no_ce_mode:
            default:
                /* Hopping flag (1 bit) */
                proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_hopping,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);

                /* Fixed sized resource block assignment (10 bits) */
                proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_fsrba,
                                    tvb, offset, 2, ENC_BIG_ENDIAN);

                /* Truncated Modulation and coding scheme (4 bits) */
                proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_tmcs,
                                    tvb, offset+1, 2, ENC_BIG_ENDIAN);

                /* TPC command for scheduled PUSCH (3 bits) */
                proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_tcsp,
                                    tvb, offset+2, 1, ENC_BIG_ENDIAN);

                /* UL delay (1 bit) */
                proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_ul_delay,
                                    tvb, offset+2, 1, ENC_BIG_ENDIAN);

                /* CQI request (1 bit) */
                proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_cqi_request,
                                    tvb, offset+2, 1, ENC_BIG_ENDIAN);

                offset += 3;
                break;

            case ce_mode_a:
                if (p_mac_lte_info->nUlRb == 0) {
                    /* UL bandwidth is unknown; do not dissect UL grant */
                    offset += 3;
                    break;
                }

                bits_offset = (offset<<3) + 4;

                /* Msg3 PUSCH narrowband index (0 to 4 bits) */
                if (p_mac_lte_info->nUlRb == 15) {
                    proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_msg3_pusch_nb_idx_ce_mode_a,
                                            tvb, bits_offset, 1, ENC_BIG_ENDIAN);
                    bits_offset += 1;
                } else if (p_mac_lte_info->nUlRb == 25) {
                    proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_msg3_pusch_nb_idx_ce_mode_a,
                                            tvb, bits_offset, 2, ENC_BIG_ENDIAN);
                    bits_offset += 2;
                } else if (p_mac_lte_info->nUlRb == 50) {
                    proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_msg3_pusch_nb_idx_ce_mode_a,
                                            tvb, bits_offset, 3, ENC_BIG_ENDIAN);
                    bits_offset += 3;
                } else if ((p_mac_lte_info->nUlRb == 75) || (p_mac_lte_info->nUlRb == 100)) {
                    proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_msg3_pusch_nb_idx_ce_mode_a,
                                            tvb, bits_offset, 4, ENC_BIG_ENDIAN);
                    bits_offset += 4;
                }

                /* Msg3 PUSCH Resource allocation (4 bits) */
                proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_msg3_pusch_res_alloc_ce_mode_a,
                                        tvb, bits_offset, 4, ENC_BIG_ENDIAN);
                bits_offset += 4;

                /* Number of Repetitions for Msg3 PUSCH (2 bits) */
                proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_nb_rep_msg3_pusch_ce_mode_a,
                                        tvb, bits_offset, 2, ENC_BIG_ENDIAN);
                bits_offset += 2;

                /* MCS (3 bits) */
                proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_mcs_ce_mode_a,
                                        tvb, bits_offset, 3, ENC_BIG_ENDIAN);
                bits_offset += 3;

                /* TPC (3 bits) */
                proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_tpc_ce_mode_a,
                                        tvb, bits_offset, 3, ENC_BIG_ENDIAN);
                bits_offset += 3;

                /* CSI request (1 bit) */
                proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_csi_request_ce_mode_a,
                                        tvb, bits_offset, 1, ENC_BIG_ENDIAN);
                bits_offset += 1;

                /* UL delay (1 bit) */
                proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_ul_delay_ce_mode_a,
                                        tvb, bits_offset, 1, ENC_BIG_ENDIAN);
                bits_offset += 1;

                /* Msg3/4 MPDCCH narrowband index (2 bits) */
                proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_msg3_msg4_mpdcch_nb_idx,
                                        tvb, bits_offset, 2, ENC_BIG_ENDIAN);
                bits_offset += 2;

                /* Optional padding (0 to 4 bits) to complete the 20 bits UL Grant */
                if (p_mac_lte_info->nUlRb == 6) {
                    proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_padding_ce_mode_a,
                                            tvb, bits_offset, 4, ENC_BIG_ENDIAN);
                } else if (p_mac_lte_info->nUlRb == 15) {
                    proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_padding_ce_mode_a,
                                            tvb, bits_offset, 3, ENC_BIG_ENDIAN);
                } else if (p_mac_lte_info->nUlRb == 25) {
                    proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_padding_ce_mode_a,
                                            tvb, bits_offset, 2, ENC_BIG_ENDIAN);
                } else if (p_mac_lte_info->nUlRb == 50) {
                    proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_padding_ce_mode_a,
                                            tvb, bits_offset, 1, ENC_BIG_ENDIAN);
                }

                offset += 3;
                break;

            case ce_mode_b:
                /* Msg3 PUSCH narrowband index (2 bits) */
                proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_msg3_pusch_nb_idx_ce_mode_b,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);

                /* Msg3 PUSCH Resource allocation (3 bits) */
                proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_msg3_pusch_res_alloc_ce_mode_b,
                                    tvb, offset, 2, ENC_BIG_ENDIAN);

                /* Number of Repetitions for Msg3 PUSCH (3 bits) */
                proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_nb_rep_msg3_pusch_ce_mode_b,
                                    tvb, offset+1, 1, ENC_BIG_ENDIAN);

                /* TBS (2 bits) */
                proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_tbs_ce_mode_b,
                                    tvb, offset+1, 1, ENC_BIG_ENDIAN);

                /* Msg3/4 MPDCCH narrowband index (2 bits) */
                proto_tree_add_bits_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_msg3_msg4_mpdcch_nb_idx,
                                        tvb, ((offset+1)<<3)+6, 2, ENC_BIG_ENDIAN);

                offset += 2;
                break;
        }
    } else {
        /* Uplink subcarrier spacing (1 bit) */
        proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_ul_subcarrier_spacing, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Subcarrier indication (6 bits) */
        proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_subcarrier_indication, tvb, offset, 2, ENC_BIG_ENDIAN);

        /* Scheduling delay (2 bits) */
        proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_scheduling_delay, tvb, offset+1, 1, ENC_BIG_ENDIAN);

        /* Msg3 repetition number (3 bits) */
        proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_msg3_repetition_number, tvb, offset+1, 1, ENC_BIG_ENDIAN);

        /* MCS index (3 bits) */
        proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_mcs_index, tvb, offset+2, 1, ENC_BIG_ENDIAN);

        /* Padding (5 bits) */
        proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_padding_nb_mode, tvb, offset+2, 1, ENC_BIG_ENDIAN);

        offset += 3;
    }

    /* Temporary C-RNTI */
    proto_tree_add_item_ret_uint(rar_body_tree, hf_mac_lte_rar_temporary_crnti, tvb, offset, 2,
                                 ENC_BIG_ENDIAN, &temp_crnti);
    offset += 2;

    rapid_description = get_mac_lte_rapid_description(rapid);

    write_pdu_label_and_info(pdu_ti, rar_body_ti, pinfo,
                             "(RAPID=%u%s: TA=%u, UL-Grant=%u, Temp C-RNTI=%u) ",
                             rapid, rapid_description,
                             timing_advance, ul_grant, temp_crnti);

    proto_item_set_len(rar_body_ti, offset-start_body_offset);

    return offset;
}


#define MAX_RAR_PDUS 64
/* Dissect Random Access Response (RAR) PDU */
static void dissect_rar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *pdu_ti,
                        int offset, mac_lte_info *p_mac_lte_info, mac_3gpp_tap_info *tap_info)
{
    unsigned    number_of_rars         = 0; /* No of RAR bodies expected following headers */
    uint8_t    *rapids                 = (uint8_t *)wmem_alloc(pinfo->pool, MAX_RAR_PDUS * sizeof(uint8_t));
    uint32_t    temp_rapid;
    bool        backoff_indicator_seen = false;
    uint32_t    backoff_indicator      = 0;
    uint8_t     extension;
    unsigned    n;
    proto_tree *rar_headers_tree;
    proto_item *ti;
    proto_item *rar_headers_ti;
    proto_item *padding_length_ti;
    int         start_headers_offset   = offset;

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "RAR (RA-RNTI=%u, SFN=%-4u, SF=%u) ",
                             p_mac_lte_info->rnti, p_mac_lte_info->sysframeNumber, p_mac_lte_info->subframeNumber);

    /* Create hidden 'virtual root' so can filter on mac-lte.rar */
    ti = proto_tree_add_item(tree, hf_mac_lte_rar, tvb, offset, -1, ENC_NA);
    proto_item_set_hidden(ti);

    /* Create headers tree */
    rar_headers_ti = proto_tree_add_item(tree,
                                         hf_mac_lte_rar_headers,
                                         tvb, offset, 0, ENC_ASCII);
    rar_headers_tree = proto_item_add_subtree(rar_headers_ti, ett_mac_lte_rar_headers);


    /***************************/
    /* Read the header entries */
    do {
        int start_header_offset = offset;
        proto_tree *rar_header_tree;
        proto_item *rar_header_ti;
        uint8_t type_value;
        uint8_t first_byte = tvb_get_uint8(tvb, offset);

        /* Create tree for this header */
        rar_header_ti = proto_tree_add_item(rar_headers_tree,
                                            hf_mac_lte_rar_header,
                                            tvb, offset, 0, ENC_ASCII);
        rar_header_tree = proto_item_add_subtree(rar_header_ti, ett_mac_lte_rar_header);

        /* Extension */
        extension = (first_byte & 0x80) >> 7;
        proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_extension, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Type */
        type_value = (first_byte & 0x40) >> 6;
        proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_t, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (type_value == 0) {
            /* Backoff Indicator (BI) case */

            uint32_t reserved;
            proto_item *tii;
            proto_item *bi_ti;

            /* 2 Reserved bits */
            tii = proto_tree_add_item_ret_uint(rar_header_tree, hf_mac_lte_rar_reserved, tvb, offset, 1, ENC_BIG_ENDIAN, &reserved);
            if (reserved != 0) {
                expert_add_info_format(pinfo, tii, &ei_mac_lte_reserved_not_zero,
                                       "RAR header Reserved bits not zero (found 0x%x)", reserved);
            }

            /* Backoff Indicator */
            bi_ti = proto_tree_add_item_ret_uint(rar_header_tree, (p_mac_lte_info->nbMode == no_nb_mode) ?
                                                 hf_mac_lte_rar_bi : hf_mac_lte_rar_bi_nb, tvb, offset, 1,
                                                 ENC_BIG_ENDIAN, &backoff_indicator);

            /* As of March 2009 spec, it must be first, and may only appear once */
            if (backoff_indicator_seen) {
                expert_add_info(pinfo, bi_ti, &ei_mac_lte_rar_bi_present);
            }
            backoff_indicator_seen = true;

            write_pdu_label_and_info(pdu_ti, rar_header_ti, pinfo,
                                     "(Backoff Indicator=%sms)",
                                     val_to_str_const(backoff_indicator, (p_mac_lte_info->nbMode == no_nb_mode) ?
                                                      rar_bi_vals : rar_bi_nb_vals, "Illegal-value "));

            /* If present, it must be the first subheader */
            if (number_of_rars > 0) {
                expert_add_info(pinfo, bi_ti, &ei_mac_lte_rar_bi_not_first_subheader);
            }

        }
        else {
            /* RAPID case */
            /* TODO: complain if the same RAPID appears twice in same frame? */
            const char *rapid_description;

            proto_tree_add_item_ret_uint(rar_header_tree, hf_mac_lte_rar_rapid, tvb, offset, 1,
                                         ENC_BIG_ENDIAN, &temp_rapid);
            rapids[number_of_rars] = (uint8_t)temp_rapid;

            rapid_description = get_mac_lte_rapid_description(rapids[number_of_rars]);

            proto_item_append_text(rar_header_ti, "(RAPID=%u%s)",
                                   rapids[number_of_rars],
                                   rapid_description);

            number_of_rars++;
        }

        offset++;

        /* Finalise length of header tree selection */
        proto_item_set_len(rar_header_ti, offset - start_header_offset);

    } while (extension && number_of_rars < MAX_RAR_PDUS);

    /* Append summary to headers root */
    proto_item_append_text(rar_headers_ti, " (%u RARs", number_of_rars);
    ti = proto_tree_add_uint(rar_headers_tree, hf_mac_lte_rar_no_of_rapids, tvb, 0, 0, number_of_rars);
    proto_item_set_generated(ti);
    if (backoff_indicator_seen) {
        proto_item_append_text(rar_headers_ti, ", BI=%sms)",
                               val_to_str_const(backoff_indicator, (p_mac_lte_info->nbMode == no_nb_mode) ?
                                                rar_bi_vals : rar_bi_nb_vals, "Illegal-value "));
    }
    else {
        proto_item_append_text(rar_headers_ti, ")");
    }

    /* Set length for headers root */
    proto_item_set_len(rar_headers_ti, offset-start_headers_offset);


    /***************************/
    /* Read any indicated RARs */
    for (n=0; n < number_of_rars; n++) {
        offset = dissect_rar_entry(tvb, pinfo, tree, pdu_ti, offset, rapids[n], p_mac_lte_info);
    }

    /* Update TAP info */
    tap_info->number_of_rars += number_of_rars;

    /* Padding may follow */
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(tree, hf_mac_lte_padding_data,
                            tvb, offset, -1, ENC_NA);
    }
    padding_length_ti = proto_tree_add_uint(tree, hf_mac_lte_padding_length,
                                            tvb, offset, 0,
                                            p_mac_lte_info->length - offset);
    proto_item_set_generated(padding_length_ti);

    /* Update padding bytes in stats */
    tap_info->padding_bytes += (p_mac_lte_info->length - offset);
}


/* Dissect BCH PDU */
static void dissect_bch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        proto_item *pdu_ti,
                        int offset, mac_lte_info *p_mac_lte_info)
{
    proto_item *ti;

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "BCH PDU (%u bytes, on %s transport)  ",
                             tvb_reported_length_remaining(tvb, offset),
                             val_to_str_const(p_mac_lte_info->rntiType,
                                              bch_transport_channel_vals,
                                              "Unknown"));

    /* Show which transport layer it came in on (inferred from RNTI type) */
    ti = proto_tree_add_uint(tree, hf_mac_lte_context_bch_transport_channel,
                             tvb, offset, 0, p_mac_lte_info->rntiType);
    proto_item_set_generated(ti);

    /****************************************/
    /* Whole frame is BCH data              */

    /* Raw data */
    ti = proto_tree_add_item(tree, hf_mac_lte_bch_pdu,
                             tvb, offset, -1, ENC_NA);

    if (global_mac_lte_attempt_rrc_decode) {
        /* Attempt to decode payload using LTE RRC dissector */
        tvbuff_t *rrc_tvb = tvb_new_subset_remaining(tvb, offset);

        /* Get appropriate dissector handle */
        dissector_handle_t protocol_handle = 0;
        if (p_mac_lte_info->rntiType == SI_RNTI) {
            if (p_mac_lte_info->nbMode == no_nb_mode) {
                if (p_mac_lte_info->ceMode == no_ce_mode) {
                    protocol_handle = lte_rrc_bcch_dl_sch_handle;
                }
                else {
                    protocol_handle = lte_rrc_bcch_dl_sch_br_handle;
                }
            }
            else {
                protocol_handle = lte_rrc_bcch_dl_sch_nb_handle;
            }
        }
        else {
            if (p_mac_lte_info->nbMode == no_nb_mode) {
                protocol_handle = lte_rrc_bcch_bch_handle;
            }
            else {
                protocol_handle = lte_rrc_bcch_bch_nb_handle;
            }
        }

        /* Hide raw view of bytes */
        proto_item_set_hidden(ti);

        call_with_catch_all(protocol_handle, rrc_tvb, pinfo, tree);
    }

    /* Check that this *is* downlink! */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        expert_add_info(pinfo, ti, &ei_mac_lte_bch_pdu);
    }
}


/* Dissect PCH PDU */
static void dissect_pch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        proto_item *pdu_ti, int offset,
                        mac_lte_info *p_mac_lte_info,
                        mac_3gpp_tap_info *tap_info)
{
    proto_item *ti;

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "PCH PDU (%u bytes)  ",
                             tvb_reported_length_remaining(tvb, offset));

    /****************************************/
    /* Whole frame is PCH data              */

    /* Always show as raw data */
    ti = proto_tree_add_item(tree, hf_mac_lte_pch_pdu,
                             tvb, offset, -1, ENC_NA);

    /* Get number of paging IDs for tap */
    tap_info->number_of_paging_ids = (tvb_get_uint8(tvb, offset) & 0x40) ?
                                        ((tvb_get_ntohs(tvb, offset) >> 7) & 0x000f) + 1 : 0;

    if (global_mac_lte_attempt_rrc_decode) {

        /* Attempt to decode payload using LTE RRC dissector */
        tvbuff_t *rrc_tvb = tvb_new_subset_remaining(tvb, offset);

        /* Hide raw view of bytes */
        proto_item_set_hidden(ti);

        /* Call it (catch exceptions so that stats will be updated) */
        if (p_mac_lte_info->nbMode == no_nb_mode) {
            call_with_catch_all(lte_rrc_pcch_handle, rrc_tvb, pinfo, tree);
        }
        else {
            call_with_catch_all(lte_rrc_pcch_nb_handle, rrc_tvb, pinfo, tree);
        }
    }

    /* Check that this *is* downlink! */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        expert_add_info(pinfo, ti, &ei_mac_lte_pch_pdu);
    }
}


/* Does this header entry correspond to a fixed-sized control element? */
static bool is_fixed_sized_control_element(uint8_t lcid, uint8_t direction)
{
    if (direction == DIRECTION_UPLINK) {
        /* Uplink */
        switch (lcid) {
            case TIMING_ADVANCE_REPORT_LCID:
            case DCQR_AND_AS_RAI_LCID:
            case AUL_CONFIRMATION_4_OCTETS:
            case AUL_CONFIRMATION_1_OCTET:
            case RECOMMENDED_BIT_RATE_QUERY_LCID:
            case SPS_CONFIRMATION_LCID:
            case POWER_HEADROOM_REPORT_LCID:
            case CRNTI_LCID:
            case TRUNCATED_BSR_LCID:
            case SHORT_BSR_LCID:
            case LONG_BSR_LCID:
                return true;

            default:
                return false;
        }
    }
    else {
        /* Assume Downlink */
        switch (lcid) {
            case DCQR_COMMAND_LCID:
            case ACTIVATION_DEACTIVATION_PDCP_DUP_LCID:
            case HIBERNATION_1_OCTET_LCID:
            case HIBERNATION_4_OCTETS_LCID:
            case RECOMMENDED_BIT_RATE_LCID:
            case SC_PTM_STOP_INDICATION_LCID:
            case ACTIVATION_DEACTIVATION_4_BYTES_LCID:
            case LONG_DRX_COMMAND_LCID:
            case ACTIVATION_DEACTIVATION_LCID:
            case UE_CONTENTION_RESOLUTION_IDENTITY_LCID:
            case TIMING_ADVANCE_LCID:
            case DRX_COMMAND_LCID:
                return true;

            default:
                return false;
        }
    }
}


/* Is this a BSR report header? */
static bool is_bsr_lcid(uint8_t lcid)
{
    return ((lcid == TRUNCATED_BSR_LCID) ||
            (lcid == SHORT_BSR_LCID) ||
            (lcid == LONG_BSR_LCID));
}


/* Helper function to call RLC dissector for SDUs (where channel params are known) */
static void call_rlc_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                               proto_item *pdu_ti,
                               int offset, uint16_t data_length,
                               uint8_t mode, uint8_t direction, uint16_t ueid,
                               uint16_t channelType, uint16_t channelId,
                               uint8_t sequenceNumberLength,
                               uint8_t priority, bool rlcExtLiField, mac_lte_nb_mode nbMode)
{
    tvbuff_t            *rb_tvb = tvb_new_subset_length(tvb, offset, data_length);
    struct rlc_lte_info *p_rlc_lte_info;

    /* Reuse or create RLC info */
    p_rlc_lte_info = (rlc_lte_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_lte, 0);
    if (p_rlc_lte_info == NULL) {
        p_rlc_lte_info = wmem_new0(wmem_file_scope(), struct rlc_lte_info);
    }

    /* Fill in struct details for channel */
    p_rlc_lte_info->rlcMode = mode;
    p_rlc_lte_info->direction = direction;
    p_rlc_lte_info->priority = priority;
    p_rlc_lte_info->ueid = ueid;
    p_rlc_lte_info->channelType = channelType;
    p_rlc_lte_info->channelId = channelId;
    p_rlc_lte_info->pduLength = data_length;
    p_rlc_lte_info->sequenceNumberLength = sequenceNumberLength;
    p_rlc_lte_info->extendedLiField = rlcExtLiField;
    if (nbMode == nb_mode) {
        p_rlc_lte_info->nbMode = rlc_nb_mode;
    } else {
        p_rlc_lte_info->nbMode = rlc_no_nb_mode;
    }

    /* Store info in packet */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_rlc_lte, 0, p_rlc_lte_info);

    if (global_mac_lte_layer_to_show != ShowRLCLayer) {
        /* Don't want these columns replaced */
        col_set_writable(pinfo->cinfo, -1, false);
    }
    else {
        /* Clear info column before first RLC PDU */
        if (s_number_of_rlc_pdus_shown == 0) {
            col_clear(pinfo->cinfo, COL_INFO);
        }
        else {
            /* Add a separator and protect column contents here */
            write_pdu_label_and_info_literal(pdu_ti, NULL, pinfo, "   ||   ");
            col_set_fence(pinfo->cinfo, COL_INFO);
        }
    }
    s_number_of_rlc_pdus_shown++;

    /* Call it (catch exceptions so that stats will be updated) */
    call_with_catch_all(rlc_lte_handle, rb_tvb, pinfo, tree);

    /* Let columns be written to again */
    col_set_writable(pinfo->cinfo, -1, true);
}


/* For DL frames, look for previous Tx. Add link back if found */
static void TrackReportedDLHARQResend(packet_info *pinfo, tvbuff_t *tvb, int length,
                                      proto_tree *tree, mac_lte_info *p_mac_lte_info)
{
    DLHARQResult *result = NULL;
    DLHARQResult *original_result = NULL;

    /* If don't have detailed DL PHY info, just give up */
    if (!p_mac_lte_info->detailed_phy_info.dl_info.present) {
        return;
    }

    /* TDD may not work... */

    if (!PINFO_FD_VISITED(pinfo)) {
        /* First time, so set result and update DL harq table */
        LastFrameData *lastData = NULL;
        LastFrameData *thisData = NULL;

        DLHarqBuffers *ueData;

        /* Read these for convenience */
        uint8_t harq_id = p_mac_lte_info->detailed_phy_info.dl_info.harq_id;
        uint8_t transport_block = p_mac_lte_info->detailed_phy_info.dl_info.transport_block;

        /* Check harq-id bounds, give up if invalid */
        if ((harq_id >= 15) || (transport_block > 1)) {
            return;
        }

        /* Look up entry for this UE/RNTI */
        ueData = (DLHarqBuffers *)g_hash_table_lookup(mac_lte_dl_harq_hash, GUINT_TO_POINTER((unsigned)p_mac_lte_info->rnti));

        if (ueData != NULL) {
            /* Get previous info for this harq-id */
            lastData = &(ueData->harqid[transport_block][harq_id]);
            if (lastData->inUse) {
                /* Compare time difference, ndi, data to see if this looks like a retx */
                if ((length == lastData->length) &&
                    (p_mac_lte_info->detailed_phy_info.dl_info.ndi == lastData->ndi) &&
                    tvb_memeql(tvb, 0, lastData->data, MIN(lastData->length, MAX_EXPECTED_PDU_LENGTH)) == 0) {

                    /* Work out gap between frames */
                    int seconds_between_packets = (int)
                          (pinfo->abs_ts.secs - lastData->received_time.secs);
                    int nseconds_between_packets =
                          pinfo->abs_ts.nsecs - lastData->received_time.nsecs;

                    /* Round difference to nearest millisecond */
                    int total_gap = (seconds_between_packets*1000) +
                                     ((nseconds_between_packets+500000) / 1000000);

                    /* Expect to be within (say) 8-13 subframes since previous */
                    if ((total_gap >= 8) && (total_gap <= 13)) {

                        /* Resend detected! Store result pointing back. */
                        result = wmem_new0(wmem_file_scope(), DLHARQResult);
                        result->previousSet = true;
                        result->previousFrameNum = lastData->framenum;
                        result->timeSincePreviousFrame = total_gap;
                        g_hash_table_insert(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(pinfo->num), result);

                        /* Now make previous frame point forward to here */
                        original_result = (DLHARQResult *)g_hash_table_lookup(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(lastData->framenum));
                        if (original_result == NULL) {
                            original_result = wmem_new0(wmem_file_scope(), DLHARQResult);
                            g_hash_table_insert(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(lastData->framenum), original_result);
                        }
                        original_result->nextSet = true;
                        original_result->nextFrameNum = pinfo->num;
                        original_result->timeToNextFrame = total_gap;
                    }
                }
            }
        }
        else {
            /* Allocate entry in table for this UE/RNTI */
            ueData = wmem_new0(wmem_file_scope(), DLHarqBuffers);
            g_hash_table_insert(mac_lte_dl_harq_hash, GUINT_TO_POINTER((unsigned)p_mac_lte_info->rnti), ueData);
        }

        /* Store this frame's details in table */
        thisData = &(ueData->harqid[transport_block][harq_id]);
        thisData->inUse = true;
        thisData->length = length;
        tvb_memcpy(tvb, thisData->data, 0, MIN(thisData->length, MAX_EXPECTED_PDU_LENGTH));
        thisData->ndi = p_mac_lte_info->detailed_phy_info.dl_info.ndi;
        thisData->framenum = pinfo->num;
        thisData->received_time = pinfo->abs_ts;
    }
    else {
        /* Not first time, so just set what's already stored in result */
        result = (DLHARQResult *)g_hash_table_lookup(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(pinfo->num));
    }


    /***************************************************/
    /* Show link back to original frame (if available) */
    if (result != NULL) {
        if (result->previousSet) {
            proto_item *gap_ti;
            proto_item *original_ti = proto_tree_add_uint(tree, hf_mac_lte_dl_harq_resend_original_frame,
                                                          tvb, 0, 0, result->previousFrameNum);
            proto_item_set_generated(original_ti);

            gap_ti = proto_tree_add_uint(tree, hf_mac_lte_dl_harq_resend_time_since_previous_frame,
                                         tvb, 0, 0, result->timeSincePreviousFrame);
            proto_item_set_generated(gap_ti);
        }

        if (result->nextSet) {
            proto_item *gap_ti;
            proto_item *next_ti = proto_tree_add_uint(tree, hf_mac_lte_dl_harq_resend_next_frame,
                                                      tvb, 0, 0, result->nextFrameNum);
            proto_item_set_generated(next_ti);

            gap_ti = proto_tree_add_uint(tree, hf_mac_lte_dl_harq_resend_time_until_next_frame,
                                         tvb, 0, 0, result->timeToNextFrame);
            proto_item_set_generated(gap_ti);
        }

    }
}


/* Return true if the given packet is thought to be a retx */
bool is_mac_lte_frame_retx(packet_info *pinfo, uint8_t direction)
{
    struct mac_lte_info *p_mac_lte_info = (struct mac_lte_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_mac_lte, 0);

    if (p_mac_lte_info == NULL) {
        return false;
    }

    if (direction == DIRECTION_UPLINK) {
        /* For UL, retx count is stored in per-packet struct */
        return (p_mac_lte_info->reTxCount > 0);
    }
    else {
        /* Use answer if told directly */
        if (p_mac_lte_info->dl_retx == dl_retx_yes) {
            return true;
        }
        else {
            /* Otherwise look up in table */
            DLHARQResult *result = (DLHARQResult *)g_hash_table_lookup(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(pinfo->num));
            return ((result != NULL) && result->previousSet);
        }
    }
}


/* Track UL frames, so that when a retx is indicated, we can search for
   the original tx.  We will either find it, and provide a link back to it,
   or flag that we couldn't find as an expert error */
static void TrackReportedULHARQResend(packet_info *pinfo, tvbuff_t *tvb, int offset,
                                      proto_tree *tree, mac_lte_info *p_mac_lte_info,
                                      proto_item *retx_ti)
{
    ULHARQResult *result = NULL;

    /* If don't have detailed DL PHY info, just give up */
    if (!p_mac_lte_info->detailed_phy_info.ul_info.present) {
        return;
    }

    /* Give up if harqid is out of range */
    if (p_mac_lte_info->detailed_phy_info.ul_info.harq_id >= 8) {
        return;
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        /* First time, so set result and update UL harq table */
        LastFrameData *lastData = NULL;
        LastFrameData *thisData = NULL;

        /* Look up entry for this UE/RNTI */
        ULHarqBuffers *ueData = (ULHarqBuffers *)g_hash_table_lookup(
            mac_lte_ul_harq_hash, GUINT_TO_POINTER((unsigned)p_mac_lte_info->rnti));
        if (ueData != NULL) {
            if (p_mac_lte_info->reTxCount >= 1) {
                /* Looking for frame previously on this harq-id */
                lastData = &(ueData->harqid[p_mac_lte_info->detailed_phy_info.ul_info.harq_id]);
                if (lastData->inUse) {
                    /* Compare time, sf, data to see if this looks like a retx */
                    if ((tvb_reported_length_remaining(tvb, offset) == lastData->length) &&
                        (p_mac_lte_info->detailed_phy_info.ul_info.ndi == lastData->ndi) &&
                        tvb_memeql(tvb, offset, lastData->data, MIN(lastData->length, MAX_EXPECTED_PDU_LENGTH)) == 0) {

                        /* Work out gap between frames */
                        int seconds_between_packets = (int)
                              (pinfo->abs_ts.secs - lastData->received_time.secs);
                        int nseconds_between_packets =
                              pinfo->abs_ts.nsecs - lastData->received_time.nsecs;

                        /* Round to nearest ms */
                        int total_gap = (seconds_between_packets*1000) +
                                         ((nseconds_between_packets+500000) / 1000000);

                        /* Could be as many as max-tx (which we don't know) * 8ms ago.
                           32 is the most I've seen... */
                        /* TODO: could configure this from RRC... */
                        if (total_gap <= 33) {
                            ULHARQResult *original_result;

                            /* Original detected!!! Store result pointing back */
                            result = wmem_new0(wmem_file_scope(), ULHARQResult);
                            result->previousSet = true;
                            result->previousFrameNum = lastData->framenum;
                            result->timeSincePreviousFrame = total_gap;
                            g_hash_table_insert(mac_lte_ul_harq_result_hash, GUINT_TO_POINTER(pinfo->num), result);

                            /* Now make previous frame point forward to here */
                            original_result = (ULHARQResult *)g_hash_table_lookup(mac_lte_ul_harq_result_hash, GUINT_TO_POINTER(lastData->framenum));
                            if (original_result == NULL) {
                                original_result = wmem_new0(wmem_file_scope(), ULHARQResult);
                                g_hash_table_insert(mac_lte_ul_harq_result_hash, GUINT_TO_POINTER(lastData->framenum), original_result);
                            }
                            original_result->nextSet = true;
                            original_result->nextFrameNum = pinfo->num;
                            original_result->timeToNextFrame = total_gap;
                        }
                    }
                }
            }
        }
        else {
            /* Allocate entry in table for this UE/RNTI */
            ueData = wmem_new0(wmem_file_scope(), ULHarqBuffers);
            g_hash_table_insert(mac_lte_ul_harq_hash, GUINT_TO_POINTER((unsigned)p_mac_lte_info->rnti), ueData);
        }

        /* Store this frame's details in table */
        thisData = &(ueData->harqid[p_mac_lte_info->detailed_phy_info.ul_info.harq_id]);
        thisData->inUse = true;
        thisData->length = tvb_reported_length_remaining(tvb, offset);
        tvb_memcpy(tvb, thisData->data, offset, MIN(thisData->length, MAX_EXPECTED_PDU_LENGTH));
        thisData->ndi = p_mac_lte_info->detailed_phy_info.ul_info.ndi;
        thisData->framenum = pinfo->num;
        thisData->received_time = pinfo->abs_ts;
    }
    else {
        /* Not first time, so just get what's already stored in result */
        result = (ULHARQResult *)g_hash_table_lookup(mac_lte_ul_harq_result_hash, GUINT_TO_POINTER(pinfo->num));
    }

    /* Show any link back to previous Tx */
    if (retx_ti != NULL) {
        if (result != NULL) {
            if (result->previousSet) {
                proto_item *original_ti, *gap_ti;

                original_ti = proto_tree_add_uint(tree, hf_mac_lte_ul_harq_resend_original_frame,
                                                  tvb, 0, 0, result->previousFrameNum);
                proto_item_set_generated(original_ti);

                gap_ti = proto_tree_add_uint(tree, hf_mac_lte_ul_harq_resend_time_since_previous_frame,
                                             tvb, 0, 0, result->timeSincePreviousFrame);
                proto_item_set_generated(gap_ti);
            }
        }
        else {
            expert_add_info_format(pinfo, retx_ti, &ei_mac_lte_orig_tx_ul_frame_not_found,
                                   "Original Tx of UL frame not found (UE %u) !!", p_mac_lte_info->ueid);
        }
    }

    /* Show link forward to any known next Tx */
    if ((result != NULL) && result->nextSet) {
        proto_item *next_ti, *gap_ti;

        next_ti = proto_tree_add_uint(tree, hf_mac_lte_ul_harq_resend_next_frame,
                                          tvb, 0, 0, result->nextFrameNum);
        expert_add_info_format(pinfo, next_ti, &ei_mac_lte_ul_harq_resend_next_frame,
                               "UL MAC PDU (UE %u) needed to be retransmitted", p_mac_lte_info->ueid);

        proto_item_set_generated(next_ti);

        gap_ti = proto_tree_add_uint(tree, hf_mac_lte_ul_harq_resend_time_until_next_frame,
                                     tvb, 0, 0, result->timeToNextFrame);
        proto_item_set_generated(gap_ti);
    }
}


/* Look up SRResult associated with a given frame. Will create one if necessary
   if can_create is set */
static SRResult *GetSRResult(uint32_t frameNum, bool can_create)
{
    SRResult *result;
    result = (SRResult *)g_hash_table_lookup(mac_lte_sr_request_hash, GUINT_TO_POINTER(frameNum));

    if ((result == NULL) && can_create) {
        result = wmem_new0(wmem_file_scope(), SRResult);
        g_hash_table_insert(mac_lte_sr_request_hash, GUINT_TO_POINTER((unsigned)frameNum), result);
    }
    return result;
}


/* Keep track of SR requests, failures and related grants, in order to show them
   as generated fields in these frames */
static void TrackSRInfo(SREvent event, packet_info *pinfo, proto_tree *tree,
                        tvbuff_t *tvb, mac_lte_info *p_mac_lte_info, int idx, proto_item *event_ti)
{
    SRResult   *result           = NULL;
    SRState    *state;
    SRResult   *resultForSRFrame = NULL;

    uint16_t    rnti;
    uint16_t    ueid;
    proto_item *ti;

    /* Get appropriate identifiers */
    if (event == SR_Request) {
        rnti = p_mac_lte_info->oob_rnti[idx];
        ueid = p_mac_lte_info->oob_ueid[idx];
    }
    else {
        rnti = p_mac_lte_info->rnti;
        ueid = p_mac_lte_info->ueid;
    }

    /* Create state for this RNTI if necessary */
    state = (SRState *)g_hash_table_lookup(mac_lte_ue_sr_state, GUINT_TO_POINTER((unsigned)rnti));
    if (state == NULL) {
        /* Allocate status for this RNTI */
        state = wmem_new(wmem_file_scope(), SRState);
        state->status = None;
        g_hash_table_insert(mac_lte_ue_sr_state, GUINT_TO_POINTER((unsigned)rnti), state);
    }

    /* First time through - update state with new info */
    if (!PINFO_FD_VISITED(pinfo)) {
        uint32_t timeSinceRequest;

        /* Store time of request */
        if (event == SR_Request) {
            state->requestTime = pinfo->abs_ts;
        }

        switch (state->status) {
            case None:
                switch (event) {
                    case SR_Grant:
                        /* Got another grant - fine */

                        /* update state */
                        state->lastGrantFramenum = pinfo->num;
                        break;

                    case SR_Request:
                        /* Sent an SR - fine */

                        /* Update state */
                        state->status = SR_Outstanding;
                        state->lastSRFramenum = pinfo->num;
                        break;

                    case SR_Failure:
                        /* This is an error, since we hadn't send an SR... */
                        result = GetSRResult(pinfo->num, true);
                        result->type = InvalidSREvent;
                        result->status = None;
                        result->event = SR_Failure;
                        break;
                }
                break;

            case SR_Outstanding:
                timeSinceRequest = (uint32_t)(((pinfo->abs_ts.secs - state->requestTime.secs) * 1000) +
                                             ((pinfo->abs_ts.nsecs - state->requestTime.nsecs) / 1000000));

                switch (event) {
                    case SR_Grant:
                        /* Got grant we were waiting for, so state goes to None */

                        /* Update state */
                        state->status = None;

                        /* Set result info */
                        result = GetSRResult(pinfo->num, true);
                        result->type = GrantAnsweringSR;
                        result->frameNum = state->lastSRFramenum;
                        result->timeDifference = timeSinceRequest;

                        /* Also set forward link for SR */
                        resultForSRFrame = GetSRResult(state->lastSRFramenum, true);
                        resultForSRFrame->type = SRLeadingToGrant;
                        resultForSRFrame->frameNum = pinfo->num;
                        resultForSRFrame->timeDifference = timeSinceRequest;
                        break;

                    case SR_Request:
                        /* Another request when already have one pending */
                        result = GetSRResult(pinfo->num, true);
                        result->type = InvalidSREvent;
                        result->status = SR_Outstanding;
                        result->event = SR_Request;
                        break;

                    case SR_Failure:
                        /* We sent an SR but it failed */

                        /* Update state */
                        state->status = SR_Failed;

                        /* Set result info for failure frame */
                        result = GetSRResult(pinfo->num, true);
                        result->type = FailureAnsweringSR;
                        result->frameNum = state->lastSRFramenum;
                        result->timeDifference = timeSinceRequest;

                        /* Also set forward link for SR */
                        resultForSRFrame = GetSRResult(state->lastSRFramenum, true);
                        resultForSRFrame->type = SRLeadingToFailure;
                        resultForSRFrame->frameNum = pinfo->num;
                        resultForSRFrame->timeDifference = timeSinceRequest;
                        break;
                }
                break;

            case SR_Failed:
                switch (event) {
                    case SR_Grant:
                        /* Got a grant, presumably after a subsequent RACH - fine */

                        /* Update state */
                        state->status = None;
                        break;

                    case SR_Request:
                        /* Tried another SR after previous one failed.
                           Presumably a subsequent RACH was tried in-between... */

                        state->status = SR_Outstanding;

                        result = GetSRResult(pinfo->num, true);
                        result->status = SR_Outstanding;
                        result->event = SR_Request;
                        break;

                    case SR_Failure:
                        /* 2 failures in a row.... */
                        result = GetSRResult(pinfo->num, true);
                        result->type = InvalidSREvent;
                        result->status = SR_Failed;
                        result->event = SR_Failure;
                        break;
                }
                break;
        }
    }

    /* Get stored result for this frame */
    result = GetSRResult(pinfo->num, false);
    if (result == NULL) {
        /* For an SR frame, there should always be either a PDCCH grant or indication
           that the SR has failed */
        if (event == SR_Request) {
            expert_add_info_format(pinfo, event_ti, &ei_mac_lte_sr_results_not_grant_or_failure_indication,
                                   "UE %u: SR results in neither a grant nor a failure indication",
                                   ueid);
        }
        return;
    }


    /* Show result info */
    switch (result->type) {
        case GrantAnsweringSR:
            ti = proto_tree_add_uint(tree, hf_mac_lte_grant_answering_sr,
                                     tvb, 0, 0, result->frameNum);
            proto_item_set_generated(ti);
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_time_since_request,
                                     tvb, 0, 0, result->timeDifference);
            proto_item_set_generated(ti);
            break;

        case FailureAnsweringSR:
            ti = proto_tree_add_uint(tree, hf_mac_lte_failure_answering_sr,
                                     tvb, 0, 0, result->frameNum);
            proto_item_set_generated(ti);
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_time_since_request,
                                     tvb, 0, 0, result->timeDifference);
            proto_item_set_generated(ti);
            break;

        case SRLeadingToGrant:
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_leading_to_grant,
                                     tvb, 0, 0, result->frameNum);
            proto_item_set_generated(ti);
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_time_until_answer,
                                     tvb, 0, 0, result->timeDifference);
            proto_item_set_generated(ti);

            break;

        case SRLeadingToFailure:
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_leading_to_failure,
                                     tvb, 0, 0, result->frameNum);
            proto_item_set_generated(ti);
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_time_until_answer,
                                     tvb, 0, 0, result->timeDifference);
            proto_item_set_generated(ti);
            break;

        case InvalidSREvent:
            proto_tree_add_expert_format(tree, pinfo, &ei_mac_lte_sr_invalid_event,
                                            tvb, 0, 0, "UE %u: Invalid SR event - state=%s, event=%s",
                                            ueid,
                                            val_to_str_const(result->status, sr_status_vals, "Unknown"),
                                            val_to_str_const(result->event,  sr_event_vals,  "Unknown"));
            break;
    }
}


/********************************************************/
/* Count number of UEs/TTI (in both directions)         */
/********************************************************/

/* For keeping track during first pass */
typedef struct tti_info_t {
    uint16_t subframe;
    nstime_t ttiStartTime;
    unsigned ues_in_tti;
} tti_info_t;

static tti_info_t UL_tti_info;
static tti_info_t DL_tti_info;

/* For associating with frame and displaying */
typedef struct TTIInfoResult_t {
    unsigned ues_in_tti;
} TTIInfoResult_t;

/* This table stores (FrameNumber -> *TTIInfoResult_t).  It is assigned during the first
   pass and used thereafter */
static GHashTable *mac_lte_tti_info_result_hash;


/* Work out which UE this is within TTI (within direction). Return answer */
static uint16_t count_ues_tti(mac_lte_info *p_mac_lte_info, packet_info *pinfo)
{
    bool same_tti = false;
    tti_info_t *tti_info;

    /* Just return any previous result */
    TTIInfoResult_t *result = (TTIInfoResult_t *)g_hash_table_lookup(mac_lte_tti_info_result_hash, GUINT_TO_POINTER(pinfo->num));
    if (result != NULL) {
        return result->ues_in_tti;
    }

    /* Set tti_info based upon direction */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        tti_info = &UL_tti_info;
    }
    else {
        tti_info = &DL_tti_info;
    }

    /* Work out if we are still in the same tti as before */
    if (tti_info->subframe == p_mac_lte_info->subframeNumber) {
        int seconds_between_packets = (int)
              (pinfo->abs_ts.secs - tti_info->ttiStartTime.secs);
        int nseconds_between_packets =
              pinfo->abs_ts.nsecs -  tti_info->ttiStartTime.nsecs;

        /* Round difference to nearest microsecond */
        int total_us_gap = (seconds_between_packets*1000000) +
                           ((nseconds_between_packets+500) / 1000);

        if (total_us_gap < 1000) {
            same_tti = true;
        }
    }

    /* Update global state */
    if (!same_tti) {
        tti_info->subframe = p_mac_lte_info->subframeNumber;
        tti_info->ttiStartTime = pinfo->abs_ts;
        tti_info->ues_in_tti = 1;
    }
    else {
        tti_info->ues_in_tti++;
    }

    /* Set result state for this frame */
    result = wmem_new(wmem_file_scope(), TTIInfoResult_t);
    result->ues_in_tti = tti_info->ues_in_tti;
    g_hash_table_insert(mac_lte_tti_info_result_hash,
                        GUINT_TO_POINTER(pinfo->num), result);

    return tti_info->ues_in_tti;
}


/* Show which UE this is (within direction) for this TTI */
static void show_ues_tti(packet_info *pinfo, mac_lte_info *p_mac_lte_info, tvbuff_t *tvb, proto_tree *context_tree)
{
    /* Look up result */
    TTIInfoResult_t *result = (TTIInfoResult_t *)g_hash_table_lookup(mac_lte_tti_info_result_hash, GUINT_TO_POINTER(pinfo->num));
    if (result != NULL) {
        proto_item *ti =  proto_tree_add_uint(context_tree,
                                              (p_mac_lte_info->direction == DIRECTION_UPLINK) ?
                                                  hf_mac_lte_ues_ul_per_tti :
                                                  hf_mac_lte_ues_dl_per_tti,
                                              tvb, 0, 0, result->ues_in_tti);
        proto_item_set_generated(ti);
    }
}

static void set_rlc_seqnum_length_ext_li_field(rlc_channel_type_t rlc_channel_type,
                                               uint8_t direction,
                                               uint8_t *seqnum_length,
                                               bool *rlc_ext_li_field)
{
    switch (rlc_channel_type) {
        case rlcUM5:
            *seqnum_length = 5;
            break;
        case rlcUM10:
            *seqnum_length = 10;
            break;
        case rlcAMulExtLiField:
            *seqnum_length = 10;
            if (direction == DIRECTION_UPLINK) {
                *rlc_ext_li_field = true;
            }
            break;
        case rlcAMdlExtLiField:
            *seqnum_length = 10;
            if (direction == DIRECTION_DOWNLINK) {
                *rlc_ext_li_field = true;
            }
            break;
        case rlcAMextLiField:
            *seqnum_length = 10;
            *rlc_ext_li_field = true;
            break;
        case rlcAMul16:
            if (direction == DIRECTION_UPLINK) {
                *seqnum_length = 16;
            } else {
                *seqnum_length = 10;
            }
            break;
        case rlcAMdl16:
            if (direction == DIRECTION_UPLINK) {
                *seqnum_length = 10;
            } else {
                *seqnum_length = 16;
            }
            break;
        case rlcAM16:
            *seqnum_length = 16;
            break;
        case rlcAMul16ulExtLiField:
            if (direction == DIRECTION_UPLINK) {
                *seqnum_length = 16;
                *rlc_ext_li_field = true;
            } else {
                *seqnum_length = 10;
            }
            break;
        case rlcAMdl16ulExtLiField:
            if (direction == DIRECTION_UPLINK) {
                *seqnum_length = 10;
                *rlc_ext_li_field = true;
            } else {
                *seqnum_length = 16;
            }
            break;
        case rlcAM16ulExtLiField:
            *seqnum_length = 16;
            if (direction == DIRECTION_UPLINK) {
                *rlc_ext_li_field = true;
            }
            break;
        case rlcAMul16dlExtLiField:
            if (direction == DIRECTION_UPLINK) {
                *seqnum_length = 16;
            } else {
                *seqnum_length = 10;
                *rlc_ext_li_field = true;
            }
            break;
        case rlcAMdl16dlExtLiField:
            if (direction == DIRECTION_UPLINK) {
                *seqnum_length = 10;
            } else {
                *seqnum_length = 16;
                *rlc_ext_li_field = true;
            }
            break;
        case rlcAM16dlExtLiField:
            *seqnum_length = 16;
            if (direction == DIRECTION_DOWNLINK) {
                *rlc_ext_li_field = true;
            }
            break;
        case rlcAMul16extLiField:
            if (direction == DIRECTION_UPLINK) {
                *seqnum_length = 16;
            } else {
                *seqnum_length = 10;
            }
            *rlc_ext_li_field = true;
            break;
        case rlcAMdl16extLiField:
            if (direction == DIRECTION_UPLINK) {
                *seqnum_length = 10;
            } else {
                *seqnum_length = 16;
            }
            *rlc_ext_li_field = true;
            break;
        case rlcAM16extLiField:
            *seqnum_length = 16;
            *rlc_ext_li_field = true;
            break;
        default:
            break;
    }
}

/* Lookup channel details for lcid */
static void lookup_rlc_channel_from_lcid(uint16_t ueid,
                                         uint8_t lcid,
                                         uint8_t direction,
                                         rlc_channel_type_t *rlc_channel_type,
                                         uint8_t *seqnum_length,
                                         int *drb_id,
                                         bool *rlc_ext_li_field)
{
    /* Zero params (in case no match is found) */
    *rlc_channel_type = rlcRaw;
    *seqnum_length    = 0;
    *drb_id           = 0;
    *rlc_ext_li_field = false;

    if (global_mac_lte_lcid_drb_source == (int)FromStaticTable) {

        /* Look up in static (UAT) table */
        unsigned m;
        for (m=0; m < num_lcid_drb_mappings; m++) {
            if (lcid == lcid_drb_mappings[m].lcid) {

                *rlc_channel_type = lcid_drb_mappings[m].channel_type;

                /* Set seqnum_length and rlc_ext_li_field */
                set_rlc_seqnum_length_ext_li_field(*rlc_channel_type, direction,
                                                   seqnum_length, rlc_ext_li_field);

                /* Set drb_id */
                *drb_id = lcid_drb_mappings[m].drbid;
                break;
            }
        }
    }
    else {
        /* Look up the dynamic mappings for this UE */
        ue_dynamic_drb_mappings_t *ue_mappings = (ue_dynamic_drb_mappings_t *)g_hash_table_lookup(mac_lte_ue_channels_hash, GUINT_TO_POINTER((unsigned)ueid));
        if (!ue_mappings) {
            return;
        }

        /* Look up setting gleaned from configuration protocol */
        if (!ue_mappings->mapping[lcid].valid) {
            return;
        }

        *rlc_channel_type = ue_mappings->mapping[lcid].channel_type;

        /* Set seqnum_length and rlc_ext_li_field */
        set_rlc_seqnum_length_ext_li_field(*rlc_channel_type, direction,
                                           seqnum_length, rlc_ext_li_field);

        /* Set drb_id */
        *drb_id = ue_mappings->mapping[lcid].drbid;
    }
}


/* Work out whether there are 1 or 4 bytes of C bits in Dual-Conn PHR CE */
static unsigned get_dual_conn_phr_num_c_bytes(tvbuff_t *tvb, unsigned offset,
                                           bool isSimultPUCCHPUSCHPCell,
                                           bool isSimultPUCCHPUSCHPSCell,
                                           unsigned subheader_length)
{
    if (subheader_length < 4) {
        /* Can't be 4 */
        return 1;
    }

    uint8_t scell_bitmap_byte = tvb_get_uint8(tvb, offset);
    unsigned i, byte_offset;

    /* Count bits set. */
    unsigned byte_bits_set = 0;
    for (i=1; i <= 7; ++i) {
        byte_bits_set += ((scell_bitmap_byte & (0x1 << i)) ? 1 : 0);
    }

    /* Only work out length for 1-byte case (skip C byte itself). */
    byte_offset = offset+1;

    /* These 2 fields depend upon seeing correct RRC signalling.. */
    if (isSimultPUCCHPUSCHPCell) {
        if ((tvb_get_uint8(tvb, byte_offset) & 0x40) == 0) {
            byte_offset++;
        }
        byte_offset++;
    }
    if (isSimultPUCCHPUSCHPSCell) {
        if ((tvb_get_uint8(tvb, byte_offset) & 0x40) == 0) {
            byte_offset++;
        }
        byte_offset++;
    }

    /* Now walk number of entries set */
    for (i=0; i <= byte_bits_set; i++) {
        /* But take care to not walk past the end. */
        if ((byte_offset-offset) >= subheader_length) {
            /* Went off the end - assume 4... */
            return 4;
        }
        if ((tvb_get_uint8(tvb, byte_offset) & 0x40) == 0) {
            byte_offset++;
        }
        byte_offset++;
    }

    /* Give verdict */
    if ((byte_offset-offset) == subheader_length) {
        return 1;
    }
    else {
        return 4;
    }
}


#define MAX_HEADERS_IN_PDU 1024

/* UL-SCH and DL-SCH formats have much in common, so handle them in a common
   function */
static void dissect_ulsch_or_dlsch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                   proto_item *pdu_ti, uint32_t offset,
                                   mac_lte_info *p_mac_lte_info, mac_3gpp_tap_info *tap_info,
                                   proto_item *retx_ti, proto_tree *context_tree,
                                   unsigned pdu_instance)
{
    uint8_t           extension;
    uint16_t          n;
    proto_item       *truncated_ti;
    proto_item       *padding_length_ti;

    /* Keep track of LCIDs and lengths as we dissect the header */
    uint16_t         number_of_headers = 0;
    uint8_t          lcids[MAX_HEADERS_IN_PDU];
    uint8_t          elcids[MAX_HEADERS_IN_PDU];
    int32_t          pdu_lengths[MAX_HEADERS_IN_PDU];

    proto_item *pdu_header_ti;
    proto_tree *pdu_header_tree;

    bool       have_seen_data_header = false;
    uint8_t    number_of_padding_subheaders = 0;
    bool       have_seen_non_padding_control = false;
    bool       have_seen_sc_mcch_sc_mtch_header = false;
    bool       have_seen_bsr = false;
    bool       expecting_body_data = false;
    uint32_t   is_truncated = false;

    /* Maintain/show UEs/TTI count */
    tap_info->ueInTTI = count_ues_tti(p_mac_lte_info, pinfo);
    show_ues_tti(pinfo, p_mac_lte_info, tvb, context_tree);

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "%s: (SFN=%-4u, SF=%u) UEId=%-3u ",
                             (p_mac_lte_info->direction == DIRECTION_UPLINK) ? "UL-SCH" : "DL-SCH",
                             p_mac_lte_info->sysframeNumber,
                             p_mac_lte_info->subframeNumber,
                             p_mac_lte_info->ueid);

    tap_info->raw_length = p_mac_lte_info->length;

    /******************************************************/
    /* DRX information                                    */

    /* Update DRX state of UE */
    if (global_mac_lte_show_drx) {
        if (!PINFO_FD_VISITED(pinfo)) {

            /* Update UE state to this subframe (but before this event is processed) */
            update_drx_info(pinfo, p_mac_lte_info);

            /* Store 'before' snapshot of UE state for this frame */
            set_drx_info(pinfo, p_mac_lte_info, true, pdu_instance);
        }

        /* Show current DRX state in tree as 'before' */
        show_drx_info(pinfo, tree, tvb, p_mac_lte_info, true, pdu_instance);

        /* Changes of state caused by events */
        if (!PINFO_FD_VISITED(pinfo)) {
            if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
                if (p_mac_lte_info->reTxCount == 0) {
                    mac_lte_drx_new_ulsch_data(p_mac_lte_info->ueid);
                }
            }
            else {
                /* Downlink */
                if ((p_mac_lte_info->crcStatusValid) && (p_mac_lte_info->crcStatus != crc_success)) {
                    mac_lte_drx_dl_crc_error(p_mac_lte_info->ueid);
                }
                else if (p_mac_lte_info->dl_retx == dl_retx_no) {
                    mac_lte_drx_new_dlsch_data(p_mac_lte_info->ueid);
                }
            }
        }
    }


    /* For uplink frames, if this is logged as a resend, look for original tx */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        TrackReportedULHARQResend(pinfo, tvb, offset, tree, p_mac_lte_info, retx_ti);
    }

    /* For uplink grants, update SR status.  N.B. only newTx grant should stop SR */
    if ((p_mac_lte_info->direction == DIRECTION_UPLINK) && (p_mac_lte_info->reTxCount == 0) &&
        global_mac_lte_track_sr) {

        TrackSRInfo(SR_Grant, pinfo, tree, tvb, p_mac_lte_info, 0, NULL);
    }

    /* Add PDU block header subtree */
    pdu_header_ti = proto_tree_add_string_format(tree,
                                                 (p_mac_lte_info->direction == DIRECTION_UPLINK) ?
                                                    hf_mac_lte_ulsch_header :
                                                    hf_mac_lte_dlsch_header,
                                                 tvb, offset, 0,
                                                 "",
                                                 "MAC PDU Header");
    pdu_header_tree = proto_item_add_subtree(pdu_header_ti,
                                             (p_mac_lte_info->direction == DIRECTION_UPLINK) ?
                                                    ett_mac_lte_ulsch_header :
                                                    ett_mac_lte_dlsch_header);


    /************************************************************************/
    /* Dissect each sub-header.                                             */
    do {
        uint8_t reserved, format2, initial_lcid;
        uint64_t length = 0;
        proto_item *pdu_subheader_ti;
        proto_tree *pdu_subheader_tree;
        proto_item *lcid_ti;
        proto_item *ti;
        int        offset_start_subheader = offset;
        uint8_t first_byte = tvb_get_uint8(tvb, offset);
        const char *lcid_str;

        /* Add PDU block header subtree.
           Default with length of 1 byte. */
        pdu_subheader_ti = proto_tree_add_string_format(pdu_header_tree,
                                                        hf_mac_lte_sch_subheader,
                                                        tvb, offset, 1,
                                                        "",
                                                        "Sub-header");
        pdu_subheader_tree = proto_item_add_subtree(pdu_subheader_ti,
                                                    ett_mac_lte_sch_subheader);

        /* Check 1st reserved bit */
        reserved = (first_byte & 0x80) >> 7;
        ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_sch_reserved,
                                 tvb, offset, 1, ENC_BIG_ENDIAN);
        if (reserved != 0) {
            expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                   "%cL-SCH header Reserved bit not zero",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? 'U' : 'D');
        }

        /* Format2 bit */
        format2 = (first_byte & 0x40) >> 6;
        proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_sch_format2,
                            tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Extended bit */
        extension = (first_byte & 0x20) >> 5;
        proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_sch_extended,
                            tvb, offset, 1, ENC_BIG_ENDIAN);

        /* LCID.  Has different meaning depending upon direction. */
        lcids[number_of_headers] = first_byte & 0x1f;
        initial_lcid = lcids[number_of_headers];
        if (p_mac_lte_info->direction == DIRECTION_UPLINK) {

            lcid_ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_ulsch_lcid,
                                          tvb, offset, 1, ENC_BIG_ENDIAN);
            /* Also add LCID as a hidden, direction-less field */
            proto_item *bi_di_lcid = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_lcid, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_set_hidden(bi_di_lcid);

            if (lcids[number_of_headers] != EXT_LOGICAL_CHANNEL_ID_LCID) {
                write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                         "(%s",
                                         val_to_str_const(lcids[number_of_headers],
                                                          ulsch_lcid_vals, "(Unknown LCID)"));
            } else {
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, "(%u", tvb_get_uint8(tvb, offset+1) + 32);
            }
        }
        else {
            /* Downlink */
            lcid_ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_dlsch_lcid,
                                          tvb, offset, 1, ENC_BIG_ENDIAN);
            /* Also add LCID as a hidden, direction-less field */
            proto_item *bi_di_lcid = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_lcid, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_set_hidden(bi_di_lcid);

            if (lcids[number_of_headers] != EXT_LOGICAL_CHANNEL_ID_LCID) {
                write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                         "(%s",
                                         val_to_str_const(lcids[number_of_headers],
                                                          dlsch_lcid_vals, "(Unknown LCID)"));

                if ((lcids[number_of_headers] == DRX_COMMAND_LCID) ||
                    (lcids[number_of_headers] == LONG_DRX_COMMAND_LCID)) {
                    expert_add_info_format(pinfo, lcid_ti, &ei_mac_lte_dlsch_lcid,
                                           "%sDRX command received for UE %u (RNTI %u)",
                                           (lcids[number_of_headers] == LONG_DRX_COMMAND_LCID) ? "Long " :"",
                                           p_mac_lte_info->ueid, p_mac_lte_info->rnti);
                }
            } else {
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, "(%u", tvb_get_uint8(tvb, offset+1) + 32);
            }
        }
        offset++;

        /* Remember if we've seen a data subheader */
        if (is_data_lcid(lcids[number_of_headers], p_mac_lte_info->direction) || lcids[number_of_headers] == EXT_LOGICAL_CHANNEL_ID_LCID) {
            have_seen_data_header = true;
            expecting_body_data = true;
        }
        if ((p_mac_lte_info->direction == DIRECTION_DOWNLINK) && (lcids[number_of_headers] == SC_MCCH_SC_MTCH_LCID)) {
            have_seen_sc_mcch_sc_mtch_header = true;
        }

        /* Show an expert item if a control subheader (except Padding) appears
           *after* a data PDU */
        if (have_seen_data_header && !is_data_lcid(lcids[number_of_headers], p_mac_lte_info->direction) &&
            (lcids[number_of_headers] != EXT_LOGICAL_CHANNEL_ID_LCID) && (lcids[number_of_headers] != PADDING_LCID))
        {
            expert_add_info_format(pinfo, lcid_ti, &ei_mac_lte_control_subheader_after_data_subheader,
                                   "%cL-SCH control subheaders should not appear after data subheaders",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? 'U' : 'D');
            return;
        }

        /* Show an expert item if we're seeing more then one BSR in a frame */
        if ((p_mac_lte_info->direction == DIRECTION_UPLINK) && is_bsr_lcid(lcids[number_of_headers])) {
            if (have_seen_bsr) {
                expert_add_info(pinfo, lcid_ti, &ei_mac_lte_control_bsr_multiple);
                return;
            }
            have_seen_bsr = true;
        }

        /* Should not see padding after non-padding control... */
        if ((lcids[number_of_headers] == PADDING_LCID) && extension)
        {
            number_of_padding_subheaders++;
            if (number_of_padding_subheaders > 2) {
                expert_add_info(pinfo, lcid_ti, &ei_mac_lte_padding_data_multiple);
            }

            if (have_seen_non_padding_control) {
                expert_add_info(pinfo, lcid_ti, &ei_mac_lte_padding_data_before_control_subheader);
            }
        }

        /* Also flag if we have final padding but also padding subheaders
           at the start! */
        if (!extension && (lcids[number_of_headers] == PADDING_LCID) &&
            (number_of_padding_subheaders > 0)) {
                expert_add_info(pinfo, lcid_ti, &ei_mac_lte_padding_data_start_and_end);
        }

        /* Remember that we've seen non-padding control */
        if (!is_data_lcid(lcids[number_of_headers], p_mac_lte_info->direction) &&
            (lcids[number_of_headers] != EXT_LOGICAL_CHANNEL_ID_LCID) &&
            (lcids[number_of_headers] != PADDING_LCID) &&
            (lcids[number_of_headers] != SC_MCCH_SC_MTCH_LCID)) {
            have_seen_non_padding_control = true;
        }

        /* Ensure that SC-MCCH or SC-MTCH header is not multiplexed with other LCID than Padding */
        if (have_seen_sc_mcch_sc_mtch_header && (have_seen_data_header || have_seen_non_padding_control)) {
            expert_add_info(pinfo, lcid_ti, &ei_mac_lte_invalid_sc_mcch_sc_mtch_subheader_multiplexing);
            return;
        }

        if (lcids[number_of_headers] == EXT_LOGICAL_CHANNEL_ID_LCID) {
            uint8_t elcid;

            ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_sch_reserved2,
                                     tvb, offset, 1, ENC_BIG_ENDIAN);
            if (reserved != 0) {
                expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                       "%cL-SCH header Reserved bits not zero",
                                       (p_mac_lte_info->direction == DIRECTION_UPLINK) ? 'U' : 'D');
            }
            elcid = (tvb_get_uint8(tvb, offset) & 0x3f);
            elcids[number_of_headers] = elcid + 32;
            proto_tree_add_uint_format_value(pdu_subheader_tree, hf_mac_lte_sch_elcid, tvb, offset,
                                             1, elcid, "%u (%u)", elcids[number_of_headers], elcid);
            /* Also add hidden as LCID */
            proto_item *bi_di_lcid = proto_tree_add_uint(pdu_subheader_tree, hf_mac_lte_lcid, tvb, offset, 1, elcids[number_of_headers]);
            proto_item_set_hidden(bi_di_lcid);
            offset++;
        }

        /********************************************************************/
        /* Length field follows if not the last header or for a fixed-sized
           control element */
        if (!extension) {
            /* Last one... */
            if (is_fixed_sized_control_element(lcids[number_of_headers], p_mac_lte_info->direction)) {
                pdu_lengths[number_of_headers] = 0;
            }
            else {
                pdu_lengths[number_of_headers] = -1;
            }
        }
        else {
            /* Not the last one */
            if (!is_fixed_sized_control_element(lcids[number_of_headers], p_mac_lte_info->direction) &&
                (lcids[number_of_headers] != PADDING_LCID)) {

                if (format2) {
                    /* >= 32768 - use 16 bits */
                    ti = proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_sch_length,
                                                     tvb, offset*8, 16, &length, ENC_BIG_ENDIAN);
                    if (length < 32768) {
                        expert_add_info(pinfo, ti, &ei_mac_lte_sch_invalid_length);
                    }

                    offset += 2;
                } else {
                    bool format;

                    /* F(ormat) bit tells us how long the length field is */
                    proto_tree_add_item_ret_boolean(pdu_subheader_tree, hf_mac_lte_sch_format,
                                                    tvb, offset, 1, ENC_BIG_ENDIAN, &format);

                    /* Now read length field itself */
                    if (format) {
                        /* >= 128 - use 15 bits */
                        proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_sch_length,
                                                    tvb, offset*8 + 1, 15, &length, ENC_BIG_ENDIAN);

                        offset += 2;
                    }
                    else {
                        /* Less than 128 - only 7 bits */
                        proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_sch_length,
                                                    tvb, offset*8 + 1, 7, &length, ENC_BIG_ENDIAN);
                        offset++;
                    }
                }
                pdu_lengths[number_of_headers] = (int32_t)length;
            }
            else {
                pdu_lengths[number_of_headers] = 0;
            }
        }


        /* Close off description in info column */
        switch (pdu_lengths[number_of_headers]) {
            case 0:
                write_pdu_label_and_info_literal(pdu_ti, NULL, pinfo, ") ");
                break;
            case -1:
                write_pdu_label_and_info_literal(pdu_ti, NULL, pinfo, ":remainder) ");
                break;
            default:
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, ":%u bytes) ",
                                         pdu_lengths[number_of_headers]);
                break;
        }

        if (lcids[number_of_headers] != EXT_LOGICAL_CHANNEL_ID_LCID) {
            lcid_str = val_to_str_const(initial_lcid, (p_mac_lte_info->direction == DIRECTION_UPLINK) ?
                                        ulsch_lcid_vals : dlsch_lcid_vals, "Unknown");
        } else {
            lcid_str = wmem_strdup_printf(pinfo->pool, "%u", elcids[number_of_headers]);
        }

        /* Append summary to subheader root */
        proto_item_append_text(pdu_subheader_ti, " (lcid=%s", lcid_str);

        switch (pdu_lengths[number_of_headers]) {
            case -1:
                proto_item_append_text(pdu_subheader_ti, ", length is remainder)");
                proto_item_append_text(pdu_header_ti, " (%s:remainder)", lcid_str);
                break;
            case 0:
                proto_item_append_text(pdu_subheader_ti, ")");
                proto_item_append_text(pdu_header_ti, " (%s)", lcid_str);
                break;
            default:
                proto_item_append_text(pdu_subheader_ti, ", length=%d)",
                                       pdu_lengths[number_of_headers]);
                proto_item_append_text(pdu_header_ti, " (%s:%u)", lcid_str, pdu_lengths[number_of_headers]);
                break;
        }


        /* Flag unknown lcid values in expert info */
        if (try_val_to_str(lcids[number_of_headers],
                         (p_mac_lte_info->direction == DIRECTION_UPLINK) ? ulsch_lcid_vals : dlsch_lcid_vals) == NULL) {
            expert_add_info_format(pinfo, pdu_subheader_ti, &ei_mac_lte_lcid_unexpected,
                                   "%cL-SCH: Unexpected LCID received (%u)",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? 'U' : 'D',
                                   lcids[number_of_headers]);
        }

        /* Set length of this subheader */
        proto_item_set_len(pdu_subheader_ti, offset - offset_start_subheader);

        number_of_headers++;
    } while ((number_of_headers < MAX_HEADERS_IN_PDU) && extension);

    /* Check that we didn't reach the end of the subheader array... */
    if (number_of_headers >= MAX_HEADERS_IN_PDU) {
        proto_tree_add_expert_format(tree, pinfo, &ei_mac_lte_too_many_subheaders, tvb, offset, 1,
                                             "Reached %u subheaders - frame obviously malformed",
                                             MAX_HEADERS_IN_PDU);
        return;
    }


    /* Append summary to overall PDU header root */
    proto_item_append_text(pdu_header_ti, "  [%u subheaders]",
                           number_of_headers);

    /* And set its length to offset */
    proto_item_set_len(pdu_header_ti, offset);


    /* For DL, see if this is a retx.  Use whole PDU present (i.e. ignore padding if not logged) */
    if (p_mac_lte_info->direction == DIRECTION_DOWNLINK) {
        /* Result will be added to context tree */
        TrackReportedDLHARQResend(pinfo, tvb, tvb_reported_length_remaining(tvb, 0), context_tree, p_mac_lte_info);

        tap_info->isPHYRetx = (p_mac_lte_info->dl_retx == dl_retx_yes);
    }


    /************************************************************************/
    /* Dissect SDUs / control elements / padding.                           */
    /************************************************************************/

    /* Dissect control element bodies first */

    for (n=0; n < number_of_headers; n++) {
        /* Get out of loop once see any data SDU subheaders */
        if (is_data_lcid(lcids[n], p_mac_lte_info->direction) ||
            lcids[n] == EXT_LOGICAL_CHANNEL_ID_LCID ||
            ((p_mac_lte_info->direction == DIRECTION_DOWNLINK) && (lcids[n] == SC_MCCH_SC_MTCH_LCID))) {
            break;
        }

        /* Process what should be a valid control PDU type */
        if (p_mac_lte_info->direction == DIRECTION_DOWNLINK) {

            /****************************/
            /* DL-SCH Control PDUs      */
            switch (lcids[n]) {
                case DCQR_COMMAND_LCID:
                    /* Zero length */
                    break;
                case ACTIVATION_DEACTIVATION_PDCP_DUP_LCID:
                {
                    /* Create PDCP Dup root */
                    proto_item *ad_pdcp_dup_ti =
                            proto_tree_add_string_format(tree,
                                                         hf_mac_lte_control_activation_deactivation_pdcp_dup,
                                                         tvb, offset, pdu_lengths[n],
                                                         "",
                                                         "Activation/Deactivation of PDCP Duplication");
                    proto_tree *ad_pdcp_dup_tree = proto_item_add_subtree(ad_pdcp_dup_ti, ett_mac_lte_activation_deactivation_pdcp_dup);

                    /* D8..D1 (6.1.3.17) */
                    proto_tree_add_item(ad_pdcp_dup_tree, hf_mac_lte_control_activation_deactivation_pdcp_dup_d8,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(ad_pdcp_dup_tree, hf_mac_lte_control_activation_deactivation_pdcp_dup_d7,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(ad_pdcp_dup_tree, hf_mac_lte_control_activation_deactivation_pdcp_dup_d6,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(ad_pdcp_dup_tree, hf_mac_lte_control_activation_deactivation_pdcp_dup_d5,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(ad_pdcp_dup_tree, hf_mac_lte_control_activation_deactivation_pdcp_dup_d4,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(ad_pdcp_dup_tree, hf_mac_lte_control_activation_deactivation_pdcp_dup_d3,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(ad_pdcp_dup_tree, hf_mac_lte_control_activation_deactivation_pdcp_dup_d2,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(ad_pdcp_dup_tree, hf_mac_lte_control_activation_deactivation_pdcp_dup_d1,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    break;
                }
                case HIBERNATION_1_OCTET_LCID:
                case HIBERNATION_4_OCTETS_LCID:
                {
                    /* 6.1.3.15 */

                    /* Hibernation root */
                    proto_item *hibernation_ti =
                            proto_tree_add_string_format(tree,
                                                         hf_mac_lte_control_hibernation,
                                                         tvb, offset, pdu_lengths[n],
                                                         "",
                                                         "Hibernation");
                    proto_tree *hibernation_tree = proto_item_add_subtree(hibernation_ti, ett_mac_lte_hibernation);

                    /* First octet common to both LCIDs */
                    proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c7,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c6,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c5,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c4,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c3,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c2,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c1,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* N.B. Last bit is reserved */
                    proto_tree_add_item(hibernation_ti, hf_mac_lte_control_hibernation_reserved,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;

                    if (lcids[n] == HIBERNATION_4_OCTETS_LCID) {
                        /* 2nd octet */
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c15,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c14,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c13,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c12,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c11,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c10,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c9,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c8,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;

                        /* 3rd octet */
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c23,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c22,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c21,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c20,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c19,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c18,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c17,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c16,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;

                        /* 4th octet */
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c31,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c30,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c29,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c28,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c27,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c26,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c25,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(hibernation_tree, hf_mac_lte_control_hibernation_c24,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                    }
                    break;
                }

                case ACTIVATION_DEACTIVATION_CSI_RS_LCID:
                    {
                        proto_item *ad_csi_rs_ti;
                        proto_tree *ad_csi_rs_tree;
                        int32_t i;

                        if (pdu_lengths[n] == -1) {
                            /* Control Element size is the remaining PDU */
                            pdu_lengths[n] = (int32_t)tvb_reported_length_remaining(tvb, offset);
                        }
                        /* Create AD CSR-RS root */
                        ad_csi_rs_ti = proto_tree_add_string_format(tree,
                                                                    hf_mac_lte_control_activation_deactivation_csi_rs,
                                                                    tvb, offset, pdu_lengths[n],
                                                                    "",
                                                                    "Activation/Deactivation of CSI-RS");
                        ad_csi_rs_tree = proto_item_add_subtree(ad_csi_rs_ti, ett_mac_lte_activation_deactivation_csi_rs);

                        for (i = 0; i < pdu_lengths[n]; i++) {
                            proto_tree_add_item(ad_csi_rs_tree, hf_mac_lte_control_activation_deactivation_csi_rs_a8,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_csi_rs_tree, hf_mac_lte_control_activation_deactivation_csi_rs_a7,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_csi_rs_tree, hf_mac_lte_control_activation_deactivation_csi_rs_a6,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_csi_rs_tree, hf_mac_lte_control_activation_deactivation_csi_rs_a5,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_csi_rs_tree, hf_mac_lte_control_activation_deactivation_csi_rs_a4,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_csi_rs_tree, hf_mac_lte_control_activation_deactivation_csi_rs_a3,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_csi_rs_tree, hf_mac_lte_control_activation_deactivation_csi_rs_a2,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_csi_rs_tree, hf_mac_lte_control_activation_deactivation_csi_rs_a1,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                        }
                    }
                    break;
                case RECOMMENDED_BIT_RATE_LCID:
                    {
                        proto_item *br_ti;
                        proto_tree *br_tree;
                        proto_item *ti;
                        uint32_t reserved;

                        /* Create BR root */
                        br_ti = proto_tree_add_string_format(tree,
                                                             hf_mac_lte_control_recommended_bit_rate,
                                                             tvb, offset, 2,
                                                             "",
                                                             "Recommended Bit Rate");
                        br_tree = proto_item_add_subtree(br_ti, ett_mac_lte_recommended_bit_rate);

                        proto_tree_add_item(br_tree, hf_mac_lte_control_recommended_bit_rate_lcid,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(br_tree, hf_mac_lte_control_recommended_bit_rate_dir,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(br_tree, hf_mac_lte_control_recommended_bit_rate_bit_rate,
                                            tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 1;
                        ti = proto_tree_add_item_ret_uint(br_tree, hf_mac_lte_control_recommended_bit_rate_reserved,
                                                          tvb, offset, 1, ENC_BIG_ENDIAN, &reserved);
                        if (reserved != 0) {
                            expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                                   "Recommended Bit Rate Reserved bits not zero");
                        }
                        offset += 1;
                    }
                    break;
                case ACTIVATION_DEACTIVATION_LCID:
                case ACTIVATION_DEACTIVATION_4_BYTES_LCID:
                    {
                        proto_item *ad_ti;
                        proto_tree *ad_tree;
                        proto_item *ti;
                        uint32_t reserved;

                        /* Create AD root */
                        ad_ti = proto_tree_add_string_format(tree,
                                                             hf_mac_lte_control_activation_deactivation,
                                                             tvb, offset,
                                                             (lcids[n] == ACTIVATION_DEACTIVATION_4_BYTES_LCID) ? 4 : 1,
                                                             "",
                                                             "Activation/Deactivation");
                        ad_tree = proto_item_add_subtree(ad_ti, ett_mac_lte_activation_deactivation);

                        proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c7,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c6,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c5,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c4,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c3,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c2,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c1,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        ti = proto_tree_add_item_ret_uint(ad_tree, hf_mac_lte_control_activation_deactivation_reserved,
                                                          tvb, offset, 1, ENC_BIG_ENDIAN, &reserved);
                        if (reserved != 0) {
                            expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                                   "Activation/Deactivation Reserved bit not zero");
                        }
                        offset++;
                        if (lcids[n] == ACTIVATION_DEACTIVATION_4_BYTES_LCID) {
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c15,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c14,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c13,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c12,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c11,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c10,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c9,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c8,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c23,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c22,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c21,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c20,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c19,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c18,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c17,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c16,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c31,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c30,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c29,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c28,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c27,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c26,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c25,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ad_tree, hf_mac_lte_control_activation_deactivation_c24,
                                                tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                        }
                    }
                    break;
                case UE_CONTENTION_RESOLUTION_IDENTITY_LCID:
                    {
                        proto_item *cr_ti;
                        proto_tree *cr_tree;
                        proto_item *ti;
                        ContentionResolutionResult *crResult;

                        /* Create CR root */
                        cr_ti = proto_tree_add_string_format(tree,
                                                             hf_mac_lte_control_ue_contention_resolution,
                                                             tvb, offset, 6,
                                                             "",
                                                             "Contention Resolution");
                        cr_tree = proto_item_add_subtree(cr_ti, ett_mac_lte_contention_resolution);

                        /* Contention resolution body */
                        proto_tree_add_item(cr_tree, hf_mac_lte_control_ue_contention_resolution_identity,
                                            tvb, offset, 6, ENC_NA);
                        if (global_mac_lte_decode_cr_body) {
                            tvbuff_t *cr_body_tvb = tvb_new_subset_length(tvb, offset, 6);
                            if (lte_rrc_ul_ccch_handle != 0) {
                                call_with_catch_all(lte_rrc_ul_ccch_handle, cr_body_tvb, pinfo, cr_tree);
                            }
                        }

                        /* Get pointer to result struct for this frame */
                        crResult =  (ContentionResolutionResult *)g_hash_table_lookup(mac_lte_cr_result_hash, GUINT_TO_POINTER(pinfo->num));
                        if (crResult == NULL) {

                            /* Need to set result by looking for and comparing with Msg3 */
                            Msg3Data *msg3Data;
                            unsigned msg3Key = p_mac_lte_info->rnti;

                            /* Allocate result and add it to the table */
                            crResult = wmem_new(wmem_file_scope(), ContentionResolutionResult);
                            g_hash_table_insert(mac_lte_cr_result_hash, GUINT_TO_POINTER(pinfo->num), crResult);

                            /* Look for Msg3 */
                            msg3Data = (Msg3Data *)g_hash_table_lookup(mac_lte_msg3_hash, GUINT_TO_POINTER(msg3Key));

                            /* Compare CCCH bytes */
                            if (msg3Data != NULL) {
                                crResult->msSinceMsg3 = (uint32_t)(((pinfo->abs_ts.secs - msg3Data->msg3Time.secs) * 1000) +
                                                                  ((pinfo->abs_ts.nsecs - msg3Data->msg3Time.nsecs) / 1000000));
                                crResult->msg3FrameNum = msg3Data->framenum;

                                /* Compare the 6 bytes */
                                if (tvb_memeql(tvb, offset, msg3Data->data, 6) == 0) {
                                    crResult->status = Msg3Match;
                                }
                                else {
                                    crResult->status = Msg3NoMatch;
                                }
                            }
                            else {
                                crResult->status = NoMsg3;
                            }
                        }

                        /* Now show CR result in tree */
                        switch (crResult->status) {
                            case NoMsg3:
                                proto_item_append_text(cr_ti, " (no corresponding Msg3 found!)");
                                break;

                            case Msg3Match:
                                /* Point back to msg3 frame */
                                ti = proto_tree_add_uint(cr_tree, hf_mac_lte_control_ue_contention_resolution_msg3,
                                                         tvb, 0, 0, crResult->msg3FrameNum);
                                proto_item_set_generated(ti);
                                ti = proto_tree_add_uint(cr_tree, hf_mac_lte_control_ue_contention_resolution_time_since_msg3,
                                                         tvb, 0, 0, crResult->msSinceMsg3);
                                proto_item_set_generated(ti);

                                ti = proto_tree_add_boolean(cr_tree, hf_mac_lte_control_ue_contention_resolution_msg3_matched,
                                                            tvb, 0, 0, true);
                                proto_item_set_generated(ti);
                                proto_item_append_text(cr_ti, " (matches Msg3 from frame %u, %ums ago)",
                                                       crResult->msg3FrameNum, crResult->msSinceMsg3);

                                if (!PINFO_FD_VISITED(pinfo)) {
                                    /* Add reverse mapping so can link forward from Msg3 frame */
                                    g_hash_table_insert(mac_lte_msg3_cr_hash, GUINT_TO_POINTER(crResult->msg3FrameNum),
                                                       GUINT_TO_POINTER(pinfo->num));
                                }
                                break;

                            case Msg3NoMatch:
                                ti = proto_tree_add_uint(cr_tree, hf_mac_lte_control_ue_contention_resolution_msg3,
                                                         tvb, 0, 0, crResult->msg3FrameNum);
                                proto_item_set_generated(ti);
                                ti = proto_tree_add_uint(cr_tree, hf_mac_lte_control_ue_contention_resolution_time_since_msg3,
                                                         tvb, 0, 0, crResult->msSinceMsg3);
                                proto_item_set_generated(ti);

                                ti = proto_tree_add_boolean(cr_tree, hf_mac_lte_control_ue_contention_resolution_msg3_matched,
                                                             tvb, 0, 0, false);
                                expert_add_info_format(pinfo, ti, &ei_mac_lte_control_ue_contention_resolution_msg3_matched,
                                                       "CR body in Msg4 doesn't match Msg3 CCCH in frame %u",
                                                       crResult->msg3FrameNum);
                                proto_item_set_generated(ti);
                                proto_item_append_text(cr_ti, " (doesn't match Msg3 from frame %u, %u ago)",
                                                       crResult->msg3FrameNum, crResult->msSinceMsg3);
                                break;
                        };

                        offset += 6;
                    }
                    break;
                case TIMING_ADVANCE_LCID:
                    {
                        proto_item *ta_ti;
                        proto_item *ta_value_ti;
                        proto_tree *ta_tree;
                        uint32_t    ta_value;

                        /* Create TA root */
                        ta_ti = proto_tree_add_string_format(tree,
                                                             hf_mac_lte_control_timing_advance,
                                                             tvb, offset, 1,
                                                             "",
                                                             "Timing Advance");
                        ta_tree = proto_item_add_subtree(ta_ti, ett_mac_lte_timing_advance);

                        /* TAG Id */
                        proto_tree_add_item(ta_tree, hf_mac_lte_control_timing_advance_group_id,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);

                        /* TA value */
                        ta_value_ti = proto_tree_add_item_ret_uint(ta_tree, hf_mac_lte_control_timing_advance_command,
                                                                   tvb, offset, 1, ENC_BIG_ENDIAN, &ta_value);

                        if (ta_value == 31) {
                            expert_add_info(pinfo, ta_value_ti, &ei_mac_lte_control_timing_advance_command_no_correction);
                        }
                        else {
                            expert_add_info_format(pinfo, ta_value_ti, &ei_mac_lte_control_timing_advance_command_correction_needed,
                                                   "Timing Advance control element received (%u) %s correction needed",
                                                   ta_value,
                                                   (ta_value < 31) ? "-ve" : "+ve");
                        }
                        offset++;
                    }
                    break;
                case DRX_COMMAND_LCID:
                case LONG_DRX_COMMAND_LCID:
                    /* No payload */
                    mac_lte_drx_control_element_received(p_mac_lte_info->ueid);
                    break;
                case PADDING_LCID:
                    /* No payload (in this position) */
                    tap_info->padding_bytes++;
                    break;

                default:
                    break;
            }
        }
        else {

            /**********************************/
            /* UL-SCH Control PDUs            */
            switch (lcids[n]) {
                case TIMING_ADVANCE_REPORT_LCID:
                    /* 6.1.3.20 */
                    /* R R */
                    proto_tree_add_item(tree, hf_mac_lte_control_timing_advance_value_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
                    /* Timing Advance */
                    proto_tree_add_item(tree, hf_mac_lte_control_timing_advance_value, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;

                case DCQR_AND_AS_RAI_LCID:
                    /* TODO: 6.1.3.19 */
                    /* AS RAI */
                    proto_tree_add_item(tree, hf_mac_lte_control_as_rai, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* R R */
                    proto_tree_add_item(tree, hf_mac_lte_control_as_rai_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* Quality Report */
                    proto_tree_add_item(tree, hf_mac_lte_control_as_rai_quality_report, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    break;

                case AUL_CONFIRMATION_1_OCTET:
                case AUL_CONFIRMATION_4_OCTETS:
                {
                    /* 6.1.3.16 */

                    /* AUL confirmation root */
                    proto_item *aul_conf_ti =
                            proto_tree_add_string_format(tree,
                                                         hf_mac_lte_control_aul_confirmation,
                                                         tvb, offset, pdu_lengths[n],
                                                         "",
                                                         "AUL Confirmation");
                    proto_tree *aul_conf_tree = proto_item_add_subtree(aul_conf_ti, ett_mac_lte_aul_confirmation);

                    /* First octet common to both LCIDs */
                    proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c7,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c6,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c5,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c4,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c3,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c2,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c1,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* N.B. Last bit is reserved */
                    proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_reserved,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;

                    if (lcids[n] == AUL_CONFIRMATION_4_OCTETS) {
                        /* 2nd octet */
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c15,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c14,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c13,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c12,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c11,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c10,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c9,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c8,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;

                        /* 3rd octet */
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c23,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c22,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c21,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c20,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c19,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c18,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c17,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c16,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;

                        /* 4th octet */
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c31,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c30,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c29,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c28,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c27,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c26,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c25,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(aul_conf_tree, hf_mac_lte_control_aul_confirmation_c24,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                    }
                    break;
                }

                case RECOMMENDED_BIT_RATE_QUERY_LCID:
                    {
                        proto_item *br_ti;
                        proto_tree *br_tree;
                        proto_item *ti;
                        uint32_t reserved;

                        /* Create BR root */
                        br_ti = proto_tree_add_string_format(tree,
                                                             hf_mac_lte_control_recommended_bit_rate_query,
                                                             tvb, offset, 2,
                                                             "",
                                                             "Recommended Bit Rate Query");
                        br_tree = proto_item_add_subtree(br_ti, ett_mac_lte_recommended_bit_rate_query);

                        proto_tree_add_item(br_tree, hf_mac_lte_control_recommended_bit_rate_query_lcid,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(br_tree, hf_mac_lte_control_recommended_bit_rate_query_dir,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(br_tree, hf_mac_lte_control_recommended_bit_rate_query_bit_rate,
                                            tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 1;
                        ti = proto_tree_add_item_ret_uint(br_tree, hf_mac_lte_control_recommended_bit_rate_query_reserved,
                                                          tvb, offset, 1, ENC_BIG_ENDIAN, &reserved);
                        if (reserved != 0) {
                            expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                                   "Recommended Bit Rate Reserved bits not zero");
                        }
                        offset += 1;
                    }
                    break;
                case TRUNCATED_SIDELINK_BSR_LCID:
                case SIDELINK_BSR_LCID:
                    {
                        proto_item *slbsr_ti;
                        proto_tree *slbsr_tree;
                        uint32_t curr_offset = offset;

                        if (pdu_lengths[n] == -1) {
                            /* Control Element size is the remaining PDU */
                            pdu_lengths[n] = (int32_t)tvb_reported_length_remaining(tvb, curr_offset);
                        }
                        /* Create SLBSR root */
                        if (lcids[n] == SIDELINK_BSR_LCID) {
                            slbsr_ti = proto_tree_add_string_format(tree,
                                                                    hf_mac_lte_control_sidelink_bsr,
                                                                    tvb, curr_offset, pdu_lengths[n],
                                                                    "",
                                                                    "Sidelink BSR");
                        } else {
                            slbsr_ti = proto_tree_add_string_format(tree,
                                                                    hf_mac_lte_control_sidelink_bsr,
                                                                    tvb, curr_offset, pdu_lengths[n],
                                                                    "",
                                                                    "Truncated Sidelink BSR");
                        }
                        slbsr_tree = proto_item_add_subtree(slbsr_ti, ett_mac_lte_sidelink_bsr);

                        while ((int32_t)(curr_offset - offset) < pdu_lengths[n]) {
                            proto_tree_add_item(slbsr_tree, hf_mac_lte_control_sidelink_bsr_destination_idx_odd,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(slbsr_tree, hf_mac_lte_control_sidelink_bsr_lcg_id_odd,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(slbsr_tree, hf_mac_lte_control_sidelink_bsr_buffer_size_odd,
                                                tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                            curr_offset++;
                            if ((int32_t)(curr_offset - offset) < (pdu_lengths[n] - 1)) {
                                proto_tree_add_item(slbsr_tree, hf_mac_lte_control_sidelink_bsr_destination_idx_even,
                                                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                curr_offset++;
                                proto_tree_add_item(slbsr_tree, hf_mac_lte_control_sidelink_bsr_lcg_id_even,
                                                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(slbsr_tree, hf_mac_lte_control_sidelink_bsr_buffer_size_even,
                                                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                curr_offset++;
                            } else {
                                /* Check Reserved bit */
                                uint32_t reserved;
                                proto_item *it;

                                it = proto_tree_add_item_ret_uint(slbsr_tree, hf_mac_lte_control_sidelink_reserved,
                                                                  tvb, curr_offset, 1, ENC_BIG_ENDIAN, &reserved);
                                if (reserved) {
                                    if (lcids[n] == SIDELINK_BSR_LCID) {
                                        expert_add_info_format(pinfo, it, &ei_mac_lte_reserved_not_zero,
                                                               "Sidelink BSR Reserved bits not zero");
                                    } else {
                                        expert_add_info_format(pinfo, it, &ei_mac_lte_reserved_not_zero,
                                                               "Truncated Sidelink BSR Reserved bits not zero");
                                    }
                                }
                                break;
                            }
                        }
                        offset += pdu_lengths[n];
                    }
                    break;
                case DUAL_CONN_POWER_HEADROOM_REPORT_LCID:
                    {
                        proto_item *dcphr_ti;
                        proto_tree *dcphr_tree;
                        proto_item *ti;
                        proto_tree *dcphr_cell_tree;
                        proto_item *dcphr_cell_ti;
                        uint8_t scell_bitmap_byte;
                        uint32_t scell_bitmap_word;
                        uint8_t byte;
                        unsigned i;
                        uint32_t curr_offset = offset;

                        if (!PINFO_FD_VISITED(pinfo)) {
                            get_mac_lte_ue_simult_pucch_pusch(p_mac_lte_info);
                        }
                        if (pdu_lengths[n] == -1) {
                            /* Control Element size is the remaining PDU */
                            pdu_lengths[n] = (int32_t)tvb_reported_length_remaining(tvb, curr_offset);
                        }

                        /* Create DCPHR root */
                        dcphr_ti = proto_tree_add_string_format(tree,
                                                                hf_mac_lte_control_dual_conn_power_headroom,
                                                                tvb, curr_offset, pdu_lengths[n],
                                                                "",
                                                                "Dual Connectivity Power Headroom Report");
                        dcphr_tree = proto_item_add_subtree(dcphr_ti, ett_mac_lte_dual_conn_power_headroom);

                        /* Work out (heuristically) whether we have 1 or 4 bytes of C bits.
                         * Should be based upon highest sCellIndex and/or whether UE is in dual-connectivity,
                         * but for now trust subheader length and see which one fits. */
                        unsigned num_c_bytes = get_dual_conn_phr_num_c_bytes(tvb, curr_offset,
                                                                          p_mac_lte_info->isSimultPUCCHPUSCHPCell,
                                                                          p_mac_lte_info->isSimultPUCCHPUSCHPSCell,
                                                                          pdu_lengths[n]);

                        scell_bitmap_byte = tvb_get_uint8(tvb, curr_offset);

                        /* Do first byte (C1-C7) */
                        proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c7,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c6,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c5,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c4,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c3,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c2,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c1,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        /* Check Reserved bit */
                        ti = proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_reserved,
                                                 tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        if (scell_bitmap_byte & 0x01) {
                            expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                                   "Dual Connectivity Power Headroom Report Reserved bit not zero");
                        }
                        curr_offset++;

                        if (num_c_bytes == 4) {
                            /* Do other 3 bytes (C8-C31) */
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c15,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c14,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c13,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c12,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c11,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c10,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c9,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c8,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            curr_offset++;

                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c23,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c22,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c21,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c20,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c19,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c18,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c17,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c16,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            curr_offset++;

                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c31,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c30,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c29,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c28,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c27,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c26,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c25,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_tree, hf_mac_lte_control_dual_conn_power_headroom_c24,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            curr_offset++;
                        }


                        if (p_mac_lte_info->isSimultPUCCHPUSCHPCell) {
                            /* PCell PH Type 2 is present */
                            byte = tvb_get_uint8(tvb, curr_offset);
                            dcphr_cell_tree = proto_tree_add_subtree(dcphr_tree, tvb, curr_offset, (!(byte&0x40)?2:1),
                                            ett_mac_lte_dual_conn_power_headroom_cell, &dcphr_cell_ti, "PCell PUCCH");
                            proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_power_backoff,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_value,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_level,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_item_append_text(dcphr_cell_ti, " (%s)",
                                                   val_to_str_ext_const((byte&0x3f), &power_headroom_vals_ext, "Unknown"));
                            curr_offset++;
                            if ((byte & 0x40) == 0) {
                                /* Pcmax,c field is present */
                                byte = tvb_get_uint8(tvb, curr_offset);
                                /* Check 2 Reserved bits */
                                ti = proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_reserved2,
                                                         tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                if (byte & 0xc0) {
                                    expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                                           "Dual Connectivity Power Headroom Report Reserved bits not zero (found 0x%x)",
                                                           (byte & 0xc0) >> 6);
                                }
                                proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_pcmaxc,
                                                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                proto_item_append_text(dcphr_cell_ti, " (%s)",
                                                       val_to_str_ext_const((byte&0x3f), &pcmaxc_vals_ext, "Unknown"));
                                curr_offset++;
                            }
                        }
                        if (p_mac_lte_info->isSimultPUCCHPUSCHPSCell) {
                            /* PSCell PH Type 2 is present */
                            byte = tvb_get_uint8(tvb, curr_offset);
                            dcphr_cell_tree = proto_tree_add_subtree(dcphr_tree, tvb, curr_offset, (!(byte&0x40)?2:1),
                                            ett_mac_lte_dual_conn_power_headroom_cell, &dcphr_cell_ti, "PSCell PUCCH");
                            proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_power_backoff,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_value,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_level,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_item_append_text(dcphr_cell_ti, " (%s)",
                                                   val_to_str_ext_const((byte&0x3f), &power_headroom_vals_ext, "Unknown"));
                            curr_offset++;
                            if ((byte & 0x40) == 0) {
                                /* Pcmax,c field is present */
                                byte = tvb_get_uint8(tvb, curr_offset);
                                /* Check 2 Reserved bits */
                                ti = proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_reserved2,
                                                         tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                if (byte & 0xc0) {
                                    expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                                           "Dual Connectivity Power Headroom Report Reserved bits not zero (found 0x%x)",
                                                           (byte & 0xc0) >> 6);
                                }
                                proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_pcmaxc,
                                                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                proto_item_append_text(dcphr_cell_ti, " (%s)",
                                                       val_to_str_ext_const((byte&0x3f), &pcmaxc_vals_ext, "Unknown"));
                                curr_offset++;
                            }
                        }
                        byte = tvb_get_uint8(tvb, curr_offset);
                        dcphr_cell_tree = proto_tree_add_subtree(dcphr_tree, tvb, curr_offset, (!(byte&0x40)?2:1),
                                            ett_mac_lte_dual_conn_power_headroom_cell, &dcphr_cell_ti, "PCell PUSCH");
                        proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_power_backoff,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_value,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_level,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_item_append_text(dcphr_cell_ti, " (%s)",
                                               val_to_str_ext_const((byte&0x3f), &power_headroom_vals_ext, "Unknown"));
                        curr_offset++;
                        if ((byte & 0x40) == 0) {
                            /* Pcmax,c field is present */
                            byte = tvb_get_uint8(tvb, curr_offset);
                            /* Check 2 Reserved bits */
                            ti = proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_reserved2,
                                                     tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            if (byte & 0xc0) {
                                expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                                       "Dual Connectivity Power Headroom Report Reserved bits not zero (found 0x%x)",
                                                       (byte & 0xc0) >> 6);
                            }
                            proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_pcmaxc,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_item_append_text(dcphr_cell_ti, " (%s)",
                                                   val_to_str_ext_const((byte&0x3f), &pcmaxc_vals_ext, "Unknown"));
                            curr_offset++;
                        }

                        /* Add entry for each set bit. Iterate over 32 entries regardless */
                        if (num_c_bytes == 1) {
                            scell_bitmap_word = scell_bitmap_byte << 24; /* least significant 3 bytes will be 0 */
                        }
                        else {
                            scell_bitmap_word = tvb_get_ntohl(tvb, offset);
                        }

                        for (i=1; i < 31; i++) {
                            /* Work out how much shift to adddress this bit */
                            unsigned byte_shift = (31-i)/8;
                            unsigned bit_shift = i % 8;
                            /* Is entry for scell i present? */
                            if (scell_bitmap_word & (0x01 << (byte_shift*8 + bit_shift))) {
                                byte = tvb_get_uint8(tvb, curr_offset);
                                dcphr_cell_tree = proto_tree_add_subtree_format(dcphr_tree, tvb, curr_offset, (!(byte&0x40)?2:1),
                                                    ett_mac_lte_dual_conn_power_headroom_cell, &dcphr_cell_ti, "SCell Index %u PUSCH", i);
                                proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_power_backoff,
                                                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_value,
                                                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_level,
                                                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                proto_item_append_text(dcphr_cell_ti, " (%s)",
                                                       val_to_str_ext_const((byte&0x3f), &power_headroom_vals_ext, "Unknown"));
                                curr_offset++;
                                if ((byte & 0x40) == 0) {
                                    /* Pcmax,c field is present */
                                    byte = tvb_get_uint8(tvb, curr_offset);
                                    /* Check 2 Reserved bits */
                                    ti = proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_reserved2,
                                                             tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                    if (byte & 0xc0) {
                                        expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                                               "Dual Connectivity Power Headroom Report Reserved bits not zero (found 0x%x)",
                                                               (byte & 0xc0) >> 6);
                                    }
                                    proto_tree_add_item(dcphr_cell_tree, hf_mac_lte_control_dual_conn_power_headroom_pcmaxc,
                                                        tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                    proto_item_append_text(dcphr_cell_ti, " (%s)",
                                                           val_to_str_ext_const((byte&0x3f), &pcmaxc_vals_ext, "Unknown"));
                                    curr_offset++;
                                }
                            }
                        }
                        if ((int32_t)(curr_offset - offset) != pdu_lengths[n]) {
                            expert_add_info_format(pinfo, dcphr_ti, &ei_mac_lte_control_element_size_invalid,
                                "Control Element has an unexpected size (computed=%u, actual=%d)",
                                curr_offset - offset, pdu_lengths[n]);
                        }
                        offset += pdu_lengths[n];
                    }
                    break;
                case EXTENDED_POWER_HEADROOM_REPORT_LCID:
                    {
                        proto_item *ephr_ti;
                        proto_tree *ephr_tree;
                        proto_item *ti;
                        proto_tree *ephr_cell_tree;
                        proto_item *ephr_cell_ti;
                        uint8_t scell_bitmap;
                        uint8_t scell_count;
                        uint8_t byte;
                        unsigned i;
                        uint32_t curr_offset = offset;
                        uint32_t computed_header_offset;

                        if (!PINFO_FD_VISITED(pinfo)) {
                            get_mac_lte_ue_simult_pucch_pusch(p_mac_lte_info);
                        }
                        if (pdu_lengths[n] == -1) {
                            /* Control Element size is the remaining PDU */
                            pdu_lengths[n] = (int16_t)tvb_reported_length_remaining(tvb, curr_offset);
                        }

                        /* Create EPHR root */
                        ephr_ti = proto_tree_add_string_format(tree,
                                                               hf_mac_lte_control_ext_power_headroom,
                                                               tvb, curr_offset, pdu_lengths[n],
                                                               "",
                                                               "Extended Power Headroom Report");
                        ephr_tree = proto_item_add_subtree(ephr_ti, ett_mac_lte_extended_power_headroom);

                        /* TODO: add support for extendedPHR2 */
                        scell_bitmap = tvb_get_uint8(tvb, curr_offset);
                        proto_tree_add_item(ephr_tree, hf_mac_lte_control_ext_power_headroom_c7,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ephr_tree, hf_mac_lte_control_ext_power_headroom_c6,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ephr_tree, hf_mac_lte_control_ext_power_headroom_c5,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ephr_tree, hf_mac_lte_control_ext_power_headroom_c4,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ephr_tree, hf_mac_lte_control_ext_power_headroom_c3,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ephr_tree, hf_mac_lte_control_ext_power_headroom_c2,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ephr_tree, hf_mac_lte_control_ext_power_headroom_c1,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        /* Check Reserved bit */
                        ti = proto_tree_add_item(ephr_tree, hf_mac_lte_control_ext_power_headroom_reserved,
                                                 tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        if (scell_bitmap & 0x01) {
                            expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                                   "Extended Power Headroom Report Reserved bit not zero");
                        }
                        curr_offset++;

                        /* Compute expected header size to deduce if PH Type 2 report is present or not */
                        /* First count the number of SCells */
                        for (i = 0, scell_count = 0; i < 7; i++) {
                            if (scell_bitmap & (0x80>>i)) {
                                scell_count++;
                            }
                        }
                        /* Now quickly parse the header */
                        computed_header_offset = curr_offset;
                        for (i = 0; i < (unsigned)(1 + scell_count); i++) {
                            if ((tvb_get_uint8(tvb, computed_header_offset) & 0x40) == 0) {
                                computed_header_offset++;
                            }
                            computed_header_offset++;
                        }

                        if (((int32_t)(computed_header_offset + 1 - curr_offset) != pdu_lengths[n]) ||
                            p_mac_lte_info->isSimultPUCCHPUSCHPCell) {
                            /* PH Type 2 might be present */
                            if ((tvb_get_uint8(tvb, computed_header_offset) & 0x40) == 0) {
                                computed_header_offset++;
                            }
                            computed_header_offset++;
                            if ((int32_t)(computed_header_offset + 1 - curr_offset) != pdu_lengths[n]) {
                                expert_add_info_format(pinfo, ephr_ti, &ei_mac_lte_control_element_size_invalid,
                                    "Control Element has an unexpected size (computed=%u, actual=%d)",
                                    computed_header_offset + 1 - curr_offset, pdu_lengths[n]);
                                offset += pdu_lengths[n];
                                break;
                            }
                            byte = tvb_get_uint8(tvb, curr_offset);
                            ephr_cell_tree = proto_tree_add_subtree(ephr_tree, tvb, curr_offset, (!(byte&0x40)?2:1),
                                            ett_mac_lte_extended_power_headroom_cell, &ephr_cell_ti, "PCell PUCCH");
                            proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_power_backoff,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_value,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_level,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_item_append_text(ephr_cell_ti, " (%s)",
                                                   val_to_str_ext_const((byte&0x3f), &power_headroom_vals_ext, "Unknown"));
                            curr_offset++;
                            if ((byte & 0x40) == 0) {
                                /* Pcmax,c field is present */
                                byte = tvb_get_uint8(tvb, curr_offset);
                                /* Check 2 Reserved bits */
                                ti = proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_reserved2,
                                                         tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                if (byte & 0xc0) {
                                    expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                                           "Extended Power Headroom Report Reserved bits not zero (found 0x%x)",
                                                           (byte & 0xc0) >> 6);
                                }
                                proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_pcmaxc,
                                                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                proto_item_append_text(ephr_cell_ti, " (%s)",
                                                       val_to_str_ext_const((byte&0x3f), &pcmaxc_vals_ext, "Unknown"));
                                curr_offset++;
                            }
                        }
                        byte = tvb_get_uint8(tvb, curr_offset);
                        ephr_cell_tree = proto_tree_add_subtree(ephr_tree, tvb, curr_offset, (!(byte&0x40)?2:1),
                                            ett_mac_lte_extended_power_headroom_cell, &ephr_cell_ti, "PCell PUSCH");
                        proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_power_backoff,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_value,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_level,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_item_append_text(ephr_cell_ti, " (%s)",
                                               val_to_str_ext_const((byte&0x3f), &power_headroom_vals_ext, "Unknown"));
                        curr_offset++;
                        if ((byte & 0x40) == 0) {
                            /* Pcmax,c field is present */
                            byte = tvb_get_uint8(tvb, curr_offset);
                            /* Check 2 Reserved bits */
                            ti = proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_reserved2,
                                                     tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            if (byte & 0xc0) {
                                expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                                       "Extended Power Headroom Report Reserved bits not zero (found 0x%x)",
                                                       (byte & 0xc0) >> 6);
                            }
                            proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_pcmaxc,
                                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                            proto_item_append_text(ephr_cell_ti, " (%s)",
                                                   val_to_str_ext_const((byte&0x3f), &pcmaxc_vals_ext, "Unknown"));
                            curr_offset++;
                        }
                        for (i = 1, scell_bitmap>>=1; i <= 7; i++, scell_bitmap>>=1) {
                            if (scell_bitmap & 0x01) {
                                byte = tvb_get_uint8(tvb, curr_offset);
                                ephr_cell_tree = proto_tree_add_subtree_format(ephr_tree, tvb, curr_offset, (!(byte&0x40)?2:1),
                                                    ett_mac_lte_extended_power_headroom_cell, &ephr_cell_ti, "SCell Index %u PUSCH", i);
                                proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_power_backoff,
                                                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_value,
                                                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_level,
                                                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                proto_item_append_text(ephr_cell_ti, " (%s)",
                                                       val_to_str_ext_const((byte&0x3f), &power_headroom_vals_ext, "Unknown"));
                                curr_offset++;
                                if ((byte & 0x40) == 0) {
                                    /* Pcmax,c field is present */
                                    byte = tvb_get_uint8(tvb, curr_offset);
                                    /* Check 2 Reserved bits */
                                    uint32_t reserved;
                                    ti = proto_tree_add_item_ret_uint(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_reserved2,
                                                                      tvb, curr_offset, 1, ENC_BIG_ENDIAN, &reserved);
                                    if (reserved != 0) {
                                        expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                                               "Extended Power Headroom Report Reserved bits not zero (found 0x%x)",
                                                               reserved);
                                    }
                                    proto_tree_add_item(ephr_cell_tree, hf_mac_lte_control_ext_power_headroom_pcmaxc,
                                                        tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                                    proto_item_append_text(ephr_cell_ti, " (%s)",
                                                           val_to_str_ext_const((byte&0x3f), &pcmaxc_vals_ext, "Unknown"));
                                    curr_offset++;
                                }
                            }
                        }
                        offset += pdu_lengths[n];
                    }
                    break;
                case POWER_HEADROOM_REPORT_LCID:
                    {
                        proto_item *phr_ti;
                        proto_tree *phr_tree;
                        proto_item *ti;
                        uint32_t reserved;
                        uint32_t level;

                        /* Create PHR root */
                        phr_ti = proto_tree_add_string_format(tree,
                                                              hf_mac_lte_control_power_headroom,
                                                              tvb, offset, 1,
                                                              "",
                                                              "Power Headroom Report");
                        phr_tree = proto_item_add_subtree(phr_ti, ett_mac_lte_power_headroom);

                        /* Check 2 Reserved bits */
                        ti = proto_tree_add_item_ret_uint(phr_tree, hf_mac_lte_control_power_headroom_reserved,
                                                          tvb, offset, 1, ENC_BIG_ENDIAN, &reserved);
                        if (reserved != 0) {
                            expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                                   "Power Headroom Report Reserved bits not zero (found 0x%x)", reserved);
                        }

                        /* Level */
                        proto_tree_add_item_ret_uint(phr_tree, hf_mac_lte_control_power_headroom_level,
                                                     tvb, offset, 1, ENC_BIG_ENDIAN, &level);

                        /* Show value in root label */
                        proto_item_append_text(phr_ti, " (%s)",
                                               val_to_str_ext_const(level, &power_headroom_vals_ext, "Unknown"));
                        offset++;
                    }
                    break;
                case CRNTI_LCID:
                    proto_tree_add_item(tree, hf_mac_lte_control_crnti,
                                        tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;
                /* TODO: treat separately */
                case TRUNCATED_BSR_LCID:
                case SHORT_BSR_LCID:
                    {
                        proto_tree *bsr_tree;
                        proto_item *bsr_ti;
                        proto_item *buffer_size_ti;
                        uint32_t lcgid;
                        uint32_t buffer_size;
                        int hfindex;
                        value_string_ext *p_vs_ext;
                        uint32_t *p_buffer_size_median;

                        if (!PINFO_FD_VISITED(pinfo)) {
                            get_mac_lte_ue_ext_bsr_sizes(p_mac_lte_info);
                        }
                        if (p_mac_lte_info->isExtendedBSRSizes) {
                            hfindex = hf_mac_lte_control_short_ext_bsr_buffer_size;
                            p_vs_ext = &ext_buffer_size_vals_ext;
                            p_buffer_size_median = ext_buffer_size_median;
                        } else {
                            hfindex = hf_mac_lte_control_short_bsr_buffer_size;
                            p_vs_ext = &buffer_size_vals_ext;
                            p_buffer_size_median = buffer_size_median;
                        }

                        if (lcids[n] == SHORT_BSR_LCID) {
                            bsr_ti = proto_tree_add_string_format(tree,
                                                                  hf_mac_lte_control_bsr,
                                                                  tvb, offset, 1,
                                                                  "",
                                                                  "Short BSR");
                        } else {
                            bsr_ti = proto_tree_add_string_format(tree,
                                                                  hf_mac_lte_control_bsr,
                                                                  tvb, offset, 1,
                                                                  "",
                                                                  "Truncated BSR");
                        }
                        bsr_tree = proto_item_add_subtree(bsr_ti, ett_mac_lte_bsr);

                        /* LCG ID */
                        proto_tree_add_item_ret_uint(bsr_tree, hf_mac_lte_control_bsr_lcg_id,
                                                     tvb, offset, 1, ENC_BIG_ENDIAN, &lcgid);
                        /* Buffer Size */
                        buffer_size_ti = proto_tree_add_item_ret_uint(bsr_tree, hfindex,
                                                                      tvb, offset, 1, ENC_BIG_ENDIAN, &buffer_size);
                        if (global_mac_lte_show_BSR_median) {
                            /* Add value that can be graphed */
                            proto_item *bsr_median_ti = proto_tree_add_uint(bsr_tree, hf_mac_lte_bsr_size_median, tvb, offset, 1, p_buffer_size_median[buffer_size]);
                            proto_item_set_generated(bsr_median_ti);
                        }
                        offset++;

                        if ((int)buffer_size >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, &ei_mac_lte_bsr_warn_threshold_exceeded,
                                                   "UE %u - BSR for LCG %u exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   lcgid,
                                                   buffer_size,
                                                   val_to_str_ext_const(buffer_size, p_vs_ext, "Unknown"));
                        }


                        proto_item_append_text(bsr_ti, " (lcgid=%u  %s)",
                                               lcgid,
                                               val_to_str_ext_const(buffer_size, p_vs_ext, "Unknown"));
                    }
                    break;
                case LONG_BSR_LCID:
                    {
                        proto_tree *bsr_tree;
                        proto_item *bsr_ti, *bsr_median_ti;
                        proto_item *buffer_size_ti;
                        uint32_t    buffer_size[4];
                        int hfindex[4];
                        value_string_ext *p_vs_ext;
                        uint32_t *p_buffer_size_median;

                        if (!PINFO_FD_VISITED(pinfo)) {
                            get_mac_lte_ue_ext_bsr_sizes(p_mac_lte_info);
                        }
                        if (p_mac_lte_info->isExtendedBSRSizes) {
                            hfindex[0] = hf_mac_lte_control_long_ext_bsr_buffer_size_0;
                            hfindex[1] = hf_mac_lte_control_long_ext_bsr_buffer_size_1;
                            hfindex[2] = hf_mac_lte_control_long_ext_bsr_buffer_size_2;
                            hfindex[3] = hf_mac_lte_control_long_ext_bsr_buffer_size_3;
                            p_vs_ext = &ext_buffer_size_vals_ext;
                            p_buffer_size_median = ext_buffer_size_median;
                        } else {
                            hfindex[0] = hf_mac_lte_control_long_bsr_buffer_size_0;
                            hfindex[1] = hf_mac_lte_control_long_bsr_buffer_size_1;
                            hfindex[2] = hf_mac_lte_control_long_bsr_buffer_size_2;
                            hfindex[3] = hf_mac_lte_control_long_bsr_buffer_size_3;
                            p_vs_ext = &buffer_size_vals_ext;
                            p_buffer_size_median = buffer_size_median;
                        }

                        bsr_ti = proto_tree_add_string_format(tree,
                                                              hf_mac_lte_control_bsr,
                                                              tvb, offset, 3,
                                                              "",
                                                              "Long BSR");
                        bsr_tree = proto_item_add_subtree(bsr_ti, ett_mac_lte_bsr);

                        /* LCID Group 0 */
                        buffer_size_ti = proto_tree_add_item_ret_uint(bsr_tree, hfindex[0],
                                                                      tvb, offset, 1,
                                                                      ENC_BIG_ENDIAN, &buffer_size[0]);

                        if (global_mac_lte_show_BSR_median) {
                            /* Add value that can be graphed */
                            bsr_median_ti = proto_tree_add_uint(bsr_tree, hf_mac_lte_bsr_size_median, tvb, offset, 1, p_buffer_size_median[buffer_size[0]]);
                            proto_item_set_generated(bsr_median_ti);
                        }

                        if ((int)buffer_size[0] >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, &ei_mac_lte_bsr_warn_threshold_exceeded,
                                                   "UE %u - BSR for LCG 0 exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   buffer_size[0],
                                                   val_to_str_ext_const(buffer_size[0], p_vs_ext, "Unknown"));
                        }

                        /* LCID Group 1 */
                        buffer_size_ti = proto_tree_add_item_ret_uint(bsr_tree, hfindex[1],
                                                                      tvb, offset, 2,
                                                                      ENC_BIG_ENDIAN, &buffer_size[1]);

                        if (global_mac_lte_show_BSR_median) {
                            /* Add value that can be graphed */
                            bsr_median_ti = proto_tree_add_uint(bsr_tree, hf_mac_lte_bsr_size_median, tvb, offset, 1, p_buffer_size_median[buffer_size[1]]);
                            proto_item_set_generated(bsr_median_ti);
                        }

                        offset++;
                        if ((int)buffer_size[1] >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, &ei_mac_lte_bsr_warn_threshold_exceeded,
                                                   "UE %u - BSR for LCG 1 exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   buffer_size[1],
                                                   val_to_str_ext_const(buffer_size[1], p_vs_ext, "Unknown"));
                        }

                        /* LCID Group 2 */
                        buffer_size_ti = proto_tree_add_item_ret_uint(bsr_tree, hfindex[2],
                                                                      tvb, offset, 2,
                                                                      ENC_BIG_ENDIAN, &buffer_size[2]);

                        if (global_mac_lte_show_BSR_median) {
                            /* Add value that can be graphed */
                            bsr_median_ti = proto_tree_add_uint(bsr_tree, hf_mac_lte_bsr_size_median, tvb, offset, 1, p_buffer_size_median[buffer_size[2]]);
                            proto_item_set_generated(bsr_median_ti);
                        }

                        offset++;
                        if ((int)buffer_size[2] >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, &ei_mac_lte_bsr_warn_threshold_exceeded,
                                                   "UE %u - BSR for LCG 2 exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   buffer_size[2],
                                                   val_to_str_ext_const(buffer_size[2], p_vs_ext, "Unknown"));
                        }

                        /* LCID Group 3 */
                        buffer_size_ti = proto_tree_add_item_ret_uint(bsr_tree, hfindex[3],
                                                                      tvb, offset, 1,
                                                                      ENC_BIG_ENDIAN, &buffer_size[3]);

                        if (global_mac_lte_show_BSR_median) {
                            /* Add value that can be graphed */
                            bsr_median_ti = proto_tree_add_uint(bsr_tree, hf_mac_lte_bsr_size_median, tvb, offset, 1, p_buffer_size_median[buffer_size[3]]);
                            proto_item_set_generated(bsr_median_ti);
                        }

                        offset++;
                        if ((int)buffer_size[3] >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, &ei_mac_lte_bsr_warn_threshold_exceeded,
                                                   "UE %u - BSR for LCG 3 exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   buffer_size[3],
                                                   val_to_str_ext_const(buffer_size[3], p_vs_ext, "Unknown"));
                        }

                        /* Append summary to parent */
                        proto_item_append_text(bsr_ti, "   0:(%s)  1:(%s)  2:(%s)  3:(%s)",
                                               val_to_str_ext_const(buffer_size[0], p_vs_ext, "Unknown"),
                                               val_to_str_ext_const(buffer_size[1], p_vs_ext, "Unknown"),
                                               val_to_str_ext_const(buffer_size[2], p_vs_ext, "Unknown"),
                                               val_to_str_ext_const(buffer_size[3], p_vs_ext, "Unknown"));
                    }
                    break;
                case PADDING_LCID:
                    /* No payload, in this position */
                    tap_info->padding_bytes++;
                    break;

                default:
                    break;
            }
        }
    }

    /* There might not be any data, if only headers (plus control data) were logged */
    is_truncated = ((tvb_captured_length_remaining(tvb, offset) == 0) && expecting_body_data);
    truncated_ti = proto_tree_add_uint(tree, hf_mac_lte_sch_header_only, tvb, 0, 0,
                                       is_truncated);
    if (is_truncated) {
        proto_item_set_generated(truncated_ti);
        expert_add_info(pinfo, truncated_ti, &ei_mac_lte_sch_header_only_truncated);
        /* Update sdu and byte count in stats */
        for (; n < number_of_headers; n++) {
            uint16_t data_length;
            /* Break out if meet padding */
            if (lcids[n] == PADDING_LCID) {
                break;
            }
            data_length = (pdu_lengths[n] == -1) ?
                            tvb_reported_length_remaining(tvb, offset) :
                            pdu_lengths[n];
            if ((lcids[n] >= 3) && (lcids[n] <= 10)) {
                tap_info->sdus_for_lcid[lcids[n]]++;
                tap_info->bytes_for_lcid[lcids[n]] += data_length;
            } else if ((lcids[n] == EXT_LOGICAL_CHANNEL_ID_LCID) &&
                       (elcids[n] >= 32) && (elcids[n] <= 38)) {
                tap_info->sdus_for_lcid[elcids[n]-21]++;
                tap_info->bytes_for_lcid[elcids[n]-21] += data_length;
            }
            offset += data_length;
        }
        if (lcids[number_of_headers-1] == PADDING_LCID) {
            /* Update padding bytes in stats */
            tap_info->padding_bytes += (p_mac_lte_info->length - offset);
        }
        return;
    }
    else {
        proto_item_set_hidden(truncated_ti);
    }


    /* Now process remaining bodies, which should all be data */
    for (; n < number_of_headers; n++) {

        /* Data SDUs treated identically for Uplink or downlink channels */
        proto_item *sdu_ti;
        uint16_t data_length;
        bool    rlc_called_for_sdu = false;

        /* Break out if meet padding */
        if (lcids[n] == PADDING_LCID) {
            break;
        }

        /* Work out length */
        data_length = (pdu_lengths[n] == -1) ?
                            tvb_reported_length_remaining(tvb, offset) :
                            pdu_lengths[n];

        if ((lcids[n] == 0) && /* CCCH */
            (p_mac_lte_info->direction == DIRECTION_UPLINK) &&
            (p_mac_lte_info->nbMode == nb_mode) &&
            (data_length > 0)) {

            /* Dissect DPR MAC Control Element that is in front of CCCH SDU (Figure 6.1.3.10-1) */
            proto_item *dpr_ti;
            proto_tree *dpr_tree;
            uint32_t reserved;

            dpr_ti = proto_tree_add_string_format(tree,
                                      hf_mac_lte_control_data_vol_power_headroom,
                                      tvb, offset, 1,
                                      "",
                                      "Data Volume and Power Headroom Report");
            dpr_tree = proto_item_add_subtree(dpr_ti, ett_mac_lte_data_vol_power_headroom);
            /* R R */
            dpr_ti = proto_tree_add_item_ret_uint(dpr_tree, hf_mac_lte_control_data_vol_power_headroom_reserved,
                                                  tvb, offset, 1, ENC_BIG_ENDIAN, &reserved);
            if (reserved) {
                expert_add_info_format(pinfo, dpr_ti, &ei_mac_lte_reserved_not_zero,
                                       "Data Volume and Power Headroom Report Reserved bits not zero");
            }
            /* PH (2 bits) */
            proto_tree_add_item(dpr_tree, hf_mac_lte_control_data_vol_power_headroom_level, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* DV (4 bits) */
            proto_tree_add_item(dpr_tree, hf_mac_lte_control_data_vol_power_headroom_data_vol, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            if (pdu_lengths[n] == -1) {
                data_length--;
            }
        }

        if ((lcids[n] == 13) && /* CCCH and Extended Power Headroom Report */
            (p_mac_lte_info->direction == DIRECTION_UPLINK) &&
            (p_mac_lte_info->nbMode == nb_mode) &&
            (data_length > 0)) {

            /* Dissect DPR MAC Control Element that is in front of CCCH SDU (Figure 6.1.3.10-1a) */
            proto_item *dpr_ti;
            proto_tree *dpr_tree;

            dpr_ti = proto_tree_add_string_format(tree,
                                      hf_mac_lte_control_data_vol_power_headroom,
                                      tvb, offset, 1,
                                      "",
                                      "Data Volume and Power Headroom Report for Extended Power Headroom");
            dpr_tree = proto_item_add_subtree(dpr_ti, ett_mac_lte_data_vol_power_headroom);

            /* PH (4 bits) */
            proto_tree_add_item(dpr_tree, hf_mac_lte_control_data_vol_power_headroom_level_4_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* DV (4 bits) */
            proto_tree_add_item(dpr_tree, hf_mac_lte_control_data_vol_power_headroom_data_vol, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            if (pdu_lengths[n] == -1) {
                data_length--;
            }
        }

        /* Dissect SDU as raw bytes */
        sdu_ti = proto_tree_add_bytes_format(tree, hf_mac_lte_sch_sdu, tvb, offset, pdu_lengths[n],
                                             NULL, "SDU (%s, length=%u bytes): ",
                                             val_to_str_const(lcids[n],
                                                              (p_mac_lte_info->direction == DIRECTION_UPLINK) ?
                                                                  ulsch_lcid_vals :
                                                                  dlsch_lcid_vals,
                                                             "Unknown"),
                                             data_length);

        /* Look for Msg3 data so that it may be compared with later
           Contention Resolution body */
        /* Starting from R13, CCCH can be more than 48 bits but only the first 48 bits are used for contention resolution */
        if ((lcids[n] == 0) && (p_mac_lte_info->direction == DIRECTION_UPLINK) && (data_length >= 6)) {
            if (!PINFO_FD_VISITED(pinfo)) {
                unsigned key = p_mac_lte_info->rnti;
                Msg3Data *data = (Msg3Data *)g_hash_table_lookup(mac_lte_msg3_hash, GUINT_TO_POINTER(key));

                /* Look for previous entry for this UE */
                if (data == NULL) {
                    /* Allocate space for data and add to table */
                    data = wmem_new(wmem_file_scope(), Msg3Data);
                    g_hash_table_insert(mac_lte_msg3_hash, GUINT_TO_POINTER(key), data);
                }

                /* Fill in data details */
                data->framenum = pinfo->num;
                tvb_memcpy(tvb, data->data, offset, 6);
                data->msg3Time = pinfo->abs_ts;
            }
        }

        /* CCCH frames can be dissected directly by LTE RRC... */
        if ((lcids[n] == 0) && global_mac_lte_attempt_rrc_decode) {
            tvbuff_t *rrc_tvb = tvb_new_subset_length(tvb, offset, data_length);

            /* Get appropriate dissector handle */
            dissector_handle_t protocol_handle = 0;
            if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
                if (p_mac_lte_info->nbMode == no_nb_mode) {
                    protocol_handle = lte_rrc_ul_ccch_handle;
                }
                else {
                    protocol_handle = lte_rrc_ul_ccch_nb_handle;
                }
            }
            else {
                if (p_mac_lte_info->nbMode == no_nb_mode) {
                    protocol_handle = lte_rrc_dl_ccch_handle;
                }
                else {
                    protocol_handle = lte_rrc_dl_ccch_nb_handle;
                }
            }

            /* Hide raw view of bytes */
            proto_item_set_hidden(sdu_ti);
            rlc_called_for_sdu = true;

            call_with_catch_all(protocol_handle, rrc_tvb, pinfo, tree);
        }

        /* LCID 1 and 2 can be assumed to be srb1&2, so can dissect as RLC AM */
        /* LCID 3 in NB mode can be assumed to be srb1bis, so can dissect as RLC AM */
        else if ((lcids[n] == 1) || (lcids[n] == 2) ||
                 (p_mac_lte_info->nbMode == nb_mode && lcids[n] == 3)) {
            if (global_mac_lte_attempt_srb_decode) {
                /* Call RLC dissector */
                call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                   RLC_AM_MODE, p_mac_lte_info->direction, p_mac_lte_info->ueid,
                                   CHANNEL_TYPE_SRB, lcids[n], 0,
                                   get_mac_lte_channel_priority(p_mac_lte_info->ueid,
                                                                lcids[n], p_mac_lte_info->direction),
                                   false, p_mac_lte_info->nbMode);

                /* Hide raw view of bytes */
                proto_item_set_hidden(sdu_ti);
                rlc_called_for_sdu = true;
            }
        }

        else if (((lcids[n] >= 3) && (lcids[n] <= 10)) || (lcids[n] == EXT_LOGICAL_CHANNEL_ID_LCID)) {

            /* Look for mapping for this LCID to drb channel set by UAT table or through
               configuration protocol. */
            rlc_channel_type_t rlc_channel_type;
            uint8_t seqnum_length;
            int drb_id;
            bool rlc_ext_li_field;
            uint8_t lcid = (lcids[n] == EXT_LOGICAL_CHANNEL_ID_LCID) ? elcids[n] : lcids[n];
            uint8_t priority = get_mac_lte_channel_priority(p_mac_lte_info->ueid,
                                                           lcid, p_mac_lte_info->direction);

            lookup_rlc_channel_from_lcid(p_mac_lte_info->ueid,
                                         lcid,
                                         p_mac_lte_info->direction,
                                         &rlc_channel_type,
                                         &seqnum_length,
                                         &drb_id,
                                         &rlc_ext_li_field);

            /* Dissect according to channel type */
            switch (rlc_channel_type) {
                case rlcUM5:
                case rlcUM10:
                    call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                       RLC_UM_MODE, p_mac_lte_info->direction, p_mac_lte_info->ueid,
                                       CHANNEL_TYPE_DRB, (uint16_t)drb_id, seqnum_length,
                                       priority, false, p_mac_lte_info->nbMode);
                    break;
                case rlcAM:
                case rlcAMulExtLiField:
                case rlcAMdlExtLiField:
                case rlcAMextLiField:
                case rlcAMul16:
                case rlcAMdl16:
                case rlcAM16:
                case rlcAMul16ulExtLiField:
                case rlcAMdl16ulExtLiField:
                case rlcAM16ulExtLiField:
                case rlcAMul16dlExtLiField:
                case rlcAMdl16dlExtLiField:
                case rlcAM16dlExtLiField:
                case rlcAMul16extLiField:
                case rlcAMdl16extLiField:
                case rlcAM16extLiField:
                    call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                       RLC_AM_MODE, p_mac_lte_info->direction, p_mac_lte_info->ueid,
                                       CHANNEL_TYPE_DRB, (uint16_t)drb_id, seqnum_length,
                                       priority, rlc_ext_li_field, p_mac_lte_info->nbMode);
                    break;
                case rlcTM:
                    call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                       RLC_TM_MODE, p_mac_lte_info->direction, p_mac_lte_info->ueid,
                                       CHANNEL_TYPE_DRB, (uint16_t)drb_id, 0,
                                       priority, false, p_mac_lte_info->nbMode);
                    break;
                case rlcRaw:
                    /* Nothing to do! */
                    break;
            }

            if (rlc_channel_type != rlcRaw) {
                /* Hide raw view of bytes */
                proto_item_set_hidden(sdu_ti);
                rlc_called_for_sdu = true;
            }

        }

        else if ((lcids[n] == SC_MCCH_SC_MTCH_LCID) && (p_mac_lte_info->rntiType == SC_RNTI)
                 && global_mac_lte_attempt_rrc_decode) {
            tvbuff_t *rrc_tvb = tvb_new_subset_length(tvb, offset, data_length);

            /* Hide raw view of bytes */
            proto_item_set_hidden(sdu_ti);
            rlc_called_for_sdu = true;

            call_with_catch_all(lte_rrc_sc_mcch_handle, rrc_tvb, pinfo, tree);
        }

        /* Show bytes too, if won't be hidden (slow). There must be a nicer way of doing this! */
        if (!rlc_called_for_sdu) {
            if (pdu_lengths[n] >= 30)
            {
                proto_item_append_text(sdu_ti, "%s", tvb_bytes_to_str(pinfo->pool, tvb, offset, 30));
                proto_item_append_text(sdu_ti, "...");
            }
            else
            {
                proto_item_append_text(sdu_ti, "%s", tvb_bytes_to_str(pinfo->pool, tvb, offset, data_length));
            }
        }

        offset += data_length;

        /* Update tap sdu and byte count for this channel */
        if ((lcids[n] >= 3) && (lcids[n] <= 10)) {
            tap_info->sdus_for_lcid[lcids[n]]++;
            tap_info->bytes_for_lcid[lcids[n]] += data_length;
        } else if ((lcids[n] == EXT_LOGICAL_CHANNEL_ID_LCID) &&
                   (elcids[n] >= 32) && (elcids[n] <= 38)) {
            tap_info->sdus_for_lcid[elcids[n]-21]++;
            tap_info->bytes_for_lcid[elcids[n]-21] += data_length;
        }
    }

    /* Was this a Msg3 that led to a CR answer? */
    if (PINFO_FD_VISITED(pinfo)) {
        if ((p_mac_lte_info->direction == DIRECTION_UPLINK) &&
            (lcids[0] == 0)) /* N.B. there has to be at least 1 lcid if we got here */ {

            uint32_t cr_frame = GPOINTER_TO_UINT (g_hash_table_lookup(mac_lte_msg3_cr_hash,
                                                                     GUINT_TO_POINTER(pinfo->num)));
            if (cr_frame != 0) {
                proto_item *cr_ti = proto_tree_add_uint(tree, hf_mac_lte_control_msg3_to_cr,
                                                        tvb, 0, 0, cr_frame);
                proto_item_set_generated(cr_ti);
            }
        }
    }

    /* Now padding, if present, extends to the end of the PDU */
    if (lcids[number_of_headers-1] == PADDING_LCID) {
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(tree, hf_mac_lte_padding_data,
                                tvb, offset, -1, ENC_NA);
        }
        padding_length_ti = proto_tree_add_uint(tree, hf_mac_lte_padding_length,
                                                tvb, offset, 0,
                                                p_mac_lte_info->length - offset);
        proto_item_set_generated(padding_length_ti);

        /* Update padding bytes in stats */
        tap_info->padding_bytes += (p_mac_lte_info->length - offset);

        /* Make sure the PDU isn't bigger than reported! */
        if (offset > p_mac_lte_info->length) {
            expert_add_info_format(pinfo, padding_length_ti, &ei_mac_lte_context_length,
                                   "%s MAC PDU is longer than reported length (reported=%u, actual=%u)",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? "UL-SCH" : "DL-SCH",
                                   p_mac_lte_info->length, offset);
        }
    }
    else {
        /* There is no padding at the end of the frame */
        if (offset < p_mac_lte_info->length) {
            /* There is a problem if we haven't used all of the PDU */
            expert_add_info_format(pinfo, pdu_ti, &ei_mac_lte_context_length,
                                   "%s PDU for UE %u is shorter than reported length (reported=%u, actual=%u)",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? "UL-SCH" : "DL-SCH",
                                   p_mac_lte_info->ueid, p_mac_lte_info->length, offset);
        }

        if (offset > p_mac_lte_info->length) {
            /* There is a problem if the PDU is longer than reported */
            expert_add_info_format(pinfo, pdu_ti, &ei_mac_lte_context_length,
                                   "%s PDU for UE %u is longer than reported length (reported=%u, actual=%u)",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? "UL-SCH" : "DL-SCH",
                                   p_mac_lte_info->ueid, p_mac_lte_info->length, offset);
        }
    }

    /* Can now store updated DRX info and show its info in the tree */
    if (global_mac_lte_show_drx) {
        if (!PINFO_FD_VISITED(pinfo)) {
            /* Store 'after' snapshot of UE state for this frame */
            set_drx_info(pinfo, p_mac_lte_info, false, pdu_instance);
        }

        /* Show current DRX state in tree as 'after' */
        show_drx_info(pinfo, tree, tvb, p_mac_lte_info, false, pdu_instance);
    }
}

static void dissect_mch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *pdu_ti,
                        uint32_t offset, mac_lte_info *p_mac_lte_info)
{
    uint8_t           extension;
    uint16_t          n;
    proto_item       *truncated_ti;
    proto_item       *padding_length_ti;
    proto_item       *hidden_root_ti;

    /* Keep track of LCIDs and lengths as we dissect the header */
    uint16_t number_of_headers = 0;
    uint8_t lcids[MAX_HEADERS_IN_PDU];
    int32_t pdu_lengths[MAX_HEADERS_IN_PDU];

    proto_item *pdu_header_ti, *sched_info_ti = NULL;
    proto_tree *pdu_header_tree;

    bool       have_seen_data_header = false;
    uint8_t    number_of_padding_subheaders = 0;
    bool       have_seen_non_padding_control = false;
    bool       expecting_body_data = false;
    uint32_t   is_truncated = false;

    write_pdu_label_and_info_literal(pdu_ti, NULL, pinfo, "MCH: ");

    /* Add hidden item to filter on */
    hidden_root_ti = proto_tree_add_string_format(tree, hf_mac_lte_mch, tvb,
                                                  offset, 0, "", "Hidden header");
    proto_item_set_hidden(hidden_root_ti);

    /* Add PDU block header subtree */
    pdu_header_ti = proto_tree_add_string_format(tree, hf_mac_lte_mch_header,
                                                 tvb, offset, 0,
                                                 "",
                                                 "MAC PDU Header");
    pdu_header_tree = proto_item_add_subtree(pdu_header_ti, ett_mac_lte_mch_header);


    /************************************************************************/
    /* Dissect each sub-header.                                             */
    do {
        uint8_t reserved, format2;
        uint64_t length = 0;
        proto_item *pdu_subheader_ti;
        proto_tree *pdu_subheader_tree;
        proto_item *lcid_ti;
        proto_item *ti;
        int        offset_start_subheader = offset;
        uint8_t first_byte = tvb_get_uint8(tvb, offset);

        /* Add PDU block header subtree.
           Default with length of 1 byte. */
        pdu_subheader_ti = proto_tree_add_string_format(pdu_header_tree,
                                                        hf_mac_lte_mch_subheader,
                                                        tvb, offset, 1,
                                                        "",
                                                        "Sub-header");
        pdu_subheader_tree = proto_item_add_subtree(pdu_subheader_ti,
                                                    ett_mac_lte_mch_subheader);

        /* Check 1st reserved bit */
        reserved = (first_byte & 0x80) >> 7;
        ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_mch_reserved,
                                 tvb, offset, 1, ENC_BIG_ENDIAN);
        if (reserved != 0) {
            expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                   "MCH header Reserved bits not zero");
        }

        /* Format2 bit */
        format2 = (first_byte & 0x40) >> 6;
        proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_mch_format2,
                            tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Extended bit */
        extension = (first_byte & 0x20) >> 5;
        proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_mch_extended,
                            tvb, offset, 1, ENC_BIG_ENDIAN);

        /* LCID */
        lcids[number_of_headers] = first_byte & 0x1f;
        lcid_ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_mch_lcid,
                                      tvb, offset, 1, ENC_BIG_ENDIAN);
        if (lcids[number_of_headers] == MCH_SCHEDULING_INFO_LCID) {
            sched_info_ti = lcid_ti;
        }
        write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                 "(%s",
                                 val_to_str_const(lcids[number_of_headers],
                                                  mch_lcid_vals, "(Unknown LCID)"));
        offset++;

        /* Remember if we've seen a data subheader */
        if (lcids[number_of_headers] <= 28) {
            have_seen_data_header = true;
            expecting_body_data = true;
        }

        /* Show an expert item if a control subheader (except Padding) appears
           *after* a data PDU */
        if (have_seen_data_header &&
            (lcids[number_of_headers] > 28) && (lcids[number_of_headers] != PADDING_LCID)) {
            expert_add_info_format(pinfo, lcid_ti, &ei_mac_lte_control_subheader_after_data_subheader,
                                   "MCH Control subheaders should not appear after data subheaders");
            return;
        }

        /* Should not see padding after non-padding control... */
        if ((lcids[number_of_headers] > 28) &&
            (lcids[number_of_headers] == PADDING_LCID) &&
            extension)
        {
            number_of_padding_subheaders++;
            if (number_of_padding_subheaders > 2) {
                expert_add_info(pinfo, lcid_ti, &ei_mac_lte_padding_data_multiple);
            }

            if (have_seen_non_padding_control) {
                expert_add_info(pinfo, lcid_ti, &ei_mac_lte_padding_data_before_control_subheader);
            }
        }

        /* Remember that we've seen non-padding control */
        if ((lcids[number_of_headers] > 28) &&
            (lcids[number_of_headers] != PADDING_LCID)) {
            have_seen_non_padding_control = true;
        }



        /********************************************************************/
        /* Length field follows if not the last header or for a fixed-sized
           control element */
        if (!extension) {
            /* Last one... */
            pdu_lengths[number_of_headers] = -1;
        }
        else {
            /* Not the last one */
            if (lcids[number_of_headers] != PADDING_LCID) {

                if (format2) {
                    /* >= 32578 - use 16 bits */
                    proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_mch_length,
                                                tvb, offset*8, 16, &length, ENC_BIG_ENDIAN);
                    if (length < 32768) {
                        expert_add_info(pinfo, ti, &ei_mac_lte_mch_invalid_length);
                    }

                    offset += 2;
                } else {
                    bool format;

                    /* F(ormat) bit tells us how long the length field is */
                    proto_tree_add_item_ret_boolean(pdu_subheader_tree, hf_mac_lte_mch_format,
                                                    tvb, offset, 1, ENC_BIG_ENDIAN, &format);

                    /* Now read length field itself */
                    if (format) {
                        /* >= 128 - use 15 bits */
                        proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_mch_length,
                                                    tvb, offset*8 + 1, 15, &length, ENC_BIG_ENDIAN);

                        offset += 2;
                    }
                    else {
                        /* Less than 128 - only 7 bits */
                        proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_mch_length,
                                                    tvb, offset*8 + 1, 7, &length, ENC_BIG_ENDIAN);
                        offset++;
                    }
                }
                pdu_lengths[number_of_headers] = (int32_t)length;
            }
            else {
                pdu_lengths[number_of_headers] = 0;
            }
        }


        /* Close off description in info column */
        switch (pdu_lengths[number_of_headers]) {
            case 0:
                write_pdu_label_and_info_literal(pdu_ti, NULL, pinfo, ") ");
                break;
            case -1:
                write_pdu_label_and_info_literal(pdu_ti, NULL, pinfo, ":remainder) ");
                break;
            default:
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, ":%u bytes) ",
                                         pdu_lengths[number_of_headers]);
                break;
        }

        /* Append summary to subheader root */
        proto_item_append_text(pdu_subheader_ti, " (lcid=%s",
                               val_to_str_const(lcids[number_of_headers],
                                                mch_lcid_vals, "Unknown"));

        switch (pdu_lengths[number_of_headers]) {
            case -1:
                proto_item_append_text(pdu_subheader_ti, ", length is remainder)");
                proto_item_append_text(pdu_header_ti, " (%s:remainder)",
                                       val_to_str_const(lcids[number_of_headers],
                                                        mch_lcid_vals,
                                                        "Unknown"));
                break;
            case 0:
                proto_item_append_text(pdu_subheader_ti, ")");
                proto_item_append_text(pdu_header_ti, " (%s)",
                                       val_to_str_const(lcids[number_of_headers],
                                                        mch_lcid_vals,
                                                        "Unknown"));
                break;
            default:
                proto_item_append_text(pdu_subheader_ti, ", length=%d)",
                                       pdu_lengths[number_of_headers]);
                proto_item_append_text(pdu_header_ti, " (%s:%d)",
                                       val_to_str_const(lcids[number_of_headers],
                                                        mch_lcid_vals,
                                                        "Unknown"),
                                       pdu_lengths[number_of_headers]);
                break;
        }


        /* Flag unknown lcid values in expert info */
        if (try_val_to_str(lcids[number_of_headers],mch_lcid_vals) == NULL) {
            expert_add_info_format(pinfo, pdu_subheader_ti, &ei_mac_lte_lcid_unexpected,
                                   "MCH: Unexpected LCID received (%u)",
                                   lcids[number_of_headers]);
        }

        /* Set length of this subheader */
        proto_item_set_len(pdu_subheader_ti, offset - offset_start_subheader);

        number_of_headers++;
    } while ((number_of_headers < MAX_HEADERS_IN_PDU) && extension);

    /* Check that we didn't reach the end of the subheader array... */
    if (number_of_headers >= MAX_HEADERS_IN_PDU) {
        proto_tree_add_expert_format(tree, pinfo, &ei_mac_lte_too_many_subheaders, tvb, offset, 1,
                                             "Reached %u subheaders - frame obviously malformed",
                                             MAX_HEADERS_IN_PDU);
        return;
    }


    /* Append summary to overall PDU header root */
    proto_item_append_text(pdu_header_ti, " (%u subheaders)",
                           number_of_headers);

    /* And set its length to offset */
    proto_item_set_len(pdu_header_ti, offset);


    /************************************************************************/
    /* Dissect SDUs / control elements / padding.                           */
    /************************************************************************/

    /* Dissect control element bodies first */

    for (n=0; n < number_of_headers; n++) {
        /* Get out of loop once see any data SDU subheaders */
        if (lcids[n] <= 28) {
            break;
        }

        /* Process what should be a valid control PDU type */
        switch (lcids[n]) {
            case MCH_SCHEDULING_INFO_LCID:
                {
                    uint32_t curr_offset = offset;
                    int16_t i;
                    uint32_t stop_mtch_val;
                    proto_item *mch_sched_info_ti, *ti;
                    proto_tree *mch_sched_info_tree;

                    if (pdu_lengths[n] == -1) {
                        /* Control Element size is the remaining PDU */
                        pdu_lengths[n] = (int16_t)tvb_reported_length_remaining(tvb, curr_offset);
                    }
                    if (pdu_lengths[n] & 0x01) {
                        expert_add_info_format(pinfo, sched_info_ti, &ei_mac_lte_context_length,
                                               "MCH Scheduling Information MAC Control Element should have an even size");
                    }

                    mch_sched_info_ti = proto_tree_add_string_format(tree,
                                                                     hf_mac_lte_control_mch_scheduling_info,
                                                                     tvb, curr_offset, pdu_lengths[n],
                                                                     "",
                                                                     "MCH Scheduling Information");
                    mch_sched_info_tree = proto_item_add_subtree(mch_sched_info_ti, ett_mac_lte_mch_scheduling_info);

                    for (i=0; i<(pdu_lengths[n]/2); i++) {
                        proto_tree_add_item(mch_sched_info_tree, hf_mac_lte_control_mch_scheduling_info_lcid,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        ti = proto_tree_add_item_ret_uint(mch_sched_info_tree, hf_mac_lte_control_mch_scheduling_info_stop_mtch,
                                                          tvb, curr_offset, 2,
                                                          ENC_BIG_ENDIAN, &stop_mtch_val);
                        if ((stop_mtch_val >= 2043) && (stop_mtch_val <= 2046)) {
                            proto_item_append_text(ti, " (reserved)");
                        }
                        else if (stop_mtch_val == 2047) {
                            proto_item_append_text(ti, " (MTCH is not scheduled)");
                        }
                        curr_offset += 2;
                    }

                    offset += pdu_lengths[n];
                }
                break;
            case PADDING_LCID:
                /* No payload (in this position) */
                break;

            default:
                break;
        }
    }


    /* There might not be any data, if only headers (plus control data) were logged */
    is_truncated = ((tvb_captured_length_remaining(tvb, offset) == 0) && expecting_body_data);
    truncated_ti = proto_tree_add_uint(tree, hf_mac_lte_mch_header_only, tvb, 0, 0,
                                       is_truncated);
    if (is_truncated) {
        proto_item_set_generated(truncated_ti);
        expert_add_info(pinfo, truncated_ti, &ei_mac_lte_mch_header_only_truncated);
        return;
    }
    else {
        proto_item_set_hidden(truncated_ti);
    }


    /* Now process remaining bodies, which should all be data */
    for (; n < number_of_headers; n++) {

        proto_item *sdu_ti;
        uint16_t data_length;

        /* Break out if meet padding */
        if (lcids[n] == PADDING_LCID) {
            break;
        }

        /* Work out length */
        data_length = (pdu_lengths[n] == -1) ?
                            tvb_reported_length_remaining(tvb, offset) :
                            pdu_lengths[n];

        if ((lcids[n] == 0) && global_mac_lte_attempt_mcch_decode) {
            /* Call RLC dissector */
            call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                               RLC_UM_MODE, DIRECTION_DOWNLINK, 0,
                               CHANNEL_TYPE_MCCH, 0, 5, 0, false, p_mac_lte_info->nbMode);
        } else if ((lcids[n] <= 28) && global_mac_lte_call_rlc_for_mtch) {
            /* Call RLC dissector */
            call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                               RLC_UM_MODE, DIRECTION_DOWNLINK, 0,
                               CHANNEL_TYPE_MTCH, 0, 5, 0, false, p_mac_lte_info->nbMode);
        } else {
            /* Dissect SDU as raw bytes */
            sdu_ti = proto_tree_add_bytes_format(tree, hf_mac_lte_mch_sdu, tvb, offset, pdu_lengths[n],
                                                 NULL, "SDU (%s, length=%u bytes): ",
                                                 val_to_str_const(lcids[n], mch_lcid_vals, "Unknown"),
                                                 data_length);
            if (pdu_lengths[n] >= 30)
            {
                proto_item_append_text(sdu_ti, "%s", tvb_bytes_to_str(pinfo->pool, tvb, offset, 30));
                proto_item_append_text(sdu_ti, "...");
            }
            else
            {
                proto_item_append_text(sdu_ti, "%s", tvb_bytes_to_str(pinfo->pool, tvb, offset, data_length));
            }
        }

        offset += data_length;
    }

    /* Now padding, if present, extends to the end of the PDU */
    if (lcids[number_of_headers-1] == PADDING_LCID) {
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(tree, hf_mac_lte_padding_data,
                                tvb, offset, -1, ENC_NA);
        }
        padding_length_ti = proto_tree_add_uint(tree, hf_mac_lte_padding_length,
                                                tvb, offset, 0,
                                                p_mac_lte_info->length - offset);
        proto_item_set_generated(padding_length_ti);

        /* Make sure the PDU isn't bigger than reported! */
        if (offset > p_mac_lte_info->length) {
            expert_add_info_format(pinfo, padding_length_ti, &ei_mac_lte_context_length,
                                   "MAC PDU is longer than reported length (reported=%u, actual=%u)",
                                   p_mac_lte_info->length, offset);
        }
    }
    else {
        /* There is no padding at the end of the frame */
        if (offset < p_mac_lte_info->length) {
            /* There is a problem if we haven't used all of the PDU */
            expert_add_info_format(pinfo, pdu_ti, &ei_mac_lte_context_length,
                                   "PDU is shorter than reported length (reported=%u, actual=%u)",
                                   p_mac_lte_info->length, offset);
        }

        if (offset > p_mac_lte_info->length) {
            /* There is a problem if the PDU is longer than reported */
            expert_add_info_format(pinfo, pdu_ti, &ei_mac_lte_context_length,
                                   "PDU is longer than reported length (reported=%u, actual=%u)",
                                   p_mac_lte_info->length, offset);
        }
    }
}


/* Dissect SL-BCH PDU */
static void dissect_sl_bch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           proto_item *pdu_ti, int offset)
{
    proto_item *ti;

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "SL-BCH PDU (%u bytes)",
                             tvb_reported_length_remaining(tvb, offset));

    /****************************************/
    /* Whole frame is SL-BCH data           */

    /* Raw data */
    ti = proto_tree_add_item(tree, hf_mac_lte_slbch_pdu,
                             tvb, offset, -1, ENC_NA);

    if (global_mac_lte_attempt_rrc_decode) {
        /* Attempt to decode payload using LTE RRC dissector */
        tvbuff_t *rrc_tvb = tvb_new_subset_remaining(tvb, offset);

        /* Hide raw view of bytes */
        proto_item_set_hidden(ti);

        call_with_catch_all(lte_rrc_sbcch_sl_bch_handle, rrc_tvb, pinfo, tree);
    }
}


/* Dissect SL-SCH PDU */
static void dissect_slsch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           proto_item *pdu_ti,
                           int offset, mac_lte_info *p_mac_lte_info)
{
    /* Keep track of LCIDs and lengths as we dissect the header */
    uint16_t number_of_headers = 0, n;
    uint8_t lcids[MAX_HEADERS_IN_PDU], extension;
    int16_t pdu_lengths[MAX_HEADERS_IN_PDU];

    proto_item *pdu_header_ti, *pdu_subheader_ti, *ti, *truncated_ti, *padding_length_ti;
    proto_tree *pdu_header_tree, *pdu_subheader_tree;

    uint8_t  number_of_padding_subheaders = 0;
    bool     expecting_body_data = false;
    bool is_truncated;
    uint32_t reserved, version;

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "%s: (SFN=%-4u, SF=%u) UEId=%-3u ",
                             "SL-SCH",
                             p_mac_lte_info->sysframeNumber,
                             p_mac_lte_info->subframeNumber,
                             p_mac_lte_info->ueid);

    /* Add PDU block header subtree */
    pdu_header_ti = proto_tree_add_string_format(tree, hf_mac_lte_slsch_header,
                                                 tvb, offset, 0,
                                                 "", "MAC PDU Header");
    pdu_header_tree = proto_item_add_subtree(pdu_header_ti, ett_mac_lte_slsch_header);

    /* Dissect SL-SCH sub-header */
    proto_item_append_text(pdu_header_ti, " (SL-SCH)");
    pdu_subheader_ti = proto_tree_add_string_format(pdu_header_tree,
                                                    hf_mac_lte_slsch_subheader,
                                                    tvb, offset, 6,
                                                    "",
                                                    "Sub-header (SL-SCH)");
    pdu_subheader_tree = proto_item_add_subtree(pdu_subheader_ti,
                                                ett_mac_lte_slsch_subheader);
    proto_tree_add_item_ret_uint(pdu_subheader_tree, hf_mac_lte_slsch_version,
                                 tvb, offset, 1, ENC_BIG_ENDIAN, &version);
    ti = proto_tree_add_item_ret_uint(pdu_subheader_tree, hf_mac_lte_slsch_reserved,
                                      tvb, offset, 1, ENC_BIG_ENDIAN, &reserved);
    offset++;
    if (reserved) {
        expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                               "SL-SCH header Reserved bits not zero");
    }
    proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_slsch_src_l2_id,
                        tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    if (version == 3) {
        proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_slsch_dst_l2_id2,
                            tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
    } else {
        proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_slsch_dst_l2_id,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    /* Dissect each sub-header */
    do {
        uint32_t    first_byte;
        uint64_t    length = 0;
        proto_item *lcid_ti;
        int         offset_start_subheader = offset;

        /* Add PDU block header subtree.
           Default with length of 1 byte. */
        pdu_subheader_ti = proto_tree_add_string_format(pdu_header_tree,
                                                        hf_mac_lte_slsch_subheader,
                                                        tvb, offset, 1,
                                                        "",
                                                        "Sub-header");
        pdu_subheader_tree = proto_item_add_subtree(pdu_subheader_ti,
                                                    ett_mac_lte_slsch_subheader);

        /* Check 1st 2 reserved bits */
        ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_slsch_reserved2,
                                 tvb, offset, 1, ENC_BIG_ENDIAN);
        first_byte = tvb_get_uint8(tvb, offset);
        if ((first_byte & 0xc0) != 0) {
            expert_add_info_format(pinfo, ti, &ei_mac_lte_reserved_not_zero,
                                   "SL-SCH header Reserved bits not zero");
        }

        /* Extended bit */
        extension = (first_byte & 0x20) >> 5;
        proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_slsch_extended,
                            tvb, offset, 1, ENC_BIG_ENDIAN);

        /* LCID */
        lcids[number_of_headers] = first_byte & 0x1f;
        lcid_ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_slsch_lcid,
                                      tvb, offset, 1, ENC_BIG_ENDIAN);
        write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                 "(%s",
                                 val_to_str_const(lcids[number_of_headers],
                                                  slsch_lcid_vals, "(Unknown LCID)"));
        offset++;

        /* Remember if we've seen a data subheader */
        if (is_data_lcid(lcids[number_of_headers], p_mac_lte_info->direction)) {
            expecting_body_data = true;
        }

        /* Should not see padding after non-padding control... */
        if ((lcids[number_of_headers] == PADDING_LCID) &&
            extension)
        {
            number_of_padding_subheaders++;
            if (number_of_padding_subheaders > 2) {
                expert_add_info(pinfo, lcid_ti, &ei_mac_lte_padding_data_multiple);
            }
        }

        /* Also flag if we have final padding but also padding subheaders
           at the start! */
        if (!extension && (lcids[number_of_headers] == PADDING_LCID) &&
            (number_of_padding_subheaders > 0)) {
                expert_add_info(pinfo, lcid_ti, &ei_mac_lte_padding_data_start_and_end);
        }

        /* Length field follows if not the last header or for a fixed-sized
           control element */
        if (!extension) {
            /* Last one... */
            pdu_lengths[number_of_headers] = -1;
        } else {
            /* Not the last one */
            if (lcids[number_of_headers] != PADDING_LCID) {
                bool format;

                /* F(ormat) bit tells us how long the length field is */
                proto_tree_add_item_ret_boolean(pdu_subheader_tree, hf_mac_lte_slsch_format,
                                                tvb, offset, 1, ENC_BIG_ENDIAN, &format);

                /* Now read length field itself */
                if (format) {
                    /* >= 128 - use 15 bits */
                    proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_slsch_length,
                                                tvb, offset*8 + 1, 15, &length, ENC_BIG_ENDIAN);
                    offset += 2;
                } else {
                    /* Less than 128 - only 7 bits */
                    proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_slsch_length,
                                                tvb, offset*8 + 1, 7, &length, ENC_BIG_ENDIAN);
                    offset++;
                }
                pdu_lengths[number_of_headers] = (int16_t)length;
            } else {
                pdu_lengths[number_of_headers] = 0;
            }
        }

        /* Close off description in info column */
        switch (pdu_lengths[number_of_headers]) {
            case 0:
                write_pdu_label_and_info_literal(pdu_ti, NULL, pinfo, ") ");
                break;
            case -1:
                write_pdu_label_and_info_literal(pdu_ti, NULL, pinfo, ":remainder) ");
                break;
            default:
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, ":%u bytes) ",
                                         pdu_lengths[number_of_headers]);
                break;
        }

        /* Append summary to subheader root */
        proto_item_append_text(pdu_subheader_ti, " (lcid=%s",
                               val_to_str_const(lcids[number_of_headers],
                                                slsch_lcid_vals, "Unknown"));

        switch (pdu_lengths[number_of_headers]) {
            case -1:
                proto_item_append_text(pdu_subheader_ti, ", length is remainder)");
                proto_item_append_text(pdu_header_ti, " (%s:remainder)",
                                       val_to_str_const(lcids[number_of_headers],
                                                        slsch_lcid_vals, "Unknown"));
                break;
            case 0:
                proto_item_append_text(pdu_subheader_ti, ")");
                proto_item_append_text(pdu_header_ti, " (%s)",
                                       val_to_str_const(lcids[number_of_headers],
                                                        slsch_lcid_vals, "Unknown"));
                break;
            default:
                proto_item_append_text(pdu_subheader_ti, ", length=%d)",
                                       pdu_lengths[number_of_headers]);
                proto_item_append_text(pdu_header_ti, " (%s:%d)",
                                       val_to_str_const(lcids[number_of_headers],
                                                        slsch_lcid_vals, "Unknown"),
                                       pdu_lengths[number_of_headers]);
                break;
        }

        /* Flag unknown lcid values in expert info */
        if (try_val_to_str(lcids[number_of_headers], slsch_lcid_vals) == NULL) {
            expert_add_info_format(pinfo, pdu_subheader_ti, &ei_mac_lte_lcid_unexpected,
                                   "SL-SCH: Unexpected LCID received (%u)",
                                   lcids[number_of_headers]);
        }

        /* Set length of this subheader */
        proto_item_set_len(pdu_subheader_ti, offset - offset_start_subheader);

        number_of_headers++;
    } while ((number_of_headers < MAX_HEADERS_IN_PDU) && extension);

    /* Check that we didn't reach the end of the subheader array... */
    if (number_of_headers >= MAX_HEADERS_IN_PDU) {
        proto_tree_add_expert_format(tree, pinfo, &ei_mac_lte_too_many_subheaders, tvb, offset, 1,
                                             "Reached %u subheaders - frame obviously malformed",
                                             MAX_HEADERS_IN_PDU);
        return;
    }

    /* Append summary to overall PDU header root */
    proto_item_append_text(pdu_header_ti, "  [%u subheaders]",
                           number_of_headers);

    /* And set its length to offset */
    proto_item_set_len(pdu_header_ti, offset);

    /* Dissect control element bodies first */

    for (n = 0; n < number_of_headers; n++) {
        /* Get out of loop once see any data SDU subheaders */
        if (is_data_lcid(lcids[n], p_mac_lte_info->direction)) {
            break;
        }

        switch (lcids[n]) {
            case PADDING_LCID:
                /* No payload (in this position) */
                break;
            default:
                break;
        }
    }

    /* There might not be any data, if only headers (plus control data) were logged */
    is_truncated = ((tvb_captured_length_remaining(tvb, offset) == 0) && expecting_body_data);
    truncated_ti = proto_tree_add_uint(tree, hf_mac_lte_slsch_header_only, tvb, 0, 0,
                                       is_truncated);
    if (is_truncated) {
        proto_item_set_generated(truncated_ti);
        expert_add_info(pinfo, truncated_ti, &ei_mac_lte_slsch_header_only_truncated);
        return;
    } else {
        proto_item_set_hidden(truncated_ti);
    }


    /* Now process remaining bodies, which should all be data */
    for (; n < number_of_headers; n++) {
        proto_item *sdu_ti;
        uint16_t data_length;

        /* Break out if meet padding */
        if (lcids[n] == PADDING_LCID) {
            break;
        }

        /* Work out length */
        data_length = (pdu_lengths[n] == -1) ?
                            tvb_reported_length_remaining(tvb, offset) :
                            pdu_lengths[n];

        /* Dissect SDU as raw bytes */
        sdu_ti = proto_tree_add_bytes_format(tree, hf_mac_lte_slsch_sdu, tvb, offset, pdu_lengths[n],
                                             NULL, "SDU (%s, length=%u bytes): ",
                                             val_to_str_const(lcids[n],
                                                              slsch_lcid_vals, "Unknown"),
                                             data_length);

        /* Show bytes too, if won't be hidden (slow). There must be a nicer way of doing this! */
        if (pdu_lengths[n] >= 30) {
            proto_item_append_text(sdu_ti, "%s", tvb_bytes_to_str(pinfo->pool, tvb, offset, 30));
            proto_item_append_text(sdu_ti, "...");
        } else {
            proto_item_append_text(sdu_ti, "%s", tvb_bytes_to_str(pinfo->pool, tvb, offset, data_length));
        }

        offset += data_length;
    }

    /* Now padding, if present, extends to the end of the PDU */
    if (lcids[number_of_headers-1] == PADDING_LCID) {
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(tree, hf_mac_lte_padding_data,
                                tvb, offset, -1, ENC_NA);
        }
        padding_length_ti = proto_tree_add_uint(tree, hf_mac_lte_padding_length,
                                                tvb, offset, 0,
                                                p_mac_lte_info->length - offset);
        proto_item_set_generated(padding_length_ti);

        /* Make sure the PDU isn't bigger than reported! */
        if (offset > p_mac_lte_info->length) {
            expert_add_info_format(pinfo, padding_length_ti, &ei_mac_lte_context_length,
                                   "SL-SCH MAC PDU is longer than reported length (reported=%u, actual=%u)",
                                   p_mac_lte_info->length, offset);
        }
    } else {
        /* There is no padding at the end of the frame */
        if (offset < p_mac_lte_info->length) {
            /* There is a problem if we haven't used all of the PDU */
            expert_add_info_format(pinfo, pdu_ti, &ei_mac_lte_context_length,
                                   "SL-SCH PDU for UE %u is shorter than reported length (reported=%u, actual=%d)",
                                   p_mac_lte_info->ueid, p_mac_lte_info->length, offset);
        }

        if (offset > p_mac_lte_info->length) {
            /* There is a problem if the PDU is longer than reported */
            expert_add_info_format(pinfo, pdu_ti, &ei_mac_lte_context_length,
                                   "SL-SCH PDU for UE %u is longer than reported length (reported=%u, actual=%u)",
                                   p_mac_lte_info->ueid, p_mac_lte_info->length, offset);
        }
    }
}


/*****************************/
/* Main dissection function. */
/* 'data' will be cast to an int, where it can then be used to differentiate
   multiple MAC PDUs logged in the same frame (e.g. in the LTE eNB LI API definition from
   the Small Cell Forum)
*/
static int dissect_mac_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree          *mac_lte_tree;
    proto_item          *pdu_ti;
    proto_tree          *context_tree;
    proto_item          *context_ti;
    proto_item          *retx_ti        = NULL;
    proto_item          *ti;
    proto_item          *hidden_root_ti;
    int                  offset         = 0;
    struct mac_lte_info *p_mac_lte_info;
    int                  n;
    unsigned            pdu_instance = GPOINTER_TO_UINT(data);

    /* Allocate and zero tap struct */
    mac_3gpp_tap_info *tap_info = wmem_new0(wmem_file_scope(), mac_3gpp_tap_info);
    tap_info->rat = MAC_RAT_LTE;

    /* Set protocol name */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC-LTE");

    /* Create protocol tree, using tvb_reported_length() as giving -1 will trigger an exception in case of oob event */
    pdu_ti = proto_tree_add_item(tree, proto_mac_lte, tvb, offset, tvb_reported_length(tvb), ENC_NA);
    proto_item_append_text(pdu_ti, " ");
    mac_lte_tree = proto_item_add_subtree(pdu_ti, ett_mac_lte);

    /* Look for packet info! */
    p_mac_lte_info = (mac_lte_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_mac_lte, 0);

    /* Can't dissect anything without it... */
    if (p_mac_lte_info == NULL) {
        proto_tree_add_expert(mac_lte_tree, pinfo, &ei_mac_lte_no_per_frame_data, tvb, offset, -1);
        return 0;
    }

    /* Clear info column */
    col_clear(pinfo->cinfo, COL_INFO);


    /*****************************************/
    /* Show context information              */

    /* Create context root */
    context_ti = proto_tree_add_string_format(mac_lte_tree, hf_mac_lte_context,
                                              tvb, offset, 0, "", "Context");
    context_tree = proto_item_add_subtree(context_ti, ett_mac_lte_context);
    proto_item_set_generated(context_ti);

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_radio_type,
                             tvb, 0, 0, p_mac_lte_info->radioType);
    proto_item_set_generated(ti);

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_direction,
                             tvb, 0, 0, p_mac_lte_info->direction);
    proto_item_set_generated(ti);

    if (p_mac_lte_info->ueid != 0) {
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_ueid,
                                 tvb, 0, 0, p_mac_lte_info->ueid);
        proto_item_set_generated(ti);
    }

    if(p_mac_lte_info->sfnSfInfoPresent) {
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_sysframe_number,
                                 tvb, 0, 0, p_mac_lte_info->sysframeNumber);
        proto_item_set_generated(ti);
        if (p_mac_lte_info->sysframeNumber > 1023) {
            expert_add_info_format(pinfo, ti, &ei_mac_lte_context_sysframe_number,
                                   "Sysframe number (%u) out of range - valid range is 0-1023",
                                   p_mac_lte_info->sysframeNumber);
        }

        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_subframe_number,
                                 tvb, 0, 0, p_mac_lte_info->subframeNumber);
        proto_item_set_generated(ti);
        if (p_mac_lte_info->subframeNumber > 9) {
            /* N.B. if we set it to valid value, it won't trigger when we rescan
               (at least with DCT2000 files where the context struct isn't re-read). */
            expert_add_info_format(pinfo, ti, &ei_mac_lte_context_sysframe_number,
                                   "Subframe number (%u) out of range - valid range is 0-9",
                                   p_mac_lte_info->subframeNumber);
        }

        if (p_mac_lte_info->subframeNumberOfGrantPresent) {
            ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_grant_subframe_number,
                                     tvb, 0, 0, p_mac_lte_info->subframeNumberOfGrant);
            proto_item_set_generated(ti);
        }
    }

    /* There are several out-of-band MAC events that may be indicated in the context info. */
    /* Handle them here */
    if (p_mac_lte_info->length == 0) {
        proto_item *preamble_ti;
        proto_tree *preamble_tree;
        const char *rapid_description;

        switch (p_mac_lte_info->oob_event) {
            case ltemac_send_preamble:
                preamble_ti = proto_tree_add_item(mac_lte_tree, hf_mac_lte_oob_send_preamble,
                                                  tvb, 0, 0, ENC_ASCII);
                preamble_tree = proto_item_add_subtree(preamble_ti, ett_mac_lte_oob);
                proto_item_set_generated(ti);

                ti = proto_tree_add_uint(preamble_tree, hf_mac_lte_context_rapid,
                                         tvb, 0, 0, p_mac_lte_info->rapid);
                proto_item_set_generated(ti);

                ti = proto_tree_add_uint(preamble_tree, hf_mac_lte_context_rach_attempt_number,
                                         tvb, 0, 0, p_mac_lte_info->rach_attempt_number);
                proto_item_set_generated(ti);

                rapid_description = get_mac_lte_rapid_description(p_mac_lte_info->rapid);

                /* Info column */
                write_pdu_label_and_info(pdu_ti, preamble_ti, pinfo,
                                         "RACH Preamble chosen for UE %u (RAPID=%u%s, attempt=%u)",
                                         p_mac_lte_info->ueid, p_mac_lte_info->rapid,
                                         rapid_description,
                                         p_mac_lte_info->rach_attempt_number);

                /* Add expert info (a note, unless attempt > 1) */
                expert_add_info_format(pinfo, ti,
                    (p_mac_lte_info->rach_attempt_number > 1) ? &ei_mac_lte_rach_preamble_sent_warn : &ei_mac_lte_rach_preamble_sent_note,
                                       "RACH Preamble sent for UE %u (RAPID=%u%s, attempt=%u)",
                                       p_mac_lte_info->ueid, p_mac_lte_info->rapid,
                                       rapid_description,
                                       p_mac_lte_info->rach_attempt_number);
                break;
            case ltemac_send_sr:
                    /* Count of SRs */
                    ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_number_of_srs,
                                             tvb, 0, 0, p_mac_lte_info->number_of_srs);
                    proto_item_set_generated(ti);


                for (n=0; n < p_mac_lte_info->number_of_srs; n++) {
                    proto_item *sr_ti;
                    proto_tree *sr_tree;

                    /* SR event is subtree */
                    sr_ti = proto_tree_add_expert_format(mac_lte_tree, pinfo, &ei_mac_lte_oob_send_sr,
                                                tvb, 0, 0,
                                                "Scheduling Request sent for UE %u (RNTI %u)", p_mac_lte_info->oob_ueid[n], p_mac_lte_info->oob_rnti[n]);
                    sr_tree = proto_item_add_subtree(sr_ti, ett_mac_lte_oob);
                    proto_item_set_generated(sr_ti);

                    /* RNTI */
                    ti = proto_tree_add_uint(sr_tree, hf_mac_lte_context_rnti,
                                             tvb, 0, 0, p_mac_lte_info->oob_rnti[n]);
                    proto_item_set_generated(ti);

                    /* UEID */
                    ti = proto_tree_add_uint(sr_tree, hf_mac_lte_context_ueid,
                                             tvb, 0, 0, p_mac_lte_info->oob_ueid[n]);
                    proto_item_set_generated(ti);

                    /* Add summary to root. */
                    proto_item_append_text(sr_ti, " (UE=%u C-RNTI=%u)",
                                           p_mac_lte_info->oob_ueid[n],
                                           p_mac_lte_info->oob_rnti[n]);

                    /* Info column */

                    if(n == 0) {
                        if (p_mac_lte_info->sfnSfInfoPresent) {
                            write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                                    "Scheduling Requests (%u) sent (SFN=%-4u, SF=%u): (UE=%u C-RNTI=%u)",
                                                    p_mac_lte_info->number_of_srs,
                                                    p_mac_lte_info->sysframeNumber,
                                                    p_mac_lte_info->subframeNumber,
                                                    p_mac_lte_info->oob_ueid[n],
                                                    p_mac_lte_info->oob_rnti[n]
                                                    );
                        }
                        else {
                            write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                                    "Scheduling Requests (%u) sent: (UE=%u C-RNTI=%u)",
                                                    p_mac_lte_info->number_of_srs,
                                                    p_mac_lte_info->oob_ueid[n],
                                                    p_mac_lte_info->oob_rnti[n]);
                        }
                    }
                    else {
                        write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                                " (UE=%u C-RNTI=%u)",
                                                p_mac_lte_info->oob_ueid[n],
                                                p_mac_lte_info->oob_rnti[n]);
                    }

                    /* Update SR status for this UE */
                    if (global_mac_lte_track_sr) {
                        TrackSRInfo(SR_Request, pinfo, mac_lte_tree, tvb, p_mac_lte_info, n, sr_ti);
                    }
                }
                break;
            case ltemac_sr_failure:
                ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_rnti,
                                         tvb, 0, 0, p_mac_lte_info->rnti);
                proto_item_set_generated(ti);

                proto_tree_add_expert_format(mac_lte_tree, pinfo, &ei_mac_lte_oob_sr_failure,
                                         tvb, 0, 0, "Scheduling Request failed for UE %u (RNTI %u)",
                                         p_mac_lte_info->ueid, p_mac_lte_info->rnti);
                proto_item_set_generated(ti);

                /* Info column */
                write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                         "Scheduling Request FAILED for UE %u (C-RNTI=%u)",
                                         p_mac_lte_info->ueid,
                                         p_mac_lte_info->rnti);

                /* Update SR status */
                if (global_mac_lte_track_sr) {
                    TrackSRInfo(SR_Failure, pinfo, mac_lte_tree, tvb, p_mac_lte_info, 0, ti);
                }

                break;
        }

        /* Our work here is done */
        return -1;
    }

    /* Show remaining meta information */
    if (p_mac_lte_info->rntiType != NO_RNTI) {
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_rnti,
                                 tvb, 0, 0, p_mac_lte_info->rnti);
        proto_item_set_generated(ti);
        proto_item_append_text(context_ti, " (RNTI=%u)", p_mac_lte_info->rnti);
    }


    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_rnti_type,
                             tvb, 0, 0, p_mac_lte_info->rntiType);
    proto_item_set_generated(ti);

    /* Check that RNTI value is consistent with given RNTI type */
    switch (p_mac_lte_info->rntiType) {
        case M_RNTI:
            if (p_mac_lte_info->rnti != 0xFFFD) {
                expert_add_info_format(pinfo, ti, &ei_mac_lte_context_rnti_type,
                      "M-RNTI indicated, but value is %u (0x%x) (must be 0x%x)",
                      p_mac_lte_info->rnti, p_mac_lte_info->rnti, 0xFFFD);
                return 0;
            }
            break;
        case P_RNTI:
            if (p_mac_lte_info->rnti != 0xFFFE) {
                expert_add_info_format(pinfo, ti, &ei_mac_lte_context_rnti_type,
                      "P-RNTI indicated, but value is %u (0x%x) (must be 0x%x)",
                      p_mac_lte_info->rnti, p_mac_lte_info->rnti, 0xFFFE);
                return 0;
            }
            break;
        case SI_RNTI:
            if (p_mac_lte_info->rnti != 0xFFFF) {
                expert_add_info_format(pinfo, ti, &ei_mac_lte_context_rnti_type,
                      "SI-RNTI indicated, but value is %u (0x%x) (must be 0x%x)",
                      p_mac_lte_info->rnti, p_mac_lte_info->rnti, 0xFFFE);
                return 0;
            }
            break;
        case RA_RNTI:
            if ((p_mac_lte_info->rnti < 0x0001) || (p_mac_lte_info->rnti > 0x0960)) {
                expert_add_info_format(pinfo, ti, &ei_mac_lte_context_rnti_type,
                      "RA_RNTI indicated, but given value %u (0x%x) is out of range",
                      p_mac_lte_info->rnti, p_mac_lte_info->rnti);
                return 0;
            }
            break;
        case C_RNTI:
        case SPS_RNTI:
        case SL_RNTI:
        case G_RNTI:
            if ((p_mac_lte_info->rnti < 0x0001) || (p_mac_lte_info->rnti > 0xFFF3)) {
                expert_add_info_format(pinfo, ti, &ei_mac_lte_context_rnti_type,
                      "%s indicated, but given value %u (0x%x) is out of range",
                      val_to_str_const(p_mac_lte_info->rntiType,  rnti_type_vals, "Unknown"),
                      p_mac_lte_info->rnti, p_mac_lte_info->rnti);
                return 0;
            }
            break;

        default:
            break;
    }

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_predefined_frame,
                             tvb, 0, 0, p_mac_lte_info->isPredefinedData);
    if (p_mac_lte_info->isPredefinedData) {
        proto_item_set_generated(ti);
    }
    else {
        proto_item_set_hidden(ti);
    }

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_length,
                             tvb, 0, 0, p_mac_lte_info->length);
    proto_item_set_generated(ti);
    /* Infer uplink grant size */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_ul_grant_size,
                                 tvb, 0, 0, p_mac_lte_info->length);
        proto_item_set_generated(ti);
    }

    /* Retx count goes in top-level tree to make it more visible */
    if (p_mac_lte_info->reTxCount) {
        proto_item *retx_reason_ti;
        retx_ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_retx_count,
                                 tvb, 0, 0, p_mac_lte_info->reTxCount);
        proto_item_set_generated(retx_ti);

        if (p_mac_lte_info->reTxCount >= global_mac_lte_retx_counter_trigger) {
            if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
                expert_add_info_format(pinfo, retx_ti, &ei_mac_lte_ul_mac_frame_retx,
                                       "UE %u: UL MAC frame ReTX no. %u",
                                       p_mac_lte_info->ueid, p_mac_lte_info->reTxCount);
            }
            else {
                expert_add_info_format(pinfo, retx_ti, &ei_mac_lte_ul_mac_frame_retx,
                                       "UE %u: DL MAC frame ReTX no. %u",
                                       p_mac_lte_info->ueid, p_mac_lte_info->reTxCount);
            }
        }

        retx_reason_ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_retx_reason,
                                             tvb, 0, 0, p_mac_lte_info->isPHICHNACK);
        proto_item_set_generated(retx_reason_ti);
    }

    if (p_mac_lte_info->crcStatusValid) {
        /* Set status */
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_crc_status,
                                 tvb, 0, 0, p_mac_lte_info->crcStatus);
        proto_item_set_generated(ti);

        /* Report non-success */
        if (p_mac_lte_info->crcStatus != crc_success) {
            expert_add_info_format(pinfo, ti, &ei_mac_lte_context_crc_status,
                                   "%s Frame has CRC error problem (%s)",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? "UL" : "DL",
                                   val_to_str_const(p_mac_lte_info->crcStatus,
                                                    crc_status_vals,
                                                    "Unknown"));
            write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                     "%s: <CRC %s> UEId=%u %s=%u ",
                                     (p_mac_lte_info->direction == DIRECTION_UPLINK) ? "UL" : "DL",
                                     val_to_str_const(p_mac_lte_info->crcStatus,
                                                    crc_status_vals,
                                                    "Unknown"),
                                     p_mac_lte_info->ueid,
                                     val_to_str_const(p_mac_lte_info->rntiType, rnti_type_vals,
                                                      "Unknown RNTI type"),
                                     p_mac_lte_info->rnti);
        }
    }

    /* Carrier Id */
    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_carrier_id,
                             tvb, 0, 0, p_mac_lte_info->carrierId);
    proto_item_set_generated(ti);

    /* May also have extra Physical layer attributes set for this frame */
    show_extra_phy_parameters(pinfo, tvb, mac_lte_tree, p_mac_lte_info);

    /* Set context-info parts of tap struct */
    tap_info->rnti = p_mac_lte_info->rnti;
    tap_info->ueid = p_mac_lte_info->ueid;
    tap_info->rntiType = p_mac_lte_info->rntiType;
    tap_info->isPredefinedData = p_mac_lte_info->isPredefinedData;
    tap_info->isPHYRetx = (p_mac_lte_info->reTxCount >= 1);
    tap_info->crcStatusValid = p_mac_lte_info->crcStatusValid;
    tap_info->crcStatus = p_mac_lte_info->crcStatus;
    tap_info->direction = p_mac_lte_info->direction;

    tap_info->mac_time = pinfo->abs_ts;

    /* Add hidden item to filter on */
    if ((p_mac_lte_info->rntiType == C_RNTI) ||
        (p_mac_lte_info->rntiType == SPS_RNTI) ||
        (p_mac_lte_info->rntiType == SC_RNTI) ||
        (p_mac_lte_info->rntiType == G_RNTI)) {
        hidden_root_ti = proto_tree_add_string_format(tree,
                                                      (p_mac_lte_info->direction == DIRECTION_UPLINK) ?
                                                          hf_mac_lte_ulsch :
                                                          hf_mac_lte_dlsch,
                                                      tvb, offset, 0,
                                                      "",
                                                      "Hidden header");
        proto_item_set_hidden(hidden_root_ti);
    } else if (p_mac_lte_info->rntiType == SL_RNTI) {
        hidden_root_ti = proto_tree_add_string_format(tree,
                                                      hf_mac_lte_slsch,
                                                      tvb, offset, 0,
                                                      "",
                                                      "Hidden header");
        proto_item_set_hidden(hidden_root_ti);
    }

    /* Also set total number of bytes (won't be used for UL/DL-SCH) */
    tap_info->single_number_of_bytes = tvb_reported_length_remaining(tvb, offset);

    /* If we know its predefined data, don't try to decode any further */
    if (p_mac_lte_info->isPredefinedData) {
        proto_tree_add_item(mac_lte_tree, hf_mac_lte_predefined_pdu, tvb, offset, -1, ENC_NA);
        write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                 "Predefined data (%u bytes%s)",
                                 p_mac_lte_info->length,
                                 (p_mac_lte_info->length > tvb_reported_length_remaining(tvb, offset) ?
                                     " - truncated" :
                                     ""));

        /* Queue tap info */
        if (!pinfo->flags.in_error_pkt) {
            tap_queue_packet(mac_lte_tap, pinfo, tap_info);
        }

        return -1;
    }

    /* IF CRC status failed, just do decode as raw bytes */
    if (!global_mac_lte_dissect_crc_failures &&
        (p_mac_lte_info->crcStatusValid &&
         (p_mac_lte_info->crcStatus != crc_success))) {

        proto_tree_add_item(mac_lte_tree, hf_mac_lte_raw_pdu, tvb, offset, -1, ENC_NA);
        write_pdu_label_and_info(pdu_ti, NULL, pinfo, "Raw data (%u bytes)", tvb_reported_length_remaining(tvb, offset));

        /* For uplink grants, update SR status.  N.B. only newTx grant should stop SR */
        if ((p_mac_lte_info->direction == DIRECTION_UPLINK) && (p_mac_lte_info->reTxCount == 0) &&
            global_mac_lte_track_sr) {

            TrackSRInfo(SR_Grant, pinfo, tree, tvb, p_mac_lte_info, 0, NULL);
            if (global_mac_lte_show_drx) {
                if (!PINFO_FD_VISITED(pinfo)) {
                    /* Update UE state to this subframe (but before this event is processed) */
                    update_drx_info(pinfo, p_mac_lte_info);

                    /* Store 'before' snapshot of UE state for this frame */
                    set_drx_info(pinfo, p_mac_lte_info, true, pdu_instance);
                }
                /* Show current DRX state in tree as 'before' */
                show_drx_info(pinfo, tree, tvb, p_mac_lte_info, true, pdu_instance);
            }
        }

        /* Queue tap info.
           TODO: unfortunately DL retx detection won't get done if we return here... */
        if (!pinfo->flags.in_error_pkt) {
            tap_queue_packet(mac_lte_tap, pinfo, tap_info);
        }

        return -1;
    }

    /* Reset this counter */
    s_number_of_rlc_pdus_shown = 0;

    /* Dissect the MAC PDU itself. Format depends upon RNTI type. */
    switch (p_mac_lte_info->rntiType) {

        case P_RNTI:
            /* PCH PDU */
            dissect_pch(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info, tap_info);
            break;

        case RA_RNTI:
            /* RAR PDU */
            dissect_rar(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info, tap_info);
            break;

        case C_RNTI:
        case SPS_RNTI:
        case SC_RNTI:
        case G_RNTI:
            /* Can be UL-SCH or DL-SCH */
            dissect_ulsch_or_dlsch(tvb, pinfo, mac_lte_tree, pdu_ti, offset,
                                   p_mac_lte_info, tap_info, retx_ti,
                                   context_tree, pdu_instance);
            break;

        case SI_RNTI:
            /* BCH over DL-SCH */
            dissect_bch(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info);
            break;

        case M_RNTI:
            /* MCH PDU */
            dissect_mch(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info);
            break;

        case SL_BCH_RNTI:
            /* SL BCH PDU */
            dissect_sl_bch(tvb, pinfo, mac_lte_tree, pdu_ti, offset);
            break;

        case SL_RNTI:
            /* SL-SCH PDU */
            dissect_slsch(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info);
            break;

        case NO_RNTI:
            /* Must be BCH over BCH... */
            dissect_bch(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info);
            break;


        default:
            break;
    }

    /* Queue tap info */
    tap_queue_packet(mac_lte_tap, pinfo, tap_info);

    return -1;
}




/* Initializes the hash tables each time a new
 * file is loaded or re-loaded in wireshark */
static void mac_lte_init_protocol(void)
{
    /* Reset structs */
    memset(&UL_tti_info, 0, sizeof(UL_tti_info));
    UL_tti_info.subframe = 0xff;  /* Invalid value */
    memset(&DL_tti_info, 0, sizeof(DL_tti_info));
    DL_tti_info.subframe = 0xff;  /* Invalid value */

    mac_lte_msg3_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    mac_lte_cr_result_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    mac_lte_msg3_cr_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    mac_lte_dl_harq_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    mac_lte_dl_harq_result_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    mac_lte_ul_harq_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    mac_lte_ul_harq_result_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    mac_lte_ue_sr_state = g_hash_table_new(g_direct_hash, g_direct_equal);
    mac_lte_sr_request_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    mac_lte_tti_info_result_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    mac_lte_ue_channels_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    mac_lte_ue_parameters = g_hash_table_new(g_direct_hash, g_direct_equal);
    mac_lte_drx_frame_result = g_hash_table_new(mac_lte_framenum_instance_hash_func, mac_lte_framenum_instance_hash_equal);

    /* Forget this setting */
    s_rapid_ranges_configured = false;
}

static void mac_lte_cleanup_protocol(void)
{
    g_hash_table_destroy(mac_lte_msg3_hash);
    g_hash_table_destroy(mac_lte_cr_result_hash);
    g_hash_table_destroy(mac_lte_msg3_cr_hash);
    g_hash_table_destroy(mac_lte_dl_harq_hash);
    g_hash_table_destroy(mac_lte_dl_harq_result_hash);
    g_hash_table_destroy(mac_lte_ul_harq_hash);
    g_hash_table_destroy(mac_lte_ul_harq_result_hash);
    g_hash_table_destroy(mac_lte_ue_sr_state);
    g_hash_table_destroy(mac_lte_sr_request_hash);
    g_hash_table_destroy(mac_lte_tti_info_result_hash);
    g_hash_table_destroy(mac_lte_ue_channels_hash);
    g_hash_table_destroy(mac_lte_ue_parameters);
    g_hash_table_destroy(mac_lte_drx_frame_result);
}

/* Callback used as part of configuring a channel mapping using UAT */
static void* lcid_drb_mapping_copy_cb(void* dest, const void* orig, size_t len _U_)
{
    const lcid_drb_mapping_t *o = (const lcid_drb_mapping_t *)orig;
    lcid_drb_mapping_t       *d = (lcid_drb_mapping_t *)dest;

    /* Copy all items over */
    d->lcid  = o->lcid;
    d->drbid = o->drbid;
    d->channel_type = o->channel_type;

    return d;
}


/*************************************************************************/
/* These functions get called from outside of this module, i.e. from RRC */

/* Set LCID -> RLC channel mappings from signalling protocol (i.e. RRC or similar). */
void set_mac_lte_channel_mapping(drb_mapping_t *drb_mapping)
{
    ue_dynamic_drb_mappings_t *ue_mappings;
    uint8_t lcid = 0;

    /* Check lcid range */
    if (drb_mapping->lcid_present) {
        lcid = drb_mapping->lcid;

        /* Ignore if LCID is out of range */
        if ((lcid < 3) || (lcid > 10 && lcid < 32) || (lcid > 38)) {
            return;
        }
    }

    /* Look for existing UE entry */
    ue_mappings = (ue_dynamic_drb_mappings_t *)g_hash_table_lookup(mac_lte_ue_channels_hash,
                                                                   GUINT_TO_POINTER((unsigned)drb_mapping->ueid));
    if (!ue_mappings) {
        /* If not found, create & add to table */
        ue_mappings = wmem_new0(wmem_file_scope(), ue_dynamic_drb_mappings_t);
        g_hash_table_insert(mac_lte_ue_channels_hash,
                            GUINT_TO_POINTER((unsigned)drb_mapping->ueid),
                            ue_mappings);
    }

    /* If lcid wasn't supplied, need to try to look up from drbid */
    if ((lcid == 0) && (drb_mapping->drbid < 32)) {
        lcid = ue_mappings->drb_to_lcid_mappings[drb_mapping->drbid];
    }
    if (lcid == 0) {
        /* Still no lcid - give up */
        return;
    }

    /* Set array entry */
    ue_mappings->mapping[lcid].valid = true;
    ue_mappings->mapping[lcid].drbid = drb_mapping->drbid;
    ue_mappings->drb_to_lcid_mappings[drb_mapping->drbid] = lcid;
    if (drb_mapping->ul_priority_present) {
        ue_mappings->mapping[lcid].ul_priority = drb_mapping->ul_priority;
    }

    /* Fill in available RLC info */
    if (drb_mapping->rlcMode_present) {
        switch (drb_mapping->rlcMode) {
            case RLC_AM_MODE:
                if (drb_mapping->rlc_ul_ext_am_sn == true) {
                    if (drb_mapping->rlc_dl_ext_am_sn == true) {
                        if (drb_mapping->rlc_ul_ext_li_field == true) {
                            if (drb_mapping->rlc_dl_ext_li_field == true) {
                                ue_mappings->mapping[lcid].channel_type = rlcAM16extLiField;
                            } else {
                                ue_mappings->mapping[lcid].channel_type = rlcAM16ulExtLiField;
                            }
                        } else {
                            if (drb_mapping->rlc_dl_ext_li_field == true) {
                                ue_mappings->mapping[lcid].channel_type = rlcAM16dlExtLiField;
                            } else {
                                ue_mappings->mapping[lcid].channel_type = rlcAM16;
                            }
                        }
                    } else {
                        if (drb_mapping->rlc_ul_ext_li_field == true) {
                            if (drb_mapping->rlc_dl_ext_li_field == true) {
                                ue_mappings->mapping[lcid].channel_type = rlcAMul16extLiField;
                            } else {
                                ue_mappings->mapping[lcid].channel_type = rlcAMul16ulExtLiField;
                            }
                        } else {
                            if (drb_mapping->rlc_dl_ext_li_field == true) {
                                ue_mappings->mapping[lcid].channel_type = rlcAMul16dlExtLiField;
                            } else {
                                ue_mappings->mapping[lcid].channel_type = rlcAMul16;
                            }
                        }
                    }
                } else if (drb_mapping->rlc_dl_ext_am_sn == true) {
                    if (drb_mapping->rlc_ul_ext_li_field == true) {
                        if (drb_mapping->rlc_dl_ext_li_field == true) {
                            ue_mappings->mapping[lcid].channel_type = rlcAMdl16extLiField;
                        } else {
                            ue_mappings->mapping[lcid].channel_type = rlcAMdl16ulExtLiField;
                        }
                    } else {
                        if (drb_mapping->rlc_dl_ext_li_field == true) {
                            ue_mappings->mapping[lcid].channel_type = rlcAMdl16dlExtLiField;
                        } else {
                            ue_mappings->mapping[lcid].channel_type = rlcAMdl16;
                        }
                    }
                } else if (drb_mapping->rlc_ul_ext_li_field == true) {
                    if (drb_mapping->rlc_dl_ext_li_field == true) {
                        ue_mappings->mapping[lcid].channel_type = rlcAMextLiField;
                    } else {
                        ue_mappings->mapping[lcid].channel_type = rlcAMulExtLiField;
                    }
                } else {
                    if (drb_mapping->rlc_dl_ext_li_field == true) {
                        ue_mappings->mapping[lcid].channel_type = rlcAMdlExtLiField;
                    } else {
                        ue_mappings->mapping[lcid].channel_type = rlcAM;
                    }
                }
                break;
            case RLC_UM_MODE:
                if (drb_mapping->um_sn_length_present) {
                    if (drb_mapping->um_sn_length == 5) {
                        ue_mappings->mapping[lcid].channel_type = rlcUM5;
                    }
                    else {
                        ue_mappings->mapping[lcid].channel_type = rlcUM10;
                    }
                    break;
                }

            default:
                break;
        }
    }
}

/* Return the configured UL priority for the channel */
static uint8_t get_mac_lte_channel_priority(uint16_t ueid, uint8_t lcid,
                                           uint8_t direction)
{
    ue_dynamic_drb_mappings_t *ue_mappings;

    /* Priority only affects UL */
    if (direction == DIRECTION_DOWNLINK) {
        return 0;
    }

    /* Look up the mappings for this UE */
    ue_mappings = (ue_dynamic_drb_mappings_t *)g_hash_table_lookup(mac_lte_ue_channels_hash, GUINT_TO_POINTER((unsigned)ueid));
    if (!ue_mappings) {
        return 0;
    }

    /* Won't report value if channel not configured */
    if (!ue_mappings->mapping[lcid].valid) {
        return 0;
    }
    else {
        return ue_mappings->mapping[lcid].ul_priority;
    }
}

/* Return mode of bearer, or 0 if not found/known */
uint8_t get_mac_lte_channel_mode(uint16_t ueid, uint8_t drbid)
{
    ue_dynamic_drb_mappings_t *ue_mappings;

    /* Look up the mappings for this UE */
    ue_mappings = (ue_dynamic_drb_mappings_t *)g_hash_table_lookup(mac_lte_ue_channels_hash, GUINT_TO_POINTER((unsigned)ueid));
    if (!ue_mappings) {
        return 0;
    }

    if (drbid > 32) {
        return 0;
    }
    /* Need sensible lcid */
    uint8_t lcid = ue_mappings->drb_to_lcid_mappings[drbid];
    if (lcid < 3) {
        /* Not valid */
        return 0;
    }

    /* Lcid needs ot have mapping */
    if (!ue_mappings->mapping[lcid].valid) {
        return 0;
    }
    rlc_channel_type_t channel_type = ue_mappings->mapping[lcid].channel_type;
    /* What mode does the channel type correspond to? */
    if (channel_type >= rlcAM)  {
        return RLC_AM_MODE;
    }
    else {
        return RLC_UM_MODE;
    }
}


/* Configure the DRX state for this UE (from RRC) */
void set_mac_lte_drx_config(uint16_t ueid, drx_config_t *drx_config, packet_info *pinfo)
{
    if (global_mac_lte_show_drx && !PINFO_FD_VISITED(pinfo)) {
        ue_parameters_t *ue_params;
        uint32_t previousFrameNum = 0;

        /* Find or create config struct for this UE */
        ue_params = (ue_parameters_t *)g_hash_table_lookup(mac_lte_ue_parameters, GUINT_TO_POINTER((unsigned)ueid));
        if (ue_params == NULL) {
            ue_params = (ue_parameters_t *)wmem_new0(wmem_file_scope(), ue_parameters_t);
            g_hash_table_insert(mac_lte_ue_parameters, GUINT_TO_POINTER((unsigned)ueid), ue_params);
        }
        else {
            previousFrameNum = ue_params->drx_state.config.frameNum;
        }

        ue_params->drx_state_valid = true;

        /* Clearing state when new config comes in... */
        init_drx_ue_state(&ue_params->drx_state, true);

        /* Copy in new config */
        ue_params->drx_state.config = *drx_config;
        /* Remember frame when current settings set */
        ue_params->drx_state.config.frameNum = pinfo->num;
        /* Also remember any previous config frame number */
        ue_params->drx_state.config.previousFrameNum = previousFrameNum;
    }
}

/* Release DRX config for this UE */
void set_mac_lte_drx_config_release(uint16_t ueid, packet_info *pinfo)
{
    if (global_mac_lte_show_drx && !PINFO_FD_VISITED(pinfo)) {
        ue_parameters_t *ue_params;

        /* Find or create config struct for this UE */
        ue_params = (ue_parameters_t *)g_hash_table_lookup(mac_lte_ue_parameters, GUINT_TO_POINTER((unsigned)ueid));
        if (ue_params != NULL) {
            ue_params->drx_state_valid = false;
        }
    }
}

/* Configure RAPID group sizes from RRC (SIB2).  Note that we currently assume
   that they won't change, i.e. if known we just return the last values we ever
   saw. */
void set_mac_lte_rapid_ranges(unsigned group_A, unsigned all_RA)
{
    s_rapid_ranges_groupA = group_A;
    s_rapid_ranges_RA = all_RA;
    s_rapid_ranges_configured = true;
}

/* Configure the BSR sizes for this UE (from RRC) */
void set_mac_lte_extended_bsr_sizes(uint16_t ueid, bool use_ext_bsr_sizes, packet_info *pinfo)
{
    if (!PINFO_FD_VISITED(pinfo)) {
        ue_parameters_t *ue_params;

        /* Find or create config struct for this UE */
        ue_params = (ue_parameters_t *)g_hash_table_lookup(mac_lte_ue_parameters, GUINT_TO_POINTER((unsigned)ueid));
        if (ue_params == NULL) {
            ue_params = (ue_parameters_t *)wmem_new0(wmem_file_scope(), ue_parameters_t);
            g_hash_table_insert(mac_lte_ue_parameters, GUINT_TO_POINTER((unsigned)ueid), ue_params);
        }

        ue_params->use_ext_bsr_sizes = use_ext_bsr_sizes;
    }
}

/* Configure the simultaneous PUCCH/PUSCH transmission for this UE (from RRC) */
void set_mac_lte_simult_pucch_pusch(uint16_t ueid, simult_pucch_pusch_cell_type cell_type, bool simult_pucch_pusch, packet_info *pinfo)
{
    if (!PINFO_FD_VISITED(pinfo)) {
        ue_parameters_t *ue_params;

        /* Find or create config struct for this UE */
        ue_params = (ue_parameters_t *)g_hash_table_lookup(mac_lte_ue_parameters, GUINT_TO_POINTER((unsigned)ueid));
        if (ue_params == NULL) {
            ue_params = (ue_parameters_t *)wmem_new0(wmem_file_scope(), ue_parameters_t);
            g_hash_table_insert(mac_lte_ue_parameters, GUINT_TO_POINTER((unsigned)ueid), ue_params);
        }

        if (cell_type == SIMULT_PUCCH_PUSCH_PCELL) {
            ue_params->use_simult_pucch_pusch_pcell = simult_pucch_pusch;
        } else {
            ue_params->use_simult_pucch_pusch_pscell = simult_pucch_pusch;
        }
    }
}

/* Function to be called from outside this module (e.g. in a plugin) to get per-packet data */
mac_lte_info *get_mac_lte_proto_data(packet_info *pinfo)
{
    return (mac_lte_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_mac_lte, 0);
}

/* Function to be called from outside this module (e.g. in a plugin) to set per-packet data */
void set_mac_lte_proto_data(packet_info *pinfo, mac_lte_info *p_mac_lte_info)
{
    p_add_proto_data(wmem_file_scope(), pinfo, proto_mac_lte, 0, p_mac_lte_info);
}

void proto_register_mac_lte(void)
{
    static hf_register_info hf[] =
    {
        /**********************************/
        /* Items for decoding context     */
        { &hf_mac_lte_context,
            { "Context",
              "mac-lte.context", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_radio_type,
            { "Radio Type",
              "mac-lte.radio-type", FT_UINT8, BASE_DEC, VALS(radio_type_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_direction,
            { "Direction",
              "mac-lte.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Direction of message", HFILL
            }
        },
        { &hf_mac_lte_context_rnti,
            { "RNTI",
              "mac-lte.rnti", FT_UINT16, BASE_DEC, NULL, 0x0,
              "RNTI associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_rnti_type,
            { "RNTI Type",
              "mac-lte.rnti-type", FT_UINT8, BASE_DEC, VALS(rnti_type_vals), 0x0,
              "Type of RNTI associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_ueid,
            { "UEId",
              "mac-lte.ueid", FT_UINT16, BASE_DEC, NULL, 0x0,
              "User Equipment Identifier associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_sysframe_number,
            { "System Frame Number",
              "mac-lte.sfn", FT_UINT16, BASE_DEC, NULL, 0x0,
              "System Frame Number associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_subframe_number,
            { "Subframe",
              "mac-lte.subframe", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Subframe number associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_grant_subframe_number,
            { "Grant Subframe",
              "mac-lte.grant-subframe", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Subframe when grant for this PDU was received", HFILL
            }
        },
        { &hf_mac_lte_context_predefined_frame,
            { "Predefined frame",
              "mac-lte.is-predefined-frame", FT_UINT8, BASE_DEC, VALS(predefined_frame_vals), 0x0,
              "Predefined test frame (or real MAC PDU)", HFILL
            }
        },
        { &hf_mac_lte_context_length,
            { "Length of frame",
              "mac-lte.length", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Original length of frame (including SDUs and padding)", HFILL
            }
        },
        { &hf_mac_lte_context_ul_grant_size,
            { "Uplink grant size",
              "mac-lte.ul-grant-size", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Uplink grant size (in bytes)", HFILL
            }
        },
        { &hf_mac_lte_context_bch_transport_channel,
            { "Transport channel",
              "mac-lte.bch-transport-channel", FT_UINT8, BASE_DEC, VALS(bch_transport_channel_vals), 0x0,
              "Transport channel BCH data was carried on", HFILL
            }
        },
        { &hf_mac_lte_context_retx_count,
            { "ReTX count",
              "mac-lte.retx-count", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Number of times this PDU has been retransmitted", HFILL
            }
        },
        { &hf_mac_lte_context_retx_reason,
            { "ReTX reason",
              "mac-lte.retx-reason", FT_UINT8, BASE_DEC, VALS(ul_retx_grant_vals), 0x0,
              "Type of UL ReTx grant", HFILL
            }
        },
        { &hf_mac_lte_context_crc_status,
            { "CRC Status",
              "mac-lte.crc-status", FT_UINT8, BASE_DEC, VALS(crc_status_vals), 0x0,
              "CRC Status as reported by PHY", HFILL
            }
        },
        { &hf_mac_lte_context_carrier_id,
            { "Carrier Id",
              "mac-lte.carrier-id", FT_UINT8, BASE_DEC, VALS(carrier_id_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_rapid,
            { "RAPID",
              "mac-lte.preamble-sent.rapid", FT_UINT8, BASE_DEC, NULL, 0x0,
              "RAPID sent in RACH preamble", HFILL
            }
        },
        { &hf_mac_lte_context_rach_attempt_number,
            { "RACH Attempt Number",
              "mac-lte.preamble-sent.attempt", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_mac_lte_ues_ul_per_tti,
            { "UL UE in TTI",
              "mac-lte.ul-tti-count", FT_UINT8, BASE_DEC, NULL, 0x0,
              "In this TTI, this is the nth UL grant", HFILL
            }
        },
        { &hf_mac_lte_ues_dl_per_tti,
            { "DL UE in TTI",
              "mac-lte.dl-tti-count", FT_UINT8, BASE_DEC, NULL, 0x0,
              "In this TTI, this is the nth DL PDU", HFILL
            }
        },


        /* Extra PHY context */
        { &hf_mac_lte_context_phy_ul,
            { "UL PHY attributes",
              "mac-lte.ul-phy", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_modulation_type,
            { "Modulation type",
              "mac-lte.ul-phy.modulation-type", FT_UINT8, BASE_DEC, VALS(modulation_type_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_tbs_index,
            { "TBs Index",
              "mac-lte.ul-phy.tbs-index", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_resource_block_length,
            { "Resource Block Length",
              "mac-lte.ul-phy.resource-block-length", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_resource_block_start,
            { "Resource Block Start",
              "mac-lte.ul-phy.resource-block-start", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_harq_id,
            { "HARQ Id",
              "mac-lte.ul-phy.harq-id", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_ndi,
            { "NDI",
              "mac-lte.ul-phy.ndi", FT_UINT8, BASE_DEC, NULL, 0x0,
              "UL New Data Indicator", HFILL
            }
        },

        { &hf_mac_lte_context_phy_dl,
            { "DL PHY attributes",
              "mac-lte.dl-phy", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_dci_format,
            { "DCI format",
              "mac-lte.dl-phy.dci-format", FT_UINT8, BASE_DEC, VALS(dci_format_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_resource_allocation_type,
            { "Resource Allocation Type",
              "mac-lte.dl-phy.resource-allocation-type", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_aggregation_level,
            { "Aggregation Level",
              "mac-lte.dl-phy.aggregation-level", FT_UINT8, BASE_DEC, VALS(aggregation_level_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_mcs_index,
            { "MCS Index",
              "mac-lte.dl-phy.mcs-index", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_redundancy_version_index,
            { "RV Index",
              "mac-lte.dl-phy.rv-index", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_retx,
            { "DL Retx",
              "mac-lte.dl-phy.dl-retx", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_resource_block_length,
            { "RB Length",
              "mac-lte.dl-phy.rb-length", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_harq_id,
            { "HARQ Id",
              "mac-lte.dl-phy.harq-id", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_ndi,
            { "NDI",
              "mac-lte.dl-phy.ndi", FT_UINT8, BASE_DEC, NULL, 0x0,
              "New Data Indicator", HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_tb,
            { "TB",
              "mac-lte.dl-phy.tb", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Transport Block (antenna #)", HFILL
            }
        },

        /* Out-of-band events */
        { &hf_mac_lte_oob_send_preamble,
            { "PRACH",
              "mac-lte.preamble-sent", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_number_of_srs,
            { "Number of SRs",
              "mac-lte.sr-req.count", FT_UINT32, BASE_DEC, NULL, 0x0,
              "Number of UEs doing SR in this frame", HFILL
            }
        },

        /*******************************************/
        /* MAC shared channel header fields        */
        { &hf_mac_lte_ulsch,
            { "UL-SCH",
              "mac-lte.ulsch", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_ulsch_header,
            { "UL-SCH Header",
              "mac-lte.ulsch.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_dlsch_header,
            { "DL-SCH Header",
              "mac-lte.dlsch.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_dlsch,
            { "DL-SCH",
              "mac-lte.dlsch", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_subheader,
            { "SCH sub-header",
              "mac-lte.sch.subheader", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_mch,
            { "MCH",
              "mac-lte.mch", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_mch_header,
            { "MCH Header",
              "mac-lte.mch.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_mch_subheader,
            { "MCH sub-header",
              "mac-lte.mch.subheader", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_slsch,
            { "SL-SCH",
              "mac-lte.slsch", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_slsch_header,
            { "SL-SCH Header",
              "mac-lte.slsch.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_slsch_subheader,
            { "SL-SCH sub-header",
              "mac-lte.slsch.subheader", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_reserved,
            { "SCH reserved bit",
              "mac-lte.sch.reserved", FT_UINT8, BASE_HEX, NULL, 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_format2,
            { "Format2",
              "mac-lte.sch.format2", FT_BOOLEAN, 8, TFS(&format2_vals), 0x40,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_extended,
            { "Extension",
              "mac-lte.sch.extended", FT_UINT8, BASE_HEX, NULL, 0x20,
              "Extension - i.e. further headers after this one", HFILL
            }
        },
        /* Will be hidden, but useful for bi-directional filtering */
        { &hf_mac_lte_lcid,
            { "LCID",
              "mac-lte.lcid", FT_UINT8, BASE_HEX, NULL, 0x1f,
              "Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_lte_dlsch_lcid,
            { "LCID",
              "mac-lte.dlsch.lcid", FT_UINT8, BASE_HEX, VALS(dlsch_lcid_vals), 0x1f,
              "DL-SCH Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_lte_ulsch_lcid,
            { "LCID",
              "mac-lte.ulsch.lcid", FT_UINT8, BASE_HEX, VALS(ulsch_lcid_vals), 0x1f,
              "UL-SCH Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_lte_sch_reserved2,
            { "SCH reserved bits",
              "mac-lte.sch.reserved2", FT_UINT8, BASE_HEX, NULL, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_elcid,
            { "eLCID",
              "mac-lte.sch.elcid", FT_UINT8, BASE_DEC, NULL, 0x3f,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_format,
            { "Format",
              "mac-lte.sch.format", FT_BOOLEAN, 8, TFS(&format_vals), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_length,
            { "Length",
              "mac-lte.sch.length", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Length of MAC SDU or MAC control element", HFILL
            }
        },
        { &hf_mac_lte_mch_reserved,
            { "MCH reserved bits",
              "mac-lte.mch.reserved", FT_UINT8, BASE_HEX, NULL, 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_mch_format2,
            { "Format2",
              "mac-lte.mch.format2", FT_BOOLEAN, 8, TFS(&format2_vals), 0x40,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_mch_extended,
            { "Extension",
              "mac-lte.mch.extended", FT_UINT8, BASE_HEX, NULL, 0x20,
              "Extension - i.e. further headers after this one", HFILL
            }
        },
        { &hf_mac_lte_mch_lcid,
            { "LCID",
              "mac-lte.mch.lcid", FT_UINT8, BASE_HEX, VALS(mch_lcid_vals), 0x1f,
              "MCH Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_lte_mch_format,
            { "Format",
              "mac-lte.mch.format", FT_BOOLEAN, 8, TFS(&format_vals), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_mch_length,
            { "Length",
              "mac-lte.mch.length", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Length of MAC SDU or MAC control element", HFILL
            }
        },
        { &hf_mac_lte_slsch_version,
            { "Version",
              "mac-lte.slsch.version", FT_UINT8, BASE_DEC, NULL, 0xf0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_slsch_reserved,
            { "Reserved bits",
              "mac-lte.slsch.reserved", FT_UINT8, BASE_HEX, NULL, 0x0f,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_slsch_src_l2_id,
            { "Source Layer-2 ID",
              "mac-lte.slsch.src-l2-id", FT_UINT24, BASE_HEX, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_slsch_dst_l2_id,
            { "Destination Layer-2 ID",
              "mac-lte.slsch.dst-l2-id", FT_UINT16, BASE_HEX, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_slsch_dst_l2_id2,
            { "Destination Layer-2 ID",
              "mac-lte.slsch.dst-l2-id", FT_UINT24, BASE_HEX, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_slsch_reserved2,
            { "Reserved bits",
              "mac-lte.slsch.reserved", FT_UINT8, BASE_HEX, NULL, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_slsch_extended,
            { "Extension",
              "mac-lte.slsch.extended", FT_UINT8, BASE_HEX, NULL, 0x20,
              "Extension - i.e. further headers after this one", HFILL
            }
        },
        { &hf_mac_lte_slsch_lcid,
            { "LCID",
              "mac-lte.slsch.lcid", FT_UINT8, BASE_HEX, VALS(slsch_lcid_vals), 0x1f,
              "SL-SCH Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_lte_slsch_format,
            { "Format",
              "mac-lte.slsch.format", FT_BOOLEAN, 8, TFS(&format_vals), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_slsch_length,
            { "Length",
              "mac-lte.slsch.length", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Length of MAC SDU or MAC control element", HFILL
            }
        },
        { &hf_mac_lte_sch_header_only,
            { "MAC PDU Header only",
              "mac-lte.sch.header-only", FT_UINT8, BASE_DEC, VALS(header_only_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_mch_header_only,
            { "MAC PDU Header only",
              "mac-lte.mch.header-only", FT_UINT8, BASE_DEC, VALS(header_only_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_slsch_header_only,
            { "MAC PDU Header only",
              "mac-lte.slsch.header-only", FT_UINT8, BASE_DEC, VALS(header_only_vals), 0x0,
              NULL, HFILL
            }
        },

        /********************************/
        /* Data                         */
        { &hf_mac_lte_sch_sdu,
            { "SDU",
              "mac-lte.sch.sdu", FT_BYTES, BASE_NONE, NULL, 0x0,
              "Shared channel SDU", HFILL
            }
        },
        { &hf_mac_lte_mch_sdu,
            { "SDU",
              "mac-lte.mch.sdu", FT_BYTES, BASE_NONE, NULL, 0x0,
              "Multicast channel SDU", HFILL
            }
        },
        { &hf_mac_lte_bch_pdu,
            { "BCH PDU",
              "mac-lte.bch.pdu", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_pch_pdu,
            { "PCH PDU",
              "mac-lte.pch.pdu", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_slbch_pdu,
            { "SL-BCH PDU",
              "mac-lte.slbch.pdu", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_slsch_sdu,
            { "SDU",
              "mac-lte.slsch.sdu", FT_BYTES, BASE_NONE, NULL, 0x0,
              "Sidelink shared channel SDU", HFILL
            }
        },
        { &hf_mac_lte_predefined_pdu,
            { "Predefined data",
              "mac-lte.predefined-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              "Predefined test data", HFILL
            }
        },
        { &hf_mac_lte_raw_pdu,
            { "Raw data",
              "mac-lte.raw-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              "Raw bytes of PDU (e.g. if CRC error)", HFILL
            }
        },
        { &hf_mac_lte_padding_data,
            { "Padding data",
              "mac-lte.padding-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_padding_length,
            { "Padding length",
              "mac-lte.padding-length", FT_UINT32, BASE_DEC, NULL, 0x0,
              "Length of padding data not included at end of frame", HFILL
            }
        },



        /*********************************/
        /* RAR fields                    */
        { &hf_mac_lte_rar,
            { "RAR",
              "mac-lte.rar", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_headers,
            { "RAR Headers",
              "mac-lte.rar.headers", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_header,
            { "RAR Header",
              "mac-lte.rar.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_extension,
            { "Extension",
              "mac-lte.rar.e", FT_UINT8, BASE_HEX, NULL, 0x80,
              "Extension - i.e. further RAR headers after this one", HFILL
            }
        },
        { &hf_mac_lte_rar_t,
            { "Type",
              "mac-lte.rar.t", FT_UINT8, BASE_HEX, VALS(rar_type_vals), 0x40,
              "Type field indicating whether the payload is RAPID or BI", HFILL
            }
        },
        { &hf_mac_lte_rar_bi,
            { "BI",
              "mac-lte.rar.bi", FT_UINT8, BASE_HEX, VALS(rar_bi_vals), 0x0f,
              "Backoff Indicator (ms)", HFILL
            }
        },
        { &hf_mac_lte_rar_bi_nb,
            { "BI",
              "mac-lte.rar.bi", FT_UINT8, BASE_HEX, VALS(rar_bi_nb_vals), 0x0f,
              "Backoff Indicator (ms)", HFILL
            }
        },
        { &hf_mac_lte_rar_rapid,
            { "RAPID",
              "mac-lte.rar.rapid", FT_UINT8, BASE_HEX_DEC, NULL, 0x3f,
              "Random Access Preamble IDentifier", HFILL
            }
        },
        { &hf_mac_lte_rar_no_of_rapids,
            { "Number of RAPIDs",
              "mac-lte.rar.no-of-rapids", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Number of RAPIDs in RAR PDU", HFILL
            }
        },
        { &hf_mac_lte_rar_reserved,
            { "Reserved",
              "mac-lte.rar.reserved", FT_UINT8, BASE_HEX, NULL, 0x30,
              "Reserved bits in RAR header - should be 0", HFILL
            }
        },

        { &hf_mac_lte_rar_body,
            { "RAR Body",
              "mac-lte.rar.body", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_reserved2,
            { "Reserved",
              "mac-lte.rar.reserved2", FT_UINT8, BASE_HEX, NULL, 0x80,
              "Reserved bit in RAR body - should be 0", HFILL
            }
        },
        { &hf_mac_lte_rar_ta,
            { "Timing Advance",
              "mac-lte.rar.ta", FT_UINT16, BASE_DEC, NULL, 0x7ff0,
              "Required adjustment to uplink transmission timing", HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_ce_mode_b,
            { "UL Grant",
              "mac-lte.rar.ul-grant", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              "Size of UL Grant", HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant,
            { "UL Grant",
              "mac-lte.rar.ul-grant", FT_UINT24, BASE_DEC, NULL, 0x0fffff,
              "Size of UL Grant", HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_hopping,
            { "Hopping Flag",
              "mac-lte.rar.ul-grant.hopping", FT_UINT8, BASE_DEC, NULL, 0x08,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_fsrba,
            { "Fixed sized resource block assignment",
              "mac-lte.rar.ul-grant.fsrba", FT_UINT16, BASE_DEC, NULL, 0x07fe,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_tmcs,
            { "Truncated Modulation and coding scheme",
              "mac-lte.rar.ul-grant.tmcs", FT_UINT16, BASE_DEC, NULL, 0x01e0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_tcsp,
            { "TPC command for scheduled PUSCH",
              "mac-lte.rar.ul-grant.tcsp", FT_UINT8, BASE_DEC, VALS(rar_ul_grant_tcsp_vals), 0x1c,
              "PUSCH power offset in dB" , HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_ul_delay,
            { "UL Delay",
              "mac-lte.rar.ul-grant.ul-delay", FT_UINT8, BASE_DEC, NULL, 0x02,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_cqi_request,
            { "CQI Request",
              "mac-lte.rar.ul-grant.cqi-request", FT_UINT8, BASE_DEC, NULL, 0x01,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_msg3_pusch_nb_idx_ce_mode_a,
            { "Msg3 PUSCH narrowband index",
              "mac-lte.rar.ul-grant.msg3-pusch-nb-idx", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_msg3_pusch_res_alloc_ce_mode_a,
            { "Msg3 PUSCH Resource allocation",
              "mac-lte.rar.ul-grant.msg3-pusch-res-alloc", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_nb_rep_msg3_pusch_ce_mode_a,
            { "Number of Repetitions for Msg3 PUSCH",
              "mac-lte.rar.ul-grant.nb-rep-msg3-pusch", FT_UINT8, BASE_DEC, VALS(rar_ul_grant_nb_rep_msg3_pusch_ce_mode_a_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_mcs_ce_mode_a,
            { "MCS",
              "mac-lte.rar.ul-grant.mcs", FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_tpc_ce_mode_a,
            { "TPC",
              "mac-lte.rar.ul-grant.tpc", FT_UINT8, BASE_DEC, VALS(rar_ul_grant_tcsp_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_csi_request_ce_mode_a,
            { "CSI request",
              "mac-lte.rar.ul-grant.csi-request", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_ul_delay_ce_mode_a,
            { "UL delay",
              "mac-lte.rar.ul-grant.ul-delay", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_msg3_msg4_mpdcch_nb_idx,
            { "Msg3/4 MPDCCH narrowband index",
              "mac-lte.rar.ul-grant.msg3-msg4-mpdcch-nb-idx", FT_UINT8, BASE_DEC, VALS(rar_ul_grant_msg3_msg4_mpdcch_nb_idx_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_padding_ce_mode_a,
            { "Padding",
              "mac-lte.rar.ul-grant.padding", FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_msg3_pusch_nb_idx_ce_mode_b,
            { "Msg3 PUSCH narrowband index",
              "mac-lte.rar.ul-grant.msg3-pusch-nb-idx", FT_UINT8, BASE_DEC, VALS(rar_ul_grant_msg3_pusch_nb_idx_ce_mode_b_vals), 0x0c,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_msg3_pusch_res_alloc_ce_mode_b,
            { "Msg3 PUSCH resource allocation",
              "mac-lte.rar.ul-grant.msg3-pusch-res-alloc", FT_UINT16, BASE_DEC, NULL, 0x0380,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_nb_rep_msg3_pusch_ce_mode_b,
            { "Number of Repetitions for Msg3 PUSCH",
              "mac-lte.rar.ul-grant.nb-rep-msg3-pusch", FT_UINT8, BASE_DEC, VALS(rar_ul_grant_nb_rep_msg3_pusch_ce_mode_b_vals), 0x70,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_tbs_ce_mode_b,
            { "TBS",
              "mac-lte.rar.ul-grant.tbs", FT_UINT8, BASE_DEC, NULL, 0x0c,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_ul_subcarrier_spacing,
            { "Uplink subcarrier spacing",
              "mac-lte.rar.ul-grant.ul-subcarrier-spacing", FT_BOOLEAN, 8, TFS(&ul_subcarrier_spacing_val), 0x08,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_subcarrier_indication,
            { "Subcarrier indication",
              "mac-lte.rar.ul-grant.subcarrier-indication", FT_UINT16, BASE_DEC, NULL, 0x07e0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_scheduling_delay,
            { "Scheduling delay",
              "mac-lte.rar.ul-grant.scheduling-delay", FT_UINT8, BASE_DEC, VALS(scheduling_delay_vals), 0x18,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_msg3_repetition_number,
            { "Msg3 repetition number",
              "mac-lte.rar.ul-grant.msg3-repetition-number", FT_UINT8, BASE_DEC, VALS(msg3_rep_nb_vals), 0x07,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_mcs_index,
            { "MCS index",
              "mac-lte.rar.ul-grant.mcs-index", FT_UINT8, BASE_DEC, NULL, 0xe0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_padding_nb_mode,
            { "Padding",
              "mac-lte.rar.ul-grant.padding", FT_UINT8, BASE_HEX, NULL, 0x1f,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_temporary_crnti,
            { "Temporary C-RNTI",
              "mac-lte.rar.temporary-crnti", FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },

        /**********************/
        /* Control PDU fields */
        { &hf_mac_lte_control_bsr,
            { "BSR",
              "mac-lte.control.bsr", FT_STRING, BASE_NONE, NULL, 0x0,
              "Buffer Status Report", HFILL
            }
        },
        { &hf_mac_lte_control_bsr_lcg_id,
            { "Logical Channel Group ID",
              "mac-lte.control.bsr.lcg-id", FT_UINT8, BASE_DEC, NULL, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_short_bsr_buffer_size,
            { "Buffer Size",
              "mac-lte.control.bsr.buffer-size", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_vals_ext, 0x3f,
              "Buffer Size available in all channels in group", HFILL
            }
        },
        { &hf_mac_lte_control_long_bsr_buffer_size_0,
            { "Buffer Size 0",
              "mac-lte.control.bsr.buffer-size-0", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_vals_ext, 0xfc,
              "Buffer Size available in logical channel group 0", HFILL
            }
        },
        { &hf_mac_lte_control_long_bsr_buffer_size_1,
            { "Buffer Size 1",
              "mac-lte.control.bsr.buffer-size-1", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &buffer_size_vals_ext, 0x03f0,
              "Buffer Size available in logical channel group 1", HFILL
            }
        },
        { &hf_mac_lte_control_long_bsr_buffer_size_2,
            { "Buffer Size 2",
              "mac-lte.control.bsr.buffer-size-2", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &buffer_size_vals_ext, 0x0fc0,
              "Buffer Size available in logical channel group 2", HFILL
            }
        },
        { &hf_mac_lte_control_long_bsr_buffer_size_3,
            { "Buffer Size 3",
              "mac-lte.control.bsr.buffer-size-3", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_vals_ext, 0x3f,
              "Buffer Size available in logical channel group 3", HFILL
            }
        },
        { &hf_mac_lte_control_short_ext_bsr_buffer_size,
            { "Buffer Size",
              "mac-lte.control.bsr.buffer-size", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ext_buffer_size_vals_ext, 0x3f,
              "Buffer Size available in all channels in group", HFILL
            }
        },
        { &hf_mac_lte_control_long_ext_bsr_buffer_size_0,
            { "Buffer Size 0",
              "mac-lte.control.bsr.buffer-size-0", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ext_buffer_size_vals_ext, 0xfc,
              "Buffer Size available in logical channel group 0", HFILL
            }
        },
        { &hf_mac_lte_control_long_ext_bsr_buffer_size_1,
            { "Buffer Size 1",
              "mac-lte.control.bsr.buffer-size-1", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &ext_buffer_size_vals_ext, 0x03f0,
              "Buffer Size available in logical channel group 1", HFILL
            }
        },
        { &hf_mac_lte_control_long_ext_bsr_buffer_size_2,
            { "Buffer Size 2",
              "mac-lte.control.bsr.buffer-size-2", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &ext_buffer_size_vals_ext, 0x0fc0,
              "Buffer Size available in logical channel group 2", HFILL
            }
        },
        { &hf_mac_lte_control_long_ext_bsr_buffer_size_3,
            { "Buffer Size 3",
              "mac-lte.control.bsr.buffer-size-3", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ext_buffer_size_vals_ext, 0x3f,
              "Buffer Size available in logical channel group 3", HFILL
            }
        },
        { &hf_mac_lte_bsr_size_median,
            { "Buffer Size Median",
              "mac-lte.control.bsr.buffer-size-median", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_crnti,
            { "C-RNTI",
              "mac-lte.control.crnti", FT_UINT16, BASE_DEC, NULL, 0x0,
              "C-RNTI for the UE", HFILL
            }
        },
        { &hf_mac_lte_control_timing_advance,
            { "Timing Advance",
              "mac-lte.control.timing-advance", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_timing_advance_group_id,
            { "Timing Advance Group Identity",
              "mac-lte.control.timing-advance.group-id", FT_UINT8, BASE_DEC, NULL, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_timing_advance_command,
            { "Timing Advance Command",
              "mac-lte.control.timing-advance.command", FT_UINT8, BASE_DEC, NULL, 0x3f,
              "Timing Advance (0-63 - see 36.213, 4.2.3)", HFILL
            }
        },
        { &hf_mac_lte_control_timing_advance_value_reserved,
            { "Reserved",
              "mac-lte.control.reserved", FT_UINT16, BASE_DEC, NULL, 0xc000,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_timing_advance_value,
            { "Timing Advance",
              "mac-lte.control.timing-advance-value", FT_UINT16, BASE_DEC, NULL, 0x3fff,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_as_rai,
            { "AS RAI",
              "mac-lte.control.as-rai", FT_UINT8, BASE_DEC, VALS(as_rai_vals), 0xc0,
              "Access Stratum Release Assistance Indication", HFILL
            }
        },
        { &hf_mac_lte_control_as_rai_reserved,
            { "Reserved",
              "mac-lte.control.as-rai.reserved", FT_UINT8, BASE_DEC, NULL, 0x30,
              NULL, HFILL
            }
        },
        /* TODO: vals from 36.133.  Would need separate vals/field for NB-IoT UE? */
        { &hf_mac_lte_control_as_rai_quality_report,
            { "Quality Report",
              "mac-lte.control.as-rai.quality-report", FT_UINT8, BASE_DEC, NULL, 0x0f,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution,
            { "UE Contention Resolution",
              "mac-lte.control.ue-contention-resolution", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution_identity,
            { "UE Contention Resolution Identity",
              "mac-lte.control.ue-contention-resolution.identity", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution_msg3,
            { "Msg3",
              "mac-lte.control.ue-contention-resolution.msg3", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution_msg3_matched,
            { "UE Contention Resolution Matches Msg3",
              "mac-lte.control.ue-contention-resolution.matches-msg3", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution_time_since_msg3,
            { "Time since Msg3",
              "mac-lte.control.ue-contention-resolution.time-since-msg3", FT_UINT32, BASE_DEC, NULL, 0x0,
              "Time in ms since corresponding Msg3", HFILL
            }
        },
        { &hf_mac_lte_control_msg3_to_cr,
            { "CR response",
              "mac-lte.msg3-cr-response", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
              NULL, HFILL
            }
        },

        { &hf_mac_lte_control_power_headroom,
            { "Power Headroom Report",
              "mac-lte.control.power-headroom", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_power_headroom_reserved,
            { "Reserved",
              "mac-lte.control.power-headroom.reserved", FT_UINT8, BASE_DEC, NULL, 0xc0,
              "Reserved bits, should be 0", HFILL
            }
        },
        { &hf_mac_lte_control_power_headroom_level,
            { "Power Headroom Level",
              "mac-lte.control.power-headroom.level", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
               &power_headroom_vals_ext, 0x3f, "Power Headroom Level in dB", HFILL
            }
        },

        { &hf_mac_lte_control_dual_conn_power_headroom,
            { "Dual Connectivity Power Headroom Report",
              "mac-lte.control.dual-conn-power-headroom", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c7,
            { "SCell Index 7 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c7", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c6,
            { "SCell Index 6 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c6", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c5,
            { "SCell Index 5 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c5", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c4,
            { "SCell Index 4 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c4", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c3,
            { "SCell Index 3 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c3", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c2,
            { "SCell Index 2 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c2", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c1,
            { "SCell Index 1 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c1", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c15,
            { "SCell Index 15 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c15", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c14,
            { "SCell Index 14 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c14", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c13,
            { "SCell Index 13 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c13", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c12,
            { "SCell Index 12 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c12", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c11,
            { "SCell Index 11 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c11", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c10,
            { "SCell Index 10 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c10", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c9,
            { "SCell Index 9 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c9", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c8,
            { "SCell Index 8 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c8", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x01, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c23,
            { "SCell Index 23 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c23", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c22,
            { "SCell Index 22 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c22", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c21,
            { "SCell Index 21 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c21", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c20,
            { "SCell Index 20 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c20", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c19,
            { "SCell Index 19 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c19", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c18,
            { "SCell Index 18 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c18", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c17,
            { "SCell Index 17 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c17", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c16,
            { "SCell Index 16 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c16", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x01, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c31,
            { "SCell Index 31 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c31", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c30,
            { "SCell Index 30 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c30", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c29,
            { "SCell Index 29 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c29", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c28,
            { "SCell Index 28 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c28", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c27,
            { "SCell Index 27 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c27", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c26,
            { "SCell Index 26 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c26", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c25,
            { "SCell Index 25 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c25", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_c24,
            { "SCell Index 24 Power Headroom",
              "mac-lte.control.dual-conn-power-headroom.c24", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x01, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_reserved,
            { "Reserved",
              "mac-lte.control.dual-conn-power-headroom.reserved", FT_UINT8, BASE_DEC,
              NULL, 0x01, "Reserved bit, should be 0", HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_power_backoff,
            { "Power Backoff",
              "mac-lte.control.dual-conn-power-headroom.power-backoff", FT_BOOLEAN, 8,
               TFS(&power_backoff_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_value,
            { "Power Headroom Value",
              "mac-lte.control.dual-conn-power-headroom.value", FT_BOOLEAN, 8,
               TFS(&ph_value_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_level,
            { "Power Headroom Level",
              "mac-lte.control.dual-conn-power-headroom.level", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
               &power_headroom_vals_ext, 0x3f, "Power Headroom Level in dB", HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_reserved2,
            { "Reserved",
              "mac-lte.control.dual-conn-power-headroom.reserved2", FT_UINT8, BASE_DEC,
              NULL, 0xc0, "Reserved bits, should be 0", HFILL
            }
        },
        { &hf_mac_lte_control_dual_conn_power_headroom_pcmaxc,
            { "Configured UE Transmit Power",
              "mac-lte.control.ext-power-headroom.pcmaxc", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
               &pcmaxc_vals_ext, 0x3f, "Pcmax,c in dBm", HFILL
            }
        },

        { &hf_mac_lte_control_ext_power_headroom,
            { "Extended Power Headroom Report",
              "mac-lte.control.ext-power-headroom", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ext_power_headroom_c7,
            { "SCell Index 7 Power Headroom",
              "mac-lte.control.ext-power-headroom.c7", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ext_power_headroom_c6,
            { "SCell Index 6 Power Headroom",
              "mac-lte.control.ext-power-headroom.c6", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ext_power_headroom_c5,
            { "SCell Index 5 Power Headroom",
              "mac-lte.control.ext-power-headroom.c5", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ext_power_headroom_c4,
            { "SCell Index 4 Power Headroom",
              "mac-lte.control.ext-power-headroom.c4", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ext_power_headroom_c3,
            { "SCell Index 3 Power Headroom",
              "mac-lte.control.ext-power-headroom.c3", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ext_power_headroom_c2,
            { "SCell Index 2 Power Headroom",
              "mac-lte.control.ext-power-headroom.c2", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ext_power_headroom_c1,
            { "SCell Index 1 Power Headroom",
              "mac-lte.control.ext-power-headroom.c1", FT_BOOLEAN, 8,
              TFS(&scell_ph_tfs), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ext_power_headroom_reserved,
            { "Reserved",
              "mac-lte.control.ext-power-headroom.reserved", FT_UINT8, BASE_DEC,
              NULL, 0x01, "Reserved bit, should be 0", HFILL
            }
        },
        { &hf_mac_lte_control_ext_power_headroom_power_backoff,
            { "Power Backoff",
              "mac-lte.control.ext-power-headroom.power-backoff", FT_BOOLEAN, 8,
               TFS(&power_backoff_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ext_power_headroom_value,
            { "Power Headroom Value",
              "mac-lte.control.ext-power-headroom.value", FT_BOOLEAN, 8,
               TFS(&ph_value_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ext_power_headroom_level,
            { "Power Headroom Level",
              "mac-lte.control.ext-power-headroom.level", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
               &power_headroom_vals_ext, 0x3f, "Power Headroom Level in dB", HFILL
            }
        },
        { &hf_mac_lte_control_ext_power_headroom_reserved2,
            { "Reserved",
              "mac-lte.control.ext-power-headroom.reserved2", FT_UINT8, BASE_DEC,
              NULL, 0xc0, "Reserved bits, should be 0", HFILL
            }
        },
        { &hf_mac_lte_control_ext_power_headroom_pcmaxc,
            { "Configured UE Transmit Power",
              "mac-lte.control.ext-power-headroom.pcmaxc", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
               &pcmaxc_vals_ext, 0x3f, "Pcmax,c in dBm", HFILL
            }
        },

        { &hf_mac_lte_control_activation_deactivation,
            { "Activation/Deactivation",
              "mac-lte.control.activation-deactivation", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c7,
            { "SCell Index 7 Status",
              "mac-lte.control.activation-deactivation.c7", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c6,
            { "SCell Index 6 Status",
              "mac-lte.control.activation-deactivation.c6", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c5,
            { "SCell Index 5 Status",
              "mac-lte.control.activation-deactivation.c5", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c4,
            { "SCell Index 4 Status",
              "mac-lte.control.activation-deactivation.c4", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c3,
            { "SCell Index 3 Status",
              "mac-lte.control.activation-deactivation.c3", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c2,
            { "SCell Index 2 Status",
              "mac-lte.control.activation-deactivation.c2", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c1,
            { "SCell Index 1 Status",
              "mac-lte.control.activation-deactivation.c1", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_reserved,
            { "Reserved",
              "mac-lte.control.activation-deactivation.reserved", FT_UINT8, BASE_DEC,
              NULL, 0x01, "Reserved bit, should be 0", HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c15,
            { "SCell Index 15 Status",
              "mac-lte.control.activation-deactivation.c15", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c14,
            { "SCell Index 14 Status",
              "mac-lte.control.activation-deactivation.c14", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c13,
            { "SCell Index 13 Status",
              "mac-lte.control.activation-deactivation.c13", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c12,
            { "SCell Index 12 Status",
              "mac-lte.control.activation-deactivation.c12", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c11,
            { "SCell Index 11 Status",
              "mac-lte.control.activation-deactivation.c11", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c10,
            { "SCell Index 10 Status",
              "mac-lte.control.activation-deactivation.c10", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c9,
            { "SCell Index 9 Status",
              "mac-lte.control.activation-deactivation.c9", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c8,
            { "SCell Index 8 Status",
              "mac-lte.control.activation-deactivation.c8", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x01, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c23,
            { "SCell Index 23 Status",
              "mac-lte.control.activation-deactivation.c23", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c22,
            { "SCell Index 22 Status",
              "mac-lte.control.activation-deactivation.c22", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c21,
            { "SCell Index 21 Status",
              "mac-lte.control.activation-deactivation.c21", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c20,
            { "SCell Index 20 Status",
              "mac-lte.control.activation-deactivation.c20", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c19,
            { "SCell Index 19 Status",
              "mac-lte.control.activation-deactivation.c19", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c18,
            { "SCell Index 18 Status",
              "mac-lte.control.activation-deactivation.c18", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c17,
            { "SCell Index 17 Status",
              "mac-lte.control.activation-deactivation.c17", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c16,
            { "SCell Index 16 Status",
              "mac-lte.control.activation-deactivation.c16", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x01, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c31,
            { "SCell Index 31 Status",
              "mac-lte.control.activation-deactivation.c31", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c30,
            { "SCell Index 30 Status",
              "mac-lte.control.activation-deactivation.c30", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c29,
            { "SCell Index 29 Status",
              "mac-lte.control.activation-deactivation.c29", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c28,
            { "SCell Index 28 Status",
              "mac-lte.control.activation-deactivation.c28", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c27,
            { "SCell Index 27 Status",
              "mac-lte.control.activation-deactivation.c27", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c26,
            { "SCell Index 26 Status",
              "mac-lte.control.activation-deactivation.c26", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c25,
            { "SCell Index 25 Status",
              "mac-lte.control.activation-deactivation.c25", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_c24,
            { "SCell Index 24 Status",
              "mac-lte.control.activation-deactivation.c24", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x01, NULL, HFILL
            }
        },

        { &hf_mac_lte_control_mch_scheduling_info,
            { "MCH Scheduling Information",
              "mac-lte.control.mch_scheduling_info", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_mch_scheduling_info_lcid,
            { "LCID",
              "mac-lte.control.mch_scheduling_info.lcid", FT_UINT8, BASE_HEX, VALS(mch_lcid_vals), 0xf8,
              "Logical Channel ID of the MTCH", HFILL
            }
        },
        { &hf_mac_lte_control_mch_scheduling_info_stop_mtch,
            { "Stop MTCH",
              "mac-lte.control.mch_scheduling_info.stop_mtch", FT_UINT16, BASE_DEC, NULL, 0x07ff,
              "Ordinal number of the subframe where the corresponding MTCH stops", HFILL
            }
        },

        { &hf_mac_lte_control_sidelink_bsr,
            { "Sidelink BSR",
              "mac-lte.control.sidelink-bsr", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_sidelink_bsr_destination_idx_odd,
            { "Destination Index",
              "mac-lte.control.sidelink-bsr.destination-idx", FT_UINT8, BASE_DEC, NULL, 0xf0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_sidelink_bsr_lcg_id_odd,
            { "Logical Channel Group ID",
              "mac-lte.control.sidelink-bsr.lcg-id", FT_UINT8, BASE_DEC, NULL, 0x0c,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_sidelink_bsr_buffer_size_odd,
            { "Buffer Size",
              "mac-lte.control.sidelink-bsr.buffer-size", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &buffer_size_vals_ext, 0x03f0,
              "Buffer Size available in all channels in group", HFILL
            }
        },
        { &hf_mac_lte_control_sidelink_bsr_destination_idx_even,
            { "Destination Index",
              "mac-lte.control.sidelink-bsr.destination-idx", FT_UINT8, BASE_DEC, NULL, 0x0f,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_sidelink_bsr_lcg_id_even,
            { "Logical Channel Group ID",
              "mac-lte.control.sidelink-bsr.lcg-id", FT_UINT8, BASE_DEC, NULL, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_sidelink_bsr_buffer_size_even,
            { "Buffer Size",
              "mac-lte.control.sidelink-bsr.buffer-size", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &buffer_size_vals_ext, 0x3f,
              "Buffer Size available in all channels in group", HFILL
            }
        },
        { &hf_mac_lte_control_sidelink_reserved,
            { "Reserved",
              "mac-lte.control.sidelink-bsr.reserved", FT_UINT8, BASE_DEC,
              NULL, 0x0f, "Reserved bits, should be 0", HFILL
            }
        },

        { &hf_mac_lte_control_data_vol_power_headroom,
            { "Data Volume and Power Headroom Report",
              "mac-lte.control.data-vol-power-headroom", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_data_vol_power_headroom_reserved,
            { "Reserved",
              "mac-lte.control.data-vol-power-headroom.reserved", FT_UINT8, BASE_DEC,
              NULL, 0xc0, "Reserved bits, should be 0", HFILL
            }
        },
        { &hf_mac_lte_control_data_vol_power_headroom_level,
            { "Power Headroom Level",
              "mac-lte.control.data-vol-power-headroom.level", FT_UINT8, BASE_DEC,
              VALS(data_vol_power_headroom_level_vals), 0x30, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_data_vol_power_headroom_level_4_bits,
            { "Power Headroom Level",
              "mac-lte.control.data-vol-power-headroom.level", FT_UINT8, BASE_DEC,
              VALS(data_vol_extended_power_headroom_level_vals), 0xf0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_data_vol_power_headroom_data_vol,
            { "Data Volume",
              "mac-lte.control.data-vol-power-headroom.data-vol", FT_UINT8, BASE_DEC,
              VALS(data_vol_power_headroom_data_vol_vals), 0x0f, NULL, HFILL
            }
        },

        { &hf_mac_lte_control_recommended_bit_rate,
            { "Recommended Bit Rate",
              "mac-lte.control.recommended-bit-rate", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_recommended_bit_rate_lcid,
            { "LCID",
              "mac-lte.control.recommended-bit-rate.lcid", FT_UINT8, BASE_DEC,
              NULL, 0xf0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_recommended_bit_rate_dir,
            { "Direction",
              "mac-lte.control.recommended-bit-rate.dir", FT_BOOLEAN, 8,
              TFS(&tfs_uplink_downlink), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_recommended_bit_rate_bit_rate,
            { "Bit Rate",
              "mac-lte.control.recommended-bit-rate.bit-rate", FT_UINT16, BASE_DEC|BASE_EXT_STRING,
              &bit_rate_vals_ext, 0x07e0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_recommended_bit_rate_reserved,
            { "Reserved",
              "mac-lte.control.recommended-bit-rate.reserved", FT_UINT8, BASE_HEX,
              NULL, 0x1f, "Reserved bits, should be 0", HFILL
            }
        },

        { &hf_mac_lte_control_recommended_bit_rate_query,
            { "Recommended Bit Rate Query",
              "mac-lte.control.recommended-bit-rate-query", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_recommended_bit_rate_query_lcid,
            { "LCID",
              "mac-lte.control.recommended-bit-rate-query.lcid", FT_UINT8, BASE_DEC,
              NULL, 0xf0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_recommended_bit_rate_query_dir,
            { "Direction",
              "mac-lte.control.recommended-bit-rate-query.dir", FT_BOOLEAN, 8,
              TFS(&tfs_uplink_downlink), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_recommended_bit_rate_query_bit_rate,
            { "Bit Rate",
              "mac-lte.control.recommended-bit-rate-query.bit-rate", FT_UINT16, BASE_DEC|BASE_EXT_STRING,
              &bit_rate_vals_ext, 0x07e0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_recommended_bit_rate_query_reserved,
            { "Reserved",
              "mac-lte.control.recommended-bit-rate-query.reserved", FT_UINT8, BASE_HEX,
              NULL, 0x1f, "Reserved bits, should be 0", HFILL
            }
        },

        { &hf_mac_lte_control_activation_deactivation_csi_rs,
            { "Activation/Deactivation of CSI-RS",
              "mac-lte.control.activation-deactivation-csi-rs", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_csi_rs_a8,
            { "CSI-RS Resource Index 8",
              "mac-lte.control.activation-deactivation-csi-rs.a8", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_csi_rs_a7,
            { "CSI-RS Resource Index 7",
              "mac-lte.control.activation-deactivation-csi-rs.a7", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_csi_rs_a6,
            { "CSI-RS Resource Index 6",
              "mac-lte.control.activation-deactivation-csi-rs.a6", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_csi_rs_a5,
            { "CSI-RS Resource Index 5",
              "mac-lte.control.activation-deactivation-csi-rs.a5", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_csi_rs_a4,
            { "CSI-RS Resource Index 4",
              "mac-lte.control.activation-deactivation-csi-rs.a4", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_csi_rs_a3,
            { "CSI-RS Resource Index 3",
              "mac-lte.control.activation-deactivation-csi-rs.a3", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_csi_rs_a2,
            { "CSI-RS Resource Index 2",
              "mac-lte.control.activation-deactivation-csi-rs.a2", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_csi_rs_a1,
            { "CSI-RS Resource Index 1",
              "mac-lte.control.activation-deactivation-csi-rs.a1", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x01, NULL, HFILL
            }
        },

        { &hf_mac_lte_control_activation_deactivation_pdcp_dup,
            { "Activation/Deactivation of PDCP Duplication",
              "mac-lte.control.activation-deactivation-pdcp-dup", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_pdcp_dup_d8,
            { "PDCP Duplication for 8th established DRB",
              "mac-lte.control.activation-deactivation-pdcp-dup.d8", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_pdcp_dup_d7,
            { "PDCP Duplication for 7th established DRB",
              "mac-lte.control.activation-deactivation-pdcp-dup.d7", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_pdcp_dup_d6,
            { "PDCP Duplication for 6th established DRB",
              "mac-lte.control.activation-deactivation-pdcp-dup.d6", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_pdcp_dup_d5,
            { "PDCP Duplication for 5th established DRB",
              "mac-lte.control.activation-deactivation-pdcp-dup.d5", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_pdcp_dup_d4,
            { "PDCP Duplication for 4th established DRB",
              "mac-lte.control.activation-deactivation-pdcp-dup.d4", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_pdcp_dup_d3,
            { "PDCP Duplication for 3rd established DRB",
              "mac-lte.control.activation-deactivation-pdcp-dup.d3", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_pdcp_dup_d2,
            { "PDCP Duplication for 2nd established DRB",
              "mac-lte.control.activation-deactivation-pdcp-dup.d2", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_activation_deactivation_pdcp_dup_d1,
            { "PDCP Duplication for 1st established DRB",
              "mac-lte.control.activation-deactivation-pdcp-dup.d1", FT_BOOLEAN, 8,
              TFS(&tfs_activated_deactivated), 0x01, NULL, HFILL
            }
        },

        { &hf_mac_lte_control_hibernation,
            { "Hibernation",
              "mac-lte.control.hibernation", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c7,
            { "C7",
              "mac-lte.control.hibernation.c7", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c6,
            { "C6",
              "mac-lte.control.hibernation.c6", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c5,
            { "C5",
              "mac-lte.control.hibernation.c5", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c4,
            { "C4",
              "mac-lte.control.hibernation.c4", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c3,
            { "C3",
              "mac-lte.control.hibernation.c3", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c2,
            { "C2",
              "mac-lte.control.hibernation.c2", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c1,
            { "C1",
              "mac-lte.control.hibernation.c1", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_reserved,
            { "Reserved",
              "mac-lte.control.hibernation.reserved", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x01, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c15,
            { "C15",
              "mac-lte.control.hibernation.c15", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c14,
            { "C14",
              "mac-lte.control.hibernation.c14", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c13,
            { "C13",
              "mac-lte.control.hibernation.c13", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c12,
            { "C12",
              "mac-lte.control.hibernation.c12", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c11,
            { "C11",
              "mac-lte.control.hibernation.c11", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c10,
            { "C10",
              "mac-lte.control.hibernation.c10", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c9,
            { "C9",
              "mac-lte.control.hibernation.c9", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c8,
            { "C8",
              "mac-lte.control.hibernation.c8", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x01, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c23,
            { "C23",
              "mac-lte.control.hibernation.c23", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c22,
            { "C22",
              "mac-lte.control.hibernation.c22", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c21,
            { "C21",
              "mac-lte.control.hibernation.c21", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c20,
            { "C20",
              "mac-lte.control.hibernation.c20", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c19,
            { "C19",
              "mac-lte.control.hibernation.c19", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c18,
            { "C18",
              "mac-lte.control.hibernation.c18", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c17,
            { "C17",
              "mac-lte.control.hibernation.c17", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c16,
            { "C16",
              "mac-lte.control.hibernation.c16", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x01, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c31,
            { "C31",
              "mac-lte.control.hibernation.c31", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c30,
            { "C30",
              "mac-lte.control.hibernation.c30", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c29,
            { "C29",
              "mac-lte.control.hibernation.c29", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c28,
            { "C28",
              "mac-lte.control.hibernation.c28", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c27,
            { "C27",
              "mac-lte.control.hibernation.c27", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c26,
            { "C26",
              "mac-lte.control.hibernation.c26", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c25,
            { "C25",
              "mac-lte.control.hibernation.c25", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_hibernation_c24,
            { "C24",
              "mac-lte.control.hibernation.c24", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x01, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation,
            { "AUL confirmation",
              "mac-lte.control.aul-confirmation", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c7,
            { "C7",
              "mac-lte.control.aul-confirmation.c7", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c6,
            { "C6",
              "mac-lte.control.aul-confirmation.c6", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c5,
            { "C5",
              "mac-lte.control.aul-confirmation.c5", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c4,
            { "C4",
              "mac-lte.control.aul-confirmation.c4", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c3,
            { "C3",
              "mac-lte.control.aul-confirmation.c3", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c2,
            { "C2",
              "mac-lte.control.aul-confirmation.c2", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c1,
            { "C1",
              "mac-lte.control.aul-confirmation.c1", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_reserved,
            { "Reserved",
              "mac-lte.control.aul-confirmation.reserved", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x01, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c15,
            { "C15",
              "mac-lte.control.aul-confirmation.c15", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c14,
            { "C14",
              "mac-lte.control.aul-confirmation.c14", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c13,
            { "C13",
              "mac-lte.control.aul-confirmation.c13", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c12,
            { "C12",
              "mac-lte.control.aul-confirmation.c12", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c11,
            { "C11",
              "mac-lte.control.aul-confirmation.c11", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c10,
            { "C10",
              "mac-lte.control.aul-confirmation.c10", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c9,
            { "C9",
              "mac-lte.control.aul-confirmation.c9", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c8,
            { "C8",
              "mac-lte.control.aul-confirmation.c8", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x01, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c23,
            { "C23",
              "mac-lte.control.aul-confirmation.c23", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c22,
            { "C22",
              "mac-lte.control.aul-confirmation.c22", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c21,
            { "C21",
              "mac-lte.control.aul-confirmation.c21", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c20,
            { "C20",
              "mac-lte.control.aul-confirmation.c20", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c19,
            { "C19",
              "mac-lte.control.aul-confirmation.c19", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c18,
            { "C18",
              "mac-lte.control.aul-confirmation.c18", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c17,
            { "C17",
              "mac-lte.control.aul-confirmation.c17", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c16,
            { "C16",
              "mac-lte.control.aul-confirmation.c16", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x01, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c31,
            { "C31",
              "mac-lte.control.aul-confirmation.c31", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x80, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c30,
            { "C30",
              "mac-lte.control.aul-confirmation.c30", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x40, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c29,
            { "C29",
              "mac-lte.control.aul-confirmation.c29", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x20, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c28,
            { "C28",
              "mac-lte.control.aul-confirmation.c28", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x10, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c27,
            { "C27",
              "mac-lte.control.aul-confirmation.c27", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x08, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c26,
            { "C26",
              "mac-lte.control.aul-confirmation.c26", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x04, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c25,
            { "C25",
              "mac-lte.control.aul-confirmation.c25", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x02, NULL, HFILL
            }
        },
        { &hf_mac_lte_control_aul_confirmation_c24,
            { "C24",
              "mac-lte.control.aul-confirmation.c24", FT_BOOLEAN, 8,
              TFS(&dormant_activate_tfs), 0x01, NULL, HFILL
            }
        },

        /* Generated fields */
        { &hf_mac_lte_dl_harq_resend_original_frame,
            { "Frame with previous tx",
              "mac-lte.dlsch.retx.original-frame", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RETRANS_PREV), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_dl_harq_resend_time_since_previous_frame,
            { "Time since previous tx (ms)",
              "mac-lte.dlsch.retx.time-since-previous", FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_dl_harq_resend_next_frame,
            { "Frame with next tx",
              "mac-lte.dlsch.retx.next-frame", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RETRANS_NEXT), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_dl_harq_resend_time_until_next_frame,
            { "Time until next tx (ms)",
              "mac-lte.dlsch.retx.time-until-next", FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_mac_lte_ul_harq_resend_original_frame,
            { "Frame with previous tx",
              "mac-lte.ulsch.retx.original-frame", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RETRANS_PREV), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_ul_harq_resend_time_since_previous_frame,
            { "Time since previous tx (ms)",
              "mac-lte.ulsch.retx.time-since-previous", FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_ul_harq_resend_next_frame,
            { "Frame with next tx",
              "mac-lte.ulsch.retx.next-frame", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RETRANS_NEXT), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_ul_harq_resend_time_until_next_frame,
            { "Time until next tx (ms)",
              "mac-lte.ulsch.retx.time-until-next", FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_mac_lte_grant_answering_sr,
            { "First Grant Following SR from",
              "mac-lte.ulsch.grant-answering-sr", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_failure_answering_sr,
            { "SR which failed",
              "mac-lte.ulsch.failure-answering-sr", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_leading_to_failure,
            { "This SR fails",
              "mac-lte.ulsch.failure-answering-sr-frame", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_leading_to_grant,
            { "This SR results in a grant here",
              "mac-lte.ulsch.grant-answering-sr-frame", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_time_since_request,
            { "Time since SR (ms)",
              "mac-lte.ulsch.time-since-sr", FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_time_until_answer,
            { "Time until answer (ms)",
              "mac-lte.ulsch.time-until-sr-answer", FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_mac_lte_drx_config,
            { "DRX Configuration",
              "mac-lte.drx-config", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_config_frame_num,
            { "Config Frame",
              "mac-lte.drx-config.config-frame", FT_FRAMENUM, BASE_NONE,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_config_previous_frame_num,
            { "Previous Config Frame",
              "mac-lte.drx-config.previous-config-frame", FT_FRAMENUM, BASE_NONE,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_config_long_cycle,
            { "Long cycle",
              "mac-lte.drx-config.long-cycle", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_config_cycle_offset,
            { "Cycle offset",
              "mac-lte.drx-config.cycle-offset", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_config_onduration_timer,
            { "OnDuration Timer",
              "mac-lte.drx-config.onduration-timer", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_config_inactivity_timer,
            { "Inactivity Timer",
              "mac-lte.drx-config.inactivity-timer", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_config_retransmission_timer,
            { "Retransmission Timer",
              "mac-lte.drx-config.retransmission-timer", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_config_short_cycle,
            { "Short cycle",
              "mac-lte.drx-config.short-cycle", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_config_short_cycle_timer,
            { "Short cycle Timer",
              "mac-lte.drx-config.short-cycle-timer", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },

        { &hf_mac_lte_drx_state,
            { "DRX State",
              "mac-lte.drx-state", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_state_long_cycle_offset,
            { "Long cycle offset",
              "mac-lte.drx-state.long-cycle-offset", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_state_short_cycle_offset,
            { "Short cycle offset",
              "mac-lte.drx-state.short-cycle-offset", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_state_inactivity_remaining,
            { "Inactivity remaining",
              "mac-lte.drx-state.inactivity-remaining", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_state_onduration_remaining,
            { "Onduration remaining",
              "mac-lte.drx-state.onduration-remaining", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_state_retransmission_remaining,
            { "Retransmission remaining",
              "mac-lte.drx-state.retransmission-remaining", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_state_rtt_remaining,
            { "RTT remaining",
              "mac-lte.drx-state.rtt-remaining", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_mac_lte_drx_state_short_cycle_remaining,
            { "Short-cycle timer remaining",
              "mac-lte.drx-state.short-cycle-remaining", FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
    };

    static int *ett[] =
    {
        &ett_mac_lte,
        &ett_mac_lte_context,
        &ett_mac_lte_phy_context,
        &ett_mac_lte_rar_headers,
        &ett_mac_lte_rar_header,
        &ett_mac_lte_rar_body,
        &ett_mac_lte_rar_ul_grant,
        &ett_mac_lte_ulsch_header,
        &ett_mac_lte_dlsch_header,
        &ett_mac_lte_mch_header,
        &ett_mac_lte_sch_subheader,
        &ett_mac_lte_mch_subheader,
        &ett_mac_lte_slsch_header,
        &ett_mac_lte_slsch_subheader,
        &ett_mac_lte_bch,
        &ett_mac_lte_bsr,
        &ett_mac_lte_pch,
        &ett_mac_lte_activation_deactivation,
        &ett_mac_lte_contention_resolution,
        &ett_mac_lte_timing_advance,
        &ett_mac_lte_power_headroom,
        &ett_mac_lte_dual_conn_power_headroom,
        &ett_mac_lte_dual_conn_power_headroom_cell,
        &ett_mac_lte_extended_power_headroom,
        &ett_mac_lte_extended_power_headroom_cell,
        &ett_mac_lte_mch_scheduling_info,
        &ett_mac_lte_oob,
        &ett_mac_lte_drx_config,
        &ett_mac_lte_drx_state,
        &ett_mac_lte_sidelink_bsr,
        &ett_mac_lte_data_vol_power_headroom,
        &ett_mac_lte_recommended_bit_rate,
        &ett_mac_lte_recommended_bit_rate_query,
        &ett_mac_lte_activation_deactivation_csi_rs,
        &ett_mac_lte_activation_deactivation_pdcp_dup,
        &ett_mac_lte_hibernation,
        &ett_mac_lte_aul_confirmation
    };

    static ei_register_info ei[] = {
        { &ei_mac_lte_reserved_not_zero, { "mac-lte.reserved-not-zero", PI_MALFORMED, PI_ERROR, "Reserved bit not zero", EXPFILL }},
        { &ei_mac_lte_rar_timing_advance_not_zero_note, { "mac-lte.rar.ta.not-zero", PI_SEQUENCE, PI_NOTE, "RAR Timing advance not zero", EXPFILL }},
        { &ei_mac_lte_rar_timing_advance_not_zero_warn, { "mac-lte.rar.ta.not-zero", PI_SEQUENCE, PI_WARN, "RAR Timing advance not zero", EXPFILL }},
        { &ei_mac_lte_rar_bi_present, { "mac-lte.rar.bi.present", PI_MALFORMED, PI_ERROR, "MAC RAR PDU has > 1 Backoff Indicator subheader present", EXPFILL }},
        { &ei_mac_lte_rar_bi_not_first_subheader, { "mac-lte.rar.bi.not-first-subheader", PI_MALFORMED, PI_WARN, "Backoff Indicator must appear as first subheader", EXPFILL }},
        { &ei_mac_lte_bch_pdu, { "mac-lte.bch.pdu.uplink", PI_MALFORMED, PI_ERROR, "BCH data should not be received in Uplink!", EXPFILL }},
        { &ei_mac_lte_pch_pdu, { "mac-lte.pch.pdu.uplink", PI_MALFORMED, PI_ERROR, "PCH data should not be received in Uplink!", EXPFILL }},
        { &ei_mac_lte_orig_tx_ul_frame_not_found, { "mac-lte.orig-tx-ul-frame-not-found", PI_SEQUENCE, PI_ERROR, "Original Tx of UL frame not found", EXPFILL }},
        { &ei_mac_lte_ul_harq_resend_next_frame, { "mac-lte.ulsch.retx.next-frame.expert", PI_SEQUENCE, PI_WARN, "UL MAC PDU needed to be retransmitted", EXPFILL }},
        { &ei_mac_lte_sr_results_not_grant_or_failure_indication, { "mac-lte.sr_results-not-grant-or-failure-indication", PI_SEQUENCE, PI_ERROR, "SR results in neither a grant nor a failure indication", EXPFILL }},
        { &ei_mac_lte_sr_invalid_event, { "mac-lte.ulsch.sr-invalid-event", PI_SEQUENCE, PI_ERROR, "Invalid SR event for UE", EXPFILL }},
        { &ei_mac_lte_dlsch_lcid, { "mac-lte.dlsch.lcid.DRX-received", PI_SEQUENCE, PI_NOTE, "DRX command received for UE", EXPFILL }},
        { &ei_mac_lte_control_subheader_after_data_subheader, { "mac-lte.control-subheader-after-data-subheader", PI_MALFORMED, PI_ERROR, "?L-SCH Control subheaders should not appear after data subheaders", EXPFILL }},
        { &ei_mac_lte_control_bsr_multiple, { "mac-lte.control.bsr.multiple", PI_MALFORMED, PI_ERROR, "There shouldn't be > 1 BSR in a frame", EXPFILL }},
        { &ei_mac_lte_padding_data_multiple, { "mac-lte.padding-data.multiple", PI_MALFORMED, PI_WARN, "Should not see more than 2 padding subheaders in one frame", EXPFILL }},
        { &ei_mac_lte_padding_data_before_control_subheader, { "mac-lte.padding-data.before-control-subheader", PI_MALFORMED, PI_ERROR, "Padding should come before other control subheaders!", EXPFILL }},
        { &ei_mac_lte_padding_data_start_and_end, { "mac-lte.padding-data.start-and-end", PI_MALFORMED, PI_ERROR, "Padding subheaders at start and end!", EXPFILL }},
        { &ei_mac_lte_lcid_unexpected, { "mac-lte.lcid-unexpected", PI_MALFORMED, PI_ERROR, "?L-SCH: Unexpected LCID received", EXPFILL }},
        { &ei_mac_lte_too_many_subheaders, { "mac-lte.too-many-subheaders", PI_MALFORMED, PI_ERROR, "Reached too many subheaders - frame obviously malformed", EXPFILL }},
        { &ei_mac_lte_control_ue_contention_resolution_msg3_matched, { "mac-lte.control.ue-contention-resolution.matches-msg3.not", PI_SEQUENCE, PI_WARN, "CR body in Msg4 doesn't match Msg3 CCCH in frame X", EXPFILL }},
        { &ei_mac_lte_control_timing_advance_command_no_correction, { "mac-lte.control.timing-advance.command.no-correction", PI_SEQUENCE, PI_NOTE, "Timing Advance control element received (no correction needed)", EXPFILL }},
        { &ei_mac_lte_control_timing_advance_command_correction_needed, { "mac-lte.control.timing-advance.correction-needed", PI_SEQUENCE, PI_WARN, "Timing Advance control element received with correction needed", EXPFILL }},
        { &ei_mac_lte_control_element_size_invalid, { "mac-lte.control-element.size-invalid", PI_MALFORMED, PI_ERROR, "Control Element has an unexpected size", EXPFILL }},
        { &ei_mac_lte_bsr_warn_threshold_exceeded, { "mac-lte.bsr-warn-threshold-exceeded", PI_SEQUENCE, PI_WARN, "BSR for LCG X exceeds threshold", EXPFILL }},
        { &ei_mac_lte_sch_header_only_truncated, { "mac-lte.sch.header-only-truncated", PI_SEQUENCE, PI_NOTE, "MAC PDU SDUs have been omitted", EXPFILL }},
        { &ei_mac_lte_mch_header_only_truncated, { "mac-lte.mch.header-only-truncated", PI_SEQUENCE, PI_NOTE, "MAC PDU SDUs have been omitted", EXPFILL }},
        { &ei_mac_lte_slsch_header_only_truncated, { "mac-lte.slsch.header-only-truncated", PI_SEQUENCE, PI_NOTE, "MAC PDU SDUs have been omitted", EXPFILL }},
        { &ei_mac_lte_context_length, { "mac-lte.length.invalid", PI_MALFORMED, PI_ERROR, "MAC PDU is longer than reported length", EXPFILL }},
        { &ei_mac_lte_rach_preamble_sent_warn, { "mac-lte.rach-preamble-sent", PI_SEQUENCE, PI_WARN, "RACH Preamble sent", EXPFILL }},
        { &ei_mac_lte_rach_preamble_sent_note, { "mac-lte.rach-preamble-sent", PI_SEQUENCE, PI_NOTE, "RACH Preamble sent", EXPFILL }},
        { &ei_mac_lte_oob_send_sr, { "mac-lte.sr-req", PI_SEQUENCE, PI_NOTE, "Scheduling Request sent", EXPFILL }},
        { &ei_mac_lte_oob_sr_failure, { "mac-lte.sr-failure", PI_SEQUENCE, PI_ERROR, "Scheduling Request failed", EXPFILL }},
        { &ei_mac_lte_context_sysframe_number, { "mac-lte.sfn.out-of-range", PI_MALFORMED, PI_ERROR, "Sysframe number out of range", EXPFILL }},
        { &ei_mac_lte_context_rnti_type, { "mac-lte.rnti-type.invalid", PI_MALFORMED, PI_ERROR, "RNTI indicated, but value is not correct", EXPFILL }},
        { &ei_mac_lte_ul_mac_frame_retx, { "mac-lte.ul-mac-frame-retx", PI_SEQUENCE, PI_WARN, "UL MAC frame ReTX", EXPFILL }},
        { &ei_mac_lte_context_crc_status, { "mac-lte.crc-status.error", PI_MALFORMED, PI_ERROR, "Frame has CRC error problem", EXPFILL }},
        { &ei_mac_lte_no_per_frame_data, { "mac-lte.no_per_frame_data", PI_UNDECODED, PI_WARN, "Can't dissect LTE MAC frame because no per-frame info was attached!", EXPFILL }},
        { &ei_mac_lte_sch_invalid_length, { "mac-lte.sch.invalid-length", PI_MALFORMED, PI_WARN, "Invalid PDU length (should be >= 32768)", EXPFILL }},
        { &ei_mac_lte_mch_invalid_length, { "mac-lte.mch.invalid-length", PI_MALFORMED, PI_WARN, "Invalid PDU length (should be >= 32768)", EXPFILL }},
        { &ei_mac_lte_invalid_sc_mcch_sc_mtch_subheader_multiplexing, { "mac-lte.mch.invalid-sc-mcch-sc-mtch-subheader-multiplexing", PI_MALFORMED, PI_ERROR, "SC-MCCH/SC-MTCH header multiplexed with non padding", EXPFILL }},
        { &ei_mac_lte_unknown_udp_framing_tag, { "mac-lte.unknown-udp-framing-tag", PI_UNDECODED, PI_WARN, "Unknown UDP framing tag, aborting dissection", EXPFILL }}
    };

    static const enum_val_t show_info_col_vals[] = {
        {"show-phy", "PHY Info", ShowPHYLayer},
        {"show-mac", "MAC Info", ShowMACLayer},
        {"show-rlc", "RLC Info", ShowRLCLayer},
        {NULL, NULL, -1}
    };

    static const enum_val_t lcid_drb_source_vals[] = {
        {"from-static-stable",          "From static table",           FromStaticTable},
        {"from-configuration-protocol", "From configuration protocol", FromConfigurationProtocol},
        {NULL, NULL, -1}
    };


    module_t *mac_lte_module;
    expert_module_t* expert_mac_lte;

    static uat_field_t lcid_drb_mapping_flds[] = {
        UAT_FLD_VS(lcid_drb_mappings, lcid, "lcid", drb_lcid_vals, "The MAC LCID"),
        UAT_FLD_DEC(lcid_drb_mappings, drbid,"drb id (1-32)", "Identifier of logical data channel"),
        UAT_FLD_VS(lcid_drb_mappings, channel_type, "RLC Channel Type", rlc_channel_type_vals, "The MAC LCID"),
        UAT_END_FIELDS
    };

    /* Register protocol. */
    proto_mac_lte = proto_register_protocol("MAC-LTE", "MAC-LTE", "mac-lte");
    proto_register_field_array(proto_mac_lte, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mac_lte = expert_register_protocol(proto_mac_lte);
    expert_register_field_array(expert_mac_lte, ei, array_length(ei));

    /* Allow other dissectors to find this one by name. */
    register_dissector("mac-lte", dissect_mac_lte, proto_mac_lte);

    /* Register the tap name */
    mac_lte_tap = register_tap("mac-3gpp");

    /* Preferences */
    mac_lte_module = prefs_register_protocol(proto_mac_lte, NULL);

    /* Obsolete preferences */
    prefs_register_obsolete_preference(mac_lte_module, "single_rar");
    prefs_register_obsolete_preference(mac_lte_module, "check_reserved_bits");
    prefs_register_obsolete_preference(mac_lte_module, "decode_rar_ul_grant");
    prefs_register_obsolete_preference(mac_lte_module, "show_rlc_info_column");
    prefs_register_obsolete_preference(mac_lte_module, "attempt_to_detect_dl_harq_resend");
    prefs_register_obsolete_preference(mac_lte_module, "attempt_to_track_ul_harq_resend");

    prefs_register_uint_preference(mac_lte_module, "retx_count_warn",
        "Number of Re-Transmits before expert warning triggered",
        "Number of Re-Transmits before expert warning triggered",
        10, &global_mac_lte_retx_counter_trigger);

    prefs_register_bool_preference(mac_lte_module, "attempt_rrc_decode",
        "Attempt to decode BCH, PCH and CCCH data using LTE RRC dissector",
        "Attempt to decode BCH, PCH and CCCH data using LTE RRC dissector",
        &global_mac_lte_attempt_rrc_decode);

    prefs_register_bool_preference(mac_lte_module, "attempt_to_dissect_crc_failures",
        "Dissect frames that have failed CRC check",
        "Attempt to dissect frames that have failed CRC check",
        &global_mac_lte_dissect_crc_failures);

    prefs_register_obsolete_preference(mac_lte_module, "heuristic_mac_lte_over_udp");

    prefs_register_bool_preference(mac_lte_module, "attempt_to_dissect_srb_sdus",
        "Attempt to dissect LCID 1&2 as srb1&2",
        "Will call LTE RLC dissector with standard settings as per RRC spec",
        &global_mac_lte_attempt_srb_decode);

    prefs_register_bool_preference(mac_lte_module, "attempt_to_dissect_mcch",
        "Attempt to dissect MCH LCID 0 as MCCH",
        "Will call LTE RLC dissector for MCH LCID 0",
        &global_mac_lte_attempt_mcch_decode);

    prefs_register_bool_preference(mac_lte_module, "call_rlc_for_mtch",
        "Call RLC dissector MTCH LCIDs",
        "Call RLC dissector MTCH LCIDs",
        &global_mac_lte_call_rlc_for_mtch);

    prefs_register_enum_preference(mac_lte_module, "lcid_to_drb_mapping_source",
        "Source of LCID -> drb channel settings",
        "Set whether LCID -> drb Table is taken from static table (below) or from "
        "info learned from control protocol (e.g. RRC)",
        &global_mac_lte_lcid_drb_source, lcid_drb_source_vals, false);

    lcid_drb_mappings_uat = uat_new("Static LCID -> drb Table",
                                    sizeof(lcid_drb_mapping_t),
                                    "drb_logchans",
                                    true,
                                    &lcid_drb_mappings,
                                    &num_lcid_drb_mappings,
                                    UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
                                    "",  /* TODO: is this ref to help manual? */
                                    lcid_drb_mapping_copy_cb,
                                    NULL,
                                    NULL,
                                    NULL,
                                    NULL,
                                    lcid_drb_mapping_flds );

    prefs_register_uat_preference(mac_lte_module,
                                  "drb_table",
                                  "LCID -> DRB Mappings Table",
                                  "A table that maps from configurable lcids -> RLC logical channels",
                                  lcid_drb_mappings_uat);

    prefs_register_uint_preference(mac_lte_module, "bsr_warn_threshold",
        "BSR size when warning should be issued (0 - 63)",
        "If any BSR report is >= this number, an expert warning will be added",
        10, &global_mac_lte_bsr_warn_threshold);

    prefs_register_bool_preference(mac_lte_module, "track_sr",
        "Track status of SRs within UEs",
        "Track status of SRs, providing links between requests, failure indications and grants",
        &global_mac_lte_track_sr);

    prefs_register_enum_preference(mac_lte_module, "layer_to_show",
        "Which layer info to show in Info column",
        "Can show PHY, MAC or RLC layer info in Info column",
        &global_mac_lte_layer_to_show, show_info_col_vals, false);

    prefs_register_bool_preference(mac_lte_module, "decode_cr_body",
        "Decode CR body as UL CCCH",
        "Attempt to decode 6 bytes of Contention Resolution body as an UL CCCH PDU",
        &global_mac_lte_decode_cr_body);

    prefs_register_bool_preference(mac_lte_module, "show_drx",
        "Show DRX Information (Incomplete/experimental!)",
        "Apply DRX config and show DRX state within each UE",
        &global_mac_lte_show_drx);

    prefs_register_bool_preference(mac_lte_module, "show_bsr_median",
        "Show BSR Median value",
        "Add as a generated field the middle of the range indicated by the BSR index",
        &global_mac_lte_show_BSR_median);

    register_init_routine(&mac_lte_init_protocol);
    register_cleanup_routine(&mac_lte_cleanup_protocol);
}

void proto_reg_handoff_mac_lte(void)
{
    /* Add as a heuristic UDP dissector */
    heur_dissector_add("udp", dissect_mac_lte_heur, "MAC-LTE over UDP", "mac_lte_udp", proto_mac_lte, HEURISTIC_DISABLE);

    rlc_lte_handle = find_dissector_add_dependency("rlc-lte", proto_mac_lte);
    lte_rrc_bcch_dl_sch_handle = find_dissector_add_dependency("lte_rrc.bcch_dl_sch", proto_mac_lte);
    lte_rrc_bcch_dl_sch_br_handle = find_dissector_add_dependency("lte_rrc.bcch_dl_sch_br", proto_mac_lte);
    lte_rrc_bcch_dl_sch_nb_handle = find_dissector_add_dependency("lte_rrc.bcch_dl_sch.nb", proto_mac_lte);
    lte_rrc_bcch_bch_handle = find_dissector_add_dependency("lte_rrc.bcch_bch", proto_mac_lte);
    lte_rrc_bcch_bch_nb_handle = find_dissector_add_dependency("lte_rrc.bcch_bch.nb", proto_mac_lte);
    lte_rrc_pcch_handle = find_dissector_add_dependency("lte_rrc.pcch", proto_mac_lte);
    lte_rrc_pcch_nb_handle = find_dissector_add_dependency("lte_rrc.pcch.nb", proto_mac_lte);
    lte_rrc_ul_ccch_handle = find_dissector_add_dependency("lte_rrc.ul_ccch", proto_mac_lte);
    lte_rrc_ul_ccch_nb_handle = find_dissector_add_dependency("lte_rrc.ul_ccch.nb", proto_mac_lte);
    lte_rrc_dl_ccch_handle = find_dissector_add_dependency("lte_rrc.dl_ccch", proto_mac_lte);
    lte_rrc_dl_ccch_nb_handle = find_dissector_add_dependency("lte_rrc.dl_ccch.nb", proto_mac_lte);
    lte_rrc_sbcch_sl_bch_handle = find_dissector_add_dependency("lte_rrc.sbcch_sl_bch", proto_mac_lte);
    lte_rrc_sc_mcch_handle = find_dissector_add_dependency("lte_rrc.sc_mcch", proto_mac_lte);
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
