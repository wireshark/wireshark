/* packet-dect-nr.c
 *
 * Routines for DECT NR+ MAC layer, and DLC and Convergence layers
 *  - ETSI TS 103 636-4 V1.6.1 (2025-07)
 *  - ETSI TS 103 636-5 V1.6.1 (2025-07)
 *
 * Copyright 2025, Stig Bjørlykke <stig@bjorlykke.org>
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
#include <epan/unit_strings.h>
#include <epan/tfs.h>
#include <epan/reassemble.h>
#include <wiretap/wtap.h>

static int proto_dect_nr;

/* 6.2: Physical Header Field */
static int hf_dect_nr_phf;
static int hf_dect_nr_header_format_type1;
static int hf_dect_nr_header_format_type2;
static int hf_dect_nr_len_type;
static int hf_dect_nr_packet_len_slots;
static int hf_dect_nr_packet_len_subslots;
static int hf_dect_nr_short_nw_id;
static int hf_dect_nr_transmitter_id;
static int hf_dect_nr_tx_pwr;
static int hf_dect_nr_res1;
static int hf_dect_nr_df_mcs_t1;
static int hf_dect_nr_df_mcs_t2;
static int hf_dect_nr_receiver_id;
static int hf_dect_nr_spatial_streams;
static int hf_dect_nr_df_red_version;
static int hf_dect_nr_df_ind;
static int hf_dect_nr_df_harq_proc;
static int hf_dect_nr_res1_hdr_format_001;
static int hf_dect_nr_fb_format;
static int hf_dect_nr_fbi1_harq_pn;
static int hf_dect_nr_fbi1_tx_fb;
static int hf_dect_nr_fbi1_bs;
static int hf_dect_nr_fbi1_cqi;
static int hf_dect_nr_fbi2_cb_index;
static int hf_dect_nr_fbi2_mimo_fb;
static int hf_dect_nr_fbi2_bs;
static int hf_dect_nr_fbi2_cqi;
static int hf_dect_nr_fbi3_harq_pn_1;
static int hf_dect_nr_fbi3_tx_fb_1;
static int hf_dect_nr_fbi3_harq_pn_2;
static int hf_dect_nr_fbi3_tx_fb_2;
static int hf_dect_nr_fbi3_cqi;
static int hf_dect_nr_fbi4_harq_fb_bm;
static int hf_dect_nr_fbi4_cqi;
static int hf_dect_nr_fbi5_harq_pn;
static int hf_dect_nr_fbi5_tx_fb;
static int hf_dect_nr_fbi5_mimo_fb;
static int hf_dect_nr_fbi5_cb_index;
static int hf_dect_nr_fbi6_harq_pn;
static int hf_dect_nr_fbi6_res1;
static int hf_dect_nr_fbi6_bs;
static int hf_dect_nr_fbi6_cqi;
static int hf_dect_nr_fb_info;
static int hf_dect_nr_phf_padding;

/* 6.3: MAC PDU */
static int hf_dect_nr_mac_pdu;
static int hf_dect_nr_mac_version;
static int hf_dect_nr_mac_security;
static int hf_dect_nr_mac_hdr_type;

/* 6.3.3.1: Data MAC PDU Header */
static int hf_dect_nr_data_hdr;
static int hf_dect_nr_data_hdr_res1;
static int hf_dect_nr_data_hdr_reset;
static int hf_dect_nr_data_hdr_sn;

/* 6.3.3.2: Beacon Header */
static int hf_dect_nr_bc_hdr;
static int hf_dect_nr_bc_hdr_nw_id;
static int hf_dect_nr_bc_hdr_tx_addr;

/* 6.3.3.3: Unicast Header */
static int hf_dect_nr_uc_hdr;
static int hf_dect_nr_uc_hdr_res1;
static int hf_dect_nr_uc_hdr_rst;
static int hf_dect_nr_uc_hdr_mac_seq;
static int hf_dect_nr_uc_hdr_sn;
static int hf_dect_nr_uc_hdr_rx_addr;
static int hf_dect_nr_uc_hdr_tx_addr;

/* 6.3.3.4: RD Broadcasting Header */
static int hf_dect_nr_rdbh_hdr;
static int hf_dect_nr_rdbh_hdr_res1;
static int hf_dect_nr_rdbh_hdr_reset;
static int hf_dect_nr_rdbh_hdr_sn;
static int hf_dect_nr_rdbh_hdr_tx_addr;

/* 6.3.4: MAC Multiplexing Header */
static int hf_dect_nr_mux_hdr;
static int hf_dect_nr_mux_mac_ext;
static int hf_dect_nr_mux_len_bit;
static int hf_dect_nr_mux_ie_type_long;
static int hf_dect_nr_mux_ie_type_short_pl0;
static int hf_dect_nr_mux_ie_type_short_pl1;
static int hf_dect_nr_mux_mac_ie_len_1;
static int hf_dect_nr_mux_mac_ie_len_2;

/* 6.4.2.2: Network Beacon message */
static int hf_dect_nr_nb_msg;
static int hf_dect_nr_nb_res1;
static int hf_dect_nr_nb_tx_pwr_field;
static int hf_dect_nr_nb_pwr_const;
static int hf_dect_nr_nb_current_field;
static int hf_dect_nr_nb_channels;
static int hf_dect_nr_nb_nb_period;
static int hf_dect_nr_nb_cb_period;
static int hf_dect_nr_nb_res2;
static int hf_dect_nr_nb_next_cl_chan;
static int hf_dect_nr_nb_time_to_next;
static int hf_dect_nr_nb_res3;
static int hf_dect_nr_nb_cl_max_tx_pwr;
static int hf_dect_nr_nb_res4;
static int hf_dect_nr_nb_curr_cl_chan;
static int hf_dect_nr_nb_res5;
static int hf_dect_nr_nb_addn_nb_channels;

/* 6.4.2.3: Cluster Beacon message */
static int hf_dect_nr_cb_msg;
static int hf_dect_nr_cb_sfn;
static int hf_dect_nr_cb_res1;
static int hf_dect_nr_cb_tx_pwr_field;
static int hf_dect_nr_cb_pwr_const;
static int hf_dect_nr_cb_fo_field;
static int hf_dect_nr_cb_next_chan_field;
static int hf_dect_nr_cb_time_to_next_field;
static int hf_dect_nr_cb_nb_period;
static int hf_dect_nr_cb_cb_period;
static int hf_dect_nr_cb_ctt;
static int hf_dect_nr_cb_rel_qual;
static int hf_dect_nr_cb_min_qual;
static int hf_dect_nr_cb_res2;
static int hf_dect_nr_cb_cl_max_tx_pwr;
static int hf_dect_nr_cb_frame_offset;
static int hf_dect_nr_cb_res3;
static int hf_dect_nr_cb_next_cl_chan;
static int hf_dect_nr_cb_time_to_next;

/* 6.4.2.4: Association Request message */
static int hf_dect_nr_a_req_msg;
static int hf_dect_nr_a_req_setup_cause;
static int hf_dect_nr_a_req_num_flows;
static int hf_dect_nr_a_req_pwr_const;
static int hf_dect_nr_a_req_ft_mode_field;
static int hf_dect_nr_a_req_current;
static int hf_dect_nr_a_req_res1;
static int hf_dect_nr_a_req_harq_proc_tx;
static int hf_dect_nr_a_req_max_harq_retx;
static int hf_dect_nr_a_req_harq_proc_rx;
static int hf_dect_nr_a_req_max_harq_rerx;
static int hf_dect_nr_a_req_res2;
static int hf_dect_nr_a_req_flow_id;
static int hf_dect_nr_a_req_nb_period;
static int hf_dect_nr_a_req_cb_period;
static int hf_dect_nr_a_req_res3;
static int hf_dect_nr_a_req_next_cl_chan;
static int hf_dect_nr_a_req_time_to_next;
static int hf_dect_nr_a_req_res4;
static int hf_dect_nr_a_req_curr_cl_chan;

/* 6.4.2.5: Association Response message */
static int hf_dect_nr_a_rsp_msg;
static int hf_dect_nr_a_rsp_ack_field;
static int hf_dect_nr_a_rsp_res1;
static int hf_dect_nr_a_rsp_harq_mod_field;
static int hf_dect_nr_a_rsp_num_flows;
static int hf_dect_nr_a_rsp_group_field;
static int hf_dect_nr_a_rsp_res2;
static int hf_dect_nr_a_rsp_rej_cause;
static int hf_dect_nr_a_rsp_rej_timer;
static int hf_dect_nr_a_rsp_harq_proc_rx;
static int hf_dect_nr_a_rsp_max_harq_rerx;
static int hf_dect_nr_a_rsp_harq_proc_tx;
static int hf_dect_nr_a_rsp_max_harq_retx;
static int hf_dect_nr_a_rsp_res3;
static int hf_dect_nr_a_rsp_flow_id;
static int hf_dect_nr_a_rsp_res4;
static int hf_dect_nr_a_rsp_group_id;
static int hf_dect_nr_a_rsp_res5;
static int hf_dect_nr_a_rsp_res_tag;
static int hf_dect_nr_a_rsp_res6;

/* 6.4.2.6: Association Release message */
static int hf_dect_nr_a_rel_msg;
static int hf_dect_nr_a_rel_cause;
static int hf_dect_nr_a_rel_res1;

/* 6.4.2.7: Reconfiguration Request message */
static int hf_dect_nr_rc_req_msg;
static int hf_dect_nr_rc_req_tx_harq_field;
static int hf_dect_nr_rc_req_rx_harq_field;
static int hf_dect_nr_rc_req_rd_capability;
static int hf_dect_nr_rc_req_num_flows;
static int hf_dect_nr_rc_req_radio_resources;
static int hf_dect_nr_rc_req_harq_proc_tx;
static int hf_dect_nr_rc_req_max_harq_retx;
static int hf_dect_nr_rc_req_harq_proc_rx;
static int hf_dect_nr_rc_req_max_harq_rerx;
static int hf_dect_nr_rc_req_setup_release;
static int hf_dect_nr_rc_req_res;
static int hf_dect_nr_rc_req_flow_id;

/* 6.4.2.8: Reconfiguration Response message */
static int hf_dect_nr_rc_rsp_msg;
static int hf_dect_nr_rc_rsp_tx_harq_field;
static int hf_dect_nr_rc_rsp_rx_harq_field;
static int hf_dect_nr_rc_rsp_rd_capability;
static int hf_dect_nr_rc_rsp_num_flows;
static int hf_dect_nr_rc_rsp_radio_resources;
static int hf_dect_nr_rc_rsp_harq_proc_tx;
static int hf_dect_nr_rc_rsp_max_harq_retx;
static int hf_dect_nr_rc_rsp_harq_proc_rx;
static int hf_dect_nr_rc_rsp_max_harq_rerx;
static int hf_dect_nr_rc_rsp_setup_release;
static int hf_dect_nr_rc_rsp_res;
static int hf_dect_nr_rc_rsp_flow_id;

/* 6.4.3.1: MAC Security Info IE */
static int hf_dect_nr_msi_ie;
static int hf_dect_nr_msi_version;
static int hf_dect_nr_msi_key;
static int hf_dect_nr_msi_ivt;
static int hf_dect_nr_msi_hpc;

/* 6.4.3.2: Route Info IE */
static int hf_dect_nr_ri_ie;
static int hf_dect_nr_ri_sink_address;
static int hf_dect_nr_ri_route_cost;
static int hf_dect_nr_ri_application_sn;

/* 6.4.3.3: Resource Allocation IE */
static int hf_dect_nr_ra_ie;
static int hf_dect_nr_ra_alloc_type;
static int hf_dect_nr_ra_add_field;
static int hf_dect_nr_ra_id_field;
static int hf_dect_nr_ra_repeat;
static int hf_dect_nr_ra_sfn_field;
static int hf_dect_nr_ra_channel_field;
static int hf_dect_nr_ra_rlf_field;
static int hf_dect_nr_ra_res1;
static int hf_dect_nr_ra_res2;
static int hf_dect_nr_ra_start_ss_dl_9;
static int hf_dect_nr_ra_start_ss_dl_8;
static int hf_dect_nr_ra_len_type_dl;
static int hf_dect_nr_ra_len_dl;
static int hf_dect_nr_ra_start_ss_ul_9;
static int hf_dect_nr_ra_start_ss_ul_8;
static int hf_dect_nr_ra_len_type_ul;
static int hf_dect_nr_ra_len_ul;
static int hf_dect_nr_ra_short_rd_id;
static int hf_dect_nr_ra_repetition;
static int hf_dect_nr_ra_validity;
static int hf_dect_nr_ra_sfn_value;
static int hf_dect_nr_ra_res3;
static int hf_dect_nr_ra_channel;
static int hf_dect_nr_ra_res4;
static int hf_dect_nr_ra_rlf;

/* 6.4.3.4: Random Access Resource IE */
static int hf_dect_nr_rar_ie;
static int hf_dect_nr_rar_res1;
static int hf_dect_nr_rar_repeat;
static int hf_dect_nr_rar_sfn_field;
static int hf_dect_nr_rar_channel_field;
static int hf_dect_nr_rar_chan_2_field;
static int hf_dect_nr_rar_res2;
static int hf_dect_nr_rar_start_ss_9;
static int hf_dect_nr_rar_start_ss_8;
static int hf_dect_nr_rar_len_type;
static int hf_dect_nr_rar_len;
static int hf_dect_nr_rar_max_len_type;
static int hf_dect_nr_rar_max_rach_len;
static int hf_dect_nr_rar_cw_min_sig;
static int hf_dect_nr_rar_dect_delay;
static int hf_dect_nr_rar_resp_win;
static int hf_dect_nr_rar_cw_max_sig;
static int hf_dect_nr_rar_repetition;
static int hf_dect_nr_rar_validity;
static int hf_dect_nr_rar_sfn_value;
static int hf_dect_nr_rar_res3;
static int hf_dect_nr_rar_channel;
static int hf_dect_nr_rar_channel_2;

/* 6.4.3.5: RD Capability IE */
static int hf_dect_nr_rdc_ie;
static int hf_dect_nr_rdc_num_phy_cap;
static int hf_dect_nr_rdc_release;
static int hf_dect_nr_rdc_res1;
static int hf_dect_nr_rdc_group_ass;
static int hf_dect_nr_rdc_paging;
static int hf_dect_nr_rdc_op_modes;
static int hf_dect_nr_rdc_mesh;
static int hf_dect_nr_rdc_sched;
static int hf_dect_nr_rdc_mac_security;
static int hf_dect_nr_rdc_dlc_type;
static int hf_dect_nr_rdc_res2;
static int hf_dect_nr_rdc_res3;
static int hf_dect_nr_rdc_pwr_class;
static int hf_dect_nr_rdc_max_nss_rx;
static int hf_dect_nr_rdc_rx_for_tx_div;
static int hf_dect_nr_rdc_rx_gain;
static int hf_dect_nr_rdc_max_mcs;
static int hf_dect_nr_rdc_soft_buf_size;
static int hf_dect_nr_rdc_num_harq_proc;
static int hf_dect_nr_rdc_res4;
static int hf_dect_nr_rdc_harq_fb_delay;
static int hf_dect_nr_rdc_d_delay;
static int hf_dect_nr_rdc_half_dup;
static int hf_dect_nr_rdc_res5;
static int hf_dect_nr_rdc_phy_cap;
static int hf_dect_nr_rdc_rd_class_mu;
static int hf_dect_nr_rdc_rd_class_b;
static int hf_dect_nr_rdc_res6;
static int hf_dect_nr_rdc_res7;

/* 6.4.3.6: Neighbouring IE */
static int hf_dect_nr_n_ie;
static int hf_dect_nr_n_res1;
static int hf_dect_nr_n_id_field;
static int hf_dect_nr_n_mu_field;
static int hf_dect_nr_n_snr_field;
static int hf_dect_nr_n_rssi2_field;
static int hf_dect_nr_n_pwr_const;
static int hf_dect_nr_n_next_channel_field;
static int hf_dect_nr_n_ttn_field;
static int hf_dect_nr_n_nb_period;
static int hf_dect_nr_n_cb_period;
static int hf_dect_nr_n_long_rd_id;
static int hf_dect_nr_n_res2;
static int hf_dect_nr_n_next_cl_channel;
static int hf_dect_nr_n_time_to_next;
static int hf_dect_nr_n_rssi2;
static int hf_dect_nr_n_snr;
static int hf_dect_nr_n_rd_class_u;
static int hf_dect_nr_n_rd_class_b;
static int hf_dect_nr_n_res3;

/* 6.4.3.7: Broadcast Indication IE */
static int hf_dect_nr_bi_ie;
static int hf_dect_nr_bi_ind_type;
static int hf_dect_nr_bi_idtype;
static int hf_dect_nr_bi_ack;
static int hf_dect_nr_bi_res1;
static int hf_dect_nr_bi_fb;
static int hf_dect_nr_bi_res_alloc;
static int hf_dect_nr_bi_short_rd_id;
static int hf_dect_nr_bi_long_rd_id;
static int hf_dect_nr_bi_mcs_res1;
static int hf_dect_nr_bi_mcs_channel_quality;
static int hf_dect_nr_bi_mimo2_res1;
static int hf_dect_nr_bi_mimo2_num_layers;
static int hf_dect_nr_bi_mimo2_cb_index;
static int hf_dect_nr_bi_mimo4_num_layers;
static int hf_dect_nr_bi_mimo4_cb_index;

/* 6.4.3.8: Padding IE */
static int hf_dect_nr_pd_ie;
static int hf_dect_nr_pd_bytes;

/* 6.4.3.9: Group Assignment IE */
static int hf_dect_nr_ga_ie;
static int hf_dect_nr_ga_single_field;
static int hf_dect_nr_ga_group_id;
static int hf_dect_nr_ga_direct;
static int hf_dect_nr_ga_resource_tag;

/* 6.4.3.10: Load Info IE */
static int hf_dect_nr_li_ie;
static int hf_dect_nr_li_res1;
static int hf_dect_nr_li_max_assoc_field;
static int hf_dect_nr_li_rd_pt_load_field;
static int hf_dect_nr_li_rach_load_field;
static int hf_dect_nr_li_channel_load_field;
static int hf_dect_nr_li_traffic_load_pct;
static int hf_dect_nr_li_max_assoc_8;
static int hf_dect_nr_li_max_assoc_16;
static int hf_dect_nr_li_curr_ft_pct;
static int hf_dect_nr_li_curr_pt_pct;
static int hf_dect_nr_li_rach_load_pct;
static int hf_dect_nr_li_subslots_free_pct;
static int hf_dect_nr_li_subslots_busy_pct;

/* 6.4.3.12: Measurement Report IE */
static int hf_dect_nr_mr_ie;
static int hf_dect_nr_mr_res1;
static int hf_dect_nr_mr_snr_field;
static int hf_dect_nr_mr_rssi2_field;
static int hf_dect_nr_mr_rssi1_field;
static int hf_dect_nr_mr_tx_count_field;
static int hf_dect_nr_mr_rach;
static int hf_dect_nr_mr_snr;
static int hf_dect_nr_mr_rssi2;
static int hf_dect_nr_mr_rssi1;
static int hf_dect_nr_mr_tx_count;

/* 6.4.3.13: Radio Device Status IE */
static int hf_dect_nr_rds_ie;
static int hf_dect_nr_rds_res1;
static int hf_dect_nr_rds_sf;
static int hf_dect_nr_rds_dur;

/* Escape */
static int hf_dect_nr_escape;

/* IE type extension */
static int hf_dect_nr_ie_type_extension;
static int hf_dect_nr_ie_extension;

/* MIC */
static int hf_dect_nr_mic_bytes;

/* DLC */
static int hf_dect_nr_dlc_pdu;
static int hf_dect_nr_dlc_ie_type;
static int hf_dect_nr_dlc_res1;
static int hf_dect_nr_dlc_si;
static int hf_dect_nr_dlc_sn;
static int hf_dect_nr_dlc_segm_offset;
static int hf_dect_nr_dlc_timers;

/* DLC Routing header */
static int hf_dect_nr_dlc_routing;
static int hf_dect_nr_dlc_routing_res1;
static int hf_dect_nr_dlc_routing_qos;
static int hf_dect_nr_dlc_routing_delay_field;
static int hf_dect_nr_dlc_routing_hop_count_limit;
static int hf_dect_nr_dlc_routing_dest_add;
static int hf_dect_nr_dlc_routing_type;
static int hf_dect_nr_dlc_routing_src_addr;
static int hf_dect_nr_dlc_routing_dst_addr;
static int hf_dect_nr_dlc_routing_hop_count;
static int hf_dect_nr_dlc_routing_hop_limit;
static int hf_dect_nr_dlc_routing_delay;

/* Higher layer signalling */
static int hf_dect_nr_hls_bin;

/* DLC Reassembly */
static int hf_dect_nr_segments;
static int hf_dect_nr_segment;
static int hf_dect_nr_segment_overlap;
static int hf_dect_nr_segment_overlap_conflict;
static int hf_dect_nr_segment_multiple_tails;
static int hf_dect_nr_segment_too_long_segment;
static int hf_dect_nr_segment_error;
static int hf_dect_nr_segment_count;
static int hf_dect_nr_reassembled_in;
static int hf_dect_nr_reassembled_length;

/* Undecoded */
static int hf_dect_nr_undecoded;

/* Expert info */
static expert_field ei_dect_nr_ie_length_not_set;
static expert_field ei_dect_nr_pdu_cut_short;
static expert_field ei_dect_nr_length_mismatch;
static expert_field ei_dect_nr_res_non_zero;
static expert_field ei_dect_nr_undecoded;

/* Protocol subtrees */
static int ett_dect_nr;
static int ett_dect_nr_phf;
static int ett_dect_nr_mac_pdu;
static int ett_dect_nr_data_hdr;
static int ett_dect_nr_bc_hdr;
static int ett_dect_nr_uc_hdr;
static int ett_dect_nr_rdbh_hdr;
static int ett_dect_nr_mux_hdr;
static int ett_dect_nr_nb_msg;
static int ett_dect_nr_cb_msg;
static int ett_dect_nr_a_req_msg;
static int ett_dect_nr_a_rsp_msg;
static int ett_dect_nr_a_rel_msg;
static int ett_dect_nr_rc_req_msg;
static int ett_dect_nr_rc_rsp_msg;
static int ett_dect_nr_msi_ie;
static int ett_dect_nr_ri_ie;
static int ett_dect_nr_ra_ie;
static int ett_dect_nr_rar_ie;
static int ett_dect_nr_rdc_ie;
static int ett_dect_nr_rdc_phy_cap;
static int ett_dect_nr_n_ie;
static int ett_dect_nr_bi_ie;
static int ett_dect_nr_ga_ie;
static int ett_dect_nr_li_ie;
static int ett_dect_nr_mr_ie;
static int ett_dect_nr_rds_ie;
static int ett_dect_nr_dlc_pdu;
static int ett_dect_nr_dlc_routing;
static int ett_dect_nr_segment;
static int ett_dect_nr_segments;

static dissector_handle_t dect_nr_handle;
static dissector_handle_t data_handle;
static dissector_handle_t ipv6_handle;

static dissector_table_t ie_dissector_table;
static dissector_table_t ie_short_dissector_table;

static heur_dissector_list_t heur_subdissector_list;

/* Preference to configure PHY header type */
typedef enum {
	PHF_TYPE_TYPE_1,
	PHF_TYPE_TYPE_2,
	PHF_TYPE_TYPE_AUTO,
} phf_type_t;

static int phf_type_pref = PHF_TYPE_TYPE_AUTO;
static const enum_val_t phf_type_pref_vals[] = {
	{ "auto", "Automatic", PHF_TYPE_TYPE_AUTO },
	{ "type1", "Type 1: 40 bits", PHF_TYPE_TYPE_1 },
	{ "type2", "Type 2: 80 bits", PHF_TYPE_TYPE_2 },
	{ NULL, NULL, -1 }
};

/* Preference to configure DLC data type */
typedef enum {
	DLC_DATA_TYPE_AUTO,
	DLC_DATA_TYPE_BINARY,
	DLC_DATA_TYPE_IPv6,
} dlc_data_type_t;

static int dlc_data_type_pref = DLC_DATA_TYPE_AUTO;
static const enum_val_t dlc_data_type_pref_vals[] = {
	{ "auto", "Automatic", DLC_DATA_TYPE_AUTO },
	{ "binary", "Binary (data)", DLC_DATA_TYPE_BINARY },
	{ "ipv6", "IPv6", DLC_DATA_TYPE_IPv6 },
	{ NULL, NULL, -1 }
};

static const value_string dect_plcf_size_vals[] = {
	{ 0, "Type 1: 40 bits" },
	{ 1, "Type 2: 80 bits" },
	{ 0, NULL }
};

/* Table 6.2.1-1: Physical Layer Control Field: Type 1 */
static const value_string header_formats_type1_vals[] = {
	{ 0, "Format 0" },
	{ 0, NULL }
};

/* Table 6.2.1-2: Physical Layer Control Field: Type 2 */
static const value_string header_formats_type2_vals[] = {
	{ 0, "Format 0 - Transmitter does request HARQ feedback" },
	{ 1, "Format 1 - Transmitter does not request HARQ feedback for the DF of this packet" },
	{ 0, NULL }
};

/* Table 6.2.1-3a: Transmit Power */
static const value_string tx_powers_3a_vals[] = {
	{ 0, "-40 dBm" },
	{ 1, "-30 dBm" },
	{ 2, "-20 dBm" },
	{ 3, "-16 dBm" },
	{ 4, "-12 dBm" },
	{ 5, "-8 dBm" },
	{ 6, "-4 dBm" },
	{ 7, "0 dBm" },
	{ 8, "4 dBm" },
	{ 9, "7 dBm" },
	{ 10, "10 dBm" },
	{ 11, "13 dBm" },
	{ 12, "16 dBm" },
	{ 13, "19 dBm" },
	{ 14, "21 dBm" },
	{ 15, "23 dBm" },
	{ 0, NULL }
};

/* Table 6.2.1-3b: Transmit Power */
static const value_string tx_powers_3b_vals[] = {
	{ 0, "Reserved" },
	{ 1, "Reserved" },
	{ 2, "Reserved" },
	{ 3, "Reserved" },
	{ 4, "-12 dBm" },
	{ 5, "-8 dBm" },
	{ 6, "-4 dBm" },
	{ 7, "0 dBm" },
	{ 8, "4 dBm" },
	{ 9, "7 dBm" },
	{ 10, "10 dBm" },
	{ 11, "13 dBm" },
	{ 12, "16 dBm" },
	{ 13, "19 dBm" },
	{ 14, "21 dBm" },
	{ 15, "23 dBm" },
	{ 0, NULL }
};

static const true_false_string pkt_len_type_tfs = {
	"Length given in slots",
	"Length given in subslots"
};

/* ETSI TS 103 636-3 */
static const value_string mcse_vals[] = {
	{ 0, "BPSK" },
	{ 1, "QPSK, R=1/2" },
	{ 2, "QPSK, R=3/4" },
	{ 3, "16-QAM, R=1/2" },
	{ 4, "16-QAM, R=3/4" },
	{ 5, "64-QAM, R=2/3" },
	{ 6, "64-QAM, R=3/4" },
	{ 7, "64-QAM, R=5/6" },
	{ 8, "256-QAM, R=3/4" },
	{ 9, "256-QAM, R=5/6" },
	{ 10, "1024-QAM, R=3/4" },
	{ 11, "1024-QAM, R=5/6" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 6.2.1-4: Number of Spatial Streams */
static const value_string num_spatial_stream_vals[] = {
	{ 0, "Single spatial stream" },
	{ 1, "Two spatial streams" },
	{ 2, "Four spatial streams" },
	{ 3, "Eight spatial streams" },
	{ 0, NULL }
};

/* Table 6.2.2-1: Feedback format for 12-bit Feedback Info */
static const value_string feedback_format_vals[] = {
	{ 0, "No feedback, receiver shall ignore feedback info bits" },
	{ 1, "Format 1" },
	{ 2, "Format 2" },
	{ 3, "Format 3" },
	{ 4, "Format 4" },
	{ 5, "Format 5" },
	{ 6, "Format 6" },
	{ 15, "Escape" },
	{ 0, NULL }
};

/* Table 6.2.2-2b: Feedback info format 2: MIMO feedback */
static const true_false_string fbi2_mimo_fb_tfs = {
	"Dual layers",
	"Single layer"
};

/* Table 6.2.2-2e: Feedback info format 5: MIMO feedback */
static const value_string fbi5_mimo_fb_vals[] = {
	{ 0, "Single layer, codebook index included" },
	{ 1, "Dual layers, codebook index included" },
	{ 2, "Four layers, codebook index included" },
	{ 3, "Reserved" },
	{ 0, NULL }
};

/* Table 6.2.2-3: Channel Quality Indicator */
static const value_string cqi_vals[] = {
	{ 0, "Out of Range" },
	{ 1, "MCS-0" },
	{ 2, "MCS-1" },
	{ 3, "MCS-2" },
	{ 4, "MCS-3" },
	{ 5, "MCS-4" },
	{ 6, "MCS-5" },
	{ 7, "MCS-6" },
	{ 8, "MCS-7" },
	{ 9, "MCS-8" },
	{ 10, "MCS-9" },
	{ 11, "MCS-10" },
	{ 12, "MCS-11" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 6.2.2-4: Buffer Status */
static const value_string buffer_status_vals[] = {
	{ 0, "BS = 0" },
	{ 1, "0 < BS ≤ 16" },
	{ 2, "16 < BS ≤ 32" },
	{ 3, "32 < BS ≤ 64" },
	{ 4, "64 < BS ≤ 128" },
	{ 5, "128 < BS ≤ 256" },
	{ 6, "256 < BS ≤ 512" },
	{ 7, "512 < BS ≤ 1 024" },
	{ 8, "1 024 < BS ≤ 2 048" },
	{ 9, "2 048 < BS ≤ 4 096" },
	{ 10, "4 096 < BS ≤ 8 192" },
	{ 11, "8 192 < BS ≤ 16 384" },
	{ 12, "16 384 < BS ≤ 32 768" },
	{ 13, "32 768 < BS ≤ 65 536" },
	{ 14, "65 536 < BS ≤ 131 072" },
	{ 15, "BS > 131 072" },
	{ 0, NULL }
};

/* Table 6.3.2-1 */
static const value_string mac_security_vals[] = {
	{ 0, "MAC security is not used for this MAC PDU" },
	/* 1: The MAC PDU sequence number is used as PSN for security. */
	/* The ciphered part starts immediately after the MAC Common header. */
	{ 1, "MAC security is used and the MAC Security IE is not present" },
	/* 2: The ciphered part starts immediately after the MAC Security info. */
	{ 2, "MAC security is used and a MAC Security Info IE is in the MAC PDU" },
	{ 3, "Reserved" },
	{ 0, NULL }
};

/* Table 6.3.2-2: MAC header Type field */
static const value_string mac_header_type_vals[] = {
	{ 0, "Data MAC PDU Header" },
	{ 1, "Beacon Header" },
	{ 2, "Unicast Header" },
	{ 3, "RD Broadcasting Header" },
	{ 15, "Escape" },
	{ 0, NULL }
};

/* Table 6.3.4-1 */
static const value_string mac_ext_vals[] = {
	{ 0, "No length field is included in the IE header, the IE type defines the length of the IE payload" },
	{ 1, "8 bit length included indicating the length of the IE payload" },
	{ 2, "16 bit length included indicating the length of the IE payload" },
	{ 3, "Short IE, a one bit length field is included in the IE header" },
	{ 0, NULL }
};

/* Table 6.3.4-1 with value 3: IE payload size */
static const value_string mac_ext_len_bit_vals[] = {
	{ 0, "IE payload size 0 bytes" },
	{ 1, "IE payload size 1 byte" },
	{ 0, NULL }
};

/* Table 6.3.4-2 */
static const value_string mux_hdr_ie_type_mac_ext_012_vals[] = {
	{ 0, "Padding IE" },
	{ 1, "Higher layer signalling - flow 1" },
	{ 2, "Higher layer signalling - flow 2" },
	{ 3, "User plane data - flow 1" },
	{ 4, "User plane data - flow 2" },
	{ 5, "User plane data - flow 3" },
	{ 6, "User plane data - flow 4" },
	{ 7, "Reserved" },
	{ 8, "Network Beacon message" },
	{ 9, "Cluster Beacon message" },
	{ 10, "Association Request message" },
	{ 11, "Association Response message" },
	{ 12, "Association Release message" },
	{ 13, "Reconfiguration Request message" },
	{ 14, "Reconfiguration Response message" },
	{ 15, "Additional MAC message" },
	{ 16, "Security Info IE" },
	{ 17, "Route Info IE" },
	{ 18, "Resource Allocation IE" },
	{ 19, "Random Access Resource IE" },
	{ 20, "RD Capability IE" },
	{ 21, "Neighbouring IE" },
	{ 22, "Broadcast Indication IE" },
	{ 23, "Group Assignment IE" },
	{ 24, "Load Info IE" },
	{ 25, "Measurement Report IE" },
	/* 26 - 61 Reserved */
	{ 62, "Escape" },
	{ 63, "IE type extension" },
	{ 0, NULL }
};

/* Table 6.3.4-4 */
static const value_string mux_hdr_ie_type_mac_ext_3_pl_0_vals[] = {
	{ 0, "Padding IE" },
	{ 1, "Configuration Request IE" },
	{ 2, "Keep Alive IE" },
	/* 3 - 15 Reserved */
	{ 16, "MAC Security Info IE" },
	/* 17 - 29 Reserved */
	{ 30, "Escape" },
	{ 0, NULL }
};

/* Table 6.4.2.2-1: Network Beacon definitions */
static const value_string mux_hdr_ie_type_mac_ext_3_pl_1_vals[] = {
	{ 0, "Padding IE" },
	{ 1, "Radio Device Status IE" },
	/* 2 - 29 Reserved */
	{ 30, "Escape" },
	{ 0, NULL }
};

/* Table 6.4.2.2-1: Current */
static const true_false_string nb_ie_current_tfs = {
	"Not the same as the next cluster channel",
	"The same as the next cluster channel"
};

/* Network Beacon channels */

/* Table 6.4.2.2-1: Network Beacon period */
static const value_string nb_ie_nb_period_vals[] = {
	{ 0, "50 ms" },
	{ 1, "100 ms" },
	{ 2, "500 ms" },
	{ 3, "1000 ms" },
	{ 4, "1500 ms" },
	{ 5, "2000 ms" },
	{ 6, "4000 ms" },
	{ 7, "Reserved" },
	{ 8, "Reserved" },
	{ 9, "Reserved" },
	{ 10, "Reserved" },
	{ 11, "Reserved" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.2.2-1: Cluster Beacon period */
static const value_string nb_ie_cb_period_vals[] = {
	{ 0, "10 ms" },
	{ 1, "50 ms" },
	{ 2, "100 ms" },
	{ 3, "500 ms" },
	{ 4, "1000 ms" },
	{ 5, "1500 ms" },
	{ 6, "2000 ms" },
	{ 7, "4000 ms" },
	{ 8, "8000 ms" },
	{ 9, "16000 ms" },
	{ 10, "32000 ms" },
	{ 11, "Reserved" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.2.3-1: Cluster beacon IE field definitions */
static const true_false_string cb_next_chan_tfs = {
	"Different cluster channel; the next cluster channel field is included",
	"The same as the current cluster channel"
};

/* Table 6.4.2.3-1: Cluster beacon IE field definitions */
static const true_false_string cb_ttn_tfs = {
	"Transmitted in a time location, the Time to next field is present",
	"Transmitted based on Cluster beacon period"
};

/* Table 6.4.3.1-1: Version */
static const value_string msi_version_vals[] = {
	{ 0, "Mode 1" },
	{ 1, "Reserved" },
	{ 2, "Reserved" },
	{ 3, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.1-2: Security IV type for Mode 1 */
static const value_string msi_ivt_vals[] = {
	{ 0, "One time HPC" },
	{ 1, "Resynchronizing HPC, initiate Mode -1 security by using this HPC value in both UL and DL communication" },
	{ 2, "One time HPC, with HPC request" },
	{ 3, "Reserved" },
	{ 4, "Reserved" },
	{ 5, "Reserved" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 8, "Reserved" },
	{ 9, "Reserved" },
	{ 10, "Reserved" },
	{ 11, "Reserved" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.4-1: RACH Resource allocation bitmap */
static const value_string rar_repeat_vals[] = {
	{ 0, "Single allocation; repetition and validity fields not present" },
	{ 1, "Repeated in the following frames; periodicity in the Repetition field" },
	{ 2, "Repeated in the following subslots; periodicity in the Repetition field" },
	{ 3, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.4-1: RACH Resource allocation bitmap */
static const true_false_string rar_sfn_tfs = {
	"Resource allocation is valid from the frame indicated in SFN value field onwards",
	"Resource allocation is immediately valid from this frame onwards (no SFN value field)"
};

/* Table 6.4.3.4-1: RACH Resource allocation bitmap */
static const true_false_string rar_channel_tfs = {
	"The channel where resource allocation is valid is indicated in the channel field of the IE",
	"The resource allocation is valid for current channel, the channel field is not present in the IE"
};

/* Table 6.4.3.4-1: RACH Resource allocation bitmap */
static const true_false_string rar_chan_2_tfs = {
	"The channel for Random access response message is included in the end of the IE",
	"The random access response is sent on the same channel as the random access message"
};

/* Table 6.4.3.4-1: RACH Resource allocation bitmap */
static const true_false_string rar_dect_delay_tfs = {
	"Response window starts 0.5 frames after the start of the frame where the RA transmission was initiated",
	"Response window starts 3 subslots after the last subslot of the Random Access packet transmission"
};

/* Signalled subslot length index starts from 0 in some cases:
 * - Packet length type in the Physical Header Field (See Table 6.2.1-1)
 * - Response window: (See Ch. 6.4.3.4 Random Access Resource IE)
 */
static const value_string signalled_s_len_vals[] = {
	{ 0, "1 slot" },
	{ 1, "2 slots" },
	{ 2, "3 slots" },
	{ 3, "4 slots" },
	{ 4, "5 slots" },
	{ 5, "6 slots" },
	{ 6, "7 slots" },
	{ 7, "8 slots" },
	{ 8, "9 slots" },
	{ 9, "10 slots" },
	{ 10, "11 slots" },
	{ 11, "12 slots" },
	{ 12, "13 slots" },
	{ 13, "14 slots" },
	{ 14, "15 slots" },
	{ 15, "16 slots" },
	{ 0, NULL }
};

static const value_string signalled_ss_len_vals[] = {
	{ 0, "1 subslot" },
	{ 1, "2 subslots" },
	{ 2, "3 subslots" },
	{ 3, "4 subslots" },
	{ 4, "5 subslots" },
	{ 5, "6 subslots" },
	{ 6, "7 subslots" },
	{ 7, "8 subslots" },
	{ 8, "9 subslots" },
	{ 9, "10 subslots" },
	{ 10, "11 subslots" },
	{ 11, "12 subslots" },
	{ 12, "13 subslots" },
	{ 13, "14 subslots" },
	{ 14, "15 subslots" },
	{ 15, "16 subslots" },
	{ 0, NULL }
};

/* Table 6.4.2.4-2: Association Setup Cause IE */
static const value_string ar_setup_cause_vals[] = {
	{ 0, "Initial association" },
	{ 1, "Association to request new set of flows" },
	{ 2, "Association due to mobility" },
	{ 3, "Re-association after error: Loss of connection, Security error or Other error" },
	{ 4, "Change of operating channel of this FT device" },
	{ 5, "Change of operating mode (PT->FT or FT->PT)" },
	{ 6, "Paging response" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.2.4-1: Association Request IE: Number of flows */
static const value_string a_req_num_flow_vals[] = {
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.2.4-1: Association Request - operating modes */
static const true_false_string ar_ft_mode_tfs = {
	"The RD operates also in FT mode, NB/CB Period, Next Cluster Channel and TTN fields are included",
	"The RD operates only in PT Mode"
};

/* Table 6.4.2.4-1: Association Request - MAX HARQ RE-TX or RE-RX */
static const value_string ar_max_harq_re_rxtx_vals[] = {
	{ 0, "0.105 ms" },
	{ 1, "0.2 ms" },
	{ 2, "0.4 ms" },
	{ 3, "0.8 ms" },
	{ 4, "1 ms" },
	{ 5, "2 ms" },
	{ 6, "4 ms" },
	{ 7, "6 ms" },
	{ 8, "8 ms" },
	{ 9, "10 ms" },
	{ 10, "20 ms" },
	{ 11, "30 ms" },
	{ 12, "40 ms" },
	{ 13, "50 ms" },
	{ 14, "60 ms" },
	{ 15, "70 ms" },
	{ 16, "80 ms" },
	{ 17, "90 ms" },
	{ 18, "100 ms" },
	{ 19, "120 ms" },
	{ 20, "140 ms" },
	{ 21, "160 ms" },
	{ 22, "180 ms" },
	{ 23, "200 ms" },
	{ 24, "240 ms" },
	{ 25, "280 ms" },
	{ 26, "320 ms" },
	{ 27, "360 ms" },
	{ 28, "400 ms" },
	{ 29, "450 ms" },
	{ 30, "500 ms" },
	{ 31, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.2.5-1: Association Response: HARQ-mod */
static const true_false_string ar_harq_mod_tfs = {
	"Present",
	"Not present, accepted as configured in the Association Request"
};

/* Table 6.4.2.5-1: Association Response: Number of flows */
static const value_string a_rsp_num_flow_vals[] = {
	{ 7, "All flows accepted as configured in the Association Request" },
	{ 0, NULL }
};

/* Table 6.4.2.5-2: Reject Cause */
static const value_string assoc_rej_cause_vals[] = {
	{ 0, "No sufficient radio capacity" },
	{ 1, "No sufficient HW capacity" },
	{ 2, "Conflict with Short RD ID detected" },
	{ 3, "Non-secured Association Requests not accepted" },
	{ 4, "Other reason" },
	{ 5, "Reserved" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 8, "Reserved" },
	{ 9, "Reserved" },
	{ 10, "Reserved" },
	{ 11, "Reserved" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.2.5-2: Reject Time */
/* Time how long the other RDs shall prohibit sending new Association Requests to this RD */
static const value_string assoc_rej_time_vals[] = {
	{ 0, "0 s" },
	{ 1, "5 s" },
	{ 2, "10 s" },
	{ 3, "30 s" },
	{ 4, "60 s" },
	{ 5, "120 s" },
	{ 6, "180 s" },
	{ 7, "300 s" },
	{ 8, "600 s" },
	{ 9, "Reserved" },
	{ 10, "Reserved" },
	{ 11, "Reserved" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.2.6-1: Association Release: Release Cause */
static const value_string assoc_rel_cause_vals[] = {
	{ 0, "Connection termination" },
	{ 1, "Mobility" },
	{ 2, "Long inactivity" },
	{ 3, "Incompatible configuration" },
	{ 4, "No sufficient HW or memory resource" },
	{ 5, "No sufficient radio resources" },
	{ 6, "Bad radio quality" },
	{ 7, "Security error" },
	{ 8, "Short RD ID Conflict detected in PT side" },
	{ 9, "Short RD ID Conflict detected in FT side" },
	{ 10, "Not associated" },
	{ 11, "Reserved" },
	{ 12, "Not operating in FT mode" },
	{ 13, "Other error" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.2.7-1: Reconfiguration Request IE field definitions */
static const true_false_string rc_harq_req_tfs = {
	"Requested to be modified",
	"Not requested to be modified"
};

/* Table 6.4.2.7-1: Reconfiguration Request IE field definitions */
static const true_false_string rc_rd_capability_req_tfs = {
	"The RD capability is changed",
	"Ignore",
};

/* Table 6.4.2.7-1: Reconfiguration Request IE: Number of flows */
static const value_string rc_req_num_flow_vals[] = {
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.2.7-1: Reconfiguration Request IE field definitions */
static const value_string rc_radio_resource_vals[] = {
	{ 0, "No Change" },
	{ 1, "Requesting more resources" },
	{ 2, "Requesting less resources" },
	{ 3, "The Resource allocation" },
	{ 0, NULL }
};

/* Table 6.4.2.7-1: Reconfiguration Request IE field definitions */
static const true_false_string rc_setup_release_tfs = {
	"Released",
	"Setup or reconfiguration"
};

/* Table 6.4.2.8-1: Reconfiguration Response IE field definitions */
static const true_false_string rc_harq_rsp_tfs = {
	"Not accepted",
	"Accepted or is not modified in the reconfiguration request"
};

/* Table 6.4.2.8-1: Reconfiguration Response IE field definitions */
static const true_false_string rc_rd_capability_rsp_tfs = {
	"The RD indicates that its capability is changed",
	"Ignore"
};

/* Table 6.4.2.8-1: Reconfiguration Response IE: Number of flows */
static const value_string rc_rsp_num_flow_vals[] = {
	{ 7, "All flows accepted as configured in the Reconfiguration Request" },
	{ 0, NULL }
};

/* Table 6.4.3.3-1: Resource allocation bitmap */
static const value_string ra_alloc_type_vals[] = {
	{ 0, "The receiving RD shall release all previously allocated scheduled resources" },
	{ 1, "Downlink allocation" },
	{ 2, "Uplink allocation " },
	{ 3, "Downlink and Uplink resources" },
	{ 0, NULL }
};

/* Table 6.4.3.3-1: Resource allocation bitmap */
static const true_false_string ra_add_tfs = {
	"The additional allocation for existing allocation",
	"New or replaces the previous allocation"
};

/* Table 6.4.3.3-1: Resource allocation bitmap */
static const value_string ra_repeat_vals[] = {
	{ 0, "Resource allocation is single allocation" },
	{ 1, "Resource allocation is repeated in the following frames" },
	{ 2, "Resource allocation is repeated in the following subslots" },
	{ 3, "Resource allocation is repeated in the following frames " },
	{ 4, "Resource allocation is repeated in the following subslots" },
	{ 5, "Reserved" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.3-1: Resource allocation bitmap */
static const true_false_string ra_sfn_tfs = {
	"Valid from the frame indicated in SFN value field onwards",
	"Immediately valid from this frame onwards"
};

/* Table 6.4.3.3-1: Resource allocation bitmap */
static const true_false_string ra_channel_tfs = {
	"The channel where resource allocation(s) is valid is indicated in channel field of the IE",
	"The resource allocation(s) is valid for the channel where the IE is received"
};

/* Table 6.4.3.3-2: Timer dectScheduledResourceFailure values */
static const value_string ra_scheduled_resource_failure_vals[] = {
	{ 0, "Reserved" },
	{ 1, "Reserved" },
	{ 2, "20 ms" },
	{ 3, "50 ms" },
	{ 4, "100 ms" },
	{ 5, "200 ms" },
	{ 6, "500 ms" },
	{ 7, "1 000 ms" },
	{ 8, "1 500 ms" },
	{ 9, "3 000 ms" },
	{ 10, "4 000 ms" },
	{ 11, "5 000 ms" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.5-1: RD Capability IE: Release */
static const value_string rdc_release_vals[] = {
	{ 0, "Reserved" },
	{ 1, "Release 1" },
	{ 2, "Release 2" },
	{ 3, "Release 3" },
	{ 4, "Release 4" },
	{ 5, "Reserved" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.5-1: RD Capability IE: Operating modes */
static const value_string rdc_op_mode_vals[] = {
	{ 0, "PT mode only" },
	{ 1, "FT mode only" },
	{ 2, "PT and FT modes" },
	{ 3, "Reserved" },
	{ 0, NULL }
};

static const value_string rdc_mac_security_vals[] = {
	{ 0, "Not supported" },
	{ 1, "Mode 1 supported" },
	{ 2, "Reserved" },
	{ 3, "Reserved" },
	{ 4, "Reserved" },
	{ 5, "Reserved" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.5-1: RD Capability IE: DLC service type */
static const value_string rdc_dlc_serv_type_vals[] = {
	{ 0, "DLC Service type 0 supported" },
	{ 1, "DLC Service type 1 supported" },
	{ 2, "DLC Service type 2 supported" },
	{ 3, "DLC Service types 1, 2, 3 supported" },
	{ 4, "DLC Service types 0, 1, 2, 3 supported" },
	{ 5, "Reserved" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.5-1: RD Capability IE: RD Power Class */
static const value_string rdc_pwr_class_vals[] = {
	{ 0, "Power class I" },
	{ 1, "Power class II" },
	{ 2, "Power class III" },
	{ 3, "Power class IV" },
	{ 4, "Reserved" },
	{ 5, "Reserved" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.5-1: RD Capability IE: power of two coded fields */
static const value_string rdc_pwr_two_field_vals[] = {
	{ 0, "1" },
	{ 1, "2" },
	{ 2, "4" },
	{ 3, "8" },
	{ 0, NULL }
};

/* Table 6.4.3.5-1: RD Capability IE: RX Gain */
static const value_string rdc_rx_gain_vals[] = {
	{ 0, "-10 dB" },
	{ 1, "-8 dB" },
	{ 2, "-6 dB" },
	{ 3, "-4 dB" },
	{ 4, "-2 dB" },
	{ 5, "-0 dB" },
	{ 6, "2 dB" },
	{ 7, "4 dB" },
	{ 8, "6 dB" },
	{ 9, "Reserved" },
	{ 10, "Reserved" },
	{ 11, "Reserved" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.5-1: RD Capability IE: Max MCS */
static const value_string rdc_max_mcse_vals[] = {
	{ 0, "MCS0" },
	{ 1, "MCS1" },
	{ 2, "MCS2" },
	{ 3, "MCS3" },
	{ 4, "MCS4" },
	{ 5, "MCS5" },
	{ 6, "MCS6" },
	{ 7, "MCS7" },
	{ 8, "MCS8" },
	{ 9, "MCS9" },
	{ 10, "MCS10" },
	{ 11, "MCS11" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.5-1: RD Capability IE: Soft buffer sizes */
static const value_string rdc_soft_buf_size_vals[] = {
	{ 0, "16 000 B" },
	{ 1, "25 344 B" },
	{ 2, "32 000 B" },
	{ 3, "64 000 B" },
	{ 4, "128 000 B" },
	{ 5, "256 000 B" },
	{ 6, "512 000 B" },
	{ 7, "1 024 000 B" },
	{ 8, "2 048 000 B" },
	{ 9, "Reserved" },
	{ 10, "Reserved" },
	{ 11, "Reserved" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.5-1: RD Capability IE: HARQ feedback delay */
static const value_string rdc_harq_fb_delay_vals[] = {
	{ 0, "0 subslots" },
	{ 1, "1 subslot" },
	{ 2, "2 subslots" },
	{ 3, "3 subslots" },
	{ 4, "4 subslots" },
	{ 5, "5 subslots" },
	{ 6, "6 subslots" },
	{ 7, "Reserved" },
	{ 8, "Reserved" },
	{ 9, "Reserved" },
	{ 10, "Reserved" },
	{ 11, "Reserved" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.5-1: RD Capability IE: Fourier transform scaling factor */
static const value_string rdc_fourier_factor_vals[] = {
	{ 0, "1" },
	{ 1, "2" },
	{ 2, "4" },
	{ 3, "8" },
	{ 4, "12" },
	{ 5, "16" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 8, "Reserved" },
	{ 9, "Reserved" },
	{ 10, "Reserved" },
	{ 11, "Reserved" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Table 5.4.3.6-1: Neighbouring IE field definitions: µ */
static const true_false_string radio_device_class_tfs = {
	"Present, the indicated RD operates with the indicated µ and β factor",
	"Not present, the indicated RD operates with same µ and β factor as the RD sending this IE"
};

/* Table 6.4.3.7-1: Broadcast Indication IE field definitions: Indication type */
static const value_string bi_ind_type_vals[] = {
	{ 0, "Paging" },
	{ 1, "RA Response" },
	{ 2, "Reserved" },
	{ 3, "Reserved" },
	{ 4, "Reserved" },
	{ 5, "Reserved" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.7-1: Broadcast Indication IE field definitions: IDType */
static const value_string bi_idtype_vals[] = {
	{ 0, "Short RD ID" },
	{ 1, "Long RD ID" },
	{ 0, NULL }
};

/* Table 6.4.3.7-1: Broadcast Indication IE field definitions: ACK/NACK */
static const true_false_string bi_ack_nack_tfs = {
	"Correctly received MAC PDU in RA TX",
	"Incorrectly received MAC PDU in RA TX"
};

/* Table 6.4.3.7-1: Broadcast Indication IE field definitions: ACK/NACK */
static const value_string bi_feedback_vals[] = {
	{ 0, "No feedback" },
	{ 1, "MCS" },
	{ 2, "MIMO 2 antenna" },
	{ 3, "MIMO 4 antenna" },
	{ 0, NULL }
};

/* Table 6.2.2-2b: Feedback info format 2 */
static const true_false_string bi_mimo2_num_layer_tfs = {
	"Dual layer",
	"Single layer"
};

/* Table 6.2.2-2e: Feedback info format 5 */
static const value_string bi_mimo4_num_layer_vals[] = {
	{ 0, "Single layer" },
	{ 1, "Dual layer" },
	{ 2, "Four layers" },
	{ 3, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.9-1: Group Assignment IE field definitions: Single */
static const true_false_string dect_nr_ga_single_tfs = {
	"Single resource assignment for the group member",
	"Multiple resource assignments follow for a group"
};

/* Table 6.4.3.9-1: Group Assignment IE field definitions: Direct */
static const true_false_string ga_direct_tfs = {
	"The Resource allocation direction is inverted",
	"The assignment follows the Resource allocation direction",
};

/* Table 6.4.3.10-1: Load Info IE field definitions: Max assoc */
static const true_false_string li_max_assoc_tfs = {
	"16 bit field",
	"8 bit field"
};

/* Table 6.4.3.12-1 Measurement Report IE field definitions: RACH */
static const true_false_string mr_rach_tfs = {
	"From DL reception of Random access response",
	"From DL scheduled resources"
};

/* Table 6.4.3.12-1 Measurement Report IE field definitions: TX Count result */
static const value_string mr_tx_count_vals[] = {
	{ 0xFF, "Transmission of MAC PDU has completely failed" },
	{ 0, NULL }
};

/* Table 6.4.3.13-1: Radio Device Status IE field definitions: Status flag */
static const value_string rds_status_vals[] = {
	{ 0, "Reserved" },
	{ 1, "Memory Full" },
	{ 2, "Normal operation resumed" },
	{ 3, "Reserved" },
	{ 0, NULL }
};

/* Table 6.4.3.13-1: Radio Device Status IE field definitions: Duration */
static const value_string rds_duration_vals[] = {
	{ 0, "50 ms" },
	{ 1, "100 ms" },
	{ 2, "200 ms" },
	{ 3, "400 ms" },
	{ 4, "600 ms" },
	{ 5, "800 ms" },
	{ 6, "1 000 ms" },
	{ 7, "1 500 ms" },
	{ 8, "2 000 ms" },
	{ 9, "3 000 ms" },
	{ 10, "4 000 ms" },
	{ 11, "Unknown" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* ETSI TS 103 636-5: DLC and Convergence layer definitions */

/* Table 5.3.1-1: DLC IE Type coding */
static const value_string dlc_ie_type_vals[] = {
	{ 0, "Data: DLC Service type 0 with routing header" },
	{ 1, "Data: DLC Service type 0 without routing header" },
	{ 2, "Data: DLC Service type 1 or 2 or 3 with routing header" },
	{ 3, "Data: DLC Service type 1 or 2 or 3 without routing header" },
	{ 4, "DLC Timers configuration control IE" },
	{ 14, "Escape" },
	{ 0, NULL }
};

/* Table 5.3.3.1-1: DLC SI coding */
static const value_string dlc_si_type_vals[] = {
	{ 0, "Data field contains the complete higher layer SDU" },
	{ 1, "Data field contains the first segment of the higher layer SDU" },
	{ 2, "Data field contains the last segment of the higher layer SDU" },
	{ 3, "Data field contains neither the first nor the last segment of the higher layer SDU" },
	{ 0, NULL }
};

/* Table 5.3.3.2-2: TX_SDU_discard_timer and RX_PDU_discard_timer */
static const value_string dlc_discard_timer_vals[] = {
	{ 0, "Reserved" },
	{ 1, "0.5 ms" },
	{ 2, "1 ms" },
	{ 3, "5 ms" },
	{ 4, "10 ms" },
	{ 5, "20 ms" },
	{ 6, "30 ms" },
	{ 7, "40 ms" },
	{ 8, "50 ms" },
	{ 9, "60 ms" },
	{ 10, "70 ms" },
	{ 11, "80 ms" },
	{ 12, "90 ms" },
	{ 13, "100 ms" },
	{ 14, "150 ms" },
	{ 15, "200 ms" },
	{ 16, "250 ms" },
	{ 17, "300 ms" },
	{ 18, "500 ms" },
	{ 19, "750 ms" },
	{ 20, "1 s" },
	{ 21, "1.5 s" },
	{ 22, "2 s" },
	{ 23, "2.5 s" },
	{ 24, "3 s" },
	{ 25, "4 s" },
	{ 26, "5 s" },
	{ 27, "6 s" },
	{ 28, "8 s" },
	{ 29, "16 s" },
	{ 30, "32 s" },
	{ 31, "60 s" },
	/* 32 - 254 Reserved */
	{ 255, "Infinity" },
	{ 0, NULL }
};

/* ETSI TS 103 636-5 Table 5.3.4-1: A routing bitmap field - bit definition */
static const value_string dlc_qos_vals[] = {
	{ 0, "Low priority data" },
	{ 1, "Reserved" },
	{ 2, "Reserved" },
	{ 3, "High priority data" },
	{ 4, "Reserved" },
	{ 5, "Reserved" },
	{ 6, "High priority signalling" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* ETSI TS 103 636-5 Table 5.3.4-1: A routing bitmap field - bit definition */
static const value_string dlc_hop_count_limit_vals[] = {
	{ 0, "Hop-count and Hop-limit are not present" },
	{ 1, "Hop-count is present and Hop-limit is not present" },
	{ 2, "Hop-count and Hop-limit are present" },
	{ 3, "Reserved" },
	{ 0, NULL }
};

/* ETSI TS 103 636-5 Table 5.3.4-1: A routing bitmap field - bit definition */
static const value_string dlc_dest_add_vals[] = {
	{ 0, "Destination and Source addresses are present" },
	{ 1, "Destination address is broadcast" },
	{ 2, "Destination address is backend" },
	{ 3, "Source address is backend" },
	{ 4, "Source address is backend and Destination address is broadcast" },
	{ 5, "Reserved" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* ETSI TS 103 636-5 Table 5.3.4-1: A routing bitmap field - bit definition */
static const value_string dlc_routing_type_vals[] = {
	{ 0, "Uplink hop by hop routing for Packet Routing to backend (uplink)" },
	{ 1, "Reserved" },
	{ 2, "Reserved" },
	{ 3, "Downlink flooding for Packet Routing from backend (downlink)" },
	{ 4, "Reserved" },
	{ 5, "Local flooding RD to RD, or RD to multicast Group, for Hop-limited flooding" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* DLC Reassembly */

static const fragment_items dect_nr_segment_items = {
	/* Segment subtrees */
	&ett_dect_nr_segment,
	&ett_dect_nr_segments,
	/* Segment fields */
	&hf_dect_nr_segments,
	&hf_dect_nr_segment,
	&hf_dect_nr_segment_overlap,
	&hf_dect_nr_segment_overlap_conflict,
	&hf_dect_nr_segment_multiple_tails,
	&hf_dect_nr_segment_too_long_segment,
	&hf_dect_nr_segment_error,
	&hf_dect_nr_segment_count,
	/* Reassembled in field */
	&hf_dect_nr_reassembled_in,
	/* Reassembled length field */
	&hf_dect_nr_reassembled_length,
	/* Reassembled data field */
	NULL,
	/* Tag */
	"DLC PDU segments"
};

typedef struct {
	uint32_t tx_id;
	uint32_t rx_id;
	uint32_t ie_type;
	uint32_t ie_length;
	bool ie_length_present;
} dect_nr_context_t;

typedef struct {
	uint32_t tx_id;
	uint32_t rx_id;
	uint32_t ie_type;
	uint32_t sn;
} dect_nr_fragment_key_t;

static unsigned dect_nr_reassembly_hash_func(const void *k)
{
	dect_nr_fragment_key_t *key = (dect_nr_fragment_key_t *)k;
	unsigned hash_val;

	hash_val = key->sn;

	return hash_val;
}

static int dect_nr_reassembly_equal_func(const void *k1, const void *k2)
{
	dect_nr_fragment_key_t *key1 = (dect_nr_fragment_key_t *)k1;
	dect_nr_fragment_key_t *key2 = (dect_nr_fragment_key_t *)k2;

	return ((key1->tx_id == key2->tx_id) && (key1->rx_id == key2->rx_id) && (key1->sn == key2->sn));
}

static void *dect_nr_reassembly_key_func(const packet_info *pinfo _U_, uint32_t id, const void *data)
{
	dect_nr_fragment_key_t *key = g_slice_new(dect_nr_fragment_key_t);
	dect_nr_context_t *ctx = (dect_nr_context_t *)data;

	key->tx_id = ctx->tx_id;
	key->rx_id = ctx->rx_id;
	key->ie_type = ctx->ie_type;
	key->sn = id;

	return (void *)key;
}

static void dect_nr_reassembly_free_key_func(void *ptr)
{
	dect_nr_fragment_key_t *key = (dect_nr_fragment_key_t *)ptr;
	g_slice_free(dect_nr_fragment_key_t, key);
}

static const reassembly_table_functions dect_nr_reassembly_functions = {
	dect_nr_reassembly_hash_func,
	dect_nr_reassembly_equal_func,
	dect_nr_reassembly_key_func,
	dect_nr_reassembly_key_func,
	dect_nr_reassembly_free_key_func,
	dect_nr_reassembly_free_key_func,
};

static reassembly_table dect_nr_reassembly_table;

/* Add expert info to reserved bits which is not zero */
static void dect_tree_add_reserved_item(proto_tree *tree, int hf_index, tvbuff_t *tvb, int offset, int length, packet_info *pinfo, const unsigned encoding)
{
	uint32_t reserved;
	proto_item *item;

	item = proto_tree_add_item_ret_uint(tree, hf_index, tvb, offset, length, encoding, &reserved);
	if (reserved != 0) {
		expert_add_info(pinfo, item, &ei_dect_nr_res_non_zero);
	}
}

/* Add expert info if IE length is -1 */
static int dect_tree_add_expected_item(proto_tree *tree, int hf_index, tvbuff_t *tvb, int offset, int length, packet_info *pinfo, const unsigned encoding)
{
	if (length != -1) {
		proto_tree_add_item(tree, hf_index, tvb, offset, length, encoding);
		offset += length;
	} else {
		/* Unknown IE length */
		expert_add_info(pinfo, tree, &ei_dect_nr_ie_length_not_set);
		offset += tvb_reported_length_remaining(tvb, offset);
	}

	return offset;
}

/* ETSI TS 103 636-2 Table 8.2.3-1: RSSI-1 measurement report mapping */
static void format_rssi_result_cf_func(char *result, uint32_t value)
{
	if (value == 0x74) {
		snprintf(result, ITEM_LABEL_LENGTH, "x ≤ -139.5 dBm");
	} else if (value > 0x74 && value <= 0xFE) {
		double x = (0xFF - value + 1) * -1.0;
		snprintf(result, ITEM_LABEL_LENGTH, "%.1f ≤ x < %.1f dBm", x + 0.5, x - 0.5);
	} else if (value == 0xFF) {
		snprintf(result, ITEM_LABEL_LENGTH, "-1.5 < x dBm");
	} else {
		snprintf(result, ITEM_LABEL_LENGTH, "Reserved");
	}
}

/* ETSI TS 103 636-2 Table 8.4.3-1: Demodulated signal to noise quality measurement report mapping */
static void format_snr_result_cf_func(char *result, uint32_t value)
{
	if (value < 0x7F) {
		double x = value * 0.5;
		snprintf(result, ITEM_LABEL_LENGTH, "%.2f ≤ x < %.2f dB", x - 0.25, x + 0.25);
	} else if (value == 0x7F) {
		snprintf(result, ITEM_LABEL_LENGTH, "63.25 ≤ x");
	} else if (value == 0xE0) {
		snprintf(result, ITEM_LABEL_LENGTH, "x < -15.75");
	} else if (value > 0xE0 && value <= 0xFF) {
		double x = (0xFF - value + 1) * -0.5;
		snprintf(result, ITEM_LABEL_LENGTH, "%.2f ≤ x < %.2f dB", x - 0.25, x + 0.25);
	} else {
		snprintf(result, ITEM_LABEL_LENGTH, "Reserved");
	}
}

/* Table 6.4.3.10-1: Load Info IE field definitions */
static void format_hex_pct_cf_func(char *result, uint32_t value)
{
	snprintf(result, ITEM_LABEL_LENGTH, "%.2f %%", (value * 100.0) / 255.0);
}

/* 6.2: Physical Header Field */
static int dissect_physical_header_field(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, dect_nr_context_t *ctx)
{
	uint32_t header_format = 0;
	bool len_type;
	int plcf;

	if (phf_type_pref == PHF_TYPE_TYPE_AUTO) {
		/* Physical Header Field Type is determined from 6th and 7th packet byte.
		 * For Type 1 they are always zero.
		 * (Type 1: 40 bits (HF 000), or Type 2: 80 bits, (HF 000 or 001))
		 */
		plcf = (tvb_get_ntohs(tvb, offset + 5) == 0) ? PHF_TYPE_TYPE_1 : PHF_TYPE_TYPE_2;
	} else {
		plcf = phf_type_pref;
	}

	/* In dect_nr, device always reserves 10 bytes for the PHF.
	 * If 5-byte version used, the remaining 5 bytes is just padding.
	 */
	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_phf, tvb, offset, 10, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_phf);

	proto_item_append_text(item, " (%s)", val_to_str_const(plcf, dect_plcf_size_vals, "Unknown"));

	if (plcf == PHF_TYPE_TYPE_1) {
		proto_tree_add_item(tree, hf_dect_nr_header_format_type1, tvb, offset, 1, ENC_BIG_ENDIAN);
	} else {
		proto_tree_add_item_ret_uint(tree, hf_dect_nr_header_format_type2, tvb, offset, 1, ENC_BIG_ENDIAN, &header_format);
	}
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_len_type, tvb, offset, 1, ENC_BIG_ENDIAN, &len_type);
	if (len_type) {
		proto_tree_add_item(tree, hf_dect_nr_packet_len_slots, tvb, offset, 1, ENC_BIG_ENDIAN);
	} else {
		proto_tree_add_item(tree, hf_dect_nr_packet_len_subslots, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	offset++;

	proto_tree_add_item(tree, hf_dect_nr_short_nw_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item_ret_uint(tree, hf_dect_nr_transmitter_id, tvb, offset, 2, ENC_BIG_ENDIAN, &ctx->tx_id);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_nr_tx_pwr, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* DF MCS length is 3 bits in Type 1 header, and 4 bits in Type 2 header */
	if (plcf == PHF_TYPE_TYPE_2) {
		proto_tree_add_item(tree, hf_dect_nr_df_mcs_t2, tvb, offset, 1, ENC_BIG_ENDIAN);
	} else {
		dect_tree_add_reserved_item(tree, hf_dect_nr_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_df_mcs_t1, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	offset++;

	/* If 80-bit (type 2) PHF is used */
	if (plcf == PHF_TYPE_TYPE_2) {
		uint32_t fb_format;

		proto_tree_add_item_ret_uint(tree, hf_dect_nr_receiver_id, tvb, offset, 2, ENC_BIG_ENDIAN, &ctx->rx_id);
		offset += 2;

		proto_tree_add_item(tree, hf_dect_nr_spatial_streams, tvb, offset, 1, ENC_BIG_ENDIAN);
		if (header_format == 0) {
			proto_tree_add_item(tree, hf_dect_nr_df_red_version, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_df_ind, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_df_harq_proc, tvb, offset, 1, ENC_BIG_ENDIAN);
		} else {
			proto_tree_add_item(tree, hf_dect_nr_res1_hdr_format_001, tvb, offset, 1, ENC_BIG_ENDIAN);
		}
		offset++;

		proto_tree_add_item_ret_uint(tree, hf_dect_nr_fb_format, tvb, offset, 2, ENC_BIG_ENDIAN, &fb_format);

		switch (fb_format) {
		case 1: /* Format 1, Table 6.2.2-2a */
			proto_tree_add_item(tree, hf_dect_nr_fbi1_harq_pn, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi1_tx_fb, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi1_bs, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi1_cqi, tvb, offset, 2, ENC_BIG_ENDIAN);
			break;

		case 2: /* Format 2, Table 6.2.2-2b */
			proto_tree_add_item(tree, hf_dect_nr_fbi2_cb_index, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi2_mimo_fb, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi2_bs, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi2_cqi, tvb, offset, 2, ENC_BIG_ENDIAN);
			break;

		case 3: /* Format 3, Table 6.2.2-2c */
			proto_tree_add_item(tree, hf_dect_nr_fbi3_harq_pn_1, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi3_tx_fb_1, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi3_harq_pn_2, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi3_tx_fb_2, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi3_cqi, tvb, offset, 2, ENC_BIG_ENDIAN);
			break;

		case 4: /* Format 4, Table 6.2.2-2d */
			proto_tree_add_item(tree, hf_dect_nr_fbi4_harq_fb_bm, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi4_cqi, tvb, offset, 2, ENC_BIG_ENDIAN);
			break;

		case 5: /* Format 5, Table 6.2.2-2e */
			proto_tree_add_item(tree, hf_dect_nr_fbi5_harq_pn, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi5_tx_fb, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi5_mimo_fb, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi5_cb_index, tvb, offset, 2, ENC_BIG_ENDIAN);
			break;

		case 6: /* Format 6, Table 6.2.2-2f */
			/* Using this feedback info format implicitly means a Negative Acknowledgement (NACK)
			 * for the corresponding HARQ process. The HARQ retransmission with the process number
			 * shall use DF Redundancy Version 0.
			 */
			proto_tree_add_item(tree, hf_dect_nr_fbi6_harq_pn, tvb, offset, 2, ENC_BIG_ENDIAN);
			dect_tree_add_reserved_item(tree, hf_dect_nr_fbi6_res1, tvb, offset, 2, pinfo, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi6_bs, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_fbi6_cqi, tvb, offset, 2, ENC_BIG_ENDIAN);
			break;

		case 15: /* Escape */
			proto_tree_add_item(tree, hf_dect_nr_escape, tvb, offset, 2, ENC_NA);
			break;

		default:
			proto_tree_add_item(tree, hf_dect_nr_fb_info, tvb, offset, 2, ENC_BIG_ENDIAN);
			break;
		}
		offset += 2;
	} else if (phf_type_pref == PHF_TYPE_TYPE_AUTO) {
		ctx->rx_id = 0;
		proto_tree_add_item(tree, hf_dect_nr_phf_padding, tvb, offset, 5, ENC_NA);
		offset += 5;
	}

	return offset;
}

/* 6.3.3: MAC Common Header */
static int dissect_mac_common_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, uint32_t mac_hdr_type)
{
	proto_item *item;
	proto_tree *tree;
	uint32_t tx_addr;
	uint32_t rx_addr;

	switch (mac_hdr_type) {
	case 0: /* 6.3.3.1: Data MAC PDU Header */
		item = proto_tree_add_item(parent_tree, hf_dect_nr_data_hdr, tvb, offset, 2, ENC_NA);
		tree = proto_item_add_subtree(item, ett_dect_nr_data_hdr);

		proto_item_set_text(item, "MAC Common Header (Data MAC PDU Header)");
		dect_tree_add_reserved_item(tree, hf_dect_nr_data_hdr_res1, tvb, offset, 2, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_data_hdr_reset, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_data_hdr_sn, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;

	case 1: /* 6.3.3.2: Beacon Header */
		item = proto_tree_add_item(parent_tree, hf_dect_nr_bc_hdr, tvb, offset, 7, ENC_NA);
		tree = proto_item_add_subtree(item, ett_dect_nr_bc_hdr);

		proto_item_set_text(item, "MAC Common Header (Beacon Header)");
		proto_tree_add_item(tree, hf_dect_nr_bc_hdr_nw_id, tvb, offset, 3, ENC_BIG_ENDIAN);
		offset += 3;

		proto_tree_add_item_ret_uint(tree, hf_dect_nr_bc_hdr_tx_addr, tvb, offset, 4, ENC_BIG_ENDIAN, &tx_addr);
		col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "0x%08x", tx_addr);
		offset += 4;
		break;

	case 2: /* 6.3.3.3: Unicast Header */
		item = proto_tree_add_item(parent_tree, hf_dect_nr_uc_hdr, tvb, offset, 10, ENC_NA);
		tree = proto_item_add_subtree(item, ett_dect_nr_uc_hdr);

		proto_item_set_text(item, "MAC Common Header (Unicast Header)");
		dect_tree_add_reserved_item(tree, hf_dect_nr_uc_hdr_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_uc_hdr_rst, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_uc_hdr_mac_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(tree, hf_dect_nr_uc_hdr_sn, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item_ret_uint(tree, hf_dect_nr_uc_hdr_rx_addr, tvb, offset, 4, ENC_BIG_ENDIAN, &rx_addr);
		col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%08x", rx_addr);
		offset += 4;

		proto_tree_add_item_ret_uint(tree, hf_dect_nr_uc_hdr_tx_addr, tvb, offset, 4, ENC_BIG_ENDIAN, &tx_addr);
		col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "0x%08x", tx_addr);
		offset += 4;
		break;

	case 3: /* 6.3.3.4: RD Broadcasting Header */
		item = proto_tree_add_item(parent_tree, hf_dect_nr_rdbh_hdr, tvb, offset, 6, ENC_NA);
		tree = proto_item_add_subtree(item, ett_dect_nr_rdbh_hdr);

		proto_item_set_text(item, "MAC Common Header (RD Broadcasting Header)");
		dect_tree_add_reserved_item(tree, hf_dect_nr_rdbh_hdr_res1, tvb, offset, 2, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_rdbh_hdr_reset, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_rdbh_hdr_sn, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item_ret_uint(tree, hf_dect_nr_rdbh_hdr_tx_addr, tvb, offset, 4, ENC_BIG_ENDIAN, &tx_addr);
		col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "0x%08x", tx_addr);
		offset += 4;
		break;

	case 15: /* Escape */
	default:
		item = proto_tree_add_item(parent_tree, hf_dect_nr_undecoded, tvb, offset, -1, ENC_NA);
		expert_add_info(pinfo, item, &ei_dect_nr_undecoded);
		offset += tvb_reported_length_remaining(tvb, offset);
		break;
	}

	return offset;
}

/* DLC Routing Header */
static int dissect_dlc_routing_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	int start = offset;
	bool delay_field;
	uint32_t hop_count_limit;
	uint32_t dest_add;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_dlc_routing, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_dlc_routing);

	dect_tree_add_reserved_item(tree, hf_dect_nr_dlc_routing_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_dlc_routing_qos, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_dlc_routing_delay_field, tvb, offset, 1, ENC_BIG_ENDIAN, &delay_field);
	offset++;

	proto_tree_add_item_ret_uint(tree, hf_dect_nr_dlc_routing_hop_count_limit, tvb, offset, 1, ENC_BIG_ENDIAN, &hop_count_limit);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_dlc_routing_dest_add, tvb, offset, 1, ENC_BIG_ENDIAN, &dest_add);
	proto_tree_add_item(tree, hf_dect_nr_dlc_routing_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if (dest_add != 3 && dest_add != 4) {
		proto_tree_add_item(tree, hf_dect_nr_dlc_routing_src_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if (dest_add != 1 && dest_add != 2 && dest_add != 4) {
		proto_tree_add_item(tree, hf_dect_nr_dlc_routing_dst_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if (hop_count_limit == 1 || hop_count_limit == 2) {
		proto_tree_add_item(tree, hf_dect_nr_dlc_routing_hop_count, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (hop_count_limit == 2) {
		proto_tree_add_item(tree, hf_dect_nr_dlc_routing_hop_limit, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (delay_field) {
		proto_tree_add_item(tree, hf_dect_nr_dlc_routing_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	proto_item_set_len(item, offset - start);

	return offset;
}

static void dissect_dlc_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	heur_dtbl_entry_t *hdtbl_entry;

	switch (dlc_data_type_pref) {
	case DLC_DATA_TYPE_AUTO:
		/* No COL_INFO updates from the dect_nr dissector after heuristic */
		col_set_writable(pinfo->cinfo, COL_INFO, true);
		if (dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, parent_tree, &hdtbl_entry, NULL)) {
			col_prepend_fstr(pinfo->cinfo, COL_PROTOCOL, "DECT NR+/");
			col_set_writable(pinfo->cinfo, COL_INFO, false);
			break;
		}
		/* FALLTHRU */

	case DLC_DATA_TYPE_BINARY:
		/* No COL_INFO updates from the data dissector */
		col_set_writable(pinfo->cinfo, COL_INFO, false);
		call_dissector(data_handle, tvb, pinfo, parent_tree);
		col_set_writable(pinfo->cinfo, COL_INFO, true);
		break;

	case DLC_DATA_TYPE_IPv6:
		/* No COL_INFO updates from the dect_nr dissector after IPv6 */
		col_set_writable(pinfo->cinfo, COL_INFO, true);
		call_dissector(ipv6_handle, tvb, pinfo, parent_tree);
		col_prepend_fstr(pinfo->cinfo, COL_PROTOCOL, "DECT NR+/");
		col_set_writable(pinfo->cinfo, COL_INFO, false);
		break;
	}
}

/* DLC Service Type */
static int dissect_dlc_service_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	int offset = 0;
	proto_item *uc_item;
	proto_item *data_item;
	uint32_t dlc_ie_type;
	uint32_t si = 0;
	uint32_t sn = 0;
	uint32_t segm_offset = 0;
	int data_len;
	uint32_t length;
	bool data_incomplete = false;
	tvbuff_t *subtvb;
	wmem_strbuf_t *data_info;
	wmem_strbuf_t *segm_info;

	dect_nr_context_t *ctx = (dect_nr_context_t *)data;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_dlc_pdu, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_dlc_pdu);

	length = tvb_captured_length_remaining(tvb, offset);

	if (!ctx->ie_length_present) {
		expert_add_info(pinfo, tree, &ei_dect_nr_ie_length_not_set);
		return offset + length;
	}

	if (length < ctx->ie_length) {
		/* DLC PDU not completely stored, try best effort */
		proto_item_set_len(item, length);

		if (length == 0) {
			col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "DLC PDU missing");
			return offset;
		}
	}

	proto_tree_add_item_ret_uint(tree, hf_dect_nr_dlc_ie_type, tvb, offset, 1, ENC_BIG_ENDIAN, &dlc_ie_type);

	switch (dlc_ie_type) {
	case 0: /* Data: DLC Service type 0 with routing header */
		dect_tree_add_reserved_item(tree, hf_dect_nr_dlc_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		offset++;

		offset = dissect_dlc_routing_header(tvb, offset, pinfo, tree);
		break;

	case 1: /* Data: DLC Service type 0 without a routing header */
		dect_tree_add_reserved_item(tree, hf_dect_nr_dlc_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		offset++;
		break;

	case 2: /* Data: DLC Service type 1 or 2 or 3 with routing header */
		proto_tree_add_item_ret_uint(tree, hf_dect_nr_dlc_si, tvb, offset, 1, ENC_BIG_ENDIAN, &si);
		proto_tree_add_item_ret_uint(tree, hf_dect_nr_dlc_sn, tvb, offset, 2, ENC_BIG_ENDIAN, &sn);
		offset += 2;

		/* Segmentation offset field is present if this is a data segment, and not the first or last one:
		 * 2 = the last segment of the higher layer SDU
		 * 3 = neither the first nor the last segment of the higher layer SDU
		 */
		if (si == 2 || si == 3) {
			proto_tree_add_item_ret_uint(tree, hf_dect_nr_dlc_segm_offset, tvb, offset, 2, ENC_BIG_ENDIAN, &segm_offset);
			offset += 2;
		}

		offset = dissect_dlc_routing_header(tvb, offset, pinfo, tree);
		break;

	case 3: /* Data: DLC Service type 1 or 2 or 3 without routing header */
		proto_tree_add_item_ret_uint(tree, hf_dect_nr_dlc_si, tvb, offset, 1, ENC_BIG_ENDIAN, &si);
		proto_tree_add_item_ret_uint(tree, hf_dect_nr_dlc_sn, tvb, offset, 2, ENC_BIG_ENDIAN, &sn);
		offset += 2;

		/* Segmentation offset field is present if this is a data segment, and not the first or last one:
		 * 2 = the last segment of the higher layer SDU
		 * 3 = neither the first nor the last segment of the higher layer SDU
		 */
		if (si == 2 || si == 3) {
			proto_tree_add_item_ret_uint(tree, hf_dect_nr_dlc_segm_offset, tvb, offset, 2, ENC_BIG_ENDIAN, &segm_offset);
			offset += 2;
		}
		break;

	case 4: /* DLC Timers configuration control IE */
		dect_tree_add_reserved_item(tree, hf_dect_nr_dlc_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(tree, hf_dect_nr_dlc_timers, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_item_set_len(item, offset);
		return offset;

	case 14: /* Escape */
		proto_tree_add_item(tree, hf_dect_nr_escape, tvb, offset, ctx->ie_length, ENC_NA);

		proto_item_set_len(item, offset);
		return offset + ctx->ie_length;

	default:
		uc_item = proto_tree_add_item(tree, hf_dect_nr_undecoded, tvb, offset, ctx->ie_length, ENC_NA);
		expert_add_info(pinfo, uc_item, &ei_dect_nr_undecoded);

		proto_item_set_len(item, offset);
		return offset + ctx->ie_length;
	}

	/* DLC SDU */

	length -= offset;
	if (length < (ctx->ie_length - offset)) {
		data_len = length;
		data_incomplete = true;
	} else {
		data_len = ctx->ie_length - offset;
	}

	data_item = proto_tree_add_item(tree, hf_dect_nr_hls_bin, tvb, offset, data_len, ENC_NA);
	segm_info = wmem_strbuf_create(pinfo->pool);

	if (dlc_ie_type == 2 || dlc_ie_type == 3) {
		fragment_head *frag_msg;

		if (si == 0) {
			wmem_strbuf_append_printf(segm_info, "SN %u, ", sn);
		} else if (si == 1) {
			wmem_strbuf_append_printf(segm_info, "SN %u (first segment), ", sn);
		} else if (si == 2) {
			wmem_strbuf_append_printf(segm_info, "SN %u (last segment at %u), ", sn, segm_offset);
		} else if (si == 3) {
			wmem_strbuf_append_printf(segm_info, "SN %u (segment at %u), ", sn, segm_offset);
		}

		/* Reassemble segments */
		frag_msg = fragment_add_seq_next(&dect_nr_reassembly_table, tvb, offset, pinfo,
						 sn, ctx, data_len, (si == 1 || si == 3));
		subtvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled DLC",
						  frag_msg, &dect_nr_segment_items, NULL, tree);
	} else {
		subtvb = tvb_new_subset_length(tvb, offset, data_len);
	}

	data_info = wmem_strbuf_create(pinfo->pool);
	wmem_strbuf_append_printf(data_info, " [ %s%d bytes ]",
				  wmem_strbuf_finalize(segm_info), ctx->ie_length);

	if (subtvb) {
		dissect_dlc_data(subtvb, pinfo, proto_tree_get_root(tree));
	}
	offset += data_len;

	if (data_incomplete) {
		wmem_strbuf_append(data_info, " [data incomplete]");
		expert_add_info(pinfo, data_item, &ei_dect_nr_pdu_cut_short);
	}

	col_append_str(pinfo->cinfo, COL_INFO, wmem_strbuf_finalize(data_info));
	proto_item_set_len(item, offset);

	return offset;
}

/* Higher layer signalling - flow 1 */
static int dissect_higher_layer_sig_flow_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	return dissect_dlc_service_type(tvb, pinfo, parent_tree, data);
}

/* Higher layer signalling - flow 2 */
static int dissect_higher_layer_sig_flow_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	return dissect_dlc_service_type(tvb, pinfo, parent_tree, data);
}

/* User plane data - flow 1*/
static int dissect_user_plane_data_flow_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	return dissect_dlc_service_type(tvb, pinfo, parent_tree, data);
}

/* User plane data - flow 2 */
static int dissect_user_plane_data_flow_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	return dissect_dlc_service_type(tvb, pinfo, parent_tree, data);
}

/* User plane data - flow 3 */
static int dissect_user_plane_data_flow_3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	return dissect_dlc_service_type(tvb, pinfo, parent_tree, data);
}

/* User plane data - flow 4 */
static int dissect_user_plane_data_flow_4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	return dissect_dlc_service_type(tvb, pinfo, parent_tree, data);
}

/* 6.4.2.2: Network Beacon message */
static int dissect_network_beacon_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	bool tx_pwr_field;
	bool nb_current_field;
	uint32_t nb_channels;
	uint32_t nb_period;
	uint32_t cb_period;
	uint32_t cluster_chan;
	uint32_t ttn;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_nb_msg, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_nb_msg);

	dect_tree_add_reserved_item(tree, hf_dect_nr_nb_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_nb_tx_pwr_field, tvb, offset, 1, ENC_BIG_ENDIAN, &tx_pwr_field);
	proto_tree_add_item(tree, hf_dect_nr_nb_pwr_const, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_nb_current_field, tvb, offset, 1, ENC_BIG_ENDIAN, &nb_current_field);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_nb_channels, tvb, offset, 1, ENC_BIG_ENDIAN, &nb_channels);
	offset++;

	proto_tree_add_item_ret_uint(tree, hf_dect_nr_nb_nb_period, tvb, offset, 1, ENC_BIG_ENDIAN, &nb_period);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_nb_cb_period, tvb, offset, 1, ENC_BIG_ENDIAN, &cb_period);
	offset++;

	dect_tree_add_reserved_item(tree, hf_dect_nr_nb_res2, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_nb_next_cl_chan, tvb, offset, 2, ENC_BIG_ENDIAN, &cluster_chan);
	offset += 2;

	proto_tree_add_item_ret_uint(tree, hf_dect_nr_nb_time_to_next, tvb, offset, 4, ENC_BIG_ENDIAN, &ttn);
	offset += 4;

	if (tx_pwr_field) {
		dect_tree_add_reserved_item(tree, hf_dect_nr_nb_res3, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_nb_cl_max_tx_pwr, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (nb_current_field) {
		dect_tree_add_reserved_item(tree, hf_dect_nr_nb_res4, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_nb_curr_cl_chan, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	for (uint32_t i = 0; i < nb_channels; i++) {
		dect_tree_add_reserved_item(tree, hf_dect_nr_nb_res5, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_nb_addn_nb_channels, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, " (%s, Cluster: %u (%s), TTN: %u µs)",
			val_to_str_const(nb_period, nb_ie_nb_period_vals, "Unknown"), cluster_chan,
			val_to_str_const(cb_period, nb_ie_cb_period_vals, "Unknown"), ttn);
	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.2.3: Cluster Beacon message */
static int dissect_cluster_beacon_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	bool tx_pwr_field;
	bool fo_field;
	bool next_chan_field;
	bool ttn_field;
	uint32_t cb_period;

	wmem_strbuf_t *next_chan_info = wmem_strbuf_create(pinfo->pool);

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_cb_msg, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_cb_msg);

	proto_tree_add_item(tree, hf_dect_nr_cb_sfn, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	dect_tree_add_reserved_item(tree, hf_dect_nr_cb_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_cb_tx_pwr_field, tvb, offset, 1, ENC_BIG_ENDIAN, &tx_pwr_field);
	proto_tree_add_item(tree, hf_dect_nr_cb_pwr_const, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_cb_fo_field, tvb, offset, 1, ENC_BIG_ENDIAN, &fo_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_cb_next_chan_field, tvb, offset, 1, ENC_BIG_ENDIAN, &next_chan_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_cb_time_to_next_field, tvb, offset, 1, ENC_BIG_ENDIAN, &ttn_field);
	offset++;

	proto_tree_add_item(tree, hf_dect_nr_cb_nb_period, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_cb_cb_period, tvb, offset, 1, ENC_BIG_ENDIAN, &cb_period);
	offset++;

	proto_tree_add_item(tree, hf_dect_nr_cb_ctt, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_cb_rel_qual, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_cb_min_qual, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if (tx_pwr_field) {
		dect_tree_add_reserved_item(tree, hf_dect_nr_cb_res2, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_cb_cl_max_tx_pwr, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (fo_field) {
		proto_tree_add_item(tree, hf_dect_nr_cb_frame_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (next_chan_field) {
		uint32_t next_chan;

		dect_tree_add_reserved_item(tree, hf_dect_nr_cb_res3, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item_ret_uint(tree, hf_dect_nr_cb_next_cl_chan, tvb, offset, 2, ENC_BIG_ENDIAN, &next_chan);
		wmem_strbuf_append_printf(next_chan_info, ", Next channel: %u", next_chan);
		offset += 2;
	}

	if (ttn_field) {
		proto_tree_add_item(tree, hf_dect_nr_cb_time_to_next, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, " (%s%s)",
			val_to_str_const(cb_period, nb_ie_cb_period_vals, "Unknown"),
			wmem_strbuf_finalize(next_chan_info));
	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.2.4: Association Request message */
static int dissect_association_request_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	uint32_t setup_cause;
	uint32_t num_flows;
	bool ft_mode_field;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_a_req_msg, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_a_req_msg);

	proto_tree_add_item_ret_uint(tree, hf_dect_nr_a_req_setup_cause, tvb, offset, 1, ENC_BIG_ENDIAN, &setup_cause);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_a_req_num_flows, tvb, offset, 1, ENC_BIG_ENDIAN, &num_flows);
	proto_tree_add_item(tree, hf_dect_nr_a_req_pwr_const, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_a_req_ft_mode_field, tvb, offset, 1, ENC_BIG_ENDIAN, &ft_mode_field);
	offset++;

	proto_tree_add_item(tree, hf_dect_nr_a_req_current, tvb, offset, 1, ENC_BIG_ENDIAN);
	dect_tree_add_reserved_item(tree, hf_dect_nr_a_req_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_dect_nr_a_req_harq_proc_tx, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_a_req_max_harq_retx, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_dect_nr_a_req_harq_proc_rx, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_a_req_max_harq_rerx, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* Value 7 is 'Reserved' */
	if (num_flows < 7) {
		for (uint32_t i = 0; i < num_flows; i++) {
			dect_tree_add_reserved_item(tree, hf_dect_nr_a_req_res2, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_a_req_flow_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
		}
	}

	if (ft_mode_field) {
		/* Table 6.4.2.4-1: "The RD operates also in FT mode. RD shall include Network Beacon period,
		 * Cluster beacon Period, Next Cluster channel and Time to next fields"
		 */
		proto_tree_add_item(tree, hf_dect_nr_a_req_nb_period, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_a_req_cb_period, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(tree, hf_dect_nr_a_req_next_cl_chan, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(tree, hf_dect_nr_a_req_time_to_next, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_dect_nr_a_req_curr_cl_chan, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str_const(setup_cause, ar_setup_cause_vals, "Unknown"));
	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.2.5: Association Response message */
static int dissect_association_response_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	bool ack_field;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_a_rsp_msg, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_a_rsp_msg);

	/* The first octet contains the ACK flag */
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_a_rsp_ack_field, tvb, offset, 1, ENC_BIG_ENDIAN, &ack_field);

	if (ack_field) { /* Association accepted */
		bool harq_mod_field;
		uint32_t num_flows;
		bool group_field;

		dect_tree_add_reserved_item(tree, hf_dect_nr_a_rsp_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item_ret_boolean(tree, hf_dect_nr_a_rsp_harq_mod_field, tvb, offset, 1, ENC_BIG_ENDIAN, &harq_mod_field);
		proto_tree_add_item_ret_uint(tree, hf_dect_nr_a_rsp_num_flows, tvb, offset, 1, ENC_BIG_ENDIAN, &num_flows);
		proto_tree_add_item_ret_boolean(tree, hf_dect_nr_a_rsp_group_field, tvb, offset, 1, ENC_BIG_ENDIAN, &group_field);
		dect_tree_add_reserved_item(tree, hf_dect_nr_a_rsp_res2, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		offset++;

		if (harq_mod_field) {
			/* HARQ configuration was not accepted as requested -> HARQ configuration is present */
			proto_tree_add_item(tree, hf_dect_nr_a_rsp_harq_proc_rx, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_a_rsp_max_harq_rerx, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;

			proto_tree_add_item(tree, hf_dect_nr_a_rsp_harq_proc_tx, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_a_rsp_max_harq_retx, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
		}

		/* Value 7 indicates 'All flows accepted as configured in Association Request' */
		if (num_flows < 7) {
			for (uint32_t i = 0; i < num_flows; i++) {
				dect_tree_add_reserved_item(tree, hf_dect_nr_a_rsp_res3, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_dect_nr_a_rsp_flow_id, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
			}
		}

		if (group_field) {
			/* Group ID and Resource Tag are included */
			dect_tree_add_reserved_item(tree, hf_dect_nr_a_rsp_res4, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_a_rsp_group_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;

			dect_tree_add_reserved_item(tree, hf_dect_nr_a_rsp_res5, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_a_rsp_res_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
		}

		col_append_str(pinfo->cinfo, COL_INFO, " (Accepted)");
	} else { /* Association Rejected */
		uint32_t rej_cause;

		dect_tree_add_reserved_item(tree, hf_dect_nr_a_rsp_res6, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item_ret_uint(tree, hf_dect_nr_a_rsp_rej_cause, tvb, offset, 1, ENC_BIG_ENDIAN, &rej_cause);
		proto_tree_add_item(tree, hf_dect_nr_a_rsp_rej_timer, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		col_append_fstr(pinfo->cinfo, COL_INFO, " (Rejected cause: %s)", val_to_str_const(rej_cause, assoc_rej_cause_vals, "Unknown"));
	}

	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.2.6: Association Release message */
static int dissect_association_release_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	uint32_t rel_cause;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_a_rel_msg, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_a_rel_msg);

	proto_tree_add_item_ret_uint(tree, hf_dect_nr_a_rel_cause, tvb, offset, 1, ENC_BIG_ENDIAN, &rel_cause);
	dect_tree_add_reserved_item(tree, hf_dect_nr_a_rel_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	offset++;

	col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str_const(rel_cause, assoc_rel_cause_vals, "Unknown"));
	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.2.7: Reconfiguration Request message */
static int dissect_reconfiguration_request_msg(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	bool tx_harq_field;
	bool rx_harq_field;
	uint32_t num_flows;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_rc_req_msg, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_rc_req_msg);

	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_rc_req_tx_harq_field, tvb, offset, 1, ENC_BIG_ENDIAN, &tx_harq_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_rc_req_rx_harq_field, tvb, offset, 1, ENC_BIG_ENDIAN, &rx_harq_field);
	proto_tree_add_item(tree, hf_dect_nr_rc_req_rd_capability, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_rc_req_num_flows, tvb, offset, 1, ENC_BIG_ENDIAN, &num_flows);
	proto_tree_add_item(tree, hf_dect_nr_rc_req_radio_resources, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if (tx_harq_field) {
		proto_tree_add_item(tree, hf_dect_nr_rc_req_harq_proc_tx, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_rc_req_max_harq_retx, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (rx_harq_field) {
		proto_tree_add_item(tree, hf_dect_nr_rc_req_harq_proc_rx, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_rc_req_max_harq_rerx, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	for (uint32_t i = 0; i < num_flows; i++) {
		proto_tree_add_item(tree, hf_dect_nr_rc_req_setup_release, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_rc_req_res, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_rc_req_flow_id, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.2.8: Reconfiguration Response message */
static int dissect_reconfiguration_response_msg(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	bool tx_harq_field;
	bool rx_harq_field;
	uint32_t num_flows;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_rc_rsp_msg, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_rc_rsp_msg);

	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_rc_rsp_tx_harq_field, tvb, offset, 1, ENC_BIG_ENDIAN, &tx_harq_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_rc_rsp_rx_harq_field, tvb, offset, 1, ENC_BIG_ENDIAN, &rx_harq_field);
	proto_tree_add_item(tree, hf_dect_nr_rc_rsp_rd_capability, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_rc_rsp_num_flows, tvb, offset, 1, ENC_BIG_ENDIAN, &num_flows);
	proto_tree_add_item(tree, hf_dect_nr_rc_rsp_radio_resources, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if (tx_harq_field) {
		proto_tree_add_item(tree, hf_dect_nr_rc_rsp_harq_proc_tx, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_rc_rsp_max_harq_retx, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (rx_harq_field) {
		proto_tree_add_item(tree, hf_dect_nr_rc_rsp_harq_proc_rx, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_rc_rsp_max_harq_rerx, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	/* Value 7 indicates 'All flows accepted as configured in the Reconfiguration Request' */
	if (num_flows < 7) {
		for (uint32_t i = 0; i < num_flows; i++) {
			proto_tree_add_item(tree, hf_dect_nr_rc_rsp_setup_release, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_rc_rsp_res, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_rc_rsp_flow_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
		}
	}

	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.3.1: MAC Security Info IE */
static int dissect_security_info_ie(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_msi_ie, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_msi_ie);

	proto_tree_add_item(tree, hf_dect_nr_msi_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_msi_key, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_msi_ivt, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_dect_nr_msi_hpc, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.3.2: Route Info IE */
static int dissect_route_info_ie(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_ri_ie, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_ri_ie);

	proto_tree_add_item(tree, hf_dect_nr_ri_sink_address, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_nr_ri_route_cost, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_dect_nr_ri_application_sn, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.3.3: Resource Allocation IE */
static int dissect_resource_allocation_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	int offset = 0;
	uint32_t allocation_type;
	bool add_field;
	bool id_field;
	uint32_t repeat;
	bool sfn_field;
	bool channel_field;
	bool rlf_field;
	bool use_9_bits = false;

	dect_nr_context_t *ctx = (dect_nr_context_t *)data;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_ra_ie, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_ra_ie);

	proto_tree_add_item_ret_uint(tree, hf_dect_nr_ra_alloc_type, tvb, offset, 1, ENC_BIG_ENDIAN, &allocation_type);

	if (allocation_type == 0) {
		/* The receiving RD shall release all previously allocated scheduled resources.
		 * No other fields are present in this IE.
		 */
		dect_tree_add_reserved_item(tree, hf_dect_nr_ra_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		offset++;

		proto_item_set_len(item, 1);

		return offset;
	}

	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_ra_add_field, tvb, offset, 1, ENC_BIG_ENDIAN, &add_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_ra_id_field, tvb, offset, 1, ENC_BIG_ENDIAN, &id_field);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_ra_repeat, tvb, offset, 1, ENC_BIG_ENDIAN, &repeat);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_ra_sfn_field, tvb, offset, 1, ENC_BIG_ENDIAN, &sfn_field);
	offset++;

	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_ra_channel_field, tvb, offset, 1, ENC_BIG_ENDIAN, &channel_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_ra_rlf_field, tvb, offset, 1, ENC_BIG_ENDIAN, &rlf_field);
	dect_tree_add_reserved_item(tree, hf_dect_nr_ra_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	offset++;

	/* 8 bits or 9 bits. The start subslot indicates the first subslot where the resource allocation
	 * is valid in the indicated frame. The indicated frame depends on the SFN field.
	 * The 8 bits version is used when µ ≤ 4 and the 9 bits version is used when µ > 4.
	 */

	if (ctx->ie_length_present) {
		/* Determine 8 bits or 9 bits based on expected length */
		uint32_t len = 2 + (allocation_type == 3 ? 4 : 2) + (id_field ? 2 : 0) + (repeat ? 2 : 0) +
				   (sfn_field ? 1 : 0) + (channel_field ? 2 : 0) + (rlf_field ? 1 : 0);
		if (ctx->ie_length == len + (allocation_type == 3 ? 2 : 1)) {
			/* 9 bits version */
			use_9_bits = true;
		}
	}

	if (allocation_type == 3) {
		if (use_9_bits) {
			dect_tree_add_reserved_item(tree, hf_dect_nr_ra_res2, tvb, offset, 2, pinfo, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_ra_start_ss_dl_9, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		} else {
			proto_tree_add_item(tree, hf_dect_nr_ra_start_ss_dl_8, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
		}

		proto_tree_add_item(tree, hf_dect_nr_ra_len_type_dl, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_ra_len_dl, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		if (use_9_bits) {
			dect_tree_add_reserved_item(tree, hf_dect_nr_ra_res2, tvb, offset, 2, pinfo, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_ra_start_ss_ul_9, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		} else {
			proto_tree_add_item(tree, hf_dect_nr_ra_start_ss_ul_8, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
		}

		proto_tree_add_item(tree, hf_dect_nr_ra_len_type_ul, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_ra_len_ul, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

	} else {
		if (use_9_bits) {
			if (allocation_type == 1) {
				dect_tree_add_reserved_item(tree, hf_dect_nr_ra_res2, tvb, offset, 2, pinfo, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_dect_nr_ra_start_ss_dl_9, tvb, offset, 2, ENC_BIG_ENDIAN);
			} else {
				dect_tree_add_reserved_item(tree, hf_dect_nr_ra_res2, tvb, offset, 2, pinfo, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_dect_nr_ra_start_ss_ul_9, tvb, offset, 2, ENC_BIG_ENDIAN);
			}
			offset += 2;
		} else {
			if (allocation_type == 1) {
				proto_tree_add_item(tree, hf_dect_nr_ra_start_ss_dl_8, tvb, offset, 1, ENC_BIG_ENDIAN);
			} else {
				proto_tree_add_item(tree, hf_dect_nr_ra_start_ss_ul_8, tvb, offset, 1, ENC_BIG_ENDIAN);
			}
			offset++;
		}

		if (allocation_type == 1) {
			proto_tree_add_item(tree, hf_dect_nr_ra_len_type_dl, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_ra_len_dl, tvb, offset, 1, ENC_BIG_ENDIAN);
		} else {
			proto_tree_add_item(tree, hf_dect_nr_ra_len_type_ul, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_dect_nr_ra_len_ul, tvb, offset, 1, ENC_BIG_ENDIAN);
		}
		offset++;
	}

	if (id_field) {
		proto_tree_add_item(tree, hf_dect_nr_ra_short_rd_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	if (repeat) {
		proto_tree_add_item(tree, hf_dect_nr_ra_repetition, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(tree, hf_dect_nr_ra_validity, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (sfn_field) {
		proto_tree_add_item(tree, hf_dect_nr_ra_sfn_value, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (channel_field) {
		dect_tree_add_reserved_item(tree, hf_dect_nr_ra_res3, tvb, offset, 2, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_ra_channel, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	if (rlf_field) {
		dect_tree_add_reserved_item(tree, hf_dect_nr_ra_res4, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_ra_rlf, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.3.4: Random Access Resource IE */
static int dissect_random_access_resource_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	int offset = 0;
	uint32_t rar_repeat;
	bool rar_sfn_field;
	bool rar_channel_field;
	bool rar_chan_2_field;
	bool use_9_bits = false;

	dect_nr_context_t *ctx = (dect_nr_context_t *)data;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_rar_ie, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_rar_ie);

	dect_tree_add_reserved_item(tree, hf_dect_nr_rar_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_rar_repeat, tvb, offset, 1, ENC_BIG_ENDIAN, &rar_repeat);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_rar_sfn_field, tvb, offset, 1, ENC_BIG_ENDIAN, &rar_sfn_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_rar_channel_field, tvb, offset, 1, ENC_BIG_ENDIAN, &rar_channel_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_rar_chan_2_field, tvb, offset, 1, ENC_BIG_ENDIAN, &rar_chan_2_field);
	offset++;

	/* 8 bits or 9 bits. The start subslot indicates the first subslot where the RACH
	 * resource allocation is valid in the frame.
	 * The 8 bits version is used when µ ≤ 4 and the 9 bits version is used when µ > 4.
	 */

	if (ctx->ie_length_present) {
		/* Determine 8 bits or 9 bits based on expected length */
		uint32_t len = 4 + (rar_repeat ? 2 : 0) + (rar_sfn_field ? 1 : 0) +
				   (rar_channel_field ? 2 : 0) + (rar_chan_2_field ? 2 : 0);
		if (ctx->ie_length == len + 2) {
			/* 9 bits version */
			use_9_bits = true;
		}
	}

	if (use_9_bits) {
		dect_tree_add_reserved_item(tree, hf_dect_nr_rar_res2, tvb, offset, 2, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_rar_start_ss_9, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	} else {
		proto_tree_add_item(tree, hf_dect_nr_rar_start_ss_8, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	proto_tree_add_item(tree, hf_dect_nr_rar_len_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_rar_len, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_dect_nr_rar_max_len_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_rar_max_rach_len, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_rar_cw_min_sig, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_dect_nr_rar_dect_delay, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_rar_resp_win, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_rar_cw_max_sig, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if (rar_repeat) {
		proto_tree_add_item(tree, hf_dect_nr_rar_repetition, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(tree, hf_dect_nr_rar_validity, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (rar_sfn_field) {
		proto_tree_add_item(tree, hf_dect_nr_rar_sfn_value, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (rar_channel_field) {
		dect_tree_add_reserved_item(tree, hf_dect_nr_rar_res3, tvb, offset, 2, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_rar_channel, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	if (rar_chan_2_field) {
		dect_tree_add_reserved_item(tree, hf_dect_nr_rar_res3, tvb, offset, 2, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_rar_channel_2, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.3.5: RD Capability IE */
static int dissect_rd_capability_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	uint32_t num_phy_cap;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_rdc_ie, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_rdc_ie);
	proto_tree *phy_tree = tree;

	proto_tree_add_item_ret_uint(tree, hf_dect_nr_rdc_num_phy_cap, tvb, offset, 1, ENC_BIG_ENDIAN, &num_phy_cap);
	proto_tree_add_item(tree, hf_dect_nr_rdc_release, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	dect_tree_add_reserved_item(tree, hf_dect_nr_rdc_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_rdc_group_ass, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_rdc_paging, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_rdc_op_modes, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_rdc_mesh, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_rdc_sched, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_dect_nr_rdc_mac_security, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_rdc_dlc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	dect_tree_add_reserved_item(tree, hf_dect_nr_rdc_res2, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	offset++;

	for (uint32_t i = 0; i <= num_phy_cap; i++) {
		if (i > 0) {
			/* Put subsequent PHY layer capabilities in a subtree */
			proto_item *phy_item = proto_tree_add_item(tree, hf_dect_nr_rdc_phy_cap, tvb, offset, 5, ENC_NA);
			proto_item_append_text(phy_item, " %u", i);
			phy_tree = proto_item_add_subtree(phy_item, ett_dect_nr_rdc_phy_cap);

			/* Subsequent PHY layer capabilities begin with RD class µ and β */
			proto_tree_add_item(phy_tree, hf_dect_nr_rdc_rd_class_mu, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(phy_tree, hf_dect_nr_rdc_rd_class_b, tvb, offset, 1, ENC_BIG_ENDIAN);
			dect_tree_add_reserved_item(phy_tree, hf_dect_nr_rdc_res6, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
			offset++;
		}

		dect_tree_add_reserved_item(phy_tree, hf_dect_nr_rdc_res3, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(phy_tree, hf_dect_nr_rdc_pwr_class, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(phy_tree, hf_dect_nr_rdc_max_nss_rx, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(phy_tree, hf_dect_nr_rdc_rx_for_tx_div, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(phy_tree, hf_dect_nr_rdc_rx_gain, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(phy_tree, hf_dect_nr_rdc_max_mcs, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(phy_tree, hf_dect_nr_rdc_soft_buf_size, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(phy_tree, hf_dect_nr_rdc_num_harq_proc, tvb, offset, 1, ENC_BIG_ENDIAN);
		dect_tree_add_reserved_item(phy_tree, hf_dect_nr_rdc_res4, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(phy_tree, hf_dect_nr_rdc_harq_fb_delay, tvb, offset, 1, ENC_BIG_ENDIAN);
		if (i == 0) {
			proto_tree_add_item(phy_tree, hf_dect_nr_rdc_d_delay, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(phy_tree, hf_dect_nr_rdc_half_dup, tvb, offset, 1, ENC_BIG_ENDIAN);
			dect_tree_add_reserved_item(phy_tree, hf_dect_nr_rdc_res5, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		} else {
			dect_tree_add_reserved_item(phy_tree, hf_dect_nr_rdc_res7, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		}
		offset++;
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, " (Num PHY: %u)", num_phy_cap);
	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.3.6: Neighbouring IE */
static int dissect_neighbouring_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	bool id_field;
	bool mu_field;
	bool snr_field;
	bool rssi2_field;
	bool next_channel_field;
	bool time_to_next_field;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_n_ie, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_n_ie);

	dect_tree_add_reserved_item(tree, hf_dect_nr_n_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_n_id_field, tvb, offset, 1, ENC_BIG_ENDIAN, &id_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_n_mu_field, tvb, offset, 1, ENC_BIG_ENDIAN, &mu_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_n_snr_field, tvb, offset, 1, ENC_BIG_ENDIAN, &snr_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_n_rssi2_field, tvb, offset, 1, ENC_BIG_ENDIAN, &rssi2_field);
	proto_tree_add_item(tree, hf_dect_nr_n_pwr_const, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_n_next_channel_field, tvb, offset, 1, ENC_BIG_ENDIAN, &next_channel_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_n_ttn_field, tvb, offset, 1, ENC_BIG_ENDIAN, &time_to_next_field);
	offset++;

	proto_tree_add_item(tree, hf_dect_nr_n_nb_period, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_nr_n_cb_period, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if (id_field) {
		proto_tree_add_item(tree, hf_dect_nr_n_long_rd_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if (next_channel_field) {
		dect_tree_add_reserved_item(tree, hf_dect_nr_n_res2, tvb, offset, 2, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_n_next_cl_channel, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	if (time_to_next_field) {
		proto_tree_add_item(tree, hf_dect_nr_n_time_to_next, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	if (rssi2_field) {
		proto_tree_add_item(tree, hf_dect_nr_n_rssi2, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (snr_field) {
		proto_tree_add_item(tree, hf_dect_nr_n_snr, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (mu_field) {
		proto_tree_add_item(tree, hf_dect_nr_n_rd_class_u, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_n_rd_class_b, tvb, offset, 1, ENC_BIG_ENDIAN);
		dect_tree_add_reserved_item(tree, hf_dect_nr_n_res3, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		offset++;
	}

	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.3.7: Broadcast Indication IE */
static int dissect_broadcast_indication_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	uint32_t ind_type;
	uint32_t idtype;
	uint32_t feedback = 0;
	uint32_t rd_id;
	char *bi_target;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_bi_ie, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_bi_ie);

	proto_tree_add_item_ret_uint(tree, hf_dect_nr_bi_ind_type, tvb, offset, 1, ENC_BIG_ENDIAN, &ind_type);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_bi_idtype, tvb, offset, 1, ENC_BIG_ENDIAN, &idtype);

	if (ind_type == 1) {
		/* Table 6.4.3.7-1: 'ACK/NACK' and 'Feedback' fields are present when the
		 * indication Type is 'Random access response' (1)
		 */
		proto_tree_add_item(tree, hf_dect_nr_bi_ack, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item_ret_uint(tree, hf_dect_nr_bi_fb, tvb, offset, 1, ENC_BIG_ENDIAN, &feedback);
	} else {
		dect_tree_add_reserved_item(tree, hf_dect_nr_bi_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	}
	proto_tree_add_item(tree, hf_dect_nr_bi_res_alloc, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* Short or Long RD ID follows as defined by the IDType field */
	if (idtype == 0) {
		proto_tree_add_item_ret_uint(tree, hf_dect_nr_bi_short_rd_id, tvb, offset, 2, ENC_BIG_ENDIAN, &rd_id);
		bi_target = wmem_strdup_printf(pinfo->pool, "0x%04x", rd_id);
		offset += 2;
	} else {
		proto_tree_add_item_ret_uint(tree, hf_dect_nr_bi_long_rd_id, tvb, offset, 4, ENC_BIG_ENDIAN, &rd_id);
		bi_target = wmem_strdup_printf(pinfo->pool, "0x%08x", rd_id);
		offset += 4;
	}

	switch (feedback) {
	case 1: /* MCS */
		dect_tree_add_reserved_item(tree, hf_dect_nr_bi_mcs_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_bi_mcs_channel_quality, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		break;

	case 2: /* MIMO 2 antenna */
		dect_tree_add_reserved_item(tree, hf_dect_nr_bi_mimo2_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_bi_mimo2_num_layers, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_bi_mimo2_cb_index, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		break;

	case 3: /* MIMO 4 antenna */
		proto_tree_add_item(tree, hf_dect_nr_bi_mimo4_num_layers, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_bi_mimo4_cb_index, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		break;
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, " (%s to %s)", val_to_str_const(ind_type, bi_ind_type_vals, "Unknown"), bi_target);
	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.3.8: Padding IE */
static int dissect_padding_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	dect_nr_context_t *ctx = (dect_nr_context_t *)data;
	int length = (ctx->ie_length_present ? (int)ctx->ie_length : -1);

	return dect_tree_add_expected_item(parent_tree, hf_dect_nr_pd_bytes, tvb, 0, length, pinfo, ENC_NA);
}

/* 6.4.3.9: Group Assignment IE */
static int dissect_group_assignment_ie(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, void *data)
{
	int offset = 0;
	bool single_field;
	int num_resource_tags;

	dect_nr_context_t *ctx = (dect_nr_context_t *)data;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_ga_ie, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_ga_ie);

	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_ga_single_field, tvb, offset, 1, ENC_BIG_ENDIAN, &single_field);
	proto_tree_add_item(tree, hf_dect_nr_ga_group_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if (ctx->ie_length_present) {
		/* Determine number of Resource Tags based on expected length */
		num_resource_tags = ctx->ie_length - offset;
	} else {
		num_resource_tags = (single_field ? 1 : 2);
	}

	for (int i = 0; i < num_resource_tags; i++) {
		proto_tree_add_item(tree, hf_dect_nr_ga_direct, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dect_nr_ga_resource_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.3.10: Load Info IE */
static int dissect_load_info_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	bool max_assoc_field;
	bool rd_pt_load_field;
	bool rach_load_field;
	bool channel_load_field;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_li_ie, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_li_ie);

	dect_tree_add_reserved_item(tree, hf_dect_nr_li_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_li_max_assoc_field, tvb, offset, 1, ENC_BIG_ENDIAN, &max_assoc_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_li_rd_pt_load_field, tvb, offset, 1, ENC_BIG_ENDIAN, &rd_pt_load_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_li_rach_load_field, tvb, offset, 1, ENC_BIG_ENDIAN, &rach_load_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_li_channel_load_field, tvb, offset, 1, ENC_BIG_ENDIAN, &channel_load_field);
	offset++;

	proto_tree_add_item(tree, hf_dect_nr_li_traffic_load_pct, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if (max_assoc_field) {
		proto_tree_add_item(tree, hf_dect_nr_li_max_assoc_16, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	} else {
		proto_tree_add_item(tree, hf_dect_nr_li_max_assoc_8, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	proto_tree_add_item(tree, hf_dect_nr_li_curr_ft_pct, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if (rd_pt_load_field) {
		proto_tree_add_item(tree, hf_dect_nr_li_curr_pt_pct, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (rach_load_field) {
		proto_tree_add_item(tree, hf_dect_nr_li_rach_load_pct, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (channel_load_field) {
		proto_tree_add_item(tree, hf_dect_nr_li_subslots_free_pct, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(tree, hf_dect_nr_li_subslots_busy_pct, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.3.12: Measurement Report IE */
static int dissect_measurement_report_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	bool snr_field;
	bool rssi2_field;
	bool rssi1_field;
	bool tx_count_field;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_mr_ie, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_mr_ie);

	dect_tree_add_reserved_item(tree, hf_dect_nr_mr_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_mr_snr_field, tvb, offset, 1, ENC_BIG_ENDIAN, &snr_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_mr_rssi2_field, tvb, offset, 1, ENC_BIG_ENDIAN, &rssi2_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_mr_rssi1_field, tvb, offset, 1, ENC_BIG_ENDIAN, &rssi1_field);
	proto_tree_add_item_ret_boolean(tree, hf_dect_nr_mr_tx_count_field, tvb, offset, 1, ENC_BIG_ENDIAN, &tx_count_field);
	proto_tree_add_item(tree, hf_dect_nr_mr_rach, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if (snr_field) {
		proto_tree_add_item(tree, hf_dect_nr_mr_snr, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (rssi2_field) {
		proto_tree_add_item(tree, hf_dect_nr_mr_rssi2, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (rssi1_field) {
		proto_tree_add_item(tree, hf_dect_nr_mr_rssi1, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	if (tx_count_field) {
		proto_tree_add_item(tree, hf_dect_nr_mr_tx_count, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	proto_item_set_len(item, offset);

	return offset;
}

/* 6.4.3.13: Radio Device Status IE */
static int dissect_radio_device_status_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	uint32_t status_field;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_rds_ie, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_rds_ie);

	dect_tree_add_reserved_item(tree, hf_dect_nr_rds_res1, tvb, offset, 1, pinfo, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_rds_sf, tvb, offset, 1, ENC_BIG_ENDIAN, &status_field);
	proto_tree_add_item(tree, hf_dect_nr_rds_dur, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str_const(status_field, rds_status_vals, "Unknown"));
	proto_item_set_len(item, offset);

	return offset;
}

/* Escape */
static int dissect_escape(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	dect_nr_context_t *ctx = (dect_nr_context_t *)data;
	int length = (ctx->ie_length_present ? (int)ctx->ie_length : -1);

	return dect_tree_add_expected_item(parent_tree, hf_dect_nr_escape, tvb, 0, length, pinfo, ENC_NA);
}

/* IE type Extension */
static int dissect_ie_type_extension(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	dect_nr_context_t *ctx = (dect_nr_context_t *)data;
	int length = (ctx->ie_length_present ? (int)ctx->ie_length - 1 : -1);

	proto_tree_add_item(parent_tree, hf_dect_nr_ie_type_extension, tvb, 0, 1, ENC_BIG_ENDIAN);

	return dect_tree_add_expected_item(parent_tree, hf_dect_nr_ie_extension, tvb, 1, length, pinfo, ENC_NA);
}

static int dissect_mac_mux_msg_ie(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, dect_nr_context_t *ctx, uint8_t mac_ext)
{
	dissector_table_t dissector_table;
	tvbuff_t *subtvb;
	int length;

	if (mac_ext < 3) {
		dissector_table = ie_dissector_table;
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s",
				    val_to_str_const(ctx->ie_type, mux_hdr_ie_type_mac_ext_012_vals, "Unknown IE"));
	} else {
		dissector_table = ie_short_dissector_table;
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s",
				    val_to_str_const(ctx->ie_type, mux_hdr_ie_type_mac_ext_3_pl_1_vals, "Unknown short IE"));
	}

	subtvb = tvb_new_subset_length(tvb, offset, ctx->ie_length);
	length = dissector_try_uint_with_data(dissector_table, ctx->ie_type, subtvb, pinfo, parent_tree, false, ctx);

	if (length > 0) {
		offset += length;
	} else if (ctx->ie_length_present) {
		/* Unknown message with known length */
		proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_undecoded, tvb, offset, ctx->ie_length, ENC_NA);
		expert_add_info(pinfo, item, &ei_dect_nr_undecoded);
		offset += ctx->ie_length;
	} else {
		/* Unknown message with unknown length */
		expert_add_info(pinfo, parent_tree, &ei_dect_nr_ie_length_not_set);
		offset += tvb_reported_length_remaining(tvb, offset);
	}

	return offset;
}

/* 6.3.4: MAC Multiplexing Header */
static int dissect_mac_mux_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, dect_nr_context_t *ctx)
{
	int start = offset;
	uint32_t mac_ext;
	const char *ie_type_name;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_mux_hdr, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_mux_hdr);

	proto_tree_add_item_ret_uint(tree, hf_dect_nr_mux_mac_ext, tvb, offset, 1, ENC_BIG_ENDIAN, &mac_ext);

	if (mac_ext == 3) {
		/* One bit length field is included in the IE header. IE type is 5 bits (6.3.4-1 options a) and b)) */
		proto_tree_add_item_ret_uint(tree, hf_dect_nr_mux_len_bit, tvb, offset, 1, ENC_BIG_ENDIAN, &ctx->ie_length);
		if (ctx->ie_length == 0) {
			/* 6.3.4-1 option a) */
			proto_tree_add_item_ret_uint(tree, hf_dect_nr_mux_ie_type_short_pl0, tvb, offset, 1, ENC_BIG_ENDIAN, &ctx->ie_type);
			/* The IE payload size is 0 bytes when the length bit (bit 2) is set to 0 */
			ie_type_name = val_to_str_const(ctx->ie_type, mux_hdr_ie_type_mac_ext_3_pl_0_vals, "Unknown");
		} else {
			/* 6.3.4-1 option b) */
			proto_tree_add_item_ret_uint(tree, hf_dect_nr_mux_ie_type_short_pl1, tvb, offset, 1, ENC_BIG_ENDIAN, &ctx->ie_type);
			/* Expect exactly one byte MAC SDU */
			ie_type_name = val_to_str_const(ctx->ie_type, mux_hdr_ie_type_mac_ext_3_pl_1_vals, "Unknown");
		}
		ctx->ie_length_present = true;
		offset++;
	} else {
		/* IE type is 6 bits (6.3.4-1 options c), d), e) and f)) */
		proto_tree_add_item_ret_uint(tree, hf_dect_nr_mux_ie_type_long, tvb, offset, 1, ENC_BIG_ENDIAN, &ctx->ie_type);
		ie_type_name = val_to_str_const(ctx->ie_type, mux_hdr_ie_type_mac_ext_012_vals, "Unknown");
		offset++;

		if (mac_ext == 0) {
			/* 6.3.4-1 option c)
			 * No length field is included in the IE header. IE type defines the length of the IE payload
			 * Expect at least one byte (length unknown at this point)
			 */
			ctx->ie_length = -1;
			ctx->ie_length_present = false;
		} else if (mac_ext == 1) {
			/* 6.3.4-1 option d)
			 * 8 bit length included indicating the length of the IE payload
			 */
			proto_tree_add_item_ret_uint(tree, hf_dect_nr_mux_mac_ie_len_1, tvb, offset, 1, ENC_BIG_ENDIAN, &ctx->ie_length);
			offset++;
			ctx->ie_length_present = true;
		} else if (mac_ext == 2) {
			/* 6.3.4-1 option e)
			 * 16 bit length included indicating the length of the IE payload
			 */
			proto_tree_add_item_ret_uint(tree, hf_dect_nr_mux_mac_ie_len_2, tvb, offset, 2, ENC_BIG_ENDIAN, &ctx->ie_length);
			offset += 2;
			ctx->ie_length_present = true;
		}
	}

	/* ie_length 0 is Short SDU with no payload (no more processing needed) */
	if (ctx->ie_length == 0) {
		/* No payload, add IE Type to info column */
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s", ie_type_name);
	} else {
		int ie_start = offset;

		/* 6.4 MAC Messages and IEs */
		offset = dissect_mac_mux_msg_ie(tvb, offset, pinfo, tree, ctx, mac_ext);

		if ((ctx->ie_length_present) && (ie_start + (int)ctx->ie_length) != offset) {
			expert_add_info_format(pinfo, tree, &ei_dect_nr_length_mismatch,
					       "Length mismatch: expected %d, got %d",
					       ctx->ie_length, offset - ie_start);
		}
	}

	proto_item_append_text(item, " (%s)", ie_type_name);
	proto_item_set_len(item, offset - start);

	return offset;
}

/* 6.3 MAC PDU */
static int dissect_mac_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, dect_nr_context_t *ctx)
{
	uint32_t mac_security;
	uint32_t mac_hdr_type;
	int length;

	proto_item *item = proto_tree_add_item(parent_tree, hf_dect_nr_mac_pdu, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr_mac_pdu);

	/* 6.3.2 MAC Header type */
	proto_tree_add_item(tree, hf_dect_nr_mac_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_mac_security, tvb, offset, 1, ENC_BIG_ENDIAN, &mac_security);
	proto_tree_add_item_ret_uint(tree, hf_dect_nr_mac_hdr_type, tvb, offset, 1, ENC_BIG_ENDIAN, &mac_hdr_type);
	offset++;

	/* 6.3.3 MAC Common header */
	offset = dissect_mac_common_header(tvb, offset, pinfo, tree, mac_hdr_type);

	/* One or more MAC SDUs included in MAC PDU with MAC multiplexing header */
	length = tvb_reported_length(tvb);

	if (mac_security != 0) {
		/* 5 bytes MIC at the end */
		length -= 5;
	}

	while (offset < length) {
		/* 6.3.4 MAC multiplexing header */
		offset = dissect_mac_mux_header(tvb, offset, pinfo, tree, ctx);
	}

	/* 5.9.1: Message Integrity Code (MIC) */
	if (mac_security != 0) {
		int mic_len = (offset <= length) ? 5 : 0;

		item = proto_tree_add_item(tree, hf_dect_nr_mic_bytes, tvb, offset, mic_len, ENC_NA);
		offset += mic_len;

		if (mic_len == 0) {
			expert_add_info(pinfo, item, &ei_dect_nr_pdu_cut_short);
			col_append_str(pinfo->cinfo, COL_INFO, " [MIC missing]");
		}
	}

	return offset;
}

static int dissect_dect_nr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	dect_nr_context_t ctx = { 0 };
	int offset = 0;

	proto_item *item = proto_tree_add_item(parent_tree, proto_dect_nr, tvb, offset, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_dect_nr);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DECT NR+");
	col_clear(pinfo->cinfo, COL_INFO);

	/* 6.2 Physical Header Field */
	offset = dissect_physical_header_field(tvb, offset, pinfo, tree, &ctx);

	/* 6.3 MAC PDU */
	offset = dissect_mac_pdu(tvb, offset, pinfo, tree, &ctx);

	return offset;
}

void proto_register_dect_nr(void)
{
	static hf_register_info hf[] = {
		/* 6.2: Physical Header Field */
		{ &hf_dect_nr_phf,
			{ "Physical Header Field", "dect_nr.phf", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_header_format_type1,
			{ "Header Format", "dect_nr.phf.hf", FT_UINT8, BASE_DEC,
			  VALS(header_formats_type1_vals), 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_header_format_type2,
			{ "Header Format", "dect_nr.phf.hf", FT_UINT8, BASE_DEC,
			  VALS(header_formats_type2_vals), 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_len_type,
			{ "Packet length type", "dect_nr.phf.len_type", FT_BOOLEAN, 8,
			  TFS(&pkt_len_type_tfs), 0x10, NULL, HFILL }
		},
		{ &hf_dect_nr_packet_len_slots,
			{ "Packet length (slots)", "dect_nr.phf.pkt_len", FT_UINT8, BASE_DEC,
			  VALS(signalled_s_len_vals), 0x0F, NULL, HFILL }
		},
		{ &hf_dect_nr_packet_len_subslots,
			{ "Packet length (subslots)", "dect_nr.phf.pkt_len", FT_UINT8, BASE_DEC,
			  VALS(signalled_ss_len_vals), 0x0F, NULL, HFILL }
		},
		{ &hf_dect_nr_short_nw_id,
			{ "Short Network ID", "dect_nr.phf.short_nw_id", FT_UINT8, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_transmitter_id,
			{ "Transmitter Short RD ID", "dect_nr.phf.transmitter_id", FT_UINT16, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_tx_pwr,
			{ "Transmit Power", "dect_nr.phf.tx_pwr", FT_UINT8, BASE_DEC,
			  VALS(tx_powers_3a_vals), 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_res1,
			{ "Reserved", "dect_nr.phf.res1", FT_UINT8, BASE_DEC,
			  NULL, 0x08, NULL, HFILL }
		},
		{ &hf_dect_nr_df_mcs_t1,
			{ "DF MCS (Type 1)", "dect_nr.phf.df_mcs_t1", FT_UINT8, BASE_DEC,
			  VALS(mcse_vals), 0x07, "Data Field Modulation and Coding Scheme (Type 1)", HFILL }
		},
		{ &hf_dect_nr_df_mcs_t2,
			{ "DF MCS (Type 2)", "dect_nr.phf.df_mcs_t2", FT_UINT8, BASE_DEC,
			  VALS(mcse_vals), 0x0F, "Data Field Modulation and Coding Scheme (Type 2)", HFILL }
		},
		{ &hf_dect_nr_receiver_id,
			{ "Receiver Short RD ID", "dect_nr.phf.receiver_id", FT_UINT16, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_spatial_streams,
			{ "Number of Spatial Streams", "dect_nr.phf.spatial_streams", FT_UINT8, BASE_DEC,
			  VALS(num_spatial_stream_vals), 0xC0, NULL, HFILL }
		},
		{ &hf_dect_nr_df_red_version,
			{ "DF Redundancy Version", "dect_nr.phf.df_red_version", FT_UINT8, BASE_DEC,
			  NULL, 0x30, NULL, HFILL }
		},
		{ &hf_dect_nr_df_ind,
			{ "DF New Data Indication", "dect_nr.phf.df_ind", FT_BOOLEAN, 8,
			  NULL, 0x08, NULL, HFILL }
		},
		{ &hf_dect_nr_df_harq_proc,
			{ "DF HARQ Process Number", "dect_nr.phf.df_harq_proc", FT_UINT8, BASE_DEC,
			  NULL, 0x07, NULL, HFILL }
		},
		{ &hf_dect_nr_res1_hdr_format_001,
			{ "Reserved", "dect_nr.phf.res1", FT_UINT8, BASE_DEC,
			  NULL, 0x3F, NULL, HFILL }
		},
		{ &hf_dect_nr_fb_format,
			{ "Feedback format", "dect_nr.phf.fb_format", FT_UINT16, BASE_DEC,
			  VALS(feedback_format_vals), 0xF000, NULL, HFILL }
		},

		/* Table 6.2.2-2a: Feedback info format 1 */
		{ &hf_dect_nr_fbi1_harq_pn,
			{ "HARQ Process number", "dect_nr.phf.fbi1.harq_pn", FT_UINT16, BASE_DEC,
			  NULL, 0x0E00, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi1_tx_fb,
			{ "Transmission feedback", "dect_nr.phf.fbi1.tx_feedback", FT_BOOLEAN, 16,
			  TFS(&tfs_ack_nack), 0x0100, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi1_bs,
			{ "Buffer status", "dect_nr.phf.fbi1.bs", FT_UINT16, BASE_DEC,
			  VALS(buffer_status_vals), 0x00F0, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi1_cqi,
			{ "Channel Quality Indicator", "dect_nr.phf.fbi1.cqi", FT_UINT16, BASE_DEC,
			  VALS(cqi_vals), 0x000F, NULL, HFILL }
		},

		/* Table 6.2.2-2b: Feedback info format 2 */
		{ &hf_dect_nr_fbi2_cb_index,
			{ "Codebook index", "dect_nr.phf.fbi2.cb_index", FT_UINT16, BASE_DEC,
			  NULL, 0x0E00, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi2_mimo_fb,
			{ "MIMO feedback", "dect_nr.phf.fbi2.mimo_fb", FT_BOOLEAN, 16,
			  TFS(&fbi2_mimo_fb_tfs), 0x0100, "Multiple Input Multiple Output feedback", HFILL }
		},
		{ &hf_dect_nr_fbi2_bs,
			{ "Buffer status", "dect_nr.phf.fbi2.bs", FT_UINT16, BASE_DEC,
			  VALS(buffer_status_vals), 0x00F0, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi2_cqi,
			{ "Channel Quality Indicator", "dect_nr.phf.fbi2.cqi", FT_UINT16, BASE_DEC,
			  VALS(cqi_vals), 0x000F, NULL, HFILL }
		},

		/* Table 6.2.2-2c: Feedback info format 3 */
		{ &hf_dect_nr_fbi3_harq_pn_1,
			{ "HARQ Process number", "dect_nr.phf.fbi3.harq_pn", FT_UINT16, BASE_DEC,
			  NULL, 0x0E00, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi3_tx_fb_1,
			{ "Transmission feedback", "dect_nr.phf.fbi3.tx_feedback", FT_BOOLEAN, 16,
			  TFS(&tfs_ack_nack), 0x0100, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi3_harq_pn_2,
			{ "HARQ Process number", "dect_nr.phf.fbi3.harq_pn", FT_UINT16, BASE_DEC,
			  NULL, 0x00E0, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi3_tx_fb_2,
			{ "Transmission feedback", "dect_nr.phf.fbi3.tx_feedback", FT_BOOLEAN, 16,
			  TFS(&tfs_ack_nack), 0x0010, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi3_cqi,
			{ "Channel Quality Indicator", "dect_nr.phf.fbi3.cqi", FT_UINT16, BASE_DEC,
			  VALS(cqi_vals), 0x000F, NULL, HFILL }
		},

		/* Table 6.2.2-2d: Feedback info format 4 */
		{ &hf_dect_nr_fbi4_harq_fb_bm,
			{ "HARQ FB Bitmap", "dect_nr.phf.fbi4.harq_fb_bm", FT_UINT16, BASE_HEX,
			  NULL, 0x0FF0, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi4_cqi,
			{ "Channel Quality Indicator", "dect_nr.phf.fbi4.cqi", FT_UINT16, BASE_DEC,
			  VALS(cqi_vals), 0x000F, NULL, HFILL }
		},

		/* Table 6.2.2-2e: Feedback info format 5 */
		{ &hf_dect_nr_fbi5_harq_pn,
			{ "HARQ Process number", "dect_nr.phf.fbi5.harq_pn", FT_UINT16, BASE_DEC,
			  NULL, 0x0E00, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi5_tx_fb,
			{ "Transmission feedback", "dect_nr.phf.fbi5.tx_feedback", FT_BOOLEAN, 16,
			  TFS(&tfs_ack_nack), 0x0100, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi5_mimo_fb,
			{ "MIMO feedback", "dect_nr.phf.fbi5.mimo_fb", FT_UINT16, BASE_DEC,
			  VALS(fbi5_mimo_fb_vals), 0x00C0, "Multiple Input Multiple Output feedback", HFILL }
		},
		{ &hf_dect_nr_fbi5_cb_index,
			{ "Codebook index", "dect_nr.phf.fbi5.cb_index", FT_UINT16, BASE_DEC,
			  NULL, 0x003F, NULL, HFILL }
		},

		/* Table 6.2.2-2f: Feedback info format 6 */
		{ &hf_dect_nr_fbi6_harq_pn,
			{ "HARQ Process number", "dect_nr.phf.fbi6.harq_pn", FT_UINT16, BASE_DEC,
			  NULL, 0x0E00, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi6_res1,
			{ "Reserved", "dect_nr.phf.fbi6.res1", FT_UINT16, BASE_DEC,
			  NULL, 0x0100, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi6_bs,
			{ "Buffer status", "dect_nr.phf.fbi6.bs", FT_UINT16, BASE_DEC,
			  VALS(buffer_status_vals), 0x00F0, NULL, HFILL }
		},
		{ &hf_dect_nr_fbi6_cqi,
			{ "Channel Quality Indicator", "dect_nr.phf.fbi6.cqi", FT_UINT16, BASE_DEC,
			  VALS(cqi_vals), 0x000F, NULL, HFILL }
		},
		{ &hf_dect_nr_fb_info,
			{ "Feedback info", "dect_nr.phf.fb_info", FT_UINT16, BASE_HEX,
			  NULL, 0x0FFF, NULL, HFILL }
		},
		{ &hf_dect_nr_phf_padding,
			{ "Padding", "dect_nr.phf.padding", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},

		/* 6.3: MAC PDU */

		{ &hf_dect_nr_mac_pdu,
			{ "MAC PDU", "dect_nr.mac", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_mac_version,
			{ "Version", "dect_nr.mac.version", FT_UINT8, BASE_DEC,
			  NULL, 0xC0, NULL, HFILL }
		},
		{ &hf_dect_nr_mac_security,
			{ "MAC security", "dect_nr.mac.security", FT_UINT8, BASE_DEC,
			  VALS(mac_security_vals), 0x30, NULL, HFILL }
		},
		{ &hf_dect_nr_mac_hdr_type,
			{ "MAC Header Type", "dect_nr.mac.hdr_type", FT_UINT8, BASE_DEC,
			  VALS(mac_header_type_vals), 0x0F, NULL, HFILL }
		},

		/* 6.3.3.1: Data MAC PDU Header */
		{ &hf_dect_nr_data_hdr,
			{ "Data MAC PDU Header", "dect_nr.mac.hdr.data", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_data_hdr_res1,
			{ "Reserved", "dect_nr.mac.hdr.data.res1", FT_UINT16, BASE_DEC,
			  NULL, 0xE000, NULL, HFILL }
		},
		{ &hf_dect_nr_data_hdr_reset,
			{ "Reset", "dect_nr.mac.hdr.data.reset", FT_BOOLEAN, 16,
			  NULL, 0x1000, NULL, HFILL }
		},
		{ &hf_dect_nr_data_hdr_sn,
			{ "Sequence number", "dect_nr.mac.hdr.data.sn", FT_UINT16, BASE_DEC,
			  NULL, 0x0FFF, NULL, HFILL }
		},

		/* 6.3.3.2: Beacon Header */
		{ &hf_dect_nr_bc_hdr,
			{ "Beacon Header", "dect_nr.mac.hdr.bc", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_bc_hdr_nw_id,
			{ "Network ID", "dect_nr.mac.hdr.bc.nw_id", FT_UINT24, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_bc_hdr_tx_addr,
			{ "Transmitter Address", "dect_nr.mac.hdr.bc.tx_addr", FT_UINT32, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},

		/* 6.3.3.3: Unicast Header */
		{ &hf_dect_nr_uc_hdr,
			{ "Unicast Header", "dect_nr.mac.hdr.uc", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_uc_hdr_res1,
			{ "Reserved", "dect_nr.mac.hdr.uc.res1", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_uc_hdr_rst,
			{ "Reset", "dect_nr.mac.hdr.uc.rst", FT_BOOLEAN, 8,
			  NULL, 0x10, NULL, HFILL }
		},
		{ &hf_dect_nr_uc_hdr_mac_seq,
			{ "MAC Sequence", "dect_nr.mac.hdr.uc.mac_seq", FT_UINT8, BASE_DEC,
			  NULL, 0x0F, NULL, HFILL }
		},
		{ &hf_dect_nr_uc_hdr_sn,
			{ "Sequence Number", "dect_nr.mac.hdr.uc.sn", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_uc_hdr_rx_addr,
			{ "Receiver Address", "dect_nr.mac.hdr.uc.rx_addr", FT_UINT32, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_uc_hdr_tx_addr,
			{ "Transmitter Address", "dect_nr.mac.hdr.uc.tx_addr", FT_UINT32, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},

		/* 6.3.3.4: RD Broadcasting Header */
		{ &hf_dect_nr_rdbh_hdr,
			{ "RD Broadcasting Header", "dect_nr.mac.hdr.rdbh", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_rdbh_hdr_res1,
			{ "Reserved", "dect_nr.mac.hdr.rdbh.res1", FT_UINT16, BASE_DEC,
			  NULL, 0xE000, NULL, HFILL }
		},
		{ &hf_dect_nr_rdbh_hdr_reset,
			{ "Reset", "dect_nr.mac.hdr.rdbh.reset", FT_BOOLEAN, 16,
			  NULL, 0x1000, NULL, HFILL }
		},
		{ &hf_dect_nr_rdbh_hdr_sn,
			{ "Sequence number", "dect_nr.mac.hdr.rdbh.sn", FT_UINT16, BASE_DEC,
			  NULL, 0x0FFF, NULL, HFILL }
		},
		{ &hf_dect_nr_rdbh_hdr_tx_addr,
			{ "Transmitter Address", "dect_nr.mac.hdr.rdbh.tx_addr", FT_UINT32, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},

		/* 6.3.4: MAC Multiplexing Header */
		{ &hf_dect_nr_mux_hdr,
			{ "MAC Multiplexing Header", "dect_nr.mac.mux_hdr", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_mux_mac_ext,
			{ "MAC extension", "dect_nr.mac.mux_hdr.mac_ext", FT_UINT8, BASE_DEC,
			  VALS(mac_ext_vals), 0xC0, NULL, HFILL }
		},
		{ &hf_dect_nr_mux_len_bit,
			{ "Length bit", "dect_nr.mac.mux_hdr.len", FT_UINT8, BASE_DEC,
			  VALS(mac_ext_len_bit_vals), 0x20, NULL, HFILL }
		},
		{ &hf_dect_nr_mux_ie_type_long,
			{ "IE type", "dect_nr.mac.mux_hdr.ie_type_long", FT_UINT8, BASE_DEC,
			  VALS(mux_hdr_ie_type_mac_ext_012_vals), 0x3F, NULL, HFILL }
		},
		{ &hf_dect_nr_mux_ie_type_short_pl0,
			{ "IE type (no payload)", "dect_nr.mac.mux_hdr.ie_type_short_pl0", FT_UINT8, BASE_DEC,
			  VALS(mux_hdr_ie_type_mac_ext_3_pl_0_vals), 0x1F, NULL, HFILL }
		},
		{ &hf_dect_nr_mux_ie_type_short_pl1,
			{ "IE type (1-byte payload)", "dect_nr.mac.mux_hdr.ie_type_short_pl1", FT_UINT8, BASE_DEC,
			  VALS(mux_hdr_ie_type_mac_ext_3_pl_1_vals), 0x1F, NULL, HFILL }
		},
		{ &hf_dect_nr_mux_mac_ie_len_1,
			{ "IE length in bytes", "dect_nr.mac.mux_hdr.ie_len_1", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_mux_mac_ie_len_2,
			{ "IE length in bytes", "dect_nr.mac.mux_hdr.ie_len_2", FT_UINT16, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},

		/* 6.4.2: MAC Messages */

		/* 6.4.2.2: Network Beacon message */
		{ &hf_dect_nr_nb_msg,
			{ "Network Beacon message", "dect_nr.mac.nb", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_res1,
			{ "Reserved", "dect_nr.mac.nb.res1", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_tx_pwr_field,
			{ "TX Power", "dect_nr.mac.nb.tx_pwr_field", FT_BOOLEAN, 8,
			  TFS(&tfs_included_not_included), 0x10, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_pwr_const,
			{ "Power Const", "dect_nr.mac.nb.pwr_const", FT_BOOLEAN, 8,
			  TFS(&tfs_yes_no), 0x08, "Power Constraints", HFILL }
		},
		{ &hf_dect_nr_nb_current_field,
			{ "Current", "dect_nr.mac.nb.current_field", FT_BOOLEAN, 8,
			  TFS(&nb_ie_current_tfs), 0x04, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_channels,
			{ "Network beacon channels", "dect_nr.mac.nb.channels", FT_UINT8, BASE_DEC,
			  NULL, 0x03, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_nb_period,
			{ "Network beacon period", "dect_nr.mac.nb.nb_period", FT_UINT8, BASE_DEC,
			  VALS(nb_ie_nb_period_vals), 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_cb_period,
			{ "Cluster beacon period", "dect_nr.mac.nb.cb_period", FT_UINT8, BASE_DEC,
			  VALS(nb_ie_cb_period_vals), 0x0F, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_res2,
			{ "Reserved", "dect_nr.mac.nb.res2", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_next_cl_chan,
			{ "Next Cluster Channel", "dect_nr.mac.nb.next_cl_chan", FT_UINT16, BASE_DEC,
			  NULL, 0x1FFF, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_time_to_next,
			{ "Time to next", "dect_nr.mac.nb.ttn", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
			  UNS(&units_microseconds), 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_res3,
			{ "Reserved", "dect_nr.mac.nb.res3", FT_UINT8, BASE_DEC,
			  NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_cl_max_tx_pwr,
			{ "Clusters Max TX Power", "dect_nr.mac.nb.cl_max_tx_pwr", FT_UINT8, BASE_DEC,
			  VALS(tx_powers_3b_vals), 0x0F, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_res4,
			{ "Reserved", "dect_nr.mac.nb.res4", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_curr_cl_chan,
			{ "Current Cluster Channel", "dect_nr.mac.nb.curr_cl_chan", FT_UINT16, BASE_DEC,
			  NULL, 0x1FFF, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_res5,
			{ "Reserved", "dect_nr.mac.nb.res5", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_nb_addn_nb_channels,
			{ "Additional Network Beacon Channels", "dect_nr.mac.nb.addn_nb_channels", FT_UINT16, BASE_DEC,
			  NULL, 0x1FFF, NULL, HFILL }
		},

		/* 6.4.2.3: Cluster Beacon message */
		{ &hf_dect_nr_cb_msg,
			{ "Cluster Beacon message", "dect_nr.mac.cb", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_sfn,
			{ "System Frame Number", "dect_nr.mac.cb.sfn", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_res1,
			{ "Reserved", "dect_nr.mac.cb.res1", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_tx_pwr_field,
			{ "TX Power", "dect_nr.mac.cb.tx_pwr_field", FT_BOOLEAN, 8,
			  TFS(&tfs_included_not_included), 0x10, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_pwr_const,
			{ "Power Const", "dect_nr.mac.cb.pwr_const", FT_BOOLEAN, 8,
			  TFS(&tfs_yes_no), 0x08, "Power Constraints", HFILL }
		},
		{ &hf_dect_nr_cb_fo_field,
			{ "FO", "dect_nr.mac.cb.fo_field", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x04, "Frame Offset", HFILL }
		},
		{ &hf_dect_nr_cb_next_chan_field,
			{ "Next Channel", "dect_nr.mac.cb.next_chan_field", FT_BOOLEAN, 8,
			  TFS(&cb_next_chan_tfs), 0x02, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_time_to_next_field,
			{ "Time to next", "dect_nr.mac.cb.ttn_field", FT_BOOLEAN, 8,
			  TFS(&cb_ttn_tfs), 0x01, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_nb_period,
			{ "Network beacon period", "dect_nr.mac.cb.nb_period", FT_UINT8, BASE_DEC,
			  VALS(nb_ie_nb_period_vals), 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_cb_period,
			{ "Cluster beacon period", "dect_nr.mac.cb.cb_period", FT_UINT8, BASE_DEC,
			  VALS(nb_ie_cb_period_vals), 0x0F, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_ctt,
			{ "Count To Trigger", "dect_nr.mac.cb.ctt", FT_UINT8, BASE_DEC,
			  NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_rel_qual,
			{ "Relative Quality", "dect_nr.mac.cb.rel_qual", FT_UINT8, BASE_DEC,
			  NULL, 0x0C, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_min_qual,
			{ "Minimum Quality", "dect_nr.mac.cb.min_qual", FT_UINT8, BASE_DEC,
			  NULL, 0x03, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_res2,
			{ "Reserved", "dect_nr.mac.cb.res2", FT_UINT8, BASE_DEC,
			  NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_cl_max_tx_pwr,
			{ "Cluster Max TX Power", "dect_nr.mac.cb.cl_max_tx_pwr", FT_UINT8, BASE_DEC,
			  VALS(tx_powers_3b_vals), 0x0F, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_frame_offset,
			{ "Frame Offset", "dect_nr.mac.cb.frame_offset", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_res3,
			{ "Reserved", "dect_nr.mac.cb.res3", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_next_cl_chan,
			{ "Next Cluster Channel", "dect_nr.mac.cb.next_cl_chan", FT_UINT16, BASE_DEC,
			  NULL, 0x1FFF, NULL, HFILL }
		},
		{ &hf_dect_nr_cb_time_to_next,
			{ "Time to next", "dect_nr.mac.cb.ttn", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
			  UNS(&units_microseconds), 0x0, NULL, HFILL }
		},

		/* 6.4.2.4: Association Request message */
		{ &hf_dect_nr_a_req_msg,
			{ "Association Request message", "dect_nr.mac.areq", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_setup_cause,
			{ "Setup Cause", "dect_nr.mac.areq.sc", FT_UINT8, BASE_DEC,
			  VALS(ar_setup_cause_vals), 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_num_flows,
			{ "Number of flows", "dect_nr.mac.areq.num_flows", FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS,
			  VALS(a_req_num_flow_vals), 0x1C, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_pwr_const,
			{ "Power Const", "dect_nr.mac.areq.pwr_const", FT_BOOLEAN, 8,
			  TFS(&tfs_yes_no), 0x02, "Power Constraints", HFILL }
		},
		{ &hf_dect_nr_a_req_ft_mode_field,
			{ "FT Mode", "dect_nr.mac.areq.ft_mode_field", FT_BOOLEAN, 8,
			  TFS(&ar_ft_mode_tfs), 0x01, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_current,
			{ "Current", "dect_nr.mac.areq.current_field", FT_BOOLEAN, 8,
			  TFS(&nb_ie_current_tfs), 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_res1,
			{ "Reserved", "dect_nr.mac.areq.res1", FT_UINT8, BASE_DEC,
			  NULL, 0x7F, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_harq_proc_tx,
			{ "HARQ Processes TX", "dect_nr.mac.areq.harq_proc_tx", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_max_harq_retx,
			{ "Max HARQ RE-TX", "dect_nr.mac.areq.max_harq_retx", FT_UINT8, BASE_DEC,
			  VALS(ar_max_harq_re_rxtx_vals), 0x1F, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_harq_proc_rx,
			{ "HARQ Processes RX", "dect_nr.mac.areq.harq_proc_rx", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_max_harq_rerx,
			{ "Max HARQ RE-RX", "dect_nr.mac.areq.max_harq_rerx", FT_UINT8, BASE_DEC,
			  VALS(ar_max_harq_re_rxtx_vals), 0x1F, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_res2,
			{ "Reserved", "dect_nr.mac.areq.res2", FT_UINT8, BASE_DEC,
			  NULL, 0xC0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_flow_id,
			{ "Flow ID", "dect_nr.mac.areq.flow_id", FT_UINT8, BASE_DEC,
			  VALS(mux_hdr_ie_type_mac_ext_012_vals), 0x3F, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_nb_period,
			{ "Network beacon period", "dect_nr.mac.areq.nb_period", FT_UINT8, BASE_DEC,
			  VALS(nb_ie_nb_period_vals), 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_cb_period,
			{ "Cluster beacon period", "dect_nr.mac.areq.cb_period", FT_UINT8, BASE_DEC,
			  VALS(nb_ie_cb_period_vals), 0x0F, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_res3,
			{ "Reserved", "dect_nr.mac.areq.res3", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_next_cl_chan,
			{ "Next Cluster Channel", "dect_nr.mac.areq.next_cl_chan", FT_UINT16, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_time_to_next,
			{ "Time to next", "dect_nr.mac.areq.ttn", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
			  UNS(&units_microseconds), 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_res4,
			{ "Reserved", "dect_nr.mac.areq.res4", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_req_curr_cl_chan,
			{ "Current Cluster Channel", "dect_nr.mac.areq.curr_cl_chan", FT_UINT16, BASE_DEC,
			  NULL, 0x1FFF, NULL, HFILL }
		},

		/* 6.4.2.5: Association Response message */
		{ &hf_dect_nr_a_rsp_msg,
			{ "Association Response message", "dect_nr.mac.arsp", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_ack_field,
			{ "Association", "dect_nr.mac.arsp.ack_nack_field", FT_BOOLEAN, 8,
			  TFS(&tfs_accepted_rejected), 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_res1,
			{ "Reserved", "dect_nr.mac.arsp.res1", FT_UINT8, BASE_DEC,
			  NULL, 0x40, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_harq_mod_field,
			{ "HARQ-mod", "dect_nr.mac.arsp.harq_mod_field", FT_BOOLEAN, 8,
			  TFS(&ar_harq_mod_tfs), 0x20, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_num_flows,
			{ "Number of flows", "dect_nr.mac.arsp.num_flows", FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS,
			  VALS(a_rsp_num_flow_vals), 0x1C, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_group_field,
			{ "Group", "dect_nr.mac.arsp.group_field", FT_BOOLEAN, 8,
			  TFS(&tfs_included_not_included), 0x02, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_res2,
			{ "Reserved", "dect_nr.mac.arsp.res2", FT_UINT8, BASE_DEC,
			  NULL, 0x01, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_rej_cause,
			{ "Reject Cause", "dect_nr.mac.arsp.rej_cause", FT_UINT8, BASE_DEC,
			  VALS(assoc_rej_cause_vals), 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_rej_timer,
			{ "Reject Timer", "dect_nr.mac.arsp.rej_timer", FT_UINT8, BASE_DEC,
			  VALS(assoc_rej_time_vals), 0x0F, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_harq_proc_rx,
			{ "HARQ Processes RX", "dect_nr.mac.arsp.harq_proc_rx", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_max_harq_rerx,
			{ "Max HARQ RE-RX", "dect_nr.mac.arsp.max_harq_rerx", FT_UINT8, BASE_DEC,
			  VALS(ar_max_harq_re_rxtx_vals), 0x1F, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_harq_proc_tx,
			{ "HARQ Processes TX", "dect_nr.mac.arsp.harq_proc_tx", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_max_harq_retx,
			{ "(RX) Max HARQ RE-TX", "dect_nr.mac.arsp.max_harq_retx", FT_UINT8, BASE_DEC,
			  VALS(ar_max_harq_re_rxtx_vals), 0x1F, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_res3,
			{ "Reserved", "dect_nr.mac.arsp.res3", FT_UINT8, BASE_DEC,
			  NULL, 0xC0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_flow_id,
			{ "Flow ID", "dect_nr.mac.arsp.flow_id", FT_UINT8, BASE_DEC,
			  VALS(mux_hdr_ie_type_mac_ext_012_vals), 0x3F, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_res4,
			{ "Reserved", "dect_nr.mac.arsp.res4", FT_UINT8, BASE_DEC,
			  NULL, 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_group_id,
			{ "Group ID", "dect_nr.mac.arsp.group_id", FT_UINT8, BASE_DEC,
			  NULL, 0x7F, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_res5,
			{ "Reserved", "dect_nr.mac.arsp.res5", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_res_tag,
			{ "Resource Tag", "dect_nr.mac.arsp.res_tag", FT_UINT8, BASE_DEC,
			  NULL, 0x1F, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rsp_res6,
			{ "Reserved", "dect_nr.mac.arsp.res6", FT_UINT8, BASE_DEC,
			  NULL, 0x7F, NULL, HFILL }
		},

		/* 6.4.2.6: Association Release message */
		{ &hf_dect_nr_a_rel_msg,
			{ "Association Release message", "dect_nr.mac.arel", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rel_cause,
			{ "Release Cause", "dect_nr.mac.arel.cause", FT_UINT8, BASE_DEC,
			  VALS(assoc_rel_cause_vals), 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_a_rel_res1,
			{ "Reserved", "dect_nr.mac.arel.res1", FT_UINT8, BASE_DEC,
			  NULL, 0x0F, NULL, HFILL }
		},

		/* 6.4.2.7: Reconfiguration Request message */
		{ &hf_dect_nr_rc_req_msg,
			{ "Reconfiguration Request message", "dect_nr.mac.rcreq", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_req_tx_harq_field,
			{ "TX HARQ", "dect_nr.mac.rcreq.tx_harq_field", FT_BOOLEAN, 8,
			  TFS(&rc_harq_req_tfs), 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_req_rx_harq_field,
			{ "RX HARQ", "dect_nr.mac.rcreq.rx_harq_field", FT_BOOLEAN, 8,
			  TFS(&rc_harq_req_tfs), 0x40, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_req_rd_capability,
			{ "RD Capability", "dect_nr.mac.rcreq.rd_capability", FT_BOOLEAN, 8,
			  TFS(&rc_rd_capability_req_tfs), 0x20, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_req_num_flows,
			{ "Number of flows", "dect_nr.mac.rcreq.num_flows", FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS,
			  VALS(rc_req_num_flow_vals), 0x1C, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_req_radio_resources,
			{ "Radio Resource", "dect_nr.mac.rcreq.radio_resources", FT_UINT8, BASE_DEC,
			  VALS(rc_radio_resource_vals), 0x03, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_req_harq_proc_tx,
			{ "HARQ Processes TX", "dect_nr.mac.rcreq.harq_proc_tx", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_req_max_harq_retx,
			{ "Max HARQ RE-TX", "dect_nr.mac.rcreq.max_harq_retx", FT_UINT8, BASE_DEC,
			  VALS(ar_max_harq_re_rxtx_vals), 0x1F, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_req_harq_proc_rx,
			{ "HARQ Processes RX", "dect_nr.mac.rcreq.harq_proc_rx", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_req_max_harq_rerx,
			{ "Max HARQ RE-RX", "dect_nr.mac.rcreq.max_harq_rerx", FT_UINT8, BASE_DEC,
			  VALS(ar_max_harq_re_rxtx_vals), 0x1F, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_req_setup_release,
			{ "Setup/Release", "dect_nr.mac.rcreq.setup_release", FT_BOOLEAN, 8,
			  TFS(&rc_setup_release_tfs), 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_req_res,
			{ "Reserved", "dect_nr.mac.rcreq.res1", FT_UINT8, BASE_DEC,
			  NULL, 0x40, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_req_flow_id,
			{ "Flow ID", "dect_nr.mac.rcreq.flow_id", FT_UINT8, BASE_DEC,
			  NULL, 0x3F, NULL, HFILL }
		},

		/* 6.4.2.8: Reconfiguration Response message */
		{ &hf_dect_nr_rc_rsp_msg,
			{ "Reconfiguration Response message", "dect_nr.mac.rcrsp", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_rsp_tx_harq_field,
			{ "TX HARQ", "dect_nr.mac.rcrsp.tx_harq_field", FT_BOOLEAN, 8,
			  TFS(&rc_harq_rsp_tfs), 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_rsp_rx_harq_field,
			{ "RX HARQ", "dect_nr.mac.rcrsp.rx_harq_field", FT_BOOLEAN, 8,
			  TFS(&rc_harq_rsp_tfs), 0x40, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_rsp_rd_capability,
			{ "RD Capability", "dect_nr.mac.rcrsp.rd_capability", FT_BOOLEAN, 8,
			  TFS(&rc_rd_capability_rsp_tfs), 0x20, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_rsp_num_flows,
			{ "Number of flows", "dect_nr.mac.rcrsp.num_flows", FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS,
			  VALS(rc_rsp_num_flow_vals), 0x1C, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_rsp_radio_resources,
			{ "Radio Resource", "dect_nr.mac.rcrsp.radio_resources", FT_UINT8, BASE_DEC,
			  VALS(rc_radio_resource_vals), 0x03, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_rsp_harq_proc_tx,
			{ "HARQ Processes TX", "dect_nr.mac.rcrsp.harq_proc_tx", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_rsp_max_harq_retx,
			{ "Max HARQ RE-TX", "dect_nr.mac.rcrsp.max_harq_retx", FT_UINT8, BASE_DEC,
			  VALS(ar_max_harq_re_rxtx_vals), 0x1F, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_rsp_harq_proc_rx,
			{ "HARQ Processes RX", "dect_nr.mac.rcrsp.harq_proc_rx", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_rsp_max_harq_rerx,
			{ "Max HARQ RE-RX", "dect_nr.mac.rcrsp.max_harq_rerx", FT_UINT8, BASE_DEC,
			  VALS(ar_max_harq_re_rxtx_vals), 0x1F, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_rsp_setup_release,
			{ "Setup/Release", "dect_nr.mac.rcrsp.setup_release", FT_BOOLEAN, 8,
			  TFS(&rc_setup_release_tfs), 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_rsp_res,
			{ "Reserved", "dect_nr.mac.rcrsp.res1", FT_UINT8, BASE_DEC,
			  NULL, 0x40, NULL, HFILL }
		},
		{ &hf_dect_nr_rc_rsp_flow_id,
			{ "Flow ID", "dect_nr.mac.rcrsp.flow_id", FT_UINT8, BASE_DEC,
			  NULL, 0x3F, NULL, HFILL }
		},

		/* 6.4.3: MAC Information Elements */

		/* 6.4.3.1: MAC Security Info IE */
		{ &hf_dect_nr_msi_ie,
			{ "MAC Security Info IE", "dect_nr.mac.msi", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_msi_version,
			{ "Version", "dect_nr.mac.msi.version", FT_UINT8, BASE_DEC,
			  VALS(msi_version_vals), 0xC0, NULL, HFILL }
		},
		{ &hf_dect_nr_msi_key,
			{ "Key Index", "dect_nr.mac.msi.key", FT_UINT8, BASE_DEC,
			  NULL, 0x30, NULL, HFILL }
		},
		{ &hf_dect_nr_msi_ivt,
			{ "Security IV Type", "dect_nr.mac.msi.ivt", FT_UINT8, BASE_DEC,
			  VALS(msi_ivt_vals), 0x0F, NULL, HFILL }
		},
		{ &hf_dect_nr_msi_hpc,
			{ "HPC", "dect_nr.mac.msi.hpc", FT_UINT32, BASE_HEX,
			  NULL, 0x0, "Hyper Packet Counter", HFILL }
		},

		/* 6.4.3.2: Route Info IE */
		{ &hf_dect_nr_ri_ie,
			{ "Route Info IE", "dect_nr.mac.ri", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_ri_sink_address,
			{ "Sink Address", "dect_nr.mac.ri.sink_address", FT_UINT32, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_ri_route_cost,
			{ "Route Cost", "dect_nr.mac.ri.route_cost", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_ri_application_sn,
			{ "Application Sequence Number", "dect_nr.mac.ri.application_sn", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},

		/* 6.4.3.3: Resource Allocation IE */
		{ &hf_dect_nr_ra_ie,
			{ "Resource Allocation IE", "dect_nr.mac.ra", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_alloc_type,
			{ "Allocation Type", "dect_nr.mac.ra.alloc_type", FT_UINT8, BASE_DEC,
			  VALS(ra_alloc_type_vals), 0xC0, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_add_field,
			{ "Add", "dect_nr.mac.ra.add_field", FT_BOOLEAN, 8,
			  TFS(&ra_add_tfs), 0x20, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_id_field,
			{ "ID", "dect_nr.mac.ra.id_field", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x10, "Short RD ID", HFILL }
		},
		{ &hf_dect_nr_ra_repeat,
			{ "Repeat", "dect_nr.mac.ra.repeat", FT_UINT8, BASE_DEC,
			  VALS(ra_repeat_vals), 0x0E, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_sfn_field,
			{ "SFN", "dect_nr.mac.ra.sfn_field", FT_BOOLEAN, 8,
			  TFS(&ra_sfn_tfs), 0x01, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_channel_field,
			{ "Channel", "dect_nr.mac.ra.channel_field", FT_BOOLEAN, 8,
			  TFS(&ra_channel_tfs), 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_rlf_field,
			{ "RLF", "dect_nr.mac.ra.rlf_field", FT_BOOLEAN, 8,
			  TFS(&tfs_included_not_included), 0x40, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_res1,
			{ "Reserved", "dect_nr.mac.ra.res1", FT_UINT8, BASE_DEC,
			  NULL, 0x3F, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_res2,
			{ "Reserved", "dect_nr.mac.ra.res2", FT_UINT16, BASE_DEC,
			  NULL, 0xE000, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_start_ss_dl_9,
			{ "DL Start subslot", "dect_nr.mac.ra.start_ss_dl", FT_UINT16, BASE_DEC,
			  NULL, 0x1FFF, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_start_ss_dl_8,
			{ "DL Start subslot", "dect_nr.mac.ra.start_ss_dl", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_len_type_dl,
			{ "DL Length type", "dect_nr.mac.ra.len_type_dl", FT_UINT8, BASE_DEC,
			  NULL, 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_len_dl,
			{ "DL Length", "dect_nr.mac.ra.len_dl", FT_UINT8, BASE_DEC,
			  NULL, 0x7F, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_start_ss_ul_9,
			{ "UL Start subslot", "dect_nr.mac.ra.start_ss_ul", FT_UINT16, BASE_DEC,
			  NULL, 0x1FFF, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_start_ss_ul_8,
			{ "UL Start subslot", "dect_nr.mac.ra.start_ss_ul", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_len_type_ul,
			{ "UL Length type", "dect_nr.mac.ra.len_type_ul", FT_UINT8, BASE_DEC,
			  NULL, 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_len_ul,
			{ "UL Length", "dect_nr.mac.ra.len_ul", FT_UINT8, BASE_DEC,
			  NULL, 0x7F, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_short_rd_id,
			{ "Short RD ID", "dect_nr.mac.ra.short_rd_id", FT_UINT16, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_repetition,
			{ "Repetition", "dect_nr.mac.ra.repetition", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_validity,
			{ "Validity", "dect_nr.mac.ra.validity", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_sfn_value,
			{ "SFN value", "dect_nr.mac.ra.sfn_value", FT_UINT8, BASE_DEC,
			  NULL, 0x0, "System Frame Number Value", HFILL }
		},
		{ &hf_dect_nr_ra_res3,
			{ "Reserved", "dect_nr.mac.ra.res3", FT_UINT16, BASE_DEC,
			  NULL, 0xE000, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_channel,
			{ "Channel", "dect_nr.mac.ra.channel", FT_UINT16, BASE_DEC,
			 NULL, 0x1FFF, NULL, HFILL }
			},
		{ &hf_dect_nr_ra_res4,
			{ "Reserved", "dect_nr.mac.ra.res4", FT_UINT8, BASE_DEC,
			 NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_ra_rlf,
			{ "dectScheduledResourceFailure", "dect_nr.mac.ra.scheduled_resource_failure", FT_UINT8, BASE_DEC,
			  VALS(ra_scheduled_resource_failure_vals), 0x0F, NULL, HFILL }
		},

		/* 6.4.3.4: Random Access Resource IE */
		{ &hf_dect_nr_rar_ie,
			{ "Random Access Resource IE", "dect_nr.mac.rar", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_res1,
			{ "Reserved", "dect_nr.mac.rar.res1", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_repeat,
			{ "Repeat", "dect_nr.mac.rar.repeat", FT_UINT8, BASE_DEC,
			  VALS(rar_repeat_vals), 0x18, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_sfn_field,
			{ "SFN", "dect_nr.mac.rar.sfn_field", FT_BOOLEAN, 8,
			  TFS(&rar_sfn_tfs), 0x04, "System Frame Number", HFILL }
		},
		{ &hf_dect_nr_rar_channel_field,
			{ "Channel", "dect_nr.mac.rar.channel_field", FT_BOOLEAN, 8,
			  TFS(&rar_channel_tfs), 0x02, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_chan_2_field,
			{ "Chan_2", "dect_nr.mac.rar.chan2_field", FT_BOOLEAN, 8,
			  TFS(&rar_chan_2_tfs), 0x01, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_res2,
			{ "Reserved", "dect_nr.mac.rar.res2", FT_UINT16, BASE_DEC,
			  NULL, 0xFE00, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_start_ss_9,
			{ "Start subslot", "dect_nr.mac.rar.start_ss", FT_UINT16, BASE_DEC,
			  NULL, 0x01FF, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_start_ss_8,
			{ "Start subslot", "dect_nr.mac.rar.start_ss", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_len_type,
			{ "Length type", "dect_nr.mac.rar.len_type", FT_BOOLEAN, 8,
			  TFS(&pkt_len_type_tfs), 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_len,
			{ "Length", "dect_nr.mac.rar.len", FT_UINT8, BASE_DEC,
			  NULL, 0x7F, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_max_len_type,
			{ "Max Len type", "dect_nr.mac.rar.max_len_type", FT_BOOLEAN, 8,
			  TFS(&pkt_len_type_tfs), 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_max_rach_len,
			{ "Max RACH Length", "dect_nr.mac.rar.max_rach_len", FT_UINT8, BASE_DEC,
			  NULL, 0x78, "Max Random Access Channel Length", HFILL }
		},
		{ &hf_dect_nr_rar_cw_min_sig,
			{ "CW Min sig", "dect_nr.mac.rar.cw_min_sig", FT_UINT8, BASE_DEC,
			  NULL, 0x07, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_dect_delay,
			{ "DECT delay", "dect_nr.mac.rar.dect_delay", FT_BOOLEAN, 8,
			  TFS(&rar_dect_delay_tfs), 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_resp_win,
			{ "Response window", "dect_nr.mac.rar.resp_win", FT_UINT8, BASE_DEC,
			  VALS(signalled_ss_len_vals), 0x78, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_cw_max_sig,
			{ "CW Max sig", "dect_nr.mac.rar.cw_max_sig", FT_UINT8, BASE_DEC,
			  NULL, 0x07, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_repetition,
			{ "Repetition", "dect_nr.mac.rar.repetition", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_validity,
			{ "Validity", "dect_nr.mac.rar.validity", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_sfn_value,
			{ "SFN value", "dect_nr.mac.rar.sfn_value", FT_UINT8, BASE_DEC,
			  NULL, 0x0, "System Frame Number Value", HFILL }
		},
		{ &hf_dect_nr_rar_res3,
			{ "Reserved", "dect_nr.mac.rar.res3", FT_UINT16, BASE_DEC,
			  NULL, 0xE000, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_channel,
			{ "Channel", "dect_nr.mac.rar.channel", FT_UINT16, BASE_DEC,
			  NULL, 0x1FFF, NULL, HFILL }
		},
		{ &hf_dect_nr_rar_channel_2,
			{ "Channel 2", "dect_nr.mac.rar.channel_2", FT_UINT16, BASE_DEC,
			  NULL, 0x1FFF, NULL, HFILL }
		},

		/* 6.4.3.5: RD Capability IE */
		{ &hf_dect_nr_rdc_ie,
			{ "RD Capability IE", "dect_nr.mac.rdc", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_num_phy_cap,
			{ "Number of PHY Capabilities", "dect_nr.mac.rdc.num_phy_cap", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_release,
			{ "Release", "dect_nr.mac.rdc.release", FT_UINT8, BASE_DEC,
			  VALS(rdc_release_vals), 0x1F, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_res1,
			{ "Reserved", "dect_nr.mac.rdc.res1", FT_UINT8, BASE_DEC,
			  NULL, 0xC0, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_group_ass,
			{ "Group Assignment", "dect_nr.mac.rdc.group_ass", FT_BOOLEAN, 8,
			  TFS(&tfs_supported_not_supported), 0x20, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_paging,
			{ "Paging", "dect_nr.mac.rdc.paging", FT_BOOLEAN, 8,
			  TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_op_modes,
			{ "Operating Modes", "dect_nr.mac.rdc.op_modes", FT_UINT8, BASE_DEC,
			  VALS(rdc_op_mode_vals), 0x0C, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_mesh,
			{ "Mesh", "dect_nr.mac.rdc.mesh", FT_BOOLEAN, 8,
			  TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_sched,
			{ "Scheduled", "dect_nr.mac.rdc.scheduled", FT_BOOLEAN, 8,
			  TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_mac_security,
			{ "MAC Security", "dect_nr.mac.rdc.mac_security", FT_UINT8, BASE_DEC,
			  VALS(rdc_mac_security_vals), 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_dlc_type,
			{ "DLC Service Type", "dect_nr.mac.rdc.dlc_type", FT_UINT8, BASE_DEC,
			  VALS(rdc_dlc_serv_type_vals), 0x1C, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_res2,
			{ "Reserved", "dect_nr.mac.rdc.res2", FT_UINT8, BASE_DEC,
			  NULL, 0x03, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_res3,
			{ "Reserved", "dect_nr.mac.rdc.res3", FT_UINT8, BASE_DEC,
			  NULL, 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_pwr_class,
			{ "RD Power Class", "dect_nr.mac.rdc.pwr_class", FT_UINT8, BASE_DEC,
			  VALS(rdc_pwr_class_vals), 0x70, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_max_nss_rx,
			{ "Max NSS for RX", "dect_nr.mac.rdc.max_nss_rx", FT_UINT8, BASE_DEC,
			  VALS(rdc_pwr_two_field_vals), 0x0C, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_rx_for_tx_div,
			{ "RX for TX Diversity", "dect_nr.mac.rdc.rx_for_tx_div", FT_UINT8, BASE_DEC,
			  VALS(rdc_pwr_two_field_vals), 0x03, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_rx_gain,
			{ "RX Gain", "dect_nr.mac.rdc.rx_gain", FT_UINT8, BASE_DEC,
			  VALS(rdc_rx_gain_vals), 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_max_mcs,
			{ "Max MCS", "dect_nr.mac.rdc.max_mcs", FT_UINT8, BASE_DEC,
			  VALS(rdc_max_mcse_vals), 0x0F, "Max Modulation and Coding Scheme", HFILL }
		},
		{ &hf_dect_nr_rdc_soft_buf_size,
			{ "Soft-buffer Size", "dect_nr.mac.rdc.soft_buf_size", FT_UINT8, BASE_DEC,
			  VALS(rdc_soft_buf_size_vals), 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_num_harq_proc,
			{ "Number of HARQ Processes", "dect_nr.mac.rdc.num_harq_proc", FT_UINT8, BASE_DEC,
			  VALS(rdc_pwr_two_field_vals), 0x0C, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_res4,
			{ "Reserved", "dect_nr.mac.rdc.res4", FT_UINT8, BASE_DEC,
			  NULL, 0x03, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_harq_fb_delay,
			{ "HARQ feedback delay", "dect_nr.mac.rdc.harq_fb_delay", FT_UINT8, BASE_DEC,
			  VALS(rdc_harq_fb_delay_vals), 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_d_delay,
			{ "D_Delay", "dect_nr.mac.rdc.d_delay", FT_BOOLEAN, 8,
			  TFS(&tfs_supported_not_supported), 0x08, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_half_dup,
			{ "Half Duplex", "dect_nr.mac.rdc.half_dup", FT_BOOLEAN, 8,
			  TFS(&tfs_supported_not_supported), 0x04, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_res5,
			{ "Reserved", "dect_nr.mac.rdc.res5", FT_UINT8, BASE_DEC,
			  NULL, 0x03, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_phy_cap,
			{ "PHY Capability", "dect_nr.mac.rdc.phy_cap", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_rd_class_mu,
			{ "Radio Device Class: µ", "dect_nr.mac.rdc.rd_class_mu", FT_UINT8, BASE_DEC,
			  VALS(rdc_pwr_two_field_vals), 0xE0, "µ = Subcarrier scaling factor", HFILL }
		},
		{ &hf_dect_nr_rdc_rd_class_b,
			{ "Radio Device Class: β", "dect_nr.mac.rdc.rd_class_b", FT_UINT8, BASE_DEC,
			  VALS(rdc_fourier_factor_vals), 0x1E, "β = Fourier transform scaling factor", HFILL }
		},
		{ &hf_dect_nr_rdc_res6,
			{ "Reserved", "dect_nr.mac.rdc.res6", FT_UINT8, BASE_DEC,
			  NULL, 0x01, NULL, HFILL }
		},
		{ &hf_dect_nr_rdc_res7,
			{ "Reserved", "dect_nr.mac.rdc.res7", FT_UINT8, BASE_DEC,
			  NULL, 0x0F, NULL, HFILL }
		},

		/* 6.4.3.6: Neighbouring IE */
		{ &hf_dect_nr_n_ie,
			{ "Neighbouring IE", "dect_nr.mac.n", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_n_res1,
			{ "Reserved", "dect_nr.mac.n.res1", FT_UINT8, BASE_DEC,
			  NULL, 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_n_id_field,
			{ "ID", "dect_nr.mac.n.id_field", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x40, "Long RD ID", HFILL }
		},
		{ &hf_dect_nr_n_mu_field,
			{ "µ", "dect_nr.mac.n.mu_field", FT_BOOLEAN, 8,
			  TFS(&radio_device_class_tfs), 0x20, "Radio device class signalling", HFILL }
		},
		{ &hf_dect_nr_n_snr_field,
			{ "SNR", "dect_nr.mac.n.snr_field", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x10, NULL, HFILL }
		},
		{ &hf_dect_nr_n_rssi2_field,
			{ "RSSI-2", "dect_nr.mac.n.rssi2_field", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x08, NULL, HFILL }
		},
		{ &hf_dect_nr_n_pwr_const,
			{ "Power Const", "dect_nr.mac.n.pwr_const", FT_BOOLEAN, 8,
			  TFS(&tfs_yes_no), 0x04, "Power Constraints", HFILL }
		},
		{ &hf_dect_nr_n_next_channel_field,
			{ "Next Channel", "dect_nr.mac.n.next_channel_field", FT_BOOLEAN, 8,
			  TFS(&cb_next_chan_tfs), 0x02, NULL, HFILL }
		},
		{ &hf_dect_nr_n_ttn_field,
			{ "Time to next", "dect_nr.mac.n.ttn_field", FT_BOOLEAN, 8,
			  TFS(&cb_ttn_tfs), 0x01, NULL, HFILL }
		},
		{ &hf_dect_nr_n_nb_period,
			{ "Network beacon period", "dect_nr.mac.n.nb_period", FT_UINT8, BASE_DEC,
			  VALS(nb_ie_nb_period_vals), 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_n_cb_period,
			{ "Cluster beacon period", "dect_nr.mac.n.cb_period", FT_UINT8, BASE_DEC,
			  VALS(nb_ie_cb_period_vals), 0x0F, NULL, HFILL }
		},
		{ &hf_dect_nr_n_long_rd_id,
			{ "Long RD ID", "dect_nr.mac.n.long_rd_id", FT_UINT32, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_n_res2,
			{ "Reserved", "dect_nr.mac.n.res2", FT_UINT16, BASE_DEC,
			  NULL, 0xE000, NULL, HFILL }
		},
		{ &hf_dect_nr_n_next_cl_channel,
			{ "Next Cluster Channel", "dect_nr.mac.n.next_cl_channel", FT_UINT16, BASE_DEC,
			  NULL, 0x1FFF, NULL, HFILL }
		},
		{ &hf_dect_nr_n_time_to_next,
			{ "Time to next", "dect_nr.mac.n.ttn", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
			  UNS(&units_microseconds), 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_n_rssi2,
			{ "RSSI-2", "dect_nr.mac.n.rssi2", FT_UINT8, BASE_CUSTOM,
			  CF_FUNC(format_rssi_result_cf_func), 0x0, "RSSI-2 measurement result", HFILL }
		},
		{ &hf_dect_nr_n_snr,
			{ "SNR", "dect_nr.mac.n.snr", FT_UINT8, BASE_CUSTOM,
			  CF_FUNC(format_snr_result_cf_func), 0x0, "SNR measurement result", HFILL }
		},
		{ &hf_dect_nr_n_rd_class_u,
			{ "Radio Device Class: µ", "dect_nr.mac.n.rd_class_mu", FT_UINT8, BASE_DEC,
			  VALS(rdc_pwr_two_field_vals), 0xE0, "µ = Subcarrier scaling factor", HFILL }
		},
		{ &hf_dect_nr_n_rd_class_b,
			{ "Radio Device Class: β", "dect_nr.mac.n.rd_class_b", FT_UINT8, BASE_DEC,
			  VALS(rdc_fourier_factor_vals), 0x1E, "β = Fourier transform scaling factor", HFILL }
		},
		{ &hf_dect_nr_n_res3,
			{ "Reserved", "dect_nr.mac.n.res3", FT_UINT8, BASE_DEC,
			  NULL, 0x01, NULL, HFILL }
		},

		/* 6.4.3.7: Broadcast Indication IE */
		{ &hf_dect_nr_bi_ie,
			{ "Broadcast Indication IE", "dect_nr.mac.bi", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_ind_type,
			{ "Indication Type", "dect_nr.mac.bi.ind_type", FT_UINT8, BASE_DEC,
			  VALS(bi_ind_type_vals), 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_idtype,
			{ "IDType", "dect_nr.mac.bi.idtype", FT_UINT8, BASE_DEC,
			  VALS(bi_idtype_vals), 0x10, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_ack,
			{ "ACK/NACK", "dect_nr.mac.bi.ack", FT_BOOLEAN, 8,
			  TFS(&bi_ack_nack_tfs), 0x08, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_res1,
			{ "Reserved", "dect_nr.mac.bi.res1", FT_UINT8, BASE_DEC,
			  NULL, 0x0E, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_fb,
			{ "Feedback", "dect_nr.mac.bi.feedback", FT_UINT8, BASE_DEC,
			  VALS(bi_feedback_vals), 0x06, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_res_alloc,
			{ "Resource Allocation", "dect_nr.mac.bi.res_alloc", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x01, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_short_rd_id,
			{ "Short RD ID", "dect_nr.mac.bi.short_rd_id", FT_UINT16, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_long_rd_id,
			{ "Long RD ID", "dect_nr.mac.bi.long_rd_id", FT_UINT32, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_mcs_res1,
			{ "Reserved", "dect_nr.mac.bi.mcs.res1", FT_UINT8, BASE_DEC,
			  NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_mcs_channel_quality,
			{ "Channel Quality", "dect_nr.mac.bi.mcs.channel_quality", FT_UINT8, BASE_DEC,
			  VALS(cqi_vals), 0x0F, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_mimo2_res1,
			{ "Reserved", "dect_nr.mac.bi.mimo2.res1", FT_UINT8, BASE_DEC,
			  NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_mimo2_num_layers,
			{ "Number of layers", "dect_nr.mac.bi.mimo2.num_layers", FT_BOOLEAN, 8,
			  TFS(&bi_mimo2_num_layer_tfs), 0x08, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_mimo2_cb_index,
			{ "Codebook index", "dect_nr.mac.bi.mimo2.cb_index", FT_UINT8, BASE_DEC,
			  NULL, 0x07, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_mimo4_num_layers,
			{ "Number of layers", "dect_nr.mac.bi.mimo4.num_layers", FT_UINT8, BASE_DEC,
			  VALS(bi_mimo4_num_layer_vals), 0xC0, NULL, HFILL }
		},
		{ &hf_dect_nr_bi_mimo4_cb_index,
			{ "Codebook index", "dect_nr.mac.bi.mimo4.cb_index", FT_UINT8, BASE_DEC,
			  NULL, 0x3F, NULL, HFILL }
		},

		/* 6.4.3.8: Padding IE */
		{ &hf_dect_nr_pd_ie,
			{ "Padding IE", "dect_nr.mac.pd", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_pd_bytes,
			{ "Padding", "dect_nr.mac.pd.bytes", FT_BYTES, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},

		/* 6.4.3.9: Group Assignment IE */
		{ &hf_dect_nr_ga_ie,
			{ "Group Assignment IE", "dect_nr.mac.ga", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_ga_single_field,
			{ "Single", "dect_nr.mac.ga.single_field", FT_BOOLEAN, 8,
			  TFS(&dect_nr_ga_single_tfs), 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_ga_group_id,
			{ "Group ID", "dect_nr.mac.ga.group_id", FT_UINT8, BASE_DEC,
			  NULL, 0x7F, NULL, HFILL }
		},
		{ &hf_dect_nr_ga_direct,
			{ "Direct", "dect_nr.mac.ga.direct", FT_BOOLEAN, 8,
			  TFS(&ga_direct_tfs), 0x80, NULL, HFILL }
		},
		{ &hf_dect_nr_ga_resource_tag,
			{ "Resource Tag", "dect_nr.mac.ga.resource_tag", FT_UINT8, BASE_DEC,
			  NULL, 0x7F, NULL, HFILL }
		},

		/* 6.4.3.10: Load Info IE */
		{ &hf_dect_nr_li_ie,
			{ "Load Info IE", "dect_nr.mac.li", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_li_res1,
			{ "Reserved", "dect_nr.mac.li.res1", FT_UINT8, BASE_DEC,
			  NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_li_max_assoc_field,
			{ "Max assoc", "dect_nr.mac.li.max_assoc_field", FT_BOOLEAN, 8,
			  TFS(&li_max_assoc_tfs), 0x08, NULL, HFILL }
		},
		{ &hf_dect_nr_li_rd_pt_load_field,
			{ "RD PT load", "dect_nr.mac.li.rd_pt_load_field", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x04, NULL, HFILL }
		},
		{ &hf_dect_nr_li_rach_load_field,
			{ "RACH load", "dect_nr.mac.li.rach_load_field", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x02, "Random Access Channel load", HFILL }
		},
		{ &hf_dect_nr_li_channel_load_field,
			{ "Channel Load", "dect_nr.mac.li.channel_load_field", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x01, NULL, HFILL }
		},
		{ &hf_dect_nr_li_traffic_load_pct,
			{ "Traffic Load percentage", "dect_nr.mac.li.traffic_load_pct", FT_UINT8, BASE_CUSTOM,
			  CF_FUNC(format_hex_pct_cf_func), 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_li_max_assoc_8,
			{ "Max number of associated RDs", "dect_nr.mac.li.max_num_assoc", FT_UINT8, BASE_DEC,
			  NULL, 0x0, "8-bit value", HFILL }
		},
		{ &hf_dect_nr_li_max_assoc_16,
			{ "Max number of associated RDs", "dect_nr.mac.li.max_num_assoc", FT_UINT16, BASE_DEC,
			  NULL, 0x0, "16-bit value", HFILL }
		},
		{ &hf_dect_nr_li_curr_ft_pct,
			{ "Currently associated RDs in FT mode", "dect_nr.mac.li.curr_ft_pct", FT_UINT8, BASE_CUSTOM,
			  CF_FUNC(format_hex_pct_cf_func), 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_li_curr_pt_pct,
			{ "Currently associated RDs in PT mode", "dect_nr.mac.li.curr_pt_pct", FT_UINT8, BASE_CUSTOM,
			   CF_FUNC(format_hex_pct_cf_func), 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_li_rach_load_pct,
			{ "RACH load in percentage", "dect_nr.mac.li.rach_load_pct", FT_UINT8, BASE_CUSTOM,
			   CF_FUNC(format_hex_pct_cf_func), 0x0, "Random Access Channel load in percentage", HFILL }
		},
		{ &hf_dect_nr_li_subslots_free_pct,
			{ "Percentage of subslots detected free", "dect_nr.mac.li.subslots_free_pct", FT_UINT8, BASE_CUSTOM,
			   CF_FUNC(format_hex_pct_cf_func), 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_li_subslots_busy_pct,
			{ "Percentage of subslots detected busy", "dect_nr.mac.li.subslots_busy_pct", FT_UINT8, BASE_CUSTOM,
			   CF_FUNC(format_hex_pct_cf_func), 0x0, NULL, HFILL }
		},

		/* 6.4.3.12: Measurement Report IE */
		{ &hf_dect_nr_mr_ie,
			{ "Measurement Report IE", "dect_nr.mac.mr", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_mr_res1,
			{ "Reserved", "dect_nr.mac.mr.res1", FT_UINT8, BASE_DEC,
			  NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_dect_nr_mr_snr_field,
			{ "SNR", "dect_nr.mac.mr.snr_field", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x10, NULL, HFILL }
		},
		{ &hf_dect_nr_mr_rssi2_field,
			{ "RSSI-2", "dect_nr.mac.mr.rssi2_field", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x08, NULL, HFILL }
		},
		{ &hf_dect_nr_mr_rssi1_field,
			{ "RSSI-1", "dect_nr.mac.mr.rssi1_field", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x04, NULL, HFILL }
		},
		{ &hf_dect_nr_mr_tx_count_field,
			{ "TX count", "dect_nr.mac.mr.tx_count_field", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x02, NULL, HFILL }
		},
		{ &hf_dect_nr_mr_rach,
			{ "RACH", "dect_nr.mac.mr.rach", FT_BOOLEAN, 8,
			  TFS(&mr_rach_tfs), 0x01, "Random Access Channel", HFILL }
		},
		{ &hf_dect_nr_mr_snr,
			{ "SNR result", "dect_nr.mac.mr.snr", FT_UINT8, BASE_CUSTOM,
			  CF_FUNC(format_snr_result_cf_func), 0x0, "SNR measurement result", HFILL }
		},
		{ &hf_dect_nr_mr_rssi2,
			{ "RSSI-2 result", "dect_nr.mac.mr.rssi2", FT_UINT8, BASE_CUSTOM,
			  CF_FUNC(format_rssi_result_cf_func), 0x0, "RSSI-2 measurement result", HFILL }
		},
		{ &hf_dect_nr_mr_rssi1,
			{ "RSSI-1 result", "dect_nr.mac.mr.rssi1", FT_UINT8, BASE_CUSTOM,
			  CF_FUNC(format_rssi_result_cf_func), 0x0, "RSSI-1 measurement result", HFILL }
		},
		{ &hf_dect_nr_mr_tx_count,
			{ "TX Count result", "dect_nr.mac.mr.tx_count", FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS,
			  VALS(mr_tx_count_vals), 0x0, NULL, HFILL }
		},

		/* 6.4.3.13: Radio Device Status IE */
		{ &hf_dect_nr_rds_ie,
			{ "Radio Device Status IE", "dect_nr.mac.rds", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_rds_res1,
			{ "Reserved", "dect_nr.mac.rds.res1", FT_UINT8, BASE_DEC,
			  NULL, 0xC0, NULL, HFILL }
		},
		{ &hf_dect_nr_rds_sf,
			{ "Status Flag", "dect_nr.mac.rds.sf", FT_UINT8, BASE_DEC,
			  VALS(rds_status_vals), 0x30, NULL, HFILL }
		},
		{ &hf_dect_nr_rds_dur,
			{ "Duration", "dect_nr.mac.rds.duration", FT_UINT8, BASE_DEC,
			  VALS(rds_duration_vals), 0x0F, NULL, HFILL }
		},

		/* Escape */
		{ &hf_dect_nr_escape,
			{ "Escape", "dect_nr.mac.escape", FT_BYTES, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},

		/* IE type extension */
		{ &hf_dect_nr_ie_type_extension,
			{ "IE Type Extension", "dect_nr.mac.ie_type_extension", FT_UINT8, BASE_DEC_HEX,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_ie_extension,
			{ "Extension data", "dect_nr.mac.ie_extension", FT_BYTES, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},

		/* MIC */
		{ &hf_dect_nr_mic_bytes,
			{ "Message Integrity Code (MIC)", "dect_nr.mac.mic_bytes", FT_BYTES, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},

		/* DLC Headers and Messages */

		{ &hf_dect_nr_dlc_pdu,
			{ "DLC PDU", "dect_nr.dlc", FT_NONE, BASE_NONE,
			  NULL, 0x0, "Data Link Control (layer) PDU", HFILL }
		},
		{ &hf_dect_nr_dlc_ie_type,
			{ "IE Type", "dect_nr.dlc.ie_type", FT_UINT8, BASE_DEC,
			  VALS(dlc_ie_type_vals), 0xF0, NULL, HFILL }
		},

		/* DLC Service Type 0 */
		{ &hf_dect_nr_dlc_res1,
			{ "Reserved", "dect_nr.dlc.res1", FT_UINT8, BASE_DEC,
			  NULL, 0x0F, NULL, HFILL }
		},

		/* DLC Service Type 1 */
		{ &hf_dect_nr_dlc_si,
			{ "Segmentation indication", "dect_nr.dlc.si", FT_UINT8, BASE_DEC,
			  VALS(dlc_si_type_vals), 0x0C, NULL, HFILL }
		},
		{ &hf_dect_nr_dlc_sn,
			{ "Sequence number", "dect_nr.dlc.sn", FT_UINT16, BASE_DEC,
			  NULL, 0x03FF, NULL, HFILL }
		},
		{ &hf_dect_nr_dlc_segm_offset,
			{ "Segmentation offset", "dect_nr.dlc.so", FT_UINT16, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},

		/* DLC Timers configuration control IE */
		{ &hf_dect_nr_dlc_timers,
			{ "DLC SDU lifetime timer", "dect_nr.dlc.sdu_lifetime_timer", FT_UINT8, BASE_DEC,
			  VALS(dlc_discard_timer_vals), 0x0, NULL, HFILL }
		},

		/* DLC Routing header */
		{ &hf_dect_nr_dlc_routing,
			{ "DLC Routing header", "dect_nr.dlc.routing", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_dlc_routing_res1,
			{ "Reserved", "dect_nr.dlc.routing.res1", FT_UINT8, BASE_DEC,
			  NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_dect_nr_dlc_routing_qos,
			{ "QoS", "dect_nr.dlc.routing.qos", FT_UINT8, BASE_DEC,
			  VALS(dlc_qos_vals), 0x0E, NULL, HFILL }
		},
		{ &hf_dect_nr_dlc_routing_delay_field,
			{ "Delay", "dect_nr.dlc.routing.delay_field", FT_BOOLEAN, 8,
			  TFS(&tfs_present_not_present), 0x01, NULL, HFILL }
		},
		{ &hf_dect_nr_dlc_routing_hop_count_limit,
			{ "Hop-Count/Limit", "dect_nr.dlc.routing.hop_count_limit", FT_UINT8, BASE_DEC,
			  VALS(dlc_hop_count_limit_vals), 0xC0, NULL, HFILL }
		},
		{ &hf_dect_nr_dlc_routing_dest_add,
			{ "Dest_Add", "dect_nr.dlc.routing.dest_addr", FT_UINT8, BASE_DEC,
			  VALS(dlc_dest_add_vals), 0x38, NULL, HFILL }
		},
		{ &hf_dect_nr_dlc_routing_type,
			{ "Routing type", "dect_nr.dlc.routing.type", FT_UINT8, BASE_DEC,
			  VALS(dlc_routing_type_vals), 0x07, NULL, HFILL }
		},
		{ &hf_dect_nr_dlc_routing_src_addr,
			{ "Source Address", "dect_nr.dlc.routing.src_addr", FT_UINT32, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_dlc_routing_dst_addr,
			{ "Destination Address", "dect_nr.dlc.routing.dst_addr", FT_UINT32, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_dlc_routing_hop_count,
			{ "Hop-count", "dect_nr.dlc.routing.hop_count", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_dlc_routing_hop_limit,
			{ "Hop-limit", "dect_nr.dlc.routing.hop_limit", FT_UINT8, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_dlc_routing_delay,
			{ "Delay", "dect_nr.dlc.routing.delay", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
			  UNS(&units_microseconds), 0x0, NULL, HFILL }
		},

		/* Higher layer signalling */
		{ &hf_dect_nr_hls_bin,
			{ "DLC data", "dect_nr.dlc.data", FT_BYTES, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},

		/* Undecoded */
		{ &hf_dect_nr_undecoded,
			{ "Undecoded", "dect_nr.undecoded", FT_BYTES, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},

		/* Fragment entries */
		{ &hf_dect_nr_segments,
			{ "DLC segments", "dect_nr.dlc.segments", FT_NONE, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_segment,
			{ "DLC segment", "dect_nr.dlc.segment", FT_FRAMENUM, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_segment_overlap,
			{ "DLC segment overlap", "dect_nr.dlc.segment.overlap", FT_BOOLEAN, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_segment_overlap_conflict,
			{ "DLC segment overlapping with conflicting data", "dect_nr.dlc.segment.overlap.conflict", FT_BOOLEAN, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_segment_multiple_tails,
			{ "DLC has multiple tails", "dect_nr.dlc.segment.multiple_tails", FT_BOOLEAN, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_segment_too_long_segment,
			{ "DLC segment too long", "dect_nr.dlc.segment.too_long_segment", FT_BOOLEAN, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_segment_error,
			{ "DLC segment error", "dect_nr.dlc.segment.error", FT_FRAMENUM, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_segment_count,
			{ "DLC segment count", "dect_nr.dlc.segment.count", FT_UINT32, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dect_nr_reassembled_in,
			{ "Reassembled DLC in frame", "dect_nr.dlc.reassembled.in", FT_FRAMENUM, BASE_NONE,
			  NULL, 0x0, "This DLC data is reassembled in this frame", HFILL }
		},
		{ &hf_dect_nr_reassembled_length,
			{ "Reassembled DLC length", "dect_nr.dlc.reassembled.length", FT_UINT32, BASE_DEC,
			  NULL, 0x0, "The total length of the reassembled payload", HFILL }
		},
	};

	static int *ett[] = {
		&ett_dect_nr,
		&ett_dect_nr_phf,
		&ett_dect_nr_mac_pdu,
		&ett_dect_nr_data_hdr,
		&ett_dect_nr_bc_hdr,
		&ett_dect_nr_uc_hdr,
		&ett_dect_nr_rdbh_hdr,
		&ett_dect_nr_mux_hdr,
		&ett_dect_nr_nb_msg,
		&ett_dect_nr_cb_msg,
		&ett_dect_nr_a_req_msg,
		&ett_dect_nr_a_rsp_msg,
		&ett_dect_nr_a_rel_msg,
		&ett_dect_nr_rc_req_msg,
		&ett_dect_nr_rc_rsp_msg,
		&ett_dect_nr_msi_ie,
		&ett_dect_nr_ri_ie,
		&ett_dect_nr_ra_ie,
		&ett_dect_nr_rar_ie,
		&ett_dect_nr_rdc_ie,
		&ett_dect_nr_rdc_phy_cap,
		&ett_dect_nr_n_ie,
		&ett_dect_nr_bi_ie,
		&ett_dect_nr_ga_ie,
		&ett_dect_nr_li_ie,
		&ett_dect_nr_mr_ie,
		&ett_dect_nr_rds_ie,
		&ett_dect_nr_dlc_pdu,
		&ett_dect_nr_dlc_routing,
		&ett_dect_nr_segment,
		&ett_dect_nr_segments,
	};

	static ei_register_info ei[] = {
		{ &ei_dect_nr_ie_length_not_set,
			{ "dect_nr.expert.ie_length_not_set", PI_MALFORMED, PI_ERROR,
			  "IE length not set (length = -1)", EXPFILL }
		},
		{ &ei_dect_nr_pdu_cut_short,
			{ "dect_nr.expert.pdu_cut_short", PI_MALFORMED, PI_WARN,
			  "PDU incomplete, perhaps trace was cut off", EXPFILL }
		},
		{ &ei_dect_nr_length_mismatch,
			{ "dect_nr.expert.length_mismatch", PI_PROTOCOL, PI_WARN,
			  "Length mismatch", EXPFILL }
		},
		{ &ei_dect_nr_res_non_zero,
			{ "dect_nr.expert.res_non_zero", PI_PROTOCOL, PI_WARN,
			  "Reserved bits are non-zero", EXPFILL }
		},
		{ &ei_dect_nr_undecoded,
			{ "dect_nr.expert.undecoded", PI_PROTOCOL, PI_WARN,
			  "Undecoded", EXPFILL }
		}
	};

	proto_dect_nr = proto_register_protocol("DECT NR+ (DECT-2020 New Radio)", "DECT NR+", "dect_nr");
	proto_register_field_array(proto_dect_nr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_module_t *expert = expert_register_protocol(proto_dect_nr);
	expert_register_field_array(expert, ei, array_length(ei));

	reassembly_table_register(&dect_nr_reassembly_table, &dect_nr_reassembly_functions);

	dect_nr_handle = register_dissector("dect_nr", dissect_dect_nr, proto_dect_nr);

	ie_dissector_table = register_dissector_table("dect_nr.msg_ie", "DECT NR+ IE", proto_dect_nr, FT_UINT32, BASE_DEC);
	ie_short_dissector_table = register_dissector_table("dect_nr.msg_ie_short", "DECT NR+ IE short", proto_dect_nr, FT_UINT32, BASE_DEC);

	module_t *module = prefs_register_protocol(proto_dect_nr, NULL);
	prefs_register_enum_preference(module, "phf_type", "Physical Header Field Type",
				       "Automatic will determine type from 6th and 7th packet byte.",
				       &phf_type_pref, phf_type_pref_vals, false);
	prefs_register_enum_preference(module, "dlc_data_type", "DLC PDU data type",
				       "Automatic will use heuristics to determine payload.",
				       &dlc_data_type_pref, dlc_data_type_pref_vals, false);

	heur_subdissector_list = register_heur_dissector_list("dect_nr.dlc", proto_dect_nr);
}

void proto_reg_handoff_dect_nr(void)
{
	data_handle = find_dissector("data");
	ipv6_handle = find_dissector("ipv6");

	/* Table 6.3.4-2: IE type field encoding for MAC Extension field encoding 00, 01, 10 */
	dissector_add_uint("dect_nr.msg_ie", 0, create_dissector_handle(dissect_padding_ie, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 1, create_dissector_handle(dissect_higher_layer_sig_flow_1, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 2, create_dissector_handle(dissect_higher_layer_sig_flow_2, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 3, create_dissector_handle(dissect_user_plane_data_flow_1, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 4, create_dissector_handle(dissect_user_plane_data_flow_2, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 5, create_dissector_handle(dissect_user_plane_data_flow_3, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 6, create_dissector_handle(dissect_user_plane_data_flow_4, proto_dect_nr));
	/* 7: Reserved */
	dissector_add_uint("dect_nr.msg_ie", 8, create_dissector_handle(dissect_network_beacon_msg, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 9, create_dissector_handle(dissect_cluster_beacon_msg, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 10, create_dissector_handle(dissect_association_request_msg, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 11, create_dissector_handle(dissect_association_response_msg, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 12, create_dissector_handle(dissect_association_release_msg, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 13, create_dissector_handle(dissect_reconfiguration_request_msg, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 14, create_dissector_handle(dissect_reconfiguration_response_msg, proto_dect_nr));
	/* 15: 6.4.2.9: Additional MAC message */
	dissector_add_uint("dect_nr.msg_ie", 16, create_dissector_handle(dissect_security_info_ie, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 17, create_dissector_handle(dissect_route_info_ie, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 18, create_dissector_handle(dissect_resource_allocation_ie, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 19, create_dissector_handle(dissect_random_access_resource_ie, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 20, create_dissector_handle(dissect_rd_capability_ie, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 21, create_dissector_handle(dissect_neighbouring_ie, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 22, create_dissector_handle(dissect_broadcast_indication_ie, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 23, create_dissector_handle(dissect_group_assignment_ie, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 24, create_dissector_handle(dissect_load_info_ie, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 25, create_dissector_handle(dissect_measurement_report_ie, proto_dect_nr));
	/* 26 - 61: Reserved */
	dissector_add_uint("dect_nr.msg_ie", 62, create_dissector_handle(dissect_escape, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie", 63, create_dissector_handle(dissect_ie_type_extension, proto_dect_nr));

	/* Table 6.3.4-4: IE type field encoding for MAC extension field encoding 11 and payload length of 1 byte */
	dissector_add_uint("dect_nr.msg_ie_short", 0, create_dissector_handle(dissect_padding_ie, proto_dect_nr));
	dissector_add_uint("dect_nr.msg_ie_short", 1, create_dissector_handle(dissect_radio_device_status_ie, proto_dect_nr));
	/* 2 - 29: Reserved */
	dissector_add_uint("dect_nr.msg_ie_short", 30, create_dissector_handle(dissect_escape, proto_dect_nr));

	dissector_add_uint("wtap_encap", WTAP_ENCAP_DECT_NR, dect_nr_handle);
	dissector_add_for_decode_as_with_preference("udp.port", dect_nr_handle);
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
