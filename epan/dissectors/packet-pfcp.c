/* packet-pfcp.c
 *
 * Routines for Packet Forwarding Control Protocol (PFCP) dissection
 *
 * Copyright 2017-2018, Anders Broman <anders.broman@ericsson.com>
 *
 * Updates and corrections:
 * Copyright 2017-2022, Joakim Karlsson <oakimk@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref 3GPP TS 29.244 V17.5.0 (2022-06-23)
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/sminmpec.h>
#include <epan/addr_resolv.h> /* Needed for BASE_ENTERPRISES */
#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-ip.h"

void proto_register_pfcp(void);
void proto_reg_handoff_pfcp(void);

static dissector_handle_t pfcp_handle;
static dissector_handle_t pfcp_3gpp_ies_handle;
static dissector_handle_t pfcp_travelping_ies_handle;
static dissector_handle_t pfcp_bbf_ies_handle;

#define UDP_PORT_PFCP  8805
static guint g_pfcp_port = UDP_PORT_PFCP;

static int proto_pfcp = -1;

static int hf_pfcp_msg_type = -1;
static int hf_pfcp_msg_length = -1;
static int hf_pfcp_hdr_flags = -1;
static int hf_pfcp_version = -1;
static int hf_pfcp_fo_flag = -1;
static int hf_pfcp_mp_flag = -1;
static int hf_pfcp_s_flag = -1;
static int hf_pfcp_seid = -1;
static int hf_pfcp_seqno = -1;
static int hf_pfcp_mp = -1;

static int hf_pfcp2_ie = -1;
static int hf_pfcp2_ie_len = -1;
static int hf_pfcp2_enterprise_ie = -1;
static int hf_pfcp_enterprise_id = -1;
static int hf_pfcp_enterprise_data = -1;

static int hf_pfcp_response_in = -1;
static int hf_pfcp_response_to = -1;
static int hf_pfcp_response_time = -1;

static int hf_pfcp_session = -1;

static int hf_pfcp_spare_b0 = -1;
static int hf_pfcp_spare_b1 = -1;
static int hf_pfcp_spare_b2 = -1;
static int hf_pfcp_spare_b3 = -1;
static int hf_pfcp_spare_b4 = -1;
static int hf_pfcp_spare_b5 = -1;
static int hf_pfcp_spare_b6 = -1;
static int hf_pfcp_spare_b7 = -1;
static int hf_pfcp_spare_b7_b6 = -1;
static int hf_pfcp_spare_b7_b5 = -1;
static int hf_pfcp_spare_b7_b4 = -1;
static int hf_pfcp_spare_b7_b3 = -1;
static int hf_pfcp_spare_b7_b2 = -1;
static int hf_pfcp_spare_b7_b1 = -1;
static int hf_pfcp_spare_h0 = -1;
static int hf_pfcp_spare_h1 = -1;
static int hf_pfcp_spare_oct = -1;
static int hf_pfcp_spare = -1;

static int hf_pfcp2_cause = -1;
static int hf_pfcp_node_id_type = -1;
static int hf_pfcp_node_id_ipv4 = -1;
static int hf_pfcp_node_id_ipv6 = -1;
static int hf_pfcp_node_id_fqdn = -1;
static int hf_pfcp_recovery_time_stamp = -1;
static int hf_pfcp_b0_v6 = -1;
static int hf_pfcp_b1_v4 = -1;
static int hf_pfcp_f_seid_ipv4 = -1;
static int hf_pfcp_f_seid_ipv6 = -1;
static int hf_pfcp_pdr_id = -1;
static int hf_pfcp_precedence = -1;
static int hf_pfcp_source_interface = -1;
static int hf_pfcp_fteid_flg_spare = -1;
static int hf_pfcp_fteid_flg_b3_ch_id = -1;
static int hf_pfcp_fteid_flg_b2_ch = -1;
static int hf_pfcp_fteid_flg_b1_v6 = -1;
static int hf_pfcp_fteid_flg_b0_v4 = -1;
static int hf_pfcp_f_teid_ch_id = -1;
static int hf_pfcp_f_teid_teid = -1;
static int hf_pfcp_f_teid_ipv4 = -1;
static int hf_pfcp_f_teid_ipv6 = -1;
static int hf_pfcp_network_instance = -1;
static int hf_pfcp_pdn_type = -1;
static int hf_pfcp_failed_rule_id_type = -1;
static int hf_pfcp_time_quota_mechanism_bti_type = -1;
static int hf_pfcp_time_quota_mechanism_bti = -1;
static int hf_pfcp_multiplier_value_digits = -1;
static int hf_pfcp_multiplier_exponent = -1;

static int hf_pfcp_ue_ip_address_flag_b0_v6 = -1;
static int hf_pfcp_ue_ip_address_flag_b1_v4 = -1;
static int hf_pfcp_ue_ip_address_flag_b2_sd = -1;
static int hf_pfcp_ue_ip_address_flag_b3_v6d = -1;
static int hf_pfcp_ue_ip_address_flag_b4_chv4 = -1;
static int hf_pfcp_ue_ip_address_flag_b5_chv6 = -1;
static int hf_pfcp_ue_ip_address_flag_b6_v6pl = -1;
static int hf_pfcp_ue_ip_addr_ipv4 = -1;
static int hf_pfcp_ue_ip_add_ipv6 = -1;
static int hf_pfcp_ue_ip_add_ipv6_prefix_delegation_bits = -1;
static int hf_pfcp_ue_ip_add_ipv6_prefix_length = -1;
static int hf_pfcp_application_id = -1;
static int hf_pfcp_application_id_str = -1;

static int hf_pfcp_sdf_filter_flags_b0_fd = -1;
static int hf_pfcp_sdf_filter_flags_b1_ttc = -1;
static int hf_pfcp_sdf_filter_flags_b2_spi = -1;
static int hf_pfcp_sdf_filter_flags_b3_fl = -1;
static int hf_pfcp_sdf_filter_flags_b4_bid = -1;

static int hf_pfcp_flow_desc_len = -1;
static int hf_pfcp_flow_desc = -1;
static int hf_pfcp_traffic_class = -1;
static int hf_pfcp_traffic_mask = -1;
static int hf_pfcp_traffic_dscp = -1;
static int hf_pfcp_spi = -1;
static int hf_pfcp_flow_label_spare_bit = -1;
static int hf_pfcp_flow_label = -1;
static int hf_pfcp_sdf_filter_id = -1;

static int hf_pfcp_out_hdr_desc = -1;
static int hf_pfcp_gtpu_ext_hdr_del_b0_pdu_sess_cont = -1;
static int hf_pfcp_far_id_flg = -1;
static int hf_pfcp_far_id = -1;
static int hf_pfcp_urr_id_flg = -1;
static int hf_pfcp_urr_id = -1;
static int hf_pfcp_qer_id_flg = -1;
static int hf_pfcp_qer_id = -1;
static int hf_pfcp_predef_rules_name = -1;



static int hf_pfcp_apply_action_flags_o6_b4_mbsu = -1;
static int hf_pfcp_apply_action_flags_o6_b3_fssm = -1;
static int hf_pfcp_apply_action_flags_o6_b2_ddpn = -1;
static int hf_pfcp_apply_action_flags_o6_b1_bdpn = -1;
static int hf_pfcp_apply_action_flags_o6_b0_edrt = -1;
static int hf_pfcp_apply_action_flags_o5_b7_dfrt = -1;
static int hf_pfcp_apply_action_flags_o5_b6_ipmd = -1;
static int hf_pfcp_apply_action_flags_o5_b5_ipma = -1;
static int hf_pfcp_apply_action_flags_o5_b4_dupl = -1;
static int hf_pfcp_apply_action_flags_o5_b3_nocp = -1;
static int hf_pfcp_apply_action_flags_o5_b2_buff = -1;
static int hf_pfcp_apply_action_flags_o5_b1_forw = -1;
static int hf_pfcp_apply_action_flags_o5_b0_drop = -1;

static int hf_pfcp_bar_id = -1;
static int hf_pfcp_fq_csid_node_id_type = -1;
static int hf_pfcp_num_csid = -1;
static int hf_pfcp_fq_csid_node_id_ipv4 = -1;
static int hf_pfcp_fq_csid_node_id_ipv6 = -1;
static int hf_pfcp_fq_csid_node_id_mcc_mnc = -1;
static int hf_pfcp_fq_csid_node_id_int = -1;
static int hf_pfcp_fq_csid = -1;
static int hf_pfcp_fq_csid_node_type = -1;
static int hf_pfcp_measurement_period = -1;
static int hf_pfcp_duration_measurement = -1;
static int hf_pfcp_time_of_first_packet = -1;
static int hf_pfcp_time_of_last_packet = -1;
static int hf_pfcp_dst_interface = -1;
static int hf_pfcp_redirect_address_type = -1;
static int hf_pfcp_redirect_server_addr_len = -1;
static int hf_pfcp_redirect_server_address = -1;
static int hf_pfcp_other_redirect_server_addr_len = -1;
static int hf_pfcp_other_redirect_server_address = -1;
static int hf_pfcp_redirect_port = -1;
static int hf_pfcp_outer_hdr_desc = -1;
static int hf_pfcp_outer_hdr_creation_teid = -1;
static int hf_pfcp_outer_hdr_creation_ipv4 = -1;
static int hf_pfcp_outer_hdr_creation_ipv6 = -1;
static int hf_pfcp_outer_hdr_creation_port = -1;
static int hf_pfcp_time_threshold = -1;
static int hf_pfcp_forwarding_policy_id_len = -1;
static int hf_pfcp_forwarding_policy_id = -1;

static int hf_pfcp_measurement_method_flags_b0_durat = -1;
static int hf_pfcp_measurement_method_flags_b1_volume = -1;
static int hf_pfcp_measurement_method_flags_b2_event = -1;

static int hf_pfcp_subsequent_time_threshold = -1;
static int hf_pfcp_inactivity_detection_time = -1;
static int hf_pfcp_monitoring_time = -1;

static int hf_pfcp_reporting_triggers_o5_b7_liusa = -1;
static int hf_pfcp_reporting_triggers_o5_b6_droth = -1;
static int hf_pfcp_reporting_triggers_o5_b5_stopt = -1;
static int hf_pfcp_reporting_triggers_o5_b4_start = -1;
static int hf_pfcp_reporting_triggers_o5_b3_quhti = -1;
static int hf_pfcp_reporting_triggers_o5_b2_timth = -1;
static int hf_pfcp_reporting_triggers_o5_b1_volth = -1;
static int hf_pfcp_reporting_triggers_o5_b0_perio = -1;
static int hf_pfcp_reporting_triggers_o6_b7_quvti = -1;
static int hf_pfcp_reporting_triggers_o6_b6_ipmjl = -1;
static int hf_pfcp_reporting_triggers_o6_b5_evequ = -1;
static int hf_pfcp_reporting_triggers_o6_b4_eveth = -1;
static int hf_pfcp_reporting_triggers_o6_b3_macar = -1;
static int hf_pfcp_reporting_triggers_o6_b2_envcl = -1;
static int hf_pfcp_reporting_triggers_o6_b1_timqu = -1;
static int hf_pfcp_reporting_triggers_o6_b0_volqu = -1;
static int hf_pfcp_reporting_triggers_o7_b1_upint = -1;
static int hf_pfcp_reporting_triggers_o7_b0_reemr = -1;

static int hf_pfcp_volume_threshold_b2_dlvol = -1;
static int hf_pfcp_volume_threshold_b1_ulvol = -1;
static int hf_pfcp_volume_threshold_b0_tovol = -1;
static int hf_pfcp_volume_threshold_tovol = -1;
static int hf_pfcp_volume_threshold_ulvol = -1;
static int hf_pfcp_volume_threshold_dlvol = -1;

static int hf_pfcp_volume_quota_b2_dlvol = -1;
static int hf_pfcp_volume_quota_b1_ulvol = -1;
static int hf_pfcp_volume_quota_b0_tovol = -1;
static int hf_pfcp_volume_quota_tovol = -1;
static int hf_pfcp_volume_quota_ulvol = -1;
static int hf_pfcp_volume_quota_dlvol = -1;

static int hf_pfcp_subseq_volume_threshold_b2_dlvol = -1;
static int hf_pfcp_subseq_volume_threshold_b1_ulvol = -1;
static int hf_pfcp_subseq_volume_threshold_b0_tovol = -1;
static int hf_pfcp_subseq_volume_threshold_tovol = -1;
static int hf_pfcp_subseq_volume_threshold_ulvol = -1;
static int hf_pfcp_subseq_volume_threshold_dlvol = -1;

static int hf_pfcp_time_quota = -1;
static int hf_pfcp_start_time = -1;
static int hf_pfcp_end_time = -1;
static int hf_pfcp_quota_holding_time = -1;
static int hf_pfcp_dropped_dl_traffic_threshold_b1_dlby = -1;
static int hf_pfcp_dropped_dl_traffic_threshold_b0_dlpa = -1;
static int hf_pfcp_downlink_packets = -1;
static int hf_pfcp_bytes_downlink_data = -1;
static int hf_pfcp_qer_correlation_id = -1;
static int hf_pfcp_gate_status_b0b1_dlgate = -1;
static int hf_pfcp_gate_status_b3b2_ulgate = -1;
static int hf_pfcp_ul_mbr = -1;
static int hf_pfcp_dl_mbr = -1;
static int hf_pfcp_ul_gbr = -1;
static int hf_pfcp_dl_gbr = -1;

static int hf_pfcp_report_type_b6_uisr = -1;
static int hf_pfcp_report_type_b5_sesr = -1;
static int hf_pfcp_report_type_b4_tmir = -1;
static int hf_pfcp_report_type_b3_upir = -1;
static int hf_pfcp_report_type_b2_erir = -1;
static int hf_pfcp_report_type_b1_usar = -1;
static int hf_pfcp_report_type_b0_dldr = -1;

static int hf_pfcp_offending_ie = -1;
static int hf_pfcp_offending_ie_value = -1;

static int hf_pfcp_up_function_features_o11_b5_upidp = -1;
static int hf_pfcp_up_function_features_o11_b4_ratp = -1;
static int hf_pfcp_up_function_features_o11_b3_eppi = -1;
static int hf_pfcp_up_function_features_o11_b2_psuprm = -1;
static int hf_pfcp_up_function_features_o11_b1_mbsn4 = -1;
static int hf_pfcp_up_function_features_o11_b0_drqos = -1;
static int hf_pfcp_up_function_features_o10_b7_dnsts = -1;
static int hf_pfcp_up_function_features_o10_b6_iprep = -1;
static int hf_pfcp_up_function_features_o10_b5_resps = -1;
static int hf_pfcp_up_function_features_o10_b4_upber = -1;
static int hf_pfcp_up_function_features_o10_b3_l2tp = -1;
static int hf_pfcp_up_function_features_o10_b2_nspoc = -1;
static int hf_pfcp_up_function_features_o10_b1_quosf = -1;
static int hf_pfcp_up_function_features_o10_b0_rttwp = -1;
static int hf_pfcp_up_function_features_o9_b7_rds = -1;
static int hf_pfcp_up_function_features_o9_b6_ddds = -1;
static int hf_pfcp_up_function_features_o9_b5_ethar = -1;
static int hf_pfcp_up_function_features_o9_b4_ciot = -1;
static int hf_pfcp_up_function_features_o9_b3_mt_edt = -1;
static int hf_pfcp_up_function_features_o9_b2_gpqm = -1;
static int hf_pfcp_up_function_features_o9_b1_qfqm = -1;
static int hf_pfcp_up_function_features_o9_b0_atsss_ll = -1;
static int hf_pfcp_up_function_features_o8_b7_mptcp = -1;
static int hf_pfcp_up_function_features_o8_b6_tscu = -1;
static int hf_pfcp_up_function_features_o8_b5_ip6pl = -1;
static int hf_pfcp_up_function_features_o8_b4_iptv = -1;
static int hf_pfcp_up_function_features_o8_b3_norp = -1;
static int hf_pfcp_up_function_features_o8_b2_vtime = -1;
static int hf_pfcp_up_function_features_o8_b1_rttl = -1;
static int hf_pfcp_up_function_features_o8_b0_mpas = -1;
static int hf_pfcp_up_function_features_o7_b7_gcom = -1;
static int hf_pfcp_up_function_features_o7_b6_bundl = -1;
static int hf_pfcp_up_function_features_o7_b5_mte_n4 = -1;
static int hf_pfcp_up_function_features_o7_b4_mnop = -1;
static int hf_pfcp_up_function_features_o7_b3_sset = -1;
static int hf_pfcp_up_function_features_o7_b2_ueip = -1;
static int hf_pfcp_up_function_features_o7_b1_adpdp = -1;
static int hf_pfcp_up_function_features_o7_b0_dpdra = -1;
static int hf_pfcp_up_function_features_o6_b7_epfar = -1;
static int hf_pfcp_up_function_features_o6_b6_pfde = -1;
static int hf_pfcp_up_function_features_o6_b5_frrt = -1;
static int hf_pfcp_up_function_features_o6_b4_trace = -1;
static int hf_pfcp_up_function_features_o6_b3_quoac = -1;
static int hf_pfcp_up_function_features_o6_b2_udbc = -1;
static int hf_pfcp_up_function_features_o6_b1_pdiu = -1;
static int hf_pfcp_up_function_features_o6_b0_empu = -1;
static int hf_pfcp_up_function_features_o5_b7_treu = -1;
static int hf_pfcp_up_function_features_o5_b6_heeu = -1;
static int hf_pfcp_up_function_features_o5_b5_pfdm = -1;
static int hf_pfcp_up_function_features_o5_b4_ftup = -1;
static int hf_pfcp_up_function_features_o5_b3_trst = -1;
static int hf_pfcp_up_function_features_o5_b2_dlbd = -1;
static int hf_pfcp_up_function_features_o5_b1_ddnd = -1;
static int hf_pfcp_up_function_features_o5_b0_bucp = -1;

static int hf_pfcp_sequence_number = -1;
static int hf_pfcp_metric = -1;
static int hf_pfcp_timer_unit = -1;
static int hf_pfcp_timer_value = -1;

static int hf_pfcp_usage_report_trigger_o5_b7_immer = -1;
static int hf_pfcp_usage_report_trigger_o5_b6_droth = -1;
static int hf_pfcp_usage_report_trigger_o5_b5_stopt = -1;
static int hf_pfcp_usage_report_trigger_o5_b4_start = -1;
static int hf_pfcp_usage_report_trigger_o5_b3_quhti = -1;
static int hf_pfcp_usage_report_trigger_o5_b2_timth = -1;
static int hf_pfcp_usage_report_trigger_o5_b1_volth = -1;
static int hf_pfcp_usage_report_trigger_o5_b0_perio = -1;
static int hf_pfcp_usage_report_trigger_o6_b7_eveth = -1;
static int hf_pfcp_usage_report_trigger_o6_b6_macar = -1;
static int hf_pfcp_usage_report_trigger_o6_b5_envcl = -1;
static int hf_pfcp_usage_report_trigger_o6_b4_monit = -1;
static int hf_pfcp_usage_report_trigger_o6_b3_termr = -1;
static int hf_pfcp_usage_report_trigger_o6_b2_liusa = -1;
static int hf_pfcp_usage_report_trigger_o6_b1_timqu = -1;
static int hf_pfcp_usage_report_trigger_o6_b0_volqu = -1;
static int hf_pfcp_usage_report_trigger_o7_b5_upint = -1;
static int hf_pfcp_usage_report_trigger_o7_b4_emrre = -1;
static int hf_pfcp_usage_report_trigger_o7_b3_quvti = -1;
static int hf_pfcp_usage_report_trigger_o7_b2_ipmjl = -1;
static int hf_pfcp_usage_report_trigger_o7_b1_tebur = -1;
static int hf_pfcp_usage_report_trigger_o7_b0_evequ = -1;

static int hf_pfcp_volume_measurement_b5_dlnop = -1;
static int hf_pfcp_volume_measurement_b4_ulnop = -1;
static int hf_pfcp_volume_measurement_b3_tonop = -1;
static int hf_pfcp_volume_measurement_b2_dlvol = -1;
static int hf_pfcp_volume_measurement_b1_ulvol = -1;
static int hf_pfcp_volume_measurement_b0_tovol = -1;
static int hf_pfcp_vol_meas_tovol = -1;
static int hf_pfcp_vol_meas_ulvol = -1;
static int hf_pfcp_vol_meas_dlvol = -1;
static int hf_pfcp_vol_meas_tonop = -1;
static int hf_pfcp_vol_meas_ulnop = -1;
static int hf_pfcp_vol_meas_dlnop = -1;

static int hf_pfcp_cp_function_features_o6_b1_rpgur = -1;
static int hf_pfcp_cp_function_features_o6_b0_psucc = -1;
static int hf_pfcp_cp_function_features_o5_b7_uiaur = -1;
static int hf_pfcp_cp_function_features_o5_b6_ardr = -1;
static int hf_pfcp_cp_function_features_o5_b5_mpas = -1;
static int hf_pfcp_cp_function_features_o5_b4_bundl = -1;
static int hf_pfcp_cp_function_features_o5_b3_sset = -1;
static int hf_pfcp_cp_function_features_o5_b2_epfar = -1;
static int hf_pfcp_cp_function_features_o5_b1_ovrl = -1;
static int hf_pfcp_cp_function_features_o5_b0_load = -1;

static int hf_pfcp_usage_information_b3_ube = -1;
static int hf_pfcp_usage_information_b2_uae = -1;
static int hf_pfcp_usage_information_b1_aft = -1;
static int hf_pfcp_usage_information_b0_bef = -1;

static int hf_pfcp_application_instance_id = -1;
static int hf_pfcp_application_instance_id_str = -1;
static int hf_pfcp_flow_dir = -1;
static int hf_pfcp_packet_rate_b0_ulpr = -1;
static int hf_pfcp_packet_rate_b1_dlpr = -1;
static int hf_pfcp_packet_rate_b2_aprc = -1;
static int hf_pfcp_ul_time_unit = -1;
static int hf_pfcp_max_ul_pr = -1;
static int hf_pfcp_dl_time_unit = -1;
static int hf_pfcp_max_dl_pr = -1;
static int hf_pfcp_a_ul_time_unit = -1;
static int hf_pfcp_a_max_ul_pr = -1;
static int hf_pfcp_a_dl_time_unit = -1;
static int hf_pfcp_a_max_dl_pr = -1;

static int hf_pfcp_dl_flow_level_marking_b0_ttc = -1;
static int hf_pfcp_dl_flow_level_marking_b1_sci = -1;

static int hf_pfcp_sci = -1;
static int hf_pfcp_dl_data_notification_delay = -1;
static int hf_pfcp_packet_count = -1;
static int hf_pfcp_dl_data_service_inf_b0_ppi = -1;
static int hf_pfcp_dl_data_service_inf_b1_qfii = -1;
static int hf_pfcp_ppi = -1;

static int hf_pfcp_pfcpsmreq_flags_b0_drobu = -1;
static int hf_pfcp_pfcpsmreq_flags_b1_sndem = -1;
static int hf_pfcp_pfcpsmreq_flags_b2_qaurr = -1;
static int hf_pfcp_pfcpsmreq_flags_b3_sumpc = -1;
static int hf_pfcp_pfcpsmreq_flags_b4_rumuc = -1;

static int hf_pfcp_pfcpsrrsp_flags_b0_drobu = -1;

static int hf_pfcp_pfd_contents_flags_b7_adnp = -1;
static int hf_pfcp_pfd_contents_flags_b6_aurl = -1;
static int hf_pfcp_pfd_contents_flags_b5_afd = -1;
static int hf_pfcp_pfd_contents_flags_b4_dnp = -1;
static int hf_pfcp_pfd_contents_flags_b3_cp = -1;
static int hf_pfcp_pfd_contents_flags_b2_dn = -1;
static int hf_pfcp_pfd_contents_flags_b1_url = -1;
static int hf_pfcp_pfd_contents_flags_b0_fd = -1;

static int hf_pfcp_url_len = -1;
static int hf_pfcp_url = -1;
static int hf_pfcp_dn_len = -1;
static int hf_pfcp_dn = -1;
static int hf_pfcp_cp_len = -1;
static int hf_pfcp_cp = -1;
static int hf_pfcp_dnp_len = -1;
static int hf_pfcp_dnp = -1;
static int hf_pfcp_afd_len = -1;
static int hf_pfcp_aurl_len = -1;
static int hf_pfcp_adnp_len = -1;
static int hf_pfcp_header_type = -1;
static int hf_pfcp_hf_len = -1;
static int hf_pfcp_hf_name = -1;
static int hf_pfcp_hf_val_len = -1;
static int hf_pfcp_hf_val = -1;

static int hf_pfcp_measurement_info_b0_mbqe = -1;
static int hf_pfcp_measurement_info_b1_inam = -1;
static int hf_pfcp_measurement_info_b2_radi = -1;
static int hf_pfcp_measurement_info_b3_istm = -1;
static int hf_pfcp_measurement_info_b4_mnop = -1;
static int hf_pfcp_measurement_info_b5_sspoc = -1;
static int hf_pfcp_measurement_info_b6_aspoc = -1;
static int hf_pfcp_measurement_info_b7_ciam = -1;

static int hf_pfcp_node_report_type_b0_upfr = -1;
static int hf_pfcp_node_report_type_b1_uprr = -1;
static int hf_pfcp_node_report_type_b2_ckdr = -1;
static int hf_pfcp_node_report_type_b3_gpqr = -1;
static int hf_pfcp_node_report_type_b4_purr = -1;
static int hf_pfcp_node_report_type_b5_vsr = -1;

static int hf_pfcp_remote_gtp_u_peer_flags_b0_v6 = -1;
static int hf_pfcp_remote_gtp_u_peer_flags_b1_v4 = -1;
static int hf_pfcp_remote_gtp_u_peer_flags_b2_di = -1;
static int hf_pfcp_remote_gtp_u_peer_flags_b3_ni = -1;
static int hf_pfcp_remote_gtp_u_peer_ipv4 = -1;
static int hf_pfcp_remote_gtp_u_peer_ipv6 = -1;
static int hf_pfcp_remote_gtp_u_peer_length_di = -1;
static int hf_pfcp_remote_gtp_u_peer_length_ni = -1;
static int hf_pfcp_ur_seqn = -1;

static int hf_pfcp_oci_flags_b0_aoci = -1;

static int hf_pfcp_pfcp_assoc_rel_req_b0_sarr = -1;

static int hf_pfcp_upiri_flags_b0_v4 = -1;
static int hf_pfcp_upiri_flags_b1_v6 = -1;
static int hf_pfcp_upiri_flg_b6_assosi = -1;
static int hf_pfcp_upiri_flg_b5_assoni = -1;
static int hf_pfcp_upiri_flg_b2b4_teidri = -1;
static int hf_pfcp_upiri_teidri = -1;
static int hf_pfcp_upiri_teid_range = -1;
static int hf_pfcp_upiri_ipv4 = -1;
static int hf_pfcp_upiri_ipv6 = -1;

static int hf_pfcp_user_plane_inactivity_timer = -1;

static int hf_pfcp_subsequent_volume_quota_b2_dlvol = -1;
static int hf_pfcp_subsequent_volume_quota_b1_ulvol = -1;
static int hf_pfcp_subsequent_volume_quota_b0_tovol = -1;
static int hf_pfcp_subsequent_volume_quota_tovol = -1;
static int hf_pfcp_subsequent_volume_quota_ulvol = -1;
static int hf_pfcp_subsequent_volume_quota_dlvol = -1;

static int hf_pfcp_subsequent_time_quota = -1;

static int hf_pfcp_rqi_flag = -1;
static int hf_pfcp_qfi = -1;
static int hf_pfcp_query_urr_reference = -1;
static int hf_pfcp_additional_usage_reports_information_b14_b0_number_value = -1;
static int hf_pfcp_additional_usage_reports_information_b15_auri = -1;
static int hf_pfcp_traffic_endpoint_id = -1;

static int hf_pfcp_mac_address_flags_b3_udes = -1;
static int hf_pfcp_mac_address_flags_b2_usou = -1;
static int hf_pfcp_mac_address_flags_b1_dest = -1;
static int hf_pfcp_mac_address_flags_b0_sour = -1;
static int hf_pfcp_mac_address_upper_dest_mac_address = -1;
static int hf_pfcp_mac_address_upper_source_mac_address = -1;
static int hf_pfcp_mac_address_dest_mac_address = -1;
static int hf_pfcp_mac_address_source_mac_address = -1;

static int hf_pfcp_c_tag_flags_b2_vid = -1;
static int hf_pfcp_c_tag_flags_b1_dei = -1;
static int hf_pfcp_c_tag_flags_b0_pcp = -1;
static int hf_pfcp_c_tag_cvid = -1;
static int hf_pfcp_c_tag_dei_flag = -1;
static int hf_pfcp_c_tag_pcp_value = -1;

static int hf_pfcp_s_tag_flags_b2_vid = -1;
static int hf_pfcp_s_tag_flags_b1_dei = -1;
static int hf_pfcp_s_tag_flags_b0_pcp = -1;
static int hf_pfcp_s_tag_svid = -1;
static int hf_pfcp_s_tag_dei_flag = -1;
static int hf_pfcp_s_tag_pcp_value = -1;

static int hf_pfcp_ethertype = -1;

static int hf_pfcp_proxying_flags_b1_ins = -1;
static int hf_pfcp_proxying_flags_b0_arp = -1;

static int hf_pfcp_ethertype_filter_id = -1;

static int hf_pfcp_ethertype_filter_properties_flags_b0_bide = -1;

static int hf_pfcp_suggested_buffering_packets_count_packet_count = -1;

static int hf_pfcp_user_id_flags_b6_peif = -1;
static int hf_pfcp_user_id_flags_b5_gpsif = -1;
static int hf_pfcp_user_id_flags_b4_supif = -1;
static int hf_pfcp_user_id_flags_b3_naif = -1;
static int hf_pfcp_user_id_flags_b2_msisdnf = -1;
static int hf_pfcp_user_id_flags_b1_imeif = -1;
static int hf_pfcp_user_id_flags_b0_imsif = -1;
static int hf_pfcp_user_id_length_of_imsi = -1;
static int hf_pfcp_user_id_length_of_imei = -1;
static int hf_pfcp_user_id_imei = -1;
static int hf_pfcp_user_id_length_of_msisdn = -1;
static int hf_pfcp_user_id_length_of_nai = -1;
static int hf_pfcp_user_id_nai = -1;
static int hf_pfcp_user_id_length_of_supi = -1;
static int hf_pfcp_user_id_supi = -1;
static int hf_pfcp_user_id_length_of_gpsi = -1;
static int hf_pfcp_user_id_gpsi = -1;
static int hf_pfcp_user_id_length_of_pei = -1;
static int hf_pfcp_user_id_pei = -1;

static int hf_pfcp_ethernet_pdu_session_information_flags_b0_ethi = -1;

static int hf_pfcp_mac_addresses_detected_number_of_mac_addresses = -1;
static int hf_pfcp_mac_addresses_detected_mac_address = -1;
static int hf_pfcp_mac_addresses_detected_length_of_ctag = -1;
static int hf_pfcp_mac_addresses_detected_length_of_stag = -1;

static int hf_pfcp_mac_addresses_removed_number_of_mac_addresses = -1;
static int hf_pfcp_mac_addresses_removed_mac_address = -1;
static int hf_pfcp_mac_addresses_removed_length_of_ctag = -1;
static int hf_pfcp_mac_addresses_removed_length_of_stag = -1;

static int hf_pfcp_ethernet_inactivity_timer = -1;

static int hf_pfcp_subsequent_event_quota = -1;

static int hf_pfcp_subsequent_event_threshold = -1;

static int hf_pfcp_trace_information_trace_id = -1;
static int hf_pfcp_trace_information_length_trigger_events = -1;
static int hf_pfcp_trace_information_trigger_events = -1;
static int hf_pfcp_trace_information_session_trace_depth = -1;
static int hf_pfcp_trace_information_length_list_interfaces = -1;
static int hf_pfcp_trace_information_list_interfaces = -1;
static int hf_pfcp_trace_information_length_ipaddress = -1;
static int hf_pfcp_trace_information_ipv4 = -1;
static int hf_pfcp_trace_information_ipv6 = -1;

static int hf_pfcp_framed_route = -1;
static int hf_pfcp_framed_routing = -1;
static int hf_pfcp_framed_ipv6_route = -1;

static int hf_pfcp_event_quota = -1;

static int hf_pfcp_event_threshold = -1;

static int hf_pfcp_time_stamp = -1;

static int hf_pfcp_averaging_window = -1;

static int hf_pfcp_paging_policy_indicator = -1;

static int hf_pfcp_apn_dnn = -1;

static int hf_pfcp_tgpp_interface_type = -1;

static int hf_pfcp_pfcpsrreq_flags_b0_psdbu = -1;

static int hf_pfcp_pfcpaureq_flags_b0_parps = -1;

static int hf_pfcp_activation_time = -1;
static int hf_pfcp_deactivation_time = -1;

static int hf_pfcp_mar_id = -1;

static int hf_pfcp_steering_functionality = -1;
static int hf_pfcp_steering_mode = -1;

static int hf_pfcp_weight = -1;
static int hf_pfcp_priority = -1;

static int hf_pfcp_ue_ip_address_pool_length = -1;
static int hf_pfcp_ue_ip_address_pool_identity = -1;

static int hf_pfcp_alternative_smf_ip_address_flags_ppe = -1;
static int hf_pfcp_alternative_smf_ip_address_ipv4 = -1;
static int hf_pfcp_alternative_smf_ip_address_ipv6 = -1;

static int hf_pfcp_packet_replication_and_detection_carry_on_information_flags_b3_dcaroni = -1;
static int hf_pfcp_packet_replication_and_detection_carry_on_information_flags_b2_prin6i = -1;
static int hf_pfcp_packet_replication_and_detection_carry_on_information_flags_b1_prin19i = -1;
static int hf_pfcp_packet_replication_and_detection_carry_on_information_flags_b0_priueai = -1;

static int hf_pfcp_validity_time_value = -1;

static int hf_pfcp_number_of_reports = -1;

static int hf_pfcp_pfcpasrsp_flags_flags_b1_uupsi = -1;
static int hf_pfcp_pfcpasrsp_flags_flags_b0_psrei = -1;

static int hf_pfcp_cp_pfcp_entity_ip_address_ipv4 = -1;
static int hf_pfcp_cp_pfcp_entity_ip_address_ipv6 = -1;

static int hf_pfcp_pfcpsereq_flags_flags_b1_sumpc = -1;
static int hf_pfcp_pfcpsereq_flags_flags_b0_resti = -1;

static int hf_pfcp_ip_multicast_address_flags_b3_any = -1;
static int hf_pfcp_ip_multicast_address_flags_b2_range = -1;
static int hf_pfcp_ip_multicast_address_start_ipv4 = -1;
static int hf_pfcp_ip_multicast_address_start_ipv6 = -1;
static int hf_pfcp_ip_multicast_address_end_ipv4 = -1;
static int hf_pfcp_ip_multicast_address_end_ipv6 = -1;

static int hf_pfcp_source_ip_address_flags_b2_mpl = -1;
static int hf_pfcp_source_ip_address_ipv4 = -1;
static int hf_pfcp_source_ip_address_ipv6 = -1;
static int hf_pfcp_source_ip_address_mask_prefix_lengt = -1;

static int hf_pfcp_packet_rate_status_flags_b2_apr = -1;
static int hf_pfcp_packet_rate_status_flags_b1_dl = -1;
static int hf_pfcp_packet_rate_status_flags_b0_ul = -1;
static int hf_pfcp_packet_rate_status_ul = -1;
static int hf_pfcp_packet_rate_status_dl = -1;
static int hf_pfcp_packet_rate_status_apr_ul = -1;
static int hf_pfcp_packet_rate_status_apr_dl = -1;
static int hf_pfcp_packet_rate_status_validity_time = -1;

static int hf_pfcp_create_bridge_info_for_tsc_flags_b0_bii = -1;

static int hf_pfcp_ds_tt_port_number = -1;

static int hf_pfcp_nw_tt_port_number = -1;

static int hf_pfcp_5gs_user_plane_node_flags_b0_bid = -1;
static int hf_pfcp_5gs_user_plane_node_value = -1;

static int hf_pfcp_port_management_information = -1;

static int hf_pfcp_requested_clock_drift_control_information_flags_b1_rrcr = -1;
static int hf_pfcp_requested_clock_drift_control_information_flags_b0_rrto = -1;

static int hf_pfcp_time_domain_number_value = -1;

static int hf_pfcp_time_offset_threshold = -1;

static int hf_pfcp_cumulative_rate_ratio_threshold = -1;

static int hf_pfcp_time_offset_measurement = -1;

static int hf_pfcp_cumulative_rate_ratio_measurement = -1;

static int hf_pfcp_srr_id = -1;

static int hf_pfcp_requested_access_availability_control_information_flags_b0_rrca = -1;

static int hf_pfcp_availability_status = -1;
static int hf_pfcp_availability_type = -1;

static int hf_pfcp_mptcp_control_information_flags_b0_tci = -1;

static int hf_pfcp_atsss_ll_control_information_flags_b0_lli = -1;

static int hf_pfcp_pmf_control_information_flags_b2_pqpm = -1;
static int hf_pfcp_pmf_control_information_flags_b1_drtti = -1;
static int hf_pfcp_pmf_control_information_flags_b0_pmfi = -1;
static int hf_pfcp_pmf_control_information_number_of_qfi = -1;

static int hf_pfcp_mptcp_address_information_flags_b1_v6 = -1;
static int hf_pfcp_mptcp_address_information_flags_b0_v4 = -1;
static int hf_pfcp_mptcp_proxy_type = -1;
static int hf_pfcp_mptcp_proxy_port = -1;
static int hf_pfcp_mptcp_proxy_ip_address_ipv4 = -1;
static int hf_pfcp_mptcp_proxy_ip_address_ipv6 = -1;

static int hf_pfcp_ue_link_specific_ip_address_flags_b3_nv6 = -1;
static int hf_pfcp_ue_link_specific_ip_address_flags_b2_nv4 = -1;
static int hf_pfcp_ue_link_specific_ip_address_flags_b1_v6 = -1;
static int hf_pfcp_ue_link_specific_ip_address_flags_b0_v4 = -1;
static int hf_pfcp_ue_link_specific_ip_address_3gpp_ipv4 = -1;
static int hf_pfcp_ue_link_specific_ip_address_3gpp_ipv6 = -1;
static int hf_pfcp_ue_link_specific_ip_address_non3gpp_ipv4 = -1;
static int hf_pfcp_ue_link_specific_ip_address_non3gpp_ipv6 = -1;

static int hf_pfcp_pmf_address_information_flags_b2_mac = -1;
static int hf_pfcp_pmf_address_information_flags_b1_v6 = -1;
static int hf_pfcp_pmf_address_information_flags_b0_v4 = -1;
static int hf_pfcp_pmf_address_ipv4 = -1;
static int hf_pfcp_pmf_address_ipv6 = -1;
static int hf_pfcp_pmf_port_3gpp = -1;
static int hf_pfcp_pmf_port_non3gpp = -1;
static int hf_pfcp_pmf_mac_address_3gpp = -1;
static int hf_pfcp_pmf_mac_address_non3gpp = -1;

static int hf_pfcp_atsss_ll_information_flags_b0_lli = -1;

static int hf_pfcp_data_network_access_identifier = -1;

static int hf_pfcp_packet_delay_milliseconds = -1;

static int hf_pfcp_qos_report_trigger_flags_b2_ire = -1;
static int hf_pfcp_qos_report_trigger_flags_b1_thr = -1;
static int hf_pfcp_qos_report_trigger_flags_b0_per = -1;

static int hf_pfcp_gtp_u_path_interface_type_flags_b1_n3 = -1;
static int hf_pfcp_gtp_u_path_interface_type_flags_b0_n9 = -1;

static int hf_pfcp_requested_qos_monitoring_flags_b3_gtpupm = -1;
static int hf_pfcp_requested_qos_monitoring_flags_b2_rp = -1;
static int hf_pfcp_requested_qos_monitoring_flags_b1_ul = -1;
static int hf_pfcp_requested_qos_monitoring_flags_b0_dl = -1;

static int hf_pfcp_reporting_frequency_flags_b2_sesrl = -1;
static int hf_pfcp_reporting_frequency_flags_b1_perio = -1;
static int hf_pfcp_reporting_frequency_flags_b0_evett = -1;

static int hf_pfcp_packet_delay_thresholds_flags_b2_rp = -1;
static int hf_pfcp_packet_delay_thresholds_flags_b1_ul = -1;
static int hf_pfcp_packet_delay_thresholds_flags_b0_dl = -1;
static int hf_pfcp_packet_delay_thresholds_downlink = -1;
static int hf_pfcp_packet_delay_thresholds_uplink = -1;
static int hf_pfcp_packet_delay_thresholds_roundtrip = -1;

static int hf_pfcp_minimum_wait_time_seconds = -1;

static int hf_pfcp_qos_monitoring_measurement_flags_b3_plmf = -1;
static int hf_pfcp_qos_monitoring_measurement_flags_b2_rp = -1;
static int hf_pfcp_qos_monitoring_measurement_flags_b1_ul = -1;
static int hf_pfcp_qos_monitoring_measurement_flags_b0_dl = -1;
static int hf_pfcp_qos_monitoring_measurement_downlink = -1;
static int hf_pfcp_qos_monitoring_measurement_uplink = -1;
static int hf_pfcp_qos_monitoring_measurement_roundtrip = -1;

static int hf_pfcp_mt_edt_control_information_flags_b0_rdsi = -1;

static int hf_pfcp_dl_data_packets_size = -1;

static int hf_pfcp_qer_control_indications_o5_b0_rcsr = -1;

static int hf_pfcp_nf_instance_id = -1;

static int hf_pfcp_s_nssai_sst = -1;
static int hf_pfcp_s_nssai_sd = -1;

static int hf_pfcp_ip_version_flags_b1_v6 = -1;
static int hf_pfcp_ip_version_flags_b0_v4 = -1;

static int hf_pfcp_pfcpasreq_flags_flags_b0_uupsi = -1;

static int hf_pfcp_data_status_flags_b1_buff = -1;
static int hf_pfcp_data_status_flags_b0_drop = -1;

static int hf_pfcp_rds_configuration_information_flags_b0_rds = -1;

static int hf_pfcp_mptcp_application_indication_flags_b0_mai = -1;

static int hf_pfcp_user_plane_nodemanagement_information_container = -1;

static int hf_pfcp_number_of_ue_ip_addresses_b1_ipv6 = -1;
static int hf_pfcp_number_of_ue_ip_addresses_b0_ipv4 = -1;
static int hf_pfcp_number_of_ue_ip_addresses_ipv6 = -1;
static int hf_pfcp_number_of_ue_ip_addresses_ipv4 = -1;

static int hf_pfcp_validity_timer = -1;

static int hf_pfcp_rattype = -1;

static int hf_pfcp_l2tp_user_authentication_proxy_authen_type_value = -1;
static int hf_pfcp_l2tp_user_authentication_b3_pai = -1;
static int hf_pfcp_l2tp_user_authentication_b2_par = -1;
static int hf_pfcp_l2tp_user_authentication_b1_pac = -1;
static int hf_pfcp_l2tp_user_authentication_b0_pan = -1;
static int hf_pfcp_l2tp_user_authentication_proxy_authen_name_len = -1;
static int hf_pfcp_l2tp_user_authentication_proxy_authen_name = -1;
static int hf_pfcp_l2tp_user_authentication_proxy_authen_challenge_len = -1;
static int hf_pfcp_l2tp_user_authentication_proxy_authen_challenge = -1;
static int hf_pfcp_l2tp_user_authentication_proxy_authen_response_len = -1;
static int hf_pfcp_l2tp_user_authentication_proxy_authen_response = -1;
static int hf_pfcp_l2tp_user_authentication_proxy_authen_id = -1;

static int hf_pfcp_lns_address_ipv4 = -1;
static int hf_pfcp_lns_address_ipv6 = -1;

static int hf_pfcp_tunnel_preference_value = -1;

static int hf_pfcp_calling_number_value = -1;
static int hf_pfcp_called_number_value = -1;

static int hf_pfcp_l2tp_session_indications_o5_b2_rensa = -1;
static int hf_pfcp_l2tp_session_indications_o5_b1_redsa = -1;
static int hf_pfcp_l2tp_session_indications_o5_b0_reuia = -1;

static int hf_pfcp_maximum_receive_unit = -1;

static int hf_pfcp_thresholds_flags_b1_plr = -1;
static int hf_pfcp_thresholds_flags_b0_rtt = -1;
static int hf_pfcp_thresholds_rtt = -1;
static int hf_pfcp_thresholds_plr = -1;

static int hf_pfcp_l2tp_steering_mode_indications_o5_b1_ueai = -1;
static int hf_pfcp_l2tp_steering_mode_indications_o5_b0_albi = -1;

static int hf_pfcp_group_id = -1;

static int hf_pfcp_cp_ip_address_ipv4 = -1;
static int hf_pfcp_cp_ip_address_ipv6 = -1;

static int hf_pfcp_ip_address_and_port_number_replacement_flag_b0_v4 = -1;
static int hf_pfcp_ip_address_and_port_number_replacement_flag_b1_v6 = -1;
static int hf_pfcp_ip_address_and_port_number_replacement_flag_b2_dpn = -1;
static int hf_pfcp_ip_address_and_port_number_replacement_flag_b3_sipv4 = -1;
static int hf_pfcp_ip_address_and_port_number_replacement_flag_b4_sipv6 = -1;
static int hf_pfcp_ip_address_and_port_number_replacement_flag_b5_spn = -1;
static int hf_pfcp_ip_address_and_port_number_replacement_destination_ipv4 = -1;
static int hf_pfcp_ip_address_and_port_number_replacement_destination_ipv6 = -1;
static int hf_pfcp_ip_address_and_port_number_replacement_destination_port = -1;
static int hf_pfcp_ip_address_and_port_number_replacement_source_ipv4 = -1;
static int hf_pfcp_ip_address_and_port_number_replacement_source_ipv6 = -1;
static int hf_pfcp_ip_address_and_port_number_replacement_source_port = -1;

static int hf_pfcp_dns_query_filter_pattern_len = -1;
static int hf_pfcp_dns_query_filter_pattern = -1;

static int hf_pfcp_event_notification_uri = -1;

static int hf_pfcp_notification_correlation_id = -1;

static int hf_pfcp_reporting_flags_o5_b0_dupl = -1;

static int hf_pfcp_mbs_session_identifier_flag_b0_tmgi = -1;
static int hf_pfcp_mbs_session_identifier_flag_b1_ssmi = -1;
static int hf_pfcp_mbs_session_identifier_flag_b2_nidi = -1;
static int hf_pfcp_mbs_session_identifier_tmgi = -1;
static int hf_pfcp_mbs_session_identifier_nidi = -1;
static int hf_pfcp_mbs_session_identifier_source_address_type = -1;
static int hf_pfcp_mbs_session_identifier_source_address_length = -1;
static int hf_pfcp_mbs_session_identifier_source_address_ipv4 = -1;
static int hf_pfcp_mbs_session_identifier_source_address_ipv6 = -1;

static int hf_pfcp_multicast_transport_information_endpoint_identifier = -1;
static int hf_pfcp_multicast_transport_information_distribution_address_type = -1;
static int hf_pfcp_multicast_transport_information_distribution_address_length = -1;
static int hf_pfcp_multicast_transport_information_distribution_address_ipv4 = -1;
static int hf_pfcp_multicast_transport_information_distribution_address_ipv6 = -1;
static int hf_pfcp_multicast_transport_information_source_address_type = -1;
static int hf_pfcp_multicast_transport_information_source_address_length = -1;
static int hf_pfcp_multicast_transport_information_source_address_ipv4 = -1;
static int hf_pfcp_multicast_transport_information_source_address_ipv6 = -1;

static int hf_pfcp_mbsn4mbreq_flags_o5_b2_mbs_resti = -1;
static int hf_pfcp_mbsn4mbreq_flags_o5_b1_jmbssm = -1;
static int hf_pfcp_mbsn4mbreq_flags_o5_b0_pllssm = -1;

static int hf_pfcp_local_ingress_tunnel_flags_b2_ch = -1;
static int hf_pfcp_local_ingress_tunnel_flags_b1_v6 = -1;
static int hf_pfcp_local_ingress_tunnel_flags_b0_v4 = -1;
static int hf_pfcp_local_ingress_tunnel_udp_port = -1;
static int hf_pfcp_local_ingress_tunnel_ipv4 = -1;
static int hf_pfcp_local_ingress_tunnel_ipv6 = -1;

static int hf_pfcp_mbs_unicast_parameters_id = -1;

static int hf_pfcp_mbsn4resp_flags_o5_b2_n19dtr = -1;
static int hf_pfcp_mbsn4resp_flags_o5_b1_jmti = -1;
static int hf_pfcp_mbsn4resp_flags_o5_b0_nn19dt = -1;

static int hf_pfcp_tunnel_password_value = -1;

static int hf_pfcp_area_session_id_value = -1;

static int hf_pfcp_dscp_to_ppi_mapping_info_ppi_value = -1;
static int hf_pfcp_dscp_to_ppi_mapping_info_dscp_value = -1;

static int hf_pfcp_pfcpsdrsp_flags_b0_puru = -1;

static int hf_pfcp_qer_indications_flags_b0_iqfis = -1;


/* Enterprise IEs */
/* BBF */
static int hf_pfcp_bbf_up_function_features_o7_b4_lcp_keepalive_offload = -1;
static int hf_pfcp_bbf_up_function_features_o7_b3_lns = -1;
static int hf_pfcp_bbf_up_function_features_o7_b2_lac = -1;
static int hf_pfcp_bbf_up_function_features_o7_b1_ipoe = -1;
static int hf_pfcp_bbf_up_function_features_o7_b0_pppoe = -1;

static int hf_pfcp_bbf_logical_port_id = -1;
static int hf_pfcp_bbf_logical_port_id_str = -1;

static int hf_pfcp_bbf_outer_hdr_desc = -1;
static int hf_pfcp_bbf_outer_hdr_creation_tunnel_id = -1;
static int hf_pfcp_bbf_outer_hdr_creation_session_id = -1;

static int hf_pfcp_bbf_out_hdr_desc = -1;

static int hf_pfcp_bbf_pppoe_session_id = -1;

static int hf_pfcp_bbf_ppp_protocol_flags = -1;
static int hf_pfcp_bbf_ppp_protocol_b2_control = -1;
static int hf_pfcp_bbf_ppp_protocol_b1_data = -1;
static int hf_pfcp_bbf_ppp_protocol_b0_specific = -1;
static int hf_pfcp_bbf_ppp_protocol = -1;

static int hf_pfcp_bbf_verification_timer_interval = -1;
static int hf_pfcp_bbf_verification_timer_count = -1;

static int hf_pfcp_bbf_ppp_lcp_magic_number_tx = -1;
static int hf_pfcp_bbf_ppp_lcp_magic_number_rx = -1;

static int hf_pfcp_bbf_mtu = -1;

static int hf_pfcp_bbf_l2tp_endp_flags = -1;
static int hf_pfcp_bbf_l2tp_endp_flags_b2_ch = -1;
static int hf_pfcp_bbf_l2tp_endp_flags_b1_v6 = -1;
static int hf_pfcp_bbf_l2tp_endp_flags_b0_v4 = -1;
static int hf_pfcp_bbf_l2tp_endp_id_tunnel_id = -1;
static int hf_pfcp_bbf_l2tp_endp_id_ipv4 = -1;
static int hf_pfcp_bbf_l2tp_endp_id_ipv6 = -1;

static int hf_pfcp_bbf_l2tp_session_id = -1;

static int hf_pfcp_bbf_l2tp_type_flags = -1;
static int hf_pfcp_bbf_l2tp_type_flags_b0_t = -1;

/* Travelping */
static int hf_pfcp_enterprise_travelping_packet_measurement = -1;
static int hf_pfcp_enterprise_travelping_packet_measurement_b2_dlnop = -1;
static int hf_pfcp_enterprise_travelping_packet_measurement_b1_ulnop = -1;
static int hf_pfcp_enterprise_travelping_packet_measurement_b0_tonop = -1;
static int hf_pfcp_travelping_pkt_meas_tonop = -1;
static int hf_pfcp_travelping_pkt_meas_ulnop = -1;
static int hf_pfcp_travelping_pkt_meas_dlnop = -1;

static int hf_pfcp_travelping_build_id = -1;
static int hf_pfcp_travelping_build_id_str = -1;
static int hf_pfcp_travelping_now = -1;
static int hf_pfcp_travelping_error_message = -1;
static int hf_pfcp_travelping_error_message_str = -1;
static int hf_pfcp_travelping_file_name = -1;
static int hf_pfcp_travelping_file_name_str = -1;
static int hf_pfcp_travelping_line_number = -1;
static int hf_pfcp_travelping_ipfix_policy = -1;
static int hf_pfcp_travelping_ipfix_policy_str = -1;
static int hf_pfcp_travelping_trace_parent = -1;
static int hf_pfcp_travelping_trace_parent_str = -1;
static int hf_pfcp_travelping_trace_state = -1;
static int hf_pfcp_travelping_trace_state_str = -1;

static int ett_pfcp = -1;
static int ett_pfcp_flags = -1;
static int ett_pfcp_ie = -1;
static int ett_pfcp_grouped_ie = -1;
static int ett_pfcp_reporting_triggers = -1;
static int ett_pfcp_up_function_features = -1;
static int ett_pfcp_report_trigger = -1;
static int ett_pfcp_flow_desc = -1;
static int ett_pfcp_tos = -1;
static int ett_pfcp_spi = -1;
static int ett_pfcp_flow_label = -1;
static int ett_pfcp_sdf_filter_id = -1;
static int ett_pfcp_adf = -1;
static int ett_pfcp_aurl = -1;
static int ett_pfcp_adnp = -1;

static int ett_pfcp_enterprise_travelping_packet_measurement = -1;
static int ett_pfcp_enterprise_travelping_error_report = -1;
static int ett_pfcp_enterprise_travelping_created_nat_binding = -1;
static int ett_pfcp_enterprise_travelping_trace_info = -1;

static int ett_pfcp_bbf_ppp_protocol_flags = -1;
static int ett_pfcp_bbf_l2tp_endp_flags = -1;
static int ett_pfcp_bbf_l2tp_type_flags = -1;
static int ett_pfcp_bbf_ppp_lcp_connectivity = -1;
static int ett_pfcp_bbf_l2tp_tunnel = -1;

static expert_field ei_pfcp_ie_reserved = EI_INIT;
static expert_field ei_pfcp_ie_data_not_decoded = EI_INIT;
static expert_field ei_pfcp_ie_not_decoded_null = EI_INIT;
static expert_field ei_pfcp_ie_not_decoded_too_large = EI_INIT;
static expert_field ei_pfcp_enterprise_ie_3gpp = EI_INIT;
static expert_field ei_pfcp_ie_encoding_error = EI_INIT;


static gboolean g_pfcp_session = FALSE;
static guint32 pfcp_session_count;

typedef struct pfcp_rule_ids {
    guint32 far;
    guint32 pdr;
    guint32 qer;
    guint32 urr;
    guint32 bar;
    guint32 mar;
    guint32 srr;
} pfcp_rule_ids_t;

typedef struct pfcp_session_args {
    wmem_list_t *seid_list;
    wmem_list_t *ip_list;
    guint64 last_seid;
    address last_ip;
    guint8 last_cause;
    pfcp_rule_ids_t last_rule_ids;
} pfcp_session_args_t;

typedef struct _pfcp_hdr {
    guint8 message; /* Message type */
    guint16 length; /* Length of header */
    gint64 seid;    /* Tunnel End-point ID */
} pfcp_hdr_t;

/* Relation between frame -> session */
GHashTable* pfcp_session_table;
/* Relation between <seid,ip> -> frame */
wmem_tree_t* pfcp_frame_tree;

typedef struct pfcp_info {
    guint64 seid;
    guint32 frame;
} pfcp_info_t;

typedef struct _pfcp_sub_dis_t {
    guint8 message_type;
    pfcp_session_args_t *args;
} pfcp_sub_dis_t;

static dissector_table_t pfcp_enterprise_ies_dissector_table;

static void dissect_pfcp_ies_common(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint offset, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_create_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_pdi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_create_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_forwarding_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_duplicating_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_create_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_create_qer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_created_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_update_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_update_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_upd_forwarding_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_update_bar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_update_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_update_qer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_remove_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_remove_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_remove_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_remove_qer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_load_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_overload_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_application_ids_pfds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_pfd_context(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_application_detection_inf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_pfcp_query_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_usage_report_smr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_usage_report_sdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_usage_report_srr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_downlink_data_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_create_bar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_update_bar_smr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_remove_bar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_error_indication_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_user_plane_path_failure_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_update_duplicating_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_aggregated_urrs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_create_traffic_endpoint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_created_traffic_endpoint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_update_traffic_endpoint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_remove_traffic_endpoint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_ethernet_packet_filter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_ethernet_traffic_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_additional_monitoring_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_create_mar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_update_mar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_remove_mar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_access_forwarding_action_information_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_access_forwarding_action_information_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_update_access_forwarding_action_information_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_update_access_forwarding_action_information_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_user_plane_path_recovery_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_pfcp_session_retention_information_within_pfcp_association_setup_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_ip_multicast_addressing_info_within_pfcp_session_establishment_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_join_ip_multicast_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_leave_ip_multicast_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_created_bridge_info_for_tsc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_tsc_management_information_ie_within_pfcp_session_modification_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_tsc_management_information_ie_within_pfcp_session_modification_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_tsc_management_information_ie_within_pfcp_session_report_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_clock_drift_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_clock_drift_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_remove_srr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_create_srr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_update_srr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_session_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_access_availability_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_access_availability_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_provide_atsss_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_atsss_control_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_mptcp_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_atsss_ll_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_pmf_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_ue_ip_address_pool_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_gtp_u_path_qos_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_gtp_u_path_qos_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_qos_information_in_gtp_u_path_qos_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_qos_monitoring_per_qos_flow_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_qos_monitoring_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_packet_rate_status_report_ie_within_pfcp_session_deletion_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_ethernet_context_information_within_pfcp_session_modification_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_redundant_transmission_detection_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_updated_pdr_ie_within_pfcp_session_modification_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_provide_rds_configuration_information_ie_within_pfcp_session_modification_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_query_packet_rate_status_ie_within_pfcp_session_modification_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_query_packet_rate_status_report_ie_within_pfcp_session_modification_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_ue_ip_address_usage_information_ie_within_pfcp_association_update_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_redundant_transmission_forward_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_transport_dealy_reporting_ie_in_create_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_partial_failure_information_within_pfcp_session_establishment_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_partial_failure_information_within_pfcp_session_modification_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_l2tp_tunnel_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_l2tp_session_information_within_pfcp_session_establishment_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_l2tp_session_information_within_pfcp_session_establishment_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_pfcp_session_change_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_direct_reporting_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_mbs_session_n4mb_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_mbs_multicast_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_add_mbs_unicast_parameters_ie_in_create_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_mbs_session_n4mb_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_remove_mbs_unicast_parameters_ie_in_update_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_mbs_session_n4_control_information_ie_within_pfcp_session_establishment_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_mbs_session_n4_control_information_ie_within_pfcp_session_establishment_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_peer_up_restart_report_ie_within_pfcp__node_report_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);
static void dissect_pfcp_dscp_to_ppi_control_information_ie_within_pfcp_session_establishment_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args _U_);

static const true_false_string pfcp_id_predef_dynamic_tfs = {
    "Predefined by UP",
    "Dynamic by CP",
};

#define PFCP_MSG_RESERVED_0                                 0

#define PFCP_MSG_HEARTBEAT_REQUEST                          1
#define PFCP_MSG_HEARTBEAT_RESPONSE                         2
#define PFCP_MSG_PFD_MANAGEMENT_REQUEST                     3
#define PFCP_MSG_PFD_MANAGEMENT_RESPONSE                    4
#define PFCP_MSG_ASSOCIATION_SETUP_REQUEST                  5
#define PFCP_MSG_ASSOCIATION_SETUP_RESPONSE                 6
#define PFCP_MSG_ASSOCIATION_UPDATE_REQUEST                 7
#define PFCP_MSG_ASSOCIATION_UPDATE_RESPONSE                8
#define PFCP_MSG_ASSOCIATION_RELEASE_REQUEST                9
#define PFCP_MSG_ASSOCIATION_RELEASE_RESPONSE               10
#define PFCP_MSG_VERSION_NOT_SUPPORTED_RESPONSE             11
#define PFCP_MSG_NODE_REPORT_REQEUST                        12
#define PFCP_MSG_NODE_REPORT_RERESPONSE                     13
#define PFCP_MSG_SESSION_SET_DELETION_REQUEST               14
#define PFCP_MSG_SESSION_SET_DELETION_RESPONSE              15
#define PFCP_MSG_SESSION_SET_MODIFICATION_REQUEST           16
#define PFCP_MSG_SESSION_SET_MODIFICATION_RESPONSE          17
#define PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST              50
#define PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE             51
#define PFCP_MSG_SESSION_MODIFICATION_REQUEST               52
#define PFCP_MSG_SESSION_MODIFICATION_RESPONSE              53
#define PFCP_MSG_SESSION_DELETION_REQUEST                   54
#define PFCP_MSG_SESSION_DELETION_RESPONSE                  55
#define PFCP_MSG_SESSION_REPORT_REQUEST                     56
#define PFCP_MSG_SESSION_REPORT_RESPONSE                    57

static const value_string pfcp_message_type[] = {
    {PFCP_MSG_RESERVED_0,             "Reserved"},
    /* PFCP Node related messages */

    { PFCP_MSG_HEARTBEAT_REQUEST, "PFCP Heartbeat Request"},
    { PFCP_MSG_HEARTBEAT_RESPONSE, "PFCP Heartbeat Response"},
    { PFCP_MSG_PFD_MANAGEMENT_REQUEST, "PFCP PFD Management Request"},
    { PFCP_MSG_PFD_MANAGEMENT_RESPONSE, "PFCP PFD Management Response"},
    { PFCP_MSG_ASSOCIATION_SETUP_REQUEST, "PFCP Association Setup Request"},
    { PFCP_MSG_ASSOCIATION_SETUP_RESPONSE, "PFCP Association Setup Response"},
    { PFCP_MSG_ASSOCIATION_UPDATE_REQUEST, "PFCP Association Update Request"},
    { PFCP_MSG_ASSOCIATION_UPDATE_RESPONSE, "PFCP Association Update Response"},
    { PFCP_MSG_ASSOCIATION_RELEASE_REQUEST, "PFCP Association Release Request"},
    { PFCP_MSG_ASSOCIATION_RELEASE_RESPONSE, "PFCP Association Release Response"},
    { PFCP_MSG_VERSION_NOT_SUPPORTED_RESPONSE, "PFCP Version Not Supported Response"},
    { PFCP_MSG_NODE_REPORT_REQEUST, "PFCP Node Report Request"},
    { PFCP_MSG_NODE_REPORT_RERESPONSE, "PFCP Node Report Response"},
    { PFCP_MSG_SESSION_SET_DELETION_REQUEST, "PFCP Session Set Deletion Request"},
    { PFCP_MSG_SESSION_SET_DELETION_RESPONSE, "PFCP Session Set Deletion Response"},
    { PFCP_MSG_SESSION_SET_MODIFICATION_REQUEST, "PFCP Session Set Modification Request"},
    { PFCP_MSG_SESSION_SET_MODIFICATION_RESPONSE, "PFCP Session Set Modification Response"},
    //18 to 49    For future use
    //PFCP Session related messages
    { PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST, "PFCP Session Establishment Request"},
    { PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE, "PFCP Session Establishment Response"},
    { PFCP_MSG_SESSION_MODIFICATION_REQUEST, "PFCP Session Modification Request"},
    { PFCP_MSG_SESSION_MODIFICATION_RESPONSE, "PFCP Session Modification Response"},
    { PFCP_MSG_SESSION_DELETION_REQUEST, "PFCP Session Deletion Request"},
    { PFCP_MSG_SESSION_DELETION_RESPONSE, "PFCP Session Deletion Response"},
    { PFCP_MSG_SESSION_REPORT_REQUEST, "PFCP Session Report Request"},
    { PFCP_MSG_SESSION_REPORT_RESPONSE, "PFCP Session Report Response"},
    //58 to 99    For future use
    //Other messages
    //100 to 255     For future use
    {0, NULL}
};
static value_string_ext pfcp_message_type_ext = VALUE_STRING_EXT_INIT(pfcp_message_type);

/* 8.1.2    Information Element Types */
#define PFCP_IE_ID_CREATE_PDR                   1
#define PFCP_IE_ID_PDI                          2
#define PFCP_IE_CREATE_FAR                      3
#define PFCP_IE_FORWARDING_PARAMETERS           4
#define PFCP_IE_DUPLICATING_PARAMETERS          5
#define PFCP_IE_CREATE_URR                      6
#define PFCP_IE_CREATE_QER                      7
#define PFCP_IE_CREATED_PDR                     8
#define PFCP_IE_UPDATE_PDR                      9
#define PFCP_IE_UPDATE_FAR                     10
#define PFCP_IE_UPD_FORWARDING_PARAM   11
#define PFCP_IE_UPDATE_BAR                     12
#define PFCP_IE_UPDATE_URR                     13
#define PFCP_IE_UPDATE_QER                     14
#define PFCP_IE_REMOVE_PDR                     15
#define PFCP_IE_REMOVE_FAR                     16
#define PFCP_IE_REMOVE_URR                     17
#define PFCP_IE_REMOVE_QER                     18

#define PFCP_IE_LOAD_CONTROL_INFORMATION          51
#define PFCP_IE_OVERLOAD_CONTROL_INFORMATION      54
#define PFCP_IE_APPLICATION_IDS_PFDS              58
#define PFCP_IE_PFD_CONTEXT                       59
#define PFCP_IE_APPLICATION_DETECTION_INF         68
#define PFCP_IE_QUERY_URR                         77
#define PFCP_IE_USAGE_REPORT_SMR                  78
#define PFCP_IE_USAGE_REPORT_SDR                  79
#define PFCP_IE_USAGE_REPORT_SRR                  80
#define PFCP_IE_DOWNLINK_DATA_REPORT              83
#define PFCP_IE_CREATE_BAR                        85
#define PFCP_IE_UPDATE_BAR_SMR                    86
#define PFCP_IE_REMOVE_BAR                        87
#define PFCP_IE_ERROR_INDICATION_REPORT           99
#define PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT   102
#define PFCP_IE_UPDATE_DUPLICATING_PARAMETERS    105
#define PFCP_IE_AGGREGATED_URRS                  118
#define PFCP_IE_CREATE_TRAFFIC_ENDPOINT          127
#define PFCP_IE_CREATED_TRAFFIC_ENDPOINT         128
#define PFCP_IE_UPDATE_TRAFFIC_ENDPOINT          129
#define PFCP_IE_REMOVE_TRAFFIC_ENDPOINT          130
#define PFCP_IE_ETHERNET_PACKET_FILTER           132
#define PFCP_IE_ETHERNET_TRAFFIC_INFORMATION     143
#define PFCP_IE_ADDITIONAL_MONITORING_TIME       147
#define PFCP_IE_EVENT_INFORMATION                148
#define PFCP_IE_EVENT_REPORTING                  149
#define PFCP_IE_CREATE_MAR                       165
#define PFCP_IE_ACCESS_FORWARDING_ACTION_INORMATION_1 166
#define PFCP_IE_ACCESS_FORWARDING_ACTION_INORMATION_2 167
#define PFCP_IE_REMOVE_MAR                       168
#define PFCP_IE_UPDATE_MAR                       169
#define PFCP_IE_UPDATE_ACCESS_FORWARDING_ACTION_INORMATION_1 175
#define PFCP_IE_UPDATE_ACCESS_FORWARDING_ACTION_INORMATION_2 176
#define PFCP_IE_PFCP_SESSION_RETENTION_INFORMATION_WITHIN_ASSOCIATION_SETUP_REQUEST 183
#define PFCP_IE_USER_PLANE_PATH_RECOVERY_REPORT  187
#define PFCP_IE_IP_MULTICAST_ADDRESSING_INFO     189
#define PFCP_IE_JOIN_IP_MULTICAST_INFORMATION    189
#define PFCP_IE_LEAVE_IP_MULTICAST_INFORMATION   190
#define PFCP_IE_CREATED_BRIDGE_INFO_FOR_TSC      195
#define PFCP_IE_TSC_MANAGEMENT_INFORMATION_WITHIN_PCFP_SESSION_MODIFICATION_REQUEST    199
#define PFCP_IE_TSC_MANAGEMENT_INFORMATION_WITHIN_PCFP_SESSION_MODIFICATION_RESPONSE   200
#define PFCP_IE_TSC_MANAGEMENT_INFORMATION_WITHIN_PCFP_SESSION_REPORT_REQUEST          201
#define PFCP_IE_CLOCK_DRIFT_CONTROL_INFORMATION  203
#define PFCP_IE_CLOCK_DRIFT_REPORT               205
#define PFCP_IE_REMOVE_SRR                       211
#define PFCP_IE_CREATE_SRR                       212
#define PFCP_IE_UPDATE_SRR                       213
#define PFCP_IE_SESSION_REPORT                   214
#define PFCP_IE_ACCESS_AVAILABILITY_CONTROL_INFORMATION 216
#define PFCP_IE_ACCESS_AVAILABILITY_REPORT       218
#define PFCP_IE_PROVICE_ATSSS_CONTROL_INFORMATION 220
#define PFCP_IE_ATSSS_CONTROl_PARAMETERS         221
#define PFCP_IE_MPTCP_PARAMETERS                 225
#define PFCP_IE_ATSSS_LL_PARAMETERS              226
#define PFCP_IE_PMF_PARAMETERS                   227
#define PFCP_IE_UE_IP_ADDRESS_POOL_INFORMATION   233
#define PFCP_IE_GTP_U_PATH_QOS_CONTROL_INFORMATION 238
#define PFCP_IE_GTP_U_PATH_QOS_REPORT            239
#define PFCP_IE_QOS_INFORMATION_IN_GTP_U_PATH_QOS_REPORT 240
#define PFCP_IE_QOS_MONITORING_PER_QOS_FLOW_CONTROL_INFORMATION 242
#define PFCP_IE_QOS_MONITORING_REPORT            247
#define PFCP_IE_PACKET_RATE_STATUS_REPORT_IE_WITHIN_PFCP_SESSION_DELETION_RESPONSE 252
#define PCFP_IE_ETHERNET_CONTEXT_INFORMATION_WITHIN_PFCP_SESSION_MODIFICATION_REQUEST 254
#define PFCP_IE_REDUNDANT_TRANSMISSION_DETECTION_PARAMETERS_IE_IN_PDI 255
#define PFCP_IE_UPDATED_PDR_IE_WITHIN_PFCP_SESSION_MODIFICATION_RESPONSE 256
#define PFCP_IE_PROVIDE_RDS_CONFIGURATION_INFORMATION_IE_WITHIN_PCFP_SESSION_ESTABLISHMENT_REQUEST 261
#define PFCP_IE_QUERY_PACKET_RATE_STATUS_IE_WITHIN_PCFP_SESSION_ESTABLISHMENT_REQUEST 263
#define PFCP_IE_QUERY_PACKET_RATE_STATUS_REPORT_IE_WITHIN_PCFP_SESSION_ESTABLISHMENT_RESPONSE 264
#define PFCP_IE_UE_IP_ADDRESS_USAGE_INFORMATION_IE_WITHIN_PFCP_ASSOCIATION_UPDATE_REQUEST 267
#define PFCP_IE_REDUNDANT_TRANSMISSION_FORWARD_PARAMETERS_IE_IN_FAR 270
#define PFCP_IE_TRANSPORT_DELAY_REPORTING 271
#define PFCP_IE_PARTIAL_FAILURE_INFORMATION_WITHIN_PFCP_SESSION_ESTABLISHMENT_RESPONSE 272
#define PFCP_IE_PARTIAL_FAILURE_INFORMATION_WITHIN_PFCP_SESSION_MODIFICATION_RESPONSE 273
#define PFCP_IE_L2TP_TUNNEL_INFORMATION 276
#define PFCP_IE_L2TP_SESSION_INFORMATION_WITHIN_PFCP_SESSION_ESTABLISHMENT_REQUEST 277
#define PFCP_IE_L2TP_SESSION_INFORMATION_WITHIN_PFCP_SESSION_ESTABLISHMENT_RESPONSE 279
#define PFCP_IE_PFCP_SESSION_CHANGE_INFO 290
#define PFCP_IE_DIRECT_REPORTING_INFORMATION 295
#define PFCP_IE_MBS_SESSION_N4MB_CONTROL_INFORMATION 300
#define PFCP_IE_MBS_MULTICAST_PARAMETERS 301
#define PFCP_IE_ADD_MBS_UNICAST_PARAMETERS_IE_IN_CREATE_FAR 302
#define PFCP_IE_MBS_SESSION_N4MB_INFORMATION 300
#define PFCP_IE_REMOVE_MBS_UNICAST_PARAMETERS_IE_IN_UPDATE_FAR 304
#define PFCP_IE_MBS_SESSION_N4_CONTROl_INFORMATION_IE_WITHIN_PFCP_SESSION_ESTABLISHMENT_REQUEST 310
#define PFCP_IE_MBS_SESSION_N4_CONTROl_INFORMATION_IE_WITHIN_PFCP_SESSION_ESTABLISHMENT_RESPONSE 311
#define PFCP_IE_PEER_UP_REPORT_IE_WITING_PFCP_NODE_REPORT_REQUEST 315
#define PFCP_IE_DSCP_TO_PPI_CONTROL_INFORMATION_IE_WITIN_PCFP_SESSION_ESTABLISHMENT_REQUEST 316

static const value_string pfcp_ie_type[] = {

    { 0, "Reserved"},
    { 1, "Create PDR"},                                             /* Extendable / Table 7.5.2.2-1 */
    { 2, "PDI"},                                                    /* Extendable / Table 7.5.2.2-2 */
    { 3, "Create FAR"},                                             /* Extendable / Table 7.5.2.3-1 */
    { 4, "Forwarding Parameters"},                                  /* Extendable / Table 7.5.2.3-2 */
    { 5, "Duplicating Parameters"},                                 /* Extendable / Table 7.5.2.3-3 */
    { 6, "Create URR"},                                             /* Extendable / Table 7.5.2.4-1 */
    { 7, "Create QER"},                                             /* Extendable / Table 7.5.2.5-1 */
    { 8, "Created PDR"},                                            /* Extendable / Table 7.5.3.2-1 */
    { 9, "Update PDR" },                                            /* Extendable / Table 7.5.4.2-1 */
    { 10, "Update FAR" },                                           /* Extendable / Table 7.5.4.3-1 */
    { 11, "Update Forwarding Parameters" },                         /* Extendable / Table 7.5.4.3-2 */
    { 12, "Update BAR (PFCP Session Report Response)" },            /* Extendable / Table 7.5.9.2-1 */
    { 13, "Update URR" },                                           /* Extendable / Table 7.5.4.4 */
    { 14, "Update QER" },                                           /* Extendable / Table 7.5.4.5 */
    { 15, "Remove PDR" },                                           /* Extendable / Table 7.5.4.6 */
    { 16, "Remove FAR" },                                           /* Extendable / Table 7.5.4.7 */
    { 17, "Remove URR" },                                           /* Extendable / Table 7.5.4.8 */
    { 18, "Remove QER" },                                           /* Extendable / Table 7.5.4.9 */
    { 19, "Cause" },                                                /* Fixed / Subclause 8.2.1 */
    { 20, "Source Interface" },                                     /* Extendable / Subclause 8.2.2 */
    { 21, "F-TEID" },                                               /* Extendable / Subclause 8.2.3 */
    { 22, "Network Instance" },                                     /* Variable Length / Subclause 8.2.4 */
    { 23, "SDF Filter" },                                           /* Extendable / Subclause 8.2.5 */
    { 24, "Application ID" },                                       /* Variable Length / Subclause 8.2.6 */
    { 25, "Gate Status" },                                          /* Extendable / Subclause 8.2.7 */
    { 26, "MBR" },                                                  /* Extendable / Subclause 8.2.8 */
    { 27, "GBR" },                                                  /* Extendable / Subclause 8.2.9 */
    { 28, "QER Correlation ID" },                                   /* Extendable / Subclause 8.2.10 */
    { 29, "Precedence" },                                           /* Extendable / Subclause 8.2.11 */
    { 30, "Transport Level Marking" },                              /* Extendable / Subclause 8.2.12 */
    { 31, "Volume Threshold" },                                     /* Extendable /Subclause 8.2.13 */
    { 32, "Time Threshold" },                                       /* Extendable /Subclause 8.2.14 */
    { 33, "Monitoring Time" },                                      /* Extendable /Subclause 8.2.15 */
    { 34, "Subsequent Volume Threshold" },                          /* Extendable /Subclause 8.2.16 */
    { 35, "Subsequent Time Threshold" },                            /* Extendable /Subclause 8.2.17 */
    { 36, "Inactivity Detection Time" },                            /* Extendable /Subclause 8.2.18 */
    { 37, "Reporting Triggers" },                                   /* Extendable /Subclause 8.2.19 */
    { 38, "Redirect Information" },                                 /* Extendable /Subclause 8.2.20 */
    { 39, "Report Type" },                                          /* Extendable / Subclause 8.2.21 */
    { 40, "Offending IE" },                                         /* Fixed / Subclause 8.2.22 */
    { 41, "Forwarding Policy" },                                    /* Extendable / Subclause 8.2.23 */
    { 42, "Destination Interface" },                                /* Extendable / Subclause 8.2.24 */
    { 43, "UP Function Features" },                                 /* Extendable / Subclause 8.2.25 */
    { 44, "Apply Action" },                                         /* Extendable / Subclause 8.2.26 */
    { 45, "Downlink Data Service Information" },                    /* Extendable / Subclause 8.2.27 */
    { 46, "Downlink Data Notification Delay" },                     /* Extendable / Subclause 8.2.28 */
    { 47, "DL Buffering Duration" },                                /* Extendable / Subclause 8.2.29 */
    { 48, "DL Buffering Suggested Packet Count" },                  /* Variable / Subclause 8.2.30 */
    { 49, "PFCPSMReq-Flags" },                                      /* Extendable / Subclause 8.2.31 */
    { 50, "PFCPSRRsp-Flags" },                                      /* Extendable / Subclause 8.2.32 */
    { 51, "Load Control Information" },                             /* Extendable / Table 7.5.3.3-1 */
    { 52, "Sequence Number" },                                      /* Fixed Length / Subclause 8.2.33 */
    { 53, "Metric" },                                               /* Fixed Length / Subclause 8.2.34 */
    { 54, "Overload Control Information" },                         /* Extendable / Table 7.5.3.4-1 */
    { 55, "Timer" },                                                /* Extendable / Subclause 8.2 35 */
    { 56, "PDR ID" },                                               /* Extendable / Subclause 8.2 36 */
    { 57, "F-SEID" },                                               /* Extendable / Subclause 8.2 37 */
    { 58, "Application ID's PFDs" },                                /* Extendable / Table 7.4.3.1-2 */
    { 59, "PFD context" },                                          /* Extendable / Table 7.4.3.1-3 */
    { 60, "Node ID" },                                              /* Extendable / Subclause 8.2.38 */
    { 61, "PFD contents" },                                         /* Extendable / Subclause 8.2.39 */
    { 62, "Measurement Method" },                                   /* Extendable / Subclause 8.2.40 */
    { 63, "Usage Report Trigger" },                                 /* Extendable / Subclause 8.2.41 */
    { 64, "Measurement Period" },                                   /* Extendable / Subclause 8.2.42 */
    { 65, "FQ-CSID" },                                              /* Extendable / Subclause 8.2.43 */
    { 66, "Volume Measurement" },                                   /* Extendable / Subclause 8.2.44 */
    { 67, "Duration Measurement" },                                 /* Extendable / Subclause 8.2.45 */
    { 68, "Application Detection Information" },                    /* Extendable / Table 7.5.8.3-2 */
    { 69, "Time of First Packet" },                                 /* Extendable / Subclause 8.2.46 */
    { 70, "Time of Last Packet" },                                  /* Extendable / Subclause 8.2.47 */
    { 71, "Quota Holding Time" },                                   /* Extendable / Subclause 8.2.48 */
    { 72, "Dropped DL Traffic Threshold" },                         /* Extendable / Subclause 8.2.49 */
    { 73, "Volume Quota" },                                         /* Extendable / Subclause 8.2.50 */
    { 74, "Time Quota" },                                           /* Extendable / Subclause 8.2.51 */
    { 75, "Start Time" },                                           /* Extendable / Subclause 8.2.52 */
    { 76, "End Time" },                                             /* Extendable / Subclause 8.2.53 */
    { 77, "Query URR" },                                            /* Extendable / Table 7.5.4.10-1 */
    { 78, "Usage Report (Session Modification Response)" },         /* Extendable / Table 7.5.5.2-1 */
    { 79, "Usage Report (Session Deletion Response)" },             /* Extendable / Table 7.5.7.2-1 */
    { 80, "Usage Report (Session Report Request)" },                /* Extendable / Table 7.5.8.3-1 */
    { 81, "URR ID" },                                               /* Extendable / Subclause 8.2.54 */
    { 82, "Linked URR ID" },                                        /* Extendable / Subclause 8.2.55 */
    { 83, "Downlink Data Report" },                                 /* Extendable / Table 7.5.8.2-1 */
    { 84, "Outer Header Creation" },                                /* Extendable / Subclause 8.2.56 */
    { 85, "Create BAR" },                                           /* Extendable / Table 7.5.2.6-1 */
    { 86, "Update BAR (Session Modification Request)" },            /* Extendable / Table 7.5.4.11-1 */
    { 87, "Remove BAR" },                                           /* Extendable / Table 7.5.4.12-1 */
    { 88, "BAR ID" },                                               /* Extendable / Subclause 8.2.57 */
    { 89, "CP Function Features" },                                 /* Extendable / Subclause 8.2.58 */
    { 90, "Usage Information" },                                    /* Extendable / Subclause 8.2.59 */
    { 91, "Application Instance ID" },                              /* Variable Length / Subclause 8.2.60 */
    { 92, "Flow Information" },                                     /* Extendable / Subclause 8.2.61 */
    { 93, "UE IP Address" },                                        /* Extendable / Subclause 8.2.62 */
    { 94, "Packet Rate" },                                          /* Extendable / Subclause 8.2.63 */
    { 95, "Outer Header Removal" },                                 /* Extendable / Subclause 8.2.64 */
    { 96, "Recovery Time Stamp" },                                  /* Extendable / Subclause 8.2.65 */
    { 97, "DL Flow Level Marking" },                                /* Extendable / Subclause 8.2.66 */
    { 98, "Header Enrichment" },                                    /* Extendable / Subclause 8.2.67 */
    { 99, "Error Indication Report" },                              /* Extendable / Table 7.5.8.4-1 */
    { 100, "Measurement Information" },                             /* Extendable / Subclause 8.2.68 */
    { 101, "Node Report Type" },                                    /* Extendable / Subclause 8.2.69 */
    { 102, "User Plane Path Failure Report" },                      /* Extendable / Table 7.4.5.1.2-1 */
    { 103, "Remote GTP-U Peer" },                                   /* Extendable / Subclause 8.2.70 */
    { 104, "UR-SEQN" },                                             /* Fixed Length / Subclause 8.2.71 */
    { 105, "Update Duplicating Parameters" },                       /* Extendable / Table 7.5.4.3-3 */
    { 106, "Activate Predefined Rules" },                           /* Variable Length / Subclause 8.2.72 */
    { 107, "Deactivate Predefined Rules" },                         /* Variable Length / Subclause 8.2.73 */
    { 108, "FAR ID" },                                              /* Extendable / Subclause 8.2.74 */
    { 109, "QER ID" },                                              /* Extendable / Subclause 8.2.75 */
    { 110, "OCI Flags" },                                           /* Extendable / Subclause 8.2.76 */
    { 111, "PFCP Association Release Request" },                    /* Extendable / Subclause 8.2.77 */
    { 112, "Graceful Release Period" },                             /* Extendable / Subclause 8.2.78 */
    { 113, "PDN Type" },                                            /* Fixed Length / Subclause 8.2.79 */
    { 114, "Failed Rule ID" },                                      /* Extendable / Subclause 8.2.80 */
    { 115, "Time Quota Mechanism" },                                /* Extendable / Subclause 8.2.81 */
    { 116, "User Plane IP Resource Information (removed in Rel 16.3)" }, /* Extendable / Subclause 8.2.82 */
    { 117, "User Plane Inactivity Timer" },                         /* Extendable / Subclause 8.2.83 */
    { 118, "Aggregated URRs" },                                     /* Extendable / Table 7.5.2.4-2 */
    { 119, "Multiplier" },                                          /* Fixed Length / Subclause 8.2.84 */
    { 120, "Aggregated URR ID IE" },                                /* Fixed Length / Subclause 8.2.85 */
    { 121, "Subsequent Volume Quota" },                             /* Extendable / Subclause 8.2.86 */
    { 122, "Subsequent Time Quota" },                               /* Extendable / Subclause 8.2.87 */
    { 123, "RQI" },                                                 /* Extendable / Subclause 8.2.88 */
    { 124, "QFI" },                                                 /* Extendable / Subclause 8.2.89 */
    { 125, "Query URR Reference" },                                 /* Extendable / Subclause 8.2.90 */
    { 126, "Additional Usage Reports Information" },                /* Extendable / Subclause 8.2.91 */
    { 127, "Create Traffic Endpoint" },                             /* Extendable / Table 7.5.2.7 */
    { 128, "Created Traffic Endpoint" },                            /* Extendable / Table 7.5.3.5 */
    { 129, "Update Traffic Endpoint" },                             /* Extendable / Table 7.5.4.13 */
    { 130, "Remove Traffic Endpoint" },                             /* Extendable / Table 7.5.4.14 */
    { 131, "Traffic Endpoint ID" },                                 /* Extendable / Subclause 8.2.92*/
    { 132, "Ethernet Packet Filter"},                               /* Extendable / Table 7.5.2.2-3 */
    { 133, "MAC address"},                                          /* Extendable / Subclause 8.2.93 */
    { 134, "C-TAG"},                                                /* Extendable / Subclause 8.2.94 */
    { 135, "S-TAG"},                                                /* Extendable / Subclause 8.2.95 */
    { 136, "Ethertype"},                                            /* Extendable / Subclause 8.2.96 */
    { 137, "Proxying"},                                             /* Extendable / Subclause 8.2.97 */
    { 138, "Ethernet Filter ID"},                                   /* Extendable / Subclause 8.2.98 */
    { 139, "Ethernet Filter Properties"},                           /* Extendable / Subclause 8.2.99 */
    { 140, "Suggested Buffering Packets Count"},                    /* Extendable / Subclause 8.2.100 */
    { 141, "User ID"},                                              /* Extendable / Subclause 8.2.101 */
    { 142, "Ethernet PDU Session Information"},                     /* Extendable / Subclause 8.2.102 */
    { 143, "Ethernet Traffic Information"},                         /* Extendable / Table 7.5.8.3-3 */
    { 144, "MAC Addresses Detected"},                               /* Extendable / Subclause 8.2.103 */
    { 145, "MAC Addresses Removed"},                                /* Extendable / Subclause 8.2.104 */
    { 146, "Ethernet Inactivity Timer"},                            /* Extendable / Subclause 8.2.105 */
    { 147, "Additional Monitoring Time"},                           /* Extendable / Table 7.5.2.4-3 */
    { 148, "Event Quota"},                                          /* Extendable / Subclause 8.2.112 */
    { 149, "Event Threshold"},                                      /* Extendable / Subclause 8.2.113 */
    { 150, "Subsequent Event Quota"},                               /* Extendable / Subclause 8.2.106 */
    { 151, "Subsequent Event Threshold"},                           /* Extendable / Subclause 8.2.107 */
    { 152, "Trace Information"},                                    /* Extendable / Subclause 8.2.108 */
    { 153, "Framed-Route"},                                         /* Variable Length  / Subclause 8.2.109 */
    { 154, "Framed-Routing"},                                       /* Fixed Length  / Subclause 8.2.110 */
    { 155, "Framed-IPv6-Route"},                                    /* Variable Length  / Subclause 8.2.111 */
    { 156, "Time Stamp"},                                           /* Extendable / Subclause 8.2.114 */
    { 157, "Averaging Window"},                                     /* Extendable / Subclause 8.2.115 */
    { 158, "Paging Policy Indicator"},                              /* Extendable / Subclause 8.2.116 */
    { 159, "APN/DNN"},                                              /* Variable Length  / Subclause 8.2.117 */
    { 160, "3GPP Interface Type"},                                  /* Extendable / Subclause 8.2.118 */
    { 161, "PFCPSRReq-Flags"},                                      /* ExtendableClause 8.2.119 */
    { 162, "PFCPAUReq-Flags"},                                      /* ExtendableClause 8.2.120 */
    { 163, "Activation Time"},                                      /* Extendable Clause 8.2.121 */
    { 164, "Deactivation Time"},                                    /* Extendable Clause 8.2.122 */
    { 165, "Create MAR"},                                           /* Extendable / Table 7.5.2.8-1 */
    { 166, "Access Forwarding Action Information 1"},               /* Extendable / Table 7.5.2.8-2 */
    { 167, "Access Forwarding Action Information 2"},               /* Extendable / Table 7.5.2.8-3 */
    { 168, "Remove MAR"},                                           /* Extendable / Table 7.5.2.15-1 */
    { 169, "Update MAR"},                                           /* Extendable / Table 7.5.2.16-1 */
    { 175, "Update Access Forwarding Action Information 1"},        /* Fixed / Clause 8.2.126 */
    { 176, "Update Access Forwarding Action Information 2"},        /* Extendable / Clause 8.2.127 */
    { 177, "UE IP address Pool Identity"},                          /* Variable Length / Clause 8.2.128 */
    { 178, "Alternative SMF IP Address"},                           /* Extendable / Clause 8.2.129 */
    { 179, "Packet Replication and Detection Carry-On Information"},/* Extendable / Clause 8.2.130 */
    { 180, "SMF Set ID"},                                           /* Extendable / Clause 8.2.131 */
    { 181, "Quota Validity Time"},                                  /* Extendable / Clause 8.2.132 */
    { 182, "Number of Reports"},                                    /* Fixed / Clause 8.2.133 */
    { 183, "PFCP Session Retention Information (within PFCP Association Setup Request)"}, /* Extendable / Table 7.4.4.1-2 */
    { 184, "PFCPASRsp-Flags"},                                      /* Extendable / Clause 8.2.134 */
    { 185, "CP PFCP Entity IP Address"},                            /* Extendable / Clause 8.2.135 */
    { 186, "PFCPSEReq-Flags"},                                      /* Extendable / Clause 8.2.136 */
    { 187, "User Plane Path Recovery Report"},                      /* Extendable / Table 7.4.5.1.3-1 */
    { 188, "IP Multicast Addressing Info within PFCP Session Establishment Request"}, /* Extendable / Clause 7.5.2.2-4 */
    { 189, "Join IP Multicast Information IE within Usage Report"}, /* Extendable / Table 7.5.8.3-4 */
    { 190, "Leave IP Multicast Information IE within Usage Report"},/* Extendable / Table 7.5.8.3-5 */
    { 191, "IP Multicast Address"},                                 /* Extendable / Clause 8.2.137 */
    { 192, "Source IP Address"},                                    /* Extendable / Clause 8.2.138 */
    { 193, "Packet Rate Status"},                                   /* Extendable / Clause 8.2.139 */
    { 194, "Create Bridge Info for TSC"},                           /* Extendable / Clause 8.2.140 */
    { 195, "Created Bridge Info for TSC"},                          /* Extendable / Table 7.5.3.6-1 */
    { 196, "DS-TT Port Number"},                                    /* Fixed Length / Clause 8.2.141 */
    { 197, "NW-TT Port Number"},                                    /* Fixed Length / Clause 8.2.142 */
    { 198, "5GS User Plane Node"},                                  /* Extendable / Clause 8.2.143 */
    { 199, "TSC Management Information IE within PFCP Session Modification Request"}, /* Extendable / Table 7.5.4.18-1 */
    { 200, "Port Management Information for TSC IE within PFCP Session Modification Response"}, /* Extendable / Table 7.5.5.3-1 */
    { 201, "Port Management Information for TSC IE within PFCP Session Report Request"}, /* Extendable / Table 7.5.8.5-1 */
    { 202, "Port Management Information Container"},                /* Variable Length / Clause 8.2.144 */
    { 203, "Clock Drift Control Information"},                      /* Extendable / Table 7.4.4.1.2-1 */
    { 204, "Requested Clock Drift Information"},                    /* Extendable / Clause 8.2.145 */
    { 205, "Clock Drift Report"},                                   /* Extendable / Table 7.4.5.1.4-1 */
    { 206, "Time Domain Number"},                                   /* Extendable / Clause 8.2.146 */
    { 207, "Time Offset Threshold"},                                /* Extendable / Clause 8.2.147 */
    { 208, "Cumulative rateRatio Threshold"},                       /* Extendable / Clause 8.2.148 */
    { 209, "Time Offset Measurement"},                              /* Extendable / Clause 8.2.149 */
    { 210, "Cumulative rateRatio Measurement"},                     /* Extendable / Clause 8.2.150 */
    { 211, "Remove SRR"},                                           /* Extendable/ Table 7.5.4.19-1 */
    { 212, "Create SRR"},                                           /* Extendable/ Table 7.5.2.9-1 */
    { 213, "Update SRR"},                                           /* Extendable/ Table 7.5.4.21-1 */
    { 214, "Session Report"},                                       /* Extendable / Table 7.5.8.7-1 */
    { 215, "SRR ID"},                                               /* Extendable / Clause 8.2.151 */
    { 216, "Access Availability Control Information"},              /* Extendable / Table 7.5.2.9-2 */
    { 217, "Requested Access Availability Information"},            /* Extendable / Clause 8.2.152 */
    { 218, "Access Availability Report"},                           /* Extendable / Table 7.5.8.6-2 */
    { 219, "Access Availability Information"},                      /* Extendable / Clause 8.2.153 */
    { 220, "Provide ATSSS Control Information"},                    /* Extendable / Table 7.5.2.10-1 */
    { 221, "ATSSS Control Parameters"},                             /* Extendable / Table 7.5.3.7-1 */
    { 222, "MPTCP Control Information"},                            /* Extendable / Clause 8.2.154 */
    { 223, "ATSSS-LL Control Information"},                         /* Extendable / Clause 8.2.155 */
    { 224, "PMF Control Information"},                              /* Extendable / Clause 8.2.156 */
    { 225, "MPTCP Parameters"},                                     /* Extendable / Table 7.5.3.7-2 */
    { 226, "ATSSS-LL Parameters"},                                  /* Extendable / Table 7.5.3.7-3 */
    { 227, "PMF Parameters"},                                       /* Extendable / Table 7.5.3.7-4 */
    { 228, "MPTCP Address Information"},                            /* Extendable / Clause 8.2.157 */
    { 229, "UE Link-Specific IP Address"},                          /* Extendable / Clause 8.2.158 */
    { 230, "PMF Address Information"},                              /* Extendable / Clause 8.2.159 */
    { 231, "ATSSS-LL Information"},                                 /* Extendable / Clause 8.2.160 */
    { 232, "Data Network Access Identifier"},                       /* Variable Length / Clause 8.2.161 */
    { 233, "UE IP address Pool Information"},                       /* Extendable / Table 7.4.4.1-3 */
    { 234, "Average Packet Delay"},                                 /* Extendable / Clause 8.2.162 */
    { 235, "Minimum Packet Delay"},                                 /* Extendable / Clause 8.2.163 */
    { 236, "Maximum Packet Delay"},                                 /* Extendable / Clause 8.2.164 */
    { 237, "QoS Report Trigger"},                                   /* Extendable / Clause 8.2.165 */
    { 238, "GTP-U Path QoS Control Information"},                   /* Extendable / Table 7.4.4.1.3-1 */
    { 239, "GTP-U Path QoS Report (PFCP Node Report Request)"},     /* Extendable / Table 7.4.5.1.5-1 */
    { 240, "QoS Information in GTP-U Path QoS Report"},             /* Extendable / Table 7.4.5.1.6-1 */
    { 241, "GTP-U Path Interface Type"},                            /* Extendable / Clause 8.2.166 */
    { 242, "QoS Monitoring per QoS flow Control Information"},      /* Extendable / Table 7.5.2.9-3 */
    { 243, "Requested QoS Monitoring"},                             /* Extendable / Clause 8.2.167 */
    { 244, "Reporting Frequency"},                                  /* Extendable / Clause 8.2.168 */
    { 245, "Packet Delay Thresholds"},                              /* Extendable / Clause 8.2.169 */
    { 246, "Minimum Wait Time"},                                    /* Extendable / Clause 8.2.170 */
    { 247, "QoS Monitoring Report"},                                /* Extendable / Table 7.5.8.6-3 */
    { 248, "QoS Monitoring Measurement"},                           /* Extendable / Clause 8.2.171 */
    { 249, "MT-EDT Control Information"},                           /* Extendable / Clause 8.2.172 */
    { 250, "DL Data Packets Size"},                                 /* Extendable / Clause 8.2.173 */
    { 251, "QER Control Indications"},                              /* Extendable / Clause 8.2.174 */
    { 252, "Packet Rate Status Report IE within PFCP Session Deletion Response"}, /* Extendable / Table 7.5.7.1-2 */
    { 253, "NF Instance ID"},                                       /* Extendable / Clause 8.2.175 */
    { 255, "Redundant Transmission Detection Parameters IE in PDI"}, /* Extendable / Table 7.5.2.2-5 */
    { 256, "Updated PDR"},                                          /* Extendable / Table 7.5.9.3-1 */
    { 257, "S-NSSAI"},                                              /* Fixed Length / Clause 8.2.176 */
    { 258, "IP version"},                                           /* Extendable / Clause 8.2.177 */
    { 259, "PFCPASReq-Flags"},                                      /* Extendable / Clause 8.2.178 */
    { 260, "Data Status"},                                          /* Extendable / Clause 8.2.179 */
    { 261, "Provide RDS Configuration Information IE within PFCP Session Establishment Request"}, /* Extendable / Table 7.5.2.11-1  */
    { 262, "RDS Configuration Information"},                        /* Extendable / Clause 8.2.180  */
    { 263, "Query Packet Rate Status IE within PFCP Session Modification Request"}, /* Extendable / Table 7.5.4.22-1  */
    { 264, "Query Packet Rate Status Report IE within PFCP Session Modification Response"}, /* Extendable / Table 7.5.5.4-1  */
    { 265, "MPTCP Applicable Indication"},                          /* Extendable / Clause 8.2.181 */
    { 266, "User Plane NodeManagement Information Container"},              /* Variable Length / Clause 8.2.182 */
    { 267, "UE IP Address Usage Information"},                      /* Extendable / Table 7.4.4.3.1-1 */
    { 268, "Number of UE IP Addresses"},                            /* Extendable / Clause 8.2.183 */
    { 269, "Validity Timer"},                                       /* Extendable / Clause 8.2.184 */
    { 270, "Redundant Transmission Forwarding Parameters"},         /* Extendable / Table 7.5.2.3-4 */
    { 271, "Transport Delay Reporting"},                            /* Extendable / Table 7.5.2.2-6 */
    { 272, "Partial Failure Information"},                          /* Extendable / Table 7.5.3.1-2 */
    { 273, "Partial Failure Information within PFCP Session Modification Response (Removed in Rel 17.2.0)"},   /* Extendable / Table 7.5.5.1-2 */
    { 274, "Offending IE Information"},                             /* Extendable / Clause 8.2.185 */
    { 275, "RAT Type"},                                             /* Extendable / Clause 8.2.186 */
    { 276, "L2TP Tunnel Information"},                              /* Extendable / Table 7.5.2.1-2 */
    { 277, "L2TP Session Information within PFCP Session Establishment Request"},   /* Extendable / Table 7.5.2.1-3 */
    { 278, "L2TP User Authentication"},                             /* Variable Length / Clause 8.2.187 */
    { 279, "L2TP Session Information within PFCP Session Establishment Response"},   /* Extendable / Table 7.5.3.1-3 */
    { 280, "LNS Address"},                                          /* Variable Length / Clause 8.2.188 */
    { 281, "Tunnel Preference"},                                    /* Fixed / Clause 8.2.189 */
    { 282, "Calling Number"},                                       /* Variable Length / Clause 8.2.190 */
    { 283, "Called Number"},                                        /* Variable Length / Clause 8.2.191 */
    { 284, "L2TP Session Indications"},                             /* Extendable / Clause 8.2.192 */
    { 285, "DNS Server Address"},                                   /* Extendable / Clause 8.2.193 */
    { 286, "NBNS Server Address"},                                  /* Fixed / Clause 8.2.194 */
    { 287, "Maximum Receive Unit"},                                 /* Variable Length / Clause 8.2.195 */
    { 288, "Thresholds"},                                           /* Variable Length / Clause 8.2.196 */
    { 289, "Steering Mode Indicator"},                              /* Extendable / Clause 8.2.197 */
    { 290, "PFCP Session Change Info"},                             /* Extendable / Table 7.4.7.1-2 */
    { 291, "Group ID"},                                             /* Fixed / Clause 8.2.198 */
    { 292, "CP IP Address"},                                        /* Extendable / Clause 8.2.199 */
    { 293, "IP Address and Port Number Replacement"},               /* Variable Length / Clause 8.2.200 */
    { 294, "DNS Query Filter"},                                     /* Variable Length / Clause 8.2.201 */
    { 295, "Direct Reporting Information"},                         /* Extendable / Table 7.5.2.9-4 */
    { 296, "Event Notification URI"},                               /* Variable Length / Clause 8.2.202 */
    { 297, "Notification Correlation ID"},                          /* Variable Length / Clause 8.2.203 */
    { 298, "Reporting Flags"},                                      /* Extendable / Clause 8.2.204 */
    { 299, "Predefined Rules Name"},                                /* Variable Length / Clause 8.2.205 */
    { 300, "MBS Session N4mb Control Information"},                 /* Extendable / Table 7.5.2.1-5 */
    { 301, "MBS Multicast Parameters"},                             /* Extendable / Table 7.5.2.3-5 */
    { 302, "Add MBS Unicast Parameters IE in Create FAR"},          /* Extendable / Table 7.5.2.3-6 */
    { 303, "MBS Session N4mb Information"},                         /* Extendable / Table 7.5.3.1-4 */
    { 304, "Remove MBS Unicast Parameters IE in Update FAR"},       /* Extendable / Table 7.5.4.3-4 */
    { 305, "MBS Session Identifier"},                               /* Extendable Length / Clause 8.2.206 */
    { 306, "Multicast Transport Information"},                      /* Extendable Length / Clause 8.2.207 */
    { 307, "MBSN4mbReq Flags"},                                     /* Extendable Length / Clause 8.2.208 */
    { 308, "Local Ingress Tunnel"},                                 /* Extendable Length / Clause 8.2.209 */
    { 309, "MBS Unicast Parameters ID"},                            /* Extendable Length / Clause 8.2.210 */
    { 310, "MBS Session N4 Control Information IE within PFCP Session Establishment Request"},      /* Extendable / Table 7.5.2.1-6 */
    { 311, "MBS Session N4 Control Information IE within PFCP Session Establishment Response"},     /* Extendable / Table 7.5.3.1-5 */
    { 312, "MBSN4Resp-Flags"},                                      /* Extendable / Clause 8.2.211 */
    { 313, "Tunnel Password"},                                      /* Variable Length / Clause 8.2.212 */
    { 314, "Area Sesson ID"},                                       /* Fixed / Clause 8.2.213 */
    { 315, "Peer UP Restart Report IE within PFCP Node Report Request"},     /* Extendable / Table 7.4.5.1-7 */
    { 316, "DSCP to PPI Control Information IE within PFCP Session Establishment Request"},     /* Extendable / Table 7.5.2.1-6 */
    { 317, "DSCP to PPI Mapping Information"},                      /* Extendable / Clause 8.2.214 */
    { 318, "PFCPSDRsp-Flags"},                                      /* Extendable / Clause 8.2.215 */
    { 319, "QER Indications"},                                      /* Extendable / Clause 8.2.216 */
    { 320, "Vendor-Specific Node Report Type"},                     /* Extendable / Clause 8.2.217 */
    //321 to 32767 Spare. For future use.
    //32768 to 65535 Vendor-specific IEs.
    {0, NULL}
};

static value_string_ext pfcp_ie_type_ext = VALUE_STRING_EXT_INIT(pfcp_ie_type);

/* PFCP Session funcs*/
static guint32
pfcp_get_frame(packet_info *pinfo, address ip, guint64 seid, guint32 *frame) {
    gboolean found = FALSE;
    wmem_list_frame_t *elem;
    pfcp_info_t *info;
    wmem_list_t *info_list;
    gchar *ip_str;

    /* First we get the seid list*/
    ip_str = address_to_str(pinfo->pool, &ip);
    info_list = (wmem_list_t*)wmem_tree_lookup_string(pfcp_frame_tree, ip_str, 0);
    if (info_list != NULL) {
        elem = wmem_list_head(info_list);
        while (!found && elem) {
            info = (pfcp_info_t*)wmem_list_frame_data(elem);
            if (seid == info->seid) {
                *frame = info->frame;
                return 1;
            }
            elem = wmem_list_frame_next(elem);
        }
    }
    return 0;
}

static gboolean
pfcp_call_foreach_ip(const void *key _U_, void *value, void *data){
    wmem_list_frame_t * elem;
    wmem_list_t *info_list = (wmem_list_t *)value;
    pfcp_info_t *info;
    guint32* frame = (guint32*)data;

    /* We loop over the <seid, frame> list */
    elem = wmem_list_head(info_list);
    while (elem) {
        info = (pfcp_info_t*)wmem_list_frame_data(elem);
        if (info->frame == *frame) {
            wmem_list_frame_t * del = elem;
            /* proceed to next request */
            elem = wmem_list_frame_next(elem);
            /* If we find the frame we remove its information from the list */
            wmem_list_remove_frame(info_list, del);
            wmem_free(wmem_file_scope(), info);
        }
        else {
            elem = wmem_list_frame_next(elem);
        }
    }

    return FALSE;
}

static void
pfcp_remove_frame_info(guint32 *f) {
    /* For each ip node */
    wmem_tree_foreach(pfcp_frame_tree, pfcp_call_foreach_ip, (void *)f);
}

static void
pfcp_add_session(guint32 frame, guint32 session) {
    guint32 *f, *session_count;

    f = wmem_new0(wmem_file_scope(), guint32);
    session_count = wmem_new0(wmem_file_scope(), guint32);
    *f = frame;
    *session_count = session;
    g_hash_table_insert(pfcp_session_table, f, session_count);
}

static gboolean
pfcp_seid_exists(guint64 seid, wmem_list_t *seid_list) {
    wmem_list_frame_t *elem;
    guint32 *info;
    gboolean found;
    found = FALSE;
    elem = wmem_list_head(seid_list);
    while (!found && elem) {
        info = (guint32*)wmem_list_frame_data(elem);
        found = *info == seid;
        elem = wmem_list_frame_next(elem);
    }
    return found;
}

static gboolean
pfcp_ip_exists(address ip, wmem_list_t *ip_list) {
    wmem_list_frame_t *elem;
    address *info;
    gboolean found;
    found = FALSE;
    elem = wmem_list_head(ip_list);
    while (!found && elem) {
        info = (address*)wmem_list_frame_data(elem);
        found = addresses_equal(info, &ip);
        elem = wmem_list_frame_next(elem);
    }
    return found;
}

static gboolean
pfcp_info_exists(pfcp_info_t *wanted, wmem_list_t *info_list) {
    wmem_list_frame_t *elem;
    pfcp_info_t *info;
    gboolean found;
    found = FALSE;
    elem = wmem_list_head(info_list);
    while (!found && elem) {
        info = (pfcp_info_t*)wmem_list_frame_data(elem);
        found = wanted->seid == info->seid;
        elem = wmem_list_frame_next(elem);
    }
    return found;
}

static void
pfcp_fill_map(wmem_list_t *seid_list, wmem_list_t *ip_list, guint32 frame) {
    wmem_list_frame_t *elem_ip, *elem_seid;
    pfcp_info_t *pfcp_info;
    wmem_list_t * info_list; /* List of <seids,frames>*/
    guint32 *f, *session, *fr, *session_count;
    GHashTableIter iter;
    guint64 seid;
    gchar *ip;

    elem_ip = wmem_list_head(ip_list);

    while (elem_ip) {
        ip = address_to_str(wmem_file_scope(), (address*)wmem_list_frame_data(elem_ip));
        /* We check if a seid list exists for this ip */
        info_list = (wmem_list_t*)wmem_tree_lookup_string(pfcp_frame_tree, ip, 0);
        if (info_list == NULL) {
            info_list = wmem_list_new(wmem_file_scope());
        }

        /* We loop over the seid list */
        elem_seid = wmem_list_head(seid_list);
        while (elem_seid) {
            seid = *(guint64*)wmem_list_frame_data(elem_seid);
            f = wmem_new0(wmem_file_scope(), guint32);
            *f = frame;
            pfcp_info = wmem_new0(wmem_file_scope(), pfcp_info_t);
            pfcp_info->seid = seid;
            pfcp_info->frame = *f;

            if (pfcp_info_exists(pfcp_info, info_list)) {
                /* If the seid and ip already existed, that means that we need to remove old info about that session */
                /* We look for its session ID */
                session = (guint32 *)g_hash_table_lookup(pfcp_session_table, f);
                if (session) {
                    g_hash_table_iter_init(&iter, pfcp_session_table);

                    while (g_hash_table_iter_next(&iter, (gpointer*)&fr, (gpointer*)&session_count)) {
                        /* If the msg has the same session ID and it's not the upd req we have to remove its info */
                        if (*session_count == *session) {
                            /* If it's the session we are looking for, we remove all the frame information */
                            pfcp_remove_frame_info(fr);
                        }
                    }
                }
            }
            wmem_list_prepend(info_list, pfcp_info);
            elem_seid = wmem_list_frame_next(elem_seid);
        }
        wmem_tree_insert_string(pfcp_frame_tree, ip, info_list, 0);
        elem_ip = wmem_list_frame_next(elem_ip);
    }
}

static gboolean
pfcp_is_cause_accepted(guint8 cause) {
    return cause == 1;
}

/* Data structure attached to a conversation
*  of a session
*/
typedef struct pfcp_session_conv_info_t {
    struct pfcp_session_conv_info_t *next;
    GHashTable             *unmatched;
    GHashTable             *matched;
} pfcp_session_conv_info_t;

static pfcp_session_conv_info_t *pfcp_session_info_items = NULL;

/* Data structure attached to a conversation,
*  to keep track of request/response-pairs
*/
typedef struct pfcp_conv_info_t {
    struct pfcp_conv_info_t *next;
    wmem_map_t             *unmatched;
    wmem_map_t             *matched;
} pfcp_conv_info_t;

static pfcp_conv_info_t *pfcp_info_items = NULL;

/* structure used to track responses to requests using sequence number */
typedef struct pfcp_msg_hash_entry {
    gboolean is_request;    /* TRUE/FALSE */
    guint32 req_frame;      /* frame with request */
    nstime_t req_time;      /* req time */
    guint32 rep_frame;      /* frame with reply */
    gint seq_nr;            /* sequence number */
    guint msgtype;          /* messagetype */
} pfcp_msg_hash_t;

static guint
pfcp_sn_hash(gconstpointer k)
{
    const pfcp_msg_hash_t *key = (const pfcp_msg_hash_t *)k;

    return key->seq_nr;
}

static gboolean
pfcp_sn_equal_matched(gconstpointer k1, gconstpointer k2)
{
    const pfcp_msg_hash_t *key1 = (const pfcp_msg_hash_t *)k1;
    const pfcp_msg_hash_t *key2 = (const pfcp_msg_hash_t *)k2;

    if (key1->req_frame && key2->req_frame && (key1->req_frame != key2->req_frame)) {
        return 0;
    }

    if (key1->rep_frame && key2->rep_frame && (key1->rep_frame != key2->rep_frame)) {
        return 0;
    }

    return key1->seq_nr == key2->seq_nr;
}

static gboolean
pfcp_sn_equal_unmatched(gconstpointer k1, gconstpointer k2)
{
    const pfcp_msg_hash_t *key1 = (const pfcp_msg_hash_t *)k1;
    const pfcp_msg_hash_t *key2 = (const pfcp_msg_hash_t *)k2;

    return key1->seq_nr == key2->seq_nr;
}

static void
pfcp_track_session(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, pfcp_hdr_t * pfcp_hdr, wmem_list_t *seid_list, wmem_list_t *ip_list, guint64 last_seid _U_, address last_ip _U_)
{
    guint32 *session, frame_seid_cp;
    proto_item *it;

    /* PFCP session */
    if (tree) {
        session = (guint32*)g_hash_table_lookup(pfcp_session_table, &pinfo->num);
        if (session) {
            it = proto_tree_add_uint(tree, hf_pfcp_session, tvb, 0, 0, *session);
            proto_item_set_generated(it);
        }
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        /* If the message does not have any session ID */
        session = (guint32*)g_hash_table_lookup(pfcp_session_table, &pinfo->num);
        if (!session) {
            /* If the message is not a SEREQ, SERES, SMREQ, SERES, SDREQ, SDRES, SRREQ or SRRES then we remove its information from seid and ip lists */
            if ((pfcp_hdr->message != PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST && pfcp_hdr->message != PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE &&
                pfcp_hdr->message != PFCP_MSG_SESSION_MODIFICATION_REQUEST && pfcp_hdr->message != PFCP_MSG_SESSION_MODIFICATION_RESPONSE &&
                pfcp_hdr->message != PFCP_MSG_SESSION_DELETION_REQUEST && pfcp_hdr->message != PFCP_MSG_SESSION_DELETION_RESPONSE &&
                pfcp_hdr->message != PFCP_MSG_SESSION_REPORT_REQUEST && pfcp_hdr->message != PFCP_MSG_SESSION_REPORT_RESPONSE)) {
                /* If the lists are not empty*/
                if (wmem_list_count(seid_list) && wmem_list_count(ip_list)) {
                    pfcp_remove_frame_info(&pinfo->num);
                }
            }
            if (pfcp_hdr->message == PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST){
                /* If SEREQ and not already in the list then we create a new session*/
                pfcp_add_session(pinfo->num, pfcp_session_count++);
            }
            else if (pfcp_hdr->message != PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE) {
                /* We have to check if its seid == seid_cp and ip.dst == gsn_ipv4 from the lists, if that is the case then we have to assign
                the corresponding session ID */
                if ((pfcp_get_frame(pinfo, pinfo->dst, (guint32)pfcp_hdr->seid, &frame_seid_cp) == 1)) {
                    /* Then we have to set its session ID */
                    session = (guint32*)g_hash_table_lookup(pfcp_session_table, &frame_seid_cp);
                    if (session != NULL) {
                        /* We add the corresponding session to the list so that when a response came we can associate its session ID*/
                        pfcp_add_session(pinfo->num, *session);
                    }
                }
            }
        }
    }
}

static void
dissect_pfcp_reserved(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_reserved, tvb, 0, length);
}

/* Functions for C-Tag and S-TAG
 * See 8.2.94 and 8.2.95
 */

/* From Tables G-2,3 of IEEE standard 802.1Q-2005 (and I-2,3,7 of 2011 and 2015 revisions) */
static const value_string pfcp_vlan_tag_pcp_vals[] = {
  { 0, "Best Effort (default), Drop Eligible"            },
  { 1, "Best Effort (default)"                           },
  { 2, "Critical Applications, Drop Eligible"            },
  { 3, "Critical Applications"                           },
  { 4, "Voice, < 10ms latency and jitter, Drop Eligible" },
  { 5, "Voice, < 10ms latency and jitter"                },
  { 6, "Internetwork Control"                            },
  { 7, "Network Control"                                 },
  { 0, NULL                                              }
};

static const true_false_string tfs_eligible_ineligible = {
    "Eligible",
    "Ineligible"
};

static int decode_pfcp_c_tag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, gint offset)
{
    static const crumb_spec_t pfcp_c_tag_cvid_crumbs[] = {
        { 0, 4 },
        { 8, 8 },
        { 0, 0 }
    };

    static int * const pfcp_c_tag_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_c_tag_flags_b2_vid,
        &hf_pfcp_c_tag_flags_b1_dei,
        &hf_pfcp_c_tag_flags_b0_pcp,
        NULL
    };
    /* Octet 5  Spare   VID   DEI   PCP */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_c_tag_flags, ENC_BIG_ENDIAN);
    offset += 1;

    //  Octet     8     7     6     5     4     3     2     1
    //    6    | C-VID value            |DEI|   PCP value     |
    //    7    | C-VID value                                  |
    proto_tree_add_split_bits_item_ret_val(tree, hf_pfcp_c_tag_cvid, tvb, offset << 3, pfcp_c_tag_cvid_crumbs, NULL);
    proto_tree_add_item(tree, hf_pfcp_c_tag_dei_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_pfcp_c_tag_pcp_value, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static int decode_pfcp_s_tag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint offset)
{
    static const crumb_spec_t pfcp_s_tag_svid_crumbs[] = {
        { 0, 4 },
        { 8, 8 },
        { 0, 0 }
    };

    static int * const pfcp_s_tag_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_s_tag_flags_b2_vid,
        &hf_pfcp_s_tag_flags_b1_dei,
        &hf_pfcp_s_tag_flags_b0_pcp,
        NULL
    };
    /* Octet 5  Spare   VID   DEI   PCP */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_s_tag_flags, ENC_BIG_ENDIAN);
    offset += 1;

    //  Octet     8     7     6     5     4     3     2     1
    //    6    | S-VID value            |DEI|   PCP value     |
    //    7    | S-VID value                                  |
    proto_tree_add_split_bits_item_ret_val(tree, hf_pfcp_s_tag_svid, tvb, offset << 3, pfcp_s_tag_svid_crumbs, NULL);
    proto_tree_add_item(tree, hf_pfcp_s_tag_dei_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_pfcp_s_tag_pcp_value, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/*
 * 8.2.1    Cause
 */
static const value_string pfcp_cause_vals[] = {

    {  0, "Reserved" },
    {  1, "Request accepted(success)" },
    {  2, "More Usage Report to send" },
    {  3, "Request partially accepted" },
    /* 4 - 63 Spare. */
    { 64, "Request rejected(reason not specified)" },
    { 65, "Session context not found" },
    { 66, "Mandatory IE missing" },
    { 67, "Conditional IE missing" },
    { 68, "Invalid length" },
    { 69, "Mandatory IE incorrect" },
    { 70, "Invalid Forwarding Policy" },
    { 71, "Invalid F-TEID allocation option" },
    { 72, "No established PFCP Association" },
    { 73, "Rule creation / modification Failure" },
    { 74, "PFCP entity in congestion" },
    { 75, "No resources available" },
    { 76, "Service not supported" },
    { 77, "System failure" },
    { 78, "Redirection Requested" },
    { 79, "All dynamic addresses are occupied" },
    { 80, "Unknown Pre-defined Rule" },
    { 81, "Unknown Application ID" },
    { 82, "L2TP tunnel Establishment failure" },
    { 83, "L2TP session Establishment failure" },
    { 84, "L2TP tunnel release" },
    { 85, "L2TP session release" },
    { 86, "PFCP session restoration failure" },
    /* 87 to 255 Spare for future use in a response message. */
    {0, NULL}
};

static void
dissect_pfcp_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args)
{
    guint32 value;
    /* Octet 5 Cause value */
    proto_tree_add_item_ret_uint(tree, hf_pfcp2_cause, tvb, 0, 1, ENC_BIG_ENDIAN, &value);
    if (g_pfcp_session) {
        args->last_cause = (guint8)value;
    }
    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_cause_vals, "Unknown"));
}

/*
 * 8.2.2    Source Interface
 */
static const value_string pfcp_source_interface_vals[] = {

    { 0, "Access" },
    { 1, "Core" },
    { 2, "SGi-LAN/N6-LAN" },
    { 3, "CP-function" },
    { 4, "5G VN Internal" },
    { 0, NULL }
};
static int
decode_pfcp_source_interface(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, gint offset)
{
    guint32 value;
    /* Octet 5 Spare    Interface value */
    proto_tree_add_item(tree, hf_pfcp_spare_h1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_source_interface, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset += 1;

    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_source_interface_vals, "Unknown"));

    return offset;

}
static void
dissect_pfcp_source_interface(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    offset = decode_pfcp_source_interface(tvb, pinfo, tree, item, offset);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.3    F-TEID
 */
static void
dissect_pfcp_f_teid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 fteid_flags_val;

    static int * const pfcp_fteid_flags[] = {
        &hf_pfcp_fteid_flg_spare,
        &hf_pfcp_fteid_flg_b3_ch_id,
        &hf_pfcp_fteid_flg_b2_ch,
        &hf_pfcp_fteid_flg_b1_v6,
        &hf_pfcp_fteid_flg_b0_v4,
        NULL
    };
    /* Octet 5  Spare  Spare  Spare  Spare  CHID  CH  V6  V4*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_fteid_flags, ENC_BIG_ENDIAN, &fteid_flags_val);
    offset += 1;
    /* The following flags are coded within Octet 5:
     * Bit 1 - V4: If this bit is set to "1" and the CH bit is not set, then the IPv4 address field shall be present,
     *         otherwise the IPv4 address field shall not be present.
     * Bit 2 - V6: If this bit is set to "1" and the CH bit is not set, then the IPv6 address field shall be present,
     *         otherwise the IPv6 address field shall not be present.
     * Bit 3 - CH (CHOOSE): If this bit is set to "1", then the TEID, IPv4 address and IPv6 address fields shall not be
     *         present and the UP function shall assign an F-TEID with an IP4 or an IPv6 address if the V4 or V6 bit is set respectively.
     *         This bit shall only be set by the CP function.
     * Bit 4 - CHID (CHOOSE_ID):If this bit is set to "1", then the UP function shall assign the same F-TEID to the
     *         PDRs requested to be created in a PFCP Session Establishment Request or PFCP Session Modification Request with
     *         the same CHOOSE ID value.
     *         This bit may only be set to "1" if the CH bit is set to "1".
     *         This bit shall only be set by the CP function.
     */

    if ((fteid_flags_val & 0x4) == 4) {
        if ((fteid_flags_val & 0x8) == 8) {
            proto_tree_add_item(tree, hf_pfcp_f_teid_ch_id, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
    } else {

        /* Octet 6 to 9    TEID */
        proto_tree_add_item(tree, hf_pfcp_f_teid_teid, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, "TEID: 0x%s", tvb_bytes_to_str(pinfo->pool, tvb, offset, 4));
        offset += 4;

        if ((fteid_flags_val & 0x1) == 1) {
            /* m to (m+3)    IPv4 address */
            proto_tree_add_item(tree, hf_pfcp_f_teid_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(item, ", IPv4 %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
            offset += 4;
        }
        if ((fteid_flags_val & 0x2) == 2) {
            /* p to (p+15)   IPv6 address */
            proto_tree_add_item(tree, hf_pfcp_f_teid_ipv6, tvb, offset, 16, ENC_NA);
            proto_item_append_text(item, ", IPv6 %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
            offset += 16;
        }
        /* If the value of CH bit is set to "0", but the value of CHID bit is "1" */
        if ((fteid_flags_val & 0x8) == 8) {
            proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_encoding_error, tvb, 0, 1);
        }
    }
    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.4    Network Instance
 */
static int
decode_pfcp_network_instance(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, gint offset, int length)
{

    int      name_len;

    if (length > 0) {
        name_len = tvb_get_guint8(tvb, offset);
        if (name_len < 0x41) {
            /* APN */
            guint8 *apn = NULL;
            int     tmp;

            name_len = tvb_get_guint8(tvb, offset);

            if (name_len < 0x20) {
                apn = tvb_get_string_enc(pinfo->pool, tvb, offset + 1, length - 1, ENC_ASCII);
                for (;;) {
                    if (name_len >= length - 1)
                        break;
                    tmp = name_len;
                    name_len = name_len + apn[tmp] + 1;
                    apn[tmp] = '.';
                }
            } else {
                apn = tvb_get_string_enc(pinfo->pool, tvb, offset, length, ENC_ASCII);
            }
            proto_tree_add_string(tree, hf_pfcp_network_instance, tvb, offset, length, apn);
            proto_item_append_text(item, "%s", apn);

        } else {
            /* Domain name*/
            const guint8* string_value;
            proto_tree_add_item_ret_string(tree, hf_pfcp_network_instance, tvb, offset, length, ENC_ASCII | ENC_NA, pinfo->pool, &string_value);
            proto_item_append_text(item, "%s", string_value);
        }
    }

    return offset + length;
}
static void
dissect_pfcp_network_instance(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item , guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int      offset = 0;

    /* Octet 5   Network Instance
     * The Network instance field shall be encoded as an OctetString and shall contain an identifier
     * which uniquely identifies a particular Network instance (e.g. PDN instance) in the UP function.
     * It may be encoded as a Domain Name or an Access Point Name (APN)
     */
     /* Test for Printable character or length indicator(APN), assume first character of Domain name >= 0x41 */

    decode_pfcp_network_instance(tvb, pinfo, tree, item, offset, length);

}

/*
 * 8.2.5    SDF Filter
 */
static void
dissect_pfcp_sdf_filter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags_val;
    guint32 fd_length;
    proto_tree *flow_desc_tree, *tos_tree, *spi_tree, *flow_label_tree, *sdf_filter_id_tree;

    static int * const pfcp_sdf_filter_flags[] = {
        &hf_pfcp_spare_h1,
        &hf_pfcp_sdf_filter_flags_b4_bid,
        &hf_pfcp_sdf_filter_flags_b3_fl,
        &hf_pfcp_sdf_filter_flags_b2_spi,
        &hf_pfcp_sdf_filter_flags_b1_ttc,
        &hf_pfcp_sdf_filter_flags_b0_fd,
        NULL
    };
    /* Octet 5  Spare   FL  SPI TTC FD*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_sdf_filter_flags, ENC_BIG_ENDIAN, &flags_val);
    offset += 1;
    /* Octet 6 Spare*/
    proto_tree_add_item(tree, hf_pfcp_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if ((flags_val & 0x1) == 1) {
        /* FD (Flow Description): If this bit is set to "1",
         * then the Length of Flow Description and the Flow Description fields shall be present
         */
        flow_desc_tree = proto_item_add_subtree(item, ett_pfcp_flow_desc);
        /* m to (m+1)    Length of Flow Description */
        proto_tree_add_item_ret_uint(flow_desc_tree, hf_pfcp_flow_desc_len, tvb, offset, 2, ENC_BIG_ENDIAN, &fd_length);
        offset += 2;
        /* Flow Description
         * The Flow Description field, when present, shall be encoded as an OctetString
         * as specified in subclause 5.4.2 of 3GPP TS 29.212
         */
        proto_tree_add_item(flow_desc_tree, hf_pfcp_flow_desc, tvb, offset, fd_length, ENC_ASCII);
        offset += fd_length;
    }
    if ((flags_val & 0x2) == 2) {
        /* TTC (ToS Traffic Class): If this bit is set to "1", then the ToS Traffic Class field shall be present */
        /* ToS Traffic Class field, when present, shall be encoded as an OctetString on two octets
         * as specified in subclause 5.3.15 of 3GPP TS 29.212
         */
        tos_tree = proto_item_add_subtree(item, ett_pfcp_tos);
        proto_tree_add_item(tos_tree, hf_pfcp_traffic_class, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(tos_tree, hf_pfcp_traffic_mask, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if ((flags_val & 0x4) == 4) {
        /* SPI (The Security Parameter Index) field, when present, shall be encoded as an OctetString on four octets and shall
         * contain the IPsec security parameter index (which is a 32-bit field),
         * as specified in subclause 5.3.51 of 3GPP TS 29.212
         */
        spi_tree = proto_item_add_subtree(item, ett_pfcp_spi);
        proto_tree_add_item(spi_tree, hf_pfcp_spi, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    if ((flags_val & 0x8) == 8) {
        /* FL (Flow Label), when present, shall be encoded as an OctetString on 3 octets as specified in
         * subclause 5.3.52 of 3GPP TS 29.212 and shall contain an IPv6 flow label (which is a 20-bit field).
         * The bits 8 to 5 of the octet "v" shall be spare and set to zero, and the remaining 20 bits shall
         * contain the IPv6 flow label.*/
        flow_label_tree = proto_item_add_subtree(item, ett_pfcp_flow_label);
        proto_tree_add_bits_item(flow_label_tree, hf_pfcp_flow_label_spare_bit, tvb, (offset<<3), 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flow_label_tree, hf_pfcp_flow_label, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
    }
    if ((flags_val & 0x10) == 16) {
        /* The SDF Filter ID, when present, shall be encoded as an Unsigned32 binary integer value.
         * It shall uniquely identify an SDF Filter among all the SDF Filters provisioned for a given PFCP Session. */
        sdf_filter_id_tree = proto_item_add_subtree(item, ett_pfcp_sdf_filter_id);
        proto_tree_add_item(sdf_filter_id_tree, hf_pfcp_sdf_filter_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.6    Application ID
 */
static void
dissect_pfcp_application_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octet 5 to (n+4) Application Identifier
    * The Application Identifier shall be encoded as an OctetString (see 3GPP TS 29.212)
    */
    if (tvb_ascii_isprint(tvb, offset, length))
    {
        const guint8* string_value;
        proto_tree_add_item_ret_string(tree, hf_pfcp_application_id_str, tvb, offset, length, ENC_ASCII | ENC_NA, pinfo->pool, &string_value);
        proto_item_append_text(item, "%s", string_value);
    }
    else
    {
        proto_tree_add_item(tree, hf_pfcp_application_id, tvb, offset, length, ENC_NA);
    }
}
/*
 * 8.2.7    Gate Status
 */
static const value_string pfcp_gate_status_vals[] = {
    { 0, "OPEN" },
    { 1, "CLOSED" },
    { 0, NULL }
};


static void
dissect_pfcp_gate_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_gate_status_flags[] = {
        &hf_pfcp_gate_status_b3b2_ulgate,
        &hf_pfcp_gate_status_b0b1_dlgate,
        NULL
    };
    /* Octet 5  Spare   UL Gate DL Gate */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_gate_status_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}


/*
 * 8.2.8    MBR
 */
static void
dissect_pfcp_mbr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    int len1 = (length != 10) ? length/2 : 5;

    /* In case length is not in accordance with documentation */
    if ( length != 10) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_encoding_error, tvb, 0, 1);
    }

    /* 5 to 9   UL MBR
    * The UL/DL MBR fields shall be encoded as kilobits per second (1 kbps = 1000 bps) in binary value
    */
    proto_tree_add_item(tree, hf_pfcp_ul_mbr, tvb, offset, len1, ENC_BIG_ENDIAN);
    offset += len1;

    /* 10 to 14 DL MBR */
    proto_tree_add_item(tree, hf_pfcp_dl_mbr, tvb, offset, len1, ENC_BIG_ENDIAN);
    offset += len1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.9    GBR
 */
static void
dissect_pfcp_gbr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    int len1 = (length != 10) ? length/2 : 5;

    /* In case length is not in accordance with documentation */
    if ( length != 10) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_encoding_error, tvb, 0, 1);
    }

    /* 5 to 9   UL GBR
    * The UL/DL MBR fields shall be encoded as kilobits per second (1 kbps = 1000 bps) in binary value
    */
    proto_tree_add_item(tree, hf_pfcp_ul_gbr, tvb, offset, len1, ENC_BIG_ENDIAN);
    offset += len1;

    /* 10 to 14 DL GBR */
    proto_tree_add_item(tree, hf_pfcp_dl_gbr, tvb, offset, len1, ENC_BIG_ENDIAN);
    offset += len1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.10   QER Correlation ID
 */
static void
dissect_pfcp_qer_correlation_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* 5 to 8   QER Correlation ID value */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_qer_correlation_id, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.11   Precedence
 */
static void
dissect_pfcp_precedence(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* Octet 5 5 to 8   Precedence value */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_precedence, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.12   Transport Level Marking
 */
static void
dissect_pfcp_transport_level_marking(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    proto_item *dscp_it;
    const gchar *dscp_str;
    guint32 tos, mask;

    /* Octet 5 to 6    ToS/Traffic Class
    * The ToS/Traffic Class shall be encoded on two octets as an OctetString.
    * The first octet shall contain the IPv4 Type-of-Service or the IPv6 Traffic-Class field and the second octet shall contain the ToS/Traffic Class mask field
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_traffic_class, tvb, offset, 1, ENC_BIG_ENDIAN, &tos);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_pfcp_traffic_mask, tvb, offset, 1, ENC_BIG_ENDIAN, &mask);
    offset += 1;

    /* display DSCP value */
    dscp_str = val_to_str_ext_const(((tos & mask) >> 2), &dscp_vals_ext, "Unknown");
    dscp_it = proto_tree_add_string(tree, hf_pfcp_traffic_dscp, tvb, 0, 2, dscp_str);
    proto_item_set_generated(dscp_it);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.13   Volume Threshold
 */
static void
dissect_pfcp_volume_threshold(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags_val;

    static int * const pfcp_volume_threshold_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_volume_threshold_b2_dlvol,
        &hf_pfcp_volume_threshold_b1_ulvol,
        &hf_pfcp_volume_threshold_b0_tovol,
        NULL
    };
    /* Octet 5  Spare   DLVOL   ULVOL   TOVOL*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_volume_threshold_flags, ENC_BIG_ENDIAN, &flags_val);
    offset += 1;

    /* The Total Volume, Uplink Volume and Downlink Volume fields shall be encoded as an Unsigned64 binary integer value.
    * They shall contain the total, uplink or downlink number of octets respectively.
    */
    if ((flags_val & 0x1) == 1) {
        /* m to (m+7)   Total Volume
        * TOVOL: If this bit is set to "1", then the Total Volume field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_volume_threshold_tovol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    if ((flags_val & 0x2) == 2) {
        /* p to (p+7)    Uplink Volume
        * ULVOL: If this bit is set to "1", then the Uplink Volume field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_volume_threshold_ulvol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    if ((flags_val & 0x4) == 4) {
        /* q to (q+7)   Downlink Volume
        * DLVOL: If this bit is set to "1", then the Downlink Volume field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_volume_threshold_dlvol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.14   Time Threshold
 */
static void
dissect_pfcp_time_threshold(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint value;

    /* Octet 5 to 8    Time Threshold
    * The Time Threshold field shall be encoded as an Unsigned32 binary integer value.
    * It shall contain the duration in seconds.
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_time_threshold, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u s", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.15   Monitoring Time
 */
static void
dissect_pfcp_monitoring_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    char *time_str;
    int offset = 0;

    /* The Monitoring Time field shall indicate the monitoring time in UTC time.
    * Octets 5 to 8 shall be encoded in the same format as the first four octets
    * of the 64-bit timestamp format as defined in section 6 of IETF RFC 5905.
    */
    proto_tree_add_item_ret_time_string(tree, hf_pfcp_monitoring_time, tvb, offset, 4, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    proto_item_append_text(item, "%s", time_str);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.16   Subsequent Volume Threshold
 */
static void
dissect_pfcp_subseq_volume_threshold(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags_val;

    static int * const pfcp_subseq_volume_threshold_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_subseq_volume_threshold_b2_dlvol,
        &hf_pfcp_subseq_volume_threshold_b1_ulvol,
        &hf_pfcp_subseq_volume_threshold_b0_tovol,
        NULL
    };
    /* Octet 5  Spare   DLVOL   ULVOL   TOVOL*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_subseq_volume_threshold_flags, ENC_BIG_ENDIAN, &flags_val);
    offset += 1;

    /* The Total Volume, Uplink Volume and Downlink Volume fields shall be encoded as an Unsigned64 binary integer value.
    * They shall contain the total, uplink or downlink number of octets respectively.
    */
    if ((flags_val & 0x1) == 1) {
        /* m to (m+7)   Total Volume
        * TOVOL: If this bit is set to "1", then the Total Volume field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_subseq_volume_threshold_tovol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    if ((flags_val & 0x2) == 2) {
        /* p to (p+7)    Uplink Volume
        * ULVOL: If this bit is set to "1", then the Uplink Volume field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_subseq_volume_threshold_ulvol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    if ((flags_val & 0x4) == 4) {
        /* q to (q+7)   Downlink Volume
        * DLVOL: If this bit is set to "1", then the Downlink Volume field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_subseq_volume_threshold_dlvol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.17   Subsequent Time Threshold
 */
static void
dissect_pfcp_subsequent_time_threshold(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* 5 to 8   Subsequent Time Threshold */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_subsequent_time_threshold, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u s", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.18   Inactivity Detection Time
 */
static void
dissect_pfcp_inactivity_detection_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* 5 to 8   Inactivity Detection Time */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_inactivity_detection_time, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u s", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.19   Reporting Triggers
 */
static void
dissect_pfcp_reporting_triggers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_reporting_triggers_o5_flags[] = {
        &hf_pfcp_reporting_triggers_o5_b7_liusa,
        &hf_pfcp_reporting_triggers_o5_b6_droth,
        &hf_pfcp_reporting_triggers_o5_b5_stopt,
        &hf_pfcp_reporting_triggers_o5_b4_start,
        &hf_pfcp_reporting_triggers_o5_b3_quhti,
        &hf_pfcp_reporting_triggers_o5_b2_timth,
        &hf_pfcp_reporting_triggers_o5_b1_volth,
        &hf_pfcp_reporting_triggers_o5_b0_perio,
        NULL
    };
    /* Octet 5 LIUSA   DROTH   STOPT   START   QUHTI   TIMTH   VOLTH   PERIO */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_reporting_triggers_o5_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset == length) {
        return;
    }

    static int * const pfcp_reporting_triggers_o6_flags[] = {
        &hf_pfcp_reporting_triggers_o6_b7_quvti,
        &hf_pfcp_reporting_triggers_o6_b6_ipmjl,
        &hf_pfcp_reporting_triggers_o6_b5_evequ,
        &hf_pfcp_reporting_triggers_o6_b4_eveth,
        &hf_pfcp_reporting_triggers_o6_b3_macar,
        &hf_pfcp_reporting_triggers_o6_b2_envcl,
        &hf_pfcp_reporting_triggers_o6_b1_timqu,
        &hf_pfcp_reporting_triggers_o6_b0_volqu,
        NULL
    };
    /* Octet 6 QUVTI   IPMJL   EVEQU   EVETH   MACAR   ENVCL   TIMQU   VOLQU */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_reporting_triggers_o6_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset == length) {
        return;
    }

    static int * const pfcp_reporting_triggers_o7_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_reporting_triggers_o7_b1_upint,
        &hf_pfcp_reporting_triggers_o7_b0_reemr,
        NULL
    };
    /* Octet 7 Spare   Spare   Spare   Spare   Spare   Spare   UPINT   REEMR */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_reporting_triggers_o7_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset == length) {
        return;
    }


    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.20   Redirect Information
 */
static const value_string pfcp_redirect_address_type_vals[] = {

    { 0, "IPv4 address" },
    { 1, "IPv6 address" },
    { 2, "URL" },
    { 3, "SIP URI" },
    { 4, "IPv4 and IPv6 addresses" },
    { 5, "Port" },
    { 6, "IPv4 address and Port" },
    { 7, "IPv6 address and Port" },
    { 8, "IPv4 and IPv6 addresses and Port" },
    { 0, NULL }
};

static void
dissect_pfcp_redirect_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 redirect_address_type, addr_len, other_addr_len;

    /* Octet Spare  Redirect Address Type */
    proto_tree_add_item(tree, hf_pfcp_spare_h1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_redirect_address_type, tvb, offset, 1, ENC_BIG_ENDIAN, &redirect_address_type);
    offset++;

    /* If the Redirect Address Type is set to Port, the Redirect Address Server Address shall not be present */
    if(!(redirect_address_type == 5)) {
        /* 6-7  Redirect Server Address Length=a */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_redirect_server_addr_len, tvb, offset, 2, ENC_BIG_ENDIAN, &addr_len);
        offset+=2;

        /* 8-(8+a-1)  Redirect Server Address */
        proto_tree_add_item(tree, hf_pfcp_redirect_server_address, tvb, offset, addr_len, ENC_UTF_8 | ENC_NA);
        offset += addr_len;

        /* - If the Redirect Address type is set to "IPv4 and IPv6 address", the Redirect Information IE shall include an IPv4 address
         *   and an IPv6 address in the Redirect Server Address IE and Other Redirect Server Address.
         * - When Redirect Address Type is set to "IPv4 and IPv6 addresses and Port", the Other Redirect Server Address shall also be present.
         */
        if((redirect_address_type == 4) || (redirect_address_type == 8)) {
            /* p-(p+1)  Other Redirect Server Address Length=b */
            proto_tree_add_item_ret_uint(tree, hf_pfcp_other_redirect_server_addr_len, tvb, offset, 2, ENC_BIG_ENDIAN, &other_addr_len);
            offset+=2;

            /* (p+2)-(p+2+b-1)  Other Redirect Server Address */
            proto_tree_add_item(tree, hf_pfcp_other_redirect_server_address, tvb, offset, other_addr_len, ENC_UTF_8 | ENC_NA);
            offset += other_addr_len;
        }
    }

    if((redirect_address_type == 5) || (redirect_address_type == 6) || (redirect_address_type == 7) || (redirect_address_type == 8)) {
        /* m to (m+1) Port */
        proto_tree_add_item(tree, hf_pfcp_redirect_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.21   Report Type
 */
static void
dissect_pfcp_report_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_report_type_flags[] = {
        &hf_pfcp_spare_b7,
        &hf_pfcp_report_type_b6_uisr,
        &hf_pfcp_report_type_b5_sesr,
        &hf_pfcp_report_type_b4_tmir,
        &hf_pfcp_report_type_b3_upir,
        &hf_pfcp_report_type_b2_erir,
        &hf_pfcp_report_type_b1_usar,
        &hf_pfcp_report_type_b0_dldr,
        NULL
    };
    /* Octet 5  Spare   UISR   SESR    TMIR   UPIR   ERIR    USAR    DLDR */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_report_type_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.22   Offending IE
 */
static void
dissect_pfcp_offending_ie(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    guint32 value;
    /* Octet 5 to 6 Type of the offending IE */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_offending_ie, tvb, 0, 2, ENC_BIG_ENDIAN, &value);

    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_ie_type, "Unknown"));

}
/*
 * 8.2.23   Forwarding Policy
 */
static void
dissect_pfcp_forwarding_policy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 id_len;

    /* Octet Forwarding Policy Identifier Length */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_forwarding_policy_id_len, tvb, offset, 1, ENC_BIG_ENDIAN, &id_len);
    offset += 1;

    proto_tree_add_item(tree, hf_pfcp_forwarding_policy_id, tvb, offset, id_len, ENC_NA);
    offset += id_len;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.24   Destination Interface
 */
static const value_string pfcp_dst_interface_vals[] = {

    { 0, "Access" },
    { 1, "Core" },
    { 2, "SGi-LAN/N6-LAN" },
    { 3, "CP- Function" },
    { 4, "LI Function" },
    { 5, "5G VN Internal" },
    { 0, NULL }
};

static int
decode_pfcp_destination_interface(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, gint offset, int length)
{
    guint32 value;

    /* Octet 5    Spare    Interface value*/
    proto_tree_add_item(tree, hf_pfcp_spare_h1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_dst_interface, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;

    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_dst_interface_vals, "Unknown"));

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

    return length;
}
static void
dissect_pfcp_destination_interface(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    decode_pfcp_destination_interface(tvb, pinfo, tree, item, offset, length);

}
/*
 * 8.2.25   UP Function Features
 */
static void
dissect_pfcp_up_function_features(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_up_function_features_o5_flags[] = {
        &hf_pfcp_up_function_features_o5_b7_treu,
        &hf_pfcp_up_function_features_o5_b6_heeu,
        &hf_pfcp_up_function_features_o5_b5_pfdm,
        &hf_pfcp_up_function_features_o5_b4_ftup,
        &hf_pfcp_up_function_features_o5_b3_trst,
        &hf_pfcp_up_function_features_o5_b2_dlbd,
        &hf_pfcp_up_function_features_o5_b1_ddnd,
        &hf_pfcp_up_function_features_o5_b0_bucp,
        NULL
    };
    /* Octet 5  TREU    HEEU    PFDM    FTUP    TRST    DLBD    DDND    BUCP */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_up_function_features_o5_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset == length) {
        return;
    }

    static int * const pfcp_up_function_features_o6_flags[] = {
        &hf_pfcp_up_function_features_o6_b7_epfar,
        &hf_pfcp_up_function_features_o6_b6_pfde,
        &hf_pfcp_up_function_features_o6_b5_frrt,
        &hf_pfcp_up_function_features_o6_b4_trace,
        &hf_pfcp_up_function_features_o6_b3_quoac,
        &hf_pfcp_up_function_features_o6_b2_udbc,
        &hf_pfcp_up_function_features_o6_b1_pdiu,
        &hf_pfcp_up_function_features_o6_b0_empu,
        NULL
    };
    /* Octet 6  EPFAR   PFDE   FRRT    TRACE   QUOAC   UDBC    PDIU    EMPU */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_up_function_features_o6_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset == length) {
        return;
    }

    static int * const pfcp_up_function_features_o7_flags[] = {
        &hf_pfcp_up_function_features_o7_b7_gcom,
        &hf_pfcp_up_function_features_o7_b6_bundl,
        &hf_pfcp_up_function_features_o7_b5_mte_n4,
        &hf_pfcp_up_function_features_o7_b4_mnop,
        &hf_pfcp_up_function_features_o7_b3_sset,
        &hf_pfcp_up_function_features_o7_b2_ueip,
        &hf_pfcp_up_function_features_o7_b1_adpdp,
        &hf_pfcp_up_function_features_o7_b0_dpdra,
        NULL
    };
    /* Octet 7  GCOM   BUNDL   MTE N4    MNOP   SSET   UEIP    ADPDP    DPDRA */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_up_function_features_o7_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset == length) {
        return;
    }

    static int * const pfcp_up_function_features_o8_flags[] = {
        &hf_pfcp_up_function_features_o8_b7_mptcp,
        &hf_pfcp_up_function_features_o8_b6_tscu,
        &hf_pfcp_up_function_features_o8_b5_ip6pl,
        &hf_pfcp_up_function_features_o8_b4_iptv,
        &hf_pfcp_up_function_features_o8_b3_norp,
        &hf_pfcp_up_function_features_o8_b2_vtime,
        &hf_pfcp_up_function_features_o8_b1_rttl,
        &hf_pfcp_up_function_features_o8_b0_mpas,
        NULL
    };
    /* Octet 8  MPTCP   TSCU   IP6PL    IPTV   NORP   VTIME    RTTL    MPAS */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_up_function_features_o8_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset == length) {
        return;
    }

    static int * const pfcp_up_function_features_o9_flags[] = {
        &hf_pfcp_up_function_features_o9_b7_rds,
        &hf_pfcp_up_function_features_o9_b6_ddds,
        &hf_pfcp_up_function_features_o9_b5_ethar,
        &hf_pfcp_up_function_features_o9_b4_ciot,
        &hf_pfcp_up_function_features_o9_b3_mt_edt,
        &hf_pfcp_up_function_features_o9_b2_gpqm,
        &hf_pfcp_up_function_features_o9_b1_qfqm,
        &hf_pfcp_up_function_features_o9_b0_atsss_ll,
        NULL
    };
    /* Octet 9  RDS     DDDS   ETHAR   CIOT    MT-EDT   GPQM    QFQM    ATSSS-LL */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_up_function_features_o9_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset == length) {
        return;
    }

    static int * const pfcp_up_function_features_o10_flags[] = {
        &hf_pfcp_up_function_features_o10_b7_dnsts,
        &hf_pfcp_up_function_features_o10_b6_iprep,
        &hf_pfcp_up_function_features_o10_b5_resps,
        &hf_pfcp_up_function_features_o10_b4_upber,
        &hf_pfcp_up_function_features_o10_b3_l2tp,
        &hf_pfcp_up_function_features_o10_b2_nspoc,
        &hf_pfcp_up_function_features_o10_b1_quosf,
        &hf_pfcp_up_function_features_o10_b0_rttwp,
        NULL
    };
    /* Octet 10  DNSTS   IPREP   RESPS    UPBER   L2TP   NSPOC    QUOSF    RTTWP */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_up_function_features_o10_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset == length) {
        return;
    }

    static int * const pfcp_up_function_features_o11_flags[] = {
        &hf_pfcp_spare_b7_b6,
        &hf_pfcp_up_function_features_o11_b5_upidp,
        &hf_pfcp_up_function_features_o11_b4_ratp,
        &hf_pfcp_up_function_features_o11_b3_eppi,
        &hf_pfcp_up_function_features_o11_b2_psuprm,
        &hf_pfcp_up_function_features_o11_b1_mbsn4,
        &hf_pfcp_up_function_features_o11_b0_drqos,
        NULL
    };
    /* Octet 11  Spare  UPIDP    RATP   EPPI    PSUPRM    MBSN4   DRQOS */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_up_function_features_o11_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset == length) {
        return;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.26   Apply Action
 */
static void
dissect_pfcp_apply_action(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_apply_action_o5_flags[] = {
        &hf_pfcp_apply_action_flags_o5_b7_dfrt,
        &hf_pfcp_apply_action_flags_o5_b6_ipmd,
        &hf_pfcp_apply_action_flags_o5_b5_ipma,
        &hf_pfcp_apply_action_flags_o5_b4_dupl,
        &hf_pfcp_apply_action_flags_o5_b3_nocp,
        &hf_pfcp_apply_action_flags_o5_b2_buff,
        &hf_pfcp_apply_action_flags_o5_b1_forw,
        &hf_pfcp_apply_action_flags_o5_b0_drop,
        NULL
    };
    /* Octet 5  DFRT   IPMD   IPMA   DUPL    NOCP    BUFF    FORW    DROP */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_apply_action_o5_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset == length) {
        return;
    }

    static int * const pfcp_apply_action_o6_flags[] = {
        &hf_pfcp_spare_b7_b5,
        &hf_pfcp_apply_action_flags_o6_b4_mbsu,
        &hf_pfcp_apply_action_flags_o6_b3_fssm,
        &hf_pfcp_apply_action_flags_o6_b2_ddpn,
        &hf_pfcp_apply_action_flags_o6_b1_bdpn,
        &hf_pfcp_apply_action_flags_o6_b0_edrt,
        NULL
    };
    /* Octet 6  Spare   MBSU    FSSM    DDPN    BDPN    EDRT */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_apply_action_o6_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.27   Downlink Data Service Information
 */
static void
dissect_pfcp_dl_data_service_inf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags;

    static int * const pfcp_dl_data_service_inf_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_dl_data_service_inf_b1_qfii,
        &hf_pfcp_dl_data_service_inf_b0_ppi,
        NULL
    };
    /* Octet 5  Spare   QFII    PPI */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_dl_data_service_inf_flags, ENC_BIG_ENDIAN, &flags);
    offset += 1;

    /* The PPI flag in octet 5 indicates whether the Paging Policy Indication value in octet 'm' shall be present */
    if ((flags & 0x1) == 1) {
        /* m    Spare   Paging Policy Indication value
         * encoded as the DSCP in TOS (IPv4) or TC (IPv6) information received in the IP payload of the GTP-U packet
         * from the PGW (see IETF RFC 2474
         */
        proto_tree_add_item(tree, hf_pfcp_spare_b7_b6, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_pfcp_ppi, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    /* The QFII flag in octet 5 indicates whether the QFI value in octet 'p' shall be present */
    if ((flags & 0x2) == 2) {
        /* m    Spare   QFI value
         * encoded as the octet 5 of the QFI IE in subclause 8.2.89.
         */
        proto_tree_add_item(tree, hf_pfcp_spare_b7_b6, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_pfcp_qfi, tvb, offset, 1, ENC_NA);
        offset++;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.28   Downlink Data Notification Delay
 */
static void
dissect_pfcp_dl_data_notification_delay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* Octet 5 Delay Value in integer multiples of 50 millisecs, or zero */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_dl_data_notification_delay, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset += 1;

    proto_item_append_text(item, "%u ms", value * 50);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.29   DL Buffering Duration
 */
static const value_string pfcp_timer_unit_vals[] = {
    { 0, "value is incremented in multiples of 2 seconds" },
    { 1, "value is incremented in multiples of 1 minute" },
    { 2, "value is incremented in multiples of 10 minutes" },
    { 3, "value is incremented in multiples of 1 hour" },
    { 4, "value is incremented in multiples of 10 hour" },
    { 5, "values shall be interpreted as multiples of 1 minute(version 14.0.0)" },
    { 6, "values shall be interpreted as multiples of 1 minute(version 14.0.0)" },
    { 7, "value indicates that the timer is infinite" },
    { 0, NULL }
};

static void
dissect_pfcp_dl_buffering_dur(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 unit, value;

    /* Octet 5  Timer unit  Timer value */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_timer_unit, tvb, offset, 1, ENC_BIG_ENDIAN, &unit);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_timer_value, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;

    if ((unit == 0) && (value == 0)) {
        proto_item_append_text(item, " Stopped");
    } else {
        switch (unit) {
        case 0:
            proto_item_append_text(item, "%u s", value * 2);
            break;
        case 1:
            proto_item_append_text(item, "%u min", value);
            break;
        case 2:
            proto_item_append_text(item, "%u min", value * 10);
            break;
        case 3:
            proto_item_append_text(item, "%u hours", value);
            break;
        case 4:
            proto_item_append_text(item, "%u hours", value * 10);
            break;
        case 7:
            proto_item_append_text(item, "Infinite (%u)", value);
            break;
            /* Value 5 and 6 */
        default:
            proto_item_append_text(item, "%u min", value);
            break;
        }
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.30   DL Buffering Suggested Packet Count
 */
static void
dissect_pfcp_dl_buffering_suggested_packet_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    guint32 value;
    /* Octet 5 to n+4 Packet Count Value
    * The length shall be set to 1 or 2 octets.
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_packet_count, tvb, 0, length, ENC_BIG_ENDIAN, &value);

    proto_item_append_text(item, "%u", value);
}
/*
 * 8.2.31   PFCPSMReq-Flags
 */
static void
dissect_pfcp_pfcpsmreq_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_pfcpsmreq_flags[] = {
        &hf_pfcp_spare_b7_b5,
        &hf_pfcp_pfcpsmreq_flags_b4_rumuc,
        &hf_pfcp_pfcpsmreq_flags_b3_sumpc,
        &hf_pfcp_pfcpsmreq_flags_b2_qaurr,
        &hf_pfcp_pfcpsmreq_flags_b1_sndem,
        &hf_pfcp_pfcpsmreq_flags_b0_drobu,
        NULL
    };
    /* Octet 5  Spare   Spare   Spare   RUMUC   SUMPC   QAURR   SNDEM   DROBU */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_pfcpsmreq_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.32   PFCPSRRsp-Flags
 */
static void
dissect_pfcp_pfcpsrrsp_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_pfcpsrrsp_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_pfcpsrrsp_flags_b0_drobu,
        NULL
    };
    /* Octet 5  Spare   Spare   Spare   Spare   Spare   Spare   Spare   DROBU */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_pfcpsrrsp_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.33   Sequence Number
 */
static void
dissect_pfcp_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    guint32 value;
    /* Octet 5 to 8    Sequence Number */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_sequence_number, tvb, 0, 4, ENC_BIG_ENDIAN, &value);

    proto_item_append_text(item, "%u", value);

}

/*
 * 8.2.34   Metric
 */
static void
dissect_pfcp_metric(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    guint32 value;
    /* Octet 5  Metric */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_metric, tvb, 0, 1, ENC_BIG_ENDIAN, &value);

    proto_item_append_text(item, "%u", value);

}

/*
 * 8.2.35   Timer
 */
static void
dissect_pfcp_timer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 unit, value;

    /* Octet 5  Timer unit  Timer value */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_timer_unit, tvb, offset, 1, ENC_BIG_ENDIAN, &unit);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_timer_value, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;

    if ((unit == 0) && (value == 0)) {
        proto_item_append_text(item, " Stopped");
    } else {
        switch (unit) {
        case 0:
            proto_item_append_text(item, "%u s", value * 2);
            break;
        case 1:
            proto_item_append_text(item, "%u min", value);
            break;
        case 2:
            proto_item_append_text(item, "%u min", value * 10);
            break;
        case 3:
            proto_item_append_text(item, "%u hours", value);
            break;
        case 4:
            proto_item_append_text(item, "%u hours", value * 10);
            break;
        case 7:
            proto_item_append_text(item, "%u Infinite", value);
            break;
            /* Value 5 and 6 */
        default:
            proto_item_append_text(item, "%u min", value * 1);
            break;
        }
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.36   PDR ID
 */
static int
decode_pfcp_pdr_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, gint offset, pfcp_session_args_t *args)
{
    guint32 rule_id;
    /* Octet 5 to 6 Rule ID*/
    proto_tree_add_item_ret_uint(tree, hf_pfcp_pdr_id, tvb, offset, 2, ENC_BIG_ENDIAN, &rule_id);
    offset += 2;

    proto_item_append_text(item, "%u", rule_id);

    if (args) {
        args->last_rule_ids.pdr = rule_id;
    }

    return offset;
}

static void
dissect_pfcp_pdr_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args)
{
    int offset = 0;

    offset = decode_pfcp_pdr_id(tvb, pinfo, tree, item, offset, args);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.37   F-SEID
 */
static void
dissect_pfcp_f_seid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args)
{
    int offset = 0;
    guint64 f_seid_flags;
    address *ipv4 = NULL, *ipv6 = NULL;
    guint64 seid_cp, *seid;
    guint32 *session;

    static int * const pfcp_f_seid_flags[] = {
        &hf_pfcp_spare_b7,
        &hf_pfcp_spare_b6,
        &hf_pfcp_spare_b5,
        &hf_pfcp_spare_b4,
        &hf_pfcp_spare_b3,
        &hf_pfcp_spare_b2,
        &hf_pfcp_b1_v4,
        &hf_pfcp_b0_v6,
        NULL
    };
    /* Octet 5  Spare   Spare   Spare   Spare   Spare   Spare   V4  V6*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_f_seid_flags, ENC_BIG_ENDIAN, &f_seid_flags);
    offset += 1;

    if ((f_seid_flags & 0x3) == 0) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_encoding_error, tvb, 0, 1);
        return;
    }
    /* Octet 6 to 13    SEID  */
    //proto_tree_add_item(tree, hf_pfcp_seid, tvb, offset, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint64(tree, hf_pfcp_seid, tvb, offset, 8, ENC_BIG_ENDIAN, &seid_cp);
    proto_item_append_text(item, "SEID: 0x%s", tvb_bytes_to_str(pinfo->pool, tvb, offset, 8));
    offset += 8;
    /* IPv4 address (if present)*/
    if ((f_seid_flags & 0x2) == 2) {
        ipv4 = wmem_new0(pinfo->pool, address);
        proto_tree_add_item(tree, hf_pfcp_f_seid_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, ", IPv4 %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
        set_address_tvb(ipv4, AT_IPv4, 4, tvb, offset);
        offset += 4;
    }
    /* IPv6 address (if present)*/
    if ((f_seid_flags & 0x1) == 1) {
        ipv6 = wmem_new0(pinfo->pool, address);
        proto_tree_add_item(tree, hf_pfcp_f_seid_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, ", IPv6 %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
        set_address_tvb(ipv6, AT_IPv6, 16, tvb, offset);
        offset += 16;
    }

    if (g_pfcp_session) {
        session = (guint32 *)g_hash_table_lookup(pfcp_session_table, &pinfo->num);
        if (!session) {
            /* We save the seid so that we could assignate its corresponding session ID later */
            args->last_seid = seid_cp;
            if (!pfcp_seid_exists(seid_cp, args->seid_list)) {
                seid = wmem_new(pinfo->pool, guint64);
                *seid = seid_cp;
                wmem_list_prepend(args->seid_list, seid);
            }
            if (ipv4 != NULL && !pfcp_ip_exists(*ipv4, args->ip_list)) {
                copy_address_wmem(pinfo->pool, &args->last_ip, ipv4);
                wmem_list_prepend(args->ip_list, ipv4);
            }
            if (ipv6 != NULL && !pfcp_ip_exists(*ipv6, args->ip_list)) {
                copy_address_wmem(pinfo->pool, &args->last_ip, ipv6);
                wmem_list_prepend(args->ip_list, ipv6);
            }
        }
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 *   8.2.38   Node ID
 */

static const value_string pfcp_node_id_type_vals[] = {

    { 0, "IPv4 address" },
    { 1, "IPv6 address" },
    { 2, "FQDN" },
    { 0, NULL }
};

static int
decode_pfcp_fqdn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, gint offset, guint16 length)
{
    int name_len, tmp;
    guint8 *fqdn = NULL;

    /* FQDN, the Node ID value encoding shall be identical to the encoding of a FQDN
    * within a DNS message of section 3.1 of IETF RFC 1035 [27] but excluding the trailing zero byte.
    */
    if (length > 0)
    {
        name_len = tvb_get_guint8(tvb, offset);
        /* NOTE 1: The FQDN field in the IE is not encoded as a dotted string as commonly used in DNS master zone files. */
        if (name_len < 0x40) {
            fqdn = tvb_get_string_enc(pinfo->pool, tvb, offset + 1, length - 2, ENC_ASCII);
            for (;;) {
                if (name_len >= length - 2)
                    break;
                tmp = name_len;
                name_len = name_len + fqdn[tmp] + 1;
                fqdn[tmp] = '.';
            }
        }
        /* In case the FQDN field is incorrectly in dotted string form.*/
        else {
            fqdn = tvb_get_string_enc(pinfo->pool, tvb, offset, length - 1, ENC_ASCII);
            proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_encoding_error, tvb, offset, length - 1);
        }
        proto_tree_add_string(tree, hf_pfcp_node_id_fqdn, tvb, offset, length - 1, fqdn);
        proto_item_append_text(item, "%s", fqdn);
        offset += length - 1;
    }
    return offset;
}

static int
decode_pfcp_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, gint offset, guint16 length)
{
    guint32 node_id_type;

    /* Octet 5    Spare Node ID Type*/
    proto_tree_add_item(tree, hf_pfcp_spare_h1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_node_id_type, tvb, offset, 1, ENC_BIG_ENDIAN, &node_id_type);
    proto_item_append_text(item, "%s: ", val_to_str_const(node_id_type, pfcp_node_id_type_vals, "Unknown"));
    offset++;

    switch (node_id_type) {
        case 0:
            /* IPv4 address */
            proto_tree_add_item(tree, hf_pfcp_node_id_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(item, "%s", tvb_ip_to_str(pinfo->pool, tvb, offset));
            offset += 4;
            break;
        case 1:
            /* IPv6 address */
            proto_tree_add_item(tree, hf_pfcp_node_id_ipv6, tvb, offset, 16, ENC_NA);
            proto_item_append_text(item, "%s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
            offset += 16;
            break;
        case 2:
            /* FQDN */
            offset = decode_pfcp_fqdn(tvb, pinfo, tree, item, offset, length);
            break;
        default:
            break;
    }
    return offset;
}
static void
dissect_pfcp_node_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    offset = decode_pfcp_address(tvb, pinfo, tree, item, offset, length);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.39   PFD Contents
 */
static void
dissect_pfcp_pfd_contents(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    int dissected_len = 0;
    guint64 flags;
    guint32 len;
    proto_tree *afd_tree, *aurl_tree, *adnp_tree;

    static int * const pfcp_pfd_contents_flags[] = {
        &hf_pfcp_pfd_contents_flags_b7_adnp,
        &hf_pfcp_pfd_contents_flags_b6_aurl,
        &hf_pfcp_pfd_contents_flags_b5_afd,
        &hf_pfcp_pfd_contents_flags_b4_dnp,
        &hf_pfcp_pfd_contents_flags_b3_cp,
        &hf_pfcp_pfd_contents_flags_b2_dn,
        &hf_pfcp_pfd_contents_flags_b1_url,
        &hf_pfcp_pfd_contents_flags_b0_fd,
        NULL
    };
    /* Octet 5  ADNP   AURL   AFD   DNP   CP   DN   URL   FD */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_pfd_contents_flags, ENC_BIG_ENDIAN, &flags);
    offset += 1;

    // Octet 6 Spare Octet
    proto_tree_add_item(tree, hf_pfcp_spare_oct, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Bit 1 - FD (Flow Description): If this bit is set to "1", then the Length of Flow Description
     * and the Flow Description fields shall be present
     */
    if (flags & 0x1) {
        /* The Flow Description field, when present, shall be encoded as an OctetString
        * as specified in subclause 6.4.3.7 of 3GPP TS 29.251
        */
        /* m to (m+1)   Length of Flow Description */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_flow_desc_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
        offset += 2;

        /* (m+2) to p   Flow Description */
        proto_tree_add_item(tree, hf_pfcp_flow_desc, tvb, offset, len, ENC_ASCII);
        offset += len;
    }

    /* Bit 2 - URL (URL): The URL field, when present,
     * shall be encoded as an OctetString as specified in subclause 6.4.3.8 of 3GPP TS 29.251 [21].
    */
    if (flags & 0x2) {
        /* q to (q+1)   Length of URL */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_url_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
        offset += 2;

        /* (q+2) to r   URL */
        proto_tree_add_item(tree, hf_pfcp_url, tvb, offset, len, ENC_ASCII);
        offset += len;

    }

    /* Bit 3 - DN (Domain Name): The Domain Name field, when present,
     * shall be encoded as an OctetString as specified in subclause 6.4.3.9 of 3GPP TS 29.251 [21].
     */
    if (flags & 0x4) {
        /* s to (s+1)   Length of Domain Name */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_dn_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
        offset += 2;

        /* (s+2) to t   Domain Name */
        proto_tree_add_item(tree, hf_pfcp_dn, tvb, offset, len, ENC_ASCII);
        offset += len;
    }

    /* Bit 4 - CP (Custom PFD Content): If this bit is set to "1", then the Length of Custom PFD Content and
     * the Custom PFD Content fields shall be present
     */
    if (flags & 0x8) {
        /* u to (u+1)   Length of Custom PFD Content */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_cp_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
        offset += 2;

        /* (u+2) to v   Custom PFD Content */
        proto_tree_add_item(tree, hf_pfcp_cp, tvb, offset, len, ENC_NA);
        offset += len;
    }

    /* Bit 5 - DNP (Domain Name Protocol): If this bit is set to "1", then the Length of Domain Name Protocol and
     * the Domain Name Protocol shall be present, otherwise they shall not be present; and if this bit is set to "1",
     * the Length of Domain Name and the Domain Name fields shall also be present.
     */
    if (flags & 0x10) {
        /* The Domain Name Protocol field, when present, shall be encoded as an OctetString
         * as specified in subclause 6.4.3.x of 3GPP TS 29.251 [21].
        */
        /* w to (w+1)   Length of Domain Name Protocol */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_dnp_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
        offset += 2;

        /* (w+2) to x   Domain Name Protocol */
        proto_tree_add_item(tree, hf_pfcp_dnp, tvb, offset, len, ENC_ASCII);
        offset += len;
    }


    /* Bit 6 - AFD (Additional Flow Description): If this bit is set to "1",
     * the Length of Additional Flow Description and the Additional Flow Description field shall be present,
     * otherwise they shall not be present.
    */
    if (flags & 0x20) {
        /* y to (y+1)   Length of Additional Flow Description */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_afd_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
        offset += 2;

        /* (y+2) to z   Additional Flow Description */
        dissected_len = 0;
        afd_tree = proto_item_add_subtree(item, ett_pfcp_adf);
        while (dissected_len < (int)len) {
            guint32 flow_desc_len;
            /* (y+2) to (y+3)   Length of Flow Description */
            proto_tree_add_item_ret_uint(afd_tree, hf_pfcp_flow_desc_len, tvb, offset, 2, ENC_BIG_ENDIAN, &flow_desc_len);
            offset += 2;
            dissected_len += 2;

            /* (y+4) to i   Flow Description */
            proto_tree_add_item(afd_tree, hf_pfcp_flow_desc, tvb, offset, flow_desc_len, ENC_ASCII);
            offset += flow_desc_len;
            dissected_len += flow_desc_len;
        }
    }

    /* Bit 7 - AURL (Additional URL): If this bit is set to "1",
     * the Length of Additional URL and the Additional URL field shall be present,
     * otherwise they shall not be present.
     */
    if (flags & 0x40) {
        /* a to (a+1)   Length of Additional URL */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_aurl_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
        offset += 2;

        /* (a+2) to b   Additional URL */
        dissected_len = 0;
        aurl_tree = proto_item_add_subtree(item, ett_pfcp_aurl);
        while (dissected_len < (int)len) {
            guint32 url_len;
            /* (a+2) to (a+3)   Length of URL */
            proto_tree_add_item_ret_uint(aurl_tree, hf_pfcp_url_len, tvb, offset, 2, ENC_BIG_ENDIAN, &url_len);
            dissected_len += 2;
            offset += 2;

            /* (a+4) to o   URL */
            proto_tree_add_item(aurl_tree, hf_pfcp_url, tvb, offset, url_len, ENC_ASCII);
            dissected_len += url_len;
            offset += url_len;
        }
    }

    /* Bit 8 - ADNP (Additional Domain Name and Domain Name Protocol): If this bit is set to "1",
     * the Length of Additional Domain Name and Domain Name Protocol, and the Additional Domain Name and
     * Domain Name Protocol field shall be present, otherwise they shall not be present.
     */
    if (flags & 0x80) {
        /* c to (c+1)   Length of Additional Domain Name and Domain Name Protocol */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_adnp_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
        offset += 2;

        /* (c+2) to d   Additional Domain Name and Domain Name Protocol */
        dissected_len = 0;
        adnp_tree = proto_item_add_subtree(item, ett_pfcp_adnp);
        while (dissected_len < (int)len) {
            guint32 domain_name_len, domain_name_prot_len;
            /* (c+2) to (c+3)   Length of Domain Name */
            proto_tree_add_item_ret_uint(adnp_tree, hf_pfcp_dn_len, tvb, offset, 2, ENC_BIG_ENDIAN, &domain_name_len);
            dissected_len += 2;
            offset += 2;

            /* (c+4) to pd   Domain Name */
            proto_tree_add_item(adnp_tree, hf_pfcp_dn, tvb, offset, domain_name_len, ENC_ASCII);
            dissected_len += domain_name_len;
            offset += domain_name_len;

            /* (pe) to (pe+1)   Length of Domain Name Protocol */
            proto_tree_add_item_ret_uint(adnp_tree, hf_pfcp_dnp_len, tvb, offset, 2, ENC_BIG_ENDIAN, &domain_name_prot_len);
            dissected_len += 2;
            offset += 2;

            /* (pe+2) to ph   Domain Name Protocol */
            proto_tree_add_item(adnp_tree, hf_pfcp_dnp, tvb, offset, domain_name_prot_len, ENC_ASCII);
            dissected_len += domain_name_prot_len;
            offset += domain_name_prot_len;
        }
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.40   Measurement Method
 */
static void
dissect_pfcp_measurement_method(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_measurement_method_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_measurement_method_flags_b2_event,
        &hf_pfcp_measurement_method_flags_b1_volume,
        &hf_pfcp_measurement_method_flags_b0_durat,
        NULL
    };
    /* Octet 5  Spare   Spare   Spare   Spare   Spare   EVENT   VOLUM   DURAT */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_measurement_method_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.41   Usage Report Trigger
 */
static void
dissect_pfcp_usage_report_trigger(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_usage_report_trigger_o5_flags[] = {
        &hf_pfcp_usage_report_trigger_o5_b7_immer,
        &hf_pfcp_usage_report_trigger_o5_b6_droth,
        &hf_pfcp_usage_report_trigger_o5_b5_stopt,
        &hf_pfcp_usage_report_trigger_o5_b4_start,
        &hf_pfcp_usage_report_trigger_o5_b3_quhti,
        &hf_pfcp_usage_report_trigger_o5_b2_timth,
        &hf_pfcp_usage_report_trigger_o5_b1_volth,
        &hf_pfcp_usage_report_trigger_o5_b0_perio,
        NULL
    };
    /* Octet 5  IMMER   DROTH   STOPT   START   QUHTI   TIMTH   VOLTH   PERIO */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_usage_report_trigger_o5_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset == length) {
        return;
    }

    static int * const pfcp_usage_report_trigger_o6_flags[] = {
        &hf_pfcp_usage_report_trigger_o6_b7_eveth,
        &hf_pfcp_usage_report_trigger_o6_b6_macar,
        &hf_pfcp_usage_report_trigger_o6_b5_envcl,
        &hf_pfcp_usage_report_trigger_o6_b4_monit,
        &hf_pfcp_usage_report_trigger_o6_b3_termr,
        &hf_pfcp_usage_report_trigger_o6_b2_liusa,
        &hf_pfcp_usage_report_trigger_o6_b1_timqu,
        &hf_pfcp_usage_report_trigger_o6_b0_volqu,
        NULL
    };
    /* Octet 6  EVETH   MACAR   ENVCL   MONIT   TERMR   LIUSA   TIMQU   VOLQU */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_usage_report_trigger_o6_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset == length) {
        return;
    }

    static int * const pfcp_usage_report_trigger_o7_flags[] = {
        &hf_pfcp_spare_b7_b6,
        &hf_pfcp_usage_report_trigger_o7_b5_upint,
        &hf_pfcp_usage_report_trigger_o7_b4_emrre,
        &hf_pfcp_usage_report_trigger_o7_b3_quvti,
        &hf_pfcp_usage_report_trigger_o7_b2_ipmjl,
        &hf_pfcp_usage_report_trigger_o7_b1_tebur,
        &hf_pfcp_usage_report_trigger_o7_b0_evequ,
        NULL
    };
    /* Octet 7  Spare   Spare   UPINT   EMRRE   QUVTI   IPMJL   TEBUR   EVEQU */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_usage_report_trigger_o7_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset == length) {
        return;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.42   Measurement Period
 */
static void
dissect_pfcp_measurement_period(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* 5 to 8   Measurement Period*/
    proto_tree_add_item_ret_uint(tree, hf_pfcp_measurement_period, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.43   Fully qualified PDN Connection Set Identifier (FQ-CSID)
 */
static const value_string pfcp_fq_csid_node_id_type_vals[] = {

    { 0, "Node-Address is a global unicast IPv4 address" },
    { 1, "Node-Address is a global unicast IPv6 address" },
    { 2, "Node-Address is a 4 octets long field" },
    { 0, NULL }
};

static const value_string pfcp_fq_csid_node_type_vals[] = {

    { 0, "MME" },
    { 1, "SGW-C" },
    { 2, "PGW-C" },
    { 3, "ePDG" },
    { 4, "TWAN" },
    { 5, "PGW-U/SGW-U" },
    { 0, NULL }
};

static void
dissect_pfcp_fq_csid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 node_id_type, num_csid;

    /* Octet 5  FQ-CSID Node-ID Type    Number of CSIDs= m*/
    proto_tree_add_item_ret_uint(tree, hf_pfcp_fq_csid_node_id_type, tvb, offset, 1, ENC_BIG_ENDIAN, &node_id_type);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_num_csid, tvb, offset, 1, ENC_BIG_ENDIAN, &num_csid);
    offset++;

    /* 6 to p   Node-Address  */
    switch (node_id_type) {
    case 0:
        /* 0    indicates that Node-Address is a global unicast IPv4 address and p = 9 */
        proto_tree_add_item(tree, hf_pfcp_fq_csid_node_id_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    case 1:
        /* 1    indicates that Node-Address is a global unicast IPv6 address and p = 21 */
        proto_tree_add_item(tree, hf_pfcp_fq_csid_node_id_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;
    case 2:
        /* 2    indicates that Node-Address is a 4 octets long field with a 32 bit value stored in network order, and p= 9
         *      Most significant 20 bits are the binary encoded value of (MCC * 1000 + MNC).
         *      Least significant 12 bits is a 12 bit integer assigned by an operator to an MME, SGW-C, SGW-U, PGW-C or PGW-U
         */
        proto_tree_add_item(tree, hf_pfcp_fq_csid_node_id_mcc_mnc, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_pfcp_fq_csid_node_id_int, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    default:
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
        break;
    }

    while (num_csid > 0) {
        proto_tree_add_item(tree, hf_pfcp_fq_csid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        num_csid--;
    }

    if (offset < length) {
        proto_tree_add_item(tree, hf_pfcp_spare_b7_b4, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_pfcp_fq_csid_node_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.44   Volume Measurement
 */
static void
dissect_pfcp_volume_measurement(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags;

    static int * const pfcp_volume_measurement_flags[] = {
        &hf_pfcp_spare_b7_b6,
        &hf_pfcp_volume_measurement_b5_dlnop,
        &hf_pfcp_volume_measurement_b4_ulnop,
        &hf_pfcp_volume_measurement_b3_tonop,
        &hf_pfcp_volume_measurement_b2_dlvol,
        &hf_pfcp_volume_measurement_b1_ulvol,
        &hf_pfcp_volume_measurement_b0_tovol,
        NULL
    };
    /* Octet 5  Spare   DLNOP   ULNOP   TONOP   DLVOL   ULVOL   TOVOL*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_volume_measurement_flags, ENC_BIG_ENDIAN, &flags);
    offset += 1;

    /* Bit 1 - TOVOL: If this bit is set to "1", then the Total Volume field shall be present*/
    if ((flags & 0x1)) {
        /* m to (m+7)   Total Volume */
        proto_tree_add_item(tree, hf_pfcp_vol_meas_tovol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    /* Bit 2 - ULVOL: If this bit is set to "1", then the Total Volume field shall be present*/
    if ((flags & 0x2)) {
        /* p to (p+7)   Uplink Volume */
        proto_tree_add_item(tree, hf_pfcp_vol_meas_ulvol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    /* Bit 3 - DLVOL: If this bit is set to "1", then the Total Volume field shall be present*/
    if ((flags & 0x4)) {
        /*q to (q+7)    Downlink Volume */
        proto_tree_add_item(tree, hf_pfcp_vol_meas_dlvol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    /* Bit 4 - TONOP: If this bit is set to "1", then the Total Number of Packets field shall be present*/
    if ((flags & 0x8)) {
        /* r to (r+7)   Total Number of Packets */
        proto_tree_add_item(tree, hf_pfcp_vol_meas_tonop, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    /* Bit 5 - ULNOP: If this bit is set to "1", then the Total Number of Packets field shall be present*/
    if ((flags & 0x10)) {
        /* s to (s+7)   Uplink Number of Packets */
        proto_tree_add_item(tree, hf_pfcp_vol_meas_ulnop, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    /* Bit 6 - DLNOP: If this bit is set to "1", then the Total Number of Packets field shall be present*/
    if ((flags & 0x20)) {
        /*t to (t+7)    Downlink Number of Packets */
        proto_tree_add_item(tree, hf_pfcp_vol_meas_dlnop, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.45   Duration Measurement
 */
static void
dissect_pfcp_duration_measurement(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* 5 to 8   Duration value*/
    proto_tree_add_item_ret_uint(tree, hf_pfcp_duration_measurement, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u s", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.46   Time of First Packet
 */
static void
dissect_pfcp_time_of_first_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    char *time_str;

    /* Octets 5 to 8 shall be encoded in the same format as the first four octets of the 64-bit timestamp
     * format as defined in section 6 of IETF RFC 5905
     */

    proto_tree_add_item_ret_time_string(tree, hf_pfcp_time_of_first_packet, tvb, offset, 4, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    proto_item_append_text(item, "%s", time_str);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.47   Time of Last Packet
 */
static void
dissect_pfcp_time_of_last_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    char *time_str;

    /* Octets 5 to 8 shall be encoded in the same format as the first four octets of the 64-bit timestamp
    * format as defined in section 6 of IETF RFC 5905
    */

    proto_tree_add_item_ret_time_string(tree, hf_pfcp_time_of_last_packet, tvb, offset, 4, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    proto_item_append_text(item, "%s", time_str);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.48   Quota Holding Time
 */
static void
dissect_pfcp_quota_holding_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* Octet 5 to 8    Time Quota value
    * TThe Time Quota value shall be encoded as an Unsigned32 binary integer value. It contains a duration in seconds
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_quota_holding_time, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u s", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.49   Dropped DL Traffic Threshold
 */
static void
dissect_pfcp_dropped_dl_traffic_threshold(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags_val;

    static int * const pfcp_dropped_dl_traffic_threshold_flags[] = {
        &hf_pfcp_dropped_dl_traffic_threshold_b1_dlby,
        &hf_pfcp_dropped_dl_traffic_threshold_b0_dlpa,
        NULL
    };
    /* Octet 5  Spare   DLBY    DLPA*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_dropped_dl_traffic_threshold_flags, ENC_BIG_ENDIAN, &flags_val);
    offset += 1;

    if ((flags_val & 0x1) == 1) {
        /* m to (m+7)   Downlink Packets
        * DLPA: If this bit is set to "1", then the Downlink Packets field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_downlink_packets, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if ((flags_val & 0x2) == 2) {
        /* o to (o+7)   Number of Bytes of Downlink Data
        * DLBY: If this bit is set to "1", then the Number of Bytes of Downlink Data field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_bytes_downlink_data, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.50   Volume Quota
 */
static void
dissect_pfcp_volume_quota(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags_val;

    static int * const pfcp_volume_quota_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_volume_quota_b2_dlvol,
        &hf_pfcp_volume_quota_b1_ulvol,
        &hf_pfcp_volume_quota_b0_tovol,
        NULL
    };
    /* Octet 5  Spare   DLVOL   ULVOL   TOVOL*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_volume_quota_flags, ENC_BIG_ENDIAN, &flags_val);
    offset += 1;

    /* The Total Volume, Uplink Volume and Downlink Volume fields shall be encoded as an Unsigned64 binary integer value.
    * They shall contain the total, uplink or downlink number of octets respectively.
    */
    if ((flags_val & 0x1) == 1) {
        /* m to (m+7)   Total Volume
        * TOVOL: If this bit is set to "1", then the Total Volume field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_volume_quota_tovol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    if ((flags_val & 0x2) == 2) {
        /* p to (p+7)    Uplink Volume
        * ULVOL: If this bit is set to "1", then the Uplink Volume field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_volume_quota_ulvol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    if ((flags_val & 0x4) == 4) {
        /* q to (q+7)   Downlink Volume
        * DLVOL: If this bit is set to "1", then the Downlink Volume field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_volume_quota_dlvol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.51   Time Quota
 */
static void
dissect_pfcp_time_quota(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* Octet 5 to 8    Time Quota value
    * TThe Time Quota value shall be encoded as an Unsigned32 binary integer value. It contains a duration in seconds
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_time_quota, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u s", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.52   Start Time
 */
static void
dissect_pfcp_start_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    char *time_str;
    int offset = 0;

    /* The Start Time field shall contain a UTC time. Octets 5 to 8 are encoded in the same format as
    * the first four octets of the 64-bit timestamp format as defined in section 6 of IETF RFC 5905 [26].
    */
    proto_tree_add_item_ret_time_string(tree, hf_pfcp_start_time, tvb, offset, 4, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    proto_item_append_text(item, "%s", time_str);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.53   End Time
 */
static void
dissect_pfcp_end_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    char *time_str;
    int offset = 0;

    /* The End Time field shall contain a UTC time. Octets 5 to 8 are encoded in the same format as
    * the first four octets of the 64-bit timestamp format as defined in section 6 of IETF RFC 5905 [26].
    */
    proto_tree_add_item_ret_time_string(tree, hf_pfcp_end_time, tvb, offset, 4, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    proto_item_append_text(item, "%s", time_str);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.54   URR ID
 */
static int
decode_pfcp_urr_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint offset, pfcp_session_args_t *args)
{
    guint32 urr_id;
    /* Octet 5 to 8 URR ID value
    * The bit 8 of octet 5 is used to indicate if the Rule ID is dynamically allocated by the CP function
    * or predefined in the UP function. If set to 0, it indicates that the Rule is dynamically provisioned
    * by the CP Function. If set to 1, it indicates that the Rule is predefined in the UP Function
    */
    urr_id = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_pfcp_urr_id_flg, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_pfcp_urr_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_item_append_text(item, "%s %u",
        tfs_get_string((urr_id & 0x80000000), &pfcp_id_predef_dynamic_tfs),
        (urr_id & 0x7fffffff));

    if (args) {
        args->last_rule_ids.urr = urr_id;
    }

    return offset;
}

static void
dissect_pfcp_urr_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args)
{
    int offset = 0;

    offset = decode_pfcp_urr_id(tvb, pinfo, tree, item, offset, args);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.55   Linked URR ID IE
 */
static void
dissect_pfcp_linked_urr_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octet 5 to 8 Linked URR ID value
    * The Linked URR ID value shall be encoded as an Unsigned32 binary integer value
    */
    offset = decode_pfcp_urr_id(tvb, pinfo, tree, item, offset, NULL);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.56   Outer Header Creation
 */

static const value_string pfcp_outer_hdr_desc_vals[] = {

    { 0x000100, "GTP-U/UDP/IPv4 " },
    { 0x000200, "GTP-U/UDP/IPv6 " },
    { 0x000300, "GTP-U/UDP/IPv4/IPv6 " },
    { 0x000400, "UDP/IPv4 " },
    { 0x000800, "UDP/IPv6 " },
    { 0x000C00, "UDP/IPv4/IPv6 " },
    { 0x001000, "IPv4 " },
    { 0x002000, "IPv6 " },
    { 0x003000, "IPv4/IPv6 " },
    { 0x004000, "C-TAG " },
    { 0x008000, "S-TAG " },
    { 0x010000, "N19 Indication " },
    { 0x020000, "N6 Indication " },
    { 0x040000, "Low Layer SSM and C-TEID " },
    { 0, NULL }
};

static void
dissect_pfcp_outer_header_creation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;

    /* Octet 5  Outer Header Creation Description */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_outer_hdr_desc, tvb, offset, 2, ENC_BIG_ENDIAN, &value);
    offset += 2;

    /* m to (m+3)   TEID
     * The TEID field shall be present if the Outer Header Creation Description requests the creation of a GTP-U header.
     * Otherwise it shall not be present
     */
    if ((value & 0x000100) || (value & 0x000200)) {
        proto_tree_add_item(tree, hf_pfcp_outer_hdr_creation_teid, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /*
    * p to (p+3)   IPv4
    * The IPv4 Address field shall be present if the Outer Header Creation Description requests the creation of a IPv4 header
    */
    if ((value & 0x000100) || (value & 0x000400) || (value & 0x001000)) {
        proto_tree_add_item(tree, hf_pfcp_outer_hdr_creation_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /*
    * q to (q+15)   IPv6
    * The IPv6 Address field shall be present if the Outer Header Creation Description requests the creation of a IPv6 header
    */
    if ((value & 0x000200) || (value & 0x000800) || (value & 0x002000)) {
        proto_tree_add_item(tree, hf_pfcp_outer_hdr_creation_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }

    /*
    * r to (r+1)   Port Number
    * The Port Number field shall be present if the Outer Header Creation Description requests the creation of a UDP/IP header
    */
    if ((value & 0x000400) || (value & 0x000800)) {
        proto_tree_add_item(tree, hf_pfcp_outer_hdr_creation_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    /*
    * t to (t+2)   C-TAG
    * The C-TAG field shall be present if the Outer Header Creation Description requests the setting of the C-Tag in Ethernet packet
    */
    if (value & 0x004000) {
        offset = decode_pfcp_c_tag(tvb, pinfo, tree, item, offset);
    }

    /*
    * u to (u+2)   S-TAG
    * The S-TAG field shall be present if the Outer Header Creation Description requests the setting of the S-Tag in Ethernet packet
    */
    if (value & 0x008000) {
        offset = decode_pfcp_s_tag(tvb, pinfo, tree, item, offset);
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.57   BAR ID
 */
static int
decode_pfcp_bar_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 offset, pfcp_session_args_t *args)
{
    guint32 value;
    /* Octet 5 BAR ID value
    * The BAR ID value shall be encoded as a binary integer value
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_bar_id, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;
    proto_item_append_text(item, "%u", value);

    if (args) {
        args->last_rule_ids.bar = value;
    }

    return offset;
}
static void
dissect_pfcp_bar_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args)
{
    int offset = 0;

    offset = decode_pfcp_bar_id(tvb, pinfo, tree, item, offset, args);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.58   CP Function Features
 */
static void
dissect_pfcp_cp_function_features(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_cp_function_features_o5_flags[] = {
        &hf_pfcp_cp_function_features_o5_b7_uiaur,
        &hf_pfcp_cp_function_features_o5_b6_ardr,
        &hf_pfcp_cp_function_features_o5_b5_mpas,
        &hf_pfcp_cp_function_features_o5_b4_bundl,
        &hf_pfcp_cp_function_features_o5_b3_sset,
        &hf_pfcp_cp_function_features_o5_b2_epfar,
        &hf_pfcp_cp_function_features_o5_b1_ovrl,
        &hf_pfcp_cp_function_features_o5_b0_load,
        NULL
    };
    /* Octet 5  UIAUR   ARDR    MPAS    BUNDL   SSET   EPFAR   OVRL   LOAD */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_cp_function_features_o5_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset == length) {
        return;
    }

    static int * const pfcp_cp_function_features_o6_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_cp_function_features_o6_b1_rpgur,
        &hf_pfcp_cp_function_features_o6_b0_psucc,
        NULL
    };
    /* Octet 6  Spare   Spare    Spare    Spare   Spare   Spare   RPGUR   PSUCC */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_cp_function_features_o6_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.59   Usage Information
 */
static void
dissect_pfcp_usage_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_usage_information_flags[] = {
        &hf_pfcp_spare_h1,
        &hf_pfcp_usage_information_b3_ube,
        &hf_pfcp_usage_information_b2_uae,
        &hf_pfcp_usage_information_b1_aft,
        &hf_pfcp_usage_information_b0_bef,
        NULL
    };
    /* Octet 5  Spare   UBE UAE AFT BEF */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_usage_information_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.60   Application Instance ID
 */
static void
dissect_pfcp_application_instance_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octet 5 5 to (n+4)   Application Instance Identifier
     * The Application Instance Identifier shall be encoded as an OctetString (see 3GPP TS 29.212)
     */
    if (tvb_ascii_isprint(tvb, offset, length))
    {
        const guint8* string_value;
        proto_tree_add_item_ret_string(tree, hf_pfcp_application_instance_id_str, tvb, offset, length, ENC_ASCII | ENC_NA, pinfo->pool, &string_value);
        proto_item_append_text(item, "%s", string_value);
    }
    else
    {
        proto_tree_add_item(tree, hf_pfcp_application_instance_id, tvb, offset, length, ENC_NA);
    }
}

/*
 * 8.2.61   Flow Information
 */
static const value_string pfcp_flow_dir_vals[] = {
    { 0, "Unspecified" },
    { 1, "Downlink (traffic to the UE)" },
    { 2, "Uplink (traffic from the UE)" },
    { 3, "Bidirectional" },
    { 0, NULL }
};

static void
dissect_pfcp_flow_inf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 len;
    /* Octet 5 Spare    Flow Direction */
    proto_tree_add_item(tree, hf_pfcp_spare_b7_b3, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_pfcp_flow_dir, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* 6 to 7   Length of Flow Description */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_flow_desc_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
    offset += 2;
    /* Flow Description
    * The Flow Description field, when present, shall be encoded as an OctetString
    * as specified in subclause 5.4.2 of 3GPP TS 29.212
    */
    proto_tree_add_item(tree, hf_pfcp_flow_desc, tvb, offset, len, ENC_ASCII);
    offset += len;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.62   UE IP Address
 */
static const true_false_string pfcp_ue_ip_add_sd_flag_vals = {
    "Destination IP address",
    "Source IP address",
};

static void
dissect_pfcp_ue_ip_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 ue_ip_address_flags;

    static int * const pfcp_ue_ip_address_flags[] = {
        &hf_pfcp_spare_b7,
        &hf_pfcp_ue_ip_address_flag_b6_v6pl,
        &hf_pfcp_ue_ip_address_flag_b5_chv6,
        &hf_pfcp_ue_ip_address_flag_b4_chv4,
        &hf_pfcp_ue_ip_address_flag_b3_v6d,
        &hf_pfcp_ue_ip_address_flag_b2_sd,
        &hf_pfcp_ue_ip_address_flag_b1_v4,
        &hf_pfcp_ue_ip_address_flag_b0_v6,
        NULL
    };
    /* Octet 5  Spare   IPV6PL  CHV6    CHV4   IPv6D   S/D     V4      V6*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_ue_ip_address_flags, ENC_BIG_ENDIAN, &ue_ip_address_flags);
    offset += 1;

    /* IPv4 address (if present)*/
    if ((ue_ip_address_flags & 0x2)) {
        proto_tree_add_item(tree, hf_pfcp_ue_ip_addr_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    /* IPv6 address (if present)*/
    if ((ue_ip_address_flags & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_ue_ip_add_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }
    /* IPv6 Prefix Delegation Bits (if present)*/
    if ((ue_ip_address_flags & 0x8)) {
        proto_tree_add_item(tree, hf_pfcp_ue_ip_add_ipv6_prefix_delegation_bits, tvb, offset, 1, ENC_NA);
        offset += 1;
    }
    /* IPv6 Prefix Lengths (if present)*/
    if ((ue_ip_address_flags & 0x40)) {
        proto_tree_add_item(tree, hf_pfcp_ue_ip_add_ipv6_prefix_length, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.63   Packet Rate
 */
static const value_string pfcp_pr_time_unit_vals[] = {
    { 0, "Minute" },
    { 1, "6 minutes" },
    { 2, "Hour" },
    { 3, "Day" },
    { 4, "Week" },
    { 0, NULL }
};

static void
dissect_pfcp_packet_rate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags;

    static int * const pfcp_packet_rate_flags[] = {
        &hf_pfcp_spare_b7_b4,
        &hf_pfcp_packet_rate_b2_aprc,
        &hf_pfcp_packet_rate_b1_dlpr,
        &hf_pfcp_packet_rate_b0_ulpr,
        NULL
    };
    /* Octet 5  Spare   DLPR    ULPR */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_packet_rate_flags, ENC_BIG_ENDIAN, &flags);
    offset += 1;

    /* Bit 1 - ULPR (Uplink Packet Rate): If this bit is set to "1", then octets m to (m+2) shall be present */
    if ((flags & 0x1)) {
        /* m */
        proto_tree_add_item(tree, hf_pfcp_spare_b7_b3, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_pfcp_ul_time_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* (m+1) to (m+2)   Maximum Uplink Packet Rate */
        proto_tree_add_item(tree, hf_pfcp_max_ul_pr, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    /* Bit 2 - DLPR (Downlink Packet Rate): If this bit is set to "1", then octets p to (p+2) shall be present*/
    if ((flags & 0x2)) {
        /* p */
        proto_tree_add_item(tree, hf_pfcp_spare_b7_b3, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_pfcp_dl_time_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* (p+1) to (p+2)   Maximum Uplink Packet Rate */
        proto_tree_add_item(tree, hf_pfcp_max_dl_pr, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    /* Bit 4 - APRC (Additional Packet Rate Control) */
    if ((flags & 0x8)) {
        /* If bit 1 (ULPR) is set to "1", then octets q to (q+2), the Additional Maximum Uplink Packet Rate shall be present. */
        if ((flags & 0x1)) {
            /* q */
            proto_tree_add_item(tree, hf_pfcp_spare_b7_b3, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_pfcp_a_ul_time_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            /* (q+1) to (q+2)   Additional Maximum Uplink Packet Rate */
            proto_tree_add_item(tree, hf_pfcp_a_max_ul_pr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
        /* If bit 2 (DLPR) is set to "1", then octets r to (r+2), the Additional Maximum Downlink Packet Rate shall be present. */
        if ((flags & 0x2)) {
            /* r */
            proto_tree_add_item(tree, hf_pfcp_spare_b7_b3, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_pfcp_a_dl_time_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            /* (r+1) to (r+2)   Additional Maximum Uplink Packet Rate */
            proto_tree_add_item(tree, hf_pfcp_a_max_dl_pr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.64   Outer Header Removal
 */
static const value_string pfcp_out_hdr_desc_vals[] = {
    { 0, "GTP-U/UDP/IPv4" },
    { 1, "GTP-U/UDP/IPv6" },
    { 2, "UDP/IPv4" },
    { 3, "UDP/IPv6 " },
    { 4, "IPv4" },
    { 5, "IPv6 " },
    { 6, "GTP-U/UDP/IP" },
    { 7, "VLAN TAG POP" },
    { 8, "VLAN TAGs POP-POP" },
    { 0, NULL }
};

static void
dissect_pfcp_outer_hdr_rem(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;

    static int * const pfcp_gtpu_ext_hdr_del_flags[] = {
        &hf_pfcp_gtpu_ext_hdr_del_b0_pdu_sess_cont,
        NULL
    };

    proto_tree_add_item_ret_uint(tree, hf_pfcp_out_hdr_desc, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;
    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_out_hdr_desc_vals, "Unknown"));

    /* Octet 6  GTP-U Extension Header Deletion */
    if (offset < length) {
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_gtpu_ext_hdr_del_flags, ENC_BIG_ENDIAN);
        offset++;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
 /*
 * 8.2.65   Recovery Time Stamp
 */

static void
dissect_pfcp_recovery_time_stamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    char *time_str;
    int offset = 0;

    /* indicates the UTC time when the node started. Octets 5 to 8 are encoded in the same format as
    * the first four octets of the 64-bit timestamp format as defined in section 6 of IETF RFC 5905 [26].
    */
    proto_tree_add_item_ret_time_string(tree, hf_pfcp_recovery_time_stamp, tvb, offset, 4, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    proto_item_append_text(item, "%s", time_str);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.66   DL Flow Level Marking
 */
static void
dissect_pfcp_dl_flow_level_marking(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags_val;

    static int * const pfcp_dl_flow_level_marking_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_dl_flow_level_marking_b1_sci,
        &hf_pfcp_dl_flow_level_marking_b0_ttc,
        NULL
    };
    /* Octet 5  Spare   SCI TTC*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_dl_flow_level_marking_flags, ENC_BIG_ENDIAN, &flags_val);
    offset += 1;

    /* Bit 1 - TTC (ToS/Traffic Class): If this bit is set to "1",
     * then the ToS/Traffic Class field shall be present
     */
    if ((flags_val & 0x1) == 1) {
        /* m to (m+1)    ToS/Traffic Class
        * The ToS/Traffic Class shall be encoded on two octets as an OctetString.
        * The first octet shall contain the IPv4 Type-of-Service or the IPv6 Traffic-Class field and
        * the second octet shall contain the ToS/Traffic Class mask field
        */
        proto_tree_add_item(tree, hf_pfcp_traffic_class, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_pfcp_traffic_mask, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    /* SCI (Service Class Indicator): If this bit is set to "1",
     * then the Service Class Indicator field shall be present
     */
    if ((flags_val & 0x2) == 2) {
        /* Octets p and (p+1) of the Service Class Indicator field, when present,
        * shall be encoded respectively as octets 2 and 3 of the Service Class Indicator Extension Header
        * specified in Figure 5.2.2.3-1 of 3GPP TS 29.281
        */
        proto_tree_add_item(tree, hf_pfcp_sci, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.67   Header Enrichment
 */
static const value_string pfcp_header_type_vals[] = {
    { 0, "HTTP" },
    { 0, NULL }
};

static void
dissect_pfcp_header_enrichment(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 len;

    /* Octet 5 Spare    Header Type
    */
    proto_tree_add_item(tree, hf_pfcp_spare_b7_b5, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_pfcp_header_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* 6    Length of Header Field Name */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_hf_len, tvb, offset, 1, ENC_BIG_ENDIAN, &len);
    offset++;

    /* 7 to m Header Field Name
     * Header Field Name shall be encoded as an OctetString
     */
    proto_tree_add_item(tree, hf_pfcp_hf_name, tvb, offset, len, ENC_NA);
    offset+= len;

    /* p    Length of Header Field Value*/
    proto_tree_add_item_ret_uint(tree, hf_pfcp_hf_val_len, tvb, offset, 1, ENC_BIG_ENDIAN, &len);
    offset++;

    /* (p+1) to q   Header Field Value */
    proto_tree_add_item(tree, hf_pfcp_hf_val, tvb, offset, len, ENC_NA);
    offset += len;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.68   Measurement Information
 */
static void
dissect_pfcp_measurement_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_measurement_info_flags[] = {
        &hf_pfcp_measurement_info_b7_ciam,
        &hf_pfcp_measurement_info_b6_aspoc,
        &hf_pfcp_measurement_info_b5_sspoc,
        &hf_pfcp_measurement_info_b4_mnop,
        &hf_pfcp_measurement_info_b3_istm,
        &hf_pfcp_measurement_info_b2_radi,
        &hf_pfcp_measurement_info_b1_inam,
        &hf_pfcp_measurement_info_b0_mbqe,
        NULL
    };
    /* Octet 5  CIAM   ASPOC   SSPOC   MNOP    ISTM    INAM    MBQE */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_measurement_info_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.69   Node Report Type
 */
static void
dissect_pfcp_node_report_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_node_report_type_flags[] = {
        &hf_pfcp_spare_b7_b6,
        &hf_pfcp_node_report_type_b5_vsr,
        &hf_pfcp_node_report_type_b4_purr,
        &hf_pfcp_node_report_type_b3_gpqr,
        &hf_pfcp_node_report_type_b2_ckdr,
        &hf_pfcp_node_report_type_b1_uprr,
        &hf_pfcp_node_report_type_b0_upfr,
        NULL
    };
    /* Octet 5  Spare   VSR   PURR   GPQR   CKDR   UPRR    MBQE */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_node_report_type_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.70   Remote GTP-U Peer
 */
static void
dissect_pfcp_remote_gtp_u_peer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags;
    guint32 length_di, length_ni;

    static int * const pfcp_remote_gtp_u_peer_flags[] = {
        &hf_pfcp_spare_b7_b4,
        &hf_pfcp_remote_gtp_u_peer_flags_b3_ni,
        &hf_pfcp_remote_gtp_u_peer_flags_b2_di,
        &hf_pfcp_remote_gtp_u_peer_flags_b1_v4,
        &hf_pfcp_remote_gtp_u_peer_flags_b0_v6,
        NULL
    };
    /* Octet 5  Spare   NI DI V4  V6*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_remote_gtp_u_peer_flags, ENC_BIG_ENDIAN, &flags);
    offset += 1;

    /* IPv4 address (if present)*/
    if (flags & 0x2) {
        proto_tree_add_item(tree, hf_pfcp_remote_gtp_u_peer_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, "IPv4 %s ", tvb_ip_to_str(pinfo->pool, tvb, offset));
        offset += 4;
    }
    /* IPv6 address (if present)*/
    if (flags & 0x1) {
        proto_tree_add_item(tree, hf_pfcp_remote_gtp_u_peer_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, "IPv6 %s ", tvb_ip6_to_str(pinfo->pool, tvb, offset));
        offset += 16;
    }
    /* DI (if present)*/
    if (flags & 0x4) {
        /* Length of Destination Interface field */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_remote_gtp_u_peer_length_di, tvb, offset, 2, ENC_BIG_ENDIAN, &length_di);
        offset += 2;

        /* Destination Interface */
        offset += decode_pfcp_destination_interface(tvb, pinfo, tree, item, offset, length_di);
    }
    /* NI (if present)*/
    if (flags & 0x8) {
        /* Length of Network Instance field */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_remote_gtp_u_peer_length_ni, tvb, offset, 2, ENC_BIG_ENDIAN, &length_ni);
        offset += 2;

        /* Network Instance */
        offset += decode_pfcp_network_instance(tvb, pinfo, tree, item, offset, length_ni);
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.71   UR-SEQN
 */
static void
dissect_pfcp_ur_seqn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    guint value;

    /* 5 to 8   UR-SEQN
    * The UR-SEQN value shall be encoded as an Unsigned32 binary integer value
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_ur_seqn, tvb, 0, 4, ENC_BIG_ENDIAN, &value);

    proto_item_append_text(item, "%u", value);


}

/*
 * 8.2.72   Activate Predefined Rules
 */
static void
dissect_pfcp_act_predef_rules(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    /* Octet 5 to (n+4) Predefined Rules Name
    * The Predefined Rules Name field shall be encoded as an OctetString
    */
    proto_tree_add_item(tree, hf_pfcp_predef_rules_name, tvb, offset, length, ENC_NA);
}
/*
 * 8.2.73   Deactivate Predefined Rules
 */
static void
dissect_pfcp_deact_predef_rules(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    /* Octet 5 to (n+4) Predefined Rules Name
    * The Predefined Rules Name field shall be encoded as an OctetString
    */
    proto_tree_add_item(tree, hf_pfcp_predef_rules_name, tvb, offset, length, ENC_NA);
}
/*
 * 8.2.74   FAR ID
 */
static int
decode_pfcp_far_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, gint offset, pfcp_session_args_t *args)
{
    guint32 far_id;
    /* Octet 5 to 8 FAR ID value
     * The bit 8 of octet 5 is used to indicate if the Rule ID is dynamically allocated
     * by the CP function or predefined in the UP function. If set to 0, it indicates that
     * the Rule is dynamically provisioned by the CP Function. If set to 1, it indicates that
     * the Rule is predefined in the UP Function.
     */
    far_id = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_pfcp_far_id_flg, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_pfcp_far_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_item_append_text(item, "%s %u",
        tfs_get_string((far_id & 0x80000000), &pfcp_id_predef_dynamic_tfs),
        (far_id & 0x7fffffff));

    if (args) {
        args->last_rule_ids.far = far_id;
    }

    return offset;
}

static void
dissect_pfcp_far_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args)
{
    int offset = 0;

    offset = decode_pfcp_far_id(tvb, pinfo, tree, item, offset, args);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.75   QER ID
 */
static int
decode_pfcp_qer_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint offset, pfcp_session_args_t *args)
{
    guint32 qer_id;
    /* Octet 5 to 8 QER ID value
    * The bit 8 of octet 5 is used to indicate if the Rule ID is dynamically allocated by the CP function
    * or predefined in the UP function. If set to 0, it indicates that the Rule is dynamically provisioned
    * by the CP Function. If set to 1, it indicates that the Rule is predefined in the UP Function
    */
    qer_id = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_pfcp_qer_id_flg, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_pfcp_qer_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_item_append_text(item, "%s %u",
        tfs_get_string((qer_id & 0x80000000), &pfcp_id_predef_dynamic_tfs),
        (qer_id & 0x7fffffff));

    if (args) {
        args->last_rule_ids.qer = qer_id;
    }

    return offset;
}
static void
dissect_pfcp_qer_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args)
{
    int offset = 0;

    offset = decode_pfcp_qer_id(tvb, pinfo, tree, item, offset, args);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.76   OCI Flags
 */
static void
dissect_pfcp_oci_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_oci_flags_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_oci_flags_b0_aoci,
        NULL
    };
    /* Octet 5  Spare   AOCI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_oci_flags_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.77   PFCP Association Release Request
 */
static void
dissect_pfcp_pfcp_assoc_rel_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_pfcp_assoc_rel_req_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_pfcp_assoc_rel_req_b0_sarr,
        NULL
    };
    /* Octet 5  Spare    SARR */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_pfcp_assoc_rel_req_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.78   Graceful Release Period
 */
static void
dissect_pfcp_graceful_release_period(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 unit, value;

    /* Octet 5  Timer unit  Timer value */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_timer_unit, tvb, offset, 1, ENC_BIG_ENDIAN, &unit);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_timer_value, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;

    if ((unit == 0) && (value == 0)) {
        proto_item_append_text(item, " Stopped");
    } else {
        switch (unit) {
        case 0:
            proto_item_append_text(item, "%u s", value * 2);
            break;
        case 1:
            proto_item_append_text(item, "%u min", value);
            break;
        case 2:
            proto_item_append_text(item, "%u min", value * 10);
            break;
        case 3:
            proto_item_append_text(item, "%u hours", value);
            break;
        case 4:
            proto_item_append_text(item, "%u hours", value * 10);
            break;
        case 7:
            proto_item_append_text(item, "%u Infinite", value);
            break;
            /* Value 5 and 6 */
        default:
            proto_item_append_text(item, "%u min", value * 1);
            break;
        }
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.79    PDN Type
 */
static const value_string pfcp_pdn_type_vals[] = {
    { 0, "Reserved" },
    { 1, "IPv4" },
    { 2, "IPv6" },
    { 3, "IPv4V6" },
    { 4, "Non-IP" },
    { 5, "Ethernet" },
    { 0, NULL }
};

static void
dissect_pfcp_pdn_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* Octet 5  Application Identifier
    * The Application Identifier shall be encoded as an OctetString (see 3GPP TS 29.212)
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_pdn_type, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;

    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_pdn_type_vals, "Unknown"));

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.80    Failed Rule ID
 */
static const value_string pfcp_failed_rule_id_type_vals[] = {
    { 0, "PDR" },
    { 1, "FAR" },
    { 2, "QER" },
    { 3, "URR" },
    { 4, "BAR" },
    { 5, "MAR" },
    { 6, "SRR" },
    { 0, NULL }
};

/*
 * 8.2.123   MAR ID
 */
static int
decode_pfcp_mar_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, gint offset, pfcp_session_args_t *args)
{
    guint32 mar_id;
    /* Octet 5 to 6 MAR ID*/
    proto_tree_add_item_ret_uint(tree, hf_pfcp_mar_id, tvb, offset, 2, ENC_BIG_ENDIAN, &mar_id);
    offset += 2;

    proto_item_append_text(item, "%u", mar_id);

    if (args) {
        args->last_rule_ids.mar = mar_id;
    }

    return offset;
}
/*
 * 8.2.151   SRR ID
 */
static int
decode_pfcp_srr_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, gint offset, pfcp_session_args_t *args)
{
    guint32 srr_id;
    /* Oct 5 The SRR ID value shall be encoded as a binary integer value. */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_srr_id, tvb, offset, 1, ENC_BIG_ENDIAN, &srr_id);
    offset += 1;

    proto_item_append_text(item, "%u", srr_id);

    if (args) {
        args->last_rule_ids.srr = srr_id;
    }

    return offset;
}

static void
dissect_pfcp_failed_rule_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 rule_type;

    /* Octet 5  Rule ID Type */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_failed_rule_id_type, tvb, offset, 1, ENC_BIG_ENDIAN, &rule_type);
    offset++;

    proto_item_append_text(item, "%s: ", val_to_str_const(rule_type, pfcp_failed_rule_id_type_vals, "Unknown"));

    /* 6 to p  Rule ID value
    * The length and the value of the Rule ID value field shall be set as specified for the
    * PDR ID, FAR ID, QER ID, URR ID, BAR ID, MAR ID and SRR ID IE types respectively.
    */
    switch (rule_type) {
        case 0:
            /* PDR ID */
            offset = decode_pfcp_pdr_id(tvb, pinfo, tree, item, offset, NULL);
            break;
        case 1:
            /* FAR ID */
            offset = decode_pfcp_far_id(tvb, pinfo, tree, item, offset, NULL);
            break;
        case 2:
            /* QER ID */
            offset = decode_pfcp_qer_id(tvb, pinfo, tree, item, offset, NULL);
            break;
        case 3:
            /* URR ID */
            offset = decode_pfcp_urr_id(tvb, pinfo, tree, item, offset, NULL);
            break;
        case 4:
            /* BAR ID */
            offset = decode_pfcp_bar_id(tvb, pinfo, tree, item, offset, NULL);
            break;
        case 5:
            /* MAR ID */
            offset = decode_pfcp_mar_id(tvb, pinfo, tree, item, offset, NULL);
            break;
        case 6:
            /* SRR ID */
            offset = decode_pfcp_srr_id(tvb, pinfo, tree, item, offset, NULL);
            break;
        default:
            break;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.81    Time Quota Mechanism
 */
static const value_string pfcp_time_quota_mechanism_bti_type_vals[] = {
    { 0, "CTP" },
    { 1, "DTP" },
    { 0, NULL }
};

static void
dissect_pfcp_time_quota_mechanism(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 bti_type;

    /* Octet 5  BIT Type */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_time_quota_mechanism_bti_type, tvb, offset, 1, ENC_BIG_ENDIAN, &bti_type);
    offset++;

    proto_item_append_text(item, "%s", val_to_str_const(bti_type, pfcp_time_quota_mechanism_bti_type_vals, "Unknown"));

    /* Base Time Interval
    * The Base Time Interval, shall be encoded as an Unsigned32
    * as specified in subclause 7.2.29 of 3GPP TS 32.299
    */
    proto_tree_add_item(tree, hf_pfcp_time_quota_mechanism_bti, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.82    User Plane IP Resource Information (removed in Rel 16.3)
 */
static void
dissect_pfcp_user_plane_ip_resource_infomation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 upiri_flags_val;
    guint32 upiri_teid_range;

    static int * const pfcp_upiri_flags[] = {
        &hf_pfcp_spare_b7_b6,
        &hf_pfcp_upiri_flg_b6_assosi,
        &hf_pfcp_upiri_flg_b5_assoni,
        &hf_pfcp_upiri_flg_b2b4_teidri,
        &hf_pfcp_upiri_flags_b1_v6,
        &hf_pfcp_upiri_flags_b0_v4,
        NULL
    };
    /* Octet 5  Spare  ASSOSI  ASSONI  TEIDRI  TEIDRI  TEIDRI  V6  V4*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_upiri_flags, ENC_BIG_ENDIAN, &upiri_flags_val);

    /* The following flags are coded within Octet 5:
     * Bit 1   - V4: If this bit is set to "1" and the CH bit is not set, then the IPv4 address field shall be present,
     *           otherwise the IPv4 address field shall not be present.
     * Bit 2   - V6: If this bit is set to "1" and the CH bit is not set, then the IPv6 address field shall be present,
     *           otherwise the IPv6 address field shall not be present.
     * Bit 3-5 - TEIDRI (TEID Range Indication): the value of this field indicates the number of bits in the most significant
     *           octet of a TEID that are used to partition the TEID range, e.g. if this field is set to "4", then the first
     *           4 bits in the TEID are used to partition the TEID range.
     * Bit 6   - ASSONI (Associated Network Instance): if this bit is set to "1", then the Network Instance field shall be present,
     *           otherwise the Network Instance field shall not be present,
     *           i.e. User Plane IP Resource Information provided can be used by CP function for any Network Instance of
     *           GTP-U user plane in the UP function.
     * Bit 7   - ASSOSI (Associated Source Interface): if this bit is set to "1", then the Source Interface field shall be present,
     *           otherwise the Source Interface field shall not be present.
     */

    /* Octet 5, bit 3-5, TEID Range Indication */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_upiri_teidri, tvb, offset, 1, ENC_BIG_ENDIAN, &upiri_teid_range);
    offset += 1;

    if (upiri_teid_range > 0)
    {
        /* Octet t    TEID Range */
        proto_tree_add_item(tree, hf_pfcp_upiri_teid_range, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    if ((upiri_flags_val & 0x1) == 1) {
        /* m to (m+3)    IPv4 address */
        proto_tree_add_item(tree, hf_pfcp_upiri_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    if ((upiri_flags_val & 0x2) == 2) {
        /* p to (p+15)   IPv6 address */
        proto_tree_add_item(tree, hf_pfcp_upiri_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }
    if ((upiri_flags_val & 0x20) == 0x20) {
        /* k to (l)   Network Instance */
        guint16 ni_len = length - offset;
        if ((upiri_flags_val & 0x40) == 0x40) {
            ni_len--;
        }
        offset = decode_pfcp_network_instance(tvb, pinfo, tree, item, offset, ni_len);
    }
    if ((upiri_flags_val & 0x40) == 0x40) {
        /* r   Source Interface */
        offset = decode_pfcp_source_interface(tvb, pinfo, tree, item, offset);
    }
    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.83    User Plane Inactivity Timer
 */
static void
dissect_pfcp_user_plane_inactivity_timer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /*
    * The User Plane Inactivity Timer field shall be encoded as an Unsigned32 binary integer value.
    * The timer value "0" shall be interpreted as an indication that
    * user plane inactivity detection and reporting is stopped.
    */

    /* 5 to 8   Inactivity Timer */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_user_plane_inactivity_timer, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    if(value == 0)
        proto_item_append_text(item, " (Stopped)");

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.84    Multiplier
 */
static void
dissect_pfcp_multiplier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{

    /* 5 to 12  Value-Digits */
    proto_tree_add_item(tree, hf_pfcp_multiplier_value_digits, tvb, 0, 8, ENC_BIG_ENDIAN);

    /* 12 to 15  Exponent */
    proto_tree_add_item(tree, hf_pfcp_multiplier_exponent, tvb, 8, 4, ENC_BIG_ENDIAN);

}

/*
 * 8.2.85    Aggregated URR ID IE
 */
static void
dissect_pfcp_aggregated_urr_id_ie(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* 5 to 8  URR ID */
    decode_pfcp_urr_id(tvb, pinfo, tree, item, 0, NULL);
}

/*
 * 8.2.86   Subsequent Volume Quota
 */
static void
dissect_pfcp_subsequent_volume_quota(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags_val;

    static int * const pfcp_subsequent_volume_quota_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_subsequent_volume_quota_b2_dlvol,
        &hf_pfcp_subsequent_volume_quota_b1_ulvol,
        &hf_pfcp_subsequent_volume_quota_b0_tovol,
        NULL
    };
    /* Octet 5  Spare   DLVOL   ULVOL   TOVOL*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_subsequent_volume_quota_flags, ENC_BIG_ENDIAN, &flags_val);
    offset += 1;

    /* The Total Volume, Uplink Volume and Downlink Volume fields shall be encoded as an Unsigned64 binary integer value.
    * They shall contain the total, uplink or downlink number of octets respectively.
    */
    if ((flags_val & 0x1) == 1) {
        /* m to (m+7)   Total Volume
        * TOVOL: If this bit is set to "1", then the Total Volume field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_subsequent_volume_quota_tovol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    if ((flags_val & 0x2) == 2) {
        /* p to (p+7)    Uplink Volume
        * ULVOL: If this bit is set to "1", then the Uplink Volume field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_subsequent_volume_quota_ulvol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    if ((flags_val & 0x4) == 4) {
        /* q to (q+7)   Downlink Volume
        * DLVOL: If this bit is set to "1", then the Downlink Volume field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_subsequent_volume_quota_dlvol, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.87   Subsequent Time Quota
 */
static void
dissect_pfcp_subsequent_time_quota(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint value;

    /* Octet 5 to 8 Time Quota
    * The Time Quota field shall be encoded as an Unsigned32 binary integer value.
    * It shall contain the duration in seconds.
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_subsequent_time_quota, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u s", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.88   RQI
 */
static void
dissect_pfcp_rqi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_pfcp_spare_b7_b1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_pfcp_rqi_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
    return;
}

/*
 * 8.2.89   QFI
 */
static int
decode_pfcp_qfi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, gint offset)
{
    /*     Octets 5 SPARE   QFI
     *    The Application Identifier shall be encoded as an OctetString
     */
    proto_tree_add_item(tree, hf_pfcp_spare_b7_b6, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_pfcp_qfi, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}
static void
dissect_pfcp_qfi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    offset = decode_pfcp_qfi(tvb, pinfo, tree, item, offset);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
    return;
}

/*
 * 8.2.90   Querry URR Reference
 */
static void
dissect_pfcp_query_urr_reference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octets 5 to 8 Query URR Reference value
     * The Query URR Reference value shall be encoded as an Unsigned32 binary integer value.
     * It shall contain the reference of a query request for URR(s).
     */
    proto_tree_add_item(tree, hf_pfcp_query_urr_reference, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.91    Additional Usage Reports Information
 */
static void
dissect_pfcp_additional_usage_reports_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    /*
     *    Octet    8      7   6      5      4      3      2         1
     *    5    | AURI |   Number of Additional Usage Reports value  |
     *    6    |    Number of Additional Usage Reports value     |
     *
     *  The Number of Additional Usage Reports value shall be encoded as
     *  an unsigned binary integer value on 15 bits.
     *  Bit 7 of Octet 5 is the most significant bit and bit 1 of Octet 6 is the least significant bit.
     *  The bit 8 of octet 5 shall encode the AURI (Additional Usage Reports Indication) flag{...}.
    */
    static int * const pfcp_additional_usage_reports_information_flags[] = {
        &hf_pfcp_additional_usage_reports_information_b15_auri,
        &hf_pfcp_additional_usage_reports_information_b14_b0_number_value,
        NULL
    };
    proto_tree_add_bitmask_list(tree, tvb, offset, 2, pfcp_additional_usage_reports_information_flags, ENC_BIG_ENDIAN);
    offset += 2;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 *   8.2.92 Traffic Endpoint ID
 */
static void dissect_pfcp_traffic_endpoint_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_pfcp_traffic_endpoint_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
    return;
}

/*
 *   8.2.93 MAC Address
 */
static void dissect_pfcp_mac_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags_val;

    static int * const pfcp_mac_address_flags[] = {
        &hf_pfcp_spare_b7_b4,
        &hf_pfcp_mac_address_flags_b3_udes,
        &hf_pfcp_mac_address_flags_b2_usou,
        &hf_pfcp_mac_address_flags_b1_dest,
        &hf_pfcp_mac_address_flags_b0_sour,
        NULL
    };
    /* Octet 5  Spare   EDES    USOU   DEST   SOUR */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_mac_address_flags, ENC_BIG_ENDIAN, &flags_val);
    offset += 1;

    // Octets "m to (m+5)" or "n to (n+5)" and "o to (o+5)" or "p to (p+5)", if present,
    // shall contain a MAC address value (12-digit hexadecimal numbers).
    if ((flags_val & 0x1) == 1) {
        /* m to (m+5)   Source MAC Address
        * SOUR: If this bit is set to "1", then the Source MAC Address field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_mac_address_source_mac_address, tvb, offset, 6, ENC_NA);
        offset += 6;
    }

    if ((flags_val & 0x2) == 2) {
        /* n to (n+5)    Destination MAC Address
        * DEST: If this bit is set to "1", then the Destination MAC Address field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_mac_address_dest_mac_address, tvb, offset, 6, ENC_NA);
        offset += 6;
    }

    if ((flags_val & 0x4) == 4) {
        /* o to (o+5)   Upper Source MAC Address
        * USOU: If this bit is set to "1", then the Upper Source MAC Address field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_mac_address_upper_source_mac_address, tvb, offset, 6, ENC_NA);
        offset += 6;
    }

    if ((flags_val & 0x8) == 8) {
        /* p to (p+5)   Upper Destination MAC Address
        * UDES: If this bit is set to "1", then the Upper Destination MAC Address field shall be present
        */
        proto_tree_add_item(tree, hf_pfcp_mac_address_upper_dest_mac_address, tvb, offset, 6, ENC_NA);
        offset += 6;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
    return;
}

/*
 *   8.2.94 C-TAG (Customer-VLAN tag)
 */
static void dissect_pfcp_c_tag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    offset = decode_pfcp_c_tag(tvb, pinfo, tree, item, offset);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
    return;
}

/*
 *   8.2.95 S-TAG (Service-VLAN tag)
 */
static void dissect_pfcp_s_tag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    offset = decode_pfcp_s_tag(tvb, pinfo, tree, item, offset);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
    return;
}

/*
 *   8.2.96 Ethertype
 */
static void dissect_pfcp_ethertype(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_pfcp_ethertype, tvb, offset, 2, ENC_NA);
    offset += 2;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
    return;
}

/*
 *   8.2.97 Proxying
 */
static void dissect_pfcp_proxying(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags_val;

    static int * const pfcp_proxying_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_proxying_flags_b1_ins,
        &hf_pfcp_proxying_flags_b0_arp,
        NULL
    };
    /* Octet 5  Spare  INS   ARP */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_proxying_flags, ENC_BIG_ENDIAN, &flags_val);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
    return;
}

/*
 *   8.2.98 Ethertype Filter ID
 */
static void dissect_pfcp_ethertype_filter_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_pfcp_ethertype_filter_id, tvb, offset, 4, ENC_NA);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
    return;
}

/*
 *   8.2.99 Ethernet Filter Properties
 */
static void dissect_pfcp_ethernet_filter_properties(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags_val;

    static int * const pfcp_ethernet_filter_properties_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_ethertype_filter_properties_flags_b0_bide,
        NULL
    };
    /* Octet 5  Spare  BIDE */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_ethernet_filter_properties_flags, ENC_BIG_ENDIAN, &flags_val);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
    return;
}

/*
 * 8.2.100   Suggested Buffering Packets Count
 */
static void
dissect_pfcp_suggested_buffering_packets_count(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* 5   Packet count value */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_suggested_buffering_packets_count_packet_count, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset += 1;

    proto_item_append_text(item, "%u packets", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 *   8.2.101 User ID
 */
static void dissect_pfcp_user_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags_val;
    guint32 length_imsi, length_imei, length_msisdn, length_nai, length_supi, length_gpsi, length_pei;

    static int * const pfcp_user_id_flags[] = {
        &hf_pfcp_spare_b7,
        &hf_pfcp_user_id_flags_b6_peif,
        &hf_pfcp_user_id_flags_b5_gpsif,
        &hf_pfcp_user_id_flags_b4_supif,
        &hf_pfcp_user_id_flags_b3_naif,
        &hf_pfcp_user_id_flags_b2_msisdnf,
        &hf_pfcp_user_id_flags_b1_imeif,
        &hf_pfcp_user_id_flags_b0_imsif,
        NULL
    };
    /* Octet 5  Spare   IMEIF   IMSIF */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_user_id_flags, ENC_BIG_ENDIAN, &flags_val);
    offset += 1;

    /* Bit 1 - IMSIF: If this bit is set to "1", then the Length of IMSI and IMSI fields shall be present */
    if ((flags_val & 0x1)) {
        /* 6   Length of IMSI */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_user_id_length_of_imsi, tvb, offset, 1, ENC_BIG_ENDIAN, &length_imsi);
        offset += 1;
        /* 7 to (a)    IMSI */
        dissect_e212_imsi(tvb, pinfo, tree,  offset, length_imsi, FALSE);
        offset += length_imsi;
    }

    /* Bit 2 - IMEIF: If this bit is set to "1", then the Length of IMEI and IMEI fields shall be present */
    if ((flags_val & 0x2)) {
        /* b   Length of IMEI */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_user_id_length_of_imei, tvb, offset, 1, ENC_BIG_ENDIAN, &length_imei);
        offset += 1;

        /* (b+1) to c    IMEI */
        /* Fetch the BCD encoded digits from tvb low half byte, formating the digits according to
        * a default digit set of 0-9 returning "?" for overdecadic digits a pointer to the EP
        * allocated string will be returned.
        */
        proto_tree_add_item(tree, hf_pfcp_user_id_imei, tvb, offset, length_imei, ENC_BCD_DIGITS_0_9);
        offset += length_imei;
    }

    /* Bit 3 - MSIDNF: If this bit is set to "1", then the Length of MSISDN and MSISDN fields shall be present */
    if ((flags_val & 0x4)) {
        /* d   Length of MSISDN */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_user_id_length_of_msisdn, tvb, offset, 1, ENC_BIG_ENDIAN, &length_msisdn);
        offset += 1;
        /* (d+1) to e    MSISDN */
        dissect_e164_msisdn(tvb, tree, offset, length_msisdn, E164_ENC_BCD);
        offset += length_msisdn;
    }

    /* Bit 4 - NAIF: If this bit is set to "1", then the Length of NAI and NAI fields shall be present */
    if ((flags_val & 0x8)) {
        /* f   Length of NAI */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_user_id_length_of_nai, tvb, offset, 1, ENC_BIG_ENDIAN, &length_nai);
        offset += 1;
        /* (f+1) to g    NAI */
        proto_tree_add_item(tree, hf_pfcp_user_id_nai, tvb, offset, length_nai, ENC_ASCII);
        offset += length_nai;
    }

    /* Bit 5 - SUPIF: If this bit is set to "1", then the Length of SUPI and SUPI fields shall be present */
    if ((flags_val & 0x10)) {
        /* f   Length of SUPI */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_user_id_length_of_supi, tvb, offset, 1, ENC_BIG_ENDIAN, &length_supi);
        offset += 1;
        /* (f+1) to g    SUPI */
        proto_tree_add_item(tree, hf_pfcp_user_id_supi, tvb, offset, length_supi, ENC_ASCII);
        offset += length_supi;
    }

    /* Bit 6 - GPSIF: If this bit is set to "1", then the Length of GPSI and GPSI fields shall be present */
    if ((flags_val & 0x20)) {
        /* f   Length of GPSI */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_user_id_length_of_gpsi, tvb, offset, 1, ENC_BIG_ENDIAN, &length_gpsi);
        offset += 1;
        /* (f+1) to g    GPSI */
        proto_tree_add_item(tree, hf_pfcp_user_id_gpsi, tvb, offset, length_gpsi, ENC_ASCII);
        offset += length_gpsi;
    }

    /* Bit 7 - PEIF: If this bit is set to "1", then the Length of PEI and PEI fields shall be present */
    if ((flags_val & 0x40)) {
        /* f   Length of PEI */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_user_id_length_of_pei, tvb, offset, 1, ENC_BIG_ENDIAN, &length_pei);
        offset += 1;
        /* (f+1) to g    PEI */
        proto_tree_add_item(tree, hf_pfcp_user_id_pei, tvb, offset, length_pei, ENC_ASCII);
        offset += length_pei;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
    return;
}

/*
 *   8.2.102 Ethernet PDU Session Information
 */
static void dissect_pfcp_ethernet_pdu_session_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_ethernet_pdu_session_information_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_ethernet_pdu_session_information_flags_b0_ethi,
        NULL
    };
    /* Octet 5  Spare   ETHI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_ethernet_pdu_session_information_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
    return;
}

/*
 * 8.2.103   MAC Addresses Detected
 */
static void
dissect_pfcp_mac_addresses_detected(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value, i, length_ctag, length_stag;

    /* 5   Number of MAC addresses  */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_mac_addresses_detected_number_of_mac_addresses, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset += 1;

    /* o to (o+6) MAC Address  */
    for (i = 0; i < value; i++)
    {
        proto_tree_add_item(tree, hf_pfcp_mac_addresses_detected_mac_address, tvb, offset, 6, ENC_NA);
        offset += 6;
    }

    if (offset == length) {
        return;
    }

    /* s   Length of C-TAG */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_mac_addresses_detected_length_of_ctag, tvb, offset, 1, ENC_BIG_ENDIAN, &length_ctag);
    offset += 1;
    /* (s+1) to t    C-TAG */
    if (length_ctag > 0)
    {
        offset = decode_pfcp_c_tag(tvb, pinfo, tree, item, offset);
    }

    /* u   Length of S-TAG */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_mac_addresses_detected_length_of_stag, tvb, offset, 1, ENC_BIG_ENDIAN, &length_stag);
    offset += 1;
    /* (u+1) to v    S-TAG */
    if (length_stag > 0)
    {
        offset = decode_pfcp_s_tag(tvb, pinfo, tree, item, offset);
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.104   MAC Addresses Removed
 */
static void
dissect_pfcp_mac_addresses_removed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value, i, length_ctag, length_stag;

    /* 5   Number of MAC addresses  */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_mac_addresses_removed_number_of_mac_addresses, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset += 1;

    /* o to (o+6) MAC Address  */
    for (i = 0; i < value; i++)
    {
        proto_tree_add_item(tree, hf_pfcp_mac_addresses_removed_mac_address, tvb, offset, 6, ENC_NA);
        offset += 6;
    }

    if (offset == length) {
        return;
    }

    /* s   Length of C-TAG */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_mac_addresses_removed_length_of_ctag, tvb, offset, 1, ENC_BIG_ENDIAN, &length_ctag);
    offset += 1;
    /* (s+1) to t    C-TAG */
    if (length_ctag > 0)
    {
        offset = decode_pfcp_c_tag(tvb, pinfo, tree, item, offset);
    }

    /* u   Length of S-TAG */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_mac_addresses_removed_length_of_stag, tvb, offset, 1, ENC_BIG_ENDIAN, &length_stag);
    offset += 1;
    /* (u+1) to v    S-TAG */
    if (length_stag > 0)
    {
        offset = decode_pfcp_s_tag(tvb, pinfo, tree, item, offset);
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.105    Ethernet Inactivity Timer
 */
static void
dissect_pfcp_ethernet_inactivity_timer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /*
    * The Ethernet Inactivity Timer field shall be encoded as an Unsigned32 binary integer value.
    */

    /* 5 to 8   Inactivity Timer */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_ethernet_inactivity_timer, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.106   Subsequent Event Quota
 */
static void
dissect_pfcp_subsequent_event_quota(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /*
    * The Subsequent Event Quota field shall be encoded as an Unsigned32 binary integer value.
    */

    /* 5 to 8   Subsequent Event Quota */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_subsequent_event_quota, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.107   Subsequent Event Threshold
 */
static void
dissect_pfcp_subsequent_event_threshold(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /*
    * The Subsequent Event Threshold field shall be encoded as an Unsigned32 binary integer value.
    */

    /* 5 to 8   Subsequent Event Threshold */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_subsequent_event_threshold, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.108   Trace Information
 */
static void
dissect_pfcp_trace_information(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 length_trigger_events, length_list_interfaces, length_ipaddress;

    /* 5 to 7   MCC MNC */
    offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, E212_NONE, TRUE);

    /* 8 to 10   Trace ID */
    proto_tree_add_item(tree, hf_pfcp_trace_information_trace_id, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* 11   Length of Trigger Events */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_trace_information_length_trigger_events, tvb, offset, 1, ENC_BIG_ENDIAN, &length_trigger_events);
    offset += 1;

    /* 12 to m   Trigger Events */
    proto_tree_add_item(tree, hf_pfcp_trace_information_trigger_events, tvb, offset, length_trigger_events, ENC_NA);
    offset += length_trigger_events;

    /* m+1   Session Trace Depth */
    proto_tree_add_item(tree, hf_pfcp_trace_information_session_trace_depth, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* m+2   Length of List of Interfaces */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_trace_information_length_list_interfaces, tvb, offset, 1, ENC_BIG_ENDIAN, &length_list_interfaces);
    offset += 1;

    /* (m+3) to p   List of Interfaces */
    proto_tree_add_item(tree, hf_pfcp_trace_information_list_interfaces, tvb, offset, length_list_interfaces, ENC_NA);
    offset += length_list_interfaces;

    /* p+1   Length of IP address of Trace Collection Entity  */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_trace_information_length_ipaddress, tvb, offset, 1, ENC_BIG_ENDIAN, &length_ipaddress);
    offset += 1;

    /* (p+2) to q   IP Address of Trace Collection Entity */
    if (length_ipaddress == 4) {
        proto_tree_add_item(tree, hf_pfcp_trace_information_ipv4, tvb, offset, length_ipaddress, ENC_NA);
    } else if (length_ipaddress == 16) {
        proto_tree_add_item(tree, hf_pfcp_trace_information_ipv6, tvb, offset, length_ipaddress, ENC_NA);
    }
    offset += length_ipaddress;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.109    Framed-Route
 */
static void
dissect_pfcp_framed_route(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* Octet 5 to (n+4) Framed-Route
    * The Framed-Route field shall be encoded as an Octet String as the value part of the Framed-Route AVP specified in IETF RFC 2865
    * RFC 2865:
    * The Text field is one or more octets, and its contents are
    *  implementation dependent.  It is intended to be human readable and
    *  MUST NOT affect operation of the protocol.  It is recommended that
    *  the message contain UTF-8 encoded 10646 [7] characters.
    */
    proto_tree_add_item(tree, hf_pfcp_framed_route, tvb, 0, length, ENC_UTF_8);
}

/*
 * 8.2.110    Framed-Routing
 */
static void
dissect_pfcp_framed_routing(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* Octet 5 to (n+4) Framed-Routing
    * The Framed-Routing field shall be encoded as an Octet String as the value part of the Framed-Routing AVP specified in IETF RFC 2865
    */
    proto_tree_add_item(tree, hf_pfcp_framed_routing, tvb, 0, length, ENC_NA);
}

/*
 * 8.2.111    Framed-IPv6-Route
 */
static void
dissect_pfcp_framed_ipv6_route(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* Octet 5 to (n+4) Framed-IPv6-Route
    * The Framed-IPv6-Route field shall be encoded as an Octet String as the value part of the Framed-IPv6-Route AVP specified in RFC 3162
    * RFC 3162
    * "...It is intended to be human readable..."
    */
    proto_tree_add_item(tree, hf_pfcp_framed_ipv6_route, tvb, 0, length, ENC_UTF_8);
}

/*
 * 8.2.112   Event Quota
 */
static void
dissect_pfcp_event_quota(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;

    /* 5 to 8   Event Quota
    * The Event Quota field shall be encoded as an Unsigned32 binary integer value.
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_event_quota, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.113   Event Threshold
 */
static void
dissect_pfcp_event_threshold(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;

    /* 5 to 8   Event Threshold
    * The Event Threshold field shall be encoded as an Unsigned32 binary integer value.
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_event_threshold, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.114   Time Stamp
 */
static void
dissect_pfcp_time_stamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    char *time_str;
    int offset = 0;

    /* The Time Stamp field shall contain a UTC time.
    * Octets 5 to 8 shall be encoded in the same format as the first four octets
    * of the 64-bit timestamp format as defined in section 6 of IETF RFC 5905.
    */
    proto_tree_add_item_ret_time_string(tree, hf_pfcp_time_stamp, tvb, offset, 4, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    proto_item_append_text(item, "%s", time_str);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.115   Averaging Window
 */
static void
dissect_pfcp_averaging_window(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;

    /* 5 to 8   Averaging Window
    * The Averaging Window field shall be encoded as an Unsigned32 binary integer value.
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_averaging_window, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.116   Paging Policy Indicator (PPI)
 */
static void
dissect_pfcp_paging_policy_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;

    /* Octet 5  Paging Policy Indicator (PPI)
    * The PPI shall be encoded as a value between 0 and 7, as specified in clause 5.5.3.7 of 3GPP TS 38.415
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_paging_policy_indicator, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;

    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.117    APN/DNN
 */
static void
dissect_pfcp_apn_dnn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item , guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int      offset = 0;

    /* Octet 5   APN/DNN
     * The encoding the APN/DNN field follows 3GPP TS 23.003 [2] clause 9.1.
     * The content of the APN/DNN field shall be the full APN/DNN with both the
     * APN/DNN Network Identifier and APN/DNN Operator Identifier
     */
     /* NOTE: The APN/DNN field is not encoded as a dotted string as commonly used in documentation. */

    const guint8* string_value;
    proto_tree_add_item_ret_string(tree, hf_pfcp_apn_dnn, tvb, offset, length, ENC_APN_STR | ENC_NA, pinfo->pool, &string_value);
    proto_item_append_text(item, "%s", string_value);

}

/*
 *   8.2.118   3GPP Interface Type
 */

static const value_string pfcp_tgpp_interface_type_vals[] = {

    { 0, "S1-U" },
    { 1, "S5/S8-U" },
    { 2, "S4-U" },
    { 3, "S11-U" },
    { 4, "S12" },
    { 5, "Gn/Gp-U" },
    { 6, "S2a-U" },
    { 7, "S2b-U" },
    { 8, "eNodeB GTP-U interface for DL data forwarding" },
    { 9, "eNodeB GTP-U interface for UL data forwarding" },
    { 10, "SGW/UPF GTP-U interface for DL data forwarding" },
    { 11, "N3 3GPP Access" },
    { 12, "N3 Trusted Non-3GPP Access" },
    { 13, "N3 Untrusted Non-3GPP Access" },
    { 14, "N3 for data forwarding" },
    { 15, "N9 (or N9 for non-roaming)" },
    { 16, "SGi" },
    { 17, "N6" },
    { 18, "N19" },
    { 19, "S8-U" },
    { 20, "Gp-U" },
    { 21, "N9 for roaming" },
    { 22, "Iu-U" },
    { 23, "N9 for data forwarding" },
    { 24, "Sxa-U" },
    { 25, "Sxb-U" },
    { 26, "Sxc-U" },
    { 27, "N4-U" },
    { 28, "SGW/UPF GTP-U interface for UL data forwarding" },
    { 29, "N6mb/Nmb9" },
    { 30, "N3mb" },
    { 31, "N19mb" },
    { 0, NULL }
};

static void
dissect_pfcp_tgpp_interface_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 tgpp_interface_type;

    /* Octet 5    Spare Node ID Type*/
    proto_tree_add_item(tree, hf_pfcp_spare_h1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_tgpp_interface_type, tvb, offset, 1, ENC_BIG_ENDIAN, &tgpp_interface_type);
    proto_item_append_text(item, "%s: ", val_to_str_const(tgpp_interface_type, pfcp_tgpp_interface_type_vals, "Unknown"));
    offset++;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.119   PFCPSRReq-Flags
 */
static void
dissect_pfcp_pfcpsrreq_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_pfcpsrreq_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_pfcpsrreq_flags_b0_psdbu,
        NULL
    };
    /* Octet 5  Spare   Spare   Spare   Spare   Spare   Spare   Spare   PSDBU */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_pfcpsrreq_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.120   PFCPAUReq-Flags
 */
static void
dissect_pfcp_pfcpaureq_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_pfcpaureq_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_pfcpaureq_flags_b0_parps,
        NULL
    };
    /* Octet 5  Spare   Spare   Spare   Spare   Spare   Spare   Spare   PSDBU */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_pfcpaureq_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.121   Activation Time
 */
static void
dissect_pfcp_activation_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    char *time_str;

    /* Octets 5 to 8 shall be encoded in the same format as the first four octets of the 64-bit timestamp
     * format as defined in section 6 of IETF RFC 5905
     */

    proto_tree_add_item_ret_time_string(tree, hf_pfcp_activation_time, tvb, offset, 4, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    proto_item_append_text(item, "%s", time_str);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.122   Deactivation Time
 */
static void
dissect_pfcp_deactivation_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    char *time_str;

    /* Octets 5 to 8 shall be encoded in the same format as the first four octets of the 64-bit timestamp
     * format as defined in section 6 of IETF RFC 5905
     */

    proto_tree_add_item_ret_time_string(tree, hf_pfcp_deactivation_time, tvb, offset, 4, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    proto_item_append_text(item, "%s", time_str);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.123   MAR ID
 */

static void
dissect_pfcp_mar_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args)
{
    int offset = 0;

    offset = decode_pfcp_mar_id(tvb, pinfo, tree, item, offset, args);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.124    Steering Functionality
 */
static const value_string pfcp_steering_functionality_vals[] = {
    { 0, "ATSSS-LL" },
    { 1, "MPTCP" },
    { 0, NULL }
};

static void
dissect_pfcp_steering_functionality(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* Octet 5  Steering Functionality Value
    * The Steering Functionality shall be encoded as a 4 bits binary
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_steering_functionality, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;

    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_steering_functionality_vals, "Unknown"));

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.125    Steering Mode
 */
static const value_string pfcp_steering_mode_vals[] = {
    { 0, "Active-Standby" },
    { 1, "Smallest Delay" },
    { 2, "Load Balancing" },
    { 3, "Priority-based" },
    { 0, NULL }
};

static void
dissect_pfcp_steering_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* Octet 5  Steering Mode Value
    * The Steering Mode shall be encoded as a 4 bits binary
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_steering_mode, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;

    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_steering_mode_vals, "Unknown"));

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.126   Weight
 */
static void
dissect_pfcp_weight(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    guint32 value;
    /* Octet 5  Weight */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_weight, tvb, 0, 1, ENC_BIG_ENDIAN, &value);

    proto_item_append_text(item, "%u", value);

}

/*
 * 8.2.127    Priority
 */
static const value_string pfcp_priority_vals[] = {
    { 0, "Active" },
    { 1, "Standby" },
    { 2, "No Standby" },
    { 3, "High" },
    { 4, "Low" },
    { 0, NULL }
};

static void
dissect_pfcp_priority(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* Octet 5  Priority Value
    * The Priority shall be encoded as a 4 bits binary.
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_priority, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;

    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_priority_vals, "Unknown"));

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.128   UE IP address Pool Identity
 */
static void
dissect_pfcp_ue_ip_address_pool_identity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 pool_length;

    /* Octet 7 to "k" UE IP address Pool Identity
    * The UE IP address Pool Identity field shall be encoded as an OctetString
    * (see the Framed-Ipv6-Pool and Framed-Pool in clause 12.6.3 of 3GPP TS 29.561).
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_ue_ip_address_pool_length, tvb, 0, 2, ENC_BIG_ENDIAN, &pool_length);
    offset += 2;

    proto_tree_add_item(tree, hf_pfcp_ue_ip_address_pool_identity, tvb, offset, pool_length, ENC_NA);
    offset += pool_length;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.129   Alternative SMF IP Address
 */
static void
dissect_pfcp_alternative_smf_ip_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 alternative_smf_ip_address_flags;

    static int * const pfcp_alternative_smf_ip_address_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_alternative_smf_ip_address_flags_ppe,
        &hf_pfcp_b1_v4,
        &hf_pfcp_b0_v6,
        NULL
    };
    /* Octet 5  Spare   PPE   V4  V6 */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_alternative_smf_ip_address_flags, ENC_BIG_ENDIAN, &alternative_smf_ip_address_flags);
    offset += 1;

    /* IPv4 address (if present) */
    if (alternative_smf_ip_address_flags & 0x2) {
        proto_tree_add_item(tree, hf_pfcp_alternative_smf_ip_address_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, ", IPv4 %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
        offset += 4;
    }
    /* IPv6 address (if present) */
    if (alternative_smf_ip_address_flags & 0x1) {
        proto_tree_add_item(tree, hf_pfcp_alternative_smf_ip_address_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, ", IPv6 %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
        offset += 16;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.130   Packet Replication and Detection Carry-On Information
 */
static void
dissect_pfcp_packet_replication_and_detection_carry_on_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_packet_replication_and_detection_carry_on_information_flags[] = {
        &hf_pfcp_spare_b7_b4,
        &hf_pfcp_packet_replication_and_detection_carry_on_information_flags_b3_dcaroni,
        &hf_pfcp_packet_replication_and_detection_carry_on_information_flags_b2_prin6i,
        &hf_pfcp_packet_replication_and_detection_carry_on_information_flags_b1_prin19i,
        &hf_pfcp_packet_replication_and_detection_carry_on_information_flags_b0_priueai,
        NULL
    };
    /* Octet 5  Spare   Spare   Spare   Spare   DCARONI   PRIN6I   PRIN19I   PRIUEAI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_packet_replication_and_detection_carry_on_information_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.131   SMF Set ID
 */
static void
dissect_pfcp_smf_set_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octet 5  Spare */
    proto_tree_add_item(tree, hf_pfcp_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* 6 to m  FQDN */
    offset = decode_pfcp_fqdn(tvb, pinfo, tree, item, offset, length);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.132   Quota Validity Time
 */
static void
dissect_pfcp_quota_validity_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint value;

    /* The Quota Validity Time value shall be encoded as an Unsigned32 binary integer value. */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_validity_time_value, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.133   Number of Reports
 */
static void
dissect_pfcp_number_of_reports(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    guint value;

    /* Number of Reports, an Unigned16 binary integer value excluding the first value "0". */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_number_of_reports, tvb, 0, length, ENC_BIG_ENDIAN, &value);
    proto_item_append_text(item, "%u", value);
}

/*
 * 8.2.134   PFCPASRsp-Flags
 */
static void
dissect_pfcp_pfcpasrsp_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_pfcpasrsp_flags_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_pfcpasrsp_flags_flags_b1_uupsi,
        &hf_pfcp_pfcpasrsp_flags_flags_b0_psrei,
        NULL
    };
    /* Octet 5  Spare   UUPSI   PSREI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_pfcpasrsp_flags_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.135   CP PFCP Entity IP Address
 */
static void
dissect_pfcp_cp_pfcp_entity_ip_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 cp_pfcp_entity_ip_address_flags;

    static int * const pfcp_cp_pfcp_entity_ip_address_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_b1_v4,
        &hf_pfcp_b0_v6,
        NULL
    };
    /* Octet 5  Spare   V4  V6 */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_cp_pfcp_entity_ip_address_flags, ENC_BIG_ENDIAN, &cp_pfcp_entity_ip_address_flags);
    offset += 1;

    /* IPv4 address (if present) */
    if ((cp_pfcp_entity_ip_address_flags & 0x2)) {
        proto_tree_add_item(tree, hf_pfcp_cp_pfcp_entity_ip_address_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, ", IPv4 %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
        offset += 4;
    }
    /* IPv6 address (if present) */
    if ((cp_pfcp_entity_ip_address_flags & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_cp_pfcp_entity_ip_address_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, ", IPv6 %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
        offset += 16;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.136   PFCPSEReq-Flags
 */
static void
dissect_pfcp_pfcpsereq_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_pfcpsereq_flags_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_pfcpsereq_flags_flags_b1_sumpc,
        &hf_pfcp_pfcpsereq_flags_flags_b0_resti,
        NULL
    };
    /* Octet 5  Spare   SUMPC   RESTI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_pfcpsereq_flags_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.137   IP Multicast Address
 */
static void
dissect_pfcp_ip_multicast_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 ip_multicast_address_flags;

    static int * const pfcp_ip_multicast_address_flags[] = {
        &hf_pfcp_spare_b7_b4,
        &hf_pfcp_ip_multicast_address_flags_b3_any,
        &hf_pfcp_ip_multicast_address_flags_b2_range,
        &hf_pfcp_b1_v4,
        &hf_pfcp_b0_v6,
        NULL
    };
    /* Octet 5  Spare   A(Any)   R(Range)   V4  V6 */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_ip_multicast_address_flags, ENC_BIG_ENDIAN, &ip_multicast_address_flags);
    offset += 1;

    /* Any: If this bit is set to "1", this indicates any IP multicast address; in this case, no IP address field shall be included. */
    if (!(ip_multicast_address_flags & 0x8)) {
        /* IPv4 address (if present) */
        if ((ip_multicast_address_flags & 0x2)) {
            proto_tree_add_item(tree, hf_pfcp_ip_multicast_address_start_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        /* IPv6 address (if present) */
        if ((ip_multicast_address_flags & 0x1)) {
            proto_tree_add_item(tree, hf_pfcp_ip_multicast_address_start_ipv6, tvb, offset, 16, ENC_NA);
            offset += 16;
        }
        /* Range */
        if ((ip_multicast_address_flags & 0x4)) {
            /* IPv4 address (if present) */
            if ((ip_multicast_address_flags & 0x2)) {
                proto_tree_add_item(tree, hf_pfcp_ip_multicast_address_end_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }
            /* IPv6 address (if present) */
            if ((ip_multicast_address_flags & 0x1)) {
                proto_tree_add_item(tree, hf_pfcp_ip_multicast_address_end_ipv6, tvb, offset, 16, ENC_NA);
                offset += 16;
            }
        }
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.138   Source IP Address
 */
static void
dissect_pfcp_source_ip_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 source_ip_address_flags;

    static int * const pfcp_source_ip_address_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_source_ip_address_flags_b2_mpl,
        &hf_pfcp_b1_v4,
        &hf_pfcp_b0_v6,
        NULL
    };
    /* Octet 5  Spare   V4  V6 */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_source_ip_address_flags, ENC_BIG_ENDIAN, &source_ip_address_flags);
    offset += 1;

    /* IPv4 address (if present) */
    if ((source_ip_address_flags & 0x2)) {
        proto_tree_add_item(tree, hf_pfcp_source_ip_address_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, ", IPv4 %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
        offset += 4;
    }
    /* IPv6 address (if present) */
    if ((source_ip_address_flags & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_source_ip_address_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, ", IPv6 %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
        offset += 16;
    }
    /* Mask/Prefix Length (if present) */
    if ((source_ip_address_flags & 0x4)) {
        proto_tree_add_item(tree, hf_pfcp_source_ip_address_mask_prefix_lengt, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, ", IPv6 %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
        offset += 16;
    }


    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.139   Packet Rate Status
 */
static void
dissect_pfcp_packet_rate_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags_val;

    static int * const pfcp_packet_rate_status_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_packet_rate_status_flags_b2_apr,
        &hf_pfcp_packet_rate_status_flags_b1_dl,
        &hf_pfcp_packet_rate_status_flags_b0_ul,
        NULL
    };
    /* Octet 5  Spare   APR   DL   UL*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_packet_rate_status_flags, ENC_BIG_ENDIAN, &flags_val);
    offset += 1;


    /* Number of Remaining Uplink Packets Allowed */
    if ((flags_val & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_packet_rate_status_ul, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if ((flags_val & 0x4)) {
            proto_tree_add_item(tree, hf_pfcp_packet_rate_status_apr_ul, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }
    /* Number of Remaining Downlink Packets Allowed */
    if ((flags_val & 0x2)) {
        proto_tree_add_item(tree, hf_pfcp_packet_rate_status_dl, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Additional number of Remaining Downlink Packets Allowed */
        if ((flags_val & 0x4)) {
            proto_tree_add_item(tree, hf_pfcp_packet_rate_status_apr_dl, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }
    /* Rate Control Status Validity Time */
    if (offset < length) {
        proto_tree_add_item(tree, hf_pfcp_packet_rate_status_validity_time, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.140   Create Bridge Info for TSC
 */
static void
dissect_pfcp_create_bridge_info_for_tsc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_create_bridge_info_for_tsc_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_create_bridge_info_for_tsc_flags_b0_bii,
        NULL
    };
    /* Octet 5  Spare   BII */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_create_bridge_info_for_tsc_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.141   DS-TT Port Number
 */
static void
dissect_pfcp_ds_tt_port_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    guint value;

    /* The DS-TT Port Number shall contain one Port Number value */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_ds_tt_port_number, tvb, 0, length, ENC_BIG_ENDIAN, &value);
    proto_item_append_text(item, "%u", value);
}

/*
 * 8.2.142   NW-TT Port Number
 */
static void
dissect_pfcp_nw_tt_port_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    guint value;

    /* The NW-TT Port Number shall contain one Port Number value */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_nw_tt_port_number, tvb, 0, length, ENC_BIG_ENDIAN, &value);
    proto_item_append_text(item, "%u", value);
}

/*
 * 8.2.143   5GS User Plane Node
 */
static void
dissect_pfcp_5gs_user_plane_node(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags_val;

    static int * const pfcp_5gs_user_plane_node_flags[] = {
        &hf_pfcp_spare_b7_b4,
        &hf_pfcp_5gs_user_plane_node_flags_b0_bid,
        NULL
    };
    /* Octet 5  Spare   BID */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_5gs_user_plane_node_flags, ENC_BIG_ENDIAN, &flags_val);
    offset += 1;

    // Bit 1 – BID: If this bit is set to "1", then the Use Plane value field shall be present,
    // The Bridge ID value is defined in IEEE.802.1Q clause 14.2.5 and value shall be encoded as an Unisigned64 binary integer.
    if ((flags_val & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_5gs_user_plane_node_value, tvb, offset, 6, ENC_NA);
        offset += 6;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.144   Port Management Information Container
 */
static void
dissect_pfcp_port_management_information_container(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* Oct 5 The Port Management Information field shall be encoded as an Octet String. */
    proto_tree_add_item(tree, hf_pfcp_port_management_information, tvb, 0, length, ENC_NA);
}

/*
 * 8.2.145   Requested Clock Drift Information
 */
static void
dissect_pfcp_requested_clock_drift_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_requested_clock_drift_control_information_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_requested_clock_drift_control_information_flags_b1_rrcr,
        &hf_pfcp_requested_clock_drift_control_information_flags_b0_rrto,
        NULL
    };
    /* Octet 5  Spare   BII */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_requested_clock_drift_control_information_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.146  Time Domain Number
 */
static void
dissect_pfcp_time_domain_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint value;

    /* Oct 5 The TSN Time Domain Number value field shall be encoded as a binary integer value. */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_time_domain_number_value, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;

    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.147   Time Offset Threshold
 */
static void
dissect_pfcp_time_offset_threshold(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Oct 5 to 12 The Time Offset Threshold field shall be encoded as a signed64 binary integer value. It shall contain the Time Offset Threshold in nanoseconds. */
    proto_tree_add_item(tree, hf_pfcp_time_offset_threshold, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.148   Cumulative rateRatio Threshold
 */
static void
dissect_pfcp_cumulative_rate_ratio_threshold(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Oct 5 The Cumulative rateRatio Threshold field shall be encoded as the cumulativeRateRatio (Integer32) specified in clauses 14.4.2 and 15.6 of IEEE Std 802.1AS-Rev/D7.3 [58], i.e. the quantity "(rateRatio- 1.0)(2^41)". */
    proto_tree_add_item(tree, hf_pfcp_cumulative_rate_ratio_threshold, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.149   Time Offset Measurement
 */
static void
dissect_pfcp_time_offset_measurement(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Oct 5 The Time Offset Measurement field shall be encoded as a signed64 binary integer value. It shall contain the Time Offset Measurement in nanoseconds. */
    proto_tree_add_item(tree, hf_pfcp_time_offset_measurement, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.150   Cumulative rateRatio Measurement
 */
static void
dissect_pfcp_cumulative_rate_ratio_measurement(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Oct 5 The Cumulative rateRatio Measurement field shall be encoded as the cumulativeRateRatio (Integer32) specified in clauses 14.4.2 and 15.6 of IEEE Std 802.1AS-Rev/D7.3 [58], i.e. the quantity "(rateRatio- 1.0)(2^41)".  */
    proto_tree_add_item(tree, hf_pfcp_cumulative_rate_ratio_measurement, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.151   SRR ID
 */

static void
dissect_pfcp_srr_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args)
{
    int offset = 0;

    offset = decode_pfcp_srr_id(tvb, pinfo, tree, item, offset, args);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.152   Requested Access Availability Information
 */
static void
dissect_pfcp_requested_access_availability_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_requested_access_availability_control_information_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_requested_access_availability_control_information_flags_b0_rrca,
        NULL
    };
    /* Octet 5  Spare   RRCA */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_requested_access_availability_control_information_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.153   Access Availability Information
 */
static const value_string pfcp_availability_status_vals[] = {
    { 0, "Access has become unavailable" },
    { 1, "Access has become available" },
    { 0, NULL }
};
static const value_string pfcp_availability_type_vals[] = {
    { 0, "3GPP access type" },
    { 1, "Non-3GPP access type" },
    { 0, NULL }
};

static void
dissect_pfcp_access_availability_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octet 5 */
    /* Availability Status */
    proto_tree_add_item(tree, hf_pfcp_availability_status, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Access Type  */
    proto_tree_add_item(tree, hf_pfcp_availability_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.154   MPTCP Control Information
 */
static void
dissect_pfcp_mptcp_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_mptcp_control_information_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_mptcp_control_information_flags_b0_tci,
        NULL
    };
    /* Octet 5  Spare   RRCA */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_mptcp_control_information_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.155   ATSSS-LL Control Information
 */
static void
dissect_pfcp_atsss_ll_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_atsss_ll_control_information_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_atsss_ll_control_information_flags_b0_lli,
        NULL
    };
    /* Octet 5  Spare   RRCA */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_atsss_ll_control_information_flags, ENC_BIG_ENDIAN);
    offset += 1;


    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.156   PMF Control Information
 */
static void
dissect_pfcp_pmf_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags;
    guint32 value, i;

    static int * const pfcp_pmf_control_information_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_pmf_control_information_flags_b2_pqpm,
        &hf_pfcp_pmf_control_information_flags_b1_drtti,
        &hf_pfcp_pmf_control_information_flags_b0_pmfi,
        NULL
    };
    /* Octet 5  Spare   PQPM   DRTTI   RRCA */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_pmf_control_information_flags, ENC_BIG_ENDIAN, &flags);
    offset += 1;

    /* QFI */
    if ((flags & 0x4)) {
        /* 6   Number of QFI  */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_pmf_control_information_number_of_qfi, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
        offset += 1;

        /* 7 to (7+p+1) QFI  */
        for (i = 0; i < value; i++)
        {
            offset = decode_pfcp_qfi(tvb, pinfo, tree, item, offset);
        }
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.157   MPTCP Address Information
 */
static void
dissect_pfcp_mptcp_address_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 mptcp_address_flags;

    static int * const pfcp_mptcp_ip_address_information_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_mptcp_address_information_flags_b1_v6,
        &hf_pfcp_mptcp_address_information_flags_b0_v4,
        NULL
    };
    /* Octet 5  Spare   V6  V4 */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_mptcp_ip_address_information_flags, ENC_BIG_ENDIAN, &mptcp_address_flags);
    offset += 1;

    /* Octet 6  MPTCP Proxy Type */
    proto_tree_add_item(tree, hf_pfcp_mptcp_proxy_type, tvb, offset, 1, ENC_NA);
    offset++;

    /* Octet 7 to 8  MPTCP Proxy Port */
    proto_tree_add_item(tree, hf_pfcp_mptcp_proxy_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* MPTCP Proxy IPv4 address (if present) */
    if ((mptcp_address_flags & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_mptcp_proxy_ip_address_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, ", IPv4 %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
        offset += 4;
    }
    /* MPTCP Proxy IPv6 address (if present) */
    if ((mptcp_address_flags & 0x2)) {
        proto_tree_add_item(tree, hf_pfcp_mptcp_proxy_ip_address_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, ", IPv6 %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
        offset += 16;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.158   UE Link-Specific IP Address
 */
static void
dissect_pfcp_ue_link_specific_ip_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 ue_link_specific_ip_address_flags;

    static int * const pfcp_ue_link_specific_ip_address_flags[] = {
        &hf_pfcp_spare_b7_b4,
        &hf_pfcp_ue_link_specific_ip_address_flags_b3_nv6,
        &hf_pfcp_ue_link_specific_ip_address_flags_b2_nv4,
        &hf_pfcp_ue_link_specific_ip_address_flags_b1_v6,
        &hf_pfcp_ue_link_specific_ip_address_flags_b0_v4,
        NULL
    };
    /* Octet 5  Spare  NV6  NV4  V6  V4 */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_ue_link_specific_ip_address_flags, ENC_BIG_ENDIAN, &ue_link_specific_ip_address_flags);
    offset += 1;

    /* UE Link-Specific IPv4 Address for 3GPP Access (if present) */
    if ((ue_link_specific_ip_address_flags & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_ue_link_specific_ip_address_3gpp_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    /* UE Link-Specific IPv6 Address for 3GPP Access (if present) */
    if ((ue_link_specific_ip_address_flags & 0x2)) {
        proto_tree_add_item(tree, hf_pfcp_ue_link_specific_ip_address_3gpp_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }

    /* UE Link-Specific IPv4 Address for Non-3GPP Access (if present) */
    if ((ue_link_specific_ip_address_flags & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_ue_link_specific_ip_address_non3gpp_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    /* UE Link-Specific IPv6 Address for Non-3GPP Access (if present) */
    if ((ue_link_specific_ip_address_flags & 0x2)) {
        proto_tree_add_item(tree, hf_pfcp_ue_link_specific_ip_address_non3gpp_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }
    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.159   PMF Address Information
 */
static void
dissect_pfcp_pmf_address_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 pmf_address_information_flags;

    static int * const pfcp_pmf_address_information_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_pmf_address_information_flags_b2_mac,
        &hf_pfcp_pmf_address_information_flags_b1_v6,
        &hf_pfcp_pmf_address_information_flags_b0_v4,
        NULL
    };
    /* Octet 5  Spare   MAC V6  V4 */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_pmf_address_information_flags, ENC_BIG_ENDIAN, &pmf_address_information_flags);
    offset += 1;

    /* p to (p+3) PMF IPv4 address (if present) */
    if ((pmf_address_information_flags & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_pmf_address_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    /* q to (q+15) PMF IPv6 address (if present) */
    if ((pmf_address_information_flags & 0x2)) {
        proto_tree_add_item(tree, hf_pfcp_pmf_address_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }
    /* r to (r+1) PMF Port for 3GPP */
    proto_tree_add_item(tree, hf_pfcp_pmf_port_3gpp, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* s to (s+1) PMF Port for Non-3GPP */
    proto_tree_add_item(tree, hf_pfcp_pmf_port_non3gpp, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* t to (t+5) PMF MAC address for 3GPP access (if present)*/
    if ((pmf_address_information_flags & 0x4)) {
        proto_tree_add_item(tree, hf_pfcp_pmf_mac_address_3gpp, tvb, offset, 6, ENC_NA);
        offset += 6;
    }

    /* u to (u+5) PMF MAC address for Non-3GPP access (if present)*/
    if ((pmf_address_information_flags & 0x4)) {
        proto_tree_add_item(tree, hf_pfcp_pmf_mac_address_non3gpp, tvb, offset, 6, ENC_NA);
        offset += 6;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.160   ATSSS-LL Information
 */
static void
dissect_pfcp_atsss_ll_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_atsss_ll_information_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_atsss_ll_information_flags_b0_lli,
        NULL
    };
    /* Octet 5  Spare   LLI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_atsss_ll_information_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.161   Data Network Access Identifier
 */
static void
dissect_pfcp_data_network_access_identifier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octet 5 to (n+4) Data Network Access Identifier
    * The Data Network Access Identifier field shall be encoded as an OctetString
    */
    proto_tree_add_item(tree, hf_pfcp_data_network_access_identifier, tvb, offset, length, ENC_NA);
}

/*
 * 8.2.162   Average Packet Delay
 */
static void
dissect_pfcp_average_packet_delay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octet 5 to 8 Delay Value in milliseconds */
    proto_tree_add_item(tree, hf_pfcp_packet_delay_milliseconds, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.163   Minimum Packet Delay
 */
static void
dissect_pfcp_minimum_packet_delay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octet 5 to 8 Delay Value in milliseconds */
    proto_tree_add_item(tree, hf_pfcp_packet_delay_milliseconds, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.164   Maximum Packet Delay
 */
static void
dissect_pfcp_maximum_packet_delay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octet 5 to 8 Delay Value in milliseconds */
    proto_tree_add_item(tree, hf_pfcp_packet_delay_milliseconds, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.165   QoS Report Trigger
 */
static void
dissect_pfcp_qos_report_trigger(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_qos_report_trigger_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_qos_report_trigger_flags_b2_ire,
        &hf_pfcp_qos_report_trigger_flags_b1_thr,
        &hf_pfcp_qos_report_trigger_flags_b0_per,
        NULL
    };
    /* Octet 5  Spare   IRE THR PER */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_qos_report_trigger_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.166   GTP-U Path Interface Type
 */
static void
dissect_pfcp_gtp_u_path_interface_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_gtp_u_path_interface_type_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_gtp_u_path_interface_type_flags_b1_n3,
        &hf_pfcp_gtp_u_path_interface_type_flags_b0_n9,
        NULL
    };
    /* Octet 5  Spare   N3  N9 */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_gtp_u_path_interface_type_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.167   Requested QoS Monitoring
 */
static void
dissect_pfcp_requested_qos_monitoring(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_requested_qos_monitoring_flags[] = {
        &hf_pfcp_spare_b7_b4,
        &hf_pfcp_requested_qos_monitoring_flags_b3_gtpupm,
        &hf_pfcp_requested_qos_monitoring_flags_b2_rp,
        &hf_pfcp_requested_qos_monitoring_flags_b1_ul,
        &hf_pfcp_requested_qos_monitoring_flags_b0_dl,
        NULL
    };
    /* Octet 5  Spare   GTPUPM   RP  Ul  DL */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_requested_qos_monitoring_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.168   Reporting Frequency
 */
static void
dissect_pfcp_reporting_frequency(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_reporting_frequency_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_reporting_frequency_flags_b2_sesrl,
        &hf_pfcp_reporting_frequency_flags_b1_perio,
        &hf_pfcp_reporting_frequency_flags_b0_evett,
        NULL
    };
    /* Octet 5  Spare   RP  Ul  DL */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_reporting_frequency_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.169   Packet Delay Thresholds
 */
static void
dissect_pfcp_packet_delay_thresholds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 packet_delay_thresholds_flags;

    static int * const pfcp_packet_delay_thresholds_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_packet_delay_thresholds_flags_b2_rp,
        &hf_pfcp_packet_delay_thresholds_flags_b1_ul,
        &hf_pfcp_packet_delay_thresholds_flags_b0_dl,
        NULL
    };
    /* Octet 5  Spare   RP  Ul  DL */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_packet_delay_thresholds_flags, ENC_BIG_ENDIAN, &packet_delay_thresholds_flags);
    offset += 1;

    /* m to (m+3) Downlink packet delay threshold */
    if ((packet_delay_thresholds_flags & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_packet_delay_thresholds_downlink, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /* p to (p+3) Uplink packet delay threshold */
    if ((packet_delay_thresholds_flags & 0x2)) {
        proto_tree_add_item(tree, hf_pfcp_packet_delay_thresholds_uplink, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /* q to (q+3) Round trip packet delay threshold */
    if ((packet_delay_thresholds_flags & 0x4)) {
        proto_tree_add_item(tree, hf_pfcp_packet_delay_thresholds_roundtrip, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.170   Minimum Wait Time
 */
static void
dissect_pfcp_minimum_wait_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octet 5 to 8     Minimum Wait Time */
    proto_tree_add_item(tree, hf_pfcp_minimum_wait_time_seconds, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.171   QoS Monitoring Measurement
 */
static void
dissect_pfcp_qos_monitoring_measurement(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 qos_monitoring_measurement_flags;

    static int * const pfcp_qos_monitoring_measurement_flags[] = {
        &hf_pfcp_spare_b7_b4,
        &hf_pfcp_qos_monitoring_measurement_flags_b3_plmf,
        &hf_pfcp_qos_monitoring_measurement_flags_b2_rp,
        &hf_pfcp_qos_monitoring_measurement_flags_b1_ul,
        &hf_pfcp_qos_monitoring_measurement_flags_b0_dl,
        NULL
    };
    /* Octet 5  Spare   RP  Ul  DL */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_qos_monitoring_measurement_flags, ENC_BIG_ENDIAN, &qos_monitoring_measurement_flags);
    offset += 1;

    /* m to (m+3) Downlink packet delay threshold */
    if ((qos_monitoring_measurement_flags & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_qos_monitoring_measurement_downlink, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /* p to (p+3) Uplink packet delay threshold */
    if ((qos_monitoring_measurement_flags & 0x2)) {
        proto_tree_add_item(tree, hf_pfcp_qos_monitoring_measurement_uplink, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /* q to (q+3) Round trip packet delay threshold */
    if ((qos_monitoring_measurement_flags & 0x4)) {
        proto_tree_add_item(tree, hf_pfcp_qos_monitoring_measurement_roundtrip, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.172   MT-EDT Control Information
 */
static void
dissect_pfcp_mt_edt_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_mt_edt_control_information_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_mt_edt_control_information_flags_b0_rdsi,
        NULL
    };
    /* Octet 5  Spare   RDSI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_mt_edt_control_information_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.173   DL Data Packets Size
 */
static void
dissect_pfcp_dl_data_packets_size(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Oct 5 to 6 DL Data Packets Size  */
    proto_tree_add_item(tree, hf_pfcp_dl_data_packets_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.174   QER Control Indications
 */
static void
dissect_pfcp_qer_control_indications(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_qer_control_indications_o5_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_qer_control_indications_o5_b0_rcsr,
        NULL
    };
    /* Octet 5  Spare    RCSR */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_qer_control_indications_o5_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.175   NF Instance ID
 */
static void
dissect_pfcp_nf_instance_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octet 5 to 20    NF Instance ID */
    proto_tree_add_item(tree, hf_pfcp_nf_instance_id, tvb, offset, length, ENC_NA);
}

/*
 * 8.2.176   S-NSSAI
 */
static void
dissect_pfcp_s_nssai(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octet 5    SST */
    proto_tree_add_item(tree, hf_pfcp_s_nssai_sst, tvb, offset, 1, ENC_NA);
    offset++;

    /* Octet 6 to 8    SD */
    proto_tree_add_item(tree, hf_pfcp_s_nssai_sd, tvb, offset, 3, ENC_NA);
    offset += 3;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.177    IP version
 */
static void
dissect_pfcp_ip_version(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_ip_version_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_ip_version_flags_b1_v6,
        &hf_pfcp_ip_version_flags_b0_v4,
        NULL
    };
    /* Octet 5  Spare  V6  V4 */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_ip_version_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.178   PFCPASReq-Flags
 */
static void
dissect_pfcp_pfcpasreq_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_pfcpasreq_flags_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_pfcpasreq_flags_flags_b0_uupsi,
        NULL
    };
    /* Octet 5  Spare   UUPSI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_pfcpasreq_flags_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.179   Data Status
 */
static void
dissect_pfcp_data_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_data_status_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_data_status_flags_b1_buff,
        &hf_pfcp_data_status_flags_b0_drop,
        NULL
    };
    /* Octet 5  Spare   BUFF    DROP */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_data_status_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.180   RDS Configuration Information
 */
static void
dissect_pfcp_rds_configuration_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_rds_configuration_information_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_rds_configuration_information_flags_b0_rds,
        NULL
    };
    /* Octet 5  Spare   RDS */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_rds_configuration_information_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.181   MPTCP Application Indication
 */
static void
dissect_pfcp_mptcp_application_indication(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_mptcp_application_indication_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_mptcp_application_indication_flags_b0_mai,
        NULL
    };
    /* Octet 5  Spare   MAI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_mptcp_application_indication_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.182   User Plane NodeManagement Information Container
 */
static void
dissect_pfcp_user_plane_nodemanagement_information_container(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    /* Octet 5 to (n+4) User Plane NodeManagement Information Container
    * The User Plane NodeManagement Information Container field shall be encoded as an OctetString.
    */
    proto_tree_add_item(tree, hf_pfcp_user_plane_nodemanagement_information_container, tvb, offset, length, ENC_NA);
}

/*
 * 8.2.183   Number of UE IP Addresses
 */
static void
dissect_pfcp_number_of_ue_ip_addresses(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 number_of_ue_ip_addresses_flags;

    static int * const pfcp_number_of_ue_ip_addresses_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_number_of_ue_ip_addresses_b1_ipv6,
        &hf_pfcp_number_of_ue_ip_addresses_b0_ipv4,
        NULL
    };
    /* Octet 5  Spare   Spare   Spare   Spare   Spare   Spare   IPv6  IPv4*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_number_of_ue_ip_addresses_flags, ENC_BIG_ENDIAN, &number_of_ue_ip_addresses_flags);
    offset += 1;

    /* a to (a+3)  Number of UE IPv4 Addresses */
    if ((number_of_ue_ip_addresses_flags & 0x1) == 1) {
        proto_tree_add_item(tree, hf_pfcp_number_of_ue_ip_addresses_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    /* b to (b+3)  Number of UE IPv6 Addresses */
    if ((number_of_ue_ip_addresses_flags & 0x2) == 2) {
        proto_tree_add_item(tree, hf_pfcp_number_of_ue_ip_addresses_ipv6, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.184   Validity Timer
 */
static void
dissect_pfcp_validity_timer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* Octet 5 to 6    Validity Timer
    * The Validity Timer value shall be encoded as an Unsigned16 binary integer value. It contains a duration in seconds
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_validity_timer, tvb, offset, 2, ENC_BIG_ENDIAN, &value);
    offset += 2;

    proto_item_append_text(item, "%u s", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.185   Offending IE Information
 */
static void
dissect_pfcp_offending_ie_information(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;

    /* Octet 5 to 6 Type of the offending IE */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_offending_ie, tvb, offset, 2, ENC_BIG_ENDIAN, &value);
    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_ie_type, "Unknown"));
    offset += 2;

    /* Octets 7 to (n+4) shall contain the value of the offending IE that caused the failure */
    proto_tree_add_item(tree, hf_pfcp_offending_ie_value, tvb, offset, 4, ENC_BIG_ENDIAN);
}

/*
 * 8.2.186    RAT Type
 */
static const value_string pfcp_rattype_vals[] = {
    { 0, "Reserved" },
    { 1, "UTRAN" },
    { 2, "GERAN" },
    { 3, "WLAN" },
    { 4, "GAN" },
    { 5, "HSPA Evolution" },
    { 6, "EUTRAN (WB-E-UTRAN)" },
    { 7, "Virtual" },
    { 8, "EUTRAN-NB-IoT" },
    { 9, "LTE-M" },
    { 10, "NR" },
    { 0, NULL }
};

static void
dissect_pfcp_rattype(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;
    /* Octet 5  RAT Type  */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_rattype, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;

    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_rattype_vals, "Unknown"));

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.187    L2TP User Authentication
 */
static void
dissect_pfcp_l2tp_user_authentication(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 l2tp_user_authentication_flags;
    guint32 l2tp_length;

    static int * const pfcp_l2tp_user_authentication_flags[] = {
        &hf_pfcp_spare_b7_b4,
        &hf_pfcp_l2tp_user_authentication_b3_pai,
        &hf_pfcp_l2tp_user_authentication_b2_par,
        &hf_pfcp_l2tp_user_authentication_b1_pac,
        &hf_pfcp_l2tp_user_authentication_b0_pan,
        NULL
    };

    /* Octet 5-6 Proxy Authen Type Value */
    proto_tree_add_item(tree, hf_pfcp_l2tp_user_authentication_proxy_authen_type_value, tvb, offset, 2, ENC_ASCII | ENC_NA);
    offset += 2;

    /* Octet 7  Spare   PAI   PAR   PAC  PAN */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_l2tp_user_authentication_flags, ENC_BIG_ENDIAN, &l2tp_user_authentication_flags);
    offset += 1;

    /* Proxy Authen Name */
    if ((l2tp_user_authentication_flags & 0x1)) {
        proto_tree_add_item_ret_uint(tree, hf_pfcp_l2tp_user_authentication_proxy_authen_name_len, tvb, offset, 1, ENC_BIG_ENDIAN, &l2tp_length);
        offset += 1;
        proto_tree_add_item(tree, hf_pfcp_l2tp_user_authentication_proxy_authen_name, tvb, offset, l2tp_length, ENC_ASCII | ENC_NA);
        offset += l2tp_length;
    }

    /* Proxy Authen Challenge */
    if ((l2tp_user_authentication_flags & 0x2)) {
        proto_tree_add_item_ret_uint(tree, hf_pfcp_l2tp_user_authentication_proxy_authen_challenge_len, tvb, offset, 1, ENC_BIG_ENDIAN, &l2tp_length);
        offset += 1;
        proto_tree_add_item(tree, hf_pfcp_l2tp_user_authentication_proxy_authen_challenge, tvb, offset, l2tp_length, ENC_ASCII | ENC_NA);
        offset += l2tp_length;
    }

    /* Proxy Authen Response */
    if ((l2tp_user_authentication_flags & 0x4)) {
        proto_tree_add_item_ret_uint(tree, hf_pfcp_l2tp_user_authentication_proxy_authen_response_len, tvb, offset, 1, ENC_BIG_ENDIAN, &l2tp_length);
        offset += 1;
        proto_tree_add_item(tree, hf_pfcp_l2tp_user_authentication_proxy_authen_response, tvb, offset, l2tp_length, ENC_ASCII | ENC_NA);
        offset += l2tp_length;
    }

    /* Proxy Authen ID */
    if ((l2tp_user_authentication_flags & 0x8)) {
        proto_tree_add_item(tree, hf_pfcp_l2tp_user_authentication_proxy_authen_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.188   LNS Address
 */
static void
dissect_pfcp_lns_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* IPv4 address */
    if (length == 4) {
        proto_tree_add_item(tree, hf_pfcp_lns_address_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    /* IPv6 address */
    else if (length == 16) {
        proto_tree_add_item(tree, hf_pfcp_lns_address_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.189   Tunnel Preference
 */
static void
dissect_pfcp_tunnel_preference(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    proto_tree_add_item(tree, hf_pfcp_tunnel_preference_value, tvb, 0, length, ENC_BIG_ENDIAN);
}

/*
 * 8.2.190   Calling Number
 */
static void
dissect_pfcp_calling_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    proto_tree_add_item(tree, hf_pfcp_calling_number_value, tvb, 0, length, ENC_ASCII | ENC_NA);
}

/*
 * 8.2.191   Called Number
 */
static void
dissect_pfcp_called_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    proto_tree_add_item(tree, hf_pfcp_called_number_value, tvb, 0, length, ENC_ASCII | ENC_NA);
}

/*
 * 8.2.192   L2TP Session Indications
 */
static void
dissect_pfcp_l2tp_session_indications(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_l2tp_session_indications_o5_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_l2tp_session_indications_o5_b2_rensa,
        &hf_pfcp_l2tp_session_indications_o5_b1_redsa,
        &hf_pfcp_l2tp_session_indications_o5_b0_reuia,
        NULL
    };
    /* Octet 5  Spare   spare    Spare    Spare   Spare   RENSA   REDSA   REUIA */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_l2tp_session_indications_o5_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.193   DNS Server Address
 */
static void
dissect_pfcp_dns_sever_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* IPv4 address */
    proto_tree_add_item(tree, hf_pfcp_node_id_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s", tvb_ip_to_str(pinfo->pool, tvb, offset));
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.194   NBNS Server Address
 */
static void
dissect_pfcp_nbns_sever_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* IPv4 address */
    proto_tree_add_item(tree, hf_pfcp_node_id_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s", tvb_ip_to_str(pinfo->pool, tvb, offset));
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.195   Maximum Receive Unit
 */
static void
dissect_pfcp_maximum_receive_unit(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* Oct 5 to 6   Maximum Receive Unit */
    proto_tree_add_item(tree, hf_pfcp_maximum_receive_unit, tvb, 0, length, ENC_BIG_ENDIAN);
}

/*
 * 8.2.196   Thresholds
 */
static void
dissect_pfcp_thresholds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags;

    static int * const pfcp_thresholds_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_thresholds_flags_b1_plr,
        &hf_pfcp_thresholds_flags_b0_rtt,
        NULL
    };
    /* Octet 5  Spare   PLR   RTT */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_thresholds_flags, ENC_BIG_ENDIAN, &flags);
    offset += 1;

    /* RTT */
    if ((flags & 0x1)) {
        /* m to (m+1)   RTT  */
        proto_tree_add_item(tree, hf_pfcp_thresholds_rtt, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    /* PLR */
    if ((flags & 0x2)) {
        /* m to (m+1)   RTT  */
        proto_tree_add_item(tree, hf_pfcp_thresholds_plr, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, length);
    }
}

/*
 * 8.2.197   Steering Mode Indicator
 */
static void
dissect_pfcp_steering_mode_indications(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_l2tp_steering_mode_indications_o5_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_l2tp_steering_mode_indications_o5_b1_ueai,
        &hf_pfcp_l2tp_steering_mode_indications_o5_b0_albi,
        NULL
    };
    /* Octet 5  Spare   spare    Spare    Spare   Spare   Spare   UEAI   ALBI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_l2tp_steering_mode_indications_o5_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.198    Group ID
 */
static void
dissect_pfcp_group_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* Octet 5 to (n+4) Group ID */
    proto_tree_add_item(tree, hf_pfcp_group_id, tvb, 0, length, ENC_UTF_8);
}

/*
 * 8.2.199   CP IP Address
 */
static void
dissect_pfcp_cp_ip_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 cp_ip_address_flags;

    static int * const pfcp_cp_ip_address_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_b1_v4,
        &hf_pfcp_b0_v6,
        NULL
    };
    /* Octet 5  Spare   V4  V6 */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_cp_ip_address_flags, ENC_BIG_ENDIAN, &cp_ip_address_flags);
    offset += 1;

    /* IPv4 address (if present) */
    if (cp_ip_address_flags & 0x2) {
        proto_tree_add_item(tree, hf_pfcp_cp_ip_address_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, ", IPv4 %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
        offset += 4;
    }
    /* IPv6 address (if present) */
    if (cp_ip_address_flags & 0x1) {
        proto_tree_add_item(tree, hf_pfcp_cp_ip_address_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, ", IPv6 %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
        offset += 16;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.200   IP Address and Port Number Replacement
 */
static void
dissect_pfcp_ip_address_and_port_number_replacement(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 ip_address_and_port_number_replacement_flags;

    static int * const pfcp_ip_address_and_port_number_replacement_flags[] = {
        &hf_pfcp_spare_b7_b6,
        &hf_pfcp_ip_address_and_port_number_replacement_flag_b5_spn,
        &hf_pfcp_ip_address_and_port_number_replacement_flag_b4_sipv6,
        &hf_pfcp_ip_address_and_port_number_replacement_flag_b3_sipv4,
        &hf_pfcp_ip_address_and_port_number_replacement_flag_b2_dpn,
        &hf_pfcp_ip_address_and_port_number_replacement_flag_b1_v6,
        &hf_pfcp_ip_address_and_port_number_replacement_flag_b0_v4,
        NULL
    };
    /* Octet 5  Spare  SPN    SIPV6   SIPV4   DPN     V6      V4*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_ip_address_and_port_number_replacement_flags, ENC_BIG_ENDIAN, &ip_address_and_port_number_replacement_flags);
    offset += 1;

    /* Destination IPv4 address (if present)*/
    if ((ip_address_and_port_number_replacement_flags & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_ip_address_and_port_number_replacement_destination_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    /* Destination IPv6 address (if present)*/
    if ((ip_address_and_port_number_replacement_flags & 0x2)) {
        proto_tree_add_item(tree, hf_pfcp_ip_address_and_port_number_replacement_destination_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }
    /* Destination Port Number (if present)*/
    if ((ip_address_and_port_number_replacement_flags & 0x4)) {
        proto_tree_add_item(tree, hf_pfcp_ip_address_and_port_number_replacement_destination_port, tvb, offset, 2, ENC_NA);
        offset += 2;
    }
    /* Source IPv4 address (if present)*/
    if ((ip_address_and_port_number_replacement_flags & 0x8)) {
        proto_tree_add_item(tree, hf_pfcp_ip_address_and_port_number_replacement_source_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    /* Source IPv6 address (if present)*/
    if ((ip_address_and_port_number_replacement_flags & 0x10)) {
        proto_tree_add_item(tree, hf_pfcp_ip_address_and_port_number_replacement_source_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }
    /* Source Port Number (if present)*/
    if ((ip_address_and_port_number_replacement_flags & 0x20)) {
        proto_tree_add_item(tree, hf_pfcp_ip_address_and_port_number_replacement_source_port, tvb, offset, 2, ENC_NA);
        offset += 2;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.201    DNS Query Filter
 */
static void
dissect_pfcp_dns_query_filter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 dns_query_length;

    proto_tree_add_item_ret_uint(tree, hf_pfcp_dns_query_filter_pattern_len, tvb, offset, 2, ENC_BIG_ENDIAN, &dns_query_length);
    offset += 2;
    proto_tree_add_item(tree, hf_pfcp_dns_query_filter_pattern, tvb, offset, dns_query_length, ENC_ASCII | ENC_NA);
    offset += dns_query_length;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.202    Event Notification URI
 */
static void
dissect_pfcp_event_notification_uri(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    proto_tree_add_item(tree, hf_pfcp_event_notification_uri, tvb, 0, length, ENC_ASCII | ENC_NA);
}


/*
 * 8.2.203   Notification Correlation ID
 */
static void
dissect_pfcp_notification_correlation_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    guint32 value;
    /* 5 to n+4   Notification Correlation ID value */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_notification_correlation_id, tvb, 0, 4, ENC_BIG_ENDIAN, &value);
    proto_item_append_text(item, "%u", value);
}

/*
 * 8.2.204   Reporting Flags
 */
static void
dissect_pfcp_reporting_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_reporting_flags_o5_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_reporting_flags_o5_b0_dupl,
        NULL
    };
    /* Octet 5 Spare   DUPL */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_reporting_flags_o5_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset == length) {
        return;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.205   Predefined Rules Name
 */
static void
dissect_pfcp_predefined_rules_name(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    /* Octet 5 to (n+4) Predefined Rules Name
    * The Predefined Rules Name field shall be encoded as an OctetString
    */
    proto_tree_add_item(tree, hf_pfcp_predef_rules_name, tvb, offset, length, ENC_NA);
}

/*
 * 8.2.206   MBS Session Identifier
 */
static void
dissect_pfcp_mbs_session_identifier(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 mbs_session_identifier_flags;

    static int * const pfcp_mbs_session_identifier_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_mbs_session_identifier_flag_b2_nidi,
        &hf_pfcp_mbs_session_identifier_flag_b1_ssmi,
        &hf_pfcp_mbs_session_identifier_flag_b0_tmgi,
        NULL
    };
    /* Octet 5  Spare   NIDI     SMI      TMGI */
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_mbs_session_identifier_flags, ENC_BIG_ENDIAN, &mbs_session_identifier_flags);
    offset += 1;

    /* TMGI (if present)*/
    if ((mbs_session_identifier_flags & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_mbs_session_identifier_tmgi, tvb, offset, 6, ENC_NA);
        offset += 6;
    }
    /* SSMI (if present)*/
    if ((mbs_session_identifier_flags & 0x2)) {
        guint32 source_address_type;
        guint32 source_address_length;

        /* Source Address Type && Length */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_mbs_session_identifier_source_address_type, tvb, offset, 1, ENC_BIG_ENDIAN, &source_address_type);
        proto_tree_add_item_ret_uint(tree, hf_pfcp_mbs_session_identifier_source_address_length, tvb, offset, 1, ENC_BIG_ENDIAN, &source_address_length);
        offset++;

        /* Source IPv4 address (if present) */
        if (source_address_type == 0) {
            proto_tree_add_item(tree, hf_pfcp_mbs_session_identifier_source_address_ipv4, tvb, offset, source_address_length, ENC_BIG_ENDIAN);
            offset += source_address_length;
        }
        /* Source IPv6 address (if present) */
        if (source_address_type == 1) {
            proto_tree_add_item(tree, hf_pfcp_mbs_session_identifier_source_address_ipv6, tvb, offset, source_address_length, ENC_NA);
            offset += source_address_length;
        }
    }
    /* NIDI (if present)*/
    if ((mbs_session_identifier_flags & 0x4)) {
        proto_tree_add_item(tree, hf_pfcp_mbs_session_identifier_nidi, tvb, offset, 5, ENC_NA);
        offset += 5;
        return;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.207   Multicast Transport Information
 */
static void
dissect_pfcp_multicast_transport_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 distribution_address_type;
    guint32 distribution_address_length;
    guint32 source_address_type;
    guint32 source_address_length;

    /* Oct 5 Spare */
    proto_tree_add_item(tree, hf_pfcp_spare_oct, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Oct 6 to 9 Common Tunnel Endpoint Identifer */
    proto_tree_add_item(tree, hf_pfcp_multicast_transport_information_endpoint_identifier, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Oct 10 Distribution Address Type && Length */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_multicast_transport_information_distribution_address_type, tvb, offset, 1, ENC_BIG_ENDIAN, &distribution_address_type);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_multicast_transport_information_distribution_address_length, tvb, offset, 1, ENC_BIG_ENDIAN, &distribution_address_length);
    offset++;

    /* Distribution IPv4 address (if present) */
    if (distribution_address_type == 0) {
        proto_tree_add_item(tree, hf_pfcp_multicast_transport_information_distribution_address_ipv4, tvb, offset, distribution_address_length, ENC_BIG_ENDIAN);
        offset += distribution_address_length;
    }
    /* Distribution IPv6 address (if present) */
    if (distribution_address_type == 1) {
        proto_tree_add_item(tree, hf_pfcp_multicast_transport_information_distribution_address_ipv6, tvb, offset, distribution_address_length, ENC_NA);
        offset += distribution_address_length;
    }

    /* Source Address Type && Length */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_multicast_transport_information_source_address_type, tvb, offset, 1, ENC_BIG_ENDIAN, &source_address_type);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_multicast_transport_information_source_address_length, tvb, offset, 1, ENC_BIG_ENDIAN, &source_address_length);
    offset++;

    /* Source IPv4 address (if present) */
    if (source_address_type == 0) {
        proto_tree_add_item(tree, hf_pfcp_multicast_transport_information_source_address_ipv4, tvb, offset, source_address_length, ENC_BIG_ENDIAN);
        offset += source_address_length;
    }
    /* Source IPv6 address (if present) */
    if (source_address_type == 1) {
        proto_tree_add_item(tree, hf_pfcp_multicast_transport_information_source_address_ipv6, tvb, offset, source_address_length, ENC_NA);
        offset += source_address_length;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.208   MBSN4mbReq-Flags
 */
static void
dissect_pfcp_mbsn4mbreq_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_mbsn4mbreq_flags_o5_flags[] = {
        &hf_pfcp_spare_b7_b2,
        &hf_pfcp_mbsn4mbreq_flags_o5_b2_mbs_resti,
        &hf_pfcp_mbsn4mbreq_flags_o5_b1_jmbssm,
        &hf_pfcp_mbsn4mbreq_flags_o5_b0_pllssm,
        NULL
    };
    /* Octet 5 Spare    MBS RESTI   JMBSSM   PLLSSM */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_mbsn4mbreq_flags_o5_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset == length) {
        return;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.209    Local Ingress Tunnel
 */
static void
dissect_pfcp_local_ingress_tunnel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 local_ingress_tunnel_flags_val;

    static int * const pfcp_local_ingress_tunnel_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_local_ingress_tunnel_flags_b2_ch,
        &hf_pfcp_local_ingress_tunnel_flags_b1_v6,
        &hf_pfcp_local_ingress_tunnel_flags_b0_v4,
        NULL
    };
    /* Octet 5  Spare  CH  V6  V4*/
    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, pfcp_local_ingress_tunnel_flags, ENC_BIG_ENDIAN, &local_ingress_tunnel_flags_val);
    offset += 1;

    /* Bit 3 – CH (CHOOSE): If this bit is set to "1", then the UDP Port, IPv4 address and IPv6 address fields shall not be present */
    if ((local_ingress_tunnel_flags_val & 0x4) != 4) {
        /* UDP PPort */
        proto_tree_add_item(tree, hf_pfcp_local_ingress_tunnel_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if ((local_ingress_tunnel_flags_val & 0x1) == 1) {
            /* IPv4 address */
            proto_tree_add_item(tree, hf_pfcp_local_ingress_tunnel_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        if ((local_ingress_tunnel_flags_val & 0x2) == 2) {
            /* IPv6 address */
            proto_tree_add_item(tree, hf_pfcp_local_ingress_tunnel_ipv6, tvb, offset, 16, ENC_NA);
            offset += 16;
        }
    }
    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.210   MBS Unicast Parameters ID
 */
static void
dissect_pfcp_mbs_unicast_parameters_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    guint32 value;
    /* Octet 5 to 6 MBS Unicast Parameters ID */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_mbs_unicast_parameters_id, tvb, 0, 2, ENC_BIG_ENDIAN, &value);
    proto_item_append_text(item, "%u", value);
}

/*
 * 8.2.211   MBSN4Resp-Flags
 */
static void
dissect_pfcp_mbsn4resp_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_mbsn4resp_flags_o5_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_mbsn4resp_flags_o5_b2_n19dtr,
        &hf_pfcp_mbsn4resp_flags_o5_b1_jmti,
        &hf_pfcp_mbsn4resp_flags_o5_b0_nn19dt,
        NULL
    };
    /* Octet 5  Spare   spare    Spare    Spare   Spare   N19DTR   JMTI   NN19DT */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_mbsn4resp_flags_o5_flags, ENC_BIG_ENDIAN);
    offset++;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.212   Tunnel Password
 */
static void
dissect_pfcp_tunnel_password(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{;
    /* Octet 5 to (n+4) Tunnel Password value */
    proto_tree_add_item(tree, hf_pfcp_tunnel_password_value, tvb, 0, -1, ENC_UTF_8 | ENC_NA);
}

/*
 * 8.2.213   Area Session ID
 */
static void
dissect_pfcp_area_session_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{;
    guint32 value;
    /* Octet 5 to (n+4) Tunnel Password value */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_area_session_id_value, tvb, 0, 2, ENC_UTF_8 | ENC_NA, &value);
    proto_item_append_text(item, "%u", value);
}

/*
 * 8.2.214   DSCP to PPI Mapping Information
 */
static void
dissect_pfcp_dscp_to_ppi_mapping_information(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    int dscp_values = 0;

    /* Octet 5  Paging Policy Indicator (PPI)
    * The PPI shall be encoded as a value between 0 and 7, as specified in clause 5.5.3.7 of 3GPP TS 38.415
    */
    proto_tree_add_item(tree, hf_pfcp_dscp_to_ppi_mapping_info_ppi_value, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    while (offset < length) {
        proto_tree_add_item(tree, hf_pfcp_dscp_to_ppi_mapping_info_dscp_value, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        dscp_values++;

        /* no more than 63 DSCP values */
        if(dscp_values >= 63) {
            break;
        }
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.215   PFCPSDRsp-Flags
 */
static void
dissect_pfcp_pfcpsdrsp_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_pfcpsdrsp_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_pfcpsdrsp_flags_b0_puru,
        NULL
    };
    /* Octet 5  Spare   PURU */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_pfcpsdrsp_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.216   QER Indications
 */
static void
dissect_pfcp_qer_indications(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_qer_indications_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_qer_indications_flags_b0_iqfis,
        NULL
    };
    /* Octet 5  Spare   PURU */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_qer_indications_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.217   Vendor-Specific Node Report Type
 */
static void
dissect_pfcp_vendor_specific_node_report_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    /* Octet 5 to 6  Enterprise ID   */
    proto_tree_add_item(tree, hf_pfcp_enterprise_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    static int * const pfcp_vendor_specific_node_report_type_flags[] = {
        &hf_pfcp_spare_b7,
        &hf_pfcp_spare_b6,
        &hf_pfcp_spare_b5,
        &hf_pfcp_spare_b4,
        &hf_pfcp_spare_b3,
        &hf_pfcp_spare_b2,
        &hf_pfcp_spare_b1,
        &hf_pfcp_spare_b0,
        NULL
    };
    /* Octet 5  Spare   */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_vendor_specific_node_report_type_flags, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}


/* Array of functions to dissect IEs
* (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
*/
typedef struct _pfcp_ie {
    void(*decode) (tvbuff_t *, packet_info *, proto_tree *, proto_item *, guint16, guint8, pfcp_session_args_t *);
} pfcp_ie_t;

static const pfcp_ie_t pfcp_ies[] = {
/*      0 */    { dissect_pfcp_reserved },
/*      1 */    { dissect_pfcp_create_pdr },                                    /* Create PDR                                       Extendable / Table 7.5.2.2-1 */
/*      2 */    { dissect_pfcp_pdi },                                           /* PDI                                              Extendable / Table 7.5.2.2-2 */
/*      3 */    { dissect_pfcp_create_far },                                    /* Create FAR                                       Extendable / Table 7.5.2.3-1 */
/*      4 */    { dissect_pfcp_forwarding_parameters },                         /* Forwarding Parameters                            Extendable / Table 7.5.2.3-2 */
/*      5 */    { dissect_pfcp_duplicating_parameters },                        /* Duplicating Parameters                           Extendable / Table 7.5.2.3-3 */
/*      6 */    { dissect_pfcp_create_urr },                                    /* Create URR                                       Extendable / Table 7.5.2.4-1 */
/*      7 */    { dissect_pfcp_create_qer },                                    /* Create QER                                       Extendable / Table 7.5.2.5-1 */
/*      8 */    { dissect_pfcp_created_pdr },                                   /* Created PDR                                      Extendable / Table 7.5.3.2-1 */
/*      9 */    { dissect_pfcp_update_pdr },                                    /* Update PDR                                       Extendable / Table 7.5.4.2-1 */
/*     10 */    { dissect_pfcp_update_far },                                    /* Update FAR                                       Extendable / Table 7.5.4.3-1 */
/*     11 */    { dissect_pfcp_upd_forwarding_param },                          /* Update Forwarding Parameters                     Extendable / Table 7.5.4.3-2 */
/*     12 */    { dissect_pfcp_update_bar },                                    /* Update BAR (PFCP Session Report Response)        Extendable / Table 7.5.9.2-1 */
/*     13 */    { dissect_pfcp_update_urr },                                    /* Update URR                                       Extendable / Table 7.5.4.4 */
/*     14 */    { dissect_pfcp_update_qer },                                    /* Update QER                                       Extendable / Table 7.5.4.5 */
/*     15 */    { dissect_pfcp_remove_pdr },                                    /* Remove PDR                                       Extendable / Table 7.5.4.6 */
/*     16 */    { dissect_pfcp_remove_far },                                    /* Remove FAR                                       Extendable / Table 7.5.4.7 */
/*     17 */    { dissect_pfcp_remove_urr },                                    /* Remove URR                                       Extendable / Table 7.5.4.8 */
/*     18 */    { dissect_pfcp_remove_qer },                                    /* Remove QER                                       Extendable / Table 7.5.4.9 */
/*     19 */    { dissect_pfcp_cause },                                         /* Cause                                            Fixed / Subclause 8.2.1 */
/*     20 */    { dissect_pfcp_source_interface },                              /* Source Interface                                 Extendable / Subclause 8.2.2 */
/*     21 */    { dissect_pfcp_f_teid },                                        /* F-TEID                                           Extendable / Subclause 8.2.3 */
/*     22 */    { dissect_pfcp_network_instance },                              /* Network Instance                                 Variable Length / Subclause 8.2.4 */
/*     23 */    { dissect_pfcp_sdf_filter },                                    /* SDF Filter                                       Extendable / Subclause 8.2.5 */
/*     24 */    { dissect_pfcp_application_id },                                /* Application ID                                   Variable Length / Subclause 8.2.6 */
/*     25 */    { dissect_pfcp_gate_status },                                   /* Gate Status                                     Extendable / Subclause 8.2.7 */
/*     26 */    { dissect_pfcp_mbr },                                           /* MBR                                             Extendable / Subclause 8.2.8 */
/*     27 */    { dissect_pfcp_gbr },                                           /* GBR                                             Extendable / Subclause 8.2.9 */
/*     28 */    { dissect_pfcp_qer_correlation_id },                            /* QER Correlation ID                              Extendable / Subclause 8.2.10 */
/*     29 */    { dissect_pfcp_precedence },                                    /* Precedence                                      Extendable / Subclause 8.2.11 */
/*     30 */    { dissect_pfcp_transport_level_marking },                       /* Transport Level Marking                         Extendable / Subclause 8.2.12 */
/*     31 */    { dissect_pfcp_volume_threshold },                              /* Volume Threshold                                Extendable /Subclause 8.2.13 */
/*     32 */    { dissect_pfcp_time_threshold },                                /* Time Threshold                                  Extendable /Subclause 8.2.14 */
/*     33 */    { dissect_pfcp_monitoring_time },                               /* Monitoring Time                                 Extendable /Subclause 8.2.15 */
/*     34 */    { dissect_pfcp_subseq_volume_threshold },                       /* Subsequent Volume Threshold                     Extendable /Subclause 8.2.16 */
/*     35 */    { dissect_pfcp_subsequent_time_threshold },                     /* Subsequent Time Threshold                       Extendable /Subclause 8.2.17 */
/*     36 */    { dissect_pfcp_inactivity_detection_time },                     /* Inactivity Detection Time                       Extendable /Subclause 8.2.18 */
/*     37 */    { dissect_pfcp_reporting_triggers },                            /* Reporting Triggers                              Extendable /Subclause 8.2.19 */
/*     38 */    { dissect_pfcp_redirect_information },                          /* Redirect Information                            Extendable /Subclause 8.2.20 */
/*     39 */    { dissect_pfcp_report_type },                                   /* Report Type                                     Extendable / Subclause 8.2.21 */
/*     40 */    { dissect_pfcp_offending_ie },                                  /* Offending IE                                    Fixed / Subclause 8.2.22 */
/*     41 */    { dissect_pfcp_forwarding_policy },                             /* Forwarding Policy                               Extendable / Subclause 8.2.23 */
/*     42 */    { dissect_pfcp_destination_interface },                         /* Destination Interface                           Extendable / Subclause 8.2.24 */
/*     43 */    { dissect_pfcp_up_function_features },                          /* UP Function Features                            Extendable / Subclause 8.2.25 */
/*     44 */    { dissect_pfcp_apply_action },                                  /* Apply Action                                    Extendable / Subclause 8.2.26 */
/*     45 */    { dissect_pfcp_dl_data_service_inf },                           /* Downlink Data Service Information               Extendable / Subclause 8.2.27 */
/*     46 */    { dissect_pfcp_dl_data_notification_delay },                    /* Downlink Data Notification Delay                Extendable / Subclause 8.2.28 */
/*     47 */    { dissect_pfcp_dl_buffering_dur },                              /* DL Buffering Duration                           Extendable / Subclause 8.2.29 */
/*     48 */    { dissect_pfcp_dl_buffering_suggested_packet_count },           /* DL Buffering Suggested Packet Count             Variable / Subclause 8.2.30 */
/*     49 */    { dissect_pfcp_pfcpsmreq_flags },                               /* PFCPSMReq-Flags                                 Extendable / Subclause 8.2.31 */
/*     50 */    { dissect_pfcp_pfcpsrrsp_flags },                               /* PFCPSRRsp-Flags                                 Extendable / Subclause 8.2.32 */
/*     51 */    { dissect_pfcp_load_control_information },                      /* Load Control Information                        Extendable / Table 7.5.3.3-1 */
/*     52 */    { dissect_pfcp_sequence_number },                               /* Sequence Number                                 Fixed Length / Subclause 8.2.33 */
/*     53 */    { dissect_pfcp_metric },                                        /* Metric                                          Fixed Length / Subclause 8.2.34 */
/*     54 */    { dissect_pfcp_overload_control_information },                  /* Overload Control Information                    Extendable / Table 7.5.3.4-1 */
/*     55 */    { dissect_pfcp_timer },                                         /* Timer                                           Extendable / Subclause 8.2 35 */
/*     56 */    { dissect_pfcp_pdr_id },                                        /* PDR ID                                          Extendable / Subclause 8.2 36 */
/*     57 */    { dissect_pfcp_f_seid },                                        /* F-SEID                                          Extendable / Subclause 8.2 37 */
/*     58 */    { dissect_pfcp_application_ids_pfds },                          /* Application ID's PFDs                           Extendable / Table 7.4.3.1-2 */
/*     59 */    { dissect_pfcp_pfd_context },                                   /* PFD context                                     Extendable / Table 7.4.3.1-3 */
/*     60 */    { dissect_pfcp_node_id },                                       /* Node ID                                         Extendable / Subclause 8.2.38 */
/*     61 */    { dissect_pfcp_pfd_contents },                                  /* PFD contents                                    Extendable / Subclause 8.2.39 */
/*     62 */    { dissect_pfcp_measurement_method },                            /* Measurement Method                              Extendable / Subclause 8.2.40 */
/*     63 */    { dissect_pfcp_usage_report_trigger },                          /* Usage Report Trigger                            Extendable / Subclause 8.2.41 */
/*     64 */    { dissect_pfcp_measurement_period },                            /* Measurement Period                              Extendable / Subclause 8.2.42 */
/*     65 */    { dissect_pfcp_fq_csid },                                       /* FQ-CSID                                         Extendable / Subclause 8.2.43 */
/*     66 */    { dissect_pfcp_volume_measurement },                            /* Volume Measurement                              Extendable / Subclause 8.2.44 */
/*     67 */    { dissect_pfcp_duration_measurement },                          /* Duration Measurement                            Extendable / Subclause 8.2.45 */
/*     68 */    { dissect_pfcp_application_detection_inf },                     /* Application Detection Information               Extendable / Table 7.5.8.3-2 */
/*     69 */    { dissect_pfcp_time_of_first_packet },                          /* Time of First Packet                            Extendable / Subclause 8.2.46 */
/*     70 */    { dissect_pfcp_time_of_last_packet },                           /* Time of Last Packet                             Extendable / Subclause 8.2.47 */
/*     71 */    { dissect_pfcp_quota_holding_time },                            /* Quota Holding Time                              Extendable / Subclause 8.2.48 */
/*     72 */    { dissect_pfcp_dropped_dl_traffic_threshold },                  /* Dropped DL Traffic Threshold                    Extendable / Subclause 8.2.49 */
/*     73 */    { dissect_pfcp_volume_quota },                                  /* Volume Quota                                    Extendable / Subclause 8.2.50 */
/*     74 */    { dissect_pfcp_time_quota },                                    /* Time Quota                                      Extendable / Subclause 8.2.51 */
/*     75 */    { dissect_pfcp_start_time },                                    /* Start Time                                      Extendable / Subclause 8.2.52 */
/*     76 */    { dissect_pfcp_end_time },                                      /* End Time                                        Extendable / Subclause 8.2.53 */
/*     77 */    { dissect_pfcp_pfcp_query_urr },                                /* Query URR                                       Extendable / Table 7.5.4.10-1 */
/*     78 */    { dissect_pfcp_usage_report_smr },                              /* Usage Report (Session Modification Response) Extendable / Table 7.5.5.2-1 */
/*     79 */    { dissect_pfcp_usage_report_sdr },                              /* Usage Report (Session Deletion Response)        Extendable / Table 7.5.7.2-1 */
/*     80 */    { dissect_pfcp_usage_report_srr },                              /* Usage Report (Session Report Request)           Extendable / Table 7.5.8.3-1 */
/*     81 */    { dissect_pfcp_urr_id },                                        /* URR ID                                          Extendable / Subclause 8.2.54 */
/*     82 */    { dissect_pfcp_linked_urr_id },                                 /* Linked URR ID                                   Extendable / Subclause 8.2.55 */
/*     83 */    { dissect_pfcp_downlink_data_report },                          /* Downlink Data Report                            Extendable / Table 7.5.8.2-1 */
/*     84 */    { dissect_pfcp_outer_header_creation },                         /* Outer Header Creation                           Extendable / Subclause 8.2.56 */
/*     85 */    { dissect_pfcp_create_bar },                                    /* Create BAR                                      Extendable / Table 7.5.2.6-1 */
/*     86 */    { dissect_pfcp_update_bar_smr },                                /* Update BAR (Session Modification Request)       Extendable / Table 7.5.4.11-1 */
/*     87 */    { dissect_pfcp_remove_bar },                                    /* Remove BAR                                      Extendable / Table 7.5.4.12-1 */
/*     88 */    { dissect_pfcp_bar_id },                                        /* BAR ID                                          Extendable / Subclause 8.2.57 */
/*     89 */    { dissect_pfcp_cp_function_features },                          /* CP Function Features                            Extendable / Subclause 8.2.58 */
/*     90 */    { dissect_pfcp_usage_information },                             /* Usage Information                               Extendable / Subclause 8.2.59 */
/*     91 */    { dissect_pfcp_application_instance_id },                       /* Application Instance ID                         Variable Length / Subclause 8.2.60 */
/*     92 */    { dissect_pfcp_flow_inf },                                      /* Flow Information                                Extendable / Subclause 8.2.61 */
/*     93 */    { dissect_pfcp_ue_ip_address },                                 /* UE IP Address                                   Extendable / Subclause 8.2.62 */
/*     94 */    { dissect_pfcp_packet_rate },                                   /* Packet Rate                                     Extendable / Subclause 8.2.63 */
/*     95 */    { dissect_pfcp_outer_hdr_rem },                                 /* Outer Header Removal                            Extendable / Subclause 8.2.64 */
/*     96 */    { dissect_pfcp_recovery_time_stamp },                           /* Recovery Time Stamp                             Extendable / Subclause 8.2.65 */
/*     97 */    { dissect_pfcp_dl_flow_level_marking },                         /* DL Flow Level Marking                           Extendable / Subclause 8.2.66 */
/*     98 */    { dissect_pfcp_header_enrichment },                             /* Header Enrichment                               Extendable / Subclause 8.2.67 */
/*     99 */    { dissect_pfcp_error_indication_report },                       /* Error Indication Report                         Extendable / Table 7.5.8.4-1 */
/*    100 */    { dissect_pfcp_measurement_info },                              /* Measurement Information                         Extendable / Subclause 8.2.68 */
/*    101 */    { dissect_pfcp_node_report_type },                              /* Node Report Type                                Extendable / Subclause 8.2.69 */
/*    102 */    { dissect_pfcp_user_plane_path_failure_report },                /* User Plane Path Failure Report                  Extendable / Table 7.4.5.1.2-1 */
/*    103 */    { dissect_pfcp_remote_gtp_u_peer },                             /* Remote GTP-U Peer                               Extendable / Subclause 8.2.70 */
/*    104 */    { dissect_pfcp_ur_seqn },                                       /* UR-SEQN                                         Fixed Length / Subclause 8.2.71 */
/*    105 */    { dissect_pfcp_update_duplicating_parameters },                 /* Update Duplicating Parameters                   Extendable / Table 7.5.4.3-3 */
/*    106 */    { dissect_pfcp_act_predef_rules },                              /* Activate Predefined Rules                       Variable Length / Subclause 8.2.72 */
/*    107 */    { dissect_pfcp_deact_predef_rules },                            /* Deactivate Predefined Rules                     Variable Length / Subclause 8.2.73 */
/*    108 */    { dissect_pfcp_far_id },                                        /* FAR ID                                          Extendable / Subclause 8.2.74 */
/*    109 */    { dissect_pfcp_qer_id },                                        /* QER ID                                          Extendable / Subclause 8.2.75 */
/*    110 */    { dissect_pfcp_oci_flags },                                     /* OCI Flags                                       Extendable / Subclause 8.2.76 */
/*    111 */    { dissect_pfcp_pfcp_assoc_rel_req },                            /* PFCP Association Release Request                Extendable / Subclause 8.2.77 */
/*    112 */    { dissect_pfcp_graceful_release_period },                       /* Graceful Release Period                         Extendable / Subclause 8.2.78 */
/*    113 */    { dissect_pfcp_pdn_type },                                      /* PDN Type                                        Fixed Length / Subclause 8.2.79 */
/*    114 */    { dissect_pfcp_failed_rule_id },                                /* Failed Rule ID                                  Extendable / Subclause 8.2.80 */
/*    115 */    { dissect_pfcp_time_quota_mechanism },                          /* Time Quota Mechanism                            Extendable / Subclause 8.2.81 */
/*    116 */    { dissect_pfcp_user_plane_ip_resource_infomation },             /* User Plane IP Resource Information              Extendable / Subclause 8.2.82 */
/*    117 */    { dissect_pfcp_user_plane_inactivity_timer },                   /* User Plane Inactivity Timer                     Extendable / Subclause 8.2.83 */
/*    118 */    { dissect_pfcp_aggregated_urrs },                               /* Aggregated URRs                                 Extendable / Table 7.5.2.4-2 */
/*    119 */    { dissect_pfcp_multiplier },                                    /* Multiplier                                      Fixed Length / Subclause 8.2.84 */
/*    120 */    { dissect_pfcp_aggregated_urr_id_ie },                          /* Aggregated URR ID IE                            Fixed Length / Subclause 8.2.85 */
/*    121 */    { dissect_pfcp_subsequent_volume_quota },                       /* Subsequent Volume Quota                         Extendable / Subclause 8.2.86 */
/*    122 */    { dissect_pfcp_subsequent_time_quota },                         /* Subsequent Time Quota                           Extendable / Subclause 8.2.87 */
/*    123 */    { dissect_pfcp_rqi },                                           /* RQI                                             Extendable / Subclause 8.2.88 */
/*    124 */    { dissect_pfcp_qfi },                                           /* QFI                                             Extendable / Subclause 8.2.89 */
/*    125 */    { dissect_pfcp_query_urr_reference },                           /* Query URR Reference                             Extendable / Subclause 8.2.90 */
/*    126 */    { dissect_pfcp_additional_usage_reports_information },          /* Additional Usage Reports Information            Extendable /  Subclause 8.2.91 */
/*    127 */    { dissect_pfcp_create_traffic_endpoint },                       /* Create Traffic Endpoint                         Extendable / Table 7.5.2.7 */
/*    128 */    { dissect_pfcp_created_traffic_endpoint },                      /* Created Traffic Endpoint                        Extendable / Table 7.5.3.5 */
/*    129 */    { dissect_pfcp_update_traffic_endpoint },                       /* Update Traffic Endpoint                         Extendable / Table 7.5.4.13 */
/*    130 */    { dissect_pfcp_remove_traffic_endpoint },                       /* Remove Traffic Endpoint                         Extendable / Table 7.5.4.14 */
/*    131 */    { dissect_pfcp_traffic_endpoint_id },                           /* Traffic Endpoint ID                             Extendable / Subclause 8.2.92 */
/*    132 */    { dissect_pfcp_ethernet_packet_filter },                        /* Ethernet Packet Filter IE                       Extendable / Table 7.5.2.2-3 */
/*    133 */    { dissect_pfcp_mac_address },                                   /* MAC address                                     Extendable / Subclause 8.2.93 */
/*    134 */    { dissect_pfcp_c_tag },                                         /* C-TAG                                           Extendable / Subclause 8.2.94 */
/*    135 */    { dissect_pfcp_s_tag },                                         /* S-TAG                                           Extendable / Subclause 8.2.95 */
/*    136 */    { dissect_pfcp_ethertype },                                     /* Ethertype                                       Extendable / Subclause 8.2.96 */
/*    137 */    { dissect_pfcp_proxying },                                      /* Proxying                                        Extendable / Subclause 8.2.97 */
/*    138 */    { dissect_pfcp_ethertype_filter_id },                           /* Ethernet Filter ID                              Extendable / Subclause 8.2.98 */
/*    139 */    { dissect_pfcp_ethernet_filter_properties },                    /* Ethernet Filter Properties                      Extendable / Subclause 8.2.99  */
/*    140 */    { dissect_pfcp_suggested_buffering_packets_count },             /* Suggested Buffering Packets Count               Extendable / Subclause 8.2.100  */
/*    141 */    { dissect_pfcp_user_id },                                       /* User ID                                         Extendable / Subclause 8.2.101  */
/*    142 */    { dissect_pfcp_ethernet_pdu_session_information },              /* Ethernet PDU Session Information                Extendable / Subclause 8.2.102  */
/*    143 */    { dissect_pfcp_ethernet_traffic_information },                  /* Ethernet Traffic Information                    Extendable / Table 7.5.8.3-3  */
/*    144 */    { dissect_pfcp_mac_addresses_detected },                        /* MAC Addresses Detected                          Extendable / Subclause 8.2.103  */
/*    145 */    { dissect_pfcp_mac_addresses_removed },                         /* MAC Addresses Removed                           Extendable / Subclause 8.2.104  */
/*    146 */    { dissect_pfcp_ethernet_inactivity_timer },                     /* Ethernet Inactivity Timer                       Extendable / Subclause 8.2.105  */
/*    147 */    { dissect_pfcp_additional_monitoring_time },                    /* Additional Monitoring Time                      Extendable / Table 7.5.2.4-3  */
/*    148 */    { dissect_pfcp_event_quota },                                   /* Event Quota                                     Extendable / Subclause 8.2.112  */
/*    149 */    { dissect_pfcp_event_threshold },                               /* Event Threshold                                 Extendable / Subclause 8.2.113  */
/*    150 */    { dissect_pfcp_subsequent_event_quota },                        /* Subsequent Event Quota                          Extendable / Subclause 8.2.106  */
/*    151 */    { dissect_pfcp_subsequent_event_threshold },                    /* Subsequent Event Threshold                      Extendable / Subclause 8.2.107  */
/*    152 */    { dissect_pfcp_trace_information },                             /* Trace Information                               Extendable / Subclause 8.2.108  */
/*    153 */    { dissect_pfcp_framed_route },                                  /* Framed-Route                                    Variable Length / Subclause 8.2.109  */
/*    154 */    { dissect_pfcp_framed_routing },                                /* Framed-Routing                                  Fixed Length / Subclause 8.2.110  */
/*    155 */    { dissect_pfcp_framed_ipv6_route },                             /* Framed-IPv6-Route                               Variable Length / Subclause 8.2.111  */
/*    156 */    { dissect_pfcp_time_stamp },                                    /* Time Stamp                                      Extendable / Subclause 8.2.114  */
/*    157 */    { dissect_pfcp_averaging_window },                              /* Averaging Window                                Extendable / Subclause 8.2.115  */
/*    158 */    { dissect_pfcp_paging_policy_indicator },                       /* Paging Policy Indicator                         Extendable / Subclause 8.2.116  */
/*    159 */    { dissect_pfcp_apn_dnn },                                       /* APN/DNN                                         Variable Length / Subclause 8.2.117  */
/*    160 */    { dissect_pfcp_tgpp_interface_type },                           /* 3GPP Interface Type                             Extendable / Subclause 8.2.118  */
/*    161 */    { dissect_pfcp_pfcpsrreq_flags },                               /* PFCPSRReq-Flags                                 Extendable / Subclause 8.2.119  */
/*    162 */    { dissect_pfcp_pfcpaureq_flags },                               /* PFCPAUReq-Flags                                 Extendable / Subclause 8.2.120  */
/*    163 */    { dissect_pfcp_activation_time },                               /* Activation Time                                 Extendable / Subclause 8.2.121  */
/*    164 */    { dissect_pfcp_deactivation_time },                             /* Deactivation Time                               Extendable / Subclause 8.2.122  */
/*    165 */    { dissect_pfcp_create_mar },                                    /* Create MAR                                      Extendable / Table 7.5.2.8-1  */
/*    166 */    { dissect_pfcp_access_forwarding_action_information_1 },        /* Access Forwarding Action Information 1          Extendable / Table 7.5.2.8-2  */
/*    167 */    { dissect_pfcp_access_forwarding_action_information_2 },        /* Access Forwarding Action Information 2          Extendable / Table 7.5.2.8-3  */
/*    168 */    { dissect_pfcp_remove_mar },                                    /* Remove MAR                                      Extendable / Table 7.5.4.15-1*/
/*    169 */    { dissect_pfcp_update_mar },                                    /* Update MAR                                      Extendable / Table 7.5.4.16-1 */
/*    170 */    { dissect_pfcp_mar_id },                                        /* MAR ID                                          Extendable / Subclause 8.2.123  */
/*    171 */    { dissect_pfcp_steering_functionality },                        /* Steering Functionality                          Extendable / Subclause 8.2.124  */
/*    172 */    { dissect_pfcp_steering_mode },                                 /* Steering Mode                                   Extendable / Subclause 8.2.125  */
/*    173 */    { dissect_pfcp_weight },                                        /* Weight                                          Fixed / Clause 8.2.126  */
/*    174 */    { dissect_pfcp_priority },                                      /* Priority                                        Extendable / Subclause 8.2.127  */
/*    175 */    { dissect_pfcp_update_access_forwarding_action_information_1 }, /* Update Access Forwarding Action Information 1   Extendable / Table 7.5.4.16-2  */
/*    176 */    { dissect_pfcp_update_access_forwarding_action_information_2 }, /* Update Access Forwarding Action Information 2   Extendable / Table 7.5.4.16-3  */
/*    177 */    { dissect_pfcp_ue_ip_address_pool_identity },                   /* UE IP address Pool Identity                     Variable Length / Clause 8.2.128  */
/*    178 */    { dissect_pfcp_alternative_smf_ip_address },                    /* Alternative SMF IP Address                      Extendable / Clause 8.2.129  */
/*    179 */    { dissect_pfcp_packet_replication_and_detection_carry_on_information }, /* Packet Replication and Detection Carry-On Information     Extendable / Clause 8.2.130  */
/*    180 */    { dissect_pfcp_smf_set_id },                                    /* SMF Set ID                                      Extendable / Clause 8.2.131  */
/*    181 */    { dissect_pfcp_quota_validity_time },                           /* Quota Validity Time                             Extendable / Clause 8.2.132  */
/*    182 */    { dissect_pfcp_number_of_reports },                             /* Number of Reports                               Fixed / Clause 8.2.133  */
/*    183 */    { dissect_pfcp_pfcp_session_retention_information_within_pfcp_association_setup_request }, /* PFCP Session Retention Information (within PFCP Association Setup Request)  Extendable / Table 7.4.4.1-2  */
/*    184 */    { dissect_pfcp_pfcpasrsp_flags },                               /* PFCPASRsp-Flags                                 Extendable / Clause 8.2.134  */
/*    185 */    { dissect_pfcp_cp_pfcp_entity_ip_address },                     /* CP PFCP Entity IP Address                       Extendable / Clause 8.2.135  */
/*    186 */    { dissect_pfcp_pfcpsereq_flags },                               /* PFCPSEReq-Flags                                 Extendable / Clause 8.2.136  */
/*    187 */    { dissect_pfcp_user_plane_path_recovery_report },               /* User Plane Path Recovery Report                 Extendable / Table 7.4.5.1.3-1  */
/*    188 */    { dissect_ip_multicast_addressing_info_within_pfcp_session_establishment_request }, /* IP Multicast Addressing Info within PFCP Session Establishment Request  Extendable / Clause 7.5.2.2-4  */
/*    189 */    { dissect_pfcp_join_ip_multicast_information },                 /* Join IP Multicast Information IE within Usage Report    Extendable / Table 7.5.8.3-4  */
/*    190 */    { dissect_pfcp_leave_ip_multicast_information },                /* Leave IP Multicast Information IE within Usage Report   Extendable / Table 7.5.8.3-5  */
/*    191 */    { dissect_pfcp_ip_multicast_address },                          /* IP Multicast Address                            Extendable / Clause 8.2.137  */
/*    192 */    { dissect_pfcp_source_ip_address },                             /* Source IP Address                               Extendable / Clause 8.2.138  */
/*    193 */    { dissect_pfcp_packet_rate_status },                            /* Packet Rate Status                              Extendable / Clause 8.2.139  */
/*    194 */    { dissect_pfcp_create_bridge_info_for_tsc },                    /* Create Bridge Info for TSC                      Extendable / Clause 8.2.140  */
/*    195 */    { dissect_pfcp_created_bridge_info_for_tsc },                   /* Created Bridge Info for TSC                     Extendable / Table 7.5.3.6-1  */
/*    196 */    { dissect_pfcp_ds_tt_port_number },                             /* DS-TT Port Number                               Fixed Length / Clause 8.2.141  */
/*    197 */    { dissect_pfcp_nw_tt_port_number },                             /* NW-TT Port Number                               Fixed Length / Clause 8.2.142  */
/*    198 */    { dissect_pfcp_5gs_user_plane_node },                           /* 5GS User Plane Node                             Extendable / Clause 8.2.143  */
/*    199 */    { dissect_pfcp_tsc_management_information_ie_within_pfcp_session_modification_request }, /* TSC Management Information IE within PFCP Session Modification Request  Extendable / Table 7.5.4.18-1  */
/*    200 */    { dissect_pfcp_tsc_management_information_ie_within_pfcp_session_modification_response }, /* TSC Management Information IE within PFCP Session Modification Response Extendable / Table 7.5.5.3-1  */
/*    201 */    { dissect_pfcp_tsc_management_information_ie_within_pfcp_session_report_request }, /* TSC Management Information IE within PFCP Session Report Request    Extendable / Table 7.5.8.5-1  */
/*    202 */    { dissect_pfcp_port_management_information_container },         /* Port Management Information Container           Variable Length / Clause 8.2.144  */
/*    203 */    { dissect_pfcp_clock_drift_control_information },               /* Clock Drift Control Information                 Extendable / Table 7.4.4.1.2-1  */
/*    204 */    { dissect_pfcp_requested_clock_drift_control_information },     /* Requested Clock Drift Information               Extendable / Clause 8.2.145  */
/*    205 */    { dissect_pfcp_clock_drift_report },                            /* Clock Drift Report                              Extendable / Table 7.4.5.1.4-1  */
/*    206 */    { dissect_pfcp_time_domain_number  },                            /* Time Domain Number                               Extendable / Clause 8.2.146  */
/*    207 */    { dissect_pfcp_time_offset_threshold },                         /* Time Offset Threshold                           Extendable / Clause 8.2.147  */
/*    208 */    { dissect_pfcp_cumulative_rate_ratio_threshold },               /* Cumulative rateRatio Threshold                  Extendable / Clause 8.2.148  */
/*    209 */    { dissect_pfcp_time_offset_measurement },                       /* Time Offset Measurement                         Extendable / Clause 8.2.149  */
/*    210 */    { dissect_pfcp_cumulative_rate_ratio_measurement },             /* Cumulative rateRatio Measurement                Extendable / Clause 8.2.150  */
/*    211 */    { dissect_pfcp_remove_srr },                                    /* Remove SRR                                      Extendable/ Table 7.5.4.19-1  */
/*    212 */    { dissect_pfcp_create_srr },                                    /* Create SRR                                      Extendable/ Table 7.5.2.9-1  */
/*    213 */    { dissect_pfcp_update_srr },                                    /* Update SRR                                      Extendable/ Table 7.5.4.21-1  */
/*    214 */    { dissect_pfcp_session_report },                                /* Session Report                                  Extendable / Table 7.5.8.7-1  */
/*    215 */    { dissect_pfcp_srr_id },                                        /* SRR ID                                          Extendable / Clause 8.2.151  */
/*    216 */    { dissect_pfcp_access_availability_control_information },       /* Access Availability Control Information         Extendable / Table 7.5.2.9-2  */
/*    217 */    { dissect_pfcp_requested_access_availability_control_information }, /* Requested Access Availability Information       Extendable / Clause 8.2.152  */
/*    218 */    { dissect_pfcp_access_availability_report },                    /* Access Availability Report                      Extendable / Table 7.5.8.6-2  */
/*    219 */    { dissect_pfcp_access_availability_information },               /* Access Availability Information                 Extendable / Clause 8.2.153  */
/*    220 */    { dissect_pfcp_provide_atsss_control_information },             /* Provide ATSSS Control Information               Extendable / Table 7.5.2.10-1  */
/*    221 */    { dissect_pfcp_atsss_control_parameters },                      /* ATSSS Control Parameters                        Extendable / Table 7.5.3.7-1  */
/*    222 */    { dissect_pfcp_mptcp_control_information },                     /* MPTCP Control Information                       Extendable / Clause 8.2.154  */
/*    223 */    { dissect_pfcp_atsss_ll_control_information },                  /* ATSSS-LL Control Information                    Extendable / Clause 8.2.155  */
/*    224 */    { dissect_pfcp_pmf_control_information },                       /* PMF Control Information                         Extendable / Clause 8.2.156  */
/*    225 */    { dissect_pfcp_mptcp_parameters },                              /* MPTCP Parameters                                Extendable / Table 7.5.3.7-2  */
/*    226 */    { dissect_pfcp_atsss_ll_parameters },                           /* ATSSS-LL Parameters                             Extendable / Table 7.5.3.7-3  */
/*    227 */    { dissect_pfcp_pmf_parameters },                                /* PMF Parameters                                  Extendable / Table 7.5.3.7-4  */
/*    228 */    { dissect_pfcp_mptcp_address_information },                     /* MPTCP Address Information                       Extendable / Clause 8.2.157  */
/*    229 */    { dissect_pfcp_ue_link_specific_ip_address },                   /* UE Link-Specific IP Address                     Extendable / Clause 8.2.158  */
/*    230 */    { dissect_pfcp_pmf_address_information },                       /* PMF Address Information                         Extendable / Clause 8.2.159  */
/*    231 */    { dissect_pfcp_atsss_ll_information },                          /* ATSSS-LL Information                            Extendable / Clause 8.2.160  */
/*    232 */    { dissect_pfcp_data_network_access_identifier },                /* Data Network Access Identifier                  Variable Length / Clause 8.2.161  */
/*    233 */    { dissect_pfcp_ue_ip_address_pool_information },                /* UE IP address Pool Information                  Extendable / Table 7.4.4.1-3  */
/*    234 */    { dissect_pfcp_average_packet_delay },                          /* Average Packet Delay                            Extendable / Clause 8.2.162  */
/*    235 */    { dissect_pfcp_minimum_packet_delay },                          /* Minimum Packet Delay                            Extendable / Clause 8.2.163  */
/*    236 */    { dissect_pfcp_maximum_packet_delay },                          /* Maximum Packet Delay                            Extendable / Clause 8.2.164  */
/*    237 */    { dissect_pfcp_qos_report_trigger },                            /* QoS Report Trigger                              Extendable / Clause 8.2.165  */
/*    238 */    { dissect_pfcp_gtp_u_path_qos_control_information },            /* GTP-U Path QoS Control Information              Extendable / Table 7.4.4.1.3-1  */
/*    239 */    { dissect_pfcp_gtp_u_path_qos_report },                         /* GTP-U Path QoS Report (PFCP Node Report Request)    Extendable / Table 7.4.5.1.5-1  */
/*    240 */    { dissect_pfcp_qos_information_in_gtp_u_path_qos_report },      /* QoS Information in GTP-U Path QoS Report        Extendable / Table 7.4.5.1.6-1  */
/*    241 */    { dissect_pfcp_gtp_u_path_interface_type },                     /* GTP-U Path Interface Type                       Extendable / Clause 8.2.166  */
/*    242 */    { dissect_pfcp_qos_monitoring_per_qos_flow_control_information }, /* QoS Monitoring per QoS flow Control Information Extendable / Table 7.5.2.9-3  */
/*    243 */    { dissect_pfcp_requested_qos_monitoring },                      /* Requested QoS Monitoring                        Extendable / Clause 8.2.167  */
/*    244 */    { dissect_pfcp_reporting_frequency },                           /* Reporting Frequency                             Extendable / Clause 8.2.168  */
/*    245 */    { dissect_pfcp_packet_delay_thresholds },                       /* Packet Delay Thresholds                         Extendable / Clause 8.2.169  */
/*    246 */    { dissect_pfcp_minimum_wait_time },                             /* Minimum Wait Time                               Extendable / Clause 8.2.170  */
/*    247 */    { dissect_pfcp_qos_monitoring_report },                         /* QoS Monitoring Report                           Extendable / Table 7.5.8.6-3  */
/*    248 */    { dissect_pfcp_qos_monitoring_measurement },                    /* QoS Monitoring Measurement                      Extendable / Clause 8.2.171  */
/*    249 */    { dissect_pfcp_mt_edt_control_information },                    /* MT-EDT Control Information                      Extendable / Clause 8.2.172  */
/*    250 */    { dissect_pfcp_dl_data_packets_size },                          /* DL Data Packets Size                            Extendable / Clause 8.2.173  */
/*    251 */    { dissect_pfcp_qer_control_indications },                       /* QER Control Indications                         Extendable / Clause 8.2.174  */
/*    252 */    { dissect_pfcp_packet_rate_status_report_ie_within_pfcp_session_deletion_response }, /* Packet Rate Status Report IE within PFCP Session Deletion Response     Extendable / Table 7.5.7.1-2  */
/*    253 */    { dissect_pfcp_nf_instance_id },                                /* NF Instance ID                                  Extendable / Clause 8.2.175  */
/*    254 */    { dissect_pfcp_ethernet_context_information_within_pfcp_session_modification_request }, /* Ethernet Context Information within PFCP Session Modification Request     Extendable / Table 7.5.4.21-1  */
/*    255 */    { dissect_pfcp_redundant_transmission_detection_parameters },   /* Redundant Transmission Detection Parameters               Extendable / Table 7.5.2.2-5  */
/*    256 */    { dissect_pfcp_updated_pdr_ie_within_pfcp_session_modification_response }, /* Updated PDR IE within PFCP Session Modification Response     Extendable / Table 7.5.5.5-1  */
/*    257 */    { dissect_pfcp_s_nssai },                                       /* S-NSSAI                                         Fixed Length / Clause 8.2.176 */
/*    258 */    { dissect_pfcp_ip_version },                                    /* IP version                                      Extendable / Clause 8.2.177 */
/*    259 */    { dissect_pfcp_pfcpasreq_flags },                               /* PFCPASReq-Flags                                 Extendable / Clause 8.2.178 */
/*    260 */    { dissect_pfcp_data_status },                                   /* Data Status                                     Extendable / Clause 8.2.179 */
/*    261 */    { dissect_pfcp_provide_rds_configuration_information_ie_within_pfcp_session_modification_request }, /* Provide RDS Configuration Information IE within PFCP Session Establishment Request   Extendable / Table 7.5.2.11-1  */
/*    262 */    { dissect_pfcp_rds_configuration_information },                 /* RDS Configuration Information                   Extendable / Clause 8.2.180  */
/*    263 */    { dissect_pfcp_query_packet_rate_status_ie_within_pfcp_session_modification_request }, /* Query Packet Rate Status IE within PFCP Session Modification Request      Extendable / Table 7.5.4.22-1  */
/*    264 */    { dissect_pfcp_query_packet_rate_status_report_ie_within_pfcp_session_modification_response }, /* Query Packet Rate Status Report IE within PFCP Session Modification Response      Extendable / Table 7.5.5.4-1  */
/*    265 */    { dissect_pfcp_mptcp_application_indication },                  /* MPTCP Applicable Indication                     Extendable / Clause 8.2.181 */
/*    266 */    { dissect_pfcp_user_plane_nodemanagement_information_container }, /* User Plane NodeManagement Information Container         Variable Length / Clause 8.2.182 */
/*    267 */    { dissect_pfcp_ue_ip_address_usage_information_ie_within_pfcp_association_update_request },       /* UE IP Address Usage Information IE within PFCP Association Update Request         Extendable / Table 7.4.4.3.1-1 */
/*    268 */    { dissect_pfcp_number_of_ue_ip_addresses },                     /* Number of UE IP Addresses                       Variable Length / Clause 8.2.183 */
/*    269 */    { dissect_pfcp_validity_timer },                                /* Validity Timer                                  Variable Length / Clause 8.2.183 */
/*    270 */    { dissect_pfcp_redundant_transmission_forward_parameters },     /* Redundant Transmission Forward Parameters       Variable Length / Clause 8.2.184  */
/*    271 */    { dissect_pfcp_transport_dealy_reporting_ie_in_create_pdr },    /* Transport Delay Reporting IE in Create PDR IE   Extendable / Table 7.5.2.2-6 */
/*    272 */    { dissect_pfcp_partial_failure_information_within_pfcp_session_establishment_response }, /* Partial Failure Information within PFCP Session Establishment Response      Extendable / Table 7.5.3.1-2 */
/*    273 */    { dissect_pfcp_partial_failure_information_within_pfcp_session_modification_response }, /* Partial Failure Information within PFCP Session Modificaton Response      Extendable / Table 7.5.5.1-2 */
/*    274 */    { dissect_pfcp_offending_ie_information },                      /* Offending IE Information                        Variable Length / Clause 8.2.185 */
/*    275 */    { dissect_pfcp_rattype },                                       /* RAT Type                                        Variable Length / Clause 8.2.186 */
/*    276 */    { dissect_pfcp_l2tp_tunnel_information },                       /* L2TP Tunnel Information                         Extendable / Table 7.5.2.1-2  */
/*    277 */    { dissect_pfcp_l2tp_session_information_within_pfcp_session_establishment_request },  /* L2TP Session Information within PFCP Session Establishment Request     Extendable / Table 7.5.2.1-3  */
/*    278 */    { dissect_pfcp_l2tp_user_authentication },                      /* L2TP User Authentication                        Variable Length / Clause 8.2.187 */
/*    279 */    { dissect_pfcp_l2tp_session_information_within_pfcp_session_establishment_response },  /* L2TP Session Information within PFCP Session Establishment Response     Extendable / Table 7.5.3.1-3  */
/*    280 */    { dissect_pfcp_lns_address },                                   /* LNS Address                                     Variable Length / Clause 8.2.188 */
/*    281 */    { dissect_pfcp_tunnel_preference },                             /* Tunnel Preference                               Fixed / Clause 8.2.189 */
/*    282 */    { dissect_pfcp_calling_number },                                /* Calling Number                                  Variable Length / Clause 8.2.190 */
/*    283 */    { dissect_pfcp_called_number },                                 /* Called Number                                   Variable Length / Clause 8.2.191 */
/*    284 */    { dissect_pfcp_l2tp_session_indications },                      /* L2TP Session Indications                        Extendable / Clause 8.2.192 */
/*    285 */    { dissect_pfcp_dns_sever_address },                             /* DNS Server Address                              Variable Length / Clause 8.2.193 */
/*    286 */    { dissect_pfcp_nbns_sever_address },                            /* NBNS Server Address                             Variable Length / Clause 8.2.194 */
/*    287 */    { dissect_pfcp_maximum_receive_unit },                          /* Maximum Receive Unit                            Fixed / Clause 8.2.195 */
/*    288 */    { dissect_pfcp_thresholds },                                    /* Thresholds                                      Variable Length / Clause 8.2.196 */
/*    289 */    { dissect_pfcp_steering_mode_indications },                     /* Steering Mode Indicator                         Extendable / Clause 8.2.197 */
/*    290 */    { dissect_pfcp_pfcp_session_change_info },                      /* PFCP Session Change Info                        Extendable / Table 7.4.7.1-2  */
/*    291 */    { dissect_pfcp_group_id },                                      /* Group ID                                        Fixed / Clause 8.2.198 */
/*    292 */    { dissect_pfcp_cp_ip_address },                                 /* CP IP Address                                   Variable Length / Clause 8.2.199 */
/*    293 */    { dissect_pfcp_ip_address_and_port_number_replacement },        /* IP Address and Port Number Replacement          Variable Length / Clause 8.2.200 */
/*    294 */    { dissect_pfcp_dns_query_filter },                              /* DNS Query Filter                                Variable Length / Clause 8.2.201 */
/*    295 */    { dissect_pfcp_direct_reporting_information },                  /* Direct Reporting Information                    Extendable / Table 7.5.2.9-4  */
/*    296 */    { dissect_pfcp_event_notification_uri },                        /* Event Notification URI                          Variable Length / Clause 8.2.202 */
/*    297 */    { dissect_pfcp_notification_correlation_id },                   /* Notification Correlation ID                     Fixed / Clause 8.2.203 */
/*    298 */    { dissect_pfcp_reporting_flags },                               /* Reporting Flags                                 Extendable / Clause 8.2.204 */
/*    299 */    { dissect_pfcp_predefined_rules_name },                         /* Predefined Rules Name                           Variable Length / Clause 8.2.205 */
/*    300 */    { dissect_pfcp_mbs_session_n4mb_control_information },          /* MBS Session N4mb Control Information            Extendable / Table 7.5.2.1-5 */
/*    301 */    { dissect_pfcp_mbs_multicast_parameters },                      /* MBS Multicast Parameters                        Extendable / Table 7.5.2.3-5 */
/*    302 */    { dissect_pfcp_add_mbs_unicast_parameters_ie_in_create_far },   /* Addd MBS Unicast Parameters IE in Create FAR    Extendable / Table 7.5.2.3-6 */
/*    303 */    { dissect_pfcp_mbs_session_n4mb_information },                  /* MBS Session N4mb Information                    Extendable / Table 7.5.3.1-4 */
/*    304 */    { dissect_pfcp_remove_mbs_unicast_parameters_ie_in_update_far },/* Remove MBS Unicast Parameters IE in Update FAR  Extendable / Table 7.5.4.3-4 */
/*    305 */    { dissect_pfcp_mbs_session_identifier },                        /* MBS Session Identifier                          Variable Length / Clause 8.2.206 */
/*    306 */    { dissect_pfcp_multicast_transport_information },               /* Multicast Transport Information                 Variable Length / Clause 8.2.207 */
/*    307 */    { dissect_pfcp_mbsn4mbreq_flags },                              /* MBSN4mbReq Flags                                Extendable / Clause 8.2.208 */
/*    308 */    { dissect_pfcp_local_ingress_tunnel },                          /* Local Ingress Tunnel                            Extendable / Clause 8.2.209 */
/*    309 */    { dissect_pfcp_mbs_unicast_parameters_id },                     /* MBS Unicast Parameters ID                       Extendable / Clause 8.2.210 */
/*    310 */    { dissect_pfcp_mbs_session_n4_control_information_ie_within_pfcp_session_establishment_request }, /* MBS Session N4 Control Information IE within PFCP Session Establishment Request      Extendable / Table 7.5.2.1-6 */
/*    311 */    { dissect_pfcp_mbs_session_n4_control_information_ie_within_pfcp_session_establishment_response }, /* MBS Session N4 Control Information IE within PFCP Session Establishment Response      Extendable / Table 7.5.3.1-5 */
/*    312 */    { dissect_pfcp_mbsn4resp_flags },                               /* MBSN4Resp-Flags                                 Extendable / Clause 8.2.211 */
/*    313 */    { dissect_pfcp_tunnel_password },                               /* Tunnel Password                                 Variable Length / Clause 8.2.212 */
/*    314 */    { dissect_pfcp_area_session_id },                               /* Area Sesson ID                                  Fixed / Clause 8.2.213 */
/*    315 */    { dissect_pfcp_peer_up_restart_report_ie_within_pfcp__node_report_request }, /* Peer UP Restart Report IE within PFCP Node Report Request      Extendable / Table 7.4.5.1-7 */
/*    316 */    { dissect_pfcp_dscp_to_ppi_control_information_ie_within_pfcp_session_establishment_request }, /* DSCP to PPI Control Information IE within PFCP Session Establishment Request      Extendable / Table 7.5.2.1-6 */
/*    317 */    { dissect_pfcp_dscp_to_ppi_mapping_information },               /* DSCP to PPI Mapping Information                 Extendable / Clause 8.2.214 */
/*    318 */    { dissect_pfcp_pfcpsdrsp_flags },                               /* PFCPSDRsp-Flags                                 Extendable / Clause 8.2.215 */
/*    319 */    { dissect_pfcp_qer_indications },                               /* QER Indications                                 Extendable / Clause 8.2.216 */
/*    320 */    { dissect_pfcp_vendor_specific_node_report_type },              /* Vendor-Specific Node Report Type                Extendable / Clause 8.2.217 */
//321 to 32767 Spare. For future use.
//32768 to 65535 Vendor-specific IEs.
    { NULL },                                                        /* End of List */
};

#define NUM_PFCP_IES (sizeof(pfcp_ies)/sizeof(pfcp_ie_t))
/* Set up the array to hold "etts" for each IE*/
gint ett_pfcp_elem[NUM_PFCP_IES-1];

static pfcp_msg_hash_t *
pfcp_match_response(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint seq_nr, guint msgtype, pfcp_conv_info_t *pfcp_info, guint8 last_cause)
{
    pfcp_msg_hash_t   pcr, *pcrp = NULL;
    guint32 *session;

    pcr.seq_nr = seq_nr;
    pcr.req_time = pinfo->abs_ts;

    switch (msgtype) {
    case PFCP_MSG_HEARTBEAT_REQUEST:
    case PFCP_MSG_PFD_MANAGEMENT_REQUEST:
    case PFCP_MSG_ASSOCIATION_SETUP_REQUEST:
    case PFCP_MSG_ASSOCIATION_UPDATE_REQUEST:
    case PFCP_MSG_ASSOCIATION_RELEASE_REQUEST:
    case PFCP_MSG_NODE_REPORT_REQEUST:
    case PFCP_MSG_SESSION_SET_DELETION_REQUEST:
    case PFCP_MSG_SESSION_SET_MODIFICATION_REQUEST:
    case PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST:
    case PFCP_MSG_SESSION_MODIFICATION_REQUEST:
    case PFCP_MSG_SESSION_DELETION_REQUEST:
    case PFCP_MSG_SESSION_REPORT_REQUEST:
        pcr.is_request = TRUE;
        pcr.req_frame = pinfo->num;
        pcr.rep_frame = 0;
        break;
    case PFCP_MSG_HEARTBEAT_RESPONSE:
    case PFCP_MSG_PFD_MANAGEMENT_RESPONSE:
    case PFCP_MSG_ASSOCIATION_SETUP_RESPONSE:
    case PFCP_MSG_ASSOCIATION_UPDATE_RESPONSE:
    case PFCP_MSG_ASSOCIATION_RELEASE_RESPONSE:
    case PFCP_MSG_VERSION_NOT_SUPPORTED_RESPONSE:
    case PFCP_MSG_NODE_REPORT_RERESPONSE:
    case PFCP_MSG_SESSION_SET_DELETION_RESPONSE:
    case PFCP_MSG_SESSION_SET_MODIFICATION_RESPONSE:
    case PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE:
    case PFCP_MSG_SESSION_MODIFICATION_RESPONSE:
    case PFCP_MSG_SESSION_DELETION_RESPONSE:
    case PFCP_MSG_SESSION_REPORT_RESPONSE:

        pcr.is_request = FALSE;
        pcr.req_frame = 0;
        pcr.rep_frame = pinfo->num;
        break;
    default:
        pcr.is_request = FALSE;
        pcr.req_frame = 0;
        pcr.rep_frame = 0;
        break;
    }

    pcrp = (pfcp_msg_hash_t *)wmem_map_lookup(pfcp_info->matched, &pcr);

    if (pcrp) {
        pcrp->is_request = pcr.is_request;
    } else {
        /* no match, let's try to make one */
        switch (msgtype) {
        case PFCP_MSG_HEARTBEAT_REQUEST:
        case PFCP_MSG_PFD_MANAGEMENT_REQUEST:
        case PFCP_MSG_ASSOCIATION_SETUP_REQUEST:
        case PFCP_MSG_ASSOCIATION_UPDATE_REQUEST:
        case PFCP_MSG_ASSOCIATION_RELEASE_REQUEST:
        case PFCP_MSG_NODE_REPORT_REQEUST:
        case PFCP_MSG_SESSION_SET_DELETION_REQUEST:
        case PFCP_MSG_SESSION_SET_MODIFICATION_REQUEST:
        case PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST:
        case PFCP_MSG_SESSION_MODIFICATION_REQUEST:
        case PFCP_MSG_SESSION_DELETION_REQUEST:
        case PFCP_MSG_SESSION_REPORT_REQUEST:

            pcr.seq_nr = seq_nr;

            pcrp = (pfcp_msg_hash_t *)wmem_map_remove(pfcp_info->unmatched, &pcr);

            /* if we can't reuse the old one, grab a new chunk */
            if (!pcrp) {
                pcrp = wmem_new(wmem_file_scope(), pfcp_msg_hash_t);
            }
            pcrp->seq_nr = seq_nr;
            pcrp->req_frame = pinfo->num;
            pcrp->req_time = pinfo->abs_ts;
            pcrp->rep_frame = 0;
            pcrp->msgtype = msgtype;
            pcrp->is_request = TRUE;
            wmem_map_insert(pfcp_info->unmatched, pcrp, pcrp);
            return NULL;
            break;
        case PFCP_MSG_HEARTBEAT_RESPONSE:
        case PFCP_MSG_PFD_MANAGEMENT_RESPONSE:
        case PFCP_MSG_ASSOCIATION_SETUP_RESPONSE:
        case PFCP_MSG_ASSOCIATION_UPDATE_RESPONSE:
        case PFCP_MSG_ASSOCIATION_RELEASE_RESPONSE:
        case PFCP_MSG_VERSION_NOT_SUPPORTED_RESPONSE:
        case PFCP_MSG_NODE_REPORT_RERESPONSE:
        case PFCP_MSG_SESSION_SET_DELETION_RESPONSE:
        case PFCP_MSG_SESSION_SET_MODIFICATION_RESPONSE:
        case PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE:
        case PFCP_MSG_SESSION_MODIFICATION_RESPONSE:
        case PFCP_MSG_SESSION_DELETION_RESPONSE:
        case PFCP_MSG_SESSION_REPORT_RESPONSE:

            pcr.seq_nr = seq_nr;
            pcrp = (pfcp_msg_hash_t *)wmem_map_lookup(pfcp_info->unmatched, &pcr);

            if (pcrp) {
                if (!pcrp->rep_frame) {
                    wmem_map_remove(pfcp_info->unmatched, pcrp);
                    pcrp->rep_frame = pinfo->num;
                    pcrp->is_request = FALSE;
                    wmem_map_insert(pfcp_info->matched, pcrp, pcrp);
                }
            }
            break;
        default:
            break;
        }
    }

    /* we have found a match */
    if (pcrp) {
        proto_item *it;

        if (pcrp->is_request) {
            it = proto_tree_add_uint(tree, hf_pfcp_response_in, tvb, 0, 0, pcrp->rep_frame);
            proto_item_set_generated(it);
        } else {
            nstime_t ns;

            it = proto_tree_add_uint(tree, hf_pfcp_response_to, tvb, 0, 0, pcrp->req_frame);
            proto_item_set_generated(it);
            nstime_delta(&ns, &pinfo->abs_ts, &pcrp->req_time);
            it = proto_tree_add_time(tree, hf_pfcp_response_time, tvb, 0, 0, &ns);
            proto_item_set_generated(it);
            if (g_pfcp_session && !PINFO_FD_VISITED(pinfo)) {
                /* PFCP session */
                /* If it's not already in the list */
                session = (guint32 *)g_hash_table_lookup(pfcp_session_table, &pinfo->num);
                if (!session) {
                    session = (guint32 *)g_hash_table_lookup(pfcp_session_table, &pcrp->req_frame);
                    if (session != NULL) {
                        pfcp_add_session(pinfo->num, *session);
                    }
                }

                if (!pfcp_is_cause_accepted(last_cause)){
                    /* If the cause is not accepted then we have to remove all the session information about its corresponding request */
                    pfcp_remove_frame_info(&pcrp->req_frame);
                }
            }
        }
    }
    return pcrp;
}

/* 7.2.3.3  Grouped Information Elements */

static void
dissect_pfcp_grouped_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, int ett_index, pfcp_session_args_t *args)
{
    int         offset = 0;
    tvbuff_t   *new_tvb;
    proto_tree *grouped_tree;

    proto_item_append_text(item, "[Grouped IE]");
    grouped_tree = proto_item_add_subtree(tree, ett_index);

    new_tvb = tvb_new_subset_length(tvb, offset, length);
    dissect_pfcp_ies_common(new_tvb, pinfo, grouped_tree, offset, length, message_type, args);

}

static void
dissect_pfcp_pdi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ID_PDI], args);
}

static void
dissect_pfcp_create_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ID_CREATE_PDR], args);
    proto_item_append_text(item, ": PDR ID: %u", args->last_rule_ids.pdr);
}

static void
dissect_pfcp_create_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATE_FAR], args);
    proto_item_append_text(item, ": FAR ID: %s %u",
                        tfs_get_string((args->last_rule_ids.far & 0x80000000), &pfcp_id_predef_dynamic_tfs),
                        (args->last_rule_ids.far & 0x7fffffff));
}

static void
dissect_pfcp_forwarding_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_FORWARDING_PARAMETERS], args);
}

static void
dissect_pfcp_duplicating_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_DUPLICATING_PARAMETERS], args);
}

static void
dissect_pfcp_create_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATE_URR], args);
    proto_item_append_text(item, ": URR ID: %s %u",
                        tfs_get_string((args->last_rule_ids.urr & 0x80000000), &pfcp_id_predef_dynamic_tfs),
                        (args->last_rule_ids.urr & 0x7fffffff));
}

static void
dissect_pfcp_create_qer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATE_QER], args);
    proto_item_append_text(item, ": QER ID: %s %u",
                        tfs_get_string((args->last_rule_ids.qer & 0x80000000), &pfcp_id_predef_dynamic_tfs),
                        (args->last_rule_ids.qer & 0x7fffffff));
}

static void
dissect_pfcp_created_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATED_PDR], args);
    proto_item_append_text(item, ": PDR ID: %u", args->last_rule_ids.pdr);
}

static void
dissect_pfcp_update_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_PDR], args);
    proto_item_append_text(item, ": PDR ID: %u", args->last_rule_ids.pdr);
}

static void
dissect_pfcp_update_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_FAR], args);
    proto_item_append_text(item, ": FAR ID: %s %u",
                        tfs_get_string((args->last_rule_ids.far & 0x80000000), &pfcp_id_predef_dynamic_tfs),
                        (args->last_rule_ids.far & 0x7fffffff));
}

static void
dissect_pfcp_upd_forwarding_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPD_FORWARDING_PARAM], args);
}

static void
dissect_pfcp_update_bar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_BAR], args);
    proto_item_append_text(item, ": BAR ID: %u", args->last_rule_ids.bar);
}

static void
dissect_pfcp_update_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_URR], args);
    proto_item_append_text(item, ": URR ID: %s %u",
                        tfs_get_string((args->last_rule_ids.urr & 0x80000000), &pfcp_id_predef_dynamic_tfs),
                        (args->last_rule_ids.urr & 0x7fffffff));
}

static void
dissect_pfcp_update_qer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_QER], args);
    proto_item_append_text(item, ": QER ID: %s %u",
                        tfs_get_string((args->last_rule_ids.qer & 0x80000000), &pfcp_id_predef_dynamic_tfs),
                        (args->last_rule_ids.qer & 0x7fffffff));
}

static void
dissect_pfcp_remove_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REMOVE_PDR], args);
    proto_item_append_text(item, ": PDR ID: %u", args->last_rule_ids.pdr);
}

static void
dissect_pfcp_remove_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REMOVE_FAR], args);
    proto_item_append_text(item, ": FAR ID: %s %u",
                        tfs_get_string((args->last_rule_ids.far & 0x80000000), &pfcp_id_predef_dynamic_tfs),
                        (args->last_rule_ids.far & 0x7fffffff));
}

static void
dissect_pfcp_remove_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REMOVE_URR], args);
    proto_item_append_text(item, ": URR ID: %s %u",
                        tfs_get_string((args->last_rule_ids.urr & 0x80000000), &pfcp_id_predef_dynamic_tfs),
                        (args->last_rule_ids.urr & 0x7fffffff));
}

static void
dissect_pfcp_remove_qer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REMOVE_QER], args);
    proto_item_append_text(item, ": QER ID: %s %u",
                        tfs_get_string((args->last_rule_ids.qer & 0x80000000), &pfcp_id_predef_dynamic_tfs),
                        (args->last_rule_ids.qer & 0x7fffffff));
}

static void
dissect_pfcp_load_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_LOAD_CONTROL_INFORMATION], args);
}

static void
dissect_pfcp_overload_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_OVERLOAD_CONTROL_INFORMATION], args);
}

static void
dissect_pfcp_application_ids_pfds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_APPLICATION_IDS_PFDS], args);
}

static void
dissect_pfcp_pfd_context(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_PFD_CONTEXT], args);
}


static void
dissect_pfcp_application_detection_inf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_APPLICATION_DETECTION_INF], args);
}

static void
dissect_pfcp_pfcp_query_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_QUERY_URR], args);
}

static void
dissect_pfcp_usage_report_smr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_USAGE_REPORT_SMR], args);
    proto_item_append_text(item, ": URR ID: %s %u",
                        tfs_get_string((args->last_rule_ids.urr & 0x80000000), &pfcp_id_predef_dynamic_tfs),
                        (args->last_rule_ids.urr & 0x7fffffff));
}

static void
dissect_pfcp_usage_report_sdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_USAGE_REPORT_SDR], args);
    proto_item_append_text(item, ": URR ID: %s %u",
                        tfs_get_string((args->last_rule_ids.urr & 0x80000000), &pfcp_id_predef_dynamic_tfs),
                        (args->last_rule_ids.urr & 0x7fffffff));
}

static void
dissect_pfcp_usage_report_srr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_USAGE_REPORT_SRR], args);
    proto_item_append_text(item, ": URR ID: %s %u",
                        tfs_get_string((args->last_rule_ids.urr & 0x80000000), &pfcp_id_predef_dynamic_tfs),
                        (args->last_rule_ids.urr & 0x7fffffff));
}

static void
dissect_pfcp_downlink_data_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_DOWNLINK_DATA_REPORT], args);
}

static void
dissect_pfcp_create_bar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATE_BAR], args);
    proto_item_append_text(item, ": BAR ID: %u", args->last_rule_ids.bar);
}

static void
dissect_pfcp_update_bar_smr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_BAR_SMR], args);
    proto_item_append_text(item, ": BAR ID: %u", args->last_rule_ids.bar);
}

static void
dissect_pfcp_remove_bar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REMOVE_BAR], args);
    proto_item_append_text(item, ": BAR ID: %u", args->last_rule_ids.bar);
}

static void
dissect_pfcp_error_indication_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ERROR_INDICATION_REPORT], args);
}

static void
dissect_pfcp_user_plane_path_failure_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT], args);
}

static void
dissect_pfcp_update_duplicating_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_DUPLICATING_PARAMETERS], args);
}

static void
dissect_pfcp_aggregated_urrs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_AGGREGATED_URRS], args);
}

static void
dissect_pfcp_create_traffic_endpoint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATE_TRAFFIC_ENDPOINT], args);
}

static void
dissect_pfcp_created_traffic_endpoint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATED_TRAFFIC_ENDPOINT], args);
}

static void
dissect_pfcp_update_traffic_endpoint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_TRAFFIC_ENDPOINT], args);
}

static void
dissect_pfcp_remove_traffic_endpoint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REMOVE_TRAFFIC_ENDPOINT], args);
}

static void
dissect_pfcp_ethernet_packet_filter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ETHERNET_PACKET_FILTER], args);
}

static void
dissect_pfcp_ethernet_traffic_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ETHERNET_TRAFFIC_INFORMATION], args);
}

static void
dissect_pfcp_additional_monitoring_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ADDITIONAL_MONITORING_TIME], args);
}

static void
dissect_pfcp_create_mar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATE_MAR], args);
    proto_item_append_text(item, ": MAR ID: %u", args->last_rule_ids.mar);
}

static void
dissect_pfcp_access_forwarding_action_information_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ACCESS_FORWARDING_ACTION_INORMATION_1], args);
}

static void
dissect_pfcp_access_forwarding_action_information_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ACCESS_FORWARDING_ACTION_INORMATION_2], args);
}

static void
dissect_pfcp_update_mar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_MAR], args);
    proto_item_append_text(item, ": MAR ID: %u", args->last_rule_ids.mar);
}

static void
dissect_pfcp_remove_mar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REMOVE_MAR], args);
    proto_item_append_text(item, ": MAR ID: %u", args->last_rule_ids.mar);
}

static void
dissect_pfcp_update_access_forwarding_action_information_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_ACCESS_FORWARDING_ACTION_INORMATION_1], args);
}

static void
dissect_pfcp_update_access_forwarding_action_information_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_ACCESS_FORWARDING_ACTION_INORMATION_2], args);
}

static void
dissect_pfcp_pfcp_session_retention_information_within_pfcp_association_setup_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_PFCP_SESSION_RETENTION_INFORMATION_WITHIN_ASSOCIATION_SETUP_REQUEST], args);
}

static void
dissect_pfcp_user_plane_path_recovery_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_USER_PLANE_PATH_RECOVERY_REPORT], args);
}

static void
dissect_ip_multicast_addressing_info_within_pfcp_session_establishment_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_IP_MULTICAST_ADDRESSING_INFO], args);
}

static void
dissect_pfcp_join_ip_multicast_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_JOIN_IP_MULTICAST_INFORMATION], args);
}

static void
dissect_pfcp_leave_ip_multicast_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_LEAVE_IP_MULTICAST_INFORMATION], args);
}

static void
dissect_pfcp_created_bridge_info_for_tsc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATED_BRIDGE_INFO_FOR_TSC], args);
}

static void
dissect_pfcp_tsc_management_information_ie_within_pfcp_session_modification_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_TSC_MANAGEMENT_INFORMATION_WITHIN_PCFP_SESSION_MODIFICATION_REQUEST], args);
}

static void
dissect_pfcp_tsc_management_information_ie_within_pfcp_session_modification_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_TSC_MANAGEMENT_INFORMATION_WITHIN_PCFP_SESSION_MODIFICATION_RESPONSE], args);
}

static void
dissect_pfcp_tsc_management_information_ie_within_pfcp_session_report_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_TSC_MANAGEMENT_INFORMATION_WITHIN_PCFP_SESSION_REPORT_REQUEST], args);
}

static void
dissect_pfcp_clock_drift_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CLOCK_DRIFT_CONTROL_INFORMATION], args);
}

static void
dissect_pfcp_clock_drift_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CLOCK_DRIFT_REPORT], args);
}

static void
dissect_pfcp_remove_srr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REMOVE_SRR], args);
    proto_item_append_text(item, ": SRR ID: %u", args->last_rule_ids.srr);
}

static void
dissect_pfcp_create_srr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATE_SRR], args);
    proto_item_append_text(item, ": SRR ID: %u", args->last_rule_ids.srr);
}

static void
dissect_pfcp_update_srr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_SRR], args);
    proto_item_append_text(item, ": SRR ID: %u", args->last_rule_ids.srr);
}

static void
dissect_pfcp_session_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_SESSION_REPORT], args);
}

static void
dissect_pfcp_access_availability_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ACCESS_AVAILABILITY_CONTROL_INFORMATION], args);
}

static void
dissect_pfcp_access_availability_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ACCESS_AVAILABILITY_REPORT], args);
}

static void
dissect_pfcp_provide_atsss_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_PROVICE_ATSSS_CONTROL_INFORMATION], args);
}

static void
dissect_pfcp_atsss_control_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ATSSS_CONTROl_PARAMETERS], args);
}

static void
dissect_pfcp_mptcp_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_MPTCP_PARAMETERS], args);
}

static void
dissect_pfcp_atsss_ll_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ATSSS_LL_PARAMETERS], args);
}

static void
dissect_pfcp_pmf_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_PMF_PARAMETERS], args);
}

static void
dissect_pfcp_ue_ip_address_pool_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UE_IP_ADDRESS_POOL_INFORMATION], args);
}

static void
dissect_pfcp_gtp_u_path_qos_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_GTP_U_PATH_QOS_CONTROL_INFORMATION], args);
}

static void
dissect_pfcp_gtp_u_path_qos_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_GTP_U_PATH_QOS_REPORT], args);
}

static void
dissect_pfcp_qos_information_in_gtp_u_path_qos_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_QOS_INFORMATION_IN_GTP_U_PATH_QOS_REPORT], args);
}

static void
dissect_pfcp_qos_monitoring_per_qos_flow_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_QOS_MONITORING_PER_QOS_FLOW_CONTROL_INFORMATION], args);
}

static void
dissect_pfcp_qos_monitoring_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_QOS_MONITORING_REPORT], args);
}

static void
dissect_pfcp_packet_rate_status_report_ie_within_pfcp_session_deletion_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_PACKET_RATE_STATUS_REPORT_IE_WITHIN_PFCP_SESSION_DELETION_RESPONSE], args);
}

static void
dissect_pfcp_ethernet_context_information_within_pfcp_session_modification_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PCFP_IE_ETHERNET_CONTEXT_INFORMATION_WITHIN_PFCP_SESSION_MODIFICATION_REQUEST], args);
}

static void
dissect_pfcp_redundant_transmission_detection_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REDUNDANT_TRANSMISSION_DETECTION_PARAMETERS_IE_IN_PDI], args);
}

static void
dissect_pfcp_updated_pdr_ie_within_pfcp_session_modification_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATED_PDR_IE_WITHIN_PFCP_SESSION_MODIFICATION_RESPONSE], args);
}

static void
dissect_pfcp_provide_rds_configuration_information_ie_within_pfcp_session_modification_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_PROVIDE_RDS_CONFIGURATION_INFORMATION_IE_WITHIN_PCFP_SESSION_ESTABLISHMENT_REQUEST], args);
}

static void
dissect_pfcp_query_packet_rate_status_ie_within_pfcp_session_modification_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_QUERY_PACKET_RATE_STATUS_IE_WITHIN_PCFP_SESSION_ESTABLISHMENT_REQUEST], args);
}

static void
dissect_pfcp_query_packet_rate_status_report_ie_within_pfcp_session_modification_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_QUERY_PACKET_RATE_STATUS_REPORT_IE_WITHIN_PCFP_SESSION_ESTABLISHMENT_RESPONSE], args);
}

static void
dissect_pfcp_ue_ip_address_usage_information_ie_within_pfcp_association_update_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UE_IP_ADDRESS_USAGE_INFORMATION_IE_WITHIN_PFCP_ASSOCIATION_UPDATE_REQUEST], args);
}

static void
dissect_pfcp_redundant_transmission_forward_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REDUNDANT_TRANSMISSION_FORWARD_PARAMETERS_IE_IN_FAR], args);
}

static void
dissect_pfcp_transport_dealy_reporting_ie_in_create_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_TRANSPORT_DELAY_REPORTING], args);
}

static void
dissect_pfcp_partial_failure_information_within_pfcp_session_establishment_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_PARTIAL_FAILURE_INFORMATION_WITHIN_PFCP_SESSION_ESTABLISHMENT_RESPONSE], args);
}

static void
dissect_pfcp_partial_failure_information_within_pfcp_session_modification_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_PARTIAL_FAILURE_INFORMATION_WITHIN_PFCP_SESSION_MODIFICATION_RESPONSE], args);
}

static void
dissect_pfcp_l2tp_tunnel_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_L2TP_TUNNEL_INFORMATION], args);
}

static void
dissect_pfcp_l2tp_session_information_within_pfcp_session_establishment_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_L2TP_SESSION_INFORMATION_WITHIN_PFCP_SESSION_ESTABLISHMENT_REQUEST], args);
}

static void
dissect_pfcp_l2tp_session_information_within_pfcp_session_establishment_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_L2TP_SESSION_INFORMATION_WITHIN_PFCP_SESSION_ESTABLISHMENT_RESPONSE], args);
}

static void
dissect_pfcp_pfcp_session_change_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_PFCP_SESSION_CHANGE_INFO], args);
}

static void
dissect_pfcp_direct_reporting_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_DIRECT_REPORTING_INFORMATION], args);
}

static void
dissect_pfcp_mbs_session_n4mb_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_MBS_SESSION_N4MB_CONTROL_INFORMATION], args);
}

static void
dissect_pfcp_mbs_multicast_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_MBS_MULTICAST_PARAMETERS], args);
}

static void
dissect_pfcp_add_mbs_unicast_parameters_ie_in_create_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ADD_MBS_UNICAST_PARAMETERS_IE_IN_CREATE_FAR], args);
}

static void
dissect_pfcp_mbs_session_n4mb_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_MBS_SESSION_N4MB_INFORMATION], args);
}

static void
dissect_pfcp_remove_mbs_unicast_parameters_ie_in_update_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REMOVE_MBS_UNICAST_PARAMETERS_IE_IN_UPDATE_FAR], args);
}

static void
dissect_pfcp_mbs_session_n4_control_information_ie_within_pfcp_session_establishment_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_MBS_SESSION_N4_CONTROl_INFORMATION_IE_WITHIN_PFCP_SESSION_ESTABLISHMENT_REQUEST], args);
}

static void
dissect_pfcp_mbs_session_n4_control_information_ie_within_pfcp_session_establishment_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_MBS_SESSION_N4_CONTROl_INFORMATION_IE_WITHIN_PFCP_SESSION_ESTABLISHMENT_RESPONSE], args);
}

static void
dissect_pfcp_peer_up_restart_report_ie_within_pfcp__node_report_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_PEER_UP_REPORT_IE_WITING_PFCP_NODE_REPORT_REQUEST], args);
}

static void
dissect_pfcp_dscp_to_ppi_control_information_ie_within_pfcp_session_establishment_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_DSCP_TO_PPI_CONTROL_INFORMATION_IE_WITIN_PCFP_SESSION_ESTABLISHMENT_REQUEST], args);
}


static void
dissect_pfcp_ies_common(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint offset, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    proto_tree *ie_tree;
    proto_item *ti;
    tvbuff_t   *ie_tvb;
    guint16 type, length_ie;
    guint16 enterprise_id;
    pfcp_sub_dis_t *pfcp_sub_dis_inf = wmem_new0(pinfo->pool, pfcp_sub_dis_t);

    pfcp_sub_dis_inf->message_type = message_type;
    pfcp_sub_dis_inf->args = args;

    /* 8.1.1    Information Element Format */
    /*
    Octets      8   7   6   5   4   3   2   1
    1 to 2      Type = xxx (decimal)
    3 to 4      Length = n
    p to (p+1)  Enterprise ID
    k to (n+4)  IE specific data or content of a grouped IE

    If the Bit 8 of Octet 1 is not set, this indicates that the IE is defined by 3GPP and the Enterprise ID is absent.
    If Bit 8 of Octet 1 is set, this indicates that the IE is defined by a vendor and the Enterprise ID is present
    identified by the Enterprise ID
    */

    /*Enterprise ID : if the IE type value is within the range of 32768 to 65535,
     * this field shall contain the IANA - assigned "SMI Network Management Private Enterprise Codes"
     * value of the vendor defining the IE.
     */
    /* Length: this field contains the length of the IE excluding the first four octets, which are common for all IEs */

    /* Process the IEs*/
    while (offset < length) {
        /* Octet 1 -2 */
        type = tvb_get_ntohs(tvb, offset);
        length_ie = tvb_get_ntohs(tvb, offset + 2);

        if ((type & 0x8000) == 0x8000 ) {
            enterprise_id = tvb_get_ntohs(tvb, offset + 4);
            ie_tvb = tvb_new_subset_length(tvb, offset, length_ie + 4);

            if (!dissector_try_uint_new(pfcp_enterprise_ies_dissector_table, enterprise_id, ie_tvb, pinfo, tree, FALSE, pfcp_sub_dis_inf)) {
                /* no Enterprise disector, do some generic decoding */
                ie_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4 + length_ie, ett_pfcp_ie, &ti, "Enterprise %s specific IE: %u",
                                                        try_enterprises_lookup(enterprise_id),
                                                        type);

                proto_tree_add_item(ie_tree, hf_pfcp2_enterprise_ie, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(ie_tree, hf_pfcp2_ie_len, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

                /* Bit 8 of Octet 1 is set, this indicates that the IE is defined by a vendor and the Enterprise ID is present */
                proto_tree_add_item(ie_tree, hf_pfcp_enterprise_id, tvb, offset + 4, 2, ENC_BIG_ENDIAN);

                /*
                 * 5.6.3    Modifying the Rules of an Existing PFCP Session
                 *
                 * Updating the Rule including the IEs to be removed with a null length,
                 * e.g. by including the Update URR IE in the PFCP Session Modification Request
                 * with the IE(s) to be removed with a null length.
                 */
                if (length_ie == 0) {
                    proto_item_append_text(ti, "[IE to be removed]");
                } else {
                    proto_tree_add_item(ie_tree, hf_pfcp_enterprise_data, ie_tvb, 6, -1, ENC_NA);
                }
            }
            offset += (4 + length_ie);
        } else {
            int tmp_ett;
            if (type < (NUM_PFCP_IES - 1)) {
                tmp_ett = ett_pfcp_elem[type];
            } else {
                tmp_ett = ett_pfcp_ie;
            }
            ie_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4 + length_ie, tmp_ett, &ti, "%s : ",
                val_to_str_ext_const(type, &pfcp_ie_type_ext, "Unknown"));

            proto_tree_add_item(ie_tree, hf_pfcp2_ie, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(ie_tree, hf_pfcp2_ie_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /*
            * 5.6.3    Modifying the Rules of an Existing PFCP Session
            *
            * Updating the Rule including the IEs to be removed with a null length,
            * e.g. by including the Update URR IE in the PFCP Session Modification Request
            * with the IE(s) to be removed with a null length.
            */
            if( length_ie == 0 ) {
                proto_item_append_text(ti, "[IE to be removed]");
            } else {
                if (type < (NUM_PFCP_IES -1)) {
                    ie_tvb = tvb_new_subset_length(tvb, offset, length_ie);
                    if(pfcp_ies[type].decode){
                        (*pfcp_ies[type].decode) (ie_tvb, pinfo, ie_tree, ti, length_ie, message_type, args);
                    } else {
                        /* NULL function pointer, we have no decoding function*/
                        proto_tree_add_expert(ie_tree, pinfo, &ei_pfcp_ie_not_decoded_null, tvb, offset, length_ie);
                    }
                } else {
                    /* IE id outside of array, We have no decoding function for it */
                    proto_tree_add_expert(ie_tree, pinfo, &ei_pfcp_ie_not_decoded_too_large, tvb, offset, length_ie);
                }
            }
            offset += length_ie;
        }
    }
}

static void
dissect_pfcp_enterprise_ies_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 message_type, pfcp_session_args_t *args,
                                   guint num_pfcp_enterprise_ies, gint * ett_pfcp_enterprise_elem, const pfcp_ie_t * pfcp_enterprise_ies,
                                   value_string_ext * pfcp_ie_enterprise_type_ext)
{
    proto_tree *ie_tree;
    proto_item *ti;
    tvbuff_t   *ie_tvb;
    gint offset = 0;
    guint16 type, length_ie;
    int tmp_ett;

    /* Octet 1 -2 */
    type = tvb_get_ntohs(tvb, offset) & ~0x8000;
    length_ie = tvb_get_ntohs(tvb, offset + 2);

    /* adjust length for Enterprise Id */
    length_ie -= 2;

    if (type < (num_pfcp_enterprise_ies - 1)) {
        tmp_ett = ett_pfcp_enterprise_elem[type];
    } else {
        tmp_ett = ett_pfcp_ie;
    }

    ie_tree = proto_tree_add_subtree_format(tree, tvb, offset, 6 + length_ie, tmp_ett, &ti, "%s : ",
                                            val_to_str_ext_const(type, pfcp_ie_enterprise_type_ext, "Unknown"));

    proto_tree_add_item(ie_tree, hf_pfcp2_enterprise_ie, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ie_tree, hf_pfcp2_ie_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ie_tree, hf_pfcp_enterprise_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*
     * 5.6.3    Modifying the Rules of an Existing PFCP Session
     *
     * Updating the Rule including the IEs to be removed with a null length,
     * e.g. by including the Update URR IE in the PFCP Session Modification Request
     * with the IE(s) to be removed with a null length.
     */
    if( length_ie == 0 ) {
        proto_item_append_text(ti, "[IE to be removed]");
    } else {
        if (type < (num_pfcp_enterprise_ies - 1)) {
            ie_tvb = tvb_new_subset_length(tvb, offset, length_ie);
            if(pfcp_enterprise_ies[type].decode){
                (*pfcp_enterprise_ies[type].decode) (ie_tvb, pinfo, ie_tree, ti, length_ie, message_type, args);
            } else {
                /* NULL function pointer, we have no decoding function*/
                proto_tree_add_expert(ie_tree, pinfo, &ei_pfcp_ie_not_decoded_null, tvb, offset, length_ie);
            }
        } else {
            /* IE id outside of array, We have no decoding function for it */
            proto_tree_add_expert(ie_tree, pinfo, &ei_pfcp_ie_not_decoded_too_large, tvb, offset, length_ie);
        }
    }
}

static int
dissect_pfcp_message(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    proto_item          *item;
    proto_tree          *sub_tree;
    int                  offset = 0;
    guint64              pfcp_flags;
    guint8               message_type, cause_aux;
    guint32              length;
    guint32              length_total;
    int                  seq_no = 0;
    conversation_t      *conversation;
    pfcp_conv_info_t    *pfcp_info;
    pfcp_session_args_t *args = NULL;
    pfcp_hdr_t          *pfcp_hdr = NULL;

    static int * const pfcp_hdr_flags[] = {
        &hf_pfcp_version,
        &hf_pfcp_spare_b4,
        &hf_pfcp_spare_b3,
        &hf_pfcp_fo_flag,
        &hf_pfcp_mp_flag,
        &hf_pfcp_s_flag,
        NULL
    };

    pfcp_hdr = wmem_new0(pinfo->pool, pfcp_hdr_t);

    /* Setting the SEID to -1 to say that the SEID is not valid for this packet */
    pfcp_hdr->seid = -1;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PFCP");
    col_clear(pinfo->cinfo, COL_INFO);

    message_type = tvb_get_guint8(tvb, 1);
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(message_type, &pfcp_message_type_ext, "Unknown"));

    args = wmem_new0(pinfo->pool, pfcp_session_args_t);
    args->last_cause = 1;                                         /* It stores the last cause decoded. Cause accepted by default */
    if (g_pfcp_session) {
        /* We create the auxiliary lists */
        args->seid_list = wmem_list_new(pinfo->pool);
        args->ip_list = wmem_list_new(pinfo->pool);
    }

    /* Do we have a conversation for this connection? */
    conversation = find_or_create_conversation(pinfo);

    /* Do we already know this conversation? */
    pfcp_info = (pfcp_conv_info_t *)conversation_get_proto_data(conversation, proto_pfcp);
    if (pfcp_info == NULL) {
        /* No. Attach that information to the conversation,
        * and add it to the list of information structures.
        */
        pfcp_info = wmem_new(wmem_file_scope(), pfcp_conv_info_t);
        /* Request/response matching tables */
        pfcp_info->matched = wmem_map_new(wmem_file_scope(), pfcp_sn_hash, pfcp_sn_equal_matched);
        pfcp_info->unmatched = wmem_map_new(wmem_file_scope(), pfcp_sn_hash, pfcp_sn_equal_unmatched);

        conversation_add_proto_data(conversation, proto_pfcp, pfcp_info);
    }

    item = proto_tree_add_item(tree, proto_pfcp, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_pfcp);

    /* 7.2.2    Message Header */
    /*
        Octet     8     7     6     5     4     3     2     1
          1    | Version        |Spare|Spare|  FO  |  MP  |  S  |
          2    |        Message Type                            |
          3    |        Message Length (1st Octet)              |
          4    |        Message Length (2nd Octet)              |
        m to   | If S flag is set to 1, then SEID shall be      |
        k(m+7) | placed into octets 5-12. Otherwise, SEID field |
               | is not present at all.                         |
        n to   | Sequence Number                                |
        (n+2)  |                                                |
        (n+3)  |         Spare                                  |

    */
    /* Octet 1 */
    proto_tree_add_bitmask_with_flags_ret_uint64(sub_tree, tvb, offset, hf_pfcp_hdr_flags,
        ett_pfcp_flags, pfcp_hdr_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT, &pfcp_flags);
    offset += 1;

    /* Octet 2 Message Type */
    pfcp_hdr->message = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(sub_tree, hf_pfcp_msg_type, tvb, offset, 1, pfcp_hdr->message);
    offset += 1;

    /* Octet 3 - 4 Message Length */
    proto_tree_add_item_ret_uint(sub_tree, hf_pfcp_msg_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
    offset += 2;

    /* length of the message in octets plus the excluded mandatory part of the PFCP header (the first 4 octets) */
    length_total = (length + 4);

    if ((pfcp_flags & 0x1) == 1) {
        /* If S flag is set to 1, then SEID shall be placed into octets 5-12*/
        /* Session Endpoint Identifier 8 Octets */
        pfcp_hdr->seid = tvb_get_ntohi64(tvb, offset);
        proto_tree_add_uint64(sub_tree, hf_pfcp_seid, tvb, offset, 8, pfcp_hdr->seid);
        offset += 8;
    }
    /* 7.2.2.2    PFCP Header for Node Related Messages */
    /*
        Octet     8     7     6     5     4     3     2     1
          1    | Version        |Spare|Spare| FO=0 | MP=0 | S=0 |
          2    |        Message Type                            |
          3    |        Message Length (1st Octet)              |
          4    |        Message Length (2nd Octet)              |
          5    |        Sequence Number (1st Octet)             |
          6    |        Sequence Number (2st Octet)             |
          7    |        Sequence Number (3st Octet)             |
          8    |             Spare                              |
    */
    proto_tree_add_item_ret_uint(sub_tree, hf_pfcp_seqno, tvb, offset, 3, ENC_BIG_ENDIAN, &seq_no);
    offset += 3;

    if ((pfcp_flags & 0x2) == 0x2) {
        /* If the "MP" flag is set to "1", then bits 8 to 5 of octet 16 shall indicate the message priority.*/
        proto_tree_add_item(sub_tree, hf_pfcp_mp, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_pfcp_spare_h0, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(sub_tree, hf_pfcp_spare_oct, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset++;

    /* Dissect the IEs in the message */
    dissect_pfcp_ies_common(tvb, pinfo, sub_tree, offset, length_total, message_type, args);

    /* Use sequence number to track Req/Resp pairs */
    cause_aux = 16; /* Cause accepted by default. Only used when no session tracking enabled */
    if (g_pfcp_session && !PINFO_FD_VISITED(pinfo)) {
        /* We insert the lists inside the table*/
        pfcp_fill_map(args->seid_list, args->ip_list, pinfo->num);
        cause_aux = args->last_cause;
    }
    pfcp_match_response(tvb, pinfo, sub_tree, seq_no, message_type, pfcp_info, cause_aux);
    if (g_pfcp_session) {
        pfcp_track_session(tvb, pinfo, sub_tree, pfcp_hdr, args->seid_list, args->ip_list, args->last_seid, args->last_ip);
    }

    return length_total;
}

static int
dissect_pfcp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void *data _U_)
{
    int     offset = 0;
    guint   length = tvb_reported_length(tvb);

    /* 7.2.1A   PFCP messages bundled in one UDP/IP packet */
    /* Each bundled PFCP message shall contain its PFCP message header and may */
    /* contain subsequent information element(s) dependent on the type of message. */
    do
    {
        /* The first octet of header, Bit 3 represents the "FO" (Follow On) flag. */
        /* If the "FO" flag is set to "1", then another PFCP message follows in the UDP/IP packet */
        gboolean follow_on = (tvb_get_guint8(tvb, offset) & 0x04);

        /* length of the message in octets plus the excluded mandatory part of the PFCP header (the first 4 octets) */
        guint16 message_length = (tvb_get_guint16(tvb, (offset + 2), 0) + 4);

        tvbuff_t *message_tvb = tvb_new_subset_length(tvb, offset, message_length);
        offset += dissect_pfcp_message(message_tvb, pinfo, tree);

        /* Lets warn of faulty FO flag */
        if (follow_on) {
            if ((length - offset) == 0) {
                proto_tree_add_expert_format(tree, pinfo, &ei_pfcp_ie_encoding_error, tvb, offset, -1, "Follow ON flag set but no data left for following message");
            }
        } else {
            if ((length - offset) > 0) {
                proto_tree_add_expert_format(tree, pinfo, &ei_pfcp_ie_encoding_error, tvb, offset, -1, "Data left for following message but Follow ON flag is not set");
            }
        }
    } while (length > (guint)offset);

    return length;
}

/* Enterprise IE decoding 3GPP */
static int
dissect_pfcp_3gpp_enterprise_ies(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    proto_tree *ie_tree;
    guint16 type;

    type = tvb_get_ntohs(tvb, offset) & ~0x8000;

    ie_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_pfcp_ie, NULL,
                                            "Enterprise %s specific IE: %u [Enterprise ID set to '10415' shall not be used for the vendor specific IEs]",
                                            try_enterprises_lookup(VENDOR_THE3GPP), type);
    proto_tree_add_item(ie_tree, hf_pfcp2_enterprise_ie, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ie_tree, hf_pfcp2_ie_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ie_tree, hf_pfcp_enterprise_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_expert(ie_tree, pinfo, &ei_pfcp_enterprise_ie_3gpp, tvb, offset, -1);

    return tvb_reported_length(tvb);
}

/* Enterprise IE decoding Broadband Forum
 *
 * TR-459: Control and User Plane Separation for a disaggregated BNG
 */

static void dissect_pfcp_enterprise_bbf_ppp_lcp_connectivity(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args);
static void dissect_pfcp_enterprise_bbf_l2tp_tunnel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args);

#define PFCP_IE_ENTERPRISE_BBF_UP_FUNCTION_FEATURES              0 /* 32768 */
#define PFCP_IE_ENTERPRISE_BBF_LOGICAL_PORT                      1 /* 32769 */
#define PFCP_IE_ENTERPRISE_BBF_OUTER_HEADER_CREATION             2 /* 32770 */
#define PFCP_IE_ENTERPRISE_BBF_OUTER_HEADER_REMOVAL              3 /* 32771 */
#define PFCP_IE_ENTERPRISE_BBF_PPPOE_SESSION_ID                  4 /* 32772 */
#define PFCP_IE_ENTERPRISE_BBF_PPP_PROTOCOL                      5 /* 32773 */
#define PFCP_IE_ENTERPRISE_BBF_VERIFICATION_TIMERS               6 /* 32774 */
#define PFCP_IE_ENTERPRISE_BBF_PPP_LCP_MAGIC_NUMBER              7 /* 32775 */
#define PFCP_IE_ENTERPRISE_BBF_MTU                               8 /* 32776 */
#define PFCP_IE_ENTERPRISE_BBF_L2TP_TUNNEL_ENDPOINT              9 /* 32777 */
#define PFCP_IE_ENTERPRISE_BBF_L2TP_SESSION_ID                  10 /* 32778 */
#define PFCP_IE_ENTERPRISE_BBF_L2TP_TYPE                        11 /* 32779 */
#define PFCP_IE_ENTERPRISE_BBF_PPP_LCP_CONNECTIVITY             12 /* 32780 */
#define PFCP_IE_ENTERPRISE_BBF_L2TP_TUNNEL                      13 /* 32781 */

static const value_string pfcp_ie_enterprise_bbf_type[] = {
    { PFCP_IE_ENTERPRISE_BBF_UP_FUNCTION_FEATURES,              "BBF UP Function Features"},
    { PFCP_IE_ENTERPRISE_BBF_LOGICAL_PORT,                      "Logical Port"},
    { PFCP_IE_ENTERPRISE_BBF_OUTER_HEADER_CREATION,             "BBF Outer Header Creation"},
    { PFCP_IE_ENTERPRISE_BBF_OUTER_HEADER_REMOVAL,              "BBF Outer Header Removal"},
    { PFCP_IE_ENTERPRISE_BBF_PPPOE_SESSION_ID,                  "PPPoE Session ID"},
    { PFCP_IE_ENTERPRISE_BBF_PPP_PROTOCOL,                      "PPP protocol"},
    { PFCP_IE_ENTERPRISE_BBF_VERIFICATION_TIMERS,               "Verification Timers"},
    { PFCP_IE_ENTERPRISE_BBF_PPP_LCP_MAGIC_NUMBER,              "PPP LCP Magic Number"},
    { PFCP_IE_ENTERPRISE_BBF_MTU,                               "MTU"},
    { PFCP_IE_ENTERPRISE_BBF_L2TP_TUNNEL_ENDPOINT,              "L2TP Tunnel Endpoint"},
    { PFCP_IE_ENTERPRISE_BBF_L2TP_SESSION_ID,                   "L2TP Session ID"},
    { PFCP_IE_ENTERPRISE_BBF_L2TP_TYPE,                         "L2TP Type"},
    { PFCP_IE_ENTERPRISE_BBF_PPP_LCP_CONNECTIVITY,              "PPP LCP Connectivity"},
    { PFCP_IE_ENTERPRISE_BBF_L2TP_TUNNEL,                       "L2TP Tunnel"},
    { 0, NULL }
};

static value_string_ext pfcp_ie_enterprise_bbf_type_ext = VALUE_STRING_EXT_INIT(pfcp_ie_enterprise_bbf_type);

/*
 * TR-459: 6.6.1 BBF UP Function Features
 */
static void
dissect_pfcp_enterprise_bbf_up_function_features(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_bbf_up_function_features_o7_flags[] = {
        &hf_pfcp_spare_b7_b5,
        &hf_pfcp_bbf_up_function_features_o7_b4_lcp_keepalive_offload,
        &hf_pfcp_bbf_up_function_features_o7_b3_lns,
        &hf_pfcp_bbf_up_function_features_o7_b2_lac,
        &hf_pfcp_bbf_up_function_features_o7_b1_ipoe,
        &hf_pfcp_bbf_up_function_features_o7_b0_pppoe,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, pfcp_bbf_up_function_features_o7_flags, ENC_BIG_ENDIAN);
    offset += 1;

    // Octet 8 Spare Octet
    proto_tree_add_item(tree, hf_pfcp_spare_oct, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    // Octet 9 Spare Octet
    proto_tree_add_item(tree, hf_pfcp_spare_oct, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    // Octet 10 Spare Octet
    proto_tree_add_item(tree, hf_pfcp_spare_oct, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * TR-459: 6.6.2 Logical Port
 */
static void
dissect_pfcp_enterprise_bbf_logical_port(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* Octet 7 to (n+4) logical-port-id */
    if (tvb_ascii_isprint(tvb, 0, length))
    {
        const guint8* string_value;
        proto_tree_add_item_ret_string(tree, hf_pfcp_bbf_logical_port_id_str, tvb, 0, length, ENC_ASCII | ENC_NA, pinfo->pool, &string_value);
        proto_item_append_text(item, "%s", string_value);
    }
    else
    {
        proto_tree_add_item(tree, hf_pfcp_bbf_logical_port_id, tvb, 0, length, ENC_NA);
    }
}

/*
 * TR-459: 6.6.3 BBF Outer Header Creation
 */

static const value_string pfcp_bbf_outer_hdr_desc_vals[] = {

    { 0x000100, "CPR-NSH " },
    { 0x000200, "Traffic-Endpoint " },
    { 0x000300, "L2TP " },
    { 0x000400, "PPP " },
    { 0, NULL }
};

static void
dissect_pfcp_enterprise_bbf_outer_header_creation(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;

    /* Octet 7  Outer Header Creation Description */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_bbf_outer_hdr_desc, tvb, offset, 2, ENC_BIG_ENDIAN, &value);
    offset += 2;

    /* Octet 9 to 10  Tunnel ID */
    proto_tree_add_item(tree, hf_pfcp_bbf_outer_hdr_creation_tunnel_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Octet 10 to 11  Session ID */
    proto_tree_add_item(tree, hf_pfcp_bbf_outer_hdr_creation_session_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * TR-459: 6.6.4 BBF Outer Header Removal
 */

static const value_string pfcp_bbf_out_hdr_desc_vals[] = {
    { 1, "Ethernet " },
    { 2, "PPPoE/Ethernet " },
    { 3, "PPP/PPPoE/Ethernet " },
    { 4, "L2TP " },
    { 5, "PPP/L2TP " },
    { 0, NULL }
};

static void
dissect_pfcp_enterprise_bbf_outer_header_removal(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;

    proto_tree_add_item_ret_uint(tree, hf_pfcp_bbf_out_hdr_desc, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;
    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_bbf_out_hdr_desc_vals, "Unknown"));

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * TR-459: 6.6.5 PPPoE Session ID
 */
static void
dissect_pfcp_enterprise_bbf_pppoe_session_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;

    proto_tree_add_item_ret_uint(tree, hf_pfcp_bbf_pppoe_session_id, tvb, offset, 2, ENC_BIG_ENDIAN, &value);
    offset += 2;
    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * TR-459: 6.6.6 PPP Protocol
 */
static void
dissect_pfcp_enterprise_bbf_ppp_protocol(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 bbf_ppp_flags_val;

    static int * const pfcp_bbf_ppp_protocol_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_bbf_ppp_protocol_b2_control,
        &hf_pfcp_bbf_ppp_protocol_b1_data,
        &hf_pfcp_bbf_ppp_protocol_b0_specific,
        NULL
    };
    /* Octet 5   control   data    specific D */
    proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_pfcp_bbf_ppp_protocol_flags,
        ett_pfcp_bbf_ppp_protocol_flags, pfcp_bbf_ppp_protocol_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT | BMT_NO_TFS, &bbf_ppp_flags_val);
    offset += 1;

    if ((bbf_ppp_flags_val & 0x01) == 1)
    {
        /* Octet 8 and 9    protocol */
        proto_tree_add_item(tree, hf_pfcp_bbf_ppp_protocol, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * TR-459: 6.6.7 Verification Timers
 */
static void
dissect_pfcp_enterprise_bbf_verification_timers(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_pfcp_bbf_verification_timer_interval, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_pfcp_bbf_verification_timer_count, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * TR-459: 6.6.8 LCP Magic Number
 */
static void
dissect_pfcp_enterprise_bbf_ppp_lcp_magic_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_pfcp_bbf_ppp_lcp_magic_number_tx, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_pfcp_bbf_ppp_lcp_magic_number_rx, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * TR-459: 6.6.9 MTU
 */
static void
dissect_pfcp_enterprise_bbf_mtu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;

    proto_tree_add_item_ret_uint(tree, hf_pfcp_bbf_mtu, tvb, offset, 2, ENC_BIG_ENDIAN, &value);
    offset += 2;
    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * TR-459: 6.6.10 L2TP Tunnel Endpoint
 */
static void
dissect_pfcp_enterprise_bbf_l2tp_tunnel_endpoint(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 bbf_l2tp_endp_flags_val;

    static int * const pfcp_bbf_l2tp_endp_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_bbf_l2tp_endp_flags_b2_ch,
        &hf_pfcp_bbf_l2tp_endp_flags_b1_v6,
        &hf_pfcp_bbf_l2tp_endp_flags_b0_v4,
        NULL
    };
    /* Octet 5   CH    v4    v6 */
    proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_pfcp_bbf_l2tp_endp_flags,
        ett_pfcp_bbf_l2tp_endp_flags, pfcp_bbf_l2tp_endp_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT | BMT_NO_TFS, &bbf_l2tp_endp_flags_val);
    offset += 1;

    proto_tree_add_item(tree, hf_pfcp_bbf_l2tp_endp_id_tunnel_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_pfcp_bbf_l2tp_endp_id_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_pfcp_bbf_l2tp_endp_id_ipv6, tvb, offset, 16, ENC_NA);
    offset += 16;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * TR-459: 6.6.11 L2TP Session ID
 */
static void
dissect_pfcp_enterprise_bbf_l2tp_session_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 value;

    proto_tree_add_item_ret_uint(tree, hf_pfcp_bbf_l2tp_session_id, tvb, offset, 2, ENC_BIG_ENDIAN, &value);
    offset += 2;
    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}


/*
 * TR-459: 6.6.12 L2TP Type
 */

static const true_false_string pfcp_bbf_l2tp_type_b0_t_tfs = {
    "control",
    "data"
};

static void
dissect_pfcp_enterprise_bbf_l2tp_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;

    static int * const pfcp_bbf_l2tp_type_flags[] = {
        &hf_pfcp_spare_b7_b1,
        &hf_pfcp_bbf_l2tp_type_flags_b0_t,
        NULL
    };
    /* Octet 7   T */
    proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_pfcp_bbf_l2tp_type_flags,
        ett_pfcp_bbf_l2tp_type_flags, pfcp_bbf_l2tp_type_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT | BMT_NO_TFS);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

static const pfcp_ie_t pfcp_enterprise_bbf_ies[] = {
/*  32768 */    { dissect_pfcp_enterprise_bbf_up_function_features },
/*  32769 */    { dissect_pfcp_enterprise_bbf_logical_port },
/*  32770 */    { dissect_pfcp_enterprise_bbf_outer_header_creation },
/*  32771 */    { dissect_pfcp_enterprise_bbf_outer_header_removal },
/*  32772 */    { dissect_pfcp_enterprise_bbf_pppoe_session_id },
/*  32773 */    { dissect_pfcp_enterprise_bbf_ppp_protocol },
/*  32774 */    { dissect_pfcp_enterprise_bbf_verification_timers },
/*  32775 */    { dissect_pfcp_enterprise_bbf_ppp_lcp_magic_number },
/*  32776 */    { dissect_pfcp_enterprise_bbf_mtu },
/*  32777 */    { dissect_pfcp_enterprise_bbf_l2tp_tunnel_endpoint },
/*  32778 */    { dissect_pfcp_enterprise_bbf_l2tp_session_id },
/*  32779 */    { dissect_pfcp_enterprise_bbf_l2tp_type },
/*  32780 */    { dissect_pfcp_enterprise_bbf_ppp_lcp_connectivity },
/*  32781 */    { dissect_pfcp_enterprise_bbf_l2tp_tunnel },
    { NULL },                                                        /* End of List */
};

#define NUM_PFCP_ENTERPRISE_BBF_IES (sizeof(pfcp_enterprise_bbf_ies)/sizeof(pfcp_ie_t))
/* Set up the array to hold "etts" for each IE*/
gint ett_pfcp_enterprise_bbf_elem[NUM_PFCP_ENTERPRISE_BBF_IES-1];

static void
dissect_pfcp_enterprise_bbf_ppp_lcp_connectivity(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_enterprise_bbf_elem[PFCP_IE_ENTERPRISE_BBF_PPP_LCP_CONNECTIVITY], args);
}

static void
dissect_pfcp_enterprise_bbf_l2tp_tunnel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_enterprise_bbf_elem[PFCP_IE_ENTERPRISE_BBF_L2TP_TUNNEL], args);
}

static int
dissect_pfcp_enterprise_bbf_ies(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    pfcp_sub_dis_t *pfcp_sub_dis_info = (pfcp_sub_dis_t *)data;

    dissect_pfcp_enterprise_ies_common(tvb, pinfo, tree, pfcp_sub_dis_info->message_type, pfcp_sub_dis_info->args,
                                       NUM_PFCP_ENTERPRISE_BBF_IES, ett_pfcp_enterprise_bbf_elem,
                                       pfcp_enterprise_bbf_ies, &pfcp_ie_enterprise_bbf_type_ext);
    return tvb_reported_length(tvb);
}

/* Enterprise IE decoding Travelping */

static void dissect_pfcp_enterprise_travelping_error_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args);
static void dissect_pfcp_enterprise_travelping_created_nat_binding(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args);
static void dissect_pfcp_enterprise_travelping_trace_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, pfcp_session_args_t *args);

/* Enterprise IE decoding Travelping */
#define PFCP_IE_ENTERPRISE_TRAVELPING_PACKET_MEASUREMENT  1
#define PFCP_IE_ENTERPRISE_TRAVELPING_BUILD_ID          2
#define PFCP_IE_ENTERPRISE_TRAVELPING_NOW               3
#define PFCP_IE_ENTERPRISE_TRAVELPING_START             4
#define PFCP_IE_ENTERPRISE_TRAVELPING_STOP              5
#define PFCP_IE_ENTERPRISE_TRAVELPING_ERROR_REPORT      6
#define PFCP_IE_ENTERPRISE_TRAVELPING_ERROR_MESSAGE     7
#define PFCP_IE_ENTERPRISE_TRAVELPING_FILE_NAME         8
#define PFCP_IE_ENTERPRISE_TRAVELPING_LINE_NUMBER       9
#define PFCP_IE_ENTERPRISE_TRAVELPING_CREATED_NAT_BINDING 10
#define PFCP_IE_ENTERPRISE_TRAVELPING_IPFIX_POLICY      11
#define PFCP_IE_ENTERPRISE_TRAVELPING_TRACE_INFO        12
#define PFCP_IE_ENTERPRISE_TRAVELPING_TRACE_PARENT      13
#define PFCP_IE_ENTERPRISE_TRAVELPING_TRACE_STATE       14

static const value_string pfcp_ie_enterprise_travelping_type[] = {
    { PFCP_IE_ENTERPRISE_TRAVELPING_PACKET_MEASUREMENT, "Packet Measurement"},
    { PFCP_IE_ENTERPRISE_TRAVELPING_BUILD_ID,           "Build Id"},
    { PFCP_IE_ENTERPRISE_TRAVELPING_NOW,                "Now"},
    { PFCP_IE_ENTERPRISE_TRAVELPING_START,              "Start"},
    { PFCP_IE_ENTERPRISE_TRAVELPING_STOP,               "Stop"},
    { PFCP_IE_ENTERPRISE_TRAVELPING_ERROR_REPORT,       "Error Report"},
    { PFCP_IE_ENTERPRISE_TRAVELPING_ERROR_MESSAGE,      "Error Message"},
    { PFCP_IE_ENTERPRISE_TRAVELPING_FILE_NAME,          "File Name"},
    { PFCP_IE_ENTERPRISE_TRAVELPING_LINE_NUMBER,        "Line Number"},
    { PFCP_IE_ENTERPRISE_TRAVELPING_IPFIX_POLICY,       "IPFIX Policy"},
    { PFCP_IE_ENTERPRISE_TRAVELPING_TRACE_INFO,         "Trace Information"},
    { PFCP_IE_ENTERPRISE_TRAVELPING_TRACE_PARENT,       "Trace Parent"},
    { PFCP_IE_ENTERPRISE_TRAVELPING_TRACE_STATE,        "Trace State"},
    { 0, NULL }
};

static value_string_ext pfcp_ie_enterprise_travelping_type_ext = VALUE_STRING_EXT_INIT(pfcp_ie_enterprise_travelping_type);

static void
dissect_pfcp_enterprise_travelping_packet_measurement(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint64 flags;

    static int * const pfcp_enterprise_travelping_packet_measurement_flags[] = {
        &hf_pfcp_spare_b7_b3,
        &hf_pfcp_enterprise_travelping_packet_measurement_b2_dlnop,
        &hf_pfcp_enterprise_travelping_packet_measurement_b1_ulnop,
        &hf_pfcp_enterprise_travelping_packet_measurement_b0_tonop,
        NULL
    };

    proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_pfcp_enterprise_travelping_packet_measurement,
        ett_pfcp_enterprise_travelping_packet_measurement, pfcp_enterprise_travelping_packet_measurement_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT, &flags);
    offset += 1;

    if ((flags & 0x1)) {
        proto_tree_add_item(tree, hf_pfcp_travelping_pkt_meas_tonop, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    if ((flags & 0x2)) {
        proto_tree_add_item(tree, hf_pfcp_travelping_pkt_meas_ulnop, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    if ((flags & 0x4)) {
        proto_tree_add_item(tree, hf_pfcp_travelping_pkt_meas_dlnop, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

static void
dissect_pfcp_enterprise_travelping_build_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* Octet 7 to (n+4) Travelping Build Id */
    if (tvb_ascii_isprint(tvb, 0, length))
    {
        const guint8* string_value;
        proto_tree_add_item_ret_string(tree, hf_pfcp_travelping_build_id_str, tvb, 0, length, ENC_ASCII | ENC_NA, pinfo->pool, &string_value);
        proto_item_append_text(item, "%s", string_value);
    }
    else
    {
        proto_tree_add_item(tree, hf_pfcp_travelping_build_id, tvb, 0, length, ENC_NA);
    }
}

static void
dissect_pfcp_enterprise_travelping_now(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    char *time_str;

    proto_tree_add_item_ret_time_string(tree, hf_pfcp_travelping_now, tvb, 0, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    offset += 8;

    proto_item_append_text(item, "%s", time_str);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

static void
dissect_pfcp_enterprise_travelping_start(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    char *time_str;

    proto_tree_add_item_ret_time_string(tree, hf_pfcp_travelping_now, tvb, 0, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    offset += 8;

    proto_item_append_text(item, "%s", time_str);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

static void
dissect_pfcp_enterprise_travelping_stop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    char *time_str;

    proto_tree_add_item_ret_time_string(tree, hf_pfcp_travelping_now, tvb, offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    offset += 8;

    proto_item_append_text(item, "%s", time_str);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

static void
dissect_pfcp_enterprise_travelping_error_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* Octet 7 to (n+4) Travelping Error Message */
    if (tvb_ascii_isprint(tvb, 0, length))
    {
        const guint8* string_value;
        proto_tree_add_item_ret_string(tree, hf_pfcp_travelping_error_message_str, tvb, 0, length, ENC_ASCII | ENC_NA, pinfo->pool, &string_value);
        proto_item_append_text(item, "%s", string_value);
    }
    else
    {
        proto_tree_add_item(tree, hf_pfcp_travelping_error_message, tvb, 0, length, ENC_NA);
    }
}

static void
dissect_pfcp_enterprise_travelping_file_name(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* Octet 7 to (n+4) Travelping Error Message */
    if (tvb_ascii_isprint(tvb, 0, length))
    {
        const guint8* string_value;
        proto_tree_add_item_ret_string(tree, hf_pfcp_travelping_file_name_str, tvb, 0, length, ENC_ASCII | ENC_NA, pinfo->pool, &string_value);
        proto_item_append_text(item, "%s", string_value);
    }
    else
    {
        proto_tree_add_item(tree, hf_pfcp_travelping_file_name, tvb, 0, length, ENC_NA);
    }
}

static void
dissect_pfcp_enterprise_travelping_line_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    int offset = 0;
    guint32 line_number;

    /* Octet 7 to 10 Travelping Line Number */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_travelping_line_number, tvb, offset, 4, ENC_BIG_ENDIAN, &line_number);
    offset += 4;

    proto_item_append_text(item, " : %u", line_number);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

static void
dissect_pfcp_enterprise_travelping_ipfix_policy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* Octet 7 to (n+4) Travelping IPFIX Policy */
    if (tvb_ascii_isprint(tvb, 0, length))
    {
        const guint8* string_value;
        proto_tree_add_item_ret_string(tree, hf_pfcp_travelping_ipfix_policy_str, tvb, 0, length, ENC_ASCII | ENC_NA, pinfo->pool, &string_value);
        proto_item_append_text(item, "%s", string_value);
    }
    else
    {
        proto_tree_add_item(tree, hf_pfcp_travelping_ipfix_policy, tvb, 0, length, ENC_NA);
    }
}

static void
dissect_pfcp_enterprise_travelping_trace_parent(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* Octet 7 to (n+4) Travelping Trace Parent */
    if (tvb_ascii_isprint(tvb, 0, length))
    {
        const guint8* string_value;
        proto_tree_add_item_ret_string(tree, hf_pfcp_travelping_trace_parent_str, tvb, 0, length, ENC_ASCII | ENC_NA, pinfo->pool, &string_value);
        proto_item_append_text(item, "%s", string_value);
    }
    else
    {
        proto_tree_add_item(tree, hf_pfcp_travelping_trace_parent, tvb, 0, length, ENC_NA);
    }
}

static void
dissect_pfcp_enterprise_travelping_trace_state(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    /* Octet 7 to (n+4) Travelping Trace State */
    if (tvb_ascii_isprint(tvb, 0, length))
    {
        const guint8* string_value;
        proto_tree_add_item_ret_string(tree, hf_pfcp_travelping_trace_state_str, tvb, 0, length, ENC_ASCII | ENC_NA, pinfo->pool, &string_value);
        proto_item_append_text(item, "%s", string_value);
    }
    else
    {
        proto_tree_add_item(tree, hf_pfcp_travelping_trace_state, tvb, 0, length, ENC_NA);
    }
}

static const pfcp_ie_t pfcp_enterprise_travelping_ies[] = {
/*      0 */    { dissect_pfcp_reserved },
/*      1 */    { dissect_pfcp_enterprise_travelping_packet_measurement },
/*      2 */    { dissect_pfcp_enterprise_travelping_build_id },
/*      3 */    { dissect_pfcp_enterprise_travelping_now },
/*      4 */    { dissect_pfcp_enterprise_travelping_start },
/*      5 */    { dissect_pfcp_enterprise_travelping_stop },
/*      6 */    { dissect_pfcp_enterprise_travelping_error_report },
/*      7 */    { dissect_pfcp_enterprise_travelping_error_message },
/*      8 */    { dissect_pfcp_enterprise_travelping_file_name },
/*      9 */    { dissect_pfcp_enterprise_travelping_line_number },
/*     10 */    { dissect_pfcp_enterprise_travelping_created_nat_binding },
/*     11 */    { dissect_pfcp_enterprise_travelping_ipfix_policy },
/*     12 */    { dissect_pfcp_enterprise_travelping_trace_info },
/*     13 */    { dissect_pfcp_enterprise_travelping_trace_parent },
/*     14 */    { dissect_pfcp_enterprise_travelping_trace_state },
    { NULL },                                                        /* End of List */
};

#define NUM_PFCP_ENTERPRISE_TRAVELPING_IES (sizeof(pfcp_enterprise_travelping_ies)/sizeof(pfcp_ie_t))
/* Set up the array to hold "etts" for each IE*/
gint ett_pfcp_enterprise_travelping_elem[NUM_PFCP_ENTERPRISE_TRAVELPING_IES-1];

static void
dissect_pfcp_enterprise_travelping_error_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_enterprise_travelping_elem[PFCP_IE_ENTERPRISE_TRAVELPING_ERROR_REPORT], args);
}

static void
dissect_pfcp_enterprise_travelping_created_nat_binding(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_enterprise_travelping_elem[PFCP_IE_ENTERPRISE_TRAVELPING_CREATED_NAT_BINDING], args);
}

static void
dissect_pfcp_enterprise_travelping_trace_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type, pfcp_session_args_t *args)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_enterprise_travelping_elem[PFCP_IE_ENTERPRISE_TRAVELPING_TRACE_INFO], args);
}

static int
dissect_pfcp_enterprise_travelping_ies(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    pfcp_sub_dis_t *pfcp_sub_dis_info = (pfcp_sub_dis_t *)data;

    dissect_pfcp_enterprise_ies_common(tvb, pinfo, tree, pfcp_sub_dis_info->message_type, pfcp_sub_dis_info->args,
                                       NUM_PFCP_ENTERPRISE_TRAVELPING_IES, ett_pfcp_enterprise_travelping_elem,
                                       pfcp_enterprise_travelping_ies, &pfcp_ie_enterprise_travelping_type_ext);
    return tvb_reported_length(tvb);
}

static void
pfcp_init(void)
{
    pfcp_session_count = 1;
    pfcp_session_table = g_hash_table_new(g_int_hash, g_int_equal);
    pfcp_frame_tree = wmem_tree_new(wmem_file_scope());
}

static void
pfcp_cleanup(void)
{
    pfcp_session_conv_info_t *pfcp_info;

    /* Free up state attached to the pfcp_info structures */
    for (pfcp_info = pfcp_session_info_items; pfcp_info != NULL; ) {
        pfcp_session_conv_info_t *next;

        g_hash_table_destroy(pfcp_info->matched);
        pfcp_info->matched=NULL;
        g_hash_table_destroy(pfcp_info->unmatched);
        pfcp_info->unmatched=NULL;

        next = pfcp_info->next;
        pfcp_info = next;
    }

    /* Free up state attached to the pfcp session structures */
    pfcp_info_items = NULL;

    if (pfcp_session_table != NULL) {
        g_hash_table_destroy(pfcp_session_table);
    }
    pfcp_session_table = NULL;
}

void
proto_register_pfcp(void)
{

    static hf_register_info hf_pfcp[] = {

        { &hf_pfcp_msg_type,
        { "Message Type", "pfcp.msg_type",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &pfcp_message_type_ext, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_msg_length,
        { "Length", "pfcp.length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_hdr_flags,
        { "Flags", "pfcp.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_version,
        { "Version", "pfcp.version",
        FT_UINT8, BASE_DEC, NULL, 0xe0,
        NULL, HFILL }
        },
        { &hf_pfcp_fo_flag,
        { "Follow On (FO)", "pfcp.fo_flag",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }
        },
        { &hf_pfcp_mp_flag,
        { "Message Priority (MP)", "pfcp.mp_flag",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }
        },
        { &hf_pfcp_s_flag,
        { "SEID (S)", "pfcp.s",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b0,
        { "Spare", "pfcp.spare_b0",
        FT_UINT8, BASE_DEC, NULL, 0x01,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b1,
        { "Spare", "pfcp.spare_b1",
        FT_UINT8, BASE_DEC, NULL, 0x02,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b2,
        { "Spare", "pfcp.spare_b2",
        FT_UINT8, BASE_DEC, NULL, 0x04,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b3,
        { "Spare", "pfcp.spare_b3",
        FT_UINT8, BASE_DEC, NULL, 0x08,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b4,
        { "Spare", "pfcp.spare_b4",
        FT_UINT8, BASE_DEC, NULL, 0x10,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b5,
        { "Spare", "pfcp.spare_b5",
        FT_UINT8, BASE_DEC, NULL, 0x20,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b6,
        { "Spare", "pfcp.spare_b6",
        FT_UINT8, BASE_DEC, NULL, 0x40,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b7,
        { "Spare", "pfcp.spare_b7",
        FT_UINT8, BASE_DEC, NULL, 0x80,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b7_b6,
        { "Spare", "pfcp.spare_b7_b6",
        FT_UINT8, BASE_DEC, NULL, 0xc0,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b7_b5,
        { "Spare", "pfcp.spare_b7_b5",
        FT_UINT8, BASE_DEC, NULL, 0xe0,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b7_b4,
        { "Spare", "pfcp.spare_b7_b4",
        FT_UINT8, BASE_DEC, NULL, 0xf0,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b7_b3,
        { "Spare", "pfcp.spare_b7_b3",
        FT_UINT8, BASE_DEC, NULL, 0xf8,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b7_b2,
        { "Spare", "pfcp.spare_b7_b2",
        FT_UINT8, BASE_DEC, NULL, 0xfc,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b7_b1,
        { "Spare", "pfcp.spare_b7_b1",
        FT_UINT8, BASE_DEC, NULL, 0xfe,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_oct,
        { "Spare", "pfcp.spare_oct",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_h0,
        { "Spare", "pfcp.spare_h0",
        FT_UINT8, BASE_DEC, NULL, 0x0f,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_h1,
        { "Spare", "pfcp.spare_h1",
        FT_UINT8, BASE_DEC, NULL, 0xf0,
        NULL, HFILL }
        },
        { &hf_pfcp_spare,
        { "Spare", "pfcp.spare",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_seid,
        { "SEID", "pfcp.seid",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_seqno,
        { "Sequence Number", "pfcp.seqno",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_response_in,
        { "Response In", "pfcp.response_in",
        FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
        "The response to this PFCP request is in this frame", HFILL }
        },
        { &hf_pfcp_response_to,
        { "Response To", "pfcp.response_to",
        FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
        "This is a response to the PFCP request in this frame", HFILL }
        },
        { &hf_pfcp_response_time,
        { "Response Time", "pfcp.response_time",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "The time between the Request and the Response", HFILL }
        },
        { &hf_pfcp_session,
        { "Session", "pfcp.session",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
        },
        { &hf_pfcp_mp,
        { "Message Priority", "pfcp.mp",
        FT_UINT24, BASE_DEC, NULL, 0xf0,
        NULL, HFILL }
        },
        { &hf_pfcp_enterprise_id,
        { "Enterprise ID",    "pfcp.enterprise_id",
        FT_UINT16, BASE_ENTERPRISES, STRINGS_ENTERPRISES,
        0x0, NULL, HFILL } },
        { &hf_pfcp_enterprise_data,
        { "Enterprise IE Data",    "pfcp.enterprise_ie_data",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp2_ie,
        { "IE Type", "pfcp.ie_type",
        FT_UINT16, BASE_DEC | BASE_EXT_STRING, &pfcp_ie_type_ext, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp2_enterprise_ie,
        { "Enterprise specific IE Type", "pfcp.enterprise_ie",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp2_ie_len,
        { "IE Length", "pfcp.ie_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_recovery_time_stamp,
        { "Recovery Time Stamp", "pfcp.recovery_time_stamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0,
        NULL, HFILL }
        },
        { &hf_pfcp2_cause,
        { "Cause", "pfcp.cause",
        FT_UINT8, BASE_DEC, VALS(pfcp_cause_vals), 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_node_id_type,
        { "Address Type", "pfcp.node_id_type",
            FT_UINT8, BASE_DEC, VALS(pfcp_node_id_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_pfcp_node_id_ipv4,
        { "IPv4", "pfcp.node_id_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_node_id_ipv6,
        { "IPv6", "pfcp.node_id_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_node_id_fqdn,
        { "FQDN", "pfcp.node_id_fqdn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_b0_v6,
        { "V6 (IPv6)", "pfcp.f_seid_flags.v6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_b1_v4,
        { "V4 (IPv4)", "pfcp.f_seid_flags.v4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_f_seid_ipv4,
        { "IPv4 address", "pfcp.f_seid.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_f_seid_ipv6,
        { "IPv6 address", "pfcp.f_seid.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_pdr_id,
        { "Rule ID", "pfcp.pdr_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_precedence,
        { "Precedence", "pfcp.precedence",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_source_interface,
        { "Source Interface", "pfcp.source_interface",
            FT_UINT8, BASE_DEC, VALS(pfcp_source_interface_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_pfcp_fteid_flg_spare,
        { "Spare", "pfcp.fteid_flg.spare",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_pfcp_fteid_flg_b3_ch_id,
        { "CHID (CHOOSE_ID)", "pfcp.f_teid_flags.ch_id",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_fteid_flg_b2_ch,
        { "CH (CHOOSE)", "pfcp.f_teid_flags.ch",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_fteid_flg_b1_v6,
        { "V6 (IPv6)", "pfcp.f_teid_flags.v6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_fteid_flg_b0_v4,
        { "V4 (IPv4)", "pfcp.f_teid_flags.v4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_f_teid_ch_id,
        { "Choose Id", "pfcp.f_teid.choose_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_f_teid_teid,
        { "TEID", "pfcp.f_teid.teid",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_f_teid_ipv4,
        { "IPv4 address", "pfcp.f_teid.ipv4_addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_f_teid_ipv6,
        { "IPv6 address", "pfcp.f_teid.ipv6_addr",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_network_instance,
        { "Network Instance", "pfcp.network_instance",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_pdn_type,
        { "PDN Type", "pfcp.pdn_type",
            FT_UINT8, BASE_DEC, VALS(pfcp_pdn_type_vals), 0x7,
            NULL, HFILL }
        },
        { &hf_pfcp_multiplier_value_digits,
        { "Value Digits", "pfcp.multiplier.value_digits",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_multiplier_exponent,
        { "Exponent", "pfcp.multiplier.exponent",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_failed_rule_id_type,
        { "Failed Rule ID Type", "pfcp.failed_rule_id_type",
            FT_UINT8, BASE_DEC, VALS(pfcp_failed_rule_id_type_vals), 0x7,
            NULL, HFILL }
        },
        { &hf_pfcp_time_quota_mechanism_bti_type,
        { "Base Time Interval Type", "pfcp.time_quota_mechanism_bti_type",
            FT_UINT8, BASE_DEC, VALS(pfcp_time_quota_mechanism_bti_type_vals), 0x3,
            NULL, HFILL }
        },
        { &hf_pfcp_time_quota_mechanism_bti,
        { "Base Time Interval", "pfcp.time_quota_mechanism_bti",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_address_flag_b0_v6,
        { "V6 (IPv6)", "pfcp.ue_ip_address_flag.v6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_address_flag_b1_v4,
        { "V4 (IPv4)", "pfcp.ue_ip_address_flag.v4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_address_flag_b2_sd,
        { "S/D", "pfcp.ue_ip_address_flag.sd",
            FT_BOOLEAN, 8, TFS(&pfcp_ue_ip_add_sd_flag_vals), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_address_flag_b3_v6d,
        { "IPv6D", "pfcp.ue_ip_address_flag.v6d",
            FT_BOOLEAN, 8, TFS(&pfcp_ue_ip_add_sd_flag_vals), 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_address_flag_b4_chv4,
        { "CHV4", "pfcp.ue_ip_address_flag.chv4",
            FT_BOOLEAN, 8, TFS(&pfcp_ue_ip_add_sd_flag_vals), 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_address_flag_b5_chv6,
        { "CHV6", "pfcp.ue_ip_address_flag.chv6",
            FT_BOOLEAN, 8, TFS(&pfcp_ue_ip_add_sd_flag_vals), 0x20,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_address_flag_b6_v6pl,
        { "IPV6PL", "pfcp.ue_ip_address_flag.v6pl",
            FT_BOOLEAN, 8, TFS(&pfcp_ue_ip_add_sd_flag_vals), 0x40,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_addr_ipv4,
        { "IPv4 address", "pfcp.ue_ip_addr_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_add_ipv6,
        { "IPv6 address", "pfcp.ue_ip_addr_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_add_ipv6_prefix_delegation_bits,
        { "IPv6 Prefix Delegation Bits", "pfcp.ue_ip_addr_ipv6_prefix",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_add_ipv6_prefix_length,
        { "IPv6 Prefix Length", "pfcp.ue_ip_addr_ipv6_prefix_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_application_id,
        { "Application Identifier", "pfcp.application_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_application_id_str,
        { "Application Identifier", "pfcp.application_id_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_sdf_filter_flags_b0_fd,
        { "FD (Flow Description)", "pfcp.sdf_filter.fd",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_sdf_filter_flags_b1_ttc,
        { "TTC (ToS Traffic Class)", "pfcp.sdf_filter.ttc",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_sdf_filter_flags_b2_spi,
        { "SPI (Security Parameter Index)", "pfcp.sdf_filter.spi",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_sdf_filter_flags_b3_fl,
        { "FL (Flow Label)", "pfcp.sdf_filter.fl",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_sdf_filter_flags_b4_bid,
        { "BID (Bidirectional SDF Filter)", "pfcp.sdf_filter.bid",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_flow_desc_len,
        { "Length of Flow Description", "pfcp.flow_desc_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_flow_desc,
        { "Flow Description", "pfcp.flow_desc",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_traffic_class,
        { "ToS Traffic Class", "pfcp.traffic_class",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_traffic_mask,
        { "Mask field", "pfcp.traffic_mask",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_traffic_dscp,
            {"DSCP", "pfcp.traffic_dscp",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_pfcp_spi,
        { "Security Parameter Index", "pfcp.spi",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_flow_label_spare_bit,
        { "Spare bit", "pfcp.flow_label_spare_bit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_flow_label,
        { "Flow Label", "pfcp.flow_label",
            FT_UINT24, BASE_HEX, NULL, 0x0FFFFF,
            NULL, HFILL }
        },
        { &hf_pfcp_sdf_filter_id,
        { "SDF Filter ID", "pfcp.sdf_filter_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_out_hdr_desc,
        { "Outer Header Removal Description", "pfcp.out_hdr_desc",
            FT_UINT8, BASE_DEC, VALS(pfcp_out_hdr_desc_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_gtpu_ext_hdr_del_b0_pdu_sess_cont,
        { "PDU Session Container to be deleted", "pfcp.gtpu_ext_hdr_del.pdu_sess_cont",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_far_id_flg,
        { "Allocation type", "pfcp.far_id_flg",
            FT_BOOLEAN, 32, TFS(&pfcp_id_predef_dynamic_tfs), 0x80000000,
            NULL, HFILL }
        },
        { &hf_pfcp_far_id,
        { "FAR ID", "pfcp.far_id",
            FT_UINT32, BASE_DEC, NULL, 0x7fffffff,
            NULL, HFILL }
        },
        { &hf_pfcp_urr_id_flg,
        { "Allocation type", "pfcp.urr_id_flg",
            FT_BOOLEAN, 32, TFS(&pfcp_id_predef_dynamic_tfs), 0x80000000,
            NULL, HFILL }
        },
        { &hf_pfcp_urr_id,
        { "URR ID", "pfcp.urr_id",
            FT_UINT32, BASE_DEC, NULL, 0x7fffffff,
            NULL, HFILL }
        },
        { &hf_pfcp_qer_id_flg,
        { "Allocation type", "pfcp.qer_id_flg",
            FT_BOOLEAN, 32, TFS(&pfcp_id_predef_dynamic_tfs), 0x80000000,
            NULL, HFILL }
        },
        { &hf_pfcp_qer_id,
        { "QER ID", "pfcp.qer_id",
            FT_UINT32, BASE_DEC, NULL, 0x7fffffff,
            NULL, HFILL }
        },
        { &hf_pfcp_predef_rules_name,
        { "Predefined Rules Name", "pfcp.predef_rules_name",
            FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags_o5_b0_drop,
        { "DROP (Drop)", "pfcp.apply_action.drop",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags_o5_b1_forw,
        { "FORW (Forward)", "pfcp.apply_action.forw",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags_o5_b2_buff,
        { "BUFF (Buffer)", "pfcp.apply_action.buff",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags_o5_b3_nocp,
        { "NOCP (Notify the CP function)", "pfcp.apply_action.nocp",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags_o5_b4_dupl,
        { "DUPL (Duplicate)", "pfcp.apply_action.dupl",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags_o5_b5_ipma,
        { "IPMA (IP Multicast Accept)", "pfcp.apply_action.ipma",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags_o5_b6_ipmd,
        { "IPMD (IP Multicast Deny)", "pfcp.apply_action.ipmd",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags_o5_b7_dfrt,
        { "DFRT (Duplicate for Redundant Transmission)", "pfcp.apply_action.dfrt",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags_o6_b0_edrt,
        { "EDRT (Eliminate Duplicate Packets for Redundant Transmission)", "pfcp.apply_action.edrt",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags_o6_b1_bdpn,
        { "BDPN (Buffered Downlink Packet Notification)", "pfcp.apply_action.bdpn",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags_o6_b2_ddpn,
        { "DDPN (Discared Downlink Packet Notification)", "pfcp.apply_action.ddpn",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags_o6_b3_fssm,
        { "FSSM (Forward packets to lower layer SSM)", "pfcp.apply_action.fssm",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags_o6_b4_mbsu,
        { "MBSU (Forward and replicate MBS data using Unicast transport)", "pfcp.apply_action.mbsu",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },

        { &hf_pfcp_bar_id,
        { "BAR ID", "pfcp.bar_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_fq_csid_node_id_type,
        { "FQ-CSID Node-ID Type", "pfcp.fq_csid_node_id_type",
            FT_UINT8, BASE_DEC, VALS(pfcp_fq_csid_node_id_type_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_pfcp_num_csid,
        { "Number of CSID", "pfcp.num_csid",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_pfcp_fq_csid_node_id_ipv4,
        { "Node-Address", "pfcp.q_csid_node_id.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_fq_csid_node_id_ipv6,
        { "Node-Address", "pfcp.q_csid_node_id.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_fq_csid_node_id_mcc_mnc,
        { "Node-Address MCC MNC", "pfcp.q_csid_node_id.mcc_mnc",
            FT_UINT32, BASE_DEC, NULL, 0xfffff000,
            NULL, HFILL }
        },
        { &hf_pfcp_fq_csid_node_id_int,
        { "Node-Address Number", "pfcp.q_csid_node_id.int",
            FT_UINT32, BASE_DEC, NULL, 0x00000fff,
            NULL, HFILL }
        },
        { &hf_pfcp_fq_csid,
        { "PDN Connection Set Identifier (CSID)", "pfcp.csid",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_fq_csid_node_type,
        { "Node Type", "pfcp.fq_csid_node_type",
            FT_UINT8, BASE_DEC, VALS(pfcp_fq_csid_node_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_pfcp_measurement_period,
        { "Measurement Period", "pfcp.measurement_period",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_duration_measurement,
        { "Duration", "pfcp.duration_measurement",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_time_of_first_packet,
        { "Time of First Packet", "pfcp.time_of_first_packet",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_time_of_last_packet,
        { "Time of Last Packet", "pfcp.time_of_last_packet",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_dst_interface,
        { "Interface", "pfcp.dst_interface",
            FT_UINT8, BASE_DEC, VALS(pfcp_dst_interface_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_pfcp_redirect_address_type,
        { "Redirect Address Type", "pfcp.redirect_address_type",
            FT_UINT8, BASE_DEC, VALS(pfcp_redirect_address_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_pfcp_redirect_server_addr_len,
        { "Redirect Server Address Length", "pfcp.redirect_server_addr_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_redirect_server_address,
        { "Redirect Server Address", "pfcp.redirect_server_address",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_other_redirect_server_addr_len,
        { "Other Redirect Server Address Length", "pfcp.other_redirect_server_addr_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_other_redirect_server_address,
        { "Other Redirect Server Address", "pfcp.other_redirect_server_address",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_redirect_port,
        { "Redirect Port", "pfcp.redirect_port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_outer_hdr_desc,
        { "Outer Header Creation Description", "pfcp.outer_hdr_desc",
            FT_UINT16, BASE_DEC, VALS(pfcp_outer_hdr_desc_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_outer_hdr_creation_teid,
        { "TEID", "pfcp.outer_hdr_creation.teid",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_outer_hdr_creation_ipv4,
        { "IPv4 Address", "pfcp.outer_hdr_creation.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_outer_hdr_creation_ipv6,
        { "IPv6 Address", "pfcp.outer_hdr_creation.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_outer_hdr_creation_port,
        { "Port Number", "pfcp.outer_hdr_creation.port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_time_threshold,
        { "Time Threshold", "pfcp.time_threshold",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_forwarding_policy_id_len,
        { "Forwarding Policy Identifier Length", "pfcp.forwarding_policy_id_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_forwarding_policy_id,
        { "Forwarding Policy Identifier", "pfcp.forwarding_policy_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_measurement_method_flags_b0_durat,
        { "DURAT (Duration)", "pfcp.measurement_method_flags.durat",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_measurement_method_flags_b1_volume,
        { "VOLUM (Volume)", "pfcp.measurement_method_flags.volume",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_measurement_method_flags_b2_event,
        { "EVENT (Event)", "pfcp.measurement_method_flags.event",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_subsequent_time_threshold,
        { "Subsequent Time Threshold", "pfcp.subsequent_time_threshold",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_inactivity_detection_time,
        { "Inactivity Detection Time", "pfcp.inactivity_detection_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_monitoring_time,
        { "Monitoring Time", "pfcp.monitoring_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o5_b0_perio,
        { "PERIO (Periodic Reporting)", "pfcp.reporting_triggers_flags.perio",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o5_b1_volth,
        { "VOLTH (Volume Threshold)", "pfcp.reporting_triggers_flags.volth",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o5_b2_timth,
        { "TIMTH (Time Threshold)", "pfcp.reporting_triggers_flags.timth",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o5_b3_quhti,
        { "QUHTI (Quota Holding Time)", "pfcp.reporting_triggers_flags.quhti",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o5_b4_start,
        { "START (Start of Traffic)", "pfcp.reporting_triggers_flags.start",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o5_b5_stopt,
        { "STOPT (Stop of Traffic)", "pfcp.reporting_triggers_flags.stopt",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o5_b6_droth,
        { "DROTH (Dropped DL Traffic Threshold)", "pfcp.reporting_triggers_flags.droth",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o5_b7_liusa,
        { "LIUSA (Linked Usage Reporting)", "pfcp.reporting_triggers_flags.liusa",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o6_b0_volqu,
        { "VOLQU (Volume Quota)", "pfcp.reporting_triggers_flags.volqu",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o6_b1_timqu,
        { "TIMQU (Time Quota)", "pfcp.reporting_triggers_flags.timqu",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o6_b2_envcl,
        { "ENVCL (Envelope Closure)", "pfcp.reporting_triggers_flags.envcl",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o6_b3_macar,
        { "MACAR (MAC Addresses Reporting)", "pfcp.reporting_triggers_flags.macar",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o6_b4_eveth,
        { "EVETH (Event Threshold)", "pfcp.reporting_triggers_flags.eveth",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o6_b5_evequ,
        { "EVEQU (Event Quota)", "pfcp.reporting_triggers_flags.evequ",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o6_b6_ipmjl,
        { "IPMJL (IP Multicast Join/Leave)", "pfcp.reporting_triggers_flags.ipmjl",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o6_b7_quvti,
        { "QUVTI (Quota Validity Time)", "pfcp.reporting_triggers_flags.quvti",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o7_b0_reemr,
        { "REEMR (REport the End Marker Reception)", "pfcp.reporting_triggers_flags.reemr",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_triggers_o7_b1_upint,
        { "UPINT (User Plane Inactivity Timer)", "pfcp.reporting_triggers_flags.upint",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o7_b0_evequ,
        { "EVEQU (Event Quota)", "pfcp.usage_report_trigger_flags.evequ",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o7_b1_tebur,
        { "TEMUR (Termination By UP function Report)", "pfcp.usage_report_trigger_flags.tebur",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o7_b2_ipmjl,
        { "IPMJL (IP Multicast Join/Leave)", "pfcp.usage_report_trigger_flags.ipmjl",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o7_b3_quvti,
        { "QUVTI (Quota Validity Time)", "pfcp.usage_report_trigger_flags.quvti",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o7_b4_emrre,
        { "EMRRE (End Marker Recetion REport)", "pfcp.usage_report_trigger_flags.emrre",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o7_b5_upint,
        { "UPINT (User Plane Inactivity Timer)", "pfcp.usage_report_trigger_flags.upint",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o6_b0_volqu,
        { "VOLQU (Volume Quota)", "pfcp.usage_report_trigger_flags.volqu",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o6_b1_timqu,
        { "TIMQU (Time Quota)", "pfcp.usage_report_trigger_flags.timqu",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o6_b2_liusa,
        { "LIUSA (Linked Usage Reporting)", "pfcp.usage_report_trigger_flags.liusa",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o6_b3_termr,
        { "TERMR (Termination Report)", "pfcp.usage_report_trigger.term",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o6_b4_monit,
        { "MONIT (Monitoring Time)", "pfcp.usage_report_trigger.monit",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o6_b5_envcl,
        { "ENVCL (Envelope Closure)", "pfcp.usage_report_trigger_flags.envcl",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o6_b7_eveth,
        { "EVETH (Event Threshold)", "pfcp.usage_report_trigger_flags.eveth",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o6_b6_macar,
        { "MACAR (MAC Addresses Reporting)", "pfcp.usage_report_trigger_flags.macar",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o5_b0_perio,
        { "PERIO (Periodic Reporting)", "pfcp.usage_report_trigger_flags.perio",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o5_b1_volth,
        { "VOLTH (Volume Threshold)", "pfcp.usage_report_trigger_flags.volth",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o5_b2_timth,
        { "TIMTH (Time Threshold)", "pfcp.usage_report_trigger_flags.timth",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o5_b3_quhti,
        { "QUHTI (Quota Holding Time)", "pfcp.usage_report_trigger_flags.quhti",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o5_b4_start,
        { "START (Start of Traffic)", "pfcp.usage_report_trigger_flags.start",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o5_b5_stopt,
        { "STOPT (Stop of Traffic)", "pfcp.usage_report_trigger_flags.stopt",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o5_b6_droth,
        { "DROTH (Dropped DL Traffic Threshold)", "pfcp.usage_report_trigger_flags.droth",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_report_trigger_o5_b7_immer,
        { "IMMER (Immediate Report)", "pfcp.usage_report_trigger.immer",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },

        { &hf_pfcp_volume_threshold_b0_tovol,
        { "TOVOL", "pfcp.volume_threshold_flags.tovol",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_threshold_b1_ulvol,
        { "ULVOL", "pfcp.volume_threshold_flags.ulvol",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_threshold_b2_dlvol,
        { "DLVOL", "pfcp.volume_threshold_flags.dlvol",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_threshold_tovol,
        { "Total Volume", "pfcp.volume_threshold.tovol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_threshold_ulvol,
        { "Uplink Volume", "pfcp.volume_threshold.ulvol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_threshold_dlvol,
        { "Downlink Volume", "pfcp.volume_threshold.dlvol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_quota_b0_tovol,
        { "TOVOL", "pfcp.volume_quota_flags.tovol",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_quota_b1_ulvol,
        { "ULVOL", "pfcp.volume_quota_flags.ulvol",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_quota_b2_dlvol,
        { "DLVOL", "pfcp.volume_quota_flags.dlvol",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_quota_tovol,
        { "Total Volume", "pfcp.volume_quota.tovol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_quota_ulvol,
        { "Uplink Volume", "pfcp.volume_quota.ulvol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_quota_dlvol,
        { "Downlink Volume", "pfcp.volume_quota.dlvol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_subseq_volume_threshold_b0_tovol,
        { "TOVOL", "pfcp.subseq_volume_threshold.tovol_flg",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_subseq_volume_threshold_b1_ulvol,
        { "ULVOL", "pfcp.subseq_volume_threshold.ulvol_flg",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_subseq_volume_threshold_b2_dlvol,
        { "DLVOL", "pfcp.subseq_volume_threshold.dlvol_flg",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_subseq_volume_threshold_tovol,
        { "Total Volume", "pfcp.subseq_volume_threshold.tovol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_subseq_volume_threshold_ulvol,
        { "Uplink Volume", "pfcp.subseq_volume_threshold.ulvol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_subseq_volume_threshold_dlvol,
        { "Downlink Volume", "pfcp.subseq_volume_threshold.dlvol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_time_quota,
        { "Time Quota", "pfcp.time_quota",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_start_time,
        { "Start Time", "pfcp.start_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_end_time,
        { "End Time", "pfcp.end_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_quota_holding_time,
        { "Quota Holding Time", "pfcp.quota_holding_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_dropped_dl_traffic_threshold_b0_dlpa,
        { "DLPA", "pfcp.dropped_dl_traffic_threshold.dlpa_flg",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_dropped_dl_traffic_threshold_b1_dlby,
        { "DLBY", "pfcp.dropped_dl_traffic_threshold.dlby_flg",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_downlink_packets,
        { "Downlink Packets", "pfcp.downlink_packets",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_bytes_downlink_data,
        { "Bytes of Downlink Data", "pfcp.bytes_downlink_data",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_qer_correlation_id,
        { "QER Correlation ID", "pfcp.qer_correlation_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_gate_status_b0b1_dlgate,
        { "DL Gate", "pfcp.gate_status.dlgate",
            FT_UINT8, BASE_DEC, VALS(pfcp_gate_status_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_pfcp_gate_status_b3b2_ulgate,
        { "UL Gate", "pfcp.gate_status.ulgate",
            FT_UINT8, BASE_DEC, VALS(pfcp_gate_status_vals), 0x0c,
            NULL, HFILL }
        },
        { &hf_pfcp_ul_mbr,
        { "UL MBR", "pfcp.ul_mbr",
            FT_UINT40, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_dl_mbr,
        { "DL MBR", "pfcp.dl_mbr",
            FT_UINT40, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ul_gbr,
        { "UL GBR", "pfcp.ul_gbr",
            FT_UINT40, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_dl_gbr,
        { "DL GBR", "pfcp.dl_gbr",
            FT_UINT40, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_report_type_b6_uisr,
        { "UISR (UP Initiated Session Request)", "pfcp.report_type.uisr",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_pfcp_report_type_b5_sesr,
        { "SESR (Session Report)", "pfcp.report_type.sesr",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_pfcp_report_type_b4_tmir,
        { "TMIR (TSC Management Information Report)", "pfcp.report_type.tmir",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_report_type_b3_upir,
        { "UPIR (User Plane Inactivity Report)", "pfcp.report_type.upir",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_report_type_b2_erir,
        { "ERIR (Error Indication Report)", "pfcp.report_type.erir",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_report_type_b1_usar,
        { "USAR (Usage Report)", "pfcp.report_type.usar",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_report_type_b0_dldr,
        { "DLDR (Downlink Data Report)", "pfcp.report_type.dldr",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_offending_ie,
        { "Type of the offending IE", "pfcp.offending_ie",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &pfcp_ie_type_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_offending_ie_value,
        { "Type of the offending IE", "pfcp.offending_ie",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_up_function_features_o5_b0_bucp,
        { "BUCP", "pfcp.up_function_features.bucp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "Downlink Data Buffering in CP function", HFILL }
        },
        { &hf_pfcp_up_function_features_o5_b1_ddnd,
        { "DDND", "pfcp.up_function_features.ddnd",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            "Buffering parameter 'Downlink Data Notification Delay", HFILL }
        },
        { &hf_pfcp_up_function_features_o5_b2_dlbd,
        { "DLBD", "pfcp.up_function_features.dlbd",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_up_function_features_o5_b3_trst,
        { "TRST", "pfcp.up_function_features.trst",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            "Traffic Steering", HFILL }
        },
        { &hf_pfcp_up_function_features_o5_b4_ftup,
        { "FTUP", "pfcp.up_function_features.ftup",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            "F-TEID allocation / release in the UP function", HFILL }
        },
        { &hf_pfcp_up_function_features_o5_b5_pfdm,
        { "PFDM", "pfcp.up_function_features.pfdm",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            "PFD Management procedure", HFILL }
        },
        { &hf_pfcp_up_function_features_o5_b6_heeu,
        { "HEEU", "pfcp.up_function_features.heeu",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            "Header Enrichment of Uplink traffic", HFILL }
        },
        { &hf_pfcp_up_function_features_o5_b7_treu,
        { "TREU", "pfcp.up_function_features.treu",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            "Traffic Redirection Enforcement in the UP function", HFILL }
        },
        { &hf_pfcp_up_function_features_o6_b0_empu,
        { "EMPU", "pfcp.up_function_features.empu",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "Sending of End Marker packets", HFILL }
        },
        { &hf_pfcp_up_function_features_o6_b1_pdiu,
        { "PDIU", "pfcp.up_function_features.pdiu",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            "Support of PDI optimised signalling", HFILL }
        },
        { &hf_pfcp_up_function_features_o6_b2_udbc,
        { "UDBC", "pfcp.up_function_features.udbc",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            "Support of UL/DL Buffering Control", HFILL }
        },
        { &hf_pfcp_up_function_features_o6_b3_quoac,
        { "QUOAC", "pfcp.up_function_features.quoac",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            "The UP function supports being provisioned with the Quota Action to apply when reaching quotas", HFILL }
        },
        { &hf_pfcp_up_function_features_o6_b4_trace,
        { "TRACE", "pfcp.up_function_features.trace",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            "The UP function supports Trace", HFILL }
        },
        { &hf_pfcp_up_function_features_o6_b5_frrt,
        { "FRRT", "pfcp.up_function_features.frrt",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            "The UP function supports Framed Routing", HFILL }
        },
        { &hf_pfcp_up_function_features_o6_b6_pfde,
        { "PFDE", "pfcp.up_function_features.pfde",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            "The UP function supports a PFD Contents including a property with multiple values", HFILL }
        },
        { &hf_pfcp_up_function_features_o6_b7_epfar,
        { "EPFAR", "pfcp.up_function_features.epfar",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            "The UP function supports the Enhanced PFCP Association Release feature", HFILL }
        },
        { &hf_pfcp_up_function_features_o7_b0_dpdra,
        { "DPDRA", "pfcp.up_function_features.dpdra",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "The UP function supports Deferred PDR Activation or Deactivation", HFILL }
        },
        { &hf_pfcp_up_function_features_o7_b1_adpdp,
        { "ADPDP", "pfcp.up_function_features.adpdp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            "The UP function supports the Activation and Deactivation of Pre-defined PDRs", HFILL }
        },
        { &hf_pfcp_up_function_features_o7_b2_ueip,
        { "UEIP", "pfcp.up_function_features.ueip",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            "The UP function supports allocating UE IP addresses or prefixes", HFILL }
        },
        { &hf_pfcp_up_function_features_o7_b3_sset,
        { "SSET", "pfcp.up_function_features.sset",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            "UP function support of PFCP sessions successively controlled by different SMFs of a same SMF", HFILL }
        },
        { &hf_pfcp_up_function_features_o7_b4_mnop,
        { "MNOP", "pfcp.up_function_features.mnop",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            "UPF supports measurement of number of packets which is instructed with the flag 'Measurement of Number of Packets' in a URR", HFILL }
        },
        { &hf_pfcp_up_function_features_o7_b5_mte_n4,
        { "MTE N4", "pfcp.up_function_features.mte_n4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            "UPF supports multiple instances of Traffic Endpoint IDs in a PDI", HFILL }
        },
        { &hf_pfcp_up_function_features_o7_b6_bundl,
        { "BUNDL", "pfcp.up_function_features.bundl",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            "PFCP messages bundling", HFILL }
        },
        { &hf_pfcp_up_function_features_o7_b7_gcom,
        { "GCOM", "pfcp.up_function_features.gcom",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            "UPF support of 5G VN Group Communication", HFILL }
        },
        { &hf_pfcp_up_function_features_o8_b0_mpas,
        { "MPAS", "pfcp.up_function_features.mpas",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "UPF support for multiple PFCP associations to the SMFs in an SMF set", HFILL }
        },
        { &hf_pfcp_up_function_features_o8_b1_rttl,
        { "RTTL", "pfcp.up_function_features.rttl",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            "The UP function supports redundant transmission at transport layer", HFILL }
        },
        { &hf_pfcp_up_function_features_o8_b2_vtime,
        { "VTIME", "pfcp.up_function_features.vtime",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            "UPF support of quota validity time feature", HFILL }
        },
        { &hf_pfcp_up_function_features_o8_b3_norp,
        { "NORP", "pfcp.up_function_features.norp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            "UP function support of Number of Reports", HFILL }
        },
        { &hf_pfcp_up_function_features_o8_b4_iptv,
        { "IPTV", "pfcp.up_function_features.iptv",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            "UPF support of IPTV service", HFILL }
        },
        { &hf_pfcp_up_function_features_o8_b5_ip6pl,
        { "IP6PL", "pfcp.up_function_features.ip6pl",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            "UPF supports UE IPv6 address(es) allocation with IPv6 prefix length other than default /64", HFILL }
        },
        { &hf_pfcp_up_function_features_o8_b6_tscu,
        { "TSCU", "pfcp.up_function_features.tscu",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            "Time Sensitive Communication is supported by the UPF", HFILL }
        },
        { &hf_pfcp_up_function_features_o8_b7_mptcp,
        { "MPTCP", "pfcp.up_function_features.mptcp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            "UPF support of MPTCP Proxy functionality", HFILL }
        },
        { &hf_pfcp_up_function_features_o9_b0_atsss_ll,
        { "ATSSS-LL", "pfcp.up_function_features.atsss_ll",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "UPF support of ATSSS-LLL steering functionality", HFILL }
        },
        { &hf_pfcp_up_function_features_o9_b1_qfqm,
        { "QFQM", "pfcp.up_function_features.qfqm",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            "UPF support of per QoS flow per UE QoS monitoring", HFILL }
        },
        { &hf_pfcp_up_function_features_o9_b2_gpqm,
        { "GPQM", "pfcp.up_function_features.gpqm",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            "UPF support of per GTP-U Path QoS monitoring", HFILL }
        },
        { &hf_pfcp_up_function_features_o9_b3_mt_edt,
        { "MT-EDT", "pfcp.up_function_features.mtedt",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            "SGW-U support of reporting the size of DL Data Packets", HFILL }
        },
        { &hf_pfcp_up_function_features_o9_b4_ciot,
        { "CIOT", "pfcp.up_function_features.ciot",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            "UPF support of CIoT feature", HFILL }
        },
        { &hf_pfcp_up_function_features_o9_b5_ethar,
        { "ETHAR", "pfcp.up_function_features.ethar",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            "UPF support of Ethernet PDU Session Anchor Relocation", HFILL }
        },
        { &hf_pfcp_up_function_features_o9_b6_ddds,
        { "DDDS", "pfcp.up_function_features.ddds",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            "UPF support of reporting of the first buffred / discarded data for downlink", HFILL }
        },
        { &hf_pfcp_up_function_features_o9_b7_rds,
        { "RDS", "pfcp.up_function_features.rds",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            "UP function support of Reliable Data Service", HFILL }
        },
        { &hf_pfcp_up_function_features_o10_b0_rttwp,
        { "RTTWP", "pfcp.up_function_features.rttwp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "UPF support of RTT measurement towards the UE without PMF", HFILL }
        },
        { &hf_pfcp_up_function_features_o10_b1_quosf,
        { "QUOSF", "pfcp.up_function_features.quosf",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            "UP function supports being provisioned with the Quota Action Application ID or a Quota Action SDF Filter to apply when reaching quotas", HFILL }
        },
        { &hf_pfcp_up_function_features_o10_b2_nspoc,
        { "NSPOC", "pfcp.up_function_features.nspoc",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            "UP function supports notifying start of Pause of Charging via user plane", HFILL }
        },
        { &hf_pfcp_up_function_features_o10_b3_l2tp,
        { "L2TP", "pfcp.up_function_features.l2tp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            "UP function supports L2TP", HFILL }
        },
        { &hf_pfcp_up_function_features_o10_b4_upber,
        { "UPBER", "pfcp.up_function_features.upber",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            "UP function supports the uplink packet buffering during EAS relocation", HFILL }
        },
        { &hf_pfcp_up_function_features_o10_b5_resps,
        { "RESPS", "pfcp.up_function_features.resps",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            "UP function supports Restoration of PFCP Session association", HFILL }
        },
        { &hf_pfcp_up_function_features_o10_b6_iprep,
        { "IPREP", "pfcp.up_function_features.iprep",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            "UP function supports IP Address and Port number replacement", HFILL }
        },
        { &hf_pfcp_up_function_features_o10_b7_dnsts,
        { "DNSTS", "pfcp.up_function_features.dnsts",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            "UP function support DNS Traffic Steering based on FQDN in the DNS Query message", HFILL }
        },
        { &hf_pfcp_up_function_features_o11_b0_drqos,
        { "DRQOS", "pfcp.up_function_features.drqos",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "UP function supports Direct Reporting of QoS monitoring events to Local NEF or AF", HFILL }
        },
        { &hf_pfcp_up_function_features_o11_b1_mbsn4,
        { "MBSN4", "pfcp.up_function_features.mbsn4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            "UPF supports sending MBS multicast session data to associated PDU sessions using 5GC individual delivery", HFILL }
        },
        { &hf_pfcp_up_function_features_o11_b2_psuprm,
        { "MBSN4", "pfcp.up_function_features.mbsn4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            "UP function supports Per Slice UP Resource Management", HFILL }
        },
        { &hf_pfcp_up_function_features_o11_b3_eppi,
        { "EPPI", "pfcp.up_function_features.eppi",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            "UP function supports Enhanced Provisioning of Paging Policy Indicator", HFILL }
        },
        { &hf_pfcp_up_function_features_o11_b4_ratp,
        { "RATP", "pfcp.up_function_features.ratp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            "UP function supports Redirection Address Types set to Port, IPv4 address and Port, IPv6 address and Port, or IPv4 and IPv6 addresses and Port", HFILL }
        },
        { &hf_pfcp_up_function_features_o11_b5_upidp,
        { "UPIDP", "pfcp.up_function_features.upidp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            "UP function supports User Plane Inactivity Detection and reporting per PDR", HFILL }
        },

        { &hf_pfcp_sequence_number,
        { "Sequence Number", "pfcp.sequence_number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_metric,
        { "Metric", "pfcp.metric",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_timer_unit,
        { "Timer unit", "pfcp.timer_unit",
            FT_UINT8, BASE_DEC, VALS(pfcp_timer_unit_vals), 0xe0,
            NULL, HFILL }
        },
        { &hf_pfcp_timer_value,
        { "Timer value", "pfcp.timer_value",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_measurement_b0_tovol,
        { "TOVOL", "pfcp.volume_measurement_flags.tovol",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_measurement_b1_ulvol,
        { "ULVOL", "pfcp.volume_measurement_flags.ulvol",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_measurement_b2_dlvol,
        { "DLVOL", "pfcp.volume_measurement_flags.dlvol",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_measurement_b3_tonop,
        { "TONOP", "pfcp.volume_measurement_flags.tonop",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_measurement_b4_ulnop,
        { "ULNOP", "pfcp.volume_measurement_flags.ulnop",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_volume_measurement_b5_dlnop,
        { "DLNOP", "pfcp.volume_measurement_flags.dlnops",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_pfcp_vol_meas_tovol,
        { "Total Volume", "pfcp.volume_measurement.tovol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_vol_meas_ulvol,
        { "Uplink Volume", "pfcp.volume_measurement.ulvol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_vol_meas_dlvol,
        { "Downlink Volume", "pfcp.volume_measurement.dlvol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_vol_meas_tonop,
        { "Total Number of Packets", "pfcp.volume_measurement.tonop",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_vol_meas_ulnop,
        { "Uplink Number of Packets", "pfcp.volume_measurement.ulnop",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_vol_meas_dlnop,
        { "Downlink Number of Packets", "pfcp.volume_measurement.dlnop",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_cp_function_features_o5_b0_load,
        { "LOAD", "pfcp.cp_function_features.load",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "Load Control", HFILL }
        },
        { &hf_pfcp_cp_function_features_o5_b1_ovrl,
        { "OVRL", "pfcp.cp_function_features.ovrl",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            "Overload Control", HFILL }
        },
        { &hf_pfcp_cp_function_features_o5_b2_epfar,
        { "EPFAR", "pfcp.cp_function_features.epfar",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            "The CP function supports the Enhanced PFCP Association Release feature", HFILL }
        },
        { &hf_pfcp_cp_function_features_o5_b3_sset,
        { "SSET", "pfcp.cp_function_features.sset",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            "SMF support of PFCP sessions successively controlled by different SMFs of a same SMF Set", HFILL }
        },
        { &hf_pfcp_cp_function_features_o5_b4_bundl,
        { "BUNDL", "pfcp.cp_function_features.bundl",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            "PFCP messages bundling", HFILL }
        },
        { &hf_pfcp_cp_function_features_o5_b5_mpas,
        { "MPAS", "pfcp.cp_function_features.mpas",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            "SMF support for multiple PFCP associations from an SMF set to a single UPF", HFILL }
        },
        { &hf_pfcp_cp_function_features_o5_b6_ardr,
        { "ARDR", "pfcp.cp_function_features.ardr",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            "CP function supports Additional Usage Reports in the PFCP Session Deletion Response", HFILL }
        },
        { &hf_pfcp_cp_function_features_o5_b7_uiaur,
        { "UIAUR", "pfcp.cp_function_features.uiaur",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            "CP function supports the UE IP Address Usage Reporting feature", HFILL }
        },
        { &hf_pfcp_cp_function_features_o6_b0_psucc,
        { "PSUCC", "pfcp.cp_function_features.psucc",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "CP function supports PFCP session establishment or modification with Partial Success", HFILL }
        },
        { &hf_pfcp_cp_function_features_o6_b1_rpgur,
        { "RPGUR", "pfcp.cp_function_features.rpgur",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            "CP function supports the Peer GTP-U Entity Restart Reporting", HFILL }
        },

        { &hf_pfcp_usage_information_b0_bef,
        { "BEF (Before)", "pfcp.usage_information.bef",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_information_b1_aft,
        { "AFT (After)", "pfcp.usage_information.aft",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_information_b2_uae,
        { "UAE (Usage After Enforcement)", "pfcp.usage_information.uae",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_usage_information_b3_ube,
        { "UBE (Usage Before Enforcement)", "pfcp.usage_information.ube",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_application_instance_id,
        { "Application Instance Identifier", "pfcp.application_instance_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_application_instance_id_str,
        { "Application Instance Identifier", "pfcp.application_instance_id_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_flow_dir,
        { "Flow Direction", "pfcp.flow_dir",
            FT_UINT8, BASE_DEC, VALS(pfcp_flow_dir_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_rate_b0_ulpr,
        { "ULPR (Uplink Packet Rate)", "pfcp.packet_rate.ulpr",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_rate_b1_dlpr,
        { "DLPR (Downlink Packet Rate)", "pfcp.packet_rate.dlpr",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_rate_b2_aprc,
        { "APRC (Additional Packet Rate Control)", "pfcp.packet_rate.aprc",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_ul_time_unit,
        { "Uplink Time Unit", "pfcp.ul_time_unit",
            FT_UINT8, BASE_DEC, VALS(pfcp_pr_time_unit_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_pfcp_max_ul_pr,
        { "Maximum Uplink Packet Rate", "pfcp.max_ul_pr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_dl_time_unit,
        { "Downlink Time Unit", "pfcp.dl_time_unit",
            FT_UINT8, BASE_DEC, VALS(pfcp_pr_time_unit_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_pfcp_max_dl_pr,
        { "Maximum Downlink Packet Rate", "pfcp.max_dl_pr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_a_ul_time_unit,
        { "Additional Uplink Time Unit", "pfcp.a_ul_time_unit",
            FT_UINT8, BASE_DEC, VALS(pfcp_pr_time_unit_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_pfcp_a_max_ul_pr,
        { "Additional Maximum Uplink Packet Rate", "pfcp.a_max_ul_pr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_a_dl_time_unit,
        { "Additional Downlink Time Unit", "pfcp.a_dl_time_unit",
            FT_UINT8, BASE_DEC, VALS(pfcp_pr_time_unit_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_pfcp_a_max_dl_pr,
        { "Additional Maximum Downlink Packet Rate", "pfcp.a_max_dl_pr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_dl_flow_level_marking_b0_ttc,
        { "TTC (ToS/Traffic Class)", "pfcp.dl_flow_level_marking.ttc",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_dl_flow_level_marking_b1_sci,
        { "SCI(Service Class Indicator)", "pfcp.dl_flow_level_marking.sci",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_sci,
        { "Service Class Indicator", "pfcp.sci",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_dl_data_notification_delay,
        { "Delay Value", "pfcp.dl_data_notification_delay",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Delay Value in integer multiples of 50 millisecs, or zero", HFILL }
        },
        { &hf_pfcp_packet_count,
        { "Packet Count", "pfcp.packet_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_dl_data_service_inf_b0_ppi,
        { "PPI(Paging Policy Indication)", "pfcp.dl_data_service_inf.ppi",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_dl_data_service_inf_b1_qfii,
        { "QFII(QoS Flow Identifier)", "pfcp.dl_data_service_inf.qfii",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_ppi,
        { "Paging Policy Indication", "pfcp.ppi",
            FT_UINT16, BASE_DEC, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_pfcp_pfcpsmreq_flags_b0_drobu,
        { "DROBU (Drop Buffered Packets)", "pfcp.smreq_flags.drobu",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_pfcpsmreq_flags_b1_sndem,
        { "SNDEM (Send End Marker Packets)", "pfcp.smreq_flags.sndem",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_pfcpsmreq_flags_b2_qaurr,
        { "QAURR (Query All URRs)", "pfcp.smreq_flags.qaurr",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_pfcpsmreq_flags_b3_sumpc,
        { "SUMPC (Stop of Usage Measurement to Pause Charging)", "pfcp.smreq_flags.sumpc",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_pfcpsmreq_flags_b4_rumuc,
        { "RUMUC (Resume of Usage Measurement to Un-pause of Charging)", "pfcp.smreq_flags.rumuc",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_pfcpsrrsp_flags_b0_drobu,
        { "DROBU (Drop Buffered Packets)", "pfcp.srrsp_flags.drobu",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_pfd_contents_flags_b0_fd,
        { "FD (Flow Description)", "pfcp.pfd_contents_flags.fd",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_pfd_contents_flags_b1_url,
        { "URL (URL)", "pfcp.pfd_contents_flags.url",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_pfd_contents_flags_b2_dn,
        { "DN (Domain Name)", "pfcp.pfd_contents_flags.dn",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_pfd_contents_flags_b3_cp,
        { "CP (Custom PFD Content)", "pfcp.pfd_contents_flags.cp",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_pfd_contents_flags_b4_dnp,
        { "DNP (Domain Name Protocol)", "pfcp.pfd_contents_flags.dnp",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_pfd_contents_flags_b5_afd,
        { "AFD (Additional Flow Description)", "pfcp.pfd_contents_flags.afd",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_pfcp_pfd_contents_flags_b6_aurl,
        { "AURL (Additional URL)", "pfcp.pfd_contents_flags.aurl",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_pfcp_pfd_contents_flags_b7_adnp,
        { "ADNP (Additional Domain Name and Domain Name Protocol)", "pfcp.pfd_contents_flags.adnp",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_pfcp_url_len,
        { "Length of URL", "pfcp.url_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_url,
        { "URL", "pfcp.url",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_dn_len,
        { "Length of Domain Name", "pfcp.dn_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_dn,
        { "Domain Name", "pfcp.dn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_cp_len,
        { "Length of Custom PFD Content", "pfcp.cp_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_cp,
        { "Custom PFD Content", "pfcp.cp",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_dnp_len,
        { "Length of Domain Name Protocol", "pfcp.dnp_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_dnp,
        { "Domain Name Protocol", "pfcp.dn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_afd_len,
        { "Length of Additional Flow Description", "pfcp.adf_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_aurl_len,
        { "Length of Additional URL", "pfcp.aurl_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_adnp_len,
        { "Length of Additional Domain Name and Domain Name Protocol", "pfcp.adnp_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_header_type,
        { "Header Type", "pfcp.header_type",
            FT_UINT8, BASE_DEC, VALS(pfcp_header_type_vals), 0x1f,
            NULL, HFILL }
        },
        { &hf_pfcp_hf_len,
        { "Length of Header Field Name", "pfcp.hf_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_hf_name,
        { "Header Field Name", "pfcp.hf_name",
            FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_hf_val_len,
        { "Length of Header Field Value", "pfcp.hf_val_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_hf_val,
        { "Header Field Value", "pfcp.hf_val",
            FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_measurement_info_b0_mbqe,
        { "MBQE (Measurement Before QoS Enforcement)", "pfcp.measurement_info.fd",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_measurement_info_b1_inam,
        { "INAM (Inactive Measurement)", "pfcp.measurement_info.inam",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_measurement_info_b2_radi,
        { "RADI (Reduced Application Detection Information)", "pfcp.measurement_info.radi",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_measurement_info_b3_istm,
        { "ISTM (Immediate Start Time Metering)", "pfcp.measurement_info.istm",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_measurement_info_b4_mnop,
        { "MNOP (Measurement of Number of Packets)", "pfcp.measurement_info.mnop",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_measurement_info_b5_sspoc,
        { "SSPOC (Send Start Pause of Charging)", "pfcp.measurement_info.sspoc",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_pfcp_measurement_info_b6_aspoc,
        { "ASPOC (Applicable for Start Pause of Charging)", "pfcp.measurement_info.aspoc",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_pfcp_measurement_info_b7_ciam,
        { "CIAM (Control of Inactive Measurement)", "pfcp.measurement_info.ciam",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_pfcp_node_report_type_b0_upfr,
        { "UPFR (User Plane Path Failure Report)", "pfcp.node_report_type.upfr",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_node_report_type_b1_uprr,
        { "UPRR (User Plane Path Recovery Report)", "pfcp.node_report_type.uprr",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_node_report_type_b2_ckdr,
        { "CKDR (Clock Drift Report)", "pfcp.node_report_type.ckdr",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_node_report_type_b3_gpqr,
        { "GPQR (GTP-U Path QoS Report)", "pfcp.node_report_type.gpqr",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_node_report_type_b4_purr,
        { "PURR (peer GTP-U entity Restart Report)", "pfcp.node_report_type.purr",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_node_report_type_b5_vsr,
        { "VSR (Vendor-Specific Report)", "pfcp.node_report_type.pvsrurr",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },

        { &hf_pfcp_remote_gtp_u_peer_flags_b0_v6,
        { "V6 (IPv6)", "pfcp.remote_gtp_u_peer_flags.v6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_remote_gtp_u_peer_flags_b1_v4,
        { "V4 (IPv4)", "pfcp.remote_gtp_u_peer_flags.v4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_remote_gtp_u_peer_flags_b2_di,
        { "DI (Destination Interface)", "pfcp.remote_gtp_u_peer_flags.di",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_remote_gtp_u_peer_flags_b3_ni,
        { "NI (Network Instance)", "pfcp.remote_gtp_u_peer_flags.ni",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_remote_gtp_u_peer_ipv4,
        { "IPv4 address", "pfcp.node_id_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_remote_gtp_u_peer_ipv6,
        { "IPv6 address", "pfcp.node_id_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_remote_gtp_u_peer_length_di,
        { "Length of Destination Interface field", "pfcp.node_id_length_di",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_remote_gtp_u_peer_length_ni,
        { "Length of Network Instance field", "pfcp.node_id_length_ni",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_ur_seqn,
        { "UR-SEQN", "pfcp.ur_seqn",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_oci_flags_b0_aoci,
        { "AOCI: Associate OCI with Node ID", "pfcp.oci_flags.aoci",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_pfcp_assoc_rel_req_b0_sarr,
        { "SARR (PFCP Association Release Request)", "pfcp.assoc_rel_req.sarr",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_upiri_flg_b6_assosi,
        { "ASSOSI (Associated Source Instance)", "pfcp.upiri_flags.assosi",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x40,
            NULL, HFILL }
        },
        { &hf_pfcp_upiri_flg_b5_assoni,
        { "ASSONI (Associated Network Instance)", "pfcp.upiri_flags.assoni",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x20,
            NULL, HFILL }
        },
        { &hf_pfcp_upiri_flg_b2b4_teidri,
        { "TEIDRI (TEID Range Indication)", "pfcp.upiri_flags.teidri",
            FT_UINT8, BASE_HEX, NULL, 0x1c,
            NULL, HFILL }
        },
        { &hf_pfcp_upiri_flags_b1_v6,
        { "V6 (IPv6)", "pfcp.upiri_flags.v6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_upiri_flags_b0_v4,
        { "V4 (IPv4)", "pfcp.upiri_flags.v4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_upiri_teidri,
        { "TEID Range Indication", "pfcp.upiri.teidri",
            FT_UINT8, BASE_DEC, NULL, 0x1C,
            NULL, HFILL }
        },
        { &hf_pfcp_upiri_teid_range,
        { "TEID", "pfcp.upiri.teid_range",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_upiri_ipv4,
        { "IPv4 address", "pfcp.upiri.ipv4_addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_upiri_ipv6,
        { "IPv6 address", "pfcp.upiri.ipv6_addr",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_user_plane_inactivity_timer,
        { "User Plane Inactivity Timer", "pfcp.user_plane_inactivity_time",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
            NULL, HFILL }
        },

        { &hf_pfcp_subsequent_volume_quota_b0_tovol,
        { "TOVOL", "pfcp.subsequent_volume_quota_flags.tovol",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_subsequent_volume_quota_b1_ulvol,
        { "ULVOL", "pfcp.subsequent_volume_quota_flags.ulvol",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_subsequent_volume_quota_b2_dlvol,
        { "DLVOL", "pfcp.subsequent_volume_quota_flags.dlvol",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_subsequent_volume_quota_tovol,
        { "Total Volume", "pfcp.subsequent_volume_quota.tovol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_subsequent_volume_quota_ulvol,
        { "Uplink Volume", "pfcp.subsequent_volume_quota.ulvol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_subsequent_volume_quota_dlvol,
        { "Downlink Volume", "pfcp.subsequent_volume_quota.dlvol",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_subsequent_time_quota,
        { "Subsequent Time Quota", "pfcp.subsequent_time_quota",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_rqi_flag,
        { "RQI", "pfcp.rqi_flag",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_qfi,
        { "QFI", "pfcp.qfi_value",
            FT_UINT8, BASE_HEX, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_pfcp_query_urr_reference,
        { "Query URR Reference", "pfcp.query_urr_reference",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_additional_usage_reports_information_b15_auri,
        { "AURI (Additional Usage Reports Indication)", "pfcp.additional_usage_reports_information_auri",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_pfcp_additional_usage_reports_information_b14_b0_number_value,
        { "Number of Additional Usage Reports value", "pfcp.additional_usage_reports_information_value",
            FT_UINT16, BASE_DEC, NULL, 0x7FFF,
            NULL, HFILL }
        },
        { &hf_pfcp_traffic_endpoint_id,
        { "Traffic Endpoint ID", "pfcp.traffic_endpoint_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_mac_address_flags_b0_sour,
        { "SOUR", "pfcp.mac_address.flags.sour",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_mac_address_flags_b1_dest,
        { "DEST", "pfcp.mac_address.flags.dest",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_mac_address_flags_b2_usou,
        { "USUO", "pfcp.mac_address.flags.usuo",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_mac_address_flags_b3_udes,
        { "UDES", "pfcp.mac_address.flags.udes",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_mac_address_source_mac_address,
        { "Source MAC Address", "pfcp.mac_address.sour",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mac_address_dest_mac_address,
        { "Destination MAC Address", "pfcp.mac_address.dest",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mac_address_upper_source_mac_address,
        { "Upper Source MAC Address", "pfcp.mac_address.usou",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mac_address_upper_dest_mac_address,
        { "Upper Destination MAC Address", "pfcp.mac_address.udes",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_c_tag_flags_b0_pcp,
        { "PCP", "pfcp.c_tag.flags.pcp",
            FT_BOOLEAN, 8, NULL, 0x01,
            "Priority code point", HFILL }
        },
        { &hf_pfcp_c_tag_flags_b1_dei,
        { "DEI", "pfcp.c_tag.flags.dei",
            FT_BOOLEAN, 8, NULL, 0x02,
            "Drop eligible indicator", HFILL }
        },
        { &hf_pfcp_c_tag_flags_b2_vid,
        { "VID", "pfcp.c_tag.flags.vid",
            FT_BOOLEAN, 8, NULL, 0x04,
            "VLAN identifier", HFILL }
        },
        { &hf_pfcp_c_tag_cvid,
        { "C-VID", "pfcp.c_tag.cvid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_c_tag_dei_flag,
        { "Drop eligible indicator (DEI)", "pfcp.c_tag.dei_flag",
            FT_BOOLEAN, 8, TFS(&tfs_eligible_ineligible), 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_c_tag_pcp_value,
        { "Priority code point (PCP)", "pfcp.c_tag.pcp",
            FT_UINT8, BASE_DEC, VALS(pfcp_vlan_tag_pcp_vals), 0x07,
            NULL, HFILL }
        },

        { &hf_pfcp_s_tag_flags_b0_pcp,
        { "PCP", "pfcp.s_tag.flags.pcp",
            FT_BOOLEAN, 8, NULL, 0x01,
            "Priority code point", HFILL }
        },
        { &hf_pfcp_s_tag_flags_b1_dei,
        { "DEI", "pfcp.s_tag.flags.dei",
            FT_BOOLEAN, 8, NULL, 0x02,
            "Drop eligible indicator", HFILL }
        },
        { &hf_pfcp_s_tag_flags_b2_vid,
        { "VID", "pfcp.s_tag.flags.vid",
            FT_BOOLEAN, 8, NULL, 0x04,
            "VLAN identifier", HFILL }
        },
        { &hf_pfcp_s_tag_svid,
        { "S-VID", "pfcp.s_tag.svid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_s_tag_dei_flag,
        { "Drop eligible indicator (DEI)", "pfcp.s_tag.dei_flag",
            FT_BOOLEAN, 8, TFS(&tfs_eligible_ineligible), 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_s_tag_pcp_value,
        { "Priority code point (PCP)", "pfcp.s_tag.pcp",
            FT_UINT8, BASE_DEC, VALS(pfcp_vlan_tag_pcp_vals), 0x07,
            NULL, HFILL }
        },

        { &hf_pfcp_ethertype,
        { "Ethertype", "pfcp.ethertype",
            FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_proxying_flags_b0_arp,
        { "ARP", "pfcp.proxying.flags.arp",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_proxying_flags_b1_ins,
        { "INS", "pfcp.proxying.flags.ins",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },

        { &hf_pfcp_ethertype_filter_id,
        { "Ethertype Filter ID", "pfcp.ethertype_filter_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_ethertype_filter_properties_flags_b0_bide,
        { "BIDE", "pfcp.ethertype_filter_properties.flags.bide",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_suggested_buffering_packets_count_packet_count,
        { "Packet count", "pfcp.suggested_buffering_packets_count.packet_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_user_id_flags_b0_imsif,
        { "IMSIF", "pfcp.user_id.flags.imsif",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_flags_b1_imeif,
        { "IMEIF", "pfcp.user_id.flags.imeif",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_flags_b2_msisdnf,
        { "MSISDNF", "pfcp.user_id.flags.msisdnf",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_flags_b3_naif,
        { "NAIF", "pfcp.user_id.flags.naif",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_flags_b4_supif,
        { "SUPIF", "pfcp.user_id.flags.supif",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_flags_b5_gpsif,
        { "GPSIF", "pfcp.user_id.flags.gpsif",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x20,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_flags_b6_peif,
        { "PEIF", "pfcp.user_id.flags.peif",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x40,
            NULL, HFILL }
        },

        { &hf_pfcp_user_id_length_of_imsi,
        { "Length of IMSI", "pfcp.user_id.length_of_imsi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_length_of_imei,
        { "Length of IMEI", "pfcp.user_id.length_of_imei",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_imei,
        { "IMEI", "pfcp.user_id.imei",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_length_of_msisdn,
        { "Length of MSISDN", "pfcp.user_id.length_of_msisdn",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_length_of_nai,
        { "Length of NAI", "pfcp.user_id.length_of_nai",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_nai,
        { "NAI", "pfcp.user_id.nai",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_length_of_supi,
        { "Length of SUPI", "pfcp.user_id.length_of_supi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_supi,
        { "SUPI", "pfcp.user_id.supi",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_length_of_gpsi,
        { "Length of GPSI", "pfcp.user_id.length_of_gpsi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_gpsi,
        { "GPSI", "pfcp.user_id.gpsi",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_length_of_pei,
        { "Length of PEI", "pfcp.user_id.length_of_pei",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_user_id_pei,
        { "PEI", "pfcp.user_id.pei",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_ethernet_pdu_session_information_flags_b0_ethi,
        { "IMSIF", "pfcp.ethernet_pdu_session_information.flags.ethi",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_mac_addresses_detected_number_of_mac_addresses,
        { "Number of MAC addresses", "pfcp.mac_addresses_detected.number_of_mac_addresses",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mac_addresses_detected_mac_address,
        { "MAC Address", "pfcp.mac_addresses_detected.mac_address",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mac_addresses_detected_length_of_ctag,
        { "Length of C-TAG", "pfcp.mac_addresses_detected.length_of_ctag",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mac_addresses_detected_length_of_stag,
        { "Length of S-TAG", "pfcp.mac_addresses_detected.length_of_stag",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_mac_addresses_removed_number_of_mac_addresses,
        { "Number of MAC addresses", "pfcp.mac_addresses_removed.number_of_mac_address",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mac_addresses_removed_mac_address,
        { "MAC Address", "pfcp.mac_addresses_removed.mac_addresses",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mac_addresses_removed_length_of_ctag,
        { "Length of C-TAG", "pfcp.mac_addresses_removed.length_of_ctag",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mac_addresses_removed_length_of_stag,
        { "Length of S-TAG", "pfcp.mac_addresses_removed.length_of_stag",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_ethernet_inactivity_timer,
        { "Ethernet Inactivity Timer", "pfcp.ethernet",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
            NULL, HFILL }
        },

        { &hf_pfcp_subsequent_event_quota,
        { "Subsequent Event Quota", "pfcp.subsequent_event_quota",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_pfcp_subsequent_event_threshold,
        { "Subsequent Event Threshold", "pfcp.subsequent_event_threshold",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_pfcp_trace_information_trace_id,
        { "Trace ID", "pfcp.trace_information.traceid",
            FT_UINT24, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_trace_information_length_trigger_events,
        { "Length of Trigger Events", "pfcp.trace_information.length_trigger_events",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_trace_information_trigger_events,
        { "Trigger Events", "pfcp.trace_information.trigger_events",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_trace_information_session_trace_depth,
        { "Session Trace Depth", "pfcp.trace_information.session_trace_depth",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_trace_information_length_list_interfaces,
        { "Length of List of Interfaces", "pfcp.trace_information.length_list_interfaces",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_trace_information_list_interfaces,
        { "List of Interfaces", "pfcp.trace_information.list_interfaces",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_trace_information_length_ipaddress,
        { "Length of IP Address", "pfcp.trace_information.length_ipaddress",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_trace_information_ipv4,
        { "IP Address of Trace Collection Entity", "pfcp.trace_information.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_trace_information_ipv6,
        { "IP Address of Trace Collection Entity", "pfcp.trace_information.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_framed_route,
        { "Framed-Route", "pfcp.framed_route",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_framed_routing,
        { "Framed-Routing", "pfcp.framed_routing",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_framed_ipv6_route,
        { "Framed-IPv6-Route", "pfcp.framed_ipv6_route",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_event_quota,
        { "Event Quota", "pfcp.event_quota",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_pfcp_event_threshold,
        { "Event Threshold", "pfcp.event_threshold",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_pfcp_time_stamp,
        { "Time Stamp", "pfcp.time_stamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_pfcp_averaging_window,
        { "Averaging Window", "pfcp.averaging_window",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_pfcp_paging_policy_indicator,
        { "Paging Policy Indicator (PPI)", "pfcp.ppi",
            FT_UINT8, BASE_DEC, NULL, 0x7,
            NULL, HFILL }
        },
        { &hf_pfcp_apn_dnn,
        { "APN/DNN", "pfcp.apn_dnn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_tgpp_interface_type,
        { "3GPP Interface Type", "pfcp.tgpp_interface_type",
            FT_UINT8, BASE_DEC, VALS(pfcp_tgpp_interface_type_vals), 0x3f,
            NULL, HFILL }
        },

        { &hf_pfcp_pfcpsrreq_flags_b0_psdbu,
        { "PSDBU (PFCP Session Deleted By the UP function)", "pfcp.srreq_flags.psdbu",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_pfcpaureq_flags_b0_parps,
        { "PARPBS (PFCP Association Release Preparation Start)", "pfcp.aureq_flags.parps",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_activation_time,
        { "Activation Time", "pfcp.activation_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_deactivation_time,
        { "Deactivation Time", "pfcp.deactivation_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_pfcp_mar_id,
        { "MAR ID", "pfcp.mar_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_steering_functionality,
        { "Steering Functionality", "pfcp.steering_functionality",
            FT_UINT8, BASE_DEC, VALS(pfcp_steering_functionality_vals), 0xF,
            NULL, HFILL }
        },
        { &hf_pfcp_steering_mode,
        { "Steering Mode", "pfcp.steering_mode",
            FT_UINT8, BASE_DEC, VALS(pfcp_steering_mode_vals), 0xF,
            NULL, HFILL }
        },

        { &hf_pfcp_weight,
        { "Weight", "pfcp.weight",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_priority,
        { "Priority", "pfcp.priority",
            FT_UINT8, BASE_DEC, VALS(pfcp_priority_vals), 0xF,
            NULL, HFILL }
        },

        { &hf_pfcp_ue_ip_address_pool_length,
        { "UE IP address Pool Identity Length", "pfcp.ue_ip_address_pool_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_address_pool_identity,
        { "UE IP address Pool Identity", "pfcp.ue_ip_address_pool_identity",
            FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_alternative_smf_ip_address_flags_ppe,
        { "PPE (Preferred PFCP Entity)", "pfcp.alternative_smf_ip_address_flags.ppe",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_alternative_smf_ip_address_ipv4,
        { "IPv4 address", "pfcp.alternative_smf_ip_address.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_alternative_smf_ip_address_ipv6,
        { "IPv6 address", "pfcp.alternative_smf_ip_address.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_packet_replication_and_detection_carry_on_information_flags_b0_priueai,
        { "PRIUEAI (Packet Replication Information – UE/PDU Session Address Indication)", "pfcp.packet_replication_and_detection_carry_on_information.flags.priueai",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_replication_and_detection_carry_on_information_flags_b1_prin19i,
        { "PRIN19I (Packet Replication Information - N19 Indication)", "pfcp.packet_replication_and_detection_carry_on_information.flags.prin19i",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_replication_and_detection_carry_on_information_flags_b2_prin6i,
        { "PRIN6I (Packet Replication Information - N6 Indication)", "pfcp.packet_replication_and_detection_carry_on_information.flags.prin6i",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_replication_and_detection_carry_on_information_flags_b3_dcaroni,
        { "DCARONI (Detection Carry-On Indication)", "pfcp.packet_replication_and_detection_carry_on_information.flags.dcaroni",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
            NULL, HFILL }
        },

        { &hf_pfcp_validity_time_value,
        { "Validity Time value", "pfcp.validity_time_value",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_number_of_reports,
        { "Number of Reports", "pfcp.number_of_reports",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_pfcpasrsp_flags_flags_b0_psrei,
        { "PSREI (PFCP Session Retained Indication)", "pfcp.asrsp_flags.flags.psrei",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_pfcpasrsp_flags_flags_b1_uupsi,
        { "UUPSI (UPF configured for IPUPS indication)", "pfcp.asrsp_flags.flags.uupsi",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },

        { &hf_pfcp_cp_pfcp_entity_ip_address_ipv4,
        { "IPv4 address", "pfcp.cp_pfcp_entity_ip_address.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_cp_pfcp_entity_ip_address_ipv6,
        { "IPv6 address", "pfcp.cp_pfcp_entity_ip_address.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_pfcpsereq_flags_flags_b0_resti,
        { "RESTI (Restoration Indication)", "pfcp.sereq_flags.flags.resti",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_pfcpsereq_flags_flags_b1_sumpc,
        { "SUMPC (Stop of Measurement of Pause of Charging)", "pfcp.sereq_flags.flags.sumpc",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },

        { &hf_pfcp_ip_multicast_address_flags_b2_range,
        { "RANGE", "pfcp.ip_multicast_address.flags.range",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_multicast_address_flags_b3_any,
        { "ANY", "pfcp.ip_multicast_address.flags.any",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_multicast_address_start_ipv4,
        { "(Start) IPv4 address", "pfcp.ip_multicast_address.start_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_multicast_address_start_ipv6,
        { "(Start) IPv6 address", "pfcp.ip_multicast_address.start_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_multicast_address_end_ipv4,
        { "(End) IPv4 address", "pfcp.ip_multicast_address.end_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_multicast_address_end_ipv6,
        { "(End) IPv6 address", "pfcp.ip_multicast_address.end_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_source_ip_address_flags_b2_mpl,
        { "MPL (Mask/Prefix Length)", "pfcp.source_ip_address.flags.mpl",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_source_ip_address_ipv4,
        { "IPv4 address", "pfcp.source_ip_address.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_source_ip_address_ipv6,
        { "IPv6 address", "pfcp.source_ip_address.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_source_ip_address_mask_prefix_lengt,
        { "Mask/Prefix Length", "pfcp.source_ip_address.mpl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_packet_rate_status_flags_b0_ul,
        { "UL", "pfcp.packet_rate_status.flags.ul",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_rate_status_flags_b1_dl,
        { "DL", "pfcp.packet_rate_status.flags.dl",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_rate_status_flags_b2_apr,
        { "APR", "pfcp.packet_rate_status.flags.apr",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_rate_status_ul,
        { "UL (remaining uplink packet limit)", "pfcp.packet_rate_status.tovol",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_rate_status_dl,
        { "DL (remaining downlink packet limit)", "pfcp.packet_rate_status.ulvol",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_rate_status_apr_ul,
        { "Additional UL (remaining uplink packet limit)", "pfcp.packet_rate_status.apr_tovol",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_rate_status_apr_dl,
        { "Additional DL (remaining downlink packet limit)", "pfcp.packet_rate_status.apr_ulvol",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_rate_status_validity_time,
        { "Validity Time value", "pfcp.packet_rate_status.validity_time",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_create_bridge_info_for_tsc_flags_b0_bii,
        { "BII (Bridge Information Indication)", "pfcp.create_bridge_info_for_tsc.flags.bii",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_ds_tt_port_number,
        { "DS-TT Port Number value", "pfcp.ds_tt_port_number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_nw_tt_port_number,
        { "NW-TT Port Number value", "pfcp.nw_tt_port_number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_5gs_user_plane_node_flags_b0_bid,
        { "BID", "pfcp.5gs_user_plane_node.flags.sour",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_5gs_user_plane_node_value,
        { "Use Plane Node value", "pfcp.5gs_user_plane_node.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_port_management_information,
        { "Port Management Information", "pfcp.port_management_information",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_requested_clock_drift_control_information_flags_b0_rrto,
        { "RRTO (Request to Report Time Offset)", "pfcp.requested_clock_drift_control_information.flags.rrto",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_requested_clock_drift_control_information_flags_b1_rrcr,
        { "RRCR (Request to Report Cumulative RateRatio)", "pfcp.requested_clock_drift_control_information.flags.rrcr",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },

        { &hf_pfcp_time_domain_number_value,
        { "Time Domain Number value", "pfcp.time_domain_number_value",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_time_offset_threshold,
        { "Time Offset Threshold", "pfcp.time_offset_threshold",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_cumulative_rate_ratio_threshold,
        { "Cumulative rateRatio Threshold", "pfcp.cumulative_rate_ratio_threshold",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },


        { &hf_pfcp_time_offset_measurement,
        { "Time Offset Measurement", "pfcp.time_offset_measurement",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_cumulative_rate_ratio_measurement,
        { "Cumulative rateRatio Measurement", "pfcp.cumulative_rate_ratio_measurement",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_srr_id,
        { "SRR ID value", "pfcp.srr_id_value",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_requested_access_availability_control_information_flags_b0_rrca,
        { "RRCA (Request to Report Change in Access availability)", "pfcp.requested_access_availability_control_information.flags.rrca",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_availability_type,
        { "Failed Rule ID Type", "pfcp.failed_rule_id_type",
            FT_UINT8, BASE_DEC, VALS(pfcp_availability_status_vals), 0xC,
            NULL, HFILL }
        },
        { &hf_pfcp_availability_status,
        { "Failed Rule ID Type", "pfcp.failed_rule_id_type",
            FT_UINT8, BASE_DEC, VALS(pfcp_availability_type_vals), 0x3,
            NULL, HFILL }
        },

        { &hf_pfcp_mptcp_control_information_flags_b0_tci,
        { "TCI (Transport Converter Indication)", "pfcp.mptcp_control_information.flags.tci",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_atsss_ll_control_information_flags_b0_lli,
        { "LLI: ATSSS-LL steering functionality is required", "pfcp.atsss_ll_control_information.flags.lli",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_pmf_control_information_flags_b0_pmfi,
        { "PMFI (PMF functionality is required)", "pfcp.pmf_control_information.flags.pmfi",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_pmf_control_information_flags_b1_drtti,
        { "DRTTI (Disallow PMF RTT Indication)", "pfcp.pmf_control_information.flags.drtti",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_pmf_control_information_flags_b2_pqpm,
        { "PQPM (Per Qos flow Performance Measurement indication)", "pfcp.pmf_control_information.flags.pqpm",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_pmf_control_information_number_of_qfi,
        { "Number of QFI", "pfcp.pmf_control_information.number_of_qfi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_mptcp_address_information_flags_b0_v4,
        { "V4", "pfcp.mptcp_ip_address_information.flags.v4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_mptcp_address_information_flags_b1_v6,
        { "V6", "pfcp.mptcp_ip_address_information.flags.v6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_mptcp_proxy_type,
        { "MPTCP proxy type", "pfcp.mptcp_proxy.type",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mptcp_proxy_port,
        { "MPTCP proxy port", "pfcp.mptcp_proxy.port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mptcp_proxy_ip_address_ipv4,
        { "MPTCP proxy IPv4 address", "pfcp.mptcp_proxy.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mptcp_proxy_ip_address_ipv6,
        { "MPTCP proxy IPv6 address", "pfcp.mptcp_proxy.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_ue_link_specific_ip_address_flags_b0_v4,
        { "V4", "pfcp.ue_link_specific_ip_address.flags.v4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_link_specific_ip_address_flags_b1_v6,
        { "V6", "pfcp.ue_link_specific_ip_address.flags.v6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_link_specific_ip_address_flags_b2_nv4,
        { "NV4", "pfcp.ue_link_specific_ip_address.flags.nv4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_link_specific_ip_address_flags_b3_nv6,
        { "NV6", "pfcp.ue_link_specific_ip_address.flags.nv6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_link_specific_ip_address_3gpp_ipv4,
        { "UE Link-Specific IPv4 Address for 3GPP Access", "pfcp.ue_link_specific_ip_address.3gpp.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_link_specific_ip_address_3gpp_ipv6,
        { "UE Link-Specific IPv6 Address for 3GPP Access", "pfcp.ue_link_specific_ip_address.3gpp.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_link_specific_ip_address_non3gpp_ipv4,
        { "UE Link-Specific IPv4 Address for Non-3GPP Access", "pfcp.ue_link_specific_ip_address.non3gpp.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_link_specific_ip_address_non3gpp_ipv6,
        { "UE Link-Specific IPv6 Address for Non-3GPP Access", "pfcp.ue_link_specific_ip_address.non3gpp.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_pmf_address_information_flags_b0_v4,
        { "V4", "pfcp.pmf_address_information.flags.v4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_pmf_address_information_flags_b1_v6,
        { "V6", "pfcp.pmf_address_information.flags.v6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_pmf_address_information_flags_b2_mac,
        { "MAC", "pfcp.pmf_address_information.flags.mac",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_pmf_address_ipv4,
        { "PMF IPv4 Address", "pfcp.pmf_address_information.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_pmf_address_ipv6,
        { "PMF IPv6 Address", "pfcp.pmf_address_information.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_pmf_port_3gpp,
        { "PMF port for 3GPP", "pfcp.pmf_address_information.port_3gpp",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_pmf_port_non3gpp,
        { "PMF port for Non-3GPP", "pfcp.pmf_address_information.port_non3gpp",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_pmf_mac_address_3gpp,
        { "MAC Address for 3GPP", "pfcp.pmf_address_information.mac_address_3gpp",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_pmf_mac_address_non3gpp,
        { "MAC Address for Non-3GPP", "pfcp.pmf_address_information.mac_address_non3gpp",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_atsss_ll_information_flags_b0_lli,
        { "LLI: ATSSS-LL steering functionality have been allocated", "pfcp.atsss_ll_information.flags.lli",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_data_network_access_identifier,
        { "Data Network Access Identifier", "pfcp.data_network_access_identifier",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_packet_delay_milliseconds,
        { "Delay Value in milliseconds", "pfcp.average_packet_delay.milliseconds",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_qos_report_trigger_flags_b0_per,
        { "PER (Periodic Reporting)", "pfcp.qos_report_trigger.flags.v4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_qos_report_trigger_flags_b1_thr,
        { "THR (Event triggered based on Threshold)", "pfcp.qos_report_trigger.flags.thr",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_qos_report_trigger_flags_b2_ire,
        { "IRE (Immediate Report)", "pfcp.qos_report_trigger.flags.ire",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },

        { &hf_pfcp_gtp_u_path_interface_type_flags_b0_n9,
        { "N9", "pfcp.qos_report_trigtp_u_path_interface_typegger.flags.n9",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_gtp_u_path_interface_type_flags_b1_n3,
        { "N3", "pfcp.gtp_u_path_interface_type.flags.n3",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },

        { &hf_pfcp_requested_qos_monitoring_flags_b0_dl,
        { "DL (Downlink)", "pfcp.requested_qos_monitoring.flags.dl",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_requested_qos_monitoring_flags_b1_ul,
        { "UL (Uplink)", "pfcp.requested_qos_monitoring.flags.ul",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_requested_qos_monitoring_flags_b2_rp,
        { "RP (Round Trip)", "pfcp.requested_qos_monitoring.flags.rp",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_requested_qos_monitoring_flags_b3_gtpupm,
        { "GTPUPM (GTP-U Path Monitoring)", "pfcp.requested_qos_monitoring.flags.gtpupm",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
            NULL, HFILL }
        },

        { &hf_pfcp_reporting_frequency_flags_b0_evett,
        { "EVETT (Event Triggered QoS monitoring reporting)", "pfcp.reporting_frequency.flags.evett",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_frequency_flags_b1_perio,
        { "PERIO (Periodic QoS monitoring reporting)", "pfcp.reporting_frequency.flags.perio",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_reporting_frequency_flags_b2_sesrl,
        { "SESRL (Session Released QoS monitoring reporting)", "pfcp.reporting_frequency.flags.sesrl",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },

        { &hf_pfcp_packet_delay_thresholds_flags_b0_dl,
        { "DL (Downlink)", "pfcp.packet_delay_thresholds.flags.dl",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_delay_thresholds_flags_b1_ul,
        { "UL (Uplink)", "pfcp.packet_delay_thresholds.flags.ul",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_delay_thresholds_flags_b2_rp,
        { "RP (Round Trip)", "pfcp.packet_delay_thresholds.flags.rp",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_delay_thresholds_downlink,
        { "Downlink packet delay threshold (milliseconds)", "pfcp.packet_delay_thresholds.downlink",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_delay_thresholds_uplink,
        { "Downlink packet delay threshold (milliseconds)", "pfcp.packet_delay_thresholds.uplink",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_packet_delay_thresholds_roundtrip,
        { "Round trip packet delay threshold (milliseconds)", "pfcp.packet_delay_thresholds.roundtrip",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_minimum_wait_time_seconds,
        { "The Minimum Wait Time (seconds)", "pfcp.minimum_wait_time.seconds",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_qos_monitoring_measurement_flags_b0_dl,
        { "DL (Downlink)", "pfcp.qos_monitoring_measurement.flags.dl",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_qos_monitoring_measurement_flags_b1_ul,
        { "UL (Uplink)", "pfcp.qos_monitoring_measurement.flags.ul",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_qos_monitoring_measurement_flags_b2_rp,
        { "RP (Round Trip)", "pfcp.qos_monitoring_measurement.flags.rp",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_qos_monitoring_measurement_flags_b3_plmf,
        { "PLMF (Packet Delay Measurement Failure)", "pfcp.qos_monitoring_measurement.flags.plmf",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_qos_monitoring_measurement_downlink,
        { "Downlink packet delay (milliseconds)", "pfcp.qos_monitoring_measurement.downlink",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_qos_monitoring_measurement_uplink,
        { "Downlink packet delay (milliseconds)", "pfcp.qos_monitoring_measurement.uplink",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_qos_monitoring_measurement_roundtrip,
        { "Round trip packet delay (milliseconds)", "pfcp.qos_monitoring_measurement.roundtrip",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_mt_edt_control_information_flags_b0_rdsi,
        { "RDSI (Reporting DL data packets Size Indication)", "pfcp.mt_edt_control_information.flags.rdsi",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_dl_data_packets_size,
        { "DL Data Packets Size", "pfcp.dl_data_packets_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_qer_control_indications_o5_b0_rcsr,
        { "RCSR (Rate Control Status Reporting)", "pfcp.qer_control_indications.rcsr",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_nf_instance_id,
        { "NF Instance ID", "pfcp.nf_instance_id",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_s_nssai_sst,
        { "SST", "pfcp.s_nssai_sst.sst",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_s_nssai_sd,
        { "SD", "pfcp.s_nssai_sst.sd",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_ip_version_flags_b1_v6,
        { "V6 (IPv6)", "pfcp.ip_version.v6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_version_flags_b0_v4,
        { "V4 (IPv4)", "pfcp.ip_version.v4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_pfcpasreq_flags_flags_b0_uupsi,
        { "UUPSI (UPF configured for IPUPS indication)", "pfcp.asreq_flags.flags.uupsi",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_data_status_flags_b0_drop,
        { "DROP (First DL packet is discared by UP function)", "pfcp.data_status.flags.drop",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_data_status_flags_b1_buff,
        { "BUFF (First DL packet is received and buffered by UP function)", "pfcp.data_status.flags.buff",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },

        { &hf_pfcp_rds_configuration_information_flags_b0_rds,
        { "RDS (Reliable Data Service)", "pfcp.rds_configuration_information.flags.rds",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_mptcp_application_indication_flags_b0_mai,
        { "MAI (MPTCP Applicable Indication)", "pfcp.mptcp_application_indication.flags.mai",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_user_plane_nodemanagement_information_container,
        { "Predefined Rules Name", "pfcp.user_plane_nodemanagement_information_container",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_number_of_ue_ip_addresses_b0_ipv4,
        { "IPv4", "pfcp.number_of_ue_ip_addresses.v4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_number_of_ue_ip_addresses_b1_ipv6,
        { "IPv6", "pfcp.number_of_ue_ip_addresses.v6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_number_of_ue_ip_addresses_ipv4,
        { "Number of UE IPv4 Addresses", "pfcp.number_of_ue_ip_addresses.ipv4addresses",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_number_of_ue_ip_addresses_ipv6,
        { "Number of UE IPv6 Addresses", "pfcp.number_of_ue_ip_addresses.ipv6addresses",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_validity_timer,
        { "Validity Timer", "pfcp.validity_timer",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_rattype,
        { "RAT Type", "pfcp.rattype",
            FT_UINT8, BASE_DEC, VALS(pfcp_rattype_vals), 0xF,
            NULL, HFILL }
        },

        { &hf_pfcp_l2tp_user_authentication_proxy_authen_type_value,
        { "Proxy Authen Type Value", "pfcp.l2tp_user_authentication.proxy_authen_type_value",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_l2tp_user_authentication_b0_pan,
        { "PAN (Proxy Authen Name)", "pfcp.l2tp_user_authentication.flags.pan",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_l2tp_user_authentication_b1_pac,
        { "PAC (Proxy Authen Challenge)", "pfcp.l2tp_user_authentication.flags.pac",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_l2tp_user_authentication_b2_par,
        { "PAR (Proxy Authen Response)", "pfcp.l2tp_user_authentication.flags.par",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_l2tp_user_authentication_b3_pai,
        { "PAI (Proxy Authen UD)", "pfcp.l2tp_user_authentication.flags.pai",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_l2tp_user_authentication_proxy_authen_name_len,
        { "Proxy Authen Name Length", "pfcp.l2tp_user_authentication.pan_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_l2tp_user_authentication_proxy_authen_name,
        { "Proxy Authen Name", "pfcp.l2tp_user_authentication.pan",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_l2tp_user_authentication_proxy_authen_challenge_len,
        { "Proxy Authen Challenge Length", "pfcp.l2tp_user_authentication.pac_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_l2tp_user_authentication_proxy_authen_challenge,
        { "Proxy Authen Challenge", "pfcp.l2tp_user_authentication.pac",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_l2tp_user_authentication_proxy_authen_response_len,
        { "Proxy Authen Response Length", "pfcp.l2tp_user_authentication.par_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_l2tp_user_authentication_proxy_authen_response,
        { "Proxy Authen Response", "pfcp.l2tp_user_authentication.par",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_l2tp_user_authentication_proxy_authen_id,
        { "Proxy Authen ID", "pfcp.l2tp_user_authentication.pai",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_lns_address_ipv4,
        { "IPv4 address", "pfcp.lns_address.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_lns_address_ipv6,
        { "IPv6 address", "pfcp.lns_address.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_tunnel_preference_value,
        { "Tunnel Preference Value", "pfcp.tunnel_preference_value",
            FT_UINT24, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_pfcp_calling_number_value,
        { "Calling Number Value", "pfcp.calling_number_value",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_called_number_value,
        { "Called Number Value", "pfcp.called_number_value",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },

        { &hf_pfcp_l2tp_session_indications_o5_b0_reuia,
        { "REUIA", "pfcp.l2tp_session_indications.reuia",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "Request UE IP Address", HFILL }
        },
        { &hf_pfcp_l2tp_session_indications_o5_b1_redsa,
        { "REDSA", "pfcp.l2tp_session_indications.redsa",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            "Request DNS Server Address", HFILL }
        },
        { &hf_pfcp_l2tp_session_indications_o5_b2_rensa,
        { "RENSA", "pfcp.l2tp_session_indications.rensa",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            "Request NBNS Server Address", HFILL }
        },

        { &hf_pfcp_maximum_receive_unit,
        { "Maximum Receive Unit", "pfcp.maximum_receive_unit",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_thresholds_flags_b0_rtt,
        { "RTT", "pfcp.thresholds.flags.rtt",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_thresholds_flags_b1_plr,
        { "PLR (Packet Loss Rate)", "pfcp.thresholds.flags.plr",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_thresholds_rtt,
        { "RTT (in milliseconds)", "pfcp.thresholds.rtt",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_thresholds_plr,
        { "Packet Loss Rate (in percent)", "pfcp.thresholds.plr",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_l2tp_steering_mode_indications_o5_b0_albi,
        { "ALBI", "pfcp.l2tp_session_indications.reuia",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "Autonomous Load Balacing Indicator", HFILL }
        },
        { &hf_pfcp_l2tp_steering_mode_indications_o5_b1_ueai,
        { "UEAI", "pfcp.l2tp_session_indications.redsa",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            "UE Assistance Indicator", HFILL }
        },

        { &hf_pfcp_group_id,
        { "Group ID", "pfcp.group_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_cp_ip_address_ipv4,
        { "IPv4 address", "pfcp.cp_ip_address.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_cp_ip_address_ipv6,
        { "IPv6 address", "pfcp.cp_ip_address.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_ip_address_and_port_number_replacement_flag_b0_v4,
        { "DIPV4", "pfcp.ip_address_and_port_number_replacement.flag.dipv4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_address_and_port_number_replacement_flag_b1_v6,
        { "DIPV6", "pfcp.ip_address_and_port_number_replacement.flag.dipv6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_address_and_port_number_replacement_flag_b2_dpn,
        { "DPN", "pfcp.ip_address_and_port_number_replacement.flag.dpn",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_address_and_port_number_replacement_flag_b3_sipv4,
        { "SIPV4", "pfcp.ip_address_and_port_number_replacement.flag.sipv4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_address_and_port_number_replacement_flag_b4_sipv6,
        { "SIPV6", "pfcp.ip_address_and_port_number_replacement.flag.sipv6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_address_and_port_number_replacement_flag_b5_spn,
        { "SPN", "pfcp.ip_address_and_port_number_replacement.flag.spn",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x20,
            NULL, HFILL }
        },

        { &hf_pfcp_ip_address_and_port_number_replacement_destination_ipv4,
        { "Destination IPv4 address", "pfcp.ip_address_and_port_number_replacement.dipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_address_and_port_number_replacement_destination_ipv6,
        { "Destination IPv6 address", "pfcp.ip_address_and_port_number_replacement.dipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_address_and_port_number_replacement_destination_port,
        { "Destination Port Number", "pfcp.ip_address_and_port_number_replacement.dpn",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_address_and_port_number_replacement_source_ipv4,
        { "Source IPv4 address", "pfcp.ip_address_and_port_number_replacement.sipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_address_and_port_number_replacement_source_ipv6,
        { "Source IPv6 address", "pfcp.ip_address_and_port_number_replacement.sipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ip_address_and_port_number_replacement_source_port,
        { "Source Port Number", "pfcp.ip_address_and_port_number_replacement.spn",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_dns_query_filter_pattern_len,
        { "DNS Query Filter Pattern Length", "pfcp.dns_query_filter.pattern_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_dns_query_filter_pattern,
        { "DNS Query Filter Pattern", "pfcp.dns_query_filter.pattern",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },

        { &hf_pfcp_event_notification_uri,
        { "Event Notification URI", "pfcp.event_notification_uri",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },

        { &hf_pfcp_notification_correlation_id,
        { "QER Correlation ID", "pfcp.qer_correlation_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_reporting_flags_o5_b0_dupl,
        { "DUPL (Duplocation Notication)", "pfcp.reporting_flags.dupl",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_mbs_session_identifier_flag_b0_tmgi,
        { "TGMI", "pfcp.session_identifier.flag.tmgi",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_mbs_session_identifier_flag_b1_ssmi,
        { "SSMI", "pfcp.session_identifier.flag.ssmi",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_mbs_session_identifier_flag_b2_nidi,
        { "NIDI", "pfcp.session_identifier.flag.nidi",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_mbs_session_identifier_tmgi,
          {"TMGI", "pfcp.mbs_session_identifier.tmgi",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_pfcp_mbs_session_identifier_source_address_type,
        { "Source Address Type", "pfcp.mbs_session_identifier.source_address.type",
            FT_UINT8, BASE_DEC, NULL, 0xC0,
            NULL, HFILL }
        },
        { &hf_pfcp_mbs_session_identifier_source_address_length,
        { "Source Address Length", "pfcp.mbs_session_identifier.source_address.length",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_pfcp_mbs_session_identifier_source_address_ipv4,
        { "Source IPv4 address", "pfcp.mbs_session_identifier.source_address.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mbs_session_identifier_source_address_ipv6,
        { "Source IPv6 address", "pfcp.mbs_session_identifier.source_address.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_mbs_session_identifier_nidi,
          {"NIDI", "pfcp.mbs_session_identifier.nidi",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },

        { &hf_pfcp_multicast_transport_information_endpoint_identifier,
        { "Common Tunnel Endpoint Identifier", "pfcp.multicast_transport_information.endpoint_identifier",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_multicast_transport_information_distribution_address_type,
        { "Distribution Address Type", "pfcp.multicast_transport_information.distribution_address.type",
            FT_UINT8, BASE_DEC, NULL, 0xC0,
            NULL, HFILL }
        },
        { &hf_pfcp_multicast_transport_information_distribution_address_length,
        { "Distribution Adress Length", "pfcp.multicast_transport_information.distribution_address.length",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_pfcp_multicast_transport_information_distribution_address_ipv4,
        { "Distribution IPv4 address", "pfcp.multicast_transport_information.distribution_address.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_multicast_transport_information_distribution_address_ipv6,
        { "Distribution IPv6 address", "pfcp.multicast_transport_information.distribution_address.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_multicast_transport_information_source_address_type,
        { "Source Address Type", "pfcp.multicast_transport_information.distribution_address.type",
            FT_UINT8, BASE_DEC, NULL, 0xC0,
            NULL, HFILL }
        },
        { &hf_pfcp_multicast_transport_information_source_address_length,
        { "Source Address Type", "pfcp.multicast_transport_information.distribution_address.length",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_pfcp_multicast_transport_information_source_address_ipv4,
        { "Source IPv4 address", "pfcp.multicast_transport_information.distribution_address.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_multicast_transport_information_source_address_ipv6,
        { "Source IPv6 address", "pfcp.multicast_transport_information.distribution_address.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_mbsn4mbreq_flags_o5_b0_pllssm,
        { "PLLSSM (Provide Lower Layer SSM)", "pfcp.reporting_flags.pllssm",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_mbsn4mbreq_flags_o5_b1_jmbssm,
        { "JMBSSM (Join MBS Session SSM)", "pfcp.reporting_flags.jmbssm",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_mbsn4mbreq_flags_o5_b2_mbs_resti,
        { "MBS RESTI (MBS Restoration Indication)", "pfcp.reporting_flags.mbs_resti",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },

        { &hf_pfcp_local_ingress_tunnel_flags_b2_ch,
        { "CH (CHOOSE)", "pfcp.local_ingress_tunnel.flags.ch",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_local_ingress_tunnel_flags_b1_v6,
        { "V6 (IPv6)", "pfcp.local_ingress_tunnel.flags.v6",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_local_ingress_tunnel_flags_b0_v4,
        { "V4 (IPv4)", "pfcp.local_ingress_tunnel.flags.v4",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_local_ingress_tunnel_udp_port,
        { "UDP Port", "pfcp.local_ingress_tunnel.udp",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_local_ingress_tunnel_ipv4,
        { "IPv4 address", "pfcp.local_ingress_tunnel.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_local_ingress_tunnel_ipv6,
        { "IPv6 address", "pfcp.local_ingress_tunnel.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_mbs_unicast_parameters_id,
        { "MBS Unicast Parameters ID value", "pfcp.mbs_unicast_parameters_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_mbsn4resp_flags_o5_b0_nn19dt,
        { "NN19DT", "pfcp.mbsn4resp_flags.nn19dt",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "New N19mb Downlink Tunnel", HFILL }
        },
        { &hf_pfcp_mbsn4resp_flags_o5_b1_jmti,
        { "JMTI", "pfcp.mbsn4resp_flags.jmti",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            "Joined N19mb Multicast Tree Indication", HFILL }
        },
        { &hf_pfcp_mbsn4resp_flags_o5_b2_n19dtr,
        { "N19DTR", "pfcp.mbsn4resp_flags.n19dtr",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            "N19mb Downlink Tunnel Removal", HFILL }
        },

        { &hf_pfcp_tunnel_password_value,
        { "Tunnel Password value", "pfcp.tunnel_password_value",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_area_session_id_value,
        { "Area Session ID value", "pfcp.area_session_id_value",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_dscp_to_ppi_mapping_info_ppi_value,
        { "PPI value", "pfcp.dscp_to_ppi_mapping_info_ppi_value",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_dscp_to_ppi_mapping_info_dscp_value,
        { "DSCP value", "pfcp.dscp_to_ppi_mapping_info_dscp_value",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_pfcpsdrsp_flags_b0_puru,
        { "PURU (Pending Usage Reports Unacknowledged)", "pfcp.pfcpsdrsp_flags.puru",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },

        { &hf_pfcp_qer_indications_flags_b0_iqfis,
        { "IQFIS (Insert DL MBS QFI SN)", "pfcp.qer_indications_flags.iqfis",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },


        /* Enterprise IEs */
        /* BBF */
        { &hf_pfcp_bbf_up_function_features_o7_b0_pppoe,
        { "PPPoE", "pfcp.bbf.up_function_features.pppoe",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            "PPPoE supported in DBNG-UP function", HFILL }
        },
        { &hf_pfcp_bbf_up_function_features_o7_b1_ipoe,
        { "IPoE", "pfcp.bbf.up_function_features.ipoe",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            "IPoE supported in DBNG-UP function", HFILL }
        },
        { &hf_pfcp_bbf_up_function_features_o7_b2_lac,
        { "LAC", "pfcp.bbf.up_function_features.lac",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            "LAC function supported in DBNG-UP function", HFILL }
        },
        { &hf_pfcp_bbf_up_function_features_o7_b3_lns,
        { "LNS", "pfcp.bbf.up_function_features.lns",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            "LNS function supported in DBNG-UP function", HFILL }
        },
        { &hf_pfcp_bbf_up_function_features_o7_b4_lcp_keepalive_offload,
        { "LCP keepalive offload", "pfcp.bbf.up_function_features.lcp_keepalive_offload",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            "PPP LCP echo supported in DBNG-UP function", HFILL }
        },

        { &hf_pfcp_bbf_logical_port_id,
        { "Logical Port", "pfcp.bbf.logical_port_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_logical_port_id_str,
        { "Logical Port", "pfcp.bbf.logical_port_id_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_bbf_outer_hdr_desc,
        { "BBF Outer Header Creation Description", "pfcp.bbf.outer_hdr_desc",
            FT_UINT16, BASE_DEC, VALS(pfcp_bbf_outer_hdr_desc_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_outer_hdr_creation_tunnel_id,
        { "L2TP Tunnel ID", "pfcp.bbf.outer_hdr_creation.tunnel_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_outer_hdr_creation_session_id,
        { "L2TP Session ID", "pfcp.bbf.outer_hdr_creation.session_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_bbf_out_hdr_desc,
        { "BBF Outer Header Removal Description", "pfcp.bbf.out_hdr_desc",
            FT_UINT8, BASE_DEC, VALS(pfcp_bbf_out_hdr_desc_vals), 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_bbf_pppoe_session_id,
        { "PPPoE Session ID", "pfcp.bbf.pppoe_session_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_bbf_ppp_protocol_flags,
        { "Flags", "pfcp.bbf.protocol_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_ppp_protocol_b2_control,
        { "control", "pfcp.bbf.protocol_flags.control",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_ppp_protocol_b1_data,
        { "data", "pfcp.bbf.protocol_flags.data",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_ppp_protocol_b0_specific,
        { "specific", "pfcp.bbf.protocol_flags.specific",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_ppp_protocol,
        { "protocol", "pfcp.bbf.protocol_flags.protocol",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_bbf_verification_timer_interval,
        { "Interval", "pfcp.bbf.verification_timer.interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_verification_timer_count,
        { "Count", "pfcp.bbf.verification_timer.count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_bbf_ppp_lcp_magic_number_tx,
        { "PPP LCP Magic Number Tx", "pfcp.bbf.lcp_magic_number.tx",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_ppp_lcp_magic_number_rx,
        { "PPP LCP Magic Number Rx", "pfcp.bbf.lcp_magic_number.rx",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_bbf_mtu,
        { "MTU", "pfcp.bbf.mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_bbf_l2tp_endp_flags,
        { "Flags", "pfcp.bbf.l2tp_endp_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_l2tp_endp_flags_b2_ch,
        { "CH (CHOOSE)", "pfcp.bbf.l2tp_endp_flags.ch",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_l2tp_endp_flags_b1_v6,
        { "V6 (IPv6)", "pfcp.bbf.l2tp_endp_flags.v6",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_l2tp_endp_flags_b0_v4,
        { "V4 (IPv4)", "pfcp.bbf.l2tp_endp_flags.v4",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_l2tp_endp_id_tunnel_id,
        { "Tunnel ID", "pfcp.bbf.l2tp_endp.tunnel_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_l2tp_endp_id_ipv4,
        { "IPv4 address", "pfcp.bbf.l2tp_endp.ipv4_addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_l2tp_endp_id_ipv6,
        { "IPv6 address", "pfcp.bbf.l2tp_endp.ipv6_addr",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_bbf_l2tp_session_id,
        { "L2TP Session ID", "pfcp.bbf.bbf_l2tp_session_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pfcp_bbf_l2tp_type_flags,
        { "Flags", "pfcp.bbf.l2tp_type_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_bbf_l2tp_type_flags_b0_t,
        { "T (TYPE)", "pfcp.bbf.l2tp_type_flags.t",
            FT_BOOLEAN, 8, TFS(&pfcp_bbf_l2tp_type_b0_t_tfs), 0x01,
            NULL, HFILL }
        },

        /* Travelping */
        { &hf_pfcp_enterprise_travelping_packet_measurement,
        { "Flags", "pfcp.travelping.volume_measurement",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_enterprise_travelping_packet_measurement_b0_tonop,
        { "TONOP", "pfcp.travelping.volume_measurement_flags.tonop",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_enterprise_travelping_packet_measurement_b1_ulnop,
        { "ULNOP", "pfcp.travelping.volume_measurement_flags.ulnop",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_enterprise_travelping_packet_measurement_b2_dlnop,
        { "DLNOP", "pfcp.travelping.volume_measurement_flags.dlnops",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_pkt_meas_tonop,
        { "Total Number of Packets", "pfcp.travelping.volume_measurement.tonop",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_pkt_meas_ulnop,
        { "Uplink Number of Packets", "pfcp.travelping.volume_measurement.ulnop",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_pkt_meas_dlnop,
        { "Downlink Number of Packets", "pfcp.travelping.volume_measurement.dlnop",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_build_id,
        { "Build Identifier", "pfcp.travelping.build_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_build_id_str,
        { "Build Identifier", "pfcp.travelping.build_id_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_now,
        { "Now", "pfcp.travelping.now",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_error_message,
        { "Error Message", "pfcp.travelping.error_message",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_error_message_str,
        { "Error Message", "pfcp.travelping.error_message_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_file_name,
        { "File Name", "pfcp.travelping.file_name",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_file_name_str,
        { "File Name", "pfcp.travelping.file_name_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_line_number,
        { "Line Number", "pfcp.travelping.line_number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_ipfix_policy,
        { "IPFIX Policy", "pfcp.travelping.ipfix_policy",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_ipfix_policy_str,
        { "IPFIX Policy", "pfcp.travelping.ipfix_policy_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_trace_parent,
        { "Trace Parent", "pfcp.travelping.trace_parent",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_trace_parent_str,
        { "Trace Parent", "pfcp.travelping.trace_parent_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_trace_state,
        { "Trace State", "pfcp.travelping.trace_state",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_travelping_trace_state_str,
        { "Trace State", "pfcp.travelping.trace_state_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
#define NUM_INDIVIDUAL_ELEMS_PFCP    24
    gint *ett[NUM_INDIVIDUAL_ELEMS_PFCP +
        (NUM_PFCP_IES - 1) +
        (NUM_PFCP_ENTERPRISE_BBF_IES - 1) +
        (NUM_PFCP_ENTERPRISE_TRAVELPING_IES - 1)];

    ett[0] = &ett_pfcp;
    ett[1] = &ett_pfcp_flags;
    ett[2] = &ett_pfcp_ie;
    ett[3] = &ett_pfcp_grouped_ie;
    ett[4] = &ett_pfcp_reporting_triggers;
    ett[5] = &ett_pfcp_up_function_features;
    ett[6] = &ett_pfcp_report_trigger;
    ett[7] = &ett_pfcp_flow_desc;
    ett[8] = &ett_pfcp_tos;
    ett[9] = &ett_pfcp_spi;
    ett[10] = &ett_pfcp_flow_label;
    ett[11] = &ett_pfcp_sdf_filter_id;
    ett[12] = &ett_pfcp_adf;
    ett[13] = &ett_pfcp_aurl;
    ett[14] = &ett_pfcp_adnp;
    /* Enterprise */
    /* Travelping */
    ett[15] = &ett_pfcp_enterprise_travelping_packet_measurement;
    ett[16] = &ett_pfcp_enterprise_travelping_error_report;
    ett[17] = &ett_pfcp_enterprise_travelping_created_nat_binding;
    ett[18] = &ett_pfcp_enterprise_travelping_trace_info;
    /* BBF */
    ett[19] = &ett_pfcp_bbf_ppp_protocol_flags;
    ett[20] = &ett_pfcp_bbf_l2tp_endp_flags;
    ett[21] = &ett_pfcp_bbf_l2tp_type_flags;
    ett[22] = &ett_pfcp_bbf_ppp_lcp_connectivity;
    ett[23] = &ett_pfcp_bbf_l2tp_tunnel;

    static ei_register_info ei[] = {
        { &ei_pfcp_ie_reserved,{ "pfcp.ie_id_reserved", PI_PROTOCOL, PI_ERROR, "Reserved IE value used", EXPFILL } },
        { &ei_pfcp_ie_data_not_decoded,{ "pfcp.ie_data_not_decoded", PI_UNDECODED, PI_NOTE, "IE data not decoded by WS yet", EXPFILL } },
        { &ei_pfcp_ie_not_decoded_null,{ "pfcp.ie_not_decoded_null", PI_UNDECODED, PI_NOTE, "IE not decoded yet(WS:no decoding function(NULL))", EXPFILL } },
        { &ei_pfcp_ie_not_decoded_too_large,{ "pfcp.ie_not_decoded", PI_UNDECODED, PI_NOTE, "IE not decoded yet(WS:IE id too large)", EXPFILL } },
        { &ei_pfcp_enterprise_ie_3gpp,{ "pfcp.ie_enterprise_3gpp", PI_PROTOCOL, PI_ERROR, "IE not decoded yet(WS:No vendor dissector)", EXPFILL } },
        { &ei_pfcp_ie_encoding_error,{ "pfcp.ie_encoding_error", PI_PROTOCOL, PI_ERROR, "IE wrongly encoded", EXPFILL } },
    };

    module_t *module_pfcp;
    expert_module_t* expert_pfcp;

    guint last_index = NUM_INDIVIDUAL_ELEMS_PFCP, i;

    for (i = 0; i < (NUM_PFCP_IES-1); i++, last_index++)
    {
        ett_pfcp_elem[i] = -1;
        ett[last_index] = &ett_pfcp_elem[i];
    }
    for (i = 0; i < (NUM_PFCP_ENTERPRISE_TRAVELPING_IES-1); i++, last_index++)
    {
        ett_pfcp_enterprise_travelping_elem[i] = -1;
        ett[last_index] = &ett_pfcp_enterprise_travelping_elem[i];
    }
    for (i = 0; i < (NUM_PFCP_ENTERPRISE_BBF_IES-1); i++, last_index++)
    {
        ett_pfcp_enterprise_bbf_elem[i] = -1;
        ett[last_index] = &ett_pfcp_enterprise_bbf_elem[i];
    }

    proto_pfcp = proto_register_protocol("Packet Forwarding Control Protocol", "PFCP", "pfcp");
    pfcp_handle = register_dissector("pfcp", dissect_pfcp, proto_pfcp);
    module_pfcp = prefs_register_protocol(proto_pfcp, proto_reg_handoff_pfcp);

    proto_register_field_array(proto_pfcp, hf_pfcp, array_length(hf_pfcp));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pfcp = expert_register_protocol(proto_pfcp);
    expert_register_field_array(expert_pfcp, ei, array_length(ei));

    /* Register dissector table for enterprise IE dissectors */
    pfcp_enterprise_ies_dissector_table = register_dissector_table("pfcp.enterprise_ies", "PFCP Enterprice IEs",
        proto_pfcp, FT_UINT32, BASE_DEC);

    pfcp_3gpp_ies_handle = register_dissector("pfcp_3gpp_ies", dissect_pfcp_3gpp_enterprise_ies, proto_pfcp);
    pfcp_travelping_ies_handle = register_dissector("pfcp_travelping_ies", dissect_pfcp_enterprise_travelping_ies, proto_pfcp);
    pfcp_bbf_ies_handle = register_dissector("pfcp_bbf_ies", dissect_pfcp_enterprise_bbf_ies, proto_pfcp);

    prefs_register_uint_preference(module_pfcp, "port_pfcp", "PFCP port", "PFCP port (default 8805)", 10, &g_pfcp_port);
    prefs_register_bool_preference(module_pfcp, "track_pfcp_session", "Track PFCP session", "Track PFCP session", &g_pfcp_session);
    register_init_routine(pfcp_init);
    register_cleanup_routine(pfcp_cleanup);

}

void
proto_reg_handoff_pfcp(void)
{
    dissector_add_uint("udp.port", g_pfcp_port, pfcp_handle);
    /* Register 3GPP in the table to give expert info and serve as an example how to add decoding of enterprise IEs*/
    dissector_add_uint("pfcp.enterprise_ies", VENDOR_THE3GPP, pfcp_3gpp_ies_handle);
    /* Register Broadband Forum IEs */
    dissector_add_uint("pfcp.enterprise_ies", VENDOR_BROADBAND_FORUM, pfcp_bbf_ies_handle);
    /* Register Travelping IEs */
    dissector_add_uint("pfcp.enterprise_ies", VENDOR_TRAVELPING, pfcp_travelping_ies_handle);
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
