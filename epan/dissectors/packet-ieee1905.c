/* packet-ieee1905.c
 * Routines for IEEE1905 dissection
 *
 * Copyright 2017, Richard Sharpe <realrichardsharpe@gmail.com>
 * Copyright 2017, The Wi-Fi Alliance.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * https://standards.ieee.org/findstds/standard/1905.1-2013.html
 *
 * IEEE Standard for a Convergent Digital Home Network for Heterogeneous
 * Technologies
 *
 * Plus incorporating the changes in the Multi-AP Technical Specification.
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/addr_resolv.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/address.h>
#include <epan/reassemble.h>
#include "packet-wps.h"
#include "packet-wifi-dpp.h"
#include "packet-ieee80211.h"

static dissector_handle_t eapol_handle;

extern value_string_ext ieee80211_reason_code_ext;
extern value_string_ext ieee80211_status_code_ext;
extern value_string_ext ff_pa_action_codes_ext;
extern const value_string wfa_subtype_vals[];

void proto_reg_handoff_ieee1905(void);
void proto_register_ieee1905(void);

/* Reassembly header fields */
static int hf_ieee1905_fragments = -1;
static int hf_ieee1905_fragment = -1;
static int hf_ieee1905_fragment_overlap = -1;
static int hf_ieee1905_fragment_overlap_conflicts = -1;
static int hf_ieee1905_fragment_multiple_tails = -1;
static int hf_ieee1905_fragment_too_long_fragment = -1;
static int hf_ieee1905_fragment_error = -1;
static int hf_ieee1905_fragment_count = -1;
static int hf_ieee1905_fragment_reassembled_in = -1;
static int hf_ieee1905_fragment_reassembled_length = -1;

/* Normal header fields */
static int proto_ieee1905 = -1;
static int hf_ieee1905_fragment_data = -1;
static int hf_ieee1905_message_version = -1;
static int hf_ieee1905_message_reserved = -1;
static int hf_ieee1905_message_type = -1;
static int hf_ieee1905_message_id = -1;
static int hf_ieee1905_fragment_id = -1;
static int hf_ieee1905_flags = -1;
static int hf_ieee1905_last_fragment = -1;
static int hf_ieee1905_relay_indicator = -1;
static int hf_ieee1905_tlv_types = -1;
static int hf_ieee1905_tlv_len = -1;
static int hf_ieee1905_tlv_len_reserved = -1;
static int hf_ieee1905_tlv_len_length = -1;
static int hf_ieee1905_tlv_data = -1;
static int hf_ieee1905_al_mac_address_type = -1;
static int hf_ieee1905_mac_address_type = -1;
static int hf_ieee1905_link_metric_query_type = -1;
static int hf_ieee1905_link_metrics_requested = -1;
static int hf_ieee1905_responder_al_mac_addr = -1;
static int hf_ieee1905_neighbor_al_mac_addr = -1;
static int hf_ieee1905_receiving_al_mac_addr = -1;
static int hf_ieee1905_bridge_flag = -1;
static int hf_ieee1905_packet_errors = -1;
static int hf_ieee1905_transmitted_packets = -1;
static int hf_ieee1905_mac_throughput_capacity = -1;
static int hf_ieee1905_link_availability = -1;
static int hf_ieee1905_phy_rate = -1;
static int hf_ieee1905_packets_received = -1;
static int hf_ieee1905_rssi = -1;
static int hf_ieee1905_data = -1;
static int hf_ieee1905_extra_tlv_data = -1;
static int hf_ieee1905_local_interface_count = -1;
static int hf_ieee1905_media_type = -1;
static int hf_ieee1905_media_spec_info_len = -1;
static int hf_ieee1905_media_spec_info = -1;
static int hf_ieee1905_media_type_high = -1;
static int hf_ieee1905_media_type_low = -1;
static int hf_ieee1905_bridging_tuples_cnt = -1;
static int hf_ieee1905_bridging_mac_address_cnt = -1;
static int hf_ieee1905_bridging_mac_address = -1;
static int hf_ieee1905_local_interface_mac = -1;
static int hf_ieee1905_non_1905_neighbor_mac = -1;
static int hf_ieee1905_neighbor_flags = -1;
static int hf_ieee1905_bridges_flag = -1;
static int hf_ieee1905_link_metric_result_code = -1;
static int hf_ieee1905_vendor_specific_oui = -1;
static int hf_ieee1905_vendor_specific_info = -1;
static int hf_ieee1905_searched_role = -1;
static int hf_ieee1905_supported_role = -1;
static int hf_ieee1905_auto_config_freq_band = -1;
static int hf_ieee1905_supported_freq_band = -1;
static int hf_ieee1905_event_notification_media_types = -1;
static int hf_ieee1905_sender_al_id = -1;
static int hf_ieee1905_push_button_event_msg_id = -1;
static int hf_ieee1905_sender_joining_interface = -1;
static int hf_ieee1905_new_device_interface = -1;
static int hf_ieee1905_device_al_mac = -1;
static int hf_ieee1905_local_intf_oui = -1;
static int hf_ieee1905_local_intf_variant = -1;
static int hf_ieee1905_local_intf_variant_name = -1;
static int hf_ieee1905_local_intf_url_count = -1;
static int hf_ieee1905_local_intf_spec_count = -1;
static int hf_ieee1905_local_intf_url = -1;
static int hf_ieee1905_local_intf_spec = -1;
static int hf_ieee1905_dev_id_friendly_name = -1;
static int hf_ieee1905_dev_id_manuf_name = -1;
static int hf_ieee1905_dev_id_manuf_model = -1;
static int hf_ieee1905_control_url = -1;
static int hf_ieee1905_ipv4_type_count = -1;
static int hf_ieee1905_mac_address = -1;
static int hf_ieee1905_ipv4_addr_count = -1;
static int hf_ieee1905_addr_type = -1;
static int hf_ieee1905_ipv4_addr = -1;
static int hf_ieee1905_dhcp_server = -1;
static int hf_ieee1905_ipv6_mac_address = -1;
static int hf_ieee1905_ipv6_linklocal = -1;
static int hf_ieee1905_ipv6_type_count = -1;
static int hf_ieee1905_ipv6_addr_count = -1;
static int hf_ieee1905_ipv6_addr_type = -1;
static int hf_ieee1905_ipv6_addr = -1;
static int hf_ieee1905_ipv6_dhcp_server = -1;
static int hf_ieee1905_generic_phy_media_types = -1;
static int hf_ieee1905_profile_version = -1;
static int hf_ieee1905_power_off_intf_count = -1;
static int hf_ieee1905_power_change_intf_count = -1;
static int hf_ieee1905_power_change_mac_addr = -1;
static int hf_ieee1905_power_change_state = -1;
static int hf_ieee1905_power_status_intf_count = -1;
static int hf_ieee1905_power_status_mac_addr = -1;
static int hf_ieee1905_power_status_state = -1;
static int hf_ieee1905_l2_neighbor_intf_count = -1;
static int hf_ieee1905_l2_local_intf_mac_addr = -1;
static int hf_ieee1905_l2_neighbor_dev_count = -1;
static int hf_ieee1905_l2_neighbor_mac_addr = -1;
static int hf_ieee1905_l2_behind_mac_addr_count = -1;
static int hf_ieee1905_l2_behind_mac_addr = -1;
static int hf_ieee1905_supported_service_count = -1;
static int hf_ieee1905_supported_service = -1;
static int hf_ieee1905_searched_service_count = -1;
static int hf_ieee1905_searched_service = -1;
static int hf_ieee1905_ap_radio_identifier = -1;
static int hf_ieee1905_operatonal_bss_radio_count = -1;
static int hf_ieee1905_ap_operational_intf_count = -1;
static int hf_ieee1905_ap_local_intf_mac_addr = -1;
static int hf_ieee1905_ap_local_intf_ssid_len = -1;
static int hf_ieee1905_ap_local_intf_ssid = -1;
static int hf_ieee1905_ap_capabilities_flags = -1;
static int hf_ieee1905_rpt_unsuccessful_associations = -1;
static int hf_ieee1905_unassoc_sta_metrics_oper_flag = -1;
static int hf_ieee1905_unassoc_sta_metrics_non_oper_flag = -1;
static int hf_ieee1905_agent_init_steering = -1;
static int hf_ieee1905_rpt_unsuccessful_assoc_report = -1;
static int hf_ieee1905_higher_layer_protocol = -1;
static int hf_ieee1905_higher_layer_data = -1;
static int hf_ieee1905_assoc_backhaul_station_mac = -1;
static int hf_ieee1905_backhaul_target_bssid = -1;
static int hf_ieee1905_backhaul_steering_status = -1;
static int hf_ieee1905_backhaul_operating_class = -1;
static int hf_ieee1905_backhaul_channel_number = -1;
static int hf_ieee1905_client_assoc_bssid = -1;
static int hf_ieee1905_association_control = -1;
static int hf_ieee1905_association_control_validity = -1;
static int hf_ieee1905_client_assoc_sta_count = -1;
static int hf_ieee1905_client_assoc_mac_addr = -1;
static int hf_ieee1905_btm_reporter_bssid = -1;
static int hf_ieee1905_btm_sta_mac_addr = -1;
static int hf_ieee1905_btm_report_status = -1;
static int hf_ieee1905_btm_report_bssid = -1;
static int hf_ieee1905_source_bss_bssid = -1;
static int hf_ieee1905_steering_request_flags = -1;
static int hf_ieee1905_steering_req_op_window = -1;
static int hf_ieee1905_steering_request_mode_flag = -1;
static int hf_ieee1905_btm_disassoc_imminent_flag = -1;
static int hf_ieee1905_btm_abridged_flag = -1;
static int hf_ieee1905_steering_req_reserved = -1;
static int hf_ieee1905_steering_btm_disass_timer = -1;
static int hf_ieee1905_steering_req_sta_count = -1;
static int hf_ieee1905_steering_req_sta_mac = -1;
static int hf_ieee1905_steering_req_target_bssid_count = -1;
static int hf_ieee1905_steering_req_target_bssid = -1;
static int hf_ieee1905_steering_req_oper_class = -1;
static int hf_ieee1905_steering_req_target_channel = -1;
static int hf_ieee1905_client_bssid = -1;
static int hf_ieee1905_client_mac_addr = -1;
static int hf_ieee1905_client_capability_result = -1;
static int hf_ieee1905_client_capability_frame = -1;
static int hf_ieee1905_association_flag = -1;
static int hf_ieee1905_association_client_mac_addr = -1;
static int hf_ieee1905_association_agent_bssid = -1;
static int hf_ieee1905_association_event_flags = -1;
static int hf_ieee1905_ap_radio_max_bss = -1;
static int hf_ieee1905_ap_radio_classes = -1;
static int hf_ieee1905_ap_radio_class = -1;
static int hf_ieee1905_ap_radio_eirp = -1;
static int hf_ieee1905_ap_radio_non_op_count = -1;
static int hf_ieee1905_radio_basic_non_op_channel = -1;
static int hf_ieee1905_max_supported_tx_streams = -1;
static int hf_ieee1905_max_supported_rx_streams = -1;
static int hf_ieee1905_short_gi_20mhz_flag = -1;
static int hf_ieee1905_short_gi_40mhz_flag = -1;
static int hf_ieee1905_ht_support_40mhz_flag = -1;
static int hf_ieee1905_ap_ht_capabilities_radio_id = -1;
static int hf_ieee1905_ht_cap_flags = -1;
static int hf_ieee1905_vht_max_supported_tx_streams = -1;
static int hf_ieee1905_vht_max_supported_rx_streams = -1;
static int hf_ieee1905_short_gi_80mhz_flag = -1;
static int hf_ieee1905_short_gi_160mhz_flag = -1;
static int hf_ieee1905_vht_support_80plus_mhz_flag = -1;
static int hf_ieee1905_vht_support_160_mhz_flag = -1;
static int hf_ieee1905_su_beamformer_capable_flag = -1;
static int hf_ieee1905_mu_beamformer_capable_flag = -1;
static int hf_ieee1905_ap_vht_capabilities_radio_id = -1;
static int hf_ieee1905_vht_cap_flags = -1;
static int hf_ieee1905_assoc_clients_bss_count = -1;
static int hf_ieee1905_assoc_bssid = -1;
static int hf_ieee1905_bss_client_count = -1;
static int hf_ieee1905_bss_client_mac = -1;
static int hf_ieee1905_bss_client_last_assoc = -1;
static int hf_ieee1905_ap_vht_supported_vht_tx_mcs = -1;
static int hf_ieee1905_ap_vht_supported_vht_rx_mcs = -1;
static int hf_ieee1905_channel_pref_preference = -1;
static int hf_ieee1905_channel_pref_reason = -1;
static int hf_ieee1905_channel_preference_radio_id = -1;
static int hf_ieee1905_channel_preference_class_count = -1;
static int hf_ieee1905_channel_pref_class = -1;
static int hf_ieee1905_channel_pref_channel_count = -1;
static int hf_ieee1905_channel_pref_channel = -1;
static int hf_ieee1905_channel_prefs_flags = -1;
static int hf_ieee1905_trans_power_limit_radio_id = -1;
static int hf_ieee1905_trans_power_limit_eirp = -1;
static int hf_ieee1905_channel_select_resp_radio_id = -1;
static int hf_ieee1905_radio_metrics_radio_id = -1;
static int hf_ieee1905_channel_select_resp_code = -1;
static int hf_ieee1905_op_channel_report_radio_id = -1;
static int hf_ieee1905_op_channel_report_classes = -1;
static int hf_ieee1905_op_channel_class = -1;
static int hf_ieee1905_op_channel_number = -1;
static int hf_ieee1905_op_channel_eirp = -1;
static int hf_ieee1905_ap_he_cap_radio_id = -1;
static int hf_ieee1905_ap_he_cap_mcs_length = -1;
static int hf_ieee1905_ap_he_cap_tx_mcs_le_80_mhz = -1;
static int hf_ieee1905_ap_he_tx_mcs_map_1ss = -1;
static int hf_ieee1905_ap_he_tx_mcs_map_2ss = -1;
static int hf_ieee1905_ap_he_tx_mcs_map_3ss = -1;
static int hf_ieee1905_ap_he_tx_mcs_map_4ss = -1;
static int hf_ieee1905_ap_he_tx_mcs_map_5ss = -1;
static int hf_ieee1905_ap_he_tx_mcs_map_6ss = -1;
static int hf_ieee1905_ap_he_tx_mcs_map_7ss = -1;
static int hf_ieee1905_ap_he_tx_mcs_map_8ss = -1;
static int hf_ieee1905_ap_he_cap_rx_mcs_le_80_mhz = -1;
static int hf_ieee1905_ap_he_rx_mcs_map_1ss = -1;
static int hf_ieee1905_ap_he_rx_mcs_map_2ss = -1;
static int hf_ieee1905_ap_he_rx_mcs_map_3ss = -1;
static int hf_ieee1905_ap_he_rx_mcs_map_4ss = -1;
static int hf_ieee1905_ap_he_rx_mcs_map_5ss = -1;
static int hf_ieee1905_ap_he_rx_mcs_map_6ss = -1;
static int hf_ieee1905_ap_he_rx_mcs_map_7ss = -1;
static int hf_ieee1905_ap_he_rx_mcs_map_8ss = -1;
static int hf_ieee1905_ap_he_cap_tx_mcs_160_mhz = -1;
static int hf_ieee1905_ap_he_cap_rx_mcs_160_mhz = -1;
static int hf_ieee1905_ap_he_cap_tx_mcs_80p80_mhz = -1;
static int hf_ieee1905_ap_he_cap_rx_mcs_80p80_mhz = -1;
static int hf_ieee1905_unassoc_link_metrics_query_mac = -1;
static int hf_ieee1905_unassoc_sta_link_metrics_class = -1;
static int hf_ieee1905_ap_metrics_reporting_interval = -1;
static int hf_ieee1905_metric_reporting_policy_radio_id = -1;
static int hf_ieee1905_metric_reporting_radio_count = -1;
static int hf_ieee1905_metric_rcpi_threshold = -1;
static int hf_ieee1905_metric_reporting_rcpi_hysteresis = -1;
static int hf_ieee1905_metrics_policy_flags = -1;
static int hf_ieee1905_metrics_channel_util_threshold = -1;
static int hf_ieee1905_assoc_sta_traffic_stats_inclusion = -1;
static int hf_ieee1905_assoc_sta_link_metrics_inclusion = -1;
static int hf_ieee1905_assoc_wf6_status_policy_inclusion = -1;
static int hf_ieee1905_reporting_policy_flags_reserved = -1;
static int hf_ieee1905_ap_metric_query_bssid_cnt = -1;
static int hf_ieee1905_ap_metric_query_bssid = -1;
static int hf_ieee1905_sta_mac_address_type = -1;
static int hf_ieee1905_assoc_sta_mac_addr = -1;
static int hf_ieee1905_assoc_sta_bssid_count = -1;
static int hf_ieee1905_assoc_sta_link_metrics_bssid = -1;
static int hf_ieee1905_assoc_sta_link_metrics_time_delta = -1;
static int hf_ieee1905_assoc_sta_link_metrics_dwn_rate = -1;
static int hf_ieee1905_assoc_sta_link_metrics_up_rate = -1;
static int hf_ieee1905_assoc_sta_link_metrics_rcpi = -1;
static int hf_ieee1905_assoc_wf6_sta_mac_addr = -1;
static int hf_ieee1905_assoc_wf6_sta_tid_count = -1;
static int hf_ieee1905_assoc_wf6_sta_tid = -1;
static int hf_ieee1905_assoc_wf6_sta_queue_size = -1;
static int hf_ieee1905_assoc_sta_ext_link_metrics_mac_addr = -1;
static int hf_ieee1905_assoc_sta_ext_link_metrics_count = -1;
static int hf_ieee1905_assoc_sta_extended_metrics_bssid = -1;
static int hf_ieee1905_assoc_sta_extended_metrics_lddlr = -1;
static int hf_ieee1905_assoc_sta_extended_metrics_ldulr = -1;
static int hf_ieee1905_assoc_sta_extended_metrics_ur = -1;
static int hf_ieee1905_assoc_sta_extended_metrics_tr = -1;
static int hf_ieee1905_unassoc_sta_link_channel_count = -1;
static int hf_ieee1905_unassoc_metrics_channel = -1;
static int hf_ieee1905_unassoc_metrics_mac_count = -1;
static int hf_ieee1905_he_max_supported_tx_streams = -1;
static int hf_ieee1905_he_max_supported_rx_streams = -1;
static int hf_ieee1905_he_support_80plus_mhz_flag = -1;
static int hf_ieee1905_he_support_160mhz_flag = -1;
static int hf_ieee1905_he_su_beamformer_capable_flag = -1;
static int hf_ieee1905_he_mu_beamformer_capable_flag = -1;
static int hf_ieee1905_ul_mu_mimo_capable_flag = -1;
static int hf_ieee1905_ul_mu_mimo_ofdma_capable_flag = -1;
static int hf_ieee1905_dl_mu_mimo_ofdma_capable_flag = -1;
static int hf_ieee1905_ul_ofdma_capable = -1;
static int hf_ieee1905_dl_ofdma_capable = -1;
static int hf_ieee1905_he_cap_flags = -1;
static int hf_ieee1905_steering_policy_local_disallowed_count = -1;
static int hf_ieee1905_steering_disallowed_mac_addr = -1;
static int hf_ieee1905_btm_steering_disallowed_count = -1;
static int hf_ieee1905_btm_steering_disallowed_mac_addr = -1;
static int hf_ieee1905_steering_policy_radio_count = -1;
static int hf_ieee1905_steering_policy_radio_id = -1;
static int hf_ieee1905_steering_policy_policy = -1;
static int hf_ieee1905_steering_policy_util = -1;
static int hf_ieee1905_steering_policy_rcpi_threshold = -1;
static int hf_ieee1905_radio_restriction_radio_id = -1;
static int hf_ieee1905_radio_restriction_op_class_count = -1;
static int hf_ieee1905_radio_restriction_op_class = -1;
static int hf_ieee1905_radio_restriction_chan_count = -1;
static int hf_ieee1905_radio_restriction_channel = -1;
static int hf_ieee1905_radio_restriction_min_separation = -1;
static int hf_ieee1905_ap_metrics_agent_bssid = -1;
static int hf_ieee1905_include_estimated_spi_ac_eq_be = -1;
static int hf_ieee1905_include_estimated_spi_ac_eq_bk = -1;
static int hf_ieee1905_include_estimated_spi_ac_eq_vo = -1;
static int hf_ieee1905_include_estimated_spi_ac_eq_vi = -1;
static int hf_ieee1905_ap_metrics_channel_utilization = -1;
static int hf_ieee1905_ap_metrics_sta_count = -1;
static int hf_ieee1905_ap_metrics_flags = -1;
static int hf_ieee1905_ap_metrics_service_params_be = -1;
static int hf_ieee1905_ap_metrics_service_params_bk = -1;
static int hf_ieee1905_ap_metrics_service_params_vo = -1;
static int hf_ieee1905_ap_metrics_service_params_vi = -1;
static int hf_ieee1905_unassoc_sta_link_metric_op_class = -1;
static int hf_ieee1905_unassoc_sta_link_metric_sta_count = -1;
static int hf_ieee1905_unassoc_link_metric_mac_addr = -1;
static int hf_ieee1905_unassoc_link_metric_channel = -1;
static int hf_ieee1905_unassoc_link_metric_delta = -1;
static int hf_ieee1905_unassoc_link_metric_uplink_rcpi = -1;
static int hf_ieee1905_beacon_metrics_query_mac_addr = -1;
static int hf_ieee1905_beacon_metrics_query_op_class = -1;
static int hf_ieee1905_beacon_metrics_query_channel = -1;
static int hf_ieee1905_beacon_metrics_query_bssid = -1;
static int hf_ieee1905_beacon_metrics_query_detail = -1;
static int hf_ieee1905_beacon_metrics_query_ssid_len = -1;
static int hf_ieee1905_beacon_metrics_query_ssid = -1;
static int hf_ieee1905_beacon_metrics_channel_count = -1;
static int hf_ieee1905_beacon_metrics_report_len = -1;
static int hf_ieee1905_beacon_metrics_report_op_class = -1;
static int hf_ieee1905_beacon_metrics_report_channel_id = -1;
static int hf_ieee1905_measurement_report = -1;
static int hf_ieee1905_beacon_metrics_response_mac_addr = -1;
static int hf_ieee1905_beacon_metrics_response_reserved = -1;
static int hf_ieee1905_beacon_metrics_response_meas_num = -1;
static int hf_ieee1905_assoc_sta_traffic_stats_mac_addr = -1;
static int hf_ieee1905_assoc_sta_traffic_stats_bytes_sent = -1;
static int hf_ieee1905_assoc_sta_traffic_stats_bytes_rcvd = -1;
static int hf_ieee1905_assoc_sta_traffic_stats_packets_sent = -1;
static int hf_ieee1905_assoc_sta_traffic_stats_packets_rcvd = -1;
static int hf_ieee1905_assoc_sta_traffic_stats_tx_pkt_errs = -1;
static int hf_ieee1905_assoc_sta_traffic_stats_rx_pkt_errs = -1;
static int hf_ieee1905_assoc_sta_traffic_stats_retrans_count = -1;
static int hf_ieee1905_error_code_value = -1;
static int hf_ieee1905_error_code_mac_addr = -1;
static int hf_ieee1905_channel_scan_rep_policy = -1;
static int hf_ieee1905_channel_scan_pol_report = -1;
static int hf_ieee1905_channel_scan_pol_reserved = -1;
static int hf_ieee1905_channel_scan_capabilities_radio_num = -1;
static int hf_ieee1905_channel_scan_capa_radio_id = -1;
static int hf_ieee1905_channel_scan_capa_flags = -1;
static int hf_ieee1905_channel_scan_capa_flags_on_boot_only = -1;
static int hf_ieee1905_channel_scan_capa_flags_scan_impact = -1;
static int hf_ieee1905_channel_scan_capa_flags_reserved = -1;
static int hf_ieee1905_channel_scan_capa_min_scan_interval = -1;
static int hf_ieee1905_channel_scan_capa_class_num = -1;
static int hf_ieee1905_channel_scan_capa_oper_class = -1;
static int hf_ieee1905_channel_scan_capa_oper_class_chan_cnt = -1;
static int hf_ieee1905_channel_scan_capa_channel = -1;
static int hf_ieee1905_channel_scan_request_flags = -1;
static int hf_ieee1905_channel_scan_request_flags_fresh_scan = -1;
static int hf_ieee1905_channel_scan_request_flags_reserved = -1;
static int hf_ieee1905_channel_scan_request_radio_num = -1;
static int hf_ieee1905_channel_scan_request_radio_id = -1;
static int hf_ieee1905_channel_scan_request_class_num = -1;
static int hf_ieee1905_channel_scan_request_oper_class = -1;
static int hf_ieee1905_channel_scan_request_oper_class_chan_cnt = -1;
static int hf_ieee1905_channel_scan_request_channel = -1;
static int hf_ieee1905_channel_scan_result_radio_id = -1;
static int hf_ieee1905_channel_scan_result_oper_class = -1;
static int hf_ieee1905_channel_scan_result_channel = -1;
static int hf_ieee1905_channel_scan_result_status = -1;
static int hf_ieee1905_channel_scan_result_timestamp_len = -1;
static int hf_ieee1905_channel_scan_result_timestamp_string = -1;
static int hf_ieee1905_channel_scan_result_utilization = -1;
static int hf_ieee1905_channel_scan_result_noise = -1;
static int hf_ieee1905_radio_metrics_noise = -1;
static int hf_ieee1905_radio_metrics_transmit = -1;
static int hf_ieee1905_radio_metrics_receive_self = -1;
static int hf_ieee1905_radio_metrics_receive_other = -1;
static int hf_ieee1905_ap_extended_metrics_bssid = -1;
static int hf_ieee1905_ap_extended_metrics_unicast_sent = -1;
static int hf_ieee1905_ap_extended_metrics_unicast_rcvd = -1;
static int hf_ieee1905_ap_extended_metrics_multicast_sent = -1;
static int hf_ieee1905_ap_extended_metrics_multicast_rcvd = -1;
static int hf_ieee1905_ap_extended_metrics_bcast_sent = -1;
static int hf_ieee1905_ap_extended_metrics_bcast_rcvd = -1;
static int hf_ieee1905_channel_scan_result_neigh_num = -1;
static int hf_ieee1905_channel_scan_result_bssid = -1;
static int hf_ieee1905_channel_scan_result_ssid_len = -1;
static int hf_ieee1905_channel_scan_result_ssid = -1;
static int hf_ieee1905_channel_scan_result_sig_level = -1;
static int hf_ieee1905_channel_scan_result_bw_len = -1;
static int hf_ieee1905_channel_scan_result_bw = -1;
static int hf_ieee1905_channel_scan_result_neigh_flags = -1;
static int hf_ieee1905_channel_scan_result_load_element_present = -1;
static int hf_ieee1905_channel_scan_result_neigh_reserved = -1;
static int hf_ieee1905_channel_scan_result_util = -1;
static int hf_ieee1905_channel_scan_result_sta_count = -1;
static int hf_ieee1905_channel_scan_result_scan_duration = -1;
static int hf_ieee1905_channel_scan_result_flags = -1;
static int hf_ieee1905_channel_scan_result_scan_type = -1;
static int hf_ieee1905_channel_scan_result_scan_flags_reserved = -1;
static int hf_ieee1905_timestamp_length = -1;
static int hf_ieee1905_timestamp_string = -1;
static int hf_ieee1905_1905_layer_sec_capa_onboarding = -1;
static int hf_ieee1905_1905_layer_sec_capa_mic_sup = -1;
static int hf_ieee1905_1905_layer_sec_capa_enc_alg_sup = -1;
static int hf_ieee1905_ap_wf6_capa_radio_id = -1;
static int hf_ieee1905_ap_wf6_role_count = -1;
static int hf_ieee1905_ap_wf6_agent_role_flags = -1;
static int hf_ieee1905_ap_wf6_capa_agents_role = -1;
static int hf_ieee1905_ap_wf6_capa_he_160_support = -1;
static int hf_ieee1905_ap_wf6_capa_he_80p80_support = -1;
static int hf_ieee1905_ap_wf6_capa_reserved = -1;
static int hf_ieee1905_ap_wf6_he_supported_flags = -1;
static int hf_ieee1905_ap_wf6_su_beamformer = -1;
static int hf_ieee1905_ap_wf6_su_beamformee = -1;
static int hf_ieee1905_ap_wf6_mu_beamformer_status = -1;
static int hf_ieee1905_ap_wf6_beamformee_sts_le_80mhz = -1;
static int hf_ieee1905_ap_wf6_beamformee_sts_gt_80mhz = -1;
static int hf_ieee1905_ap_wf6_ul_mu_mimo = -1;
static int hf_ieee1905_ap_wf6_ul_ofdma = -1;
static int hf_ieee1905_ap_wf6_dl_ofdma = -1;
static int hf_ieee1905_ap_wf6_mimo_max_flags = -1;
static int hf_ieee1905_ap_wf6_max_ap_dl_mu_mimo_tx = -1;
static int hf_ieee1905_ap_wf6_max_ap_ul_mu_mimi_rx = -1;
static int hf_ieee1905_ap_wf6_dl_ofdma_max_tx = -1;
static int hf_ieee1905_ap_wf6_ul_ofdma_max_rx = -1;
static int hf_ieee1905_ap_wf6_gen_flags = -1;
static int hf_ieee1905_ap_wf6_gen_rts = -1;
static int hf_ieee1905_ap_wf6_gen_mu_rts = -1;
static int hf_ieee1905_ap_wf6_gen_multi_bssid = -1;
static int hf_ieee1905_ap_wf6_gen_mu_edca = -1;
static int hf_ieee1905_ap_wf6_gen_twt_requester = -1;
static int hf_ieee1905_ap_wf6_gen_twt_responder = -1;
static int hf_ieee1905_ap_wf6_gen_reserved = -1;
static int hf_ieee1905_agent_list_bytes = -1;
static int hf_ieee1905_loop_prevention_mech_setting = -1;
static int hf_ieee1905_loop_prevention_mechanism = -1;
static int hf_ieee1905_loop_prevention_preferred_backhaul_intf = -1;
static int hf_ieee1905_loop_prevention_reserved = -1;
static int hf_ieee1905_loop_detection_sequence_number = -1;
static int hf_ieee1905_group_integrity_key_id = -1;
static int hf_ieee1905_group_integrity_key_len = -1;
static int hf_ieee1905_group_integrity_key_bytes = -1;
static int hf_ieee1905_group_integrity_key_mic_alg = -1;
static int hf_ieee1905_mic_group_temporal_key_id = -1;
static int hf_ieee1905_mic_integrity_transmission_counter = -1;
static int hf_ieee1905_mic_source_la_mac_id = -1;
static int hf_ieee1905_mic_length = -1;
static int hf_ieee1905_mic_bytes = -1;
static int hf_ieee1905_1905_gtk_key_id = -1;
static int hf_ieee1905_mic_version = -1;
static int hf_ieee1905_mic_reserved = -1;
static int hf_ieee1905_encrypted_dest_al_mac_addr = -1;
static int hf_ieee1905_encrypted_enc_transmission_count = -1;
static int hf_ieee1905_encrypted_source_la_mac_id = -1;
static int hf_ieee1905_encrypted_enc_output_field_len = -1;
static int hf_ieee1905_encrypted_enc_output_field = -1;
static int hf_ieee1905_cac_request_radio_count = -1;
static int hf_ieee1905_cac_request_radio_id = -1;
static int hf_ieee1905_cac_request_op_class = -1;
static int hf_ieee1905_cac_request_channel = -1;
static int hf_ieee1905_cac_request_flags = -1;
static int hf_ieee1905_cac_request_method = -1;
static int hf_ieee1905_cac_request_completion_action = -1;
static int hf_ieee1905_cac_request_completion_unsuccess = -1;
static int hf_ieee1905_cac_request_reserved = -1;
static int hf_ieee1905_cac_termination_radio_count = -1;
static int hf_ieee1905_cac_terminate_radio_id = -1;
static int hf_ieee1905_cac_terminate_op_class = -1;
static int hf_ieee1905_cac_terminate_channel = -1;
static int hf_ieee1905_cac_terminate_action = -1;
static int hf_ieee1905_cac_completion_rep_radio_count = -1;
static int hf_ieee1905_cac_completion_radio_id = -1;
static int hf_ieee1905_cac_completion_op_class = -1;
static int hf_ieee1905_cac_completion_channel = -1;
static int hf_ieee1905_cac_completion_status = -1;
static int hf_ieee1905_cac_completion_radar_count = -1;
static int hf_ieee1905_cac_comp_radar_op_class = -1;
static int hf_ieee1905_cac_comp_radar_channel = -1;
static int hf_ieee1905_cac_status_rpt_active_chan = -1;
static int hf_ieee1905_cac_status_rpt_avail_op_class = -1;
static int hf_ieee1905_cac_status_rpt_avail_channel = -1;
static int hf_ieee1905_cac_status_rpt_avail_minutes = -1;
static int hf_ieee1905_cac_status_rpt_non_occ_cnt = -1;
static int hf_ieee1905_cac_status_rpt_non_occ_op_class = -1;
static int hf_ieee1905_cac_status_rpt_non_occ_channel = -1;
static int hf_ieee1905_cac_status_rpt_non_occ_seconds = -1;
static int hf_ieee1905_cac_status_rpt_active_cac_cnt = -1;
static int hf_ieee1905_cac_status_rpt_active_cac_op_class = -1;
static int hf_ieee1905_cac_status_rpt_active_cac_channel = -1;
static int hf_ieee1905_cac_status_rpt_active_cac_seconds = -1;
static int hf_ieee1905_cac_capa_country_code = -1;
static int hf_ieee1905_cac_capa_radio_cnt = -1;
static int hf_ieee1905_cac_capabilities_radio_id = -1;
static int hf_ieee1905_cac_capabilities_types_num = -1;
static int hf_ieee1905_cac_capabilities_cac_mode = -1;
static int hf_ieee1905_cac_capabilities_cac_seconds = -1;
static int hf_ieee1905_cac_capabilities_op_class_num = -1;
static int hf_ieee1905_cac_capabilities_op_class = -1;
static int hf_ieee1905_cac_capabilities_channel_cnt = -1;
static int hf_ieee1905_cac_capabillity_channel = -1;
static int hf_ieee1905_multi_ap_version = -1;
static int hf_ieee1905_max_total_serv_prio_rules = -1;
static int hf_ieee1905_r2_ap_capa_reserved = -1;
static int hf_ieee1905_r2_ap_capa_flags = -1;
static int hf_ieee1905_byte_counter_units = -1;
static int hf_ieee1905_basic_service_prio_flag = -1;
static int hf_ieee1905_enhanced_service_prio_flag = -1;
static int hf_ieee1905_r2_ap_capa_flags_reserved = -1;
static int hf_ieee1905_max_vid_count = -1;
static int hf_ieee1905_default_802_1q_settings_primary_vlan = -1;
static int hf_ieee1905_default_802_1q_settings_flags = -1;
static int hf_ieee1905_default_802_1q_settings_default_pcp = -1;
static int hf_ieee1905_default_802_1q_settings_reserved = -1;
static int hf_ieee1905_ap_radio_advanced_capa_radio_id = -1;
static int hf_ieee1905_radio_advanced_capa_flags = -1;
static int hf_ieee1905_traffic_separation_policy_num_ssids = -1;
static int hf_ieee1905_traffic_separation_policy_ssid_len = -1;
static int hf_ieee1905_traffic_separation_policy_ssid = -1;
static int hf_ieee1905_traffic_separation_policy_vlanid = -1;
static int hf_ieee1905_bss_config_report_radio_count = -1;
static int hf_ieee1905_bss_config_report_radio_id = -1;
static int hf_ieee1905_bss_config_report_flags = -1;
static int hf_ieee1905_bss_config_report_backhaul_bss = -1;
static int hf_ieee1905_bss_config_report_fronthaul_bss = -1;
static int hf_ieee1905_bss_config_report_r1_disallowed_status = -1;
static int hf_ieee1905_bss_config_report_r2_disallowed_status = -1;
static int hf_ieee1905_bss_config_report_multiple_bssid_set = -1;
static int hf_ieee1905_bss_config_report_transmitted_bssid = -1;
static int hf_ieee1905_bss_config_report_reserved = -1;
static int hf_ieee1905_bss_config_report_res = -1;
static int hf_ieee1905_bss_config_report_bss_cnt = -1;
static int hs_ieee1902_bss_config_report_mac = -1;
static int hf_ieee1902_bss_config_report_ssid_len = -1;
static int hf_ieee1905_bss_config_report_ssid = -1;
static int hf_ieee1905_packet_filtering_policy_bssid_num = -1;
static int hf_ieee1905_packet_filtering_policy_bssid = -1;
static int hf_ieee1905_packet_filtering_policy_mac_count = -1;
static int hf_ieee1905_packet_filtering_policy_mac_addr = -1;
static int hf_ieee1905_bssid_tlv_bssid = -1;
static int hf_ieee1905_service_prio_rule_id = -1;
static int hf_ieee1905_service_prio_rule_flags = -1;
static int hf_ieee1905_service_prio_rule_add_remove_filter_bit = -1;
static int hf_ieee1905_service_prio_rule_flags_reserved = -1;
static int hf_ieee1905_service_prio_match_flags = -1;
static int hf_ieee1905_service_prio_rule_precedence = -1;
static int hf_ieee1905_service_prio_rule_output = -1;
static int hf_ieee1905_service_prio_rule_match_always = -1;
static int hf_ieee1905_service_prio_rule_match_reserved = -1;
static int hf_ieee1905_service_prio_rule_match_up_in_qos = -1;
static int hf_ieee1905_service_prio_rule_match_up_control_match = -1;
static int hf_ieee1905_service_prio_rule_match_source_mac = -1;
static int hf_ieee1905_service_prio_rule_match_source_mac_sense = -1;
static int hf_ieee1905_service_prio_rule_match_dest_mac = -1;
static int hf_ieee1905_service_prio_rule_match_dest_mac_sense = -1;
static int hf_ieee1905_service_prio_rule_up_control = -1;
static int hf_ieee1905_service_prio_rule_source_mac = -1;
static int hf_ieee1905_service_prio_rule_dest_mac = -1;
static int hf_ieee1905_dscp_mapping_table_val = -1;
static int hf_ieee1905_r2_error_reason_code = -1;
static int hf_ieee1905_r2_error_bssid = -1;
static int hf_ieee1905_ap_radio_advance_capa_backhaul_bss_traffic_sep = -1;
static int hf_ieee1905_ap_radio_advance_capa_combined_r1_r2_backhaul = -1;
static int hf_ieee1905_ap_radio_advance_capa_reserved = -1;
static int hf_ieee1905_assoc_status_notif_num_bssid = -1;
static int hf_ieee1905_assoc_status_notif_bssid = -1;
static int hf_ieee1905_assoc_status_notif_status = -1;
static int hf_ieee1905_source_info_mac_addr = -1;
static int hf_ieee1905_tunneled_message_type = -1;
static int hf_ieee1905_tunneled_data = -1;
static int hf_ieee1905_status_code_status = -1;
static int hf_ieee1905_disassociation_reason_code = -1;
static int hf_ieee1905_backhaul_sta_radio_id = -1;
static int hf_ieee1905_backhaul_sta_radio_capabilities = -1;
static int hf_ieee1905_backhaul_sta_radio_capa_mac_included = -1;
static int hf_ieee1905_backhaul_sta_radio_capa_reserved = -1;
static int hf_ieee1905_backhaul_sta_addr = -1;
static int hf_ieee1905_backhaul_akm_suite_capa_count = -1;
static int hf_ieee1905_akm_backhaul_suite_oui = -1;
static int hf_ieee1905_akm_backhaul_suite_type = -1;
static int hf_ieee1905_fronthaul_akm_suite_capa_count = -1;
static int hf_ieee1905_akm_fronthaul_suite_oui = -1;
static int hf_ieee1905_akm_fronthaul_suite_type = -1;
static int hf_ieee1905_encap_dpp_flags = -1;
static int hf_ieee1905_dpp_encap_enrollee_mac_present = -1;
static int hf_ieee1905_dpp_encap_reserved = -1;
static int hf_ieee1905_dpp_encap_frame_type_flag = -1;
static int hf_ieee1905_dpp_encap_reserved2 = -1;
static int hf_ieee1905_encap_dpp_sta_mac = -1;
static int hf_ieee1905_dpp_encap_frame_type = -1;
static int hf_ieee1905_dpp_encap_frame_length = -1;
static int hf_ieee1905_dpp_encap_dpp_oui = -1;
static int hf_ieee1905_dpp_encap_category = -1;
static int hf_ieee1905_dpp_encap_public_action = -1;
static int hf_ieee1905_dpp_encap_dpp_subtype = -1;
static int hf_ieee1905_dpp_bootstrapping_uri_radio_id = -1;
static int hf_ieee1905_dpp_bootstrapping_uri_local_mac_addr = -1;
static int hf_ieee1905_dpp_bootstrapping_uri_bsta_mac_addr = -1;
static int hf_ieee1905_dpp_bootstrapping_uri_received = -1;
static int hf_ieee1905_dpp_advertise_cce_flag = -1;
static int hf_ieee1905_dpp_chirp_value_flags = -1;
static int hf_ieee1905_dpp_chirp_enrollee_mac_addr_present = -1;
static int hf_ieee1905_dpp_chirp_hash_validity = -1;
static int hf_ieee1905_dpp_chirp_reserved = -1;
static int hf_ieee1905_dpp_chirp_enrollee_mac_addr = -1;
static int hf_ieee1905_dpp_chirp_value_hash_length = -1;
static int hf_ieee1905_dpp_chirp_value_hash_value = -1;
static int hf_ieee1905_dev_inventory_lsn = -1;
static int hf_ieee1905_dev_inventory_serial = -1;
static int hf_ieee1905_dev_inventory_lsv = -1;
static int hf_ieee1905_dev_inventory_sw_vers = -1;
static int hf_ieee1905_dev_inventory_lee = -1;
static int hf_ieee1905_dev_inventory_exec_env = -1;
static int hf_ieee1905_dev_inventory_num_radios = -1;
static int hf_ieee1905_dev_inventory_radio_id = -1;
static int hf_ieee1905_dev_inventory_lcv = -1;
static int hf_ieee1905_dev_inventory_chp_ven = -1;
static int hf_ieee1905_r2_steering_req_src_bssid = -1;
static int hf_ieee1905_r2_steering_req_flags = -1;
static int hf_ieee1905_r2_steering_request_mode_flag = -1;
static int hf_ieee1905_r2_btm_disassoc_imminent_flag = -1;
static int hf_ieee1905_r2_btm_abridged_flag = -1;
static int hf_ieee1905_r2_steering_req_reserved = -1;
static int hf_ieee1905_r2_steering_op_window = -1;
static int hf_ieee1905_r2_steering_btm_dissasoc_tmr = -1;
static int hf_ieee1905_r2_steering_sta_count = -1;
static int hf_ieee1905_r2_steering_sta_mac = -1;
static int hf_ieee1905_r2_steering_target_count = -1;
static int hf_ieee1905_r2_steering_target_bssid = -1;
static int hf_ieee1905_r2_steering_target_op_class = -1;
static int hf_ieee1905_r2_steering_target_channel = -1;
static int hf_ieee1905_r2_steering_reason = -1;
static int hf_ieee1905_metric_collection_interval = -1;
static int hf_ieee1905_max_reporting_rate = -1;
static int hf_ieee1905_bss_configuration_request = -1;
static int hf_ieee1905_bss_configuration_response = -1;
static int hf_ieee1905_dpp_message_category = -1;
static int hf_ieee1905_dpp_message_public_action = -1;

static gint ett_ieee1905 = -1;
static gint ett_ieee1905_flags = -1;
static gint ett_ieee1905_tlv_len = -1;
static gint ett_tlv = -1;
static gint ett_device_information_list = -1;
static gint ett_device_information_tree = -1;
static gint ett_media_type = -1;
static gint ett_bridging_tuples_list = -1;
static gint ett_bridging_mac_list = -1;
static gint ett_non_1905_neighbor_list = -1;
static gint ett_1905_neighbor_list = -1;
static gint ett_ieee1905_neighbor_flags = -1;
static gint ett_media_type_list = -1;
static gint ett_media_item = -1;
static gint ett_local_interface_list = -1;
static gint ett_local_interface_info = -1;
static gint ett_ipv4_list = -1;
static gint ett_ipv4_info = -1;
static gint ett_ipv4_type_addr_list = -1;
static gint ett_ipv4_addr_info = -1;
static gint ett_ipv6_list = -1;
static gint ett_ipv6_info = -1;
static gint ett_ipv6_type_addr_list = -1;
static gint ett_ipv6_addr_info = -1;
static gint ett_push_button_phy_list = -1;
static gint ett_push_button_phy_info = -1;
static gint ett_power_off_info = -1;
static gint ett_power_change_list = -1;
static gint ett_power_change_info = -1;
static gint ett_power_status_list = -1;
static gint ett_power_status_info = -1;
static gint ett_l2_local_intf_list = -1;
static gint ett_l2_neighbor_device_info = -1;
static gint ett_l2_neighbor_dev_list = -1;
static gint ett_l2_neighbor_dev_tree = -1;
static gint ett_supported_service_list = -1;
static gint ett_searched_service_list = -1;
static gint ett_ap_operational_bss_list = -1;
static gint ett_ap_operational_bss_tree = -1;
static gint ett_ap_operational_bss_intf = -1;
static gint ett_ap_operational_bss_intf_list = -1;
static gint ett_ap_operational_bss_intf_tree = -1;
static gint ett_ieee1905_capabilities_flags = -1;
static gint ett_ieee1905_unsuccessful_associations = -1;
static gint ett_assoc_control_list = -1;
static gint ett_ieee1905_steering_request_flags = -1;
static gint ett_ieee1905_association_event_flags = -1;
static gint ett_radio_basic_class_list = -1;
static gint ett_ap_radio_basic_cap_class_tree = -1;
static gint ett_radio_basic_non_op_list = -1;
static gint ett_ht_cap_flags = -1;
static gint ett_vht_cap_flags = -1;
static gint ett_assoc_clients_bss_list = -1;
static gint ett_assoc_client_bss_tree = -1;
static gint ett_assoc_client_list = -1;
static gint ett_assoc_client_tree = -1;
static gint ett_channel_preference_class_list = -1;
static gint ett_ap_channel_preference_class_tree = -1;
static gint ett_channel_pref_channel_list = -1;
static gint ett_ieee1905_channel_prefs_flags = -1;
static gint ett_op_channel_report_class_tree = -1;
static gint ett_op_channel_report_class_list = -1;
static gint ett_sta_link_metrics_query_channel_list = -1;
static gint ett_sta_link_link_mac_addr_list = -1;
static gint ett_metric_reporting_policy_list = -1;
static gint ett_metric_reporting_policy_tree = -1;
static gint ett_metric_policy_flags = -1;
static gint ett_ap_metric_query_bssid_list = -1;
static gint ett_ieee1905_ap_metrics_flags = -1;
static gint ett_sta_list_metrics_bss_list = -1;
static gint ett_sta_list_metrics_bss_tree = -1;
static gint ett_sta_wf6_status_report_tid_list = -1;
static gint ett_sta_wf6_status_report_tid_tree = -1;
static gint ett_sta_extended_link_metrics_list = -1;
static gint ett_sta_extended_link_metrics_tree = -1;
static gint ett_ap_he_mcs_set = -1;
static gint ett_ap_he_cap_flags = -1;
static gint ett_ieee1905_ap_he_tx_mcs_set = -1;
static gint ett_ieee1905_ap_he_rx_mcs_set = -1;
static gint ett_steering_policy_disallowed_list = -1;
static gint ett_btm_steering_policy_disallowed_list = -1;
static gint ett_btm_steering_radio_list = -1;
static gint ett_radio_restriction_op_class_list = -1;
static gint ett_radio_restriction_op_class_tree = -1;
static gint ett_radio_restriction_channel_list = -1;
static gint ett_radio_restriction_channel_tree = -1;
static gint ett_unassoc_sta_link_metric_list = -1;
static gint ett_unassoc_sta_link_metric_tree = -1;
static gint ett_beacon_metrics_query_list = -1;
static gint ett_beacon_metrics_query_tree = -1;
static gint ett_beacon_metrics_query_channel_list = -1;
static gint ett_beacon_report_subelement_list = -1;
static gint ett_beacon_report_sub_element_tree = -1;
static gint ett_beacon_metrics_response_report_list = -1;
static gint ett_beacon_metrics_response_report_tree = -1;
static gint ett_ieee1905_beacon_reported_flags = -1;
static gint ett_channel_scan_rep_policy = -1;
static gint ett_channel_scan_capa_radio_list = -1;
static gint ett_channel_scan_capa_radio = -1;
static gint ett_channel_scan_capa_flags = -1;
static gint ett_channel_scan_capa_class_list = -1;
static gint ett_channel_scan_capa_class = -1;
static gint ett_channel_scan_capa_channels = -1;
static gint ett_channel_scan_request_flags = -1;
static gint ett_channel_scan_request_radio_list = -1;
static gint ett_channel_scan_request_radio = -1;
static gint ett_channel_scan_request_class_list = -1;
static gint ett_channel_scan_request_class = -1;
static gint ett_channel_scan_request_channels = -1;
static gint ett_channel_scan_result_neigh_list = -1;
static gint ett_channel_scan_result_neigh_flags = -1;
static gint ett_channel_scan_result_neigh = -1;
static gint ett_channel_scan_result_flags = -1;
static gint ett_ap_wf6_role_list = -1;
static gint ett_ap_wf6_role_tree = -1;
static gint ett_ap_wf6_agent_role_flags = -1;
static gint ett_ap_wf6_supported_flags = -1;
static gint ett_ap_wf6_mimo_max_flags = -1;
static gint ett_ap_wf6_gen_flags = -1;
static gint ett_cac_request_flags = -1;
static gint ett_cac_request_radio_list = -1;
static gint ett_cac_request_radio = -1;
static gint ett_cac_terminate_radio_list = -1;
static gint ett_cac_terminate_radio = -1;
static gint ett_cac_completion_radio_list = -1;
static gint ett_cac_completion_radio = -1;
static gint ett_cac_completion_radar_list = -1;
static gint ett_cac_completion_radar = -1;
static gint ett_cac_status_rpt_avail_list = -1;
static gint ett_cac_status_rpt_avail_chan = -1;
static gint ett_cac_status_rpt_non_occupy_list = -1;
static gint ett_cac_status_rpt_unocc_chan = -1;
static gint ett_cac_status_rpt_active_cac_list = -1;
static gint ett_cac_status_rpt_active_cac_tree = -1;
static gint ett_cac_capabilities_radio_list = -1;
static gint ett_cac_capabilities_radio_tree = -1;
static gint ett_cac_capabilities_type_list = -1;
static gint ett_cac_capabilities_type_tree = -1;
static gint ett_cac_capabilities_class_list = -1;
static gint ett_cac_capabilities_class_tree = -1;
static gint ett_cac_capabilities_channel_list = -1;
static gint ett_cac_capabilities_channel = -1;
static gint ett_r2_ap_capa_flags = -1;
static gint ett_edge_interface_list = -1;
static gint ett_radio_advanced_capa_flags = -1;
static gint ett_ap_operational_backhaul_bss_tree = -1;
static gint ett_ap_operational_backhaul_bss_intf_list = -1;
static gint ett_default_802_1q_settings_flags = -1;
static gint ett_traffic_separation_ssid_list = -1;
static gint ett_traffic_separation_ssid = -1;
static gint ett_bss_config_report_list = -1;
static gint ett_bss_config_report_tree = -1;
static gint ett_bss_config_report_bss_list = -1;
static gint ett_bss_config_report_bss_tree = -1;
static gint ett_bss_config_report_flags = -1;
static gint ett_packet_filtering_policy_bssid_list = -1;
static gint ett_packet_filtering_policy_bssid = -1;
static gint ett_packet_filtering_policy_mac_tree = -1;
static gint ett_ethernet_config_policy_list = -1;
static gint ett_ethernet_config_policy = -1;
static gint ett_ethernet_config_policy_flags = -1;
static gint ett_ieee1905_service_prio_rule_flags = -1;
static gint ett_ieee1905_service_prio_rule_match_flags = -1;
static gint ett_backhaul_sta_radio_capa_flags = -1;
static gint ett_assoc_status_notif_bssid_list = -1;
static gint ett_assoc_status_notif_bssid_tree = -1;
static gint ett_akm_suite_list = -1;
static gint ett_akm_suite = -1;
static gint ett_backhaul_akm_suite_list = -1;
static gint ett_backhaul_akm_suite = -1;
static gint ett_fronthaul_akm_suite_list = -1;
static gint ett_fronthaul_akm_suite = -1;
static gint ett_1905_encap_dpp_flags = -1;
static gint ett_1905_encap_dpp_classes = -1;
static gint ett_1905_encap_dpp_op_class_tree = -1;
static gint ett_1905_encap_dpp_channel_list = -1;
static gint ett_ieee1905_dpp_chirp = -1;
static gint ett_device_inventory_radio_list = -1;
static gint ett_device_inventory_radio_tree = -1;
static gint ett_r2_steering_sta_list = -1;
static gint ett_r2_steering_target_list = -1;
static gint ett_r2_steering_target = -1;
static gint ett_loop_prevention_mech = -1;
static gint ett_mic_group_temporal_key = -1;

static gint ett_ieee1905_fragment = -1;
static gint ett_ieee1905_fragments = -1;

static expert_field ei_ieee1905_malformed_tlv = EI_INIT;
static expert_field ei_ieee1905_extraneous_data_after_eom = EI_INIT;
static expert_field ei_ieee1905_extraneous_tlv_data = EI_INIT;
static expert_field ei_ieee1905_deprecated_tlv = EI_INIT;

#define TOPOLOGY_DISCOVERY_MESSAGE                     0x0000
#define TOPOLOGY_NOTIFICATION_MESSAGE                  0x0001
#define TOPOLOGY_QUERY_MESSAGE                         0x0002
#define TOPOLOGY_RESPONSE_MESSAGE                      0x0003
#define VENDOR_SPECIFIC_MESSAGE                        0x0004
#define LINK_METRIC_QUERY_MESSAGE                      0x0005
#define LINK_METRIC_RESPONSE_MESSAGE                   0x0006
#define AP_AUTOCONFIGURATION_SEARCH_MESSAGE            0x0007
#define AP_AUTOCONFIGURATION_RESPONSE_MESSAGE          0x0008
#define AP_AUTOCONFIGURATION_WSC_MESSAGE               0x0009
#define AP_AUTOCONFIGURATION_RENEW_MESSAGE             0x000A
#define IEEE1905_PUSH_BUTTON_EVENT_NOTIFICATION_MESSAGE 0x000B
#define IEEE1905_PUSH_BUTTON_JOIN_NOTIFICATION_MESSAGE  0x000C
#define HIGHER_LAYER_QUERY_MESSAGE                     0x000D
#define HIGHER_LAYER_RESPONSE_MESSAGE                  0x000E
#define INTERFACE_POWER_CHANGE_REQUEST_MESSAGE         0x000F
#define INTERFACE_POWER_CHANGE_RESPONSE_MESSAGE        0x0010
#define GENERIC_PHY_QUERY_MESSAGE                      0x0011
#define GENERIC_PHY_RESPONSE_MESSAGE                   0x0012
#define IEEE1905_ACK_MESSAGE                           0x8000
#define AP_CAPABILITY_QUERY_MESSAGE                    0x8001
#define AP_CAPABILITY_REPORT_MESSAGE                   0x8002
#define MULTI_AP_POLICY_CONFIG_REQUEST_MESSAGE         0x8003
#define CHANNEL_PREFERENCE_QUERY_MESSAGE               0x8004
#define CHANNEL_PREFERENCE_REPORT_MESSAGE              0x8005
#define CHANNEL_SELECTION_REQUEST_MESSAGE              0x8006
#define CHANNEL_SELECTION_RESPONSE_MESSAGE             0x8007
#define OPERATING_CHANNEL_REPORT_MESSAGE               0x8008
#define CLIENT_CAPABILITIES_QUERY_MESSAGE              0x8009
#define CLIENT_CAPABILITIES_REPORT_MESSAGE             0x800A
#define AP_METRICS_QUERY_MESSAGE                       0x800B
#define AP_METRICS_RESPONSE_MESSAGE                    0x800C
#define ASSOCIATED_STA_LINK_METRICS_QUERY_MESSAGE      0x800D
#define ASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE   0x800E
#define UNASSOCIATED_STA_LINK_METRICS_QUERY_MESSAGE    0x800F
#define UNASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE 0x8010
#define BEACON_METRICS_QUERY_MESSAGE                   0x8011
#define BEACON_METRICS_REPONSE_METRICS                 0x8012
#define COMBINED_INFRASTRUCTURE_METRICS_MESSAGE        0x8013
#define CLIENT_STEERING_REQUEST_MESSAGE                0x8014
#define CLIENT_STEERING_BTM_REPORT_MESSAGE             0x8015
#define CLIENT_ASSOCIATION_CONTROL_REQUEST_MESSAGE     0x8016
#define STEERING_COMPLETED_MESSAGE                     0x8017
#define HIGHER_LAYER_DATA_MESSAGE                      0x8018
#define BACKHAUL_STEERING_REQUEST_MESSAGE              0x8019
#define BACKHAUL_STEERING_RESPONSE_MESSAGE             0x801A
#define CHANNEL_SCAN_REQUEST_MESSAGE                   0x801B
#define CHANNEL_SCAN_REPORT_MESSAGE                    0x801C
#define DPP_CCE_INDICATION_MESSAGE                     0x801D
#define IEEE1905_REKEY_REQUEST_MESSAGE                 0x801E
#define IEEE1905_DECRYPTION_FAILURE                    0x801F
#define CAC_REQUEST_MESSAGE                            0x8020
#define CAC_TERMINATION_MESSAGE                        0x8021
#define CLIENT_DISASSOCIATION_STATS_MESSAGE            0x8022
#define SERVICE_PPRIORITIZATION_REQUEST                0x8023
#define ERROR_RESPONSE_MESSAGE                         0x8024
#define ASSOCIATION_STATUS_NOTIFICATION_MESSAGE        0x8025
#define TUNNELLED_MESSAGE                              0x8026
#define BACKHAUL_STA_CAPABILITY_QUERY_MESSAGE          0x8027
#define BACKHAUL_STA_CAPABILITY_REPORT_MESSAGE         0x8028
#define PROXIED_ENCAP_DPP_MESSAGE                      0x8029
#define DIRECT_ENCAP_DPP_MESSAGE                       0x802a
#define RECONFIGURATION_TRIGGER_MESSAGE                0x802B
#define BSS_CONFIGURATION_REQUEST_MESSAGE              0x802C
#define BSS_CONFIGURATION_RESPONSE_MESSAGE             0x802D
#define BSS_CONFIGURATION_RESULT_MESSAGE               0x802E
#define CHIRP_NOTIFICATION_MESSAGE                     0x802F
#define IEEE1905_ENCAP_EAPOL_MESSAGE                   0x8030
#define DPP_BOOTSTRAPPING_URI_NOTIFICATION_MESSAGE     0x8031
#define DPP_BOOTSTRAPPING_URI_QUERY_MESSAGE            0x8032
#define FAILED_CONNECTION_MESSAGE                      0x8033
#define DPP_URI_NOTIFICATION_MESSAGE                   0x8034
#define AGENT_LIST_MESSAGE                             0x8035
#define LOOP_DETECTION_MESSAGE                         0x8036

static const value_string ieee1905_message_type_vals[] = {
  { TOPOLOGY_DISCOVERY_MESSAGE,                  "Topology discovery" },
  { TOPOLOGY_NOTIFICATION_MESSAGE,               "Topology notification" },
  { TOPOLOGY_QUERY_MESSAGE,                      "Topology query" },
  { TOPOLOGY_RESPONSE_MESSAGE,                   "Topology response" },
  { VENDOR_SPECIFIC_MESSAGE,                     "Vendor specific" },
  { LINK_METRIC_QUERY_MESSAGE,                   "Link metric query" },
  { LINK_METRIC_RESPONSE_MESSAGE,                "Link metric response" },
  { AP_AUTOCONFIGURATION_SEARCH_MESSAGE,         "AP autoconfiguration search" },
  { AP_AUTOCONFIGURATION_RESPONSE_MESSAGE,       "AP autoconfiguration response" },
  { AP_AUTOCONFIGURATION_WSC_MESSAGE,            "AP autoconfiguration Wi-Fi simple configuration (WSC)" },
  { AP_AUTOCONFIGURATION_RENEW_MESSAGE,          "AP autoconfiguration renew" },
  { IEEE1905_PUSH_BUTTON_EVENT_NOTIFICATION_MESSAGE, "1905 push button event notification" },
  { IEEE1905_PUSH_BUTTON_JOIN_NOTIFICATION_MESSAGE,  "1905 push button join notification" },
  { HIGHER_LAYER_QUERY_MESSAGE,                  "Higher layer query" },
  { HIGHER_LAYER_RESPONSE_MESSAGE,               "Higher layer response" },
  { INTERFACE_POWER_CHANGE_REQUEST_MESSAGE,      "Interface power change request" },
  { INTERFACE_POWER_CHANGE_RESPONSE_MESSAGE,     "Interface power change response" },
  { GENERIC_PHY_QUERY_MESSAGE,                   "Generic phy query" },
  { GENERIC_PHY_RESPONSE_MESSAGE,                "Generic phy response" },
  { IEEE1905_ACK_MESSAGE,                        "1905 Ack" },
  { AP_CAPABILITY_QUERY_MESSAGE,                 "AP Capability Query" },
  { AP_CAPABILITY_REPORT_MESSAGE,                "AP Capability Report" },
  { MULTI_AP_POLICY_CONFIG_REQUEST_MESSAGE,      "Multi-AP Policy Config Request" },
  { CHANNEL_PREFERENCE_QUERY_MESSAGE,            "Channel Preference Query" },
  { CHANNEL_PREFERENCE_REPORT_MESSAGE,           "Channel Preference Report" },
  { CHANNEL_SELECTION_REQUEST_MESSAGE,           "Channel Selection Request" },
  { CHANNEL_SELECTION_RESPONSE_MESSAGE,          "Channel Selection Response" },
  { OPERATING_CHANNEL_REPORT_MESSAGE,            "Operating Channel Report" },
  { CLIENT_CAPABILITIES_QUERY_MESSAGE,           "Client Capability Query"  },
  { CLIENT_CAPABILITIES_REPORT_MESSAGE,          "Client Capability Report" },
  { AP_METRICS_QUERY_MESSAGE,                    "AP Metrics Query" },
  { AP_METRICS_RESPONSE_MESSAGE,                 "AP Metrics Response" },
  { ASSOCIATED_STA_LINK_METRICS_QUERY_MESSAGE,   "Associated STA Link Metrics Query" },
  { ASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE, "Associated STA Link Metrics Response" },
  { UNASSOCIATED_STA_LINK_METRICS_QUERY_MESSAGE, "Unassociated STA Link Metrics Query" },
  { UNASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE, "Unassociated STA Link Metrics Response" },
  { BEACON_METRICS_QUERY_MESSAGE,                "Beacon Metrics Query" },
  { BEACON_METRICS_REPONSE_METRICS,              "Beacon Metrics Response" },
  { COMBINED_INFRASTRUCTURE_METRICS_MESSAGE,     "Combined Infrastructure Metrics" },
  { CLIENT_STEERING_REQUEST_MESSAGE,             "Client Steering Request" },
  { CLIENT_STEERING_BTM_REPORT_MESSAGE,          "Client Steering BTM Report" },
  { CLIENT_ASSOCIATION_CONTROL_REQUEST_MESSAGE,  "Client Association Control Request" },
  { STEERING_COMPLETED_MESSAGE,                  "Steering Completed" },
  { HIGHER_LAYER_DATA_MESSAGE,                   "Higher Layer Data" },
  { BACKHAUL_STEERING_REQUEST_MESSAGE,           "Backhaul Steering Request" },
  { BACKHAUL_STEERING_RESPONSE_MESSAGE,          "Backhaul Steering Response" },
  { CHANNEL_SCAN_REQUEST_MESSAGE,                "Channel Scan Request" },
  { CHANNEL_SCAN_REPORT_MESSAGE,                 "Channel Scan Report" },
  { DPP_CCE_INDICATION_MESSAGE,                  "DPP CCE Indication" },
  { IEEE1905_REKEY_REQUEST_MESSAGE,              "1905 Rekey Request" },
  { IEEE1905_DECRYPTION_FAILURE,                 "1905 Decryption Failure" },
  { CAC_REQUEST_MESSAGE,                         "CAC Request" },
  { CAC_TERMINATION_MESSAGE,                     "CAC Termination" },
  { CLIENT_DISASSOCIATION_STATS_MESSAGE,         "Client Disassociation Stats" },
  { SERVICE_PPRIORITIZATION_REQUEST,             "Service Prioritization Request" },
  { ERROR_RESPONSE_MESSAGE,                      "Error Response" },
  { ASSOCIATION_STATUS_NOTIFICATION_MESSAGE,     "Association Status Notification" },
  { TUNNELLED_MESSAGE,                           "Tunnelled" },
  { BACKHAUL_STA_CAPABILITY_QUERY_MESSAGE,       "Backhaul STA Capability Query" },
  { BACKHAUL_STA_CAPABILITY_REPORT_MESSAGE,      "Backhaul STA Capability Report" },
  { PROXIED_ENCAP_DPP_MESSAGE,                   "Proxied Encap DPP" },
  { DIRECT_ENCAP_DPP_MESSAGE,                    "Direct Encap DPP" },
  { RECONFIGURATION_TRIGGER_MESSAGE,             "Reconfiguration Trigger" },
  { BSS_CONFIGURATION_REQUEST_MESSAGE,           "BSS Configuration Request" },
  { BSS_CONFIGURATION_RESPONSE_MESSAGE,          "BSS Configuration Response" },
  { BSS_CONFIGURATION_RESULT_MESSAGE,            "BSS Configuration Result" },
  { CHIRP_NOTIFICATION_MESSAGE,                  "Chirp Notification" },
  { IEEE1905_ENCAP_EAPOL_MESSAGE,                "1905 Encap EAPOL" },
  { DPP_BOOTSTRAPPING_URI_NOTIFICATION_MESSAGE,  "DPP Bootstrapping URI Notification" },
  { DPP_BOOTSTRAPPING_URI_QUERY_MESSAGE,         "DPP Bootstrapping URI Query" },
  { FAILED_CONNECTION_MESSAGE,                   "Failed Connection" },
  { DPP_URI_NOTIFICATION_MESSAGE,                "DPP URI Notification" },
  { AGENT_LIST_MESSAGE,                          "Agent List" },
  { LOOP_DETECTION_MESSAGE,                      "Loop Detection" },
  { 0, NULL }
};
static value_string_ext ieee1905_message_type_vals_ext = VALUE_STRING_EXT_INIT(ieee1905_message_type_vals);

#define EOM_TLV                                 0x00
#define AL_MAC_ADDRESS_TYPE_TLV                 1
#define MAC_ADDRESS_TYPE_TLV                    2
#define DEVICE_INFORMATION_TYPE_TLV             3
#define DEVICE_BRIDGING_CAPABILITY_TLV          4
#define NON_1905_NEIGHBOR_DEVICE_LIST_TLV       6
#define NEIGHBOR_DEVICE_TLV                     7
#define LINK_METRIC_QUERY_TLV                   8
#define TRANSMITTER_LINK_METRIC_TLV             9
#define RECEIVER_LINK_METRIC_TLV                10
#define VENDOR_SPECIFIC_TLV                     11
#define LINK_METRIC_RESULT_CODE_TLV             12
#define SEARCHED_ROLE_TLV                       13
#define AUTO_CONFIG_FREQ_BAND_TLV               14
#define SUPPORTED_ROLE_TLV                      15
#define SUPPORTED_FREQ_BAND_TLV                 16
#define WSC_TLV                                 17
#define PUSH_BUTTON_EVENT_NOTIFICATION_TLV      18
#define PUSH_BUTTON_JOIN_NOTIFICATION_TLV       19
#define GENERIC_PHY_DEVICE_INFORMATION_TLV      20
#define DEVICE_IDENTIFICATION_TYPE_TLV          21
#define CONTROL_URL_TYPE_TLV                    22
#define IPV4_TYPE_TLV                           23
#define IPV6_TYPE_TLV                           24
#define PUSH_BUTTON_EVENT_TYPE_NOTIFICATION_TLV 25
#define IEEE1905_PROFILE_VERSION_TLV            26
#define POWER_OFF_INTERFACE_TLV                 27
#define INTERFACE_POWER_CHANGE_INFORMATION_TLV  28
#define INTERFACE_POWER_CHANGE_STATUS_TLV       29
#define L2_NEIGHBOR_DEVICE_TLV                  30
#define SUPPORTED_SERVICE_TLV                   0x80
#define SEARCHED_SERVICE_TLV                    0x81
#define AP_RADIO_IDENTIFIER_TLV                 0x82
#define AP_OPERATIONAL_BSS_TLV                  0x83
#define ASSOCIATED_CLIENTS_TLV                  0x84
#define AP_RADIO_BASIC_CAPABILITIES_TLV         0x85
#define AP_HT_CAPABILITIES_TLV                  0x86
#define AP_VHT_CAPABILITIES_TLV                 0x87
#define AP_HE_CAPABILITIES_TLV                  0x88
#define STEERING_POLICY_TLV                     0x89
#define METRIC_REPORTING_POLICY_TLV             0x8A
#define CHANNEL_PREFERENCE_TLV                  0x8B
#define RADIO_OPERATION_RESTRICTION_TLV         0x8C
#define TRANSMIT_POWER_LIMIT_TLV                0x8D
#define CHANNEL_SELECTION_RESPONSE_TLV          0x8E
#define OPERATING_CHANNEL_REPORT_TLV            0x8F
#define CLIENT_INFO_TLV                         0x90
#define CLIENT_CAPABILITY_REPORT_TLV            0x91
#define CLIENT_ASSOCIATION_EVENT_TLV            0x92
#define AP_METRIC_QUERY_TLV                     0x93
#define AP_METRICS_TLV                          0x94
#define STA_MAC_ADDRESS_TYPE_TLV                0x95
#define ASSOCIATED_STA_LINK_METRICS_TLV         0x96
#define UNASSOCIATED_STA_LINK_METRICS_QUERY_TLV 0x97
#define UNASSOCIATED_STA_LINK_METRICS_RESPONSE_TLV 0x98
#define BEACON_METRICS_QUERY_TLV                0x99
#define BEACON_METRICS_RESPONSE_TLV             0x9A
#define STEERING_REQUEST_TLV                    0x9B
#define STEERING_BTM_REPORT_TLV                 0x9C
#define CLIENT_ASSOCIATION_CONTROL_REQUEST_TLV  0x9D
#define BACKHAUL_STEERING_REQUEST_TLV           0x9E
#define BACKHAUL_STEERING_RESPONSE_TLV          0x9F
#define HIGHER_LAYER_DATA_TLV                   0xA0
#define AP_CAPABILITY_TLV                       0xA1
#define ASSOCIATED_STA_TRAFFIC_STATS_TLV        0xA2
#define ERROR_CODE_TLV                          0xA3
#define CHANNEL_SCAN_REPORTING_POLICY_TLV       0xA4
#define CHANNEL_SCAN_CAPABILITIES_TLV           0xA5
#define CHANNEL_SCAN_REQUEST_TLV                0xA6
#define CHANNEL_SCAN_RESULT_TLV                 0xA7
#define TIMESTAMP_TLV                           0xA8
#define IEEE1905_LAYER_SECURITY_CAPABILITY_TLV  0xA9
#define AP_WF6_CAPABILITIES_TLV                 0xAA
#define MIC_TLV                                 0xAB
#define ENCRYPTED_TLV                           0xAC
#define CAC_REQUEST_TLV                         0xAD
#define CAC_TERMINATION_TLV                     0xAE
#define CAC_COMPLETION_REPORT_TLV               0xAF
#define ASSOCIATED_WF6_STA_STATUS_REPORT_TLV    0xB0
#define CAC_STATUS_REPORT_TLV                   0xB1
#define CAC_CAPABILITIES_TLV                    0xB2
#define MULTI_AP_PROFILE_TLV                    0xB3
#define PROFILE_2_AP_CAPABILITY_TLV             0xB4
#define DEFAULT_802_1Q_SETTINGS_TLV             0xB5
#define TRAFFIC_SEPARATION_POLICY_TLV           0xB6
#define BSS_CONFIGURATION_REPORT_TLV            0xB7
#define BSSID_TLV                               0xB8
#define SERVICE_PRIORITIZATION_RULE_TLV         0xB9
#define DSCP_MAPPING_TABLE_TLV                  0xBA
#define BSS_CONFIGURATION_REQUEST_TLV           0xBB
#define PROFILE_2_ERROR_CODE_ERROR_TLV          0xBC
#define BSS_CONFIGURATION_RESPONSE_TLV          0xBD /* FIX */
#define AP_RADIO_ADVANCED_CAPABILITIES_TLV      0xBE
#define ASSOCIATION_STATUS_NOTIFICATION_TLV     0xBF
#define SOURCE_INFO_TLV                         0xC0
#define TUNNELED_MESSAGE_TYPE_TLV               0xC1
#define TUNNELED_TLV                            0xC2
#define PROFILE_2_STEERING_REQUEST_TLV          0xC3
#define UNSUCCESSFUL_ASSOCIATION_POLICY_TLV     0xC4
#define METRIC_COLLECTION_INTERVAL_TLV          0xC5
#define RADIO_METRICS_TLV                       0xC6
#define AP_EXTENDED_METRICS_TLV                 0xC7
#define ASSOCIATED_STA_EXTENDED_LINK_METRICS_TLV 0xC8
#define STATUS_CODE_TLV                         0xC9
#define REASON_CODE_TLV                         0xCA
#define BACKHAUL_STA_RADIO_CAPABILITIES_TLV     0xCB
#define AKM_SUITE_CAPABILITIES_TLV              0xCC
#define IEEE1905_ENCAP_DPP_TLV                  0xCD
#define IEEE1905_ENCAP_EAPOL_TLV                0xCE
#define DPP_BOOTSTRAPPING_URI_NOTIFICATION_TLV  0xCF
#define BACKHAUL_BSS_CONFIGURATION              0xD0
#define DPP_MESSAGE_TLV                         0xD1
#define DPP_CCE_INDICATION_TLV                  0xD2
#define DPP_CHIRP_VALUE_TLV                     0xD3
#define DEVICE_INVENTORY_TLV                    0xD4
#define AGENT_LIST_TLV                          0xD5
#define LOOP_PREVENTION_MECHANISM_SETTING_TLV   0xD6
#define LOOP_DETECTION_SEQUENCE_NUMBER_TLV      0xD7
#define GROUP_INTEGRITY_KEY_TLV                 0xD8
#define CAC_STATUS_REQUEST_TLV                  0xD9
#define PACKET_FILTERING_POLICY_TLV             0xDA

static const value_string ieee1905_tlv_types_vals[] = {
  { EOM_TLV,                                 "End of message" },
  { AL_MAC_ADDRESS_TYPE_TLV,                 "1905 AL MAC address type" },
  { MAC_ADDRESS_TYPE_TLV,                    "MAC address type" },
  { DEVICE_INFORMATION_TYPE_TLV,             "1905 device information type" },
  { DEVICE_BRIDGING_CAPABILITY_TLV,          "Device bridging capability" },
  { NON_1905_NEIGHBOR_DEVICE_LIST_TLV,       "Non-1905 neighbor device list" },
  { NEIGHBOR_DEVICE_TLV,                     "1905 neighbor device" },
  { LINK_METRIC_QUERY_TLV,                   "Link metric query" },
  { TRANSMITTER_LINK_METRIC_TLV,             "1905 transmitter link metric" },
  { RECEIVER_LINK_METRIC_TLV,                "1905 receiver link metric" },
  { VENDOR_SPECIFIC_TLV,                     "Vendor specific" },
  { LINK_METRIC_RESULT_CODE_TLV,             "1905 link metric result code" },
  { SEARCHED_ROLE_TLV,                       "SearchedRole" },
  { AUTO_CONFIG_FREQ_BAND_TLV,               "AutoconfigFreqBand" },
  { SUPPORTED_ROLE_TLV,                      "SupportedRole" },
  { SUPPORTED_FREQ_BAND_TLV,                 "SupportedFreqBand" },
  { WSC_TLV,                                 "WSC" },
  { PUSH_BUTTON_EVENT_NOTIFICATION_TLV,      "Push_Button_Event notification" },
  { PUSH_BUTTON_JOIN_NOTIFICATION_TLV,       "Push_Button_Join notification" },
  { GENERIC_PHY_DEVICE_INFORMATION_TLV,      "Generic Phy device information" },
  { DEVICE_IDENTIFICATION_TYPE_TLV,          "Device identification type" },
  { CONTROL_URL_TYPE_TLV,                    "Control URL type" },
  { IPV4_TYPE_TLV,                           "IPv4 type" },
  { IPV6_TYPE_TLV,                           "IPv6 type" },
  { PUSH_BUTTON_EVENT_TYPE_NOTIFICATION_TLV, "Push_Button_Generic_Phy_Event notification" },
  { IEEE1905_PROFILE_VERSION_TLV,            "1905 profile version" },
  { POWER_OFF_INTERFACE_TLV,                 "Power off interface" },
  { INTERFACE_POWER_CHANGE_INFORMATION_TLV,  "Interface power change information" },
  { INTERFACE_POWER_CHANGE_STATUS_TLV,       "Interface power change status" },
  { L2_NEIGHBOR_DEVICE_TLV,                  "L2 neighbor device" },
  { SUPPORTED_SERVICE_TLV,                   "Supported service information" },
  { SEARCHED_SERVICE_TLV,                    "Searched service information" },
  { AP_RADIO_IDENTIFIER_TLV,                 "AP radio identifier" },
  { AP_OPERATIONAL_BSS_TLV,                  "AP operational BSS" },
  { ASSOCIATED_CLIENTS_TLV,                  "Associated clients" },
  { AP_RADIO_BASIC_CAPABILITIES_TLV,         "AP radio basic capabilities" },
  { AP_HT_CAPABILITIES_TLV,                  "AP HT capabilities" },
  { AP_VHT_CAPABILITIES_TLV,                 "AP VHT capabilities" },
  { AP_HE_CAPABILITIES_TLV,                  "AP HE capabilities" },
  { STEERING_POLICY_TLV,                     "Steering policy" },
  { METRIC_REPORTING_POLICY_TLV,             "Metric reporting policy" },
  { CHANNEL_PREFERENCE_TLV,                  "Channel preference" },
  { RADIO_OPERATION_RESTRICTION_TLV,         "Radio operation restriction" },
  { TRANSMIT_POWER_LIMIT_TLV,                "Transmit power limit" },
  { CHANNEL_SELECTION_RESPONSE_TLV,          "Channel selection response" },
  { OPERATING_CHANNEL_REPORT_TLV,            "Operating channel report" },
  { CLIENT_INFO_TLV,                         "Client info" },
  { CLIENT_CAPABILITY_REPORT_TLV,            "Client capability report" },
  { CLIENT_ASSOCIATION_EVENT_TLV,            "Client association event" },
  { AP_METRIC_QUERY_TLV,                     "AP metric query" },
  { AP_METRICS_TLV,                          "AP metrics" },
  { STA_MAC_ADDRESS_TYPE_TLV,                "STA MAC address type" },
  { ASSOCIATED_STA_LINK_METRICS_TLV,         "Associated STA Link Metrics" },
  { UNASSOCIATED_STA_LINK_METRICS_QUERY_TLV, "Unassociated STA link metrics query" },
  { UNASSOCIATED_STA_LINK_METRICS_RESPONSE_TLV, "Unassociated STA link metrics response" },
  { BEACON_METRICS_QUERY_TLV,                "Beacon metrics query" },
  { BEACON_METRICS_RESPONSE_TLV,             "Beacon metrics response" },
  { STEERING_REQUEST_TLV,                    "Steering request" },
  { STEERING_BTM_REPORT_TLV,                 "Steering BTM report" },
  { CLIENT_ASSOCIATION_CONTROL_REQUEST_TLV,  "Client association control request" },
  { BACKHAUL_STEERING_REQUEST_TLV,           "Backhaul steering request" },
  { BACKHAUL_STEERING_RESPONSE_TLV,          "Backhaul steering response" },
  { HIGHER_LAYER_DATA_TLV,                   "Higher layer data" },
  { AP_CAPABILITY_TLV,                       "AP capability" },
  { ASSOCIATED_STA_TRAFFIC_STATS_TLV,        "Associated STA Traffic Stats" },
  { ERROR_CODE_TLV,                          "Error Code" },
  { CHANNEL_SCAN_REPORTING_POLICY_TLV,       "Channel Scan Reporting Policy" },
  { CHANNEL_SCAN_CAPABILITIES_TLV,           "Channel Scan Capabilities" },
  { CHANNEL_SCAN_REQUEST_TLV,                "Channel Scan Request" },
  { CHANNEL_SCAN_RESULT_TLV,                 "Channel Scan Result" },
  { TIMESTAMP_TLV,                           "Timestamp" },
  { IEEE1905_LAYER_SECURITY_CAPABILITY_TLV,  "1905 Layer Security Capability" },
  { AP_WF6_CAPABILITIES_TLV,                 "AP Wi-Fi 6 Capabilities" },
  { MIC_TLV,                                 "MIC" },
  { ENCRYPTED_TLV,                           "Encrypted" },
  { CAC_REQUEST_TLV,                         "CAC Request" },
  { CAC_TERMINATION_TLV,                     "CAC Termination" },
  { CAC_COMPLETION_REPORT_TLV,               "CAC Completion Report" },
  { ASSOCIATED_WF6_STA_STATUS_REPORT_TLV,    "Associated Wi-Fi 6 STA Status Report" },
  { CAC_STATUS_REPORT_TLV,                   "CAC Status Report" },
  { CAC_CAPABILITIES_TLV,                    "CAC Capabilities" },
  { MULTI_AP_PROFILE_TLV,                    "Multi AP Profile" },
  { PROFILE_2_AP_CAPABILITY_TLV,             "Profile 2 AP Capability" },
  { DEFAULT_802_1Q_SETTINGS_TLV,             "Default 802.1 Settings" },
  { TRAFFIC_SEPARATION_POLICY_TLV,           "Traffic Separation Policy" },
  { BSS_CONFIGURATION_REPORT_TLV,            "BSS Configuration Report" },
  { BSSID_TLV,                               "BSSID" },
  { SERVICE_PRIORITIZATION_RULE_TLV,         "Service Prioritization Rule" },
  { DSCP_MAPPING_TABLE_TLV,                  "DSCP Mapping Table" },
  { BSS_CONFIGURATION_REQUEST_TLV,           "BSS Configuration Request" },
  { PROFILE_2_ERROR_CODE_ERROR_TLV,          "Profile 2 Error Code" },
  { BSS_CONFIGURATION_RESPONSE_TLV,          "BSS Configuration Response" },
  { AP_RADIO_ADVANCED_CAPABILITIES_TLV,      "AP Radio Advanced Capabilities" },
  { ASSOCIATION_STATUS_NOTIFICATION_TLV,     "Associated Status Notification" },
  { SOURCE_INFO_TLV,                         "Source Info" },
  { TUNNELED_MESSAGE_TYPE_TLV,               "Tunneled Message Type" },
  { TUNNELED_TLV,                            "Tunneled" },
  { PROFILE_2_STEERING_REQUEST_TLV,          "Profile 2 Steering Request" },
  { UNSUCCESSFUL_ASSOCIATION_POLICY_TLV,     "Unsuccessful Association Policy" },
  { METRIC_COLLECTION_INTERVAL_TLV,          "Metric Collection Interval" },
  { RADIO_METRICS_TLV,                       "Radio Metrics" },
  { AP_EXTENDED_METRICS_TLV,                 "AP Extended Metrics" },
  { ASSOCIATED_STA_EXTENDED_LINK_METRICS_TLV,"Associated STA Extended Link Metrics" },
  { STATUS_CODE_TLV,                         "Status Code" },
  { REASON_CODE_TLV,                         "Reason Code" },
  { BACKHAUL_STA_RADIO_CAPABILITIES_TLV,     "Backhaul STA Radio Capabilities" },
  { AKM_SUITE_CAPABILITIES_TLV,              "AKM Suite Capabilities" },
  { IEEE1905_ENCAP_DPP_TLV,                  "1905 Encap DPP" },
  { IEEE1905_ENCAP_EAPOL_TLV,                "1905 Encap EAPOL" },
  { DPP_BOOTSTRAPPING_URI_NOTIFICATION_TLV,  "DPP Bootstrapping URI Notification" },
  { DPP_MESSAGE_TLV,                         "DPP Message" },
  { DPP_CCE_INDICATION_TLV,                  "DPP CCE Indication" },
  { DPP_CHIRP_VALUE_TLV,                     "DPP Chirp Value" },
  { DEVICE_INVENTORY_TLV,                    "Device Inventory" },
  { AGENT_LIST_TLV,                          "Agent List" },
  { LOOP_PREVENTION_MECHANISM_SETTING_TLV,   "Loop Prevention Mechanism Setting" },
  { LOOP_DETECTION_SEQUENCE_NUMBER_TLV,      "Loop Detection Sequence Number" },
  { GROUP_INTEGRITY_KEY_TLV,                 "Group Integrity Key" },
  { CAC_STATUS_REQUEST_TLV,                  "CAC Status Request" },
  { PACKET_FILTERING_POLICY_TLV,             "Packet Filtering Policy" },
  { 0, NULL }
};
static value_string_ext ieee1905_tlv_types_vals_ext = VALUE_STRING_EXT_INIT(ieee1905_tlv_types_vals);

static const true_false_string tfs_last_fragment = {
  "This is the last fragment",
  "This is not the last fragment"
};

static const true_false_string tfs_relay_indicator = {
  "Relayed multicast",
  "Neighbor multicast or unicast"
};

static const value_string ieee1905_link_metric_query_type_vals[] = {
  { 0x00, "All neighbors" },
  { 0x01, "Specific neighbor" },
  { 0, NULL }
};

static const value_string ieee1905_link_metrics_requested_vals[] = {
  { 0x00, "Tx link metrics only" },
  { 0x01, "Rx link metrics only" },
  { 0x02, "Both Tx and Rx link metrics" },
  { 0, NULL }
};

static const value_string ieee1905_bridge_flag_vals[] = {
  { 0x00, "1905 link does not include an IEEE 802.1 bridge" },
  { 0x01, "1905 link includes one or more IEEE 802.1 bridges" },
  { 0, NULL }
};

static const value_string ieee1905_media_type_0_vals[] = {
  { 0, "IEEE 802.3u fast Ethernet" },
  { 1, "IEEE 802.3ab gigabit" },
  { 0, NULL }
};

static const value_string ieee1905_media_type_1_vals[] = {
  { 0, "IEEE 802.11b (2.4 GHz)" },
  { 1, "IEEE 802.11g (2.4 GHz)" },
  { 2, "IEEE 802.11a (5 GHz)" },
  { 3, "IEEE 802.11n (2.4 GHz)" },
  { 4, "IEEE 802.11n (5 GHz)" },
  { 5, "IEEE 802.11ac (5 GHz)" },
  { 6, "IEEE 802.11ad (60 GHz)" },
  { 7, "IEEE 802.11ax (2.4 GHz)" },
  { 8, "IEEE 802.11ax (5 GHz)" },
  { 0, NULL }
};

static const value_string ieee1905_media_type_2_vals[] = {
  { 0, "IEEE 1901 wavelet" },
  { 1, "IEEE 1901 FFT" },
  { 0, NULL }
};

static const value_string ieee1905_media_type_3_vals[] = {
  { 0, "MoCA v1.1" },
  { 0, NULL }
};

static const value_string ieee1905_link_metric_result_vals[] = {
  { 0, "Invalid neighbor" },
  { 0, NULL }
};

static const true_false_string tfs_bridges_flag = {
  "At least one IEEE 802.1 bridge exists between this device and the neighbor",
  "No IEEE 802.1 bridges exist"
};

static const value_string ieee1905_searched_role_vals[] = {
  { 0, "Registrar" },
  { 0, NULL }
};

static const value_string ieee1905_freq_band_vals[] = {
  { 0, "802.11 2.4 GHz" },
  { 1, "802.11 5 GHz" },
  { 2, "802.11 60 GHz" },
  { 0, NULL }
};

static const value_string ieee1905_ipv4_addr_type_vals[] = {
  { 0, "Unknown" },
  { 1, "DHCP" },
  { 2, "Static" },
  { 3, "Auto-IP" },
  { 0, NULL }
};

static const value_string ieee1905_ipv6_addr_type_vals[] = {
  { 0, "Unknown" },
  { 1, "DHCP" },
  { 2, "Static" },
  { 3, "SLAAC" },
  { 0, NULL}
};

static const value_string ieee1905_profile_version_vals[] = {
  { 0, "1905.1" },
  { 1, "1905.1a" },
  { 0, NULL }
};

static const value_string ieee1905_power_state_vals[] = {
  { 0, "PWR_OFF" },
  { 1, "PWR_ON" },
  { 2, "PWR_SAVE" },
  { 0, NULL }
};

static const value_string ieee1905_power_status_vals[] = {
  { 0, "Request completed" },
  { 1, "No change made" },
  { 2, "Alternate change made" },
  { 0, NULL }
};

static const value_string ieee1905_supported_service_vals[] = {
  { 0x00, "Multi-AP Controller" },
  { 0x01, "Multi-AP Agent" },
  { 0, NULL }
};

static const value_string ieee1905_higher_layer_protocol_vals[] = {
  { 0x00, "Reserved" },
  { 0x01, "TR-181 transport protocol" },
  { 0, NULL }
};

static const value_string ieee1905_backhaul_status_vals[] = {
  { 0x00, "Success" },
  { 0x01, "Rejected because the backhaul station cannot operate on the channel specified" },
  { 0x02, "Rejected because the target BSS signal is too weak or not found" },
  { 0x03, "Authentication or association rejected by the target BSS" },
  { 0, NULL },
};

static const value_string ieee1905_association_control_vals[] = {
  { 0x00, "Block" },
  { 0x01, "Unblock" },
  { 0, NULL }
};

static const true_false_string tfs_ieee1905_steering_request_mode_flag = {
  "Request is a steering mandate to trigger steering for specific client STA(s)",
  "Request is a steering opportunity",
};

static const true_false_string tfs_ieee1905_report_unsuccessful_association_attempt_flag = {
  "Report",
  "Do not Report",
};

static const true_false_string tfs_ieee1905_btm_disassoc_imminent_flag = {
  "BTM disassociation imminent",
  "BTM disassociation not imminent"
};

static const true_false_string tfs_ieee1905_btm_abridged_flag = {
  "BTM abridged",
  "BTM not abridged"
};

static const value_string ieee1905_client_capability_result_vals[] = {
  { 0x00, "Success" },
  { 0x01, "Unspecified failure" },
  { 0x02, "Client not associated with specified BSSID" },
  { 0, NULL }
};

static const true_false_string tfs_ieee1905_association_event_flag = {
  "Client has joined the BSS",
  "Client has left the BSS"
};

static const value_string max_supported_tx_streams_vals[] = {
  { 0x00, "1 Tx spatial stream" },
  { 0x01, "2 Tx spatial streams" },
  { 0x02, "3 Tx spatial streams" },
  { 0x03, "4 Tx spatial streams" },
  { 0, NULL },
};

static const value_string max_supported_rx_streams_vals[] = {
  { 0x00, "1 Rx spatial stream" },
  { 0x01, "2 Rx spatial streams" },
  { 0x02, "3 Rx spatial streams" },
  { 0x03, "4 Rx spatial streams" },
  { 0, NULL },
};

static const value_string vht_he_max_supported_tx_streams_vals[] = {
  { 0x00, "1 Tx spatial stream" },
  { 0x01, "2 Tx spatial streams" },
  { 0x02, "3 Tx spatial streams" },
  { 0x03, "4 Tx spatial streams" },
  { 0x04, "5 Tx spatial streams" },
  { 0x05, "6 Tx spatial streams" },
  { 0x06, "7 Tx spatial streams" },
  { 0x07, "8 Tx spatial streams" },
  { 0, NULL },
};

static const value_string vht_he_max_supported_rx_streams_vals[] = {
  { 0x00, "1 Rx spatial stream" },
  { 0x01, "2 Rx spatial streams" },
  { 0x02, "3 Rx spatial streams" },
  { 0x03, "4 Rx spatial streams" },
  { 0x04, "5 Rx spatial streams" },
  { 0x05, "6 Rx spatial streams" },
  { 0x06, "7 Rx spatial streams" },
  { 0x07, "8 Rx spatial streams" },
  { 0, NULL },
};

static const value_string  channel_preference_prefs_vals[] = {
  { 0x0, "Non-operable" },
  { 0x1, "Operable with preference score 1" },
  { 0x2, "Operable with preference score 2" },
  { 0x3, "Operable with preference score 3" },
  { 0x4, "Operable with preference score 4" },
  { 0x5, "Operable with preference score 5" },
  { 0x6, "Operable with preference score 6" },
  { 0x7, "Operable with preference score 7" },
  { 0x8, "Operable with preference score 8" },
  { 0x9, "Operable with preference score 9" },
  { 0xA, "Operable with preference score 10" },
  { 0xB, "Operable with preference score 11" },
  { 0xC, "Operable with preference score 12" },
  { 0xD, "Operable with preference score 13" },
  { 0xE, "Operable with preference score 14" },
  { 0, NULL }
};

static const value_string channel_preference_reason_vals[] = {
  { 0x0, "Unspecified" },
  { 0x1, "Proximate non-802.11 interference in local environment" },
  { 0x2, "Intra-network 802.11 OBSS interference management" },
  { 0x3, "External network 802.11 OBSS interference management" },
  { 0x4, "Reduced coverage (e.g. due to limited transmit power" },
  { 0x5, "Reduced throughput (e.g. due to limited channel bandwidth..." },
  { 0x6, "In-device interference within AP" },
  { 0x7, "Operation disallowed due to radar detection on a DFS channel" },
  { 0x8, "Operation would prevent backhaul operation using shared radio" },
  { 0x9, "Immediate operation possible on a DFS channel" },
  { 0xA, "DFS channel state unknown" },
  { 0xB, "Controller DFS Channel Clear Indication" },
  { 0xC, "Operation disallowed by AFC restriction" },
  { 0, NULL }
};

static const value_string ieee1905_channel_select_resp_code_vals[] = {
  { 0x00, "Accept" },
  { 0x01, "Declined because request violates current preferences" },
  { 0x02, "Declined because request violates most recently reported preferences" },
  { 0x02, "Declined because request would prevent operation of a current backhaul link" },
  { 0, NULL }
};

static const value_string ieee1905_steering_policy_vals[] = {
  { 0x0, "Agent initiated steering disallowed" },
  { 0x1, "Agent initiated RCPI-based steering mandated" },
  { 0x2, "Agent initiated RCPI-based steering allowed" },
  { 0, NULL}
};

static const value_string ieee1905_error_code_vals[] = {
  { 0x01, "STA associated with a BSS operated by the Agent" },
  { 0x02, "STA not associated with any BSS operated by the Agent" },
  { 0x03, "Client capability report unspecified failure" },
  { 0x04, "Backhaul steering request rejected because station cannot operate on specified channel" },
  { 0x05, "Backhaul steering request rejected because target BSS signal too weak or not found" },
  { 0x06, "Backhaul steering request authentication or association Rejected by target BSS" },
  { 0, NULL }
};

/*
 * Minimum message has a single End of Message TLV with 3 bytes, plus 8 byte
 * header.
 */
#define IEEE1905_MIN_LENGTH 11

static int
dissect_media_type(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_item *pi = NULL;
    proto_tree *media_type = NULL;
    guint8 bits_15_to_8 = 0, bits_7_to_0 = 0;

    pi = proto_tree_add_item(tree, hf_ieee1905_media_type, tvb, offset,
                             2, ENC_BIG_ENDIAN);

    media_type = proto_item_add_subtree(pi, ett_media_type);

    /*
     * Now, break it out
     */
    bits_15_to_8 = tvb_get_guint8(tvb, offset);
    bits_7_to_0 = tvb_get_guint8(tvb, offset + 1);

    proto_tree_add_item(media_type, hf_ieee1905_media_type_high, tvb, offset,
                        1, ENC_NA);
    offset++;

    proto_tree_add_item(media_type, hf_ieee1905_media_type_low, tvb, offset,
                        1, ENC_NA);
    offset++;

    switch (bits_15_to_8) {
    case 0:
        proto_item_append_text(pi, ", %s",
                        val_to_str(bits_7_to_0,
                            ieee1905_media_type_0_vals,
                            "Reserved"));
        break;

    case 1:
        proto_item_append_text(pi, ", %s",
                        val_to_str(bits_7_to_0,
                            ieee1905_media_type_1_vals,
                            "Reserved"));
        break;

    case 2:
        proto_item_append_text(pi, ", %s",
                        val_to_str(bits_7_to_0,
                            ieee1905_media_type_2_vals,
                            "Reserved"));
        break;

    case 3:
        proto_item_append_text(pi, ", %s",
                        val_to_str(bits_7_to_0,
                            ieee1905_media_type_3_vals,
                            "Reserved"));
        break;

    case 0xff:
        proto_item_append_text(pi, ", Unknown media");
        break;

    default:
        proto_item_append_text(pi, ", Reserved");
        break;
    }

    return offset;
}

/*
 * Dissect a local interface list, putting them each in a subtree labeled
 * with the number of the interface.
 */
static int
dissect_local_interface_list(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint8 count)
{
    guint lil_index = 0;
    guint media_type_offset = 0;
    proto_item *pi = NULL;
    proto_tree *dev_tree = NULL;

    while (count > 0) {
        guint8 spec_info_len = 0;

        dev_tree = proto_tree_add_subtree_format(tree, tvb, offset, 8,
                                ett_device_information_tree,
                                &pi, "Local interface %u device info",
                                lil_index);

        proto_tree_add_item(dev_tree, hf_ieee1905_mac_address_type, tvb,
                            offset, 6, ENC_NA);
        offset += 6;

        media_type_offset = offset;

        offset = dissect_media_type(tvb, pinfo, dev_tree, offset);

        spec_info_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_item(dev_tree, hf_ieee1905_media_spec_info_len,
                            tvb, offset, 1, ENC_NA);
        offset++;

        if (spec_info_len) {
            /* FIXME: This should be dissected ... */
            proto_tree_add_item(dev_tree, hf_ieee1905_media_spec_info,
                                tvb, offset, spec_info_len, ENC_NA);
            offset += spec_info_len;
        }

        proto_item_set_len(pi, 6 + (offset - media_type_offset));

        count--;
        lil_index++;
    }

    return offset;
}

/*
 * Dissect device bridging capabilities
 */
static int
dissect_device_bridging_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 count = tvb_get_guint8(tvb, offset);
    guint8 tuple_no = 0;
    guint8 mac_addresses = 0;
    guint start = 0;
    proto_tree *tuple_list = NULL;
    proto_tree *bridging_list = NULL;
    proto_item *tpi = NULL, *mpi = NULL;

    proto_tree_add_item(tree, hf_ieee1905_bridging_tuples_cnt, tvb, offset,
                        1, ENC_NA);
    tuple_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                ett_bridging_tuples_list,
                                &tpi, "Bridging tuples list");

    start = offset; /* Starts at the count! */
    offset++;

    while (count > 0) {
        guint bl_start = offset;
        mac_addresses = tvb_get_guint8(tvb, offset);

        bridging_list = proto_tree_add_subtree_format(tuple_list, tvb, offset,
                                -1, ett_bridging_mac_list,
                                &mpi, "Bridging tuple %u", tuple_no);

        proto_tree_add_item(bridging_list,
                            hf_ieee1905_bridging_mac_address_cnt,
                            tvb, offset, 1, ENC_NA);

        offset++;
        tuple_no++;

        while (mac_addresses) {
           proto_tree_add_item(bridging_list,
                               hf_ieee1905_bridging_mac_address, tvb,
                               offset, 6, ENC_NA);
           offset += 6;
           mac_addresses--;

        }

        proto_item_set_len(mpi, offset - bl_start);
        count--;
    }

    proto_item_set_len(tpi, offset - start);
    return offset;
}

/*
 * Dissect the non 1905 neighbor device list TLV
 */
static int
dissect_non_1905_neighbor_device_list(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    proto_tree *neighbor_list = NULL;
    proto_item *pi = NULL;
    guint start;

    start = offset;
    neighbor_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                ett_non_1905_neighbor_list,
                                &pi, "Non IEEE1905 neighbor devices");

    while (len >= 12) {
        proto_tree_add_item(neighbor_list, hf_ieee1905_local_interface_mac, tvb,
                        offset, 6, ENC_NA);

        len -= 6;
        offset += 6;

        proto_tree_add_item(neighbor_list, hf_ieee1905_non_1905_neighbor_mac,
                        tvb, offset, 6, ENC_NA);

        len -= 6;
        offset += 6;

    }

    if (len > 0) {
        proto_item *ei;

        ei = proto_tree_add_item(tree, hf_ieee1905_extra_tlv_data, tvb, offset,
                             len, ENC_NA);
        expert_add_info(pinfo, ei, &ei_ieee1905_extraneous_tlv_data);
        offset += len; /* Skip the extras. */

    }

    proto_item_set_len(pi, offset - start);

    return offset;
}

/*
 * Dissect an IEEE1905 Neighbor device TLV
 */
static int
dissect_1905_neighbor_device(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    proto_item *pi = NULL;
    proto_item *neighbor_list = NULL;
    guint start;
    static int * const flags[] = {
      &hf_ieee1905_bridges_flag,
      NULL,
    };

    proto_tree_add_item(tree, hf_ieee1905_local_interface_mac, tvb,
                        offset, 6, ENC_NA);

    len -= 6;
    offset += 6;

    neighbor_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                ett_1905_neighbor_list, &pi,
                                "IEEE1905 neighbor devices");

    start = offset;
    while (len > 0) {
        proto_tree_add_item(neighbor_list, hf_ieee1905_neighbor_al_mac_addr,
                            tvb, offset, 6, ENC_NA);

        len -= 6;
        offset += 6;

        proto_tree_add_bitmask(neighbor_list, tvb, offset,
                               hf_ieee1905_neighbor_flags,
                               ett_ieee1905_neighbor_flags, flags, ENC_NA);

        len--;
        offset++;

    }

    proto_item_set_len(pi, offset - start);

    return offset;
}

/*
 * Dissect the link metric result code
 */
static int
dissect_link_metric_result_code(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_item *pi = NULL;
    guint8 code = tvb_get_guint8(tvb, offset);

    pi = proto_tree_add_item(tree, hf_ieee1905_link_metric_result_code,
                             tvb, offset, 1, ENC_NA);

    proto_item_append_text(pi, ", %s",
                        val_to_str(code, ieee1905_link_metric_result_vals,
                                "Reserved"));

    offset++;

    return offset;
}

/*
 * Dissect a vendor specific TLV.
 */
static int
dissect_vendor_specific(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{

    proto_tree_add_item(tree, hf_ieee1905_vendor_specific_oui, tvb, offset,
                        3, ENC_NA);
    offset += 3;

    proto_tree_add_item(tree, hf_ieee1905_vendor_specific_info, tvb, offset,
                        len - 3, ENC_NA);
    offset += (len - 3);

    return offset;
}

/*
 * Dissect the searched role TLV
 */
static int
dissect_searched_role(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_item *pi = NULL;
    guint8 role = tvb_get_guint8(tvb, offset);

    pi = proto_tree_add_item(tree, hf_ieee1905_searched_role, tvb, offset,
                             1, ENC_NA);

    proto_item_append_text(pi, ", %s",
                        val_to_str(role, ieee1905_searched_role_vals,
                                "Reserved"));

    offset++;

    return offset;
}

/*
 * Dissect the supported role TLV
 */
static int
dissect_supported_role(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_item *pi = NULL;
    guint8 role = tvb_get_guint8(tvb, offset);

    pi = proto_tree_add_item(tree, hf_ieee1905_supported_role, tvb, offset,
                             1, ENC_NA);

    /*
     * We can re-use this.
     */
    proto_item_append_text(pi, ", %s",
                        val_to_str(role, ieee1905_searched_role_vals,
                                "Reserved"));

    offset++;

    return offset;
}

/*
 * Dissect an Auto config frequency band TLV
 */
static int
dissect_auto_config_freq_band(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_item *pi = NULL;
    guint8 freq = tvb_get_guint8(tvb, offset);

    pi = proto_tree_add_item(tree, hf_ieee1905_auto_config_freq_band, tvb,
                             offset, 1, ENC_NA);

    proto_item_append_text(pi, ", %s",
                        val_to_str(freq, ieee1905_freq_band_vals,
                                "Reserved"));

    offset++;

    return offset;
}

/*
 * Dissect a Supported frequency band TLV
 */
static int
dissect_supported_freq_band(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_item *pi = NULL;
    guint8 freq = tvb_get_guint8(tvb, offset);

    pi = proto_tree_add_item(tree, hf_ieee1905_supported_freq_band, tvb,
                             offset, 1, ENC_NA);

    proto_item_append_text(pi, ", %s",
                        val_to_str(freq, ieee1905_freq_band_vals,
                                "Reserved"));

    offset++;

    return offset;
}

/*
 * Dissect a WSC TLV
 */
static int
dissect_wsc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        guint offset, guint16 len)
{
    dissect_wps_tlvs(tree, tvb, offset, len, pinfo);
    offset += len;

    return offset;
}

/*
 * Dissect a push button notification event TLV
 */
static int
dissect_push_button_event_notification(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, guint offset)
{
    proto_item *pi = NULL, *mpi = NULL;
    proto_tree *media_type_list = NULL, *media_item = NULL;
    guint list_offset = 0, media_type_offset = 0;
    guint8 media_types = tvb_get_guint8(tvb, offset);
    guint8 media_type_index = 0;

    proto_tree_add_item(tree, hf_ieee1905_event_notification_media_types,
                        tvb, offset, 1, ENC_NA);
    offset++;

    /* If there are none, nothing more to do. */
    if (media_types == 0)
        return offset;

    media_type_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                             ett_media_type_list,
                                             &pi, "Media type list");
    list_offset = offset;

    while (media_type_index < media_types) {
        guint8 spec_info_len = 0;

        media_item = proto_tree_add_subtree_format(media_type_list,
                                tvb, offset, -1,
                                ett_media_item, &mpi,
                                "Media type %u", media_type_index);

        media_type_offset = offset;

        offset = dissect_media_type(tvb, pinfo, media_item, offset);

        spec_info_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_item(media_item, hf_ieee1905_media_spec_info_len,
                            tvb, offset, 1, ENC_NA);
        offset++;

        if (spec_info_len) {
            /* FIXME: This should be dissected ... */
            proto_tree_add_item(media_item, hf_ieee1905_media_spec_info,
                                tvb, offset, spec_info_len, ENC_NA);
            offset += spec_info_len;
        }

        proto_item_set_len(mpi, offset - media_type_offset);

        media_type_index++;
    }

    proto_item_set_len(pi, offset - list_offset);

    return offset;
}

/*
 * Dissect a push button event join TLV
 */
static int
dissect_push_button_join_notification(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_ieee1905_sender_al_id, tvb, offset, 6,
                        ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_push_button_event_msg_id, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ieee1905_sender_joining_interface, tvb,
                        offset, 2, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_new_device_interface, tvb,
                        offset, 2, ENC_NA);

    return offset;
}

/*
 * Dissect a generic phy device info TLV
 */
static int
dissect_generic_phy_device_info(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_item *pi = NULL;
    proto_tree *local_interface_list = NULL;
    guint8 local_intf_count, local_intf_index = 0;
    gint saved_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_device_al_mac, tvb, offset,
                        6, ENC_NA);
    offset += 6;

    local_intf_count = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ieee1905_local_interface_count, tvb,
                        offset, 1, ENC_NA);

    offset++;

    if (local_intf_count == 0)
        return offset;

    local_interface_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                        ett_local_interface_list,
                                        &pi, "Local interface list");
    saved_offset = 0;

    while (local_intf_index < local_intf_count) {
        proto_tree *intf_tree = NULL;
        proto_item *ipi = NULL;
        guint start_offset = offset;
        guint8 url_field_count, media_spec_count;

        intf_tree = proto_tree_add_subtree_format(local_interface_list,
                                        tvb, offset, -1,
                                        ett_local_interface_info,
                                        &ipi, "Local interface %u generic info",
                                        local_intf_index);

        proto_tree_add_item(intf_tree, hf_ieee1905_local_interface_mac,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        proto_tree_add_item(intf_tree, hf_ieee1905_local_intf_oui,
                            tvb, offset, 3, ENC_NA);
        offset+= 3;

        proto_tree_add_item(intf_tree, hf_ieee1905_local_intf_variant,
                            tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(intf_tree, hf_ieee1905_local_intf_variant_name,
                            tvb, offset, 32, ENC_UTF_8);
        offset += 32;

        url_field_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(intf_tree, hf_ieee1905_local_intf_url_count,
                            tvb, offset, 1, ENC_NA);
        offset++;

        media_spec_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(intf_tree, hf_ieee1905_local_intf_spec_count,
                            tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(intf_tree, hf_ieee1905_local_intf_url, tvb,
                            offset, url_field_count, ENC_ASCII);
        offset += url_field_count;

        proto_tree_add_item(intf_tree, hf_ieee1905_local_intf_spec, tvb,
                            offset, media_spec_count, ENC_NA);
        offset+= media_spec_count;

        proto_item_set_len(ipi, offset - start_offset);

        local_intf_index++;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

/*
 * Dissect a Device Identification Type TLV
 */
static int
dissect_device_identification(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_ieee1905_dev_id_friendly_name, tvb,
                        offset, 64, ENC_UTF_8);
    offset += 64;

    proto_tree_add_item(tree, hf_ieee1905_dev_id_manuf_name, tvb,
                        offset, 64, ENC_UTF_8);
    offset += 64;

    proto_tree_add_item(tree, hf_ieee1905_dev_id_manuf_model, tvb,
                        offset, 64, ENC_UTF_8);
    offset += 64;

    return offset;
}

/*
 * Dissect a Control URL Type TLV
 */
static int
dissect_control_url_type(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    proto_tree_add_item(tree, hf_ieee1905_control_url, tvb, offset,
                        len, ENC_ASCII);
    offset += len;

    return offset;
}

/*
 * Dissect an IPv4 Type TLV
 */
static int
dissect_ipv4_type(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint8 entry_count = tvb_get_guint8(tvb, offset);
    guint8 entry_index = 0;
    proto_item *pi = NULL;
    proto_tree *ipv4_list = NULL;
    guint saved_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_ipv4_type_count, tvb, offset,
                        1, ENC_NA);
    offset++;

    if (entry_count == 0)
        return offset;

    ipv4_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                       ett_ipv4_list,
                                       &pi, "IPv4 type list");
    saved_offset = offset;

    while (entry_index < entry_count) {
        proto_tree *ipv4_tree = NULL, *addr_list = NULL;
        proto_item *ipi = NULL;
        guint start_offset = offset;
        guint8 addr_count = 0, addr_index = 0;

        ipv4_tree = proto_tree_add_subtree_format(ipv4_list,
                                        tvb, offset, -1,
                                        ett_ipv4_info,
                                        &ipi, "IPv4 type %u info",
                                        entry_index);

        proto_tree_add_item(ipv4_tree, hf_ieee1905_mac_address, tvb,
                            offset, 6, ENC_NA);
        offset += 6;

        addr_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(ipv4_tree, hf_ieee1905_ipv4_addr_count,
                            tvb, offset, 1, ENC_NA);
        offset++;

        if (addr_count == 0)
            continue;

        addr_list = proto_tree_add_subtree(ipv4_tree, tvb, offset,
                                        addr_count * 9,
                                        ett_ipv4_type_addr_list,
                                        NULL, "IPv4 address list");

        while (addr_index < addr_count) {
            proto_tree *addr_tree = NULL;
            proto_item *atpi = NULL;
            guint8 addr_type = tvb_get_guint8(tvb, offset);

            addr_tree = proto_tree_add_subtree_format(addr_list, tvb,
                                        offset, 9, ett_ipv4_addr_info,
                                        NULL, "IPv4 address %u info",
                                        addr_index);

            atpi = proto_tree_add_item(addr_tree, hf_ieee1905_addr_type,
                        tvb, offset, 1, ENC_NA);
            proto_item_append_text(atpi, ", %s",
                        val_to_str(addr_type, ieee1905_ipv4_addr_type_vals,
                                "Reserved"));
            offset++;

            proto_tree_add_item(addr_tree, hf_ieee1905_ipv4_addr, tvb,
                        offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(addr_tree, hf_ieee1905_dhcp_server, tvb,
                        offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            addr_index++;
        }

        proto_item_set_len(ipi, offset - start_offset);

        entry_index++;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

/*
 * Dissect an IPv6 Type TLV
 */
static int
dissect_ipv6_type(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint8 entry_count = tvb_get_guint8(tvb, offset);
    guint8 entry_index = 0;
    proto_item *pi = NULL;
    proto_tree *ipv6_list = NULL;
    guint saved_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_ipv6_type_count, tvb, offset,
                        1, ENC_NA);
    offset++;

    if (entry_count == 0)
        return offset;

    ipv6_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                       ett_ipv6_list,
                                       &pi, "IPv6 type list");
    saved_offset = offset;

    while (entry_index < entry_count) {
        proto_tree *ipv6_tree = NULL, *addr_list = NULL;
        proto_item *ipi = NULL;
        guint start_offset = offset;
        guint8 addr_count = 0, addr_index = 0;

        ipv6_tree = proto_tree_add_subtree_format(ipv6_list,
                                        tvb, offset, -1,
                                        ett_ipv6_info,
                                        &ipi, "IPv6 type %u info",
                                        entry_index);

        proto_tree_add_item(ipv6_tree, hf_ieee1905_ipv6_mac_address, tvb,
                            offset, 6, ENC_NA);
        offset += 6;

        proto_tree_add_item(ipv6_tree, hf_ieee1905_ipv6_linklocal, tvb,
                            offset, 16, ENC_NA);

        offset += 16;

        addr_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(ipv6_tree, hf_ieee1905_ipv6_addr_count,
                            tvb, offset, 1, ENC_NA);
        offset++;

        if (addr_count == 0)
            continue;

        addr_list = proto_tree_add_subtree(ipv6_tree, tvb, offset,
                                        addr_count * 9,
                                        ett_ipv6_type_addr_list,
                                        NULL, "IPv6 address list");

        while (addr_index < addr_count) {
            proto_tree *addr_tree = NULL;
            proto_item *atpi = NULL;
            guint8 addr_type = tvb_get_guint8(tvb, offset);

            addr_tree = proto_tree_add_subtree_format(addr_list, tvb,
                                        offset, 9, ett_ipv6_addr_info,
                                        NULL, "IPv6 address %u info",
                                        addr_index);

            atpi = proto_tree_add_item(addr_tree, hf_ieee1905_ipv6_addr_type,
                        tvb, offset, 1, ENC_NA);
            proto_item_append_text(atpi, ", %s",
                        val_to_str(addr_type, ieee1905_ipv6_addr_type_vals,
                                "Reserved"));
            offset++;

            proto_tree_add_item(addr_tree, hf_ieee1905_ipv6_addr, tvb,
                        offset, 16, ENC_NA);
            offset += 16;

            proto_tree_add_item(addr_tree, hf_ieee1905_ipv6_dhcp_server, tvb,
                        offset, 16, ENC_NA);
            offset += 16;

            addr_index++;
        }

        proto_item_set_len(ipi, offset - start_offset);

        entry_index++;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

/*
 * Dissect a push butteon generic phy event notification
 */
static int
dissect_push_button_event_type_notification(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint8 media_type_count = tvb_get_guint8(tvb, offset);
    guint8 media_type_index = 0;
    guint saved_offset;
    proto_item *pi = NULL;
    proto_tree *phy_list = NULL;

    proto_tree_add_item(tree, hf_ieee1905_generic_phy_media_types,
                        tvb, offset, 1, ENC_NA);
    offset++;

    phy_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                       ett_push_button_phy_list,
                                       &pi, "Generic Phy media type list");
    saved_offset = offset;

    while (media_type_index < media_type_count) {
        proto_item *ppi = NULL;
        proto_tree *phy_tree;
        guint start_offset = offset;
        guint8 media_specific_len;

        phy_tree = proto_tree_add_subtree_format(phy_list, tvb,
                                    offset, -1, ett_push_button_phy_info,
                                    &ppi, "Generic Phy media type %u info",
                                    media_type_index);

        proto_tree_add_item(phy_tree, hf_ieee1905_local_intf_oui,
                            tvb, offset, 3, ENC_NA);
        offset+= 3;

        proto_tree_add_item(phy_tree, hf_ieee1905_local_intf_variant,
                            tvb, offset, 1, ENC_NA);
        offset++;

        media_specific_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_item(phy_tree, hf_ieee1905_local_intf_spec_count,
                            tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(phy_tree, hf_ieee1905_local_intf_spec, tvb,
                            offset, media_specific_len, ENC_NA);
        offset += media_specific_len;

        proto_item_set_len(ppi, offset - start_offset);

        media_type_index++;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

/*
 * Dissect a 1905 profile version TLV
 */
static int
dissect_profile_version(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint8 profile_version = tvb_get_guint8(tvb, offset);
    proto_item *pi = NULL;

    pi = proto_tree_add_item(tree, hf_ieee1905_profile_version, tvb,
                offset, 1, ENC_NA);
    proto_item_append_text(pi, ", %s",
                val_to_str(profile_version, ieee1905_profile_version_vals,
                           "Reserved"));
    offset++;

    return offset;
}

/*
 * Dissect the power off interface TLV
 */
static int
dissect_power_off_interface(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint8 local_intf_count = tvb_get_guint8(tvb, offset);
    guint8 local_intf_index = 0;
    proto_item *pi = NULL;
    proto_tree *intf_list = NULL;
    guint saved_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_power_off_intf_count, tvb,
                        offset, 1, ENC_NA);
    offset++;

    if (local_intf_count == 0)
        return offset;

    intf_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                       ett_push_button_phy_list,
                                       &pi, "Generic Phy media type list");
    saved_offset = offset;

    while (local_intf_index < local_intf_count) {
        proto_tree *intf_tree = NULL;
        proto_item *ppi = NULL;
        guint8 media_specific_len = 0;

        intf_tree = proto_tree_add_subtree_format(intf_list, tvb,
                                    offset, -1, ett_power_off_info,
                                    &ppi, "Powered off interface %u info",
                                    local_intf_index);

        proto_tree_add_item(intf_tree, hf_ieee1905_mac_address, tvb,
                            offset, 6, ENC_NA);
        offset += 6;

        offset = dissect_media_type(tvb, pinfo, intf_tree, offset);

        proto_tree_add_item(intf_tree, hf_ieee1905_local_intf_oui,
                            tvb, offset, 3, ENC_NA);
        offset+= 3;

        proto_tree_add_item(intf_tree, hf_ieee1905_local_intf_variant,
                            tvb, offset, 1, ENC_NA);
        offset++;

        media_specific_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_item(intf_tree, hf_ieee1905_local_intf_spec_count,
                            tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(intf_tree, hf_ieee1905_local_intf_spec, tvb,
                            offset, media_specific_len, ENC_NA);
        offset += media_specific_len;

        local_intf_index++;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

/*
 * Dissect an interface power change information TLV.
 */
static int
dissect_interface_power_change_info(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint intf_count = tvb_get_guint8(tvb, offset);
    guint intf_index = 0;
    proto_tree *intf_list = NULL;

    proto_tree_add_item(tree, hf_ieee1905_power_change_intf_count, tvb,
                        offset, 1, ENC_NA);

    intf_list = proto_tree_add_subtree(tree, tvb, offset, intf_count * 7,
                        ett_power_change_list, NULL,
                        "Interface power change list");

    while (intf_index < intf_count) {
        proto_tree *intf_tree = NULL;
        proto_item *pi = NULL;
        guint8 power_state = 0;

        intf_tree = proto_tree_add_subtree_format(intf_list, tvb,
                        offset, 7, ett_power_change_info,
                        NULL, "Power change interface %u info",
                        intf_index);

        proto_tree_add_item(intf_tree, hf_ieee1905_power_change_mac_addr,
                        tvb, offset, 6, ENC_NA);
        offset += 6;

        power_state = tvb_get_guint8(tvb, offset);
        pi = proto_tree_add_item(tree, hf_ieee1905_power_change_state, tvb,
                        offset, 1, ENC_NA);
        proto_item_append_text(pi, ", %s",
                        val_to_str(power_state,
                                   ieee1905_power_state_vals,
                                   "Reserved"));
        offset++;

        intf_index++;
    }

    return offset;
}

/*
 * Dissect an interface power change status TLV.
 */
static int
dissect_interface_power_change_status(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint intf_count = tvb_get_guint8(tvb, offset);
    guint intf_index = 0;
    proto_tree *intf_list = NULL;

    proto_tree_add_item(tree, hf_ieee1905_power_status_intf_count, tvb,
                        offset, 1, ENC_NA);

    intf_list = proto_tree_add_subtree(tree, tvb, offset, intf_count * 7,
                        ett_power_status_list, NULL,
                        "Interface power status list");

    while (intf_index < intf_count) {
        proto_tree *intf_tree = NULL;
        proto_item *pi = NULL;
        guint8 power_state = 0;

        intf_tree = proto_tree_add_subtree_format(intf_list, tvb,
                        offset, 7, ett_power_status_info,
                        NULL, "Power status interface %u info",
                        intf_index);

        proto_tree_add_item(intf_tree, hf_ieee1905_power_status_mac_addr,
                        tvb, offset, 6, ENC_NA);
        offset += 6;

        power_state = tvb_get_guint8(tvb, offset);
        pi = proto_tree_add_item(tree, hf_ieee1905_power_status_state, tvb,
                        offset, 1, ENC_NA);
        proto_item_append_text(pi, ", %s",
                        val_to_str(power_state,
                                   ieee1905_power_status_vals,
                                   "Reserved"));
        offset++;

        intf_index++;
    }

    return offset;
}

static int
dissect_l2_neighbor_device(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint intf_count = tvb_get_guint8(tvb, offset);
    guint intf_index = 0;
    proto_tree *intf_list = NULL;
    proto_item *pi = NULL;
    guint saved_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_l2_neighbor_intf_count, tvb,
                        offset, 1, ENC_NA);
    offset++;

    if (intf_count == 0)
        return offset;

    intf_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                        ett_l2_local_intf_list, &pi,
                        "L2 local interface list");

    saved_offset = offset;

    while (intf_index < intf_count) {
        proto_tree *intf_tree = NULL, *neighbor_list = NULL;
        proto_item *ipi = NULL, *mpi = NULL;
        guint16 neighbor_device_count = 0, neighbor_device_index = 0;
        guint start_offset = offset, ndl_start_offset = 0;

        intf_tree = proto_tree_add_subtree_format(intf_list, tvb, offset, -1,
                            ett_l2_neighbor_device_info, &ipi,
                            "L2 neighbor device %u info", intf_count);

        proto_tree_add_item(intf_tree, hf_ieee1905_l2_local_intf_mac_addr, tvb,
                            offset, 6, ENC_NA);
        offset += 6;

        neighbor_device_count = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(intf_tree, hf_ieee1905_l2_neighbor_dev_count, tvb,
                            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        neighbor_list = proto_tree_add_subtree(intf_tree, tvb, offset, -1,
                            ett_l2_neighbor_dev_list, &mpi,
                            "Neighbor device list");

        ndl_start_offset = offset;

        while (neighbor_device_index < neighbor_device_count) {
            proto_tree *neighbor_dev_tree = NULL;
            proto_item *bmpi = NULL;
            guint16 behind_mac_addr_count = 0, behind_mac_addr_index = 0;
            guint ndt_start_offset = offset;

            neighbor_dev_tree = proto_tree_add_subtree_format(neighbor_list,
                                        tvb, offset, -1,
                                        ett_l2_neighbor_dev_tree, &bmpi,
                                        "Neighbor device %u info",
                                        neighbor_device_index);

            proto_tree_add_item(neighbor_dev_tree,
                                hf_ieee1905_l2_neighbor_mac_addr, tvb,
                                offset, 6, ENC_NA);
            offset += 6;

            behind_mac_addr_count = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(neighbor_dev_tree,
                                hf_ieee1905_l2_behind_mac_addr_count,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            while(behind_mac_addr_index < behind_mac_addr_count) {
                proto_tree_add_item(neighbor_dev_tree,
                                    hf_ieee1905_l2_behind_mac_addr, tvb,
                                    offset, 6, ENC_NA);
                offset += 6;

                behind_mac_addr_index++;
            }

            neighbor_device_index++;

            proto_item_set_len(bmpi, offset - ndt_start_offset);

        }

        proto_item_set_len(mpi, offset - ndl_start_offset);
        proto_item_set_len(ipi, offset - start_offset);

        intf_index++;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

static int
dissect_supported_service(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint service_count = tvb_get_guint8(tvb, offset);
    guint service_index = 0;
    proto_tree *service_list = NULL;

    proto_tree_add_item(tree, hf_ieee1905_supported_service_count, tvb,
                        offset, 1, ENC_NA);
    offset++;

    service_list = proto_tree_add_subtree(tree, tvb, offset, service_count,
                        ett_supported_service_list, NULL,
                        "Supported service list");

    while (service_index < service_count) {
        proto_item *pi = NULL;
        guint8 service = tvb_get_guint8(tvb, offset);

        pi = proto_tree_add_item(service_list, hf_ieee1905_supported_service,
                                tvb, offset, 1, ENC_NA);

        proto_item_append_text(pi, ", %s",
                        val_to_str(service,
                                   ieee1905_supported_service_vals,
                                   "Reserved"));
        offset++;

        service_index++;
    }

    return offset;
}

/*
 * Dissect a searched service TLV\
 */
static int
dissect_searched_service(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint service_count = tvb_get_guint8(tvb, offset);
    guint service_index = 0;
    proto_tree *service_list = NULL;

    proto_tree_add_item(tree, hf_ieee1905_searched_service_count, tvb,
                        offset, 1, ENC_NA);
    offset++;

    service_list = proto_tree_add_subtree(tree, tvb, offset, service_count,
                        ett_searched_service_list, NULL,
                        "Searched service list");

    while (service_index < service_count) {
        proto_item *pi = NULL;
        guint8 service = tvb_get_guint8(tvb, offset);

        pi = proto_tree_add_item(service_list, hf_ieee1905_searched_service,
                                tvb, offset, 1, ENC_NA);

        /*
         * Use the same set of values until we figure out if the spec has
         * an error in 17.2.2.
         */
        proto_item_append_text(pi, ", %s",
                        val_to_str(service,
                                   ieee1905_supported_service_vals,
                                   "Reserved"));
        offset++;

        service_index++;
    }

    return offset;
}

/*
 * Dissect an AP Radio Identifier TLV
 */
static int
dissect_ap_radio_identifier(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_ieee1905_ap_radio_identifier, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    return offset;
}

/*
 * Dissect an AP Operational BSS TLV
 */
static int
dissect_ap_operational_bss(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_item *rpi = NULL;
    proto_tree *radio_list = NULL;
    guint8 radio_count = tvb_get_guint8(tvb, offset);
    guint8 radio_index = 0;
    guint saved_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_operatonal_bss_radio_count,
                        tvb, offset, 1, ENC_NA);
    offset++;

    if (radio_count == 0)
        return offset;

    radio_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                        ett_ap_operational_bss_list, &rpi,
                        "AP operational BSS radio list");
    saved_offset = offset;

    while (radio_index < radio_count) {
        proto_tree *radio_tree = NULL, *local_intf_list = NULL;
        proto_item *opi = NULL, *ipi = NULL;
        guint start_offset = offset, list_start_offset;
        guint8 local_intf_count = 0;
        guint8 local_intf_index = 0;

        radio_tree = proto_tree_add_subtree_format(radio_list,
                                    tvb, offset, -1,
                                    ett_ap_operational_bss_tree, &opi,
                                    "AP operational BSS %u info",
                                    radio_index);

        proto_tree_add_item(radio_tree, hf_ieee1905_ap_radio_identifier,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        local_intf_count = tvb_get_guint8(tvb, offset);

        proto_tree_add_item(radio_tree, hf_ieee1905_ap_operational_intf_count,
                            tvb, offset, 1, ENC_NA);
        offset++;

        list_start_offset = offset;

        local_intf_list = proto_tree_add_subtree(radio_tree, tvb, offset, -1,
                                ett_ap_operational_bss_intf_list, &ipi,
                                "AP operational BSS local interface list");

        while (local_intf_index < local_intf_count) {
            guint8 ssid_len = 0;
            proto_tree *local_intf_tree = NULL;
            proto_item *itpi = NULL;
            guint local_intf_offset = offset;

            local_intf_tree = proto_tree_add_subtree_format(local_intf_list,
                                tvb, offset, -1,
                                ett_ap_operational_bss_intf_tree, &itpi,
                                "AP operational BSS Interface %u",
                                local_intf_index);

            proto_tree_add_item(local_intf_tree, hf_ieee1905_ap_local_intf_mac_addr,
                                tvb, offset, 6, ENC_NA);
            offset += 6;

            ssid_len = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(local_intf_tree, hf_ieee1905_ap_local_intf_ssid_len,
                                tvb, offset, 1, ENC_NA);
            offset++;

            proto_tree_add_item(local_intf_tree, hf_ieee1905_ap_local_intf_ssid,
                                tvb, offset, ssid_len, ENC_ASCII);
            offset += ssid_len;

            proto_item_set_len(itpi, offset - local_intf_offset);

            local_intf_index++;
        }

        proto_item_set_len(ipi, offset - list_start_offset);
        proto_item_set_len(opi, offset - start_offset);
        radio_index++;
    }

    proto_item_set_len(rpi, offset - saved_offset);

    return offset;
}

/*
 * Dissect an Associated Clients TLV
 */
static int
dissect_associated_clients(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint8 bss_count = tvb_get_guint8(tvb, offset);
    guint8 bss_index = 0;
    proto_tree *bss_list = NULL;
    proto_item *pi = NULL;
    guint saved_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_assoc_clients_bss_count,
                        tvb, offset, 1, ENC_NA);
    offset++;

    bss_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                ett_assoc_clients_bss_list, &pi,
                                "Associated BSS list");
    saved_offset = offset;

    while (bss_index < bss_count) {
        proto_tree *bss_tree = NULL, *client_list = NULL;
        proto_item *bpi = NULL;
        guint start_offset = offset;
        guint16 client_count = 0, client_index = 0;


        bss_tree = proto_tree_add_subtree_format(bss_list,
                                tvb, offset, -1,
                                ett_assoc_client_bss_tree, &bpi,
                                "Associated BSS %u",
                                bss_index);

        proto_tree_add_item(bss_tree, hf_ieee1905_assoc_bssid, tvb,
                            offset, 6, ENC_NA);
        offset += 6;

        client_count = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(bss_tree, hf_ieee1905_bss_client_count,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        client_list = proto_tree_add_subtree(bss_tree, tvb, offset,
                            client_count * 8, ett_assoc_client_list,
                            NULL, "Associated BSS clients list");

        while (client_index < client_count) {
            proto_tree *client_tree = NULL;

            client_tree = proto_tree_add_subtree_format(client_list, tvb,
                                offset, 8, ett_assoc_client_tree,
                                NULL, "Client %u", client_index);

            proto_tree_add_item(client_tree, hf_ieee1905_bss_client_mac,
                                tvb, offset, 6, ENC_NA);
            offset += 6;

            proto_tree_add_item(client_tree, hf_ieee1905_bss_client_last_assoc,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            client_index++;
        }

        proto_item_set_len(bpi, offset - start_offset);
        bss_index++;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

/*
 * Dissect an AP Capability TLV
 */
static int
dissect_ap_capability(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    static int * const capabilities[] = {
        &hf_ieee1905_unassoc_sta_metrics_oper_flag,
        &hf_ieee1905_unassoc_sta_metrics_non_oper_flag,
        &hf_ieee1905_agent_init_steering,
        NULL,
    };

    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_ap_capabilities_flags,
                           ett_ieee1905_capabilities_flags,
                           capabilities, ENC_NA);
    offset++;

    return offset;
}

/*
 * Dissect an AP Radio Basic Capabilities TLV
 */
static int
dissect_ap_radio_basic_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint8 classes = 0, class_index = 0;
    proto_tree *class_list = NULL;
    proto_item *pi = NULL;
    guint saved_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_ap_radio_identifier, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_ap_radio_max_bss, tvb,
                        offset, 1, ENC_NA);
    offset++;

    classes = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_ap_radio_classes, tvb,
                        offset, 1, ENC_NA);
    offset++;

    class_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                        ett_radio_basic_class_list, &pi,
                        "Supported operating classes list");
    saved_offset = offset;

    while (class_index < classes) {
        proto_tree *class_tree = NULL;
        proto_tree *non_op_channel_list = NULL;
        proto_item *cpi = NULL;
        guint class_offset = offset;
        guint8 non_op_channel_count = 0;

        class_tree = proto_tree_add_subtree_format(class_list,
                                tvb, offset, -1,
                                ett_ap_radio_basic_cap_class_tree, &cpi,
                                "Operating class %u",
                                class_index);

        proto_tree_add_item(class_tree, hf_ieee1905_ap_radio_class, tvb,
                            offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(class_tree, hf_ieee1905_ap_radio_eirp,
                            tvb, offset, 1, ENC_NA);
        offset++;

        non_op_channel_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(class_tree, hf_ieee1905_ap_radio_non_op_count,
                            tvb, offset, 1, ENC_NA);
        offset++;

        if (non_op_channel_count > 0) {

            non_op_channel_list = proto_tree_add_subtree(class_tree, tvb, offset,
                                    non_op_channel_count,
                                    ett_radio_basic_non_op_list, NULL,
                                    "Non-operating channel list");

            while (non_op_channel_count > 0) {
                proto_tree_add_item(non_op_channel_list,
                                    hf_ieee1905_radio_basic_non_op_channel,
                                    tvb, offset, 1, ENC_NA);
                offset++;

                non_op_channel_count--;
            }
        }

        proto_item_set_len(cpi, offset - class_offset);
        class_index++;
    }

    proto_item_set_len(pi, offset - saved_offset);
    return offset;
}

/*
 * Dissect an AP HT Capabilities TLV
 */
static int
dissect_ap_ht_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    static int * const capabilities[] = {
        &hf_ieee1905_max_supported_tx_streams,
        &hf_ieee1905_max_supported_rx_streams,
        &hf_ieee1905_short_gi_20mhz_flag,
        &hf_ieee1905_short_gi_40mhz_flag,
        &hf_ieee1905_ht_support_40mhz_flag,
        NULL,
    };

    proto_tree_add_item(tree, hf_ieee1905_ap_ht_capabilities_radio_id,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_bitmask(tree, tvb, offset, hf_ieee1905_ht_cap_flags,
                           ett_ht_cap_flags, capabilities, ENC_NA);
    offset++;

    return offset;
}

/*
 * Dissect an AP VHT Capabilities TLV
 */
static int
dissect_ap_vht_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    static int * const capabilities[] = {
        &hf_ieee1905_vht_max_supported_tx_streams,
        &hf_ieee1905_vht_max_supported_rx_streams,
        &hf_ieee1905_short_gi_80mhz_flag,
        &hf_ieee1905_short_gi_160mhz_flag,
        &hf_ieee1905_vht_support_80plus_mhz_flag,
        &hf_ieee1905_vht_support_160_mhz_flag,
        &hf_ieee1905_su_beamformer_capable_flag,
        &hf_ieee1905_mu_beamformer_capable_flag,
        NULL,
    };

    proto_tree_add_item(tree, hf_ieee1905_ap_vht_capabilities_radio_id,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_ap_vht_supported_vht_tx_mcs,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ieee1905_ap_vht_supported_vht_rx_mcs,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask(tree, tvb, offset, hf_ieee1905_vht_cap_flags,
                           ett_vht_cap_flags, capabilities, ENC_NA);
    offset += 2;

    return offset;
}

/*
 * Dissect an AP HE Capabilities TLV
 */
static int * const he_capabilities[] = {
    &hf_ieee1905_he_max_supported_tx_streams,
    &hf_ieee1905_he_max_supported_rx_streams,
    &hf_ieee1905_he_support_80plus_mhz_flag,
    &hf_ieee1905_he_support_160mhz_flag,
    &hf_ieee1905_he_su_beamformer_capable_flag,
    &hf_ieee1905_he_mu_beamformer_capable_flag,
    &hf_ieee1905_ul_mu_mimo_capable_flag,
    &hf_ieee1905_ul_mu_mimo_ofdma_capable_flag,
    &hf_ieee1905_dl_mu_mimo_ofdma_capable_flag,
    &hf_ieee1905_ul_ofdma_capable,
    &hf_ieee1905_dl_ofdma_capable,
    NULL,
};

static const value_string max_he_mcs_1_ss_vals[] = {
    { 0, "Support for HE-MCS 0-7 for 1 Spatial Stream" },
    { 1, "Support for HE-MCS 0-9 for 1 Spatial Stream" },
    { 2, "Support for HE-MCS 0-11 for 1 Spatial Stream" },
    { 3, "1 Spatial Stream not supported" },
    { 0, NULL }
};

static const value_string max_he_mcs_2_ss_vals[] = {
    { 0, "Support for HE-MCS 0-7 for 2 Spatial Streams" },
    { 1, "Support for HE-MCS 0-9 for 2 Spatial Streams" },
    { 2, "Support for HE-MCS 0-11 for 2 Spatial Streams" },
    { 3, "2 Spatial Streams not supported" },
    { 0, NULL }
};

static const value_string max_he_mcs_3_ss_vals[] = {
    { 0, "Support for HE-MCS 0-7 for 3 Spatial Streams" },
    { 1, "Support for HE-MCS 0-9 for 3 Spatial Streams" },
    { 2, "Support for HE-MCS 0-11 for 3 Spatial Streams" },
    { 3, "3 Spatial Streams not supported" },
    { 0, NULL }
};

static const value_string max_he_mcs_4_ss_vals[] = {
    { 0, "Support for HE-MCS 0-7 for 4 Spatial Streams" },
    { 1, "Support for HE-MCS 0-9 for 4 Spatial Streams" },
    { 2, "Support for HE-MCS 0-11 for 4 Spatial Streams" },
    { 3, "4 Spatial Streams not supported" },
    { 0, NULL }
};

static const value_string max_he_mcs_5_ss_vals[] = {
    { 0, "Support for HE-MCS 0-7 for 5 Spatial Streams" },
    { 1, "Support for HE-MCS 0-9 for 5 Spatial Streams" },
    { 2, "Support for HE-MCS 0-11 for 5 Spatial Streams" },
    { 3, "5 Spatial Streams not supported" },
    { 0, NULL }
};

static const value_string max_he_mcs_6_ss_vals[] = {
    { 0, "Support for HE-MCS 0-7 for 6 Spatial Streams" },
    { 1, "Support for HE-MCS 0-9 for 6 Spatial Streams" },
    { 2, "Support for HE-MCS 0-11 for 6 Spatial Streams" },
    { 3, "6 Spatial Streams not supported" },
    { 0, NULL }
};

static const value_string max_he_mcs_7_ss_vals[] = {
    { 0, "Support for HE-MCS 0-7 for 7 Spatial Streams" },
    { 1, "Support for HE-MCS 0-9 for 7 Spatial Streams" },
    { 2, "Support for HE-MCS 0-11 for 7 Spatial Streams" },
    { 3, "7 Spatial Streams not supported" },
    { 0, NULL }
};

static const value_string max_he_mcs_8_ss_vals[] = {
    { 0, "Support for HE-MCS 0-7 for 8 Spatial Streams" },
    { 1, "Support for HE-MCS 0-9 for 8 Spatial Streams" },
    { 2, "Support for HE-MCS 0-11 for 8 Spatial Streams" },
    { 3, "8 Spatial Streams not supported" },
    { 0, NULL }
};

static int * const rx_he_mcs_map_headers[] = {
    &hf_ieee1905_ap_he_rx_mcs_map_1ss,
    &hf_ieee1905_ap_he_rx_mcs_map_2ss,
    &hf_ieee1905_ap_he_rx_mcs_map_3ss,
    &hf_ieee1905_ap_he_rx_mcs_map_4ss,
    &hf_ieee1905_ap_he_rx_mcs_map_5ss,
    &hf_ieee1905_ap_he_rx_mcs_map_6ss,
    &hf_ieee1905_ap_he_rx_mcs_map_7ss,
    &hf_ieee1905_ap_he_rx_mcs_map_8ss,
    NULL
};

static int * const tx_he_mcs_map_headers[] = {
    &hf_ieee1905_ap_he_tx_mcs_map_1ss,
    &hf_ieee1905_ap_he_tx_mcs_map_2ss,
    &hf_ieee1905_ap_he_tx_mcs_map_3ss,
    &hf_ieee1905_ap_he_tx_mcs_map_4ss,
    &hf_ieee1905_ap_he_tx_mcs_map_5ss,
    &hf_ieee1905_ap_he_tx_mcs_map_6ss,
    &hf_ieee1905_ap_he_tx_mcs_map_7ss,
    &hf_ieee1905_ap_he_tx_mcs_map_8ss,
    NULL
};

static int
dissect_ap_he_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint8 he_mcs_len = 0;

    proto_tree_add_item(tree, hf_ieee1905_ap_he_cap_radio_id, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    he_mcs_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_ap_he_cap_mcs_length, tvb,
                        offset, 1, ENC_NA);
    offset++;

    /*
     * If the count is not 4, 8, or 12, it is an error.
     */
    if (he_mcs_len != 4 && he_mcs_len != 8 && he_mcs_len != 12) {

    } else {
        proto_tree *mcs_set = NULL;

        mcs_set = proto_tree_add_subtree(tree, tvb, offset, 4,
                        ett_ap_he_mcs_set, NULL,
                        "Supported HE-MCS and NSS Set <= 80 MHz");

        proto_tree_add_bitmask_with_flags(mcs_set, tvb, offset,
                        hf_ieee1905_ap_he_cap_tx_mcs_le_80_mhz,
                        ett_ieee1905_ap_he_rx_mcs_set,
                        tx_he_mcs_map_headers, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        offset += 2;

        proto_tree_add_bitmask_with_flags(mcs_set, tvb, offset,
                        hf_ieee1905_ap_he_cap_rx_mcs_le_80_mhz,
                        ett_ieee1905_ap_he_rx_mcs_set,
                        rx_he_mcs_map_headers, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        offset += 2;

        if (he_mcs_len > 4) {
            mcs_set = proto_tree_add_subtree(tree, tvb, offset, 4,
                        ett_ap_he_mcs_set, NULL,
                        "Supported HE-MCS and NSS Set 160 MHz");

            proto_tree_add_bitmask_with_flags(mcs_set, tvb, offset,
                        hf_ieee1905_ap_he_cap_tx_mcs_160_mhz,
                        ett_ieee1905_ap_he_rx_mcs_set,
                        tx_he_mcs_map_headers, ENC_BIG_ENDIAN, BMT_NO_APPEND);
            offset += 2;

            proto_tree_add_bitmask_with_flags(mcs_set, tvb, offset,
                        hf_ieee1905_ap_he_cap_rx_mcs_160_mhz,
                        ett_ieee1905_ap_he_rx_mcs_set,
                        rx_he_mcs_map_headers, ENC_BIG_ENDIAN, BMT_NO_APPEND);
            offset += 2;
        }

        if (he_mcs_len > 8) {
            mcs_set = proto_tree_add_subtree(tree, tvb, offset, 4,
                        ett_ap_he_mcs_set, NULL,
                        "Supported HE-MCS and NSS Set 80+80 MHz");

            proto_tree_add_bitmask_with_flags(mcs_set, tvb, offset,
                        hf_ieee1905_ap_he_cap_tx_mcs_80p80_mhz,
                        ett_ieee1905_ap_he_rx_mcs_set,
                        tx_he_mcs_map_headers, ENC_BIG_ENDIAN, BMT_NO_APPEND);
            offset += 2;

            proto_tree_add_bitmask_with_flags(mcs_set, tvb, offset,
                        hf_ieee1905_ap_he_cap_rx_mcs_80p80_mhz,
                        ett_ieee1905_ap_he_rx_mcs_set,
                        rx_he_mcs_map_headers, ENC_BIG_ENDIAN, BMT_NO_APPEND);
            offset += 2;
        }
    }

    proto_tree_add_bitmask(tree, tvb, offset, hf_ieee1905_he_cap_flags,
                           ett_ap_he_cap_flags, he_capabilities,
                           ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/*
 * Dissect a Steering Policy TLV
 */
static int
dissect_steering_policy(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 steering_disallowed_count = tvb_get_guint8(tvb, offset);
    guint8 btm_steering_disallowed_count = 0;
    guint8 radio_count = 0, radio_index = 0;

    proto_tree_add_item(tree, hf_ieee1905_steering_policy_local_disallowed_count,
                        tvb, offset, 1, ENC_NA);
    offset++;

    if (steering_disallowed_count) {
        proto_tree *disallowed_list = NULL;

        disallowed_list = proto_tree_add_subtree(tree, tvb, offset,
                        steering_disallowed_count * 6,
                        ett_steering_policy_disallowed_list, NULL,
                        "Steering disallowed STA list");

        while (steering_disallowed_count > 0) {
            proto_tree_add_item(disallowed_list,
                        hf_ieee1905_steering_disallowed_mac_addr,
                        tvb, offset, 6, ENC_NA);
            offset += 6;
            steering_disallowed_count--;
        }
    }

    btm_steering_disallowed_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_btm_steering_disallowed_count,
                        tvb, offset, 1, ENC_NA);
    offset++;

    if (btm_steering_disallowed_count > 0) {
        proto_tree *btm_disallowed_list = NULL;

        btm_disallowed_list = proto_tree_add_subtree(tree, tvb, offset,
                        btm_steering_disallowed_count * 6,
                        ett_btm_steering_policy_disallowed_list, NULL,
                        "BTM steering disallowed STA list");

        while (btm_steering_disallowed_count > 0) {

            proto_tree_add_item(btm_disallowed_list,
                        hf_ieee1905_btm_steering_disallowed_mac_addr,
                        tvb, offset, 6, ENC_NA);
            offset += 6;

            btm_steering_disallowed_count--;
        }
    }

    radio_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_steering_policy_radio_count,
                        tvb, offset, 1, ENC_NA);
    offset++;

    if (radio_count > 0) {
        proto_tree *policy_list = NULL;

        policy_list = proto_tree_add_subtree(tree, tvb, offset,
                        radio_count * 9,
                        ett_btm_steering_radio_list, NULL,
                        "BTM steering policy radio list");

        while (radio_index < radio_count) {
            proto_tree *policy_tree = NULL;
            proto_item *pi = NULL;
            guint8 policy = 0;

            policy_tree = proto_tree_add_subtree_format(policy_list,
                                tvb, offset, 9,
                                ett_ap_operational_bss_intf_tree, NULL,
                                "Radio %u", radio_index);

            proto_tree_add_item(policy_tree, hf_ieee1905_steering_policy_radio_id,
                                tvb, offset, 6, ENC_NA);
            offset += 6;

            policy = tvb_get_guint8(tvb, offset);
            pi = proto_tree_add_item(policy_tree, hf_ieee1905_steering_policy_policy,
                                tvb, offset, 1, ENC_NA);
            proto_item_append_text(pi, ", %s",
                                val_to_str(policy,
                                        ieee1905_steering_policy_vals,
                                        "Reserved"));
            offset++;

            proto_tree_add_item(policy_tree, hf_ieee1905_steering_policy_util,
                                tvb, offset, 1, ENC_NA);
            offset++;

            proto_tree_add_item(policy_tree,
                                hf_ieee1905_steering_policy_rcpi_threshold,
                                tvb, offset, 1, ENC_NA);
            offset++;

            radio_index++;
        }

    }

    return offset;
}

static void
rcpi_threshold_custom(gchar *result, guint8 rcpi_threshold)
{
    if (rcpi_threshold == 0) {
        snprintf(result, ITEM_LABEL_LENGTH, "Do not report STA Metrics based on RCPI threshold");
    } else if (rcpi_threshold > 0 && rcpi_threshold < 220) {
        snprintf(result, ITEM_LABEL_LENGTH, "RCPI Threshold = %.1fdBm",
                 (float)rcpi_threshold/2 - 110);
    } else if (rcpi_threshold == 220) {
        snprintf(result, ITEM_LABEL_LENGTH, "RCPI Threshold >= 0dBm");
    } else {
        snprintf(result, ITEM_LABEL_LENGTH, "Reserved");
    }
}

static void
rcpi_hysteresis_custom(gchar *result, guint8 rcpi_hysteresis)
{
    if (rcpi_hysteresis == 0) {
        snprintf(result, ITEM_LABEL_LENGTH, "Use Agent's implementation-specific default RCPI Hysteresis margin");
    } else {
        snprintf(result, ITEM_LABEL_LENGTH, "%udB", rcpi_hysteresis);
    }
}

/*
 * Dissect a Metric Reporing Policy TLV
 */
static int
dissect_metric_reporting_policy(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint8 radio_count = 0, radio_index = 0;
    proto_tree *radio_list = NULL;
    proto_tree *radio_tree = NULL;
    proto_item *pi = NULL;
    guint saved_offset = 0;
    static int * const ieee1905_reporting_policy_flags[] = {
        &hf_ieee1905_assoc_sta_traffic_stats_inclusion,
        &hf_ieee1905_assoc_sta_link_metrics_inclusion,
        &hf_ieee1905_assoc_wf6_status_policy_inclusion,
        &hf_ieee1905_reporting_policy_flags_reserved,
        NULL
    };

    proto_tree_add_item(tree, hf_ieee1905_ap_metrics_reporting_interval,
                        tvb, offset, 1, ENC_NA);
    offset++;

    radio_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_metric_reporting_radio_count,
                        tvb, offset, 1, ENC_NA);
    offset++;

    if (radio_count == 0)
        return offset;

    radio_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                        ett_metric_reporting_policy_list, &pi,
                        "Metric reporting policy list");
    saved_offset = offset;

    while (radio_index < radio_count) {
        radio_tree = proto_tree_add_subtree_format(radio_list,
                                tvb, offset, 8,
                                ett_metric_reporting_policy_tree, NULL,
                                "Reporting policy for radio %u",
                                radio_index);

        proto_tree_add_item(radio_tree, hf_ieee1905_metric_reporting_policy_radio_id,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        proto_tree_add_item(radio_tree, hf_ieee1905_metric_rcpi_threshold, tvb,
                            offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(radio_tree, hf_ieee1905_metric_reporting_rcpi_hysteresis,
                            tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(radio_tree, hf_ieee1905_metrics_channel_util_threshold,
                            tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_bitmask_with_flags(radio_tree, tvb, offset,
                            hf_ieee1905_metrics_policy_flags,
                            ett_metric_policy_flags,
                            ieee1905_reporting_policy_flags, ENC_NA,
                            BMT_NO_APPEND);
        offset++;

        radio_index++;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

/*
 * Dissect a Channel Preference TLV
 */
static int
dissect_channel_preference(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 operating_classes = 0, operating_index = 0;
    proto_tree *class_list = NULL;
    proto_item *pi = NULL;
    guint saved_offset = 0;
    static int * const preference[] = {
        &hf_ieee1905_channel_pref_preference,
        &hf_ieee1905_channel_pref_reason,
        NULL,
    };

    if (len < 6) {
        expert_add_info(pinfo, tree, &ei_ieee1905_malformed_tlv);
        return offset + len;
    }

    proto_tree_add_item(tree, hf_ieee1905_channel_preference_radio_id,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    if (len < 7) {
        expert_add_info(pinfo, tree, &ei_ieee1905_malformed_tlv);
        return offset;
    }

    operating_classes = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_channel_preference_class_count,
                        tvb, offset, 1, ENC_NA);
    offset++;

    if (operating_classes == 0)
        return offset;

    class_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                        ett_channel_preference_class_list, &pi,
                        "Supported operating classes list");
    saved_offset = offset;

    /*
     * There should be at least 2 more bytes here ... add some more expert
     * info soon.
     */

    while (operating_index < operating_classes) {
        proto_tree *class_tree = NULL;
        proto_item *cpi = NULL;
        guint8 channels = 0;
        guint start_offset = offset;

        class_tree = proto_tree_add_subtree_format(class_list,
                                tvb, offset, -1,
                                ett_ap_channel_preference_class_tree, &cpi,
                                "Operating class %u",
                                operating_index);

        proto_tree_add_item(class_tree, hf_ieee1905_channel_pref_class,
                            tvb, offset, 1, ENC_NA);
        offset++;

        channels = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(class_tree, hf_ieee1905_channel_pref_channel_count,
                            tvb, offset, 1, ENC_NA);
        offset++;

        if (channels > 0) {
            proto_tree *channel_list = NULL;

            channel_list = proto_tree_add_subtree(class_tree, tvb, offset,
                                    channels,
                                    ett_channel_pref_channel_list, NULL,
                                    "Channel list");

            while (channels > 0) {
                proto_tree_add_item(channel_list,
                                    hf_ieee1905_channel_pref_channel,
                                    tvb, offset, 1, ENC_NA);
                offset++;

                channels--;
            }

        }

        proto_tree_add_bitmask(class_tree, tvb, offset,
                           hf_ieee1905_channel_prefs_flags,
                           ett_ieee1905_channel_prefs_flags,
                           preference, ENC_NA);
        offset++;

        proto_item_set_len(cpi, offset - start_offset);

        operating_index++;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

/*
 * Dissect a Radio Operation Restriction TLV
 */
static int
dissect_radio_operation_restriction(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 op_class_count = 0, op_class_index = 0;
    proto_tree *op_class_list = NULL, *op_class_tree = NULL;
    proto_item *pi = NULL;
    guint saved_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_radio_restriction_radio_id,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    op_class_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_radio_restriction_op_class_count,
                        tvb, offset, 1, ENC_NA);
    offset++;

    if (op_class_count == 0)
        return offset;

    op_class_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                        ett_radio_restriction_op_class_list, &pi,
                        "Restricted operating class list");
    saved_offset = offset;

    while (op_class_index < op_class_count) {
        proto_item *ocpi = NULL;
        proto_tree *channel_list = NULL, *channel_tree = NULL;
        guint start_offset = offset;
        guint8 channel_count = 0, channel_index = 0;

        op_class_tree = proto_tree_add_subtree_format(op_class_list,
                                tvb, offset, -1,
                                ett_radio_restriction_op_class_tree, &ocpi,
                                "Operating class %u",
                                op_class_index);

        proto_tree_add_item(op_class_tree, hf_ieee1905_radio_restriction_op_class,
                            tvb, offset, 1, ENC_NA);
        offset++;

        channel_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(op_class_tree, hf_ieee1905_radio_restriction_chan_count,
                            tvb, offset, 1, ENC_NA);
        offset++;

        if (channel_count == 0) {
            proto_item_set_len(ocpi, offset - start_offset);
            op_class_index++;
            continue;
        }

        channel_list = proto_tree_add_subtree(op_class_tree, tvb, offset, channel_count * 2,
                        ett_radio_restriction_channel_list, NULL,
                        "Restricted channel(s) list");

        while (channel_index < channel_count) {
            guint8 separation = 0;
            guint sep_mhz = 0;

            channel_tree = proto_tree_add_subtree_format(channel_list,
                                tvb, offset, 2,
                                ett_radio_restriction_channel_tree, NULL,
                                "Channel restriction %u",
                                channel_index);

            proto_tree_add_item(channel_tree, hf_ieee1905_radio_restriction_channel,
                                tvb, offset, 1, ENC_NA);
            offset++;

            separation = tvb_get_guint8(tvb, offset);
            sep_mhz = separation * 10;
            proto_tree_add_uint_format(channel_tree,
                                hf_ieee1905_radio_restriction_min_separation,
                                tvb, offset, 1, separation,
                                "Min frequency separation: %dMHz", sep_mhz);
            offset++;

            channel_index++;
        }

        proto_item_set_len(ocpi, offset - start_offset);
        op_class_index++;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

/*
 * Dissect a Transmit Power Limit TLV
 */
static int
dissect_transmit_power_limit(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_ieee1905_trans_power_limit_radio_id,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_trans_power_limit_eirp,
                        tvb, offset, 1, ENC_NA);
    offset++;

    return offset;
}

/*
 * Dissect a Channel Selection Response TLV
 */
static int
dissect_channel_selection_response(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint8 response_code = 0;
    proto_item *pi = NULL;

    proto_tree_add_item(tree, hf_ieee1905_channel_select_resp_radio_id,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    response_code = tvb_get_guint8(tvb, offset);
    pi = proto_tree_add_item(tree, hf_ieee1905_channel_select_resp_code, tvb,
                        offset, 1, ENC_NA);
    proto_item_append_text(pi, ", %s",
                        val_to_str(response_code,
                            ieee1905_channel_select_resp_code_vals,
                            "Reserved"));
    offset++;

    return offset;
}

/*
 * Dissect an Operaring Channel Report TLV
 */
static int
dissect_operating_channel_report(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint8 class_count = 0, class_index = 0;
    proto_tree *class_list = NULL, *class_tree = NULL;

    proto_tree_add_item(tree, hf_ieee1905_op_channel_report_radio_id,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    class_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_op_channel_report_classes,
                        tvb, offset, 1, ENC_NA);
    offset++;

    if (class_count > 0) {

        class_list = proto_tree_add_subtree(tree, tvb, offset, 2 * class_count,
                                ett_op_channel_report_class_list, NULL,
                                "Operating classes list");

        while (class_index < class_count) {
            class_tree = proto_tree_add_subtree_format(class_list, tvb,
                                offset, 2, ett_op_channel_report_class_tree,
                                NULL, "Operating class %u", class_index);

            proto_tree_add_item(class_tree, hf_ieee1905_op_channel_class,
                                tvb, offset, 1, ENC_NA);
            offset++;

            proto_tree_add_item(class_tree, hf_ieee1905_op_channel_number,
                                tvb, offset, 1, ENC_NA);
            offset++;

            class_index++;
        }
    }

    proto_tree_add_item(tree, hf_ieee1905_op_channel_eirp, tvb,
                             offset, 1, ENC_NA);
    offset++;

    return offset;
}

/*
 * Dissect a Higher Layer Data TLV
 */
static int
dissect_higher_layer_data(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    guint8 protocol = tvb_get_guint8(tvb, offset);
    proto_item *pi = NULL;

    pi = proto_tree_add_item(tree, hf_ieee1905_higher_layer_protocol,
                             tvb, offset, 1, ENC_NA);

    proto_item_append_text(pi, ", %s",
                    val_to_str(protocol,
                               ieee1905_higher_layer_protocol_vals,
                               "Reserved"));
    offset++;

    proto_tree_add_item(tree, hf_ieee1905_higher_layer_data, tvb,
                        offset, len - 1, ENC_NA);
    offset += len - 1;

    return offset;
}

/*
 * Dissect an unassociated sta link metric response TLV
 */
static int
dissect_unassociated_sta_link_metric_response(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 sta_count = 0, sta_index = 0;
    proto_tree *sta_list = NULL;

    proto_tree_add_item(tree, hf_ieee1905_unassoc_sta_link_metric_op_class,
                        tvb, offset, 1, ENC_NA);
    offset++;

    sta_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_unassoc_sta_link_metric_sta_count,
                        tvb, offset, 1, ENC_NA);
    offset++;

    sta_list = proto_tree_add_subtree(tree, tvb, offset, sta_count * 12,
                        ett_unassoc_sta_link_metric_list, NULL,
                        "Unassociated STA list");

    while (sta_index < sta_count) {
        proto_tree *sta_tree = NULL;

        sta_tree = proto_tree_add_subtree_format(sta_list, tvb,
                                offset, 12, ett_unassoc_sta_link_metric_tree,
                                NULL, "STA %u", sta_index);

        proto_tree_add_item(sta_tree, hf_ieee1905_unassoc_link_metric_mac_addr,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        proto_tree_add_item(sta_tree, hf_ieee1905_unassoc_link_metric_channel,
                            tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(sta_tree, hf_ieee1905_unassoc_link_metric_delta,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(sta_tree, hf_ieee1905_unassoc_link_metric_uplink_rcpi,
                            tvb, offset, 1, ENC_NA);
        offset++;

        sta_index++;
    }

    return offset;
}

/*
 * Dissect a Steering request TLV
 */
static int * const steering_flags[] = {
    &hf_ieee1905_steering_request_mode_flag,
    &hf_ieee1905_btm_disassoc_imminent_flag,
    &hf_ieee1905_btm_abridged_flag,
    &hf_ieee1905_steering_req_reserved,
    NULL,
};

static int
dissect_steering_request(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    guint8 mode = 0;
    guint8 steering_count = 0;
    proto_item *pi = NULL;
    proto_tree *sta_list = NULL, *bssid_list = NULL;
    guint8 target_bssid_count = 0;
    guint start_offset = offset;

    proto_tree_add_item(tree, hf_ieee1905_source_bss_bssid, tvb, offset,
                        6, ENC_NA);
    offset += 6;

    mode = tvb_get_guint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_steering_request_flags,
                           ett_ieee1905_steering_request_flags,
                           steering_flags, ENC_NA);
    offset++;

    /* If Request Mode is 1, this field is ignored. */
    proto_tree_add_item(tree, hf_ieee1905_steering_req_op_window,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ieee1905_steering_btm_disass_timer,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    steering_count = tvb_get_guint8(tvb, offset);
    pi = proto_tree_add_item(tree, hf_ieee1905_steering_req_sta_count,
                        tvb, offset, 1, ENC_NA);
    offset++;

    if (steering_count > 0) {
        sta_list = proto_tree_add_subtree(tree, tvb, offset, steering_count * 6,
                            ett_assoc_control_list, NULL,
                            "Steering request MAC list");

        while (steering_count > 0) {
            proto_tree_add_item(sta_list, hf_ieee1905_steering_req_sta_mac,
                            tvb, offset, 6, ENC_NA);
            offset += 6;

            steering_count--;
        }


    } else {
        proto_item_append_text(pi, " (Request applies to all STA(s) in BSS)");
    }

    /*
     * These fields only appear if Request mode is one.
     */
    if (mode & 0x80) {
        target_bssid_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_ieee1905_steering_req_target_bssid_count,
                            tvb, offset, 1, ENC_NA);
        offset++;

        bssid_list = proto_tree_add_subtree(tree, tvb, offset,
                            target_bssid_count * 8,
                            ett_assoc_control_list, NULL,
                            "Target BSSID list");

        while (target_bssid_count > 0) {
            /* Have to add a tree here ... */
            proto_tree_add_item(bssid_list,
                            hf_ieee1905_steering_req_target_bssid,
                            tvb, offset, 6, ENC_NA);
            offset += 6;

            proto_tree_add_item(bssid_list,
                            hf_ieee1905_steering_req_oper_class,
                            tvb, offset, 1, ENC_NA);
            offset++;

            proto_tree_add_item(bssid_list,
                            hf_ieee1905_steering_req_target_channel,
                            tvb, offset, 1, ENC_NA);
            offset++;

            target_bssid_count--;
        }
    }

    if ((offset - start_offset) < len) {
        proto_item *ei = NULL;

        ei = proto_tree_add_item(tree, hf_ieee1905_extra_tlv_data, tvb, offset,
                             len - (offset - start_offset), ENC_NA);
        expert_add_info(pinfo, ei, &ei_ieee1905_extraneous_tlv_data);
        offset = start_offset + len; /* Skip the extras. */
    }
    return offset;
}

/*
 * Dissect a Steering BTM report TLV
 */
static int
dissect_steering_btm_report(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    proto_tree_add_item(tree, hf_ieee1905_btm_reporter_bssid, tvb, offset,
                        6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_btm_sta_mac_addr, tvb, offset,
                        6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_btm_report_status, tvb, offset,
                        1, ENC_NA);
    offset++;

    /*
     * Handle the BSSID if present. Not sure which status values indicate
     * its presence. 13 is the number of bytes already dissected above.
     */
    if (len >= 13 + 6) {
        proto_tree_add_item(tree, hf_ieee1905_btm_report_bssid, tvb, offset,
                            len - 13, ENC_NA);
        offset += len - 13; /* Should check for more entries ... */
    }

    return offset;
}

/*
 * Dissect a Client association control request TLV
 */
static int
dissect_client_association_control_request(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint sta_list_count = 0;
    guint control = 0;
    proto_tree *sta_list = NULL;
    proto_item *pi = NULL;

    proto_tree_add_item(tree, hf_ieee1905_client_assoc_bssid, tvb, offset,
                        6, ENC_NA);
    offset += 6;

    control = tvb_get_guint8(tvb, offset);
    pi = proto_tree_add_item(tree, hf_ieee1905_association_control, tvb,
                             offset, 1, ENC_NA);
    proto_item_append_text(pi, ", %s",
                        val_to_str(control,
                           ieee1905_association_control_vals,
                           "Reserved"));
    offset++;

    pi = proto_tree_add_item(tree, hf_ieee1905_association_control_validity,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(pi, " seconds");
    offset += 2;

    sta_list_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_client_assoc_sta_count, tvb,
                        offset, 1, ENC_NA);
    offset++;

    sta_list = proto_tree_add_subtree(tree, tvb, offset, sta_list_count * 6,
                            ett_assoc_control_list, NULL,
                            "Client association control MAC list");

    while (sta_list_count > 0) {
        proto_tree_add_item(sta_list, hf_ieee1905_client_assoc_mac_addr,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        sta_list_count--;
    }

    return offset;
}

/*
 * Dissect a Beacon Metrics Query TLV
 */
static int
dissect_beacon_metrics_query(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 ssid_len = 0;
    guint8 channel_count = 0, channel_index = 0;
    guint saved_offset = 0;
    proto_tree *channel_report_list = NULL;
    proto_item *pi = NULL;

    proto_tree_add_item(tree, hf_ieee1905_beacon_metrics_query_mac_addr,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_beacon_metrics_query_op_class,
                        tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(tree, hf_ieee1905_beacon_metrics_query_channel,
                        tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(tree, hf_ieee1905_beacon_metrics_query_bssid,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_beacon_metrics_query_detail,
                        tvb, offset, 1, ENC_NA);
    offset++;

    ssid_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_beacon_metrics_query_ssid_len,
                        tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(tree, hf_ieee1905_beacon_metrics_query_ssid,
                        tvb, offset, ssid_len, ENC_ASCII);
    offset += ssid_len;

    /*
     * This field should only be non-zero if query_channel above is
     * not 255 ... should check
     */
    channel_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_beacon_metrics_channel_count,
                        tvb, offset, 1, ENC_NA);
    offset++;

    channel_report_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                            ett_beacon_metrics_query_list, &pi,
                            "Channel report list");
    saved_offset = offset;

    while (channel_index < channel_count) {
        guint8 report_len = 0, report_index = 0;
        proto_tree *channel_report_tree = NULL;
        proto_item *lpi = NULL;
        guint start_offset = offset;
        proto_tree *channel_list = NULL;

        channel_report_tree = proto_tree_add_subtree_format(channel_report_list, tvb,
                                offset, -1, ett_beacon_metrics_query_tree,
                                &lpi, "Channel report %u", channel_index);

        report_len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(channel_report_tree,
                            hf_ieee1905_beacon_metrics_report_len,
                            tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(channel_report_tree,
                            hf_ieee1905_beacon_metrics_report_op_class,
                            tvb, offset, 1, ENC_NA);
        offset++;

        channel_list = proto_tree_add_subtree(channel_report_tree, tvb, offset,
                            report_len - 1,
                            ett_beacon_metrics_query_channel_list, NULL,
                            "Channel report list");
        while (report_index < report_len - 1) {
            proto_tree_add_item(channel_list,
                                hf_ieee1905_beacon_metrics_report_channel_id,
                                tvb, offset, 1, ENC_NA);
            offset++;

            report_index++;
        }

        proto_item_set_len(lpi, offset - start_offset);

        channel_index++;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

/*
 * Dissect a measurement report. This should go into ieee80211.c but not
 * for now. We expect a new TVB that contains only one measurement report.
 */
static int
dissect_measurement_report(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree)
{
    guint8 offset = 0;
    guint rep_len = tvb_reported_length_remaining(tvb, offset);

    proto_tree_add_item(tree, hf_ieee1905_measurement_report, tvb, offset,
                        rep_len, ENC_NA);
    offset += rep_len;

    return offset;
}

/*
 * Dissect a Beacon Metrics Response TLV
 */
static int
dissect_beacon_metrics_response(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 report_index = 0;
    proto_item *pi = NULL;
    proto_tree *report_list = NULL;
    guint saved_offset = 0;
    guint8 meas_count = 0;

    proto_tree_add_item(tree, hf_ieee1905_beacon_metrics_response_mac_addr,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    pi = proto_tree_add_item(tree, hf_ieee1905_beacon_metrics_response_reserved,
                        tvb, offset, 1, ENC_NA);
    offset++;

    meas_count = tvb_get_guint8(tvb, offset);
    pi = proto_tree_add_item(tree, hf_ieee1905_beacon_metrics_response_meas_num,
                        tvb, offset, 1, ENC_NA);
    offset++;

    /* Now, the report(s) ... */
    report_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                            ett_beacon_metrics_response_report_list, &pi,
                            "Measurement report list");
    saved_offset = offset;

    while (meas_count > 0) {
        proto_tree *report_tree = NULL;
        proto_item *lpi = NULL;
        tvbuff_t *new_tvb = NULL;
        guint8 new_len = 0;

        report_tree = proto_tree_add_subtree_format(report_list, tvb,
                                offset, -1,
                                ett_beacon_metrics_response_report_tree,
                                &lpi, "Beacon report %u", report_index);

        /*
         * This is a measurement report, so the elt-id must be 39. The length
         * is the next field. Create a new TVB?
         */
        new_len = tvb_get_guint8(tvb, offset + 1);
        new_tvb = tvb_new_subset_length_caplen(tvb, offset + 2, new_len, new_len);

        dissect_measurement_report(new_tvb, pinfo, report_tree);

        proto_item_set_len(lpi, new_len + 2);

        offset += 2 + new_len;
        report_index++;
        meas_count--;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

/*
 * Dissect a Backhaul steering request TLV
 */
static int
dissect_backhaul_steering_request(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_ieee1905_assoc_backhaul_station_mac, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_backhaul_target_bssid, tvb, offset,
                        6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_backhaul_operating_class, tvb,
                        offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(tree, hf_ieee1905_backhaul_channel_number, tvb,
                        offset, 1, ENC_NA);
    offset++;

    return offset;
}

/*
 * Dissect a Backhaul steering response TLV
 */
static int
dissect_backhaul_steering_response(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_item *pi = NULL;
    guint8 status = 0;

    proto_tree_add_item(tree, hf_ieee1905_assoc_backhaul_station_mac, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_backhaul_target_bssid, tvb, offset,
                        6, ENC_NA);
    offset += 6;

    status = tvb_get_guint8(tvb, offset);
    pi = proto_tree_add_item(tree, hf_ieee1905_backhaul_steering_status,
                        tvb, offset, 1, ENC_NA);
    proto_item_append_text(pi, ", %s",
                        val_to_str(status,
                                   ieee1905_backhaul_status_vals,
                                   "Reserved"));
    offset++;

    return offset;
}

/*
 * Dissect a client info TLV
 */
static int
dissect_client_info(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_ieee1905_client_bssid, tvb, offset,
                        6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_client_mac_addr, tvb, offset,
                        6, ENC_NA);
    offset += 6;
    return offset;
}

/*
 * Dissect a client capability report TLV
 */
static int
dissect_client_capability_report(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    guint8 result = tvb_get_guint8(tvb, offset);
    proto_item *pi = NULL;

    pi = proto_tree_add_item(tree, hf_ieee1905_client_capability_result, tvb,
                        offset, 1, ENC_NA);
    proto_item_append_text(pi, ", %s",
                        val_to_str(result,
                                   ieee1905_client_capability_result_vals,
                                   "Reserved"));
    offset++;

    if (len > 1) { /* Must be the frame body of most recent assoc req */
        proto_tree_add_item(tree, hf_ieee1905_client_capability_frame, tvb,
                            offset, len - 1, ENC_NA);
        offset += len - 1;
    }

    return offset;
}

/*
 * Dissect a client capability report TLV
 */
static int
dissect_client_association_event(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    static int * const association_flags[] = {
        &hf_ieee1905_association_flag,
        NULL,
    };

    proto_tree_add_item(tree, hf_ieee1905_association_client_mac_addr,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_association_agent_bssid,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_association_event_flags,
                           ett_ieee1905_association_event_flags,
                           association_flags, ENC_NA);
    offset++;

    return offset;
}

/*
 * Dissect an AP Metrics Query TLV
 */
static int
dissect_ap_metric_query(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    proto_tree *bssid_list = NULL;
    proto_item *pi = NULL;
    guint saved_offset;

    proto_tree_add_item(tree, hf_ieee1905_ap_metric_query_bssid_cnt, tvb,
                        offset, 1, ENC_NA);
    offset++;

    bssid_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                            ett_ap_metric_query_bssid_list, &pi,
                            "AP BSSID list");
    saved_offset = offset;

    while (len >= 6) {
        proto_tree_add_item(bssid_list, hf_ieee1905_ap_metric_query_bssid,
                            tvb, offset, 6, ENC_NA);
        offset += 6;
        len -= 6;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

/*
 * Dissect an STA MAC address type TLV
 */
#define INCLUDE_ESTIMATED_SP_AC_EQ_BE 0x80
#define INCLUDE_ESTIMATED_SP_AC_EQ_BK 0x40
#define INCLUDE_ESTIMATED_SP_AC_EQ_VO 0x20
#define INCLUDE_ESTIMATED_SP_AC_EQ_VI 0x10

static int
dissect_ap_metrics(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 presence_flags = 0;
    static int * const flags[] = {
        &hf_ieee1905_include_estimated_spi_ac_eq_be,
        &hf_ieee1905_include_estimated_spi_ac_eq_bk,
        &hf_ieee1905_include_estimated_spi_ac_eq_vo,
        &hf_ieee1905_include_estimated_spi_ac_eq_vi,
        NULL
    };

    proto_tree_add_item(tree, hf_ieee1905_ap_metrics_agent_bssid,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_ap_metrics_channel_utilization,
                        tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(tree, hf_ieee1905_ap_metrics_sta_count,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    presence_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_bitmask_with_flags(tree, tvb, offset,
                        hf_ieee1905_ap_metrics_flags,
                        ett_ieee1905_ap_metrics_flags, flags, ENC_NA,
                        BMT_NO_APPEND);
    offset++;

    /*
     * This field should always be present, and the associated flag bit
     * should be 1 (TODO:check that).
     */
    proto_tree_add_item(tree, hf_ieee1905_ap_metrics_service_params_be,
                        tvb, offset, 3, ENC_NA);
    offset += 3;

    /*
     * We should indicate an error if the field is too small. Also,
     * need to know the format of these fields.
     */
    if (presence_flags & INCLUDE_ESTIMATED_SP_AC_EQ_BK) {
        proto_tree_add_item(tree, hf_ieee1905_ap_metrics_service_params_bk,
                        tvb, offset, 3, ENC_NA);
        offset += 3;
    }

    if (presence_flags & INCLUDE_ESTIMATED_SP_AC_EQ_VO) {
        proto_tree_add_item(tree, hf_ieee1905_ap_metrics_service_params_vo,
                        tvb, offset, 3, ENC_NA);
        offset += 3;
    }

    if (presence_flags & INCLUDE_ESTIMATED_SP_AC_EQ_VI) {
        proto_tree_add_item(tree, hf_ieee1905_ap_metrics_service_params_vi,
                        tvb, offset, 3, ENC_NA);
        offset += 3;
    }

    return offset;
}

/*
 * Dissect an STA MAC address type TLV
 */
static int
dissect_sta_mac_address_type(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_sta_mac_address_type, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    return offset;
}

/*
 * Dissect an Associated STA Link Metrics TLV
 */
static int
dissect_associated_sta_link_metrics(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree *bss_list = NULL;
    proto_tree *bss_tree = NULL;
    proto_item *pi = NULL;
    guint8 bss_list_index = 0;
    guint start_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_assoc_sta_mac_addr, tvb, offset,
                        6, ENC_NA);
    offset += 6;
    len -= 6;

    proto_tree_add_item(tree, hf_ieee1905_assoc_sta_bssid_count, tvb, offset,
                        1, ENC_NA);
    offset++;
    len--;

    bss_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                            ett_sta_list_metrics_bss_list, NULL,
                            "BSS list");

    while (len >= 19) {
        bss_tree = proto_tree_add_subtree_format(bss_list, tvb,
                                offset, 18, ett_sta_list_metrics_bss_tree,
                                NULL, "BSS %u", bss_list_index);

        proto_tree_add_item(bss_tree, hf_ieee1905_assoc_sta_link_metrics_bssid,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        proto_tree_add_item(bss_tree, hf_ieee1905_assoc_sta_link_metrics_time_delta,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(bss_tree, hf_ieee1905_assoc_sta_link_metrics_dwn_rate,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(bss_tree, hf_ieee1905_assoc_sta_link_metrics_up_rate,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(bss_tree, hf_ieee1905_assoc_sta_link_metrics_rcpi,
                            tvb, offset, 1, ENC_NA);
        offset++;

        bss_list_index++;
        len -= 19;
    }

    proto_item_set_len(pi, offset - start_offset);

    if (len > 0) {
        offset += len;
    }

    return offset;
}

/*
 * Dissect an Associated Wi-Fi 6 STA Status Report TLV
 */
static int
dissect_associated_wf6_sta_status_report(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    proto_tree *tid_list = NULL;
    proto_tree *tid_tree = NULL;
    proto_item *pi = NULL;
    guint8 tid_list_index = 0;
    guint start_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_assoc_wf6_sta_mac_addr, tvb, offset,
                        6, ENC_NA);
    offset += 6;
    len -= 6;

    proto_tree_add_item(tree, hf_ieee1905_assoc_wf6_sta_tid_count, tvb, offset,
                        1, ENC_NA);
    offset++;
    len--;

    tid_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                            ett_sta_wf6_status_report_tid_list, NULL,
                            "TID list");

    while (len >= 2) {
        guint8 tid = tvb_get_guint8(tvb, offset);

        tid_tree = proto_tree_add_subtree_format(tid_list, tvb,
                                offset, 2, ett_sta_wf6_status_report_tid_tree,
                                NULL, "TID %u (%0x)", tid_list_index, tid);

        proto_tree_add_item(tid_tree, hf_ieee1905_assoc_wf6_sta_tid,
                            tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tid_tree, hf_ieee1905_assoc_wf6_sta_queue_size,
                            tvb, offset, 1, ENC_NA);
        offset += 1;

        tid_list_index++;
        len -= 2;
    }

    proto_item_set_len(pi, offset - start_offset);

    if (len > 0) {
        offset += len;
    }

    return offset;
}

/*
 * Dissect an Associated STA extended link metrics TLV
 */
static int
dissect_associated_sta_extended_link_metrics(tvbuff_t *tvb,
        packet_info *pinfo _U_, proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 bssid_count = 0;

    proto_tree_add_item(tree, hf_ieee1905_assoc_sta_ext_link_metrics_mac_addr,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    bssid_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_assoc_sta_ext_link_metrics_count, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    if (bssid_count > 0) {
        proto_tree *bss_list = NULL, *bss_tree = NULL;
        proto_item *bli = NULL;
        guint saved_offset = offset;
        guint8 bssid_id = 0;

        bss_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                          ett_sta_extended_link_metrics_list,
                                          &bli, "BSS List");
        while (bssid_id < bssid_count) {
            bss_tree = proto_tree_add_subtree_format(bss_list, tvb, offset, 22,
                                              ett_sta_extended_link_metrics_tree,
                                              NULL, "BSS #%u", bssid_id);

            proto_tree_add_item(bss_tree,
                                hf_ieee1905_assoc_sta_extended_metrics_bssid,
                                tvb, offset, 6, ENC_NA);
            offset += 6;

            proto_tree_add_item(bss_tree,
                                hf_ieee1905_assoc_sta_extended_metrics_lddlr,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(bss_tree,
                                hf_ieee1905_assoc_sta_extended_metrics_ldulr,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(bss_tree,
                                hf_ieee1905_assoc_sta_extended_metrics_ur,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(bss_tree,
                                hf_ieee1905_assoc_sta_extended_metrics_tr,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            bssid_id++;
        }
        proto_item_set_len(bli, offset - saved_offset);
    }

    return offset;
}

/*
 * Dissect an Unassociated STA Link Metrics Query TLV
 */
static int
dissect_unassociated_sta_link_metrics_query(tvbuff_t *tvb,
        packet_info *pinfo _U_, proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 channel_count = 0;
    guint8 mac_count = 0;
    proto_tree *channel_list = NULL;
    proto_tree *sta_mac_list = NULL;
    proto_item *pi = NULL, *ci = NULL;
    guint saved_offset = 0, chan_saved_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_unassoc_sta_link_metrics_class,
                        tvb, offset, 1, ENC_NA);
    offset++;

    channel_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_unassoc_sta_link_channel_count,
                        tvb, offset, 1, ENC_NA);
    offset++;

    if (channel_count > 0) {
        chan_saved_offset = offset;

        channel_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                            ett_sta_link_metrics_query_channel_list, &ci,
                            "Channel list");

        while (channel_count > 0) {
            proto_tree_add_item(channel_list,
                            hf_ieee1905_unassoc_metrics_channel,
                            tvb, offset, 1, ENC_NA);
            offset++;
            channel_count--;

            mac_count = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(channel_list,
                                hf_ieee1905_unassoc_metrics_mac_count,
                                tvb, offset, 1, ENC_NA);
            offset += 1;

            saved_offset = offset;
            sta_mac_list = proto_tree_add_subtree(channel_list, tvb, offset, -1,
                                    ett_sta_link_link_mac_addr_list, &pi,
                                    "MAC address list");

            while (mac_count) {
                proto_tree_add_item(sta_mac_list,
                            hf_ieee1905_unassoc_link_metrics_query_mac,
                            tvb, offset, 6, ENC_NA);
                offset += 6;
                mac_count--;
            }

            proto_item_set_len(pi, offset - saved_offset);
        }
        proto_item_set_len(ci, offset - chan_saved_offset);
    }

    return offset;
}

/*
 * Dissect a Device Information Type TLV
 */
static int
dissect_device_information_type(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_item *pi = NULL;
    proto_tree *sub_tree = NULL;
    guint8 count;
    guint start_offset;

    proto_tree_add_item(tree, hf_ieee1905_al_mac_address_type, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_local_interface_count, tvb,
                        offset, 1, ENC_NA);
    offset++;
    start_offset = offset;

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
                            ett_device_information_list,
                            &pi, "Local interface list");

    offset = dissect_local_interface_list(tvb, pinfo, sub_tree,
                            offset, count);

    proto_item_set_len(pi, offset - start_offset);

    return offset;
}

/*
 * Dissect a Transmitter Link Metric TLV
 */
static int
dissect_transmitter_link_metric(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    guint remaining;

    proto_tree_add_item(tree, hf_ieee1905_responder_al_mac_addr, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_neighbor_al_mac_addr, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    remaining = len - 12;
    while (remaining) {
        proto_tree_add_item(tree, hf_ieee1905_receiving_al_mac_addr,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        proto_tree_add_item(tree, hf_ieee1905_neighbor_al_mac_addr,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        offset = dissect_media_type(tvb, pinfo, tree, offset);

        proto_tree_add_item(tree, hf_ieee1905_bridge_flag, tvb, offset,
                            1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_ieee1905_packet_errors, tvb, offset,
                            4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(tree, hf_ieee1905_transmitted_packets, tvb,
                            offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(tree, hf_ieee1905_mac_throughput_capacity, tvb,
                            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_ieee1905_link_availability, tvb,
                            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_ieee1905_phy_rate, tvb, offset,
                            2, ENC_BIG_ENDIAN);
        offset += 2;

        remaining -= 29;
    }

    return offset;
}

/*
 * Dissect a Receiver Link Metric TLV
 */
static int
dissect_receiver_link_metric(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    guint remaining;

    proto_tree_add_item(tree, hf_ieee1905_responder_al_mac_addr, tvb,
                        offset, 6, ENC_NA);
    offset += 6;
    proto_tree_add_item(tree, hf_ieee1905_neighbor_al_mac_addr, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    remaining = len - 12;
    while (remaining) {
        proto_tree_add_item(tree, hf_ieee1905_receiving_al_mac_addr,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        proto_tree_add_item(tree, hf_ieee1905_neighbor_al_mac_addr,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        offset = dissect_media_type(tvb, pinfo, tree, offset);

        proto_tree_add_item(tree, hf_ieee1905_packet_errors, tvb, offset,
                            4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(tree, hf_ieee1905_packets_received, tvb,
                            offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(tree, hf_ieee1905_rssi, tvb, offset, 1, ENC_NA);
        offset++;

        remaining -= 23;
    }
    return offset;
}

/*
 * Dissect an Associated STA Traffic Stats TLV
 */
static int
dissect_associated_sta_traffic_stats(tvbuff_t *tvb,
        packet_info *pinfo _U_, proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_assoc_sta_traffic_stats_mac_addr, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_assoc_sta_traffic_stats_bytes_sent,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_ieee1905_assoc_sta_traffic_stats_bytes_rcvd,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_ieee1905_assoc_sta_traffic_stats_packets_sent,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_ieee1905_assoc_sta_traffic_stats_packets_rcvd,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_ieee1905_assoc_sta_traffic_stats_tx_pkt_errs,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_ieee1905_assoc_sta_traffic_stats_rx_pkt_errs,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_ieee1905_assoc_sta_traffic_stats_retrans_count,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/*
 * Dissect an Error code TLV
 */
static int
dissect_error_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        guint offset, guint16 len _U_)
{
    proto_item *pi = NULL;
    guint8 error_code = tvb_get_guint8(tvb, offset);

    pi = proto_tree_add_item(tree, hf_ieee1905_error_code_value, tvb,
                        offset, 1, ENC_NA);
    proto_item_append_text(pi, ", %s",
                        val_to_str(error_code,
                                   ieee1905_error_code_vals,
                                   "Reserved"));
    offset++;

    proto_tree_add_item(tree, hf_ieee1905_error_code_mac_addr, tvb, offset,
                        6, ENC_NA);
    offset += 6;

    return offset;
}

/*
 * Dissect a Channel Scan Reporting Policy TLV
 */
static int * const  channel_scan_rep_policy_headers[] = {
    &hf_ieee1905_channel_scan_pol_report,
    &hf_ieee1905_channel_scan_pol_reserved,
    NULL
};

static const true_false_string report_independent_scans_tfs = {
    "Report Independent Channel Scans",
    "Do not report Independent Channel Scans unless requested"
};

static int
dissect_channel_scan_reporting_policy(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_channel_scan_rep_policy,
                           ett_channel_scan_rep_policy,
                           channel_scan_rep_policy_headers, ENC_NA);
    offset += 1;

    return offset;
}

/*
 * Dissect a Channel Scan Capabilities TLV
 */
static int * const channel_scan_capa_flags_headers[] = {
    &hf_ieee1905_channel_scan_capa_flags_on_boot_only,
    &hf_ieee1905_channel_scan_capa_flags_scan_impact,
    &hf_ieee1905_channel_scan_capa_flags_reserved,
    NULL
};

static const true_false_string channel_scan_capa_flags_on_boot_only_tfs = {
    "Agent can only perform scan on boot",
    "Agent can perform requested scans"
};

static const value_string channel_scan_capa_flags_impact_vals[] = {
    { 0, "No impact" },
    { 1, "Reduced number of spacial streams" },
    { 2, "Time slicing impairment" },
    { 3, "Radio unavailable for >= 2 seconds" },
    { 0, NULL }
};

static int
dissect_channel_scan_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree *radio_list = NULL;
    proto_item *rli = NULL;
    guint8 radio_count = 0, radio_num = 0;
    guint radio_list_start = 0;

    radio_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_channel_scan_capabilities_radio_num,
                        tvb, offset, 1, ENC_NA);
    offset += 1;

    radio_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                        ett_channel_scan_capa_radio_list,
                                        &rli, "Radio List");
    radio_list_start = offset;

    while (radio_num < radio_count) {
        proto_tree *radio_tree = NULL;
        proto_item *ri = NULL;
        proto_tree *oper_class_list = NULL;
        proto_item *cli = NULL;
        guint start_offset = offset;
        guint8 oper_class_count = 0, oper_class_num = 0;
        guint class_start_offset = 0;

        radio_tree = proto_tree_add_subtree_format(radio_list, tvb, offset,
                                        -1, ett_channel_scan_capa_radio,
                                        &ri, "Radio %u", radio_num);

        proto_tree_add_item(radio_tree, hf_ieee1905_channel_scan_capa_radio_id,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        proto_tree_add_bitmask(radio_tree, tvb, offset,
                               hf_ieee1905_channel_scan_capa_flags,
                               ett_channel_scan_capa_flags,
                               channel_scan_capa_flags_headers, ENC_NA);
        offset += 1;

        proto_tree_add_item(radio_tree,
                            hf_ieee1905_channel_scan_capa_min_scan_interval,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        oper_class_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(radio_tree, hf_ieee1905_channel_scan_capa_class_num,
                            tvb, offset, 1, ENC_NA);
        offset += 1;

        oper_class_list = proto_tree_add_subtree(radio_tree, tvb, offset, -1,
                                             ett_channel_scan_capa_class_list,
                                             &cli, "Operating Class List");

        class_start_offset = offset;
        while (oper_class_num < oper_class_count) {
            guint8 chan_num = 0;
            proto_tree *oper_class = NULL;
            proto_item *ci = NULL;
            gint oper_class_start_offset = offset;

            oper_class = proto_tree_add_subtree_format(oper_class_list, tvb,
                                                offset, -1,
                                                ett_channel_scan_capa_class,
                                                &ci, "Operating Class %d",
                                                oper_class_num);


            proto_tree_add_item(oper_class,
                                hf_ieee1905_channel_scan_capa_oper_class, tvb,
                                offset, 1, ENC_NA);
            offset += 1;

            chan_num = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(oper_class,
                                hf_ieee1905_channel_scan_capa_oper_class_chan_cnt,
                                tvb, offset, 1, ENC_NA);
            offset += 1;

            if (chan_num > 0) {
                /* Add them */
                proto_tree *channels = NULL;

                channels = proto_tree_add_subtree(oper_class, tvb, offset, chan_num,
                                       ett_channel_scan_capa_channels,
                                       NULL, "Channel List");

                while (chan_num > 0) {
                    proto_tree_add_item(channels, hf_ieee1905_channel_scan_capa_channel,
                                        tvb, offset, 1, ENC_NA);
                    offset += 1;
                    chan_num--;
                }

                offset += chan_num;
            }

            proto_item_set_len(ci, offset - oper_class_start_offset);
            oper_class_num++;
        }

        proto_item_set_len(cli, offset - class_start_offset);
        proto_item_set_len(ri, offset - start_offset);
        radio_num++;
    }

    proto_item_set_len(rli, offset - radio_list_start);

    return offset;
}

/*
 * Dissect a Channel Scan Request TLV
 */
static int * const channel_scan_request_flags_headers[] = {
    &hf_ieee1905_channel_scan_request_flags_fresh_scan,
    &hf_ieee1905_channel_scan_request_flags_reserved,
    NULL
};

static const true_false_string perform_fresh_scan_tfs = {
    "Perform a fresh scan",
    "Return results from previous scan"
};

static int
dissect_channel_scan_request(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree *radio_list = NULL;
    proto_item *rli = NULL;
    guint8 radio_count = 0, radio_num = 0;
    guint radio_list_start = 0;

    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_channel_scan_request_flags,
                           ett_channel_scan_request_flags,
                           channel_scan_request_flags_headers, ENC_NA);
    offset += 1;

    radio_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_channel_scan_request_radio_num,
                        tvb, offset, 1, ENC_NA);
    offset += 1;

    radio_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                        ett_channel_scan_request_radio_list,
                                        &rli, "Radio List");
    radio_list_start = offset;

    while (radio_num < radio_count) {
        proto_tree *radio_tree = NULL;
        proto_item *ri = NULL;
        proto_tree *oper_class_list = NULL;
        proto_item *cli = NULL;
        guint start_offset = offset;
        guint8 oper_class_count = 0, oper_class_num = 0;
        guint class_start_offset = 0;

        radio_tree = proto_tree_add_subtree_format(radio_list, tvb, offset,
                                        -1, ett_channel_scan_request_radio,
                                        &ri, "Radio %u", radio_num);

        proto_tree_add_item(radio_tree, hf_ieee1905_channel_scan_request_radio_id,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        oper_class_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(radio_tree, hf_ieee1905_channel_scan_request_class_num,
                            tvb, offset, 1, ENC_NA);
        offset += 1;

        if (oper_class_count > 0) {
            oper_class_list = proto_tree_add_subtree(radio_tree, tvb, offset, -1,
                                             ett_channel_scan_request_class_list,
                                             &cli, "Operating Class List");

            class_start_offset = offset;
            while (oper_class_num < oper_class_count) {
                guint8 chan_num = 0;
                proto_tree *oper_class = NULL;
                proto_item *ci = NULL;
                gint oper_class_start_offset = offset;

                oper_class = proto_tree_add_subtree_format(oper_class_list, tvb,
                                                offset, -1,
                                                ett_channel_scan_request_class,
                                                &ci, "Operating Class %d",
                                                oper_class_num);


                proto_tree_add_item(oper_class,
                                hf_ieee1905_channel_scan_request_oper_class, tvb,
                                offset, 1, ENC_NA);
                offset += 1;

                chan_num = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(oper_class,
                                hf_ieee1905_channel_scan_request_oper_class_chan_cnt,
                                tvb, offset, 1, ENC_NA);
                offset += 1;

                if (chan_num > 0) {
                    /* Add them */
                    proto_tree *channels = NULL;

                    channels = proto_tree_add_subtree(oper_class, tvb, offset, chan_num,
                                       ett_channel_scan_request_channels,
                                       NULL, "Channel List");

                    while (chan_num > 0) {
                        proto_tree_add_item(channels, hf_ieee1905_channel_scan_request_channel,
                                        tvb, offset, 1, ENC_NA);
                        offset += 1;
                        chan_num--;
                    }
                }

                proto_item_set_len(ci, offset - oper_class_start_offset);
                oper_class_num++;
            }
        }

        proto_item_set_len(cli, offset - class_start_offset);
        proto_item_set_len(ri, offset - start_offset);
        radio_num++;
    }

    proto_item_set_len(rli, offset - radio_list_start);

    return offset;
}

/*
 * Dissect a Channel Scan Result TLV
 */
static const range_string channel_scan_result_status_rvals[] = {
    { 0, 0, "Success" },
    { 1, 1, "Scan not supported on this operating class/channel on this radio" },
    { 2, 2, "Request too soon after last scan" },
    { 3, 3, "Radio too busy to perform scan" },
    { 4, 4, "Scan not completed" },
    { 5, 5, "Scan aborted" },
    { 6, 6, "Fresh scan not supported. Radio only supports on-boot scans" },
    { 7, 255, "Reserved" },
    { 0, 0, NULL }
};

static int * const channel_scan_result_neigh_flags[] = {
    &hf_ieee1905_channel_scan_result_load_element_present,
    &hf_ieee1905_channel_scan_result_neigh_reserved,
    NULL
};

static int * const channel_scan_result_flags[] = {
    &hf_ieee1905_channel_scan_result_scan_type,
    &hf_ieee1905_channel_scan_result_scan_flags_reserved,
    NULL
};

static const true_false_string channel_scan_result_type_tfs = {
    "Scan was an Active scan",
    "Scan was a Passive scan"
};

static int
dissect_channel_scan_result(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 status = 0;

    proto_tree_add_item(tree, hf_ieee1905_channel_scan_result_radio_id, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_channel_scan_result_oper_class, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_channel_scan_result_channel, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    status = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_channel_scan_result_status, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    if (status == 0) {
        guint8 timestamp_len = tvb_get_guint8(tvb, offset);
        guint8 ssid_len;
        guint16 neighbor_num = 0, neighbor_cnt = 0;
        proto_tree *neigh_list = NULL;
        proto_item *nli = NULL;
        guint saved_offset = 0;

        proto_tree_add_item(tree, hf_ieee1905_channel_scan_result_timestamp_len,
                            tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_ieee1905_channel_scan_result_timestamp_string,
                            tvb, offset, timestamp_len, ENC_NA|ENC_ASCII);
        offset += timestamp_len;

        proto_tree_add_item(tree, hf_ieee1905_channel_scan_result_utilization,
                            tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_ieee1905_channel_scan_result_noise, tvb,
                            offset, 1, ENC_NA);
        offset += 1;

        neighbor_num = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_ieee1905_channel_scan_result_neigh_num,
                            tvb, offset, 2, ENC_NA);
        offset += 2;

        if (neighbor_num > 0) {
            neigh_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                            ett_channel_scan_result_neigh_list,
                                            &nli, "Neighbor List");
            saved_offset = offset;

            while (neighbor_cnt < neighbor_num) {
                proto_tree *neigh_tree = NULL;
                proto_item *nti = NULL;
                guint neigh_saved_offset = offset;
                guint8 channel_bw_len = 0;
                guint8 flags = 0;

                neigh_tree = proto_tree_add_subtree_format(neigh_list, tvb,
                                        offset, -1,
                                        ett_channel_scan_result_neigh,
                                        &nti, "Neighbor %u", neighbor_cnt);

                proto_tree_add_item(neigh_tree,
                                hf_ieee1905_channel_scan_result_bssid, tvb,
                                offset, 6, ENC_NA);
                offset += 6;

                ssid_len = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(neigh_tree,
                                hf_ieee1905_channel_scan_result_ssid_len, tvb,
                                offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(neigh_tree, hf_ieee1905_channel_scan_result_ssid,
                                    tvb, offset, ssid_len, ENC_ASCII);
                offset += ssid_len;

                proto_tree_add_item(neigh_tree,
                                    hf_ieee1905_channel_scan_result_sig_level,
                                    tvb, offset, 1, ENC_NA);
                offset += 1;

                channel_bw_len = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(neigh_tree, hf_ieee1905_channel_scan_result_bw_len,
                                tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(neigh_tree, hf_ieee1905_channel_scan_result_bw,
                                tvb, offset, channel_bw_len, ENC_ASCII);
                offset += channel_bw_len;

                flags = tvb_get_guint8(tvb, offset);
                proto_tree_add_bitmask(neigh_tree, tvb, offset,
                                   hf_ieee1905_channel_scan_result_neigh_flags,
                                   ett_channel_scan_result_neigh_flags,
                                   channel_scan_result_neigh_flags, ENC_NA);
                offset += 1;

                if (flags & 0x80) {
                    proto_tree_add_item(neigh_tree, hf_ieee1905_channel_scan_result_util,
                                     tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(neigh_tree, hf_ieee1905_channel_scan_result_sta_count,
                                     tvb, offset, 2, ENC_NA);
                    offset += 2;
                }

                proto_item_set_len(nti, offset - neigh_saved_offset);
                neighbor_cnt++;
            }
        }

        proto_item_set_len(nli, offset - saved_offset);

        proto_tree_add_item(tree, hf_ieee1905_channel_scan_result_scan_duration,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_bitmask(tree, tvb, offset,
                               hf_ieee1905_channel_scan_result_flags,
                               ett_channel_scan_result_flags,
                               channel_scan_result_flags, ENC_NA);
        offset += 1;

    }

    return offset;
}

/*
 * Dissect a Timestamp TLV
 */
static int
dissect_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 timestamp_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ieee1905_timestamp_length, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_timestamp_string, tvb, offset,
                        timestamp_len, ENC_NA|ENC_ASCII);
    offset += timestamp_len;

    return offset;
}

/*
 * Dissect a 1905 Layer Security Capability TLV
 */
static const range_string onboarding_protocol_supported_rvals[] = {
    { 0, 0,   "1905 Device Provisioning Protocol" },
    { 1, 255, "Reserved" },
    { 0, 0,   NULL }
};

static const range_string message_integrity_algorithms_sup_rvals[] = {
    { 0, 0,   "HMAC-SHAR256" },
    { 1, 255, "Reserved" },
    { 0, 0,   NULL }
};

static const range_string message_encryption_algorithms_sup_rvals[] = {
    { 0, 0,   "AES-SIV" },
    { 1, 255, "Reserved" },
    { 0, 0,   NULL }
};

static int
dissect_1905_layer_security_capability(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_1905_layer_sec_capa_onboarding, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_1905_layer_sec_capa_mic_sup, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_1905_layer_sec_capa_enc_alg_sup, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

/*
 * Dissect an AP Wi-Fi 6 Capabilities TLV
 */
static int * const ap_wf6_role_flags[] = {
    &hf_ieee1905_ap_wf6_capa_agents_role,
    &hf_ieee1905_ap_wf6_capa_he_160_support,
    &hf_ieee1905_ap_wf6_capa_he_80p80_support,
    &hf_ieee1905_ap_wf6_capa_reserved,
    NULL
};

static int * const ap_wf6_supported_flags[] = {
    &hf_ieee1905_ap_wf6_su_beamformer,
    &hf_ieee1905_ap_wf6_su_beamformee,
    &hf_ieee1905_ap_wf6_mu_beamformer_status,
    &hf_ieee1905_ap_wf6_beamformee_sts_le_80mhz,
    &hf_ieee1905_ap_wf6_beamformee_sts_gt_80mhz,
    &hf_ieee1905_ap_wf6_ul_mu_mimo,
    &hf_ieee1905_ap_wf6_ul_ofdma,
    &hf_ieee1905_ap_wf6_dl_ofdma,
    NULL
};

static int * const ap_wf6_mimo_flags[] = {
    &hf_ieee1905_ap_wf6_max_ap_dl_mu_mimo_tx,
    &hf_ieee1905_ap_wf6_max_ap_ul_mu_mimi_rx,
    NULL
};

static int * const ap_wf6_gen_flags[] = {
    &hf_ieee1905_ap_wf6_gen_rts,
    &hf_ieee1905_ap_wf6_gen_mu_rts,
    &hf_ieee1905_ap_wf6_gen_multi_bssid,
    &hf_ieee1905_ap_wf6_gen_mu_edca,
    &hf_ieee1905_ap_wf6_gen_twt_requester,
    &hf_ieee1905_ap_wf6_gen_twt_responder,
    &hf_ieee1905_ap_wf6_gen_reserved,
    NULL
};

static const value_string ap_wf6_agent_role_vals[] = {
    { 0, "Wi-Fi 6 support info for the AP role" },
    { 1, "Wi-Fi 6 support info for the non-AP STA role" },
    { 0, NULL }
};

static int
dissect_ap_wf6_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 role_count, role_id = 0;
    proto_tree *role_list = NULL;
    proto_item *rli = NULL;
    guint start_list_offset;

    proto_tree_add_item(tree, hf_ieee1905_ap_wf6_capa_radio_id, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    role_count = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ieee1905_ap_wf6_role_count, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    start_list_offset = offset;
    role_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                       ett_ap_wf6_role_list,
                                       &rli, "Role List");

    while (role_id < role_count) {
        proto_tree *role_tree;
        proto_item *rti = NULL;
        guint start_tree_offset = offset;
        proto_tree *mcs_set = NULL;

        role_tree = proto_tree_add_subtree_format(role_list, tvb, offset, -1,
                                                  ett_ap_wf6_role_tree,
                                                  &rti, "Role %u", role_id);

        guint8 role_flags = tvb_get_guint8(tvb, offset);

        proto_tree_add_bitmask(role_tree, tvb, offset,
                               hf_ieee1905_ap_wf6_agent_role_flags,
                               ett_ap_wf6_agent_role_flags, ap_wf6_role_flags,
                               ENC_NA);
        offset += 1;

        mcs_set = proto_tree_add_subtree(role_tree, tvb, offset, 4,
                        ett_ap_he_mcs_set, NULL,
                        "Supported HE-MCS and NSS Set <= 80 MHz");

        proto_tree_add_bitmask_with_flags(mcs_set, tvb, offset,
                        hf_ieee1905_ap_he_cap_tx_mcs_le_80_mhz,
                        ett_ieee1905_ap_he_rx_mcs_set,
                        tx_he_mcs_map_headers, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        offset += 2;

        proto_tree_add_bitmask_with_flags(mcs_set, tvb, offset,
                        hf_ieee1905_ap_he_cap_rx_mcs_le_80_mhz,
                        ett_ieee1905_ap_he_rx_mcs_set,
                        rx_he_mcs_map_headers, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        offset += 2;


        if (role_flags & 0x20) { /* HE MCS & NSS for 160MHz */
            mcs_set = proto_tree_add_subtree(role_tree, tvb, offset, 4,
                        ett_ap_he_mcs_set, NULL,
                        "Supported HE-MCS and NSS Set 160 MHz");

            proto_tree_add_bitmask_with_flags(mcs_set, tvb, offset,
                        hf_ieee1905_ap_he_cap_tx_mcs_160_mhz,
                        ett_ieee1905_ap_he_rx_mcs_set,
                        tx_he_mcs_map_headers, ENC_BIG_ENDIAN, BMT_NO_APPEND);
            offset += 2;

            proto_tree_add_bitmask_with_flags(mcs_set, tvb, offset,
                        hf_ieee1905_ap_he_cap_rx_mcs_160_mhz,
                        ett_ieee1905_ap_he_rx_mcs_set,
                        rx_he_mcs_map_headers, ENC_BIG_ENDIAN, BMT_NO_APPEND);
            offset += 2;
        }

        if (role_flags & 0x10) { /* HE MCS & NSS for 80+80MHz */
            mcs_set = proto_tree_add_subtree(role_tree, tvb, offset, 4,
                        ett_ap_he_mcs_set, NULL,
                        "Supported HE-MCS and NSS Set 80+80 MHz");

            proto_tree_add_bitmask_with_flags(mcs_set, tvb, offset,
                        hf_ieee1905_ap_he_cap_tx_mcs_80p80_mhz,
                        ett_ieee1905_ap_he_rx_mcs_set,
                        tx_he_mcs_map_headers, ENC_BIG_ENDIAN, BMT_NO_APPEND);
            offset += 2;

            proto_tree_add_bitmask_with_flags(mcs_set, tvb, offset,
                        hf_ieee1905_ap_he_cap_rx_mcs_80p80_mhz,
                        ett_ieee1905_ap_he_rx_mcs_set,
                        rx_he_mcs_map_headers, ENC_BIG_ENDIAN, BMT_NO_APPEND);
            offset += 2;
        }

        proto_tree_add_bitmask(role_tree, tvb, offset,
                               hf_ieee1905_ap_wf6_he_supported_flags,
                               ett_ap_wf6_supported_flags,
                               ap_wf6_supported_flags, ENC_NA);
        offset += 1;

        proto_tree_add_bitmask(role_tree, tvb, offset,
                               hf_ieee1905_ap_wf6_mimo_max_flags,
                               ett_ap_wf6_mimo_max_flags, ap_wf6_mimo_flags,
                               ENC_NA);
        offset += 1;

        proto_tree_add_item(role_tree, hf_ieee1905_ap_wf6_dl_ofdma_max_tx, tvb,
                            offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(role_tree, hf_ieee1905_ap_wf6_ul_ofdma_max_rx, tvb,
                            offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_bitmask(role_tree, tvb, offset,
                               hf_ieee1905_ap_wf6_gen_flags,
                               ett_ap_wf6_gen_flags, ap_wf6_gen_flags,
                               ENC_NA);
        offset += 1;

        proto_item_set_len(rti, offset - start_tree_offset);
        role_id++;
    }

    proto_item_set_len(rli, offset - start_list_offset);
    return offset;
}

static int
dissect_agent_list(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_agent_list_bytes, tvb, offset,
                        len, ENC_NA);
    offset += len;

    return offset;
}

static const value_string loop_prev_mech_vals[] = {
    { 0, "No Multi-AP loop prevention mechanism" },
    { 1, "Multi-AP L2 Multicast Loop Detection message-based" },
    { 2, "Reserved" },
    { 3, "Reserved" },
    { 0, NULL }
};

static const value_string pref_backhaul_intf_vals[] = {
    { 0, "Multi-AP Logical Ethernet Interface" },
    { 1, "Wi-Fi bSTA" },
    { 2, "Reserved" },
    { 3, "Reserved" },
    { 0, NULL }
};

static int * const loop_prevention_mech_headers[] = {
    &hf_ieee1905_loop_prevention_mechanism,
    &hf_ieee1905_loop_prevention_preferred_backhaul_intf,
    &hf_ieee1905_loop_prevention_reserved,
    NULL
};

static int
dissect_loop_prevention_mechanism_setting(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_loop_prevention_mech_setting,
                           ett_loop_prevention_mech,
                           loop_prevention_mech_headers, ENC_NA);
    offset += 1;

    return offset;
}

static int
dissect_loop_detection_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_loop_detection_sequence_number,
                        tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

/*
 * Dissect a Group Integrity Key TLV
 */
static const range_string group_integrity_key_mic_alg_rvals[] = {
    { 0, 0,   "HMAC-SHA256" },
    { 1, 255, "Reserved" },
    { 0, 0,   NULL }
};

static int
dissect_group_integrity_key(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 key_len = 0;

    proto_tree_add_item(tree, hf_ieee1905_group_integrity_key_id, tvb, offset,
                        1, ENC_NA);
    offset += 1;

    key_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_group_integrity_key_len, tvb, offset,
                        1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_group_integrity_key_bytes, tvb,
                        offset, key_len, ENC_NA);
    offset += key_len;

    proto_tree_add_item(tree, hf_ieee1905_group_integrity_key_mic_alg, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

/*
 * Dissect a MIC TLV
 */
static int * const gtk_key_id_headers[] = {
    &hf_ieee1905_1905_gtk_key_id,
    &hf_ieee1905_mic_version,
    &hf_ieee1905_mic_reserved,
    NULL
};

static const value_string mic_version_vals[] = {
    { 0, "Version 1" },
    { 1, "Reserved" },
    { 2, "Reserved" },
    { 3, "Reserved" },
    { 0, NULL }
};

static int
dissect_mic(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint16 mic_len = 0;

    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_mic_group_temporal_key_id,
                           ett_mic_group_temporal_key,
                           gtk_key_id_headers, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_mic_integrity_transmission_counter,
                        tvb, offset, 6, ENC_BIG_ENDIAN);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_mic_source_la_mac_id, tvb, offset, 6,
                        ENC_NA);
    offset += 6;

    mic_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_mic_length, tvb, offset, 2, ENC_NA);
    offset += 2;

    proto_tree_add_item(tree, hf_ieee1905_mic_bytes, tvb, offset, mic_len,
                        ENC_NA);
    offset += mic_len;

    return offset;
}

/*
 * Dissect an Encrypted TLV
 */
static int
dissect_encrypted(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint16 enc_len = 0;

    proto_tree_add_item(tree, hf_ieee1905_encrypted_enc_transmission_count,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_encrypted_source_la_mac_id, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_encrypted_dest_al_mac_addr, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    enc_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_encrypted_enc_output_field_len, tvb,
                        offset, 2, ENC_NA);
    offset += 2;

    proto_tree_add_item(tree, hf_ieee1905_encrypted_enc_output_field, tvb,
                        offset, enc_len, ENC_NA);
    offset += enc_len;

    return offset;
}

/*
 * Dissect a CAC Request TLV
 */
static int * const cac_request_method_flags[] = {
    &hf_ieee1905_cac_request_method,
    &hf_ieee1905_cac_request_completion_action,
    &hf_ieee1905_cac_request_completion_unsuccess,
    &hf_ieee1905_cac_request_reserved,
    NULL
};

static const value_string cac_request_method_vals[] = {
    { 0, "Continuous CAC" },
    { 1, "Continuous with dedicated radio" },
    { 2, "MIMO dimension reduced" },
    { 3, "Time sliced CAC" },
    { 4, "Reserved" },
    { 5, "Reserved" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL }
};

static const range_string cac_completion_action_vals[] = {
    { 0, 0,   "Remain on channel and continue to monitor for radar" },
    { 1, 1,   "Return to previous state" },
    { 2, 255, "Reserved" },
    { 0, 0,   NULL }
};

static int
dissect_cac_request(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint radio_count = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ieee1905_cac_request_radio_count, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    if (radio_count > 0) {
        proto_tree *radio_list = NULL;
        guint8 radio_num = 0;

        radio_list = proto_tree_add_subtree(tree, tvb, offset, radio_count * 9,
                                        ett_cac_request_radio_list,
                                        NULL, "Radio List");

        while (radio_num < radio_count) {
            proto_tree *radio = NULL;

            radio = proto_tree_add_subtree_format(radio_list, tvb, offset, 9,
                                           ett_cac_request_radio, NULL,
                                           "Radio %u", radio_num);

            proto_tree_add_item(radio, hf_ieee1905_cac_request_radio_id, tvb,
                                offset, 6, ENC_NA);
            offset += 6;

            proto_tree_add_item(radio, hf_ieee1905_cac_request_op_class, tvb,
                                offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(radio, hf_ieee1905_cac_request_channel, tvb,
                                offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(radio, tvb, offset,
                           hf_ieee1905_cac_request_flags,
                           ett_cac_request_flags,
                           cac_request_method_flags, ENC_NA);
            offset += 1;

            radio_num += 1;
        }


    }

    return offset;
}

/*
 * Dissect a CAC Termination TLV
 */
static int
dissect_cac_termination(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 radio_count = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ieee1905_cac_termination_radio_count, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    if (radio_count > 0) {
        proto_tree *radio_list = NULL;
        guint8 radio_num = 0;

        radio_list = proto_tree_add_subtree(tree, tvb, offset, radio_count * 9,
                                        ett_cac_terminate_radio_list,
                                        NULL, "Radio list");

        while (radio_num < radio_count) {
            proto_tree *radio = NULL;

            radio = proto_tree_add_subtree_format(radio_list, tvb, offset, 9,
                                           ett_cac_terminate_radio, NULL,
                                           "Radio %u", radio_num);

            proto_tree_add_item(radio, hf_ieee1905_cac_terminate_radio_id, tvb,
                                offset, 6, ENC_NA);
            offset += 6;

            proto_tree_add_item(radio, hf_ieee1905_cac_terminate_op_class, tvb,
                                offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(radio, hf_ieee1905_cac_terminate_channel, tvb,
                                offset, 1, ENC_NA);
            offset += 1;

            radio_num += 1;
        }
    }

    return offset;
}

/*
 * Dissect a CAC Completion Report TLV
 */
static const range_string cac_completion_status_rvals[] = {
    { 0, 0,   "Successful" },
    { 1, 1,   "Radar detected" },
    { 2, 2,   "CAC not supported as requested" },
    { 3, 3,   "Radio too busy to perform CAC" },
    { 4, 4,   "Request was considered non conformant to regulations in country of operation" },
    { 5, 5,   "Other error" },
    { 6, 255, "Reserved" },
    { 0, 0, NULL },
};

static int
dissect_cac_completion_report(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 radio_count = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ieee1905_cac_completion_rep_radio_count, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    if (radio_count > 0) {
        proto_tree *radio_list = NULL;
        guint8 radio_num = 0;
        guint8 radar_count = 0;

        radio_list = proto_tree_add_subtree(tree, tvb, offset, radio_count * 9,
                                        ett_cac_completion_radio_list,
                                        NULL, "Radio list");

        while (radio_num < radio_count) {
            proto_tree *radio = NULL;

            radio = proto_tree_add_subtree_format(radio_list, tvb, offset, 9,
                                           ett_cac_completion_radio, NULL,
                                           "Radio %u", radio_num);

            proto_tree_add_item(radio, hf_ieee1905_cac_completion_radio_id, tvb,
                                offset, 6, ENC_NA);
            offset += 6;

            proto_tree_add_item(radio, hf_ieee1905_cac_completion_op_class, tvb,
                                offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(radio, hf_ieee1905_cac_completion_channel, tvb,
                                offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(radio, hf_ieee1905_cac_completion_status, tvb,
                                offset, 1, ENC_NA);
            offset += 1;

            radar_count = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(radio, hf_ieee1905_cac_completion_radar_count,
                                tvb, offset, 1, ENC_NA);
            offset += 1;

            if (radar_count > 0) {
                proto_tree *radar_det_list = NULL;
                guint8 radar_num = 0;

                radar_det_list = proto_tree_add_subtree(radio, tvb, offset,
                                                radar_count * 2,
                                                ett_cac_completion_radar_list,
                                                NULL, "Radar detection list");
                while (radar_num < radar_count) {
                    proto_tree *radar = NULL;

                    radar = proto_tree_add_subtree_format(radar_det_list, tvb,
                                                offset, 2,
                                                ett_cac_completion_radar, NULL,
                                                "Class/Channel pair %u",
                                                radar_num);

                    proto_tree_add_item(radar,
                                        hf_ieee1905_cac_comp_radar_op_class,
                                        tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(radar,
                                        hf_ieee1905_cac_comp_radar_channel,
                                        tvb, offset, 1, ENC_NA);
                    offset += 1;

                    radar_num += 1;
                }
            }

            radio_num += 1;
        }
    }

    return offset;
}

/*
 * Dissect a CAC Status Request TLV. Deprecated.
 */
static int
dissect_cac_status_request(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_tlv_data, tvb, offset, len, ENC_NA);
    expert_add_info(pinfo, tree, &ei_ieee1905_deprecated_tlv);
    offset += len;

    return offset;
}

/*
 * Dissect a CAC Status Report TLV
 */
static int
dissect_cac_status_report(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 channel_count = tvb_get_guint8(tvb, offset);
    guint8 non_occupancy_count = 0;
    guint8 active_cac_count = 0;

    proto_tree_add_item(tree, hf_ieee1905_cac_status_rpt_active_chan, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    if (channel_count > 0) {
        guint8 channel_num = 0;
        proto_tree *active_chan_list = NULL;

        active_chan_list = proto_tree_add_subtree(tree, tvb, offset,
                                        4 * channel_count,
                                        ett_cac_status_rpt_avail_list,
                                        NULL, "Available Channels List");
        while (channel_num < channel_count) {
            proto_tree *active_chan_tree = NULL;

            active_chan_tree = proto_tree_add_subtree_format(active_chan_list,
                                        tvb, offset, 4,
                                        ett_cac_status_rpt_avail_chan,
                                        NULL, "Available Channel %u",
                                        channel_num);

            proto_tree_add_item(active_chan_tree,
                                hf_ieee1905_cac_status_rpt_avail_op_class,
                                tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(active_chan_tree,
                                hf_ieee1905_cac_status_rpt_avail_channel,
                                tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(active_chan_tree,
                                hf_ieee1905_cac_status_rpt_avail_minutes,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            channel_num += 1;
        }
    }

    non_occupancy_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_cac_status_rpt_non_occ_cnt, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    if (non_occupancy_count > 0) {
        guint8 non_occupancy_num = 0;
        proto_tree *non_occupancy_list = NULL;

        non_occupancy_list = proto_tree_add_subtree(tree, tvb, offset,
                                        4 * non_occupancy_count,
                                        ett_cac_status_rpt_non_occupy_list,
                                        NULL, "Non-occupancy List");
        while (non_occupancy_num < non_occupancy_count) {
            proto_tree *non_occupancy_tree = NULL;

            non_occupancy_tree = proto_tree_add_subtree_format(
                                        non_occupancy_list, tvb, offset, 4,
                                        ett_cac_status_rpt_unocc_chan,
                                        NULL, "Unoccupied Channel %u",
                                        non_occupancy_num);

            proto_tree_add_item(non_occupancy_tree,
                                hf_ieee1905_cac_status_rpt_non_occ_op_class,
                                tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(non_occupancy_tree,
                                hf_ieee1905_cac_status_rpt_non_occ_channel,
                                tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(non_occupancy_tree,
                                hf_ieee1905_cac_status_rpt_non_occ_seconds,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            non_occupancy_num += 1;
        }
    }

    active_cac_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_cac_status_rpt_active_cac_cnt, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    if (active_cac_count > 0) {
        guint8 active_cac_num = 0;
        proto_tree *active_cac_list = NULL;

        active_cac_list = proto_tree_add_subtree(tree, tvb, offset,
                                        5 * active_cac_count,
                                        ett_cac_status_rpt_active_cac_list,
                                        NULL, "Active CAC List");
        while (active_cac_num < active_cac_count) {
            proto_tree *active_cac_tree = NULL;

            active_cac_tree = proto_tree_add_subtree_format(active_cac_list,
                                        tvb, offset, 5,
                                        ett_cac_status_rpt_active_cac_tree,
                                        NULL, "Active CAC %u",
                                        active_cac_num);

            proto_tree_add_item(active_cac_tree,
                                hf_ieee1905_cac_status_rpt_active_cac_op_class,
                                tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(active_cac_tree,
                                hf_ieee1905_cac_status_rpt_active_cac_channel,
                                tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(active_cac_tree,
                                hf_ieee1905_cac_status_rpt_active_cac_seconds,
                                tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;

            active_cac_num += 1;
        }
    }

    return offset;
}

/*
 * Dissect a CAC Capabilities TLV
 */
static const range_string cac_mode_supported_rvals[] = {
    { 0, 0,   "Continuous CAC" },
    { 1, 1,   "Continuous with dedicated radio" },
    { 2, 2,   "MIMO dimension reduced" },
    { 3, 3,   "Time sliced CAC" },
    { 4, 255, "Reserved" },
    { 0, 0, NULL }
};

static int
dissect_cac_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 cac_radios = 0;

    proto_tree_add_item(tree, hf_ieee1905_cac_capa_country_code, tvb, offset,
                        2, ENC_NA|ENC_ASCII);
    offset += 2;

    cac_radios = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_cac_capa_radio_cnt, tvb, offset,
                        1, ENC_NA);
    offset += 1;

    if (cac_radios > 0) {
        guint8 radio_num = 0;
        proto_tree *radio_list = NULL;
        proto_item *rli = NULL;
        guint start_offset = offset;

        radio_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                        ett_cac_capabilities_radio_list,
                                        &rli, "Radio List");
        while (radio_num < cac_radios) {
            proto_tree *radio_tree = NULL;
            guint8 cac_types = 0;

            radio_tree = proto_tree_add_subtree_format(radio_list,
                                        tvb, offset, 5,
                                        ett_cac_capabilities_radio_tree,
                                        NULL, "Radio %u",
                                        radio_num);

            proto_tree_add_item(radio_tree,
                                hf_ieee1905_cac_capabilities_radio_id, tvb,
                                offset, 6, ENC_NA);
            offset += 6;

            cac_types = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(radio_tree,
                                hf_ieee1905_cac_capabilities_types_num,
                                tvb, offset, 1, ENC_NA);
            offset += 1;

            if (cac_types > 0) {
                guint8 cac_num = 0;
                proto_tree *cac_type_list = NULL;
                proto_item *rci = NULL;
                guint cac_type_start = offset;
                guint8 cac_classes = 0;

                cac_type_list = proto_tree_add_subtree(radio_tree, tvb, offset,
                                        -1, ett_cac_capabilities_type_list,
                                        &rci, "CAC Type List");
                while (cac_num < cac_types) {
                    proto_tree *cac_type_tree = NULL;
                    proto_item *cti = NULL;

                    cac_type_tree = proto_tree_add_subtree_format(cac_type_list,
                                        tvb, offset,
                                        -1, ett_cac_capabilities_type_tree,
                                        &cti, "CAC Type %u", cac_num);

                    proto_tree_add_item(cac_type_tree,
                                hf_ieee1905_cac_capabilities_cac_mode, tvb,
                                offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(cac_type_tree,
                                hf_ieee1905_cac_capabilities_cac_seconds, tvb,
                                offset, 3, ENC_BIG_ENDIAN);
                    offset += 3;

                    cac_classes = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(cac_type_tree,
                                hf_ieee1905_cac_capabilities_op_class_num, tvb,
                                offset, 1, ENC_NA);
                    offset += 1;

                    if (cac_classes > 0) {
                        proto_tree *cac_class_list = NULL;
                        guint8 cac_class_num = 0;
                        proto_item *cli = NULL;

                        cac_class_list = proto_tree_add_subtree(cac_type_tree,
                                tvb, offset, -1,
                                ett_cac_capabilities_class_list, &cli,
                                "Class List");

                        while (cac_class_num < cac_classes) {
                            guint8 channel_cnt = 0;
                            proto_tree *cac_class_tree = NULL;
                            guint cac_class_start = offset;

                            cac_class_tree = proto_tree_add_subtree_format(
                                    cac_class_list, tvb, offset, -1,
                                    ett_cac_capabilities_class_tree, &cti,
                                    "Operating Class %u", cac_class_num);

                            proto_tree_add_item(cac_class_tree,
                                    hf_ieee1905_cac_capabilities_op_class, tvb,
                                    offset, 1, ENC_NA);
                            offset += 1;

                            channel_cnt = tvb_get_guint8(tvb, offset);
                            proto_tree_add_item(cac_class_tree,
                                    hf_ieee1905_cac_capabilities_channel_cnt,
                                    tvb, offset, 1, ENC_NA);
                            offset += 1;

                            if (channel_cnt > 0) {
                                proto_tree *channel_list = NULL;

                                channel_list = proto_tree_add_subtree(
                                            cac_class_tree, tvb, offset,
                                            channel_cnt,
                                            ett_cac_capabilities_channel_list,
                                            NULL, "Channel List");

                                while (channel_cnt > 0) {
                                    proto_tree_add_item(channel_list,
                                            hf_ieee1905_cac_capabillity_channel,
                                            tvb, offset, 1, ENC_NA);
                                    channel_cnt -= 1;
                                    offset += 1;
                                }
                            }

                            proto_item_set_len(cti, offset - cac_class_start);
                            cac_class_num += 1;
                        }
                    }
                    cac_num += 1;
                }
                proto_item_set_len(rci, offset - cac_type_start);
            }

            radio_num += 1;
        }
        proto_item_set_len(rli, offset - start_offset);
    }

    return offset;
}

/*
 * Dissect a Multi-AP Version TLV
 */

static const range_string multi_ap_version_rvals[] = {
    { 0, 0,   "Reserved" },
    { 1, 1,   "Multi-AP Profile 1" },
    { 2, 2,   "Multi-AP Profile 2" },
    { 3, 3,   "Multi-AP Profile 3" },
    { 4, 255, "Reserved" },
    { 0, 0, NULL }
};

static int
dissect_multi_ap_version(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_multi_ap_version, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    return offset;
}

/*
 * Dissect an R2 AP Capabilities TLV
 */
static const value_string byte_counter_units_vals[] = {
    { 0, "bytes" },
    { 1, "kibibytes (KiB)" },
    { 2, "mebibytes (MiB)" },
    { 3, "reserved" },
    { 0, NULL }
};

static int* const r2_ap_capa_flags[] = {
    &hf_ieee1905_byte_counter_units,
    &hf_ieee1905_basic_service_prio_flag,
    &hf_ieee1905_enhanced_service_prio_flag,
    &hf_ieee1905_r2_ap_capa_flags_reserved,
    NULL
};

static int
dissect_r2_ap_capability(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_max_total_serv_prio_rules, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_r2_ap_capa_reserved, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_r2_ap_capa_flags,
                           ett_r2_ap_capa_flags,
                           r2_ap_capa_flags, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_max_vid_count, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    return offset;
}

/*
 * Dissect a Service Prioritization Rule TLV
 */
static int * const default_802_1q_settings_flags[] = {
    &hf_ieee1905_default_802_1q_settings_default_pcp,
    &hf_ieee1905_default_802_1q_settings_reserved,
    NULL
};

static int
dissect_default_802_1q_settings(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_default_802_1q_settings_primary_vlan, tvb,
                        offset, 2, ENC_NA);
    offset += 2;

    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_default_802_1q_settings_flags,
                           ett_default_802_1q_settings_flags,
                           default_802_1q_settings_flags, ENC_NA);
    offset += 1;

    return offset;
}

/*
 * Dissect a Traffic Separation Policy TLV
 */
static int
dissect_traffic_separation_policy(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 ssid_cnt = tvb_get_guint8(tvb, offset);
    guint8 ssid_num = 0;
    proto_tree *ssid_list = NULL;
    proto_item *sli = NULL;
    guint saved_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_traffic_separation_policy_num_ssids,
                        tvb, offset, 1, ENC_NA);
    offset += 1;

    if (ssid_cnt > 0) {
        ssid_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                        ett_traffic_separation_ssid_list,
                                        &sli, "SSID List");
        saved_offset = offset;
    }

    while (ssid_num < ssid_cnt) {
        proto_tree *ssid_tree = NULL;
        proto_item *si = NULL;
        guint8 ssid_len = tvb_get_guint8(tvb, offset);
        guint start_offset = offset;

        ssid_tree = proto_tree_add_subtree_format(ssid_list, tvb, offset, -1,
                                                  ett_traffic_separation_ssid,
                                                  &si, "SSID %u", ssid_num);

        proto_tree_add_item(ssid_tree,
                            hf_ieee1905_traffic_separation_policy_ssid_len,
                            tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(ssid_tree,
                            hf_ieee1905_traffic_separation_policy_ssid,
                            tvb, offset, ssid_len, ENC_ASCII);
        offset += ssid_len;

        proto_tree_add_item(ssid_tree,
                            hf_ieee1905_traffic_separation_policy_vlanid, tvb,
                            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_item_set_len(si, offset - start_offset);
        ssid_num++;
    }

    if (ssid_cnt > 0) {
        proto_item_set_len(sli, offset - saved_offset);
    }

    return offset;
}

/*
 * Dissect a BSS Configuration Report
 */
static int * const bss_config_report_flags[] = {
    &hf_ieee1905_bss_config_report_backhaul_bss,
    &hf_ieee1905_bss_config_report_fronthaul_bss,
    &hf_ieee1905_bss_config_report_r1_disallowed_status,
    &hf_ieee1905_bss_config_report_r2_disallowed_status,
    &hf_ieee1905_bss_config_report_multiple_bssid_set,
    &hf_ieee1905_bss_config_report_transmitted_bssid,
    &hf_ieee1905_bss_config_report_reserved,
    NULL
};

static const true_false_string tfs_allowed_disallowed = {
    "Allowed",
    "Disallowed"
};

static const true_false_string tfs_transmitted_non_transmitted = {
    "Transmitted",
    "Non-transmitted"
};

static int
dissect_bss_configuration_report(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 radio_count = tvb_get_guint8(tvb, offset);
    guint8 radio_id = 0;
    guint start_offset;
    proto_tree *radio_list = NULL;
    proto_item *rti = NULL;

    proto_tree_add_item(tree, hf_ieee1905_bss_config_report_radio_count, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    start_offset = offset;

    radio_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                        ett_bss_config_report_list, &rti,
                                        "BSS Configuration Radio List");
    while (radio_id < radio_count) {
        proto_tree *radio_tree = NULL;
        proto_tree *bss_list = NULL;
        proto_item *rli = NULL, *bli = NULL;
        guint radio_saved_offset = offset, bss_start_offset = 0;
        guint8 bss_count, bss_id = 0;

        radio_tree = proto_tree_add_subtree_format(radio_list, tvb, offset, -1,
                                                   ett_bss_config_report_tree,
                                                   &rli, "Radio %d", radio_id);

        proto_tree_add_item(radio_tree, hf_ieee1905_bss_config_report_radio_id,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        bss_count = tvb_get_guint8(tvb, offset);

        proto_tree_add_item(radio_tree, hf_ieee1905_bss_config_report_bss_cnt,
                            tvb, offset, 1, ENC_NA);
        offset += 1;

        radio_id++;  /* Increment this before we continue */

        /* If no BSSes on the radio, skip it. Spec says so. */
        if (bss_count == 0) {
                proto_item_set_len(rli, offset - radio_saved_offset);
                continue;
        }

        bss_list = proto_tree_add_subtree(radio_tree, tvb, offset, -1,
                                          ett_bss_config_report_bss_list, &bli,
                                          "BSS List");
        bss_start_offset = offset;

        while (bss_id < bss_count) {
                proto_tree *bss_tree = NULL;
                proto_item *bti = NULL;
                guint bss_item_start = offset;
                guint8 ssid_len = 0;

                bss_tree = proto_tree_add_subtree_format(bss_list, tvb, offset,
                                          -1, ett_bss_config_report_bss_tree,
                                          &bti, "BSS %d", bss_id);

                proto_tree_add_item(bss_tree, hs_ieee1902_bss_config_report_mac,
                                    tvb, offset, 6, ENC_NA);
                offset += 6;

                proto_tree_add_bitmask(bss_tree, tvb, offset,
                                       hf_ieee1905_bss_config_report_flags,
                                       ett_bss_config_report_flags,
                                       bss_config_report_flags, ENC_NA);
                offset += 1;

                proto_tree_add_item(bss_tree, hf_ieee1905_bss_config_report_res,
                                    tvb, offset, 1, ENC_NA);
                offset += 1;

                ssid_len = tvb_get_guint8(tvb, offset);

                proto_tree_add_item(bss_tree,
                                    hf_ieee1902_bss_config_report_ssid_len,
                                    tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(bss_tree,
                            hf_ieee1905_bss_config_report_ssid,
                            tvb, offset, ssid_len, ENC_ASCII);
                offset += ssid_len;

                proto_item_set_len(bti, offset - bss_item_start);

                bss_id++;
        }

        proto_item_set_len(bli, offset - bss_start_offset);
        proto_item_set_len(rli, offset - radio_saved_offset);
    }

    proto_item_set_len(rti, offset - start_offset);

    return offset;
}

/*
 * Dissect a Packet Filtering Policy TLV
 */
static int
dissect_packet_filtering_policy(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 bssid_num = tvb_get_guint8(tvb, offset);
    guint8 bssid_cnt = 0;
    proto_tree *bssid_list = NULL;
    proto_item *bli = NULL;
    guint start_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_packet_filtering_policy_bssid_num,
                        tvb, offset, 1, ENC_NA);
    offset += 1;

    if (bssid_num == 0) {
        /* Check if there is any rubbish after the count */
        return offset;
    }

    bssid_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                        ett_packet_filtering_policy_bssid_list, &bli,
                        "BSSID List");
    start_offset = offset;

    while (bssid_cnt < bssid_num) {
        proto_tree *bssid_tree = NULL, *mac_tree = NULL;
        proto_item *bi = NULL;
        guint bssid_start_offset = offset;
        guint8 dest_mac_count = 0;

        bssid_tree = proto_tree_add_subtree_format(bssid_list, tvb, offset, -1,
                                        ett_packet_filtering_policy_bssid,
                                        &bi, "BSSID %u", bssid_cnt);

        proto_tree_add_item(bssid_tree, hf_ieee1905_packet_filtering_policy_bssid,
                            tvb, offset, 6, ENC_NA);
        offset += 6;

        dest_mac_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(bssid_tree, hf_ieee1905_packet_filtering_policy_mac_count,
                            tvb, offset, 1, ENC_NA);
        offset += 1;

        mac_tree = proto_tree_add_subtree(bssid_tree, tvb, offset,
                                          dest_mac_count * 6,
                                          ett_packet_filtering_policy_mac_tree,
                                          NULL, "MAC Address List");

        while (dest_mac_count > 0) {
            proto_tree_add_item(mac_tree,
                            hf_ieee1905_packet_filtering_policy_mac_addr,
                            tvb, offset, 6, ENC_NA);
            offset += 6;
            dest_mac_count -= 1;
        }

        bssid_cnt++;

        proto_item_set_len(bi, offset - bssid_start_offset);
    }

    proto_item_set_len(bli, offset - start_offset);
    return offset;
}

static int
dissect_bssid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
              guint offset, guint16 len _U_)
{
        proto_tree_add_item(tree, hf_ieee1905_bssid_tlv_bssid, tvb, offset, 6,
                            ENC_NA);
        offset += 6;

        return offset;
}

/*
 * Dissect a Service Prioritization Format TLV
 */
static int * const sp_rule_flags_headers[] = {
    &hf_ieee1905_service_prio_rule_add_remove_filter_bit,
    &hf_ieee1905_service_prio_rule_flags_reserved,
    NULL
};

static int * const sp_rule_match_headers[] = {
    &hf_ieee1905_service_prio_rule_match_always,
    &hf_ieee1905_service_prio_rule_match_reserved,
    &hf_ieee1905_service_prio_rule_match_up_in_qos,
    &hf_ieee1905_service_prio_rule_match_up_control_match,
    &hf_ieee1905_service_prio_rule_match_source_mac,
    &hf_ieee1905_service_prio_rule_match_source_mac_sense,
    &hf_ieee1905_service_prio_rule_match_dest_mac,
    &hf_ieee1905_service_prio_rule_match_dest_mac_sense,
    NULL
};

static const true_false_string tfs_add_remove = {
    "Add this filter",
    "Remove this filter"
};

static int
dissect_service_prioritization_rule(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 flags = 0;
    guint8 match_flags = 0;

    proto_tree_add_item(tree, hf_ieee1905_service_prio_rule_id, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
    offset += 4;

    flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_ieee1905_service_prio_rule_flags,
                           ett_ieee1905_service_prio_rule_flags,
                           sp_rule_flags_headers, ENC_NA);
    offset += 1;

    if ((flags & 0x80) == 0) {
        return offset;  /* We are done here ... */
    }

    proto_tree_add_item(tree, hf_ieee1905_service_prio_rule_precedence, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_service_prio_rule_output, tvb, offset,
                        1, ENC_NA);
    offset += 1;

    match_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_service_prio_match_flags,
                           ett_ieee1905_service_prio_rule_match_flags,
                           sp_rule_match_headers, ENC_NA);
    offset += 1;

    if (match_flags & 0x20) { /* MATCH UP in 802.11 QOS ... */
        proto_tree_add_item(tree, hf_ieee1905_service_prio_rule_up_control, tvb,
                            offset, 1, ENC_NA);
        offset += 1;
    }

    if (match_flags & 0x08) {
        proto_tree_add_item(tree, hf_ieee1905_service_prio_rule_source_mac, tvb,
                            offset, 6, ENC_NA);
        offset += 6;
    }

    if (match_flags & 0x02) {
        proto_tree_add_item(tree, hf_ieee1905_service_prio_rule_dest_mac, tvb,
                            offset, 6, ENC_NA);
        offset += 6;
   }

    return offset;
}

/*
 * Dissect a DSCP Mapping Table TLV
 */
static int
dissect_dscp_mapping_table(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    int i = 0;

    for (i = 0; i < 64; i++) {
        guint8 pcp_val = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint_format(tree, hf_ieee1905_dscp_mapping_table_val, tvb,
                offset, 1, pcp_val, "DSCP:%d -> PCP: %u", i, pcp_val);
        offset += 1;
    }

    return offset;
}

/*
 * Dissect an R2 Error Code TLV
 */
static const range_string r2_error_code_rvals[] = {
    { 0, 0,   "Reserved" },
    { 1, 1,   "Service Prioritization Rule not found" },
    { 2, 2,   "Number of Service Prioritization Rules reached the max supported" },
    { 3, 3,   "Default PCP or VLAN ID not provided" },
    { 4, 4,   "Reserved" },
    { 5, 5,   "Number of unique VID exceeds maximum supported" },
    { 6, 6,   "Reserved" },
    { 7, 7,   "Traffic Separation one combined fronthaul and Profile-1 backhaul unsupported" },
    { 8, 8,   "Traffic Separation on combined Profile-1 backhaul and Profile-2 backhaul unsupported" },
    { 9, 9,   "Service Prioritization Rule not supported" },
    { 10, 255, "Reserved" },
    { 0, 0,   NULL }
};

static int
dissect_r2_error_code(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 reason_code = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ieee1905_r2_error_reason_code, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    if (reason_code == 7 || reason_code == 8) {
        proto_tree_add_item(tree, hf_ieee1905_r2_error_bssid,
                        tvb, offset, 6, ENC_NA);
        offset += 6;
    }

    return offset;
}

/*
 * Dissect an AP Radio Advanced Capabilities TLV
 */

static int * const ap_radio_advanced_capa_flags[] = {
    &hf_ieee1905_ap_radio_advance_capa_backhaul_bss_traffic_sep,
    &hf_ieee1905_ap_radio_advance_capa_combined_r1_r2_backhaul,
    &hf_ieee1905_ap_radio_advance_capa_reserved,
    NULL
};

static int
dissect_ap_radio_advanced_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_ap_radio_advanced_capa_radio_id, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_radio_advanced_capa_flags,
                           ett_radio_advanced_capa_flags,
                           ap_radio_advanced_capa_flags, ENC_NA);
    offset += 1;

    return offset;
}

/*
 * Dissect an Association Status Notification TLV:
 */
static const range_string assoc_status_notif_status_rvals[] = {
    { 0, 0,   "No more associations allowed" },
    { 1, 1,   "Associations allowed" },
    { 2, 255, "Reserved" },
    { 0, 0, NULL }
};

static int
dissect_association_status_notification(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 num_bssids = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ieee1905_assoc_status_notif_num_bssid, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    if (num_bssids > 0) {
        proto_tree *bssid_list = NULL;
        guint8 bssid_num = 0;

        bssid_list = proto_tree_add_subtree(tree, tvb, offset,
                                7 * num_bssids,
                                ett_assoc_status_notif_bssid_list, NULL,
                                "BSSID list");
        while (bssid_num < num_bssids) {
            proto_tree *bssid_tree = NULL;

            bssid_tree = proto_tree_add_subtree_format(bssid_list, tvb, offset,
                                7, ett_assoc_status_notif_bssid_tree, NULL,
                                "BSSID %u", bssid_num);

            proto_tree_add_item(bssid_tree,
                                hf_ieee1905_assoc_status_notif_bssid, tvb,
                                offset, 6, ENC_NA);
            offset += 6;

            proto_tree_add_item(bssid_tree,
                                hf_ieee1905_assoc_status_notif_status,
                                tvb, offset, 1, ENC_NA);
            offset += 1;

            bssid_num++;
        }
    }

    return offset;
}

/*
 * Dissect a Source Info TLV:
 */
static int
dissect_source_info(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_source_info_mac_addr, tvb, offset,
                        6, ENC_NA);
    offset += 6;

    return offset;
}

/*
 * Dissect a Tunneled Message Type TLV:
 */
static const range_string tunneled_message_type_rvals[] = {
    { 0, 0,   "Association Request" },
    { 1, 1,   "Re-Association Request" },
    { 2, 2,   "BTM Query" },
    { 3, 3,   "WNM Request" },
    { 4, 4,   "ANQP Request for Neighbor Report" },
    { 5, 5,   "DPP Message" },
    { 6, 255, "Reserved" },
    { 0, 0, NULL }
};

static int
dissect_tunneled_message_type(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_tunneled_message_type, tvb, offset,
                        1, ENC_NA);
    offset += 1;

    return offset;
}

/*
 * Dissect a Tunneled TLV:
 */
static int
dissect_tunneled(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_tunneled_data, tvb, offset, len,
                        ENC_NA);

    /*
     * TODO: Save the tunnelled type and then dissect the message
     */
    offset += len;

    return offset;
}

/*
 * Dissect an R2 Steering Request TLV:
 */
static int * const r2_steering_flags[] = {
    &hf_ieee1905_r2_steering_request_mode_flag,
    &hf_ieee1905_r2_btm_disassoc_imminent_flag,
    &hf_ieee1905_r2_btm_abridged_flag,
    &hf_ieee1905_r2_steering_req_reserved,
    NULL,
};

static int
dissect_r2_steering_request(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 sta_list_count = 0;
    guint8 target_count = 0;
    proto_item *steer_item = NULL;

    proto_tree_add_item(tree, hf_ieee1905_r2_steering_req_src_bssid, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_r2_steering_req_flags,
                           ett_ieee1905_steering_request_flags,
                           r2_steering_flags, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_r2_steering_op_window, tvb, offset,
                        2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ieee1905_r2_steering_btm_dissasoc_tmr, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    sta_list_count = tvb_get_guint8(tvb, offset);
    steer_item = proto_tree_add_item(tree, hf_ieee1905_r2_steering_sta_count,
                                     tvb, offset, 1, ENC_NA);
    offset += 1;

    if (sta_list_count == 0) {
        proto_item_append_text(steer_item, " (Steering request applies to all"
                                           "AMB capable associated STAs in the"
                                           "BSS)");
    } else {
        proto_tree *amb_list = NULL;

        amb_list = proto_tree_add_subtree(tree, tvb, offset, 6 * sta_list_count,
                                ett_r2_steering_sta_list, NULL,
                                "AMB capable STA list");
        while (sta_list_count > 0) {
            proto_tree_add_item(amb_list, hf_ieee1905_r2_steering_sta_mac, tvb,
                                offset, 6, ENC_NA);
            offset += 6;

            sta_list_count -= 1;
        }
    }

    target_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_r2_steering_target_count, tvb, offset,
                        1, ENC_NA);
    offset += 1;

    if (target_count > 0) {
        proto_tree *target_list = NULL;
        int target_num = 0;

        target_list = proto_tree_add_subtree(tree, tvb, offset,
                                             9 * target_count,
                                             ett_r2_steering_target_list,
                                             NULL, "Target BSS list");
        while (target_num < target_count) {
            proto_tree *target = NULL;

            target = proto_tree_add_subtree_format(target_list, tvb, offset, 9,
                                                   ett_r2_steering_target,
                                                   NULL, "Target BSS %u",
                                                   target_num);

            proto_tree_add_item(target, hf_ieee1905_r2_steering_target_bssid,
                                tvb, offset, 6, ENC_NA);
            offset += 6;

            proto_tree_add_item(target, hf_ieee1905_r2_steering_target_op_class,
                                tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(target, hf_ieee1905_r2_steering_target_channel,
                                tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(target, hf_ieee1905_r2_steering_reason, tvb,
                                offset, 1, ENC_NA);
            offset += 1;

            target_num += 1;
        }
    }

    return offset;
}

/*
 * Dissect an Unsuccessful Association Policy TLV:
 */
static int
dissect_unsuccessful_association_policy(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    static int * const capabilities[] = {
      &hf_ieee1905_rpt_unsuccessful_assoc_report,
      NULL,
    };

    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_rpt_unsuccessful_associations,
                           ett_ieee1905_unsuccessful_associations,
                           capabilities, ENC_NA);
    offset++;

    proto_tree_add_item(tree, hf_ieee1905_max_reporting_rate,
                        tvb, offset, 4, ENC_NA);
    offset += 4;

    return offset;
}

/*
 * Dissect a Metric Collection Interval TLV:
 */
static int
dissect_metric_collection_interval(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_metric_collection_interval,
                        tvb, offset, 4, ENC_NA);
    offset += len;

    return offset;
}

/*
 * Dissect a Radio Metrics TLV:
 */
static int
dissect_radio_metrics(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_radio_metrics_radio_id,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_radio_metrics_noise, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_radio_metrics_transmit, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_radio_metrics_receive_self, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_radio_metrics_receive_other, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

/*
 * Dissect an AP Extended Metrics TLV:
 */
static int
dissect_ap_extended_metrics(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_ap_extended_metrics_bssid, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_ap_extended_metrics_unicast_sent, tvb,
                        offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(tree, hf_ieee1905_ap_extended_metrics_unicast_rcvd,
                        tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(tree, hf_ieee1905_ap_extended_metrics_multicast_sent,
                        tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(tree, hf_ieee1905_ap_extended_metrics_multicast_rcvd,
                        tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(tree, hf_ieee1905_ap_extended_metrics_bcast_sent,
                        tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(tree, hf_ieee1905_ap_extended_metrics_bcast_rcvd,
                        tvb, offset, 4, ENC_NA);
    offset += 4;

    return offset;
}

/*
 * Dissect an Status Code TLV:
 */
static int
dissect_status_code(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_status_code_status, tvb,
                        offset, 2, ENC_NA);
    offset += 2;

    return offset;
}

/*
 * Dissect a Disassociation Reason Code TLV:
 */
static int
dissect_disassociation_reason_code(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_disassociation_reason_code, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/*
 * Dissect a Backhaul STA Radio Capabilitoes TLV:
 */
static int * const backhaul_sta_radio_capa_flags[] = {
    &hf_ieee1905_backhaul_sta_radio_capa_mac_included,
    &hf_ieee1905_backhaul_sta_radio_capa_reserved,
    NULL
};

static int
dissect_backhaul_sta_radio_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 mac_addr_included = 0;

    proto_tree_add_item(tree, hf_ieee1905_backhaul_sta_radio_id, tvb, offset,
                        6, ENC_NA);
    offset += 6;

    mac_addr_included = tvb_get_guint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_backhaul_sta_radio_capabilities,
                           ett_backhaul_sta_radio_capa_flags,
                           backhaul_sta_radio_capa_flags, ENC_NA);
    offset += 1;

    if (mac_addr_included & 0x80) {
        proto_tree_add_item(tree, hf_ieee1905_backhaul_sta_addr, tvb, offset,
                            6, ENC_NA);
        offset += 6;
    }

    return offset;
}

/*
 * Dissect an AKM Suite Capabilities TLV:
 */
static int
dissect_akm_suite_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 backhaul_akm_suite_count = 0;
    guint8 fronthaul_akm_suite_count = 0;

    backhaul_akm_suite_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_backhaul_akm_suite_capa_count, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    if (backhaul_akm_suite_count > 0) {
        guint8 backhaul_suite_num = 0;
        proto_tree *backhaul_suite_list = NULL;

        backhaul_suite_list = proto_tree_add_subtree(tree, tvb, offset,
                                backhaul_akm_suite_count * 4,
                                ett_backhaul_akm_suite_list, NULL,
                                "Backhaul AKM Suite list");

        while (backhaul_suite_num < backhaul_akm_suite_count) {
            proto_tree *backhaul_akm_suite = NULL;

            backhaul_akm_suite = proto_tree_add_subtree_format(backhaul_suite_list,
                                tvb, offset, 4, ett_backhaul_akm_suite, NULL,
                                "Backhaul AKM Suite %u", backhaul_suite_num++);

            proto_tree_add_item(backhaul_akm_suite,
                                hf_ieee1905_akm_backhaul_suite_oui, tvb,
                                offset, 3, ENC_NA);
            offset += 3;

            proto_tree_add_item(backhaul_akm_suite,
                                hf_ieee1905_akm_backhaul_suite_type, tvb,
                                offset, 1, ENC_NA);
            offset += 1;
        }
    }

    fronthaul_akm_suite_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_fronthaul_akm_suite_capa_count, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    if (fronthaul_akm_suite_count > 0) {
        guint8 fronthaul_suite_num = 0;
        proto_tree *fronthaul_suite_list = NULL;

        fronthaul_suite_list = proto_tree_add_subtree(tree, tvb, offset,
                                fronthaul_akm_suite_count * 4,
                                ett_fronthaul_akm_suite_list, NULL,
                                "Fronthaul AKM Suite list");

        while (fronthaul_suite_num < fronthaul_akm_suite_count) {
            proto_tree *fronthaul_akm_suite = NULL;

            fronthaul_akm_suite = proto_tree_add_subtree_format(fronthaul_suite_list,
                                tvb, offset, 4, ett_fronthaul_akm_suite, NULL,
                                "Fronthaul AKM Suite %u", fronthaul_suite_num++);

            proto_tree_add_item(fronthaul_akm_suite,
                                hf_ieee1905_akm_fronthaul_suite_oui, tvb,
                                offset, 3, ENC_NA);
            offset += 3;

            proto_tree_add_item(fronthaul_akm_suite,
                                hf_ieee1905_akm_fronthaul_suite_type, tvb,
                                offset, 1, ENC_NA);
            offset += 1;
        }
    }

    return offset;
}

static const true_false_string tfs_dpp_frame_indicator = {
    "GAS frame",
    "DPP public action frame"
};

static int * const ieee1905_encap_dpp_flags[] = {
  &hf_ieee1905_dpp_encap_enrollee_mac_present,
  &hf_ieee1905_dpp_encap_reserved,
  &hf_ieee1905_dpp_encap_frame_type_flag,
  &hf_ieee1905_dpp_encap_reserved2,
  NULL
};

static int
dissect_1905_encap_dpp(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 flags = tvb_get_guint8(tvb, offset);
    guint16 frame_length;

    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_encap_dpp_flags,
                           ett_1905_encap_dpp_flags,
                           ieee1905_encap_dpp_flags, ENC_NA);
    offset += 1;

    if (flags & 0x80) { /* Enrollee MAC present */
        proto_tree_add_item(tree, hf_ieee1905_encap_dpp_sta_mac, tvb, offset,
                            6, ENC_NA);
        offset += 6;
    }

    proto_tree_add_item(tree, hf_ieee1905_dpp_encap_frame_type, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    frame_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_dpp_encap_frame_length, tvb, offset,
                        2, ENC_BIG_ENDIAN);
    offset += 2;

    if (flags & 0x20) {
        guint8 code;
        tvbuff_t *new_tvb;

        proto_tree_add_item(tree, hf_ieee1905_dpp_message_category, tvb,
                            offset, 1, ENC_NA);
        offset += 1;

        code = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_ieee1905_dpp_message_public_action, tvb,
                            offset, 1, ENC_NA);
        offset += 1;

        new_tvb = tvb_new_subset_length(tvb, offset, frame_length - 2);

        add_ff_action_public_fields(tree, new_tvb, pinfo, 0, code);

        offset += frame_length - 2;
    } else {
        tvbuff_t *new_tvb;

        proto_tree_add_item(tree, hf_ieee1905_dpp_encap_category, tvb,
                            offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_ieee1905_dpp_encap_public_action, tvb,
                            offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_ieee1905_dpp_encap_dpp_oui, tvb, offset,
                            3, ENC_NA);
        offset += 3;

        proto_tree_add_item(tree, hf_ieee1905_dpp_encap_dpp_subtype, tvb,
                            offset, 1, ENC_NA);
        offset += 1;

        new_tvb = tvb_new_subset_length(tvb, offset, frame_length - 6);
        dissect_wifi_dpp_public_action(new_tvb, pinfo, tree, NULL);

        offset += (frame_length - 6);
    }

    return offset;
}

/*
 * Dissect a 1905 Encap EAPOL TLV:
 */
static int
dissect_1905_encap_eapol(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    offset += call_dissector(eapol_handle,
                             tvb_new_subset_length(tvb, offset, len),
                             pinfo, tree);

    return offset;
}

/*
 * Dissect a DPP Bootstrapping URI Notification TLV:
 */
static int
dissect_dpp_bootstrapping_uri_notification(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint16 uri_len;

    proto_tree_add_item(tree, hf_ieee1905_dpp_bootstrapping_uri_radio_id,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_dpp_bootstrapping_uri_local_mac_addr,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_dpp_bootstrapping_uri_bsta_mac_addr,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    /* Assume we got the whole URI */
    uri_len = len - 18;
    proto_tree_add_item(tree, hf_ieee1905_dpp_bootstrapping_uri_received,
                        tvb, offset, uri_len, ENC_ASCII);
    offset += uri_len;

    return offset;
}

/*
 * Dissect a DPP CCE Indication TLV:
 */
static int
dissect_dpp_cce_indication(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_dpp_advertise_cce_flag, tvb, offset,
                        1, ENC_NA);
    offset += 1;

    return offset;
}

/*
 * Dissect a DPP Chirp Value TLV:
 */
static int * const dpp_chirp_headers[] = {
    &hf_ieee1905_dpp_chirp_enrollee_mac_addr_present,
    &hf_ieee1905_dpp_chirp_hash_validity,
    &hf_ieee1905_dpp_chirp_reserved,
    NULL
};

static const true_false_string tfs_chirp_hash_validity_bit = {
    "Establish DPP authentication state pertaining to this hash value",
    "Purge any DPP authentication state pertaining to this hash value"
};

static int
dissect_dpp_chirp_value(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 flags = tvb_get_guint8(tvb, offset);
    guint8 hash_length = 0;

    proto_tree_add_bitmask_with_flags(tree, tvb, offset,
                        hf_ieee1905_dpp_chirp_value_flags,
                        ett_ieee1905_dpp_chirp, dpp_chirp_headers, ENC_NA,
                        BMT_NO_APPEND);
    offset += 1;

    if (flags & 0x80) {
        proto_tree_add_item(tree, hf_ieee1905_dpp_chirp_enrollee_mac_addr, tvb,
                            offset, 6, ENC_NA);
        offset += 6;
    }

    hash_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_dpp_chirp_value_hash_length, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    if (hash_length) {
      proto_tree_add_item(tree, hf_ieee1905_dpp_chirp_value_hash_value, tvb,
                          offset, hash_length, ENC_NA);
      offset += hash_length;
    }

    return offset;
}

static int
dissect_device_inventory(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 lsn = tvb_get_guint8(tvb, offset);
    guint lsv = 0, lee = 0, num_radios = 0;

    proto_tree_add_item(tree, hf_ieee1905_dev_inventory_lsn, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_dev_inventory_serial, tvb, offset,
                        lsn, ENC_ASCII);
    offset += lsn;

    lsv = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_dev_inventory_lsv, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_dev_inventory_sw_vers, tvb, offset,
                        lsv, ENC_ASCII);
    offset += lsv;

    lee = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_dev_inventory_lee, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_dev_inventory_exec_env, tvb, offset,
                        lee, ENC_ASCII);
    offset += lee;

    num_radios = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_dev_inventory_num_radios, tvb, offset,
                        1, ENC_NA);
    offset += 1;

    if (num_radios > 0) {
        guint8 radio_id = 0;
        proto_tree *radio_list = NULL;
        proto_item *rli = NULL;
        guint start_list_offset = offset;

        radio_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                            ett_device_inventory_radio_list,
                                            &rli, "Radio List");

        while (num_radios > 0) {
            guint8 lcv = 0;
            proto_tree *radio_tree = NULL;
            proto_item *rti = NULL;
            guint start_tree_offset = offset;

            radio_tree = proto_tree_add_subtree_format(radio_list, tvb, offset,
                                            -1, ett_device_inventory_radio_tree,
                                            &rti, "Radio %u", radio_id);

            proto_tree_add_item(radio_tree, hf_ieee1905_dev_inventory_radio_id,
                                tvb, offset, 6, ENC_NA);
            offset += 6;

            lcv = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(radio_tree, hf_ieee1905_dev_inventory_lcv, tvb,
                                offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(radio_tree, hf_ieee1905_dev_inventory_chp_ven,
                                tvb, offset, lcv, ENC_ASCII);
            offset += lcv;

            proto_item_set_len(rti, offset - start_tree_offset);
            num_radios -= 1;
            radio_id += 1;
        }
        proto_item_set_len(rli, offset - start_list_offset);
    }

    return offset;
}

static int
dissect_bss_configuration_request(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_bss_configuration_request, tvb,
                        offset, len, ENC_NA);
    offset += len;

    return offset;
}

static int
dissect_bss_configuration_response(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    proto_tree_add_item(tree, hf_ieee1905_bss_configuration_response, tvb,
                        offset, len, ENC_NA);
    offset += len;

    return offset;
}

static int
dissect_dpp_message(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 code;
    tvbuff_t *new_tvb;

    code = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ieee1905_dpp_message_category, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ieee1905_dpp_message_public_action, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    new_tvb = tvb_new_subset_length(tvb, offset, len - 2);

    add_ff_action_public_fields(tree, new_tvb, pinfo, 0, code);

    offset += len -2;

    return offset;
}

/*
 * Dissect each of the TLV types we know about
 */
static int
dissect_ieee1905_tlv_data(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint8 tlv_type, guint16 tlv_len)
{
    guint link_metric_query;

    switch (tlv_type) {

    case AL_MAC_ADDRESS_TYPE_TLV:
        proto_tree_add_item(tree, hf_ieee1905_al_mac_address_type, tvb,
                            offset, 6, ENC_NA);
        offset += 6;
        break;

    case MAC_ADDRESS_TYPE_TLV:
        proto_tree_add_item(tree, hf_ieee1905_mac_address_type, tvb,
                            offset, 6, ENC_NA);
        offset += 6;
        break;

    case DEVICE_INFORMATION_TYPE_TLV:
        offset = dissect_device_information_type(tvb, pinfo, tree, offset,
                                tlv_len);
        break;

    case DEVICE_BRIDGING_CAPABILITY_TLV:
        offset = dissect_device_bridging_capabilities(tvb, pinfo, tree,
                                offset, tlv_len);
        break;

    case NON_1905_NEIGHBOR_DEVICE_LIST_TLV:
        offset = dissect_non_1905_neighbor_device_list(tvb, pinfo, tree,
                                offset, tlv_len);
        break;

    case NEIGHBOR_DEVICE_TLV:
        offset = dissect_1905_neighbor_device(tvb, pinfo, tree, offset,
                                tlv_len);
        break;

    case LINK_METRIC_QUERY_TLV:
        proto_tree_add_item_ret_uint(tree,
                                      hf_ieee1905_link_metric_query_type,
                                      tvb, offset, 1, ENC_NA,
                                      &link_metric_query);
        offset++;

        if (link_metric_query) {
            proto_tree_add_item(tree, hf_ieee1905_al_mac_address_type, tvb,
                                offset, 6, ENC_NA);
            offset += 6;
        }

        proto_tree_add_item(tree, hf_ieee1905_link_metrics_requested, tvb,
                            offset, 1, ENC_NA);
        offset++;
        break;

    case TRANSMITTER_LINK_METRIC_TLV:
        offset = dissect_transmitter_link_metric(tvb, pinfo, tree, offset,
                                        tlv_len);
        break;

    case RECEIVER_LINK_METRIC_TLV:
        offset = dissect_receiver_link_metric(tvb, pinfo, tree, offset,
                                        tlv_len);
        break;

    case VENDOR_SPECIFIC_TLV:
        offset = dissect_vendor_specific(tvb, pinfo, tree, offset, tlv_len);
        break;

    case LINK_METRIC_RESULT_CODE_TLV:
        offset = dissect_link_metric_result_code(tvb, pinfo, tree, offset);
        break;

    case SEARCHED_ROLE_TLV:
        offset = dissect_searched_role(tvb, pinfo, tree, offset);
        break;

    case AUTO_CONFIG_FREQ_BAND_TLV:
        offset = dissect_auto_config_freq_band(tvb, pinfo, tree, offset);
        break;

    case SUPPORTED_ROLE_TLV:
        offset = dissect_supported_role(tvb, pinfo, tree, offset);
        break;

    case SUPPORTED_FREQ_BAND_TLV:
        offset = dissect_supported_freq_band(tvb, pinfo, tree, offset);
        break;

    case WSC_TLV:
        offset = dissect_wsc(tvb, pinfo, tree, offset, tlv_len);
        break;

    case PUSH_BUTTON_EVENT_NOTIFICATION_TLV:
        offset = dissect_push_button_event_notification(tvb, pinfo,
                                tree, offset);
        break;

    case PUSH_BUTTON_JOIN_NOTIFICATION_TLV:
        offset = dissect_push_button_join_notification(tvb, pinfo,
                                tree, offset);
        break;

    case GENERIC_PHY_DEVICE_INFORMATION_TLV:
        offset = dissect_generic_phy_device_info(tvb, pinfo, tree,
                                offset);
        break;

    case DEVICE_IDENTIFICATION_TYPE_TLV:
        offset = dissect_device_identification(tvb, pinfo, tree,
                                offset);
        break;

    case CONTROL_URL_TYPE_TLV:
        offset = dissect_control_url_type(tvb, pinfo, tree, offset, tlv_len);
        break;

    case IPV4_TYPE_TLV:
        offset = dissect_ipv4_type(tvb, pinfo, tree, offset);
        break;

    case IPV6_TYPE_TLV:
        offset = dissect_ipv6_type(tvb, pinfo, tree, offset);
        break;

    case PUSH_BUTTON_EVENT_TYPE_NOTIFICATION_TLV:
        offset = dissect_push_button_event_type_notification(tvb, pinfo, tree,
                                offset);
        break;

    case IEEE1905_PROFILE_VERSION_TLV:
        offset = dissect_profile_version(tvb, pinfo, tree, offset);
        break;

    case POWER_OFF_INTERFACE_TLV:
        offset = dissect_power_off_interface(tvb, pinfo, tree, offset);
        break;

    case INTERFACE_POWER_CHANGE_INFORMATION_TLV:
        offset = dissect_interface_power_change_info(tvb, pinfo, tree, offset);
        break;

    case INTERFACE_POWER_CHANGE_STATUS_TLV:
        offset = dissect_interface_power_change_status(tvb, pinfo, tree, offset);
        break;

    case L2_NEIGHBOR_DEVICE_TLV:
        offset = dissect_l2_neighbor_device(tvb, pinfo, tree, offset);
        break;

    case SUPPORTED_SERVICE_TLV:
        offset = dissect_supported_service(tvb, pinfo, tree, offset);
        break;

    case SEARCHED_SERVICE_TLV:
        offset = dissect_searched_service(tvb, pinfo, tree, offset);
        break;

    case AP_RADIO_IDENTIFIER_TLV:
        offset = dissect_ap_radio_identifier(tvb, pinfo, tree, offset);
        break;

    case AP_OPERATIONAL_BSS_TLV:
        offset = dissect_ap_operational_bss(tvb, pinfo, tree, offset);
        break;

    case ASSOCIATED_CLIENTS_TLV:
        offset = dissect_associated_clients(tvb, pinfo, tree, offset);
        break;

    case AP_RADIO_BASIC_CAPABILITIES_TLV:
        offset = dissect_ap_radio_basic_capabilities(tvb, pinfo, tree, offset);
        break;

    case AP_HT_CAPABILITIES_TLV:
        offset = dissect_ap_ht_capabilities(tvb, pinfo, tree, offset);
        break;

    case AP_VHT_CAPABILITIES_TLV:
        offset = dissect_ap_vht_capabilities(tvb, pinfo, tree, offset);
        break;

    case AP_HE_CAPABILITIES_TLV:
        offset = dissect_ap_he_capabilities(tvb, pinfo, tree, offset);
        break;

    case STEERING_POLICY_TLV:
        offset = dissect_steering_policy(tvb, pinfo, tree, offset, tlv_len);
        break;

    case METRIC_REPORTING_POLICY_TLV:
        offset = dissect_metric_reporting_policy(tvb, pinfo, tree, offset);
        break;

    case CHANNEL_PREFERENCE_TLV:
        offset = dissect_channel_preference(tvb, pinfo, tree, offset, tlv_len);
        break;

    case RADIO_OPERATION_RESTRICTION_TLV:
        offset = dissect_radio_operation_restriction(tvb, pinfo, tree, offset,
                                tlv_len);
        break;

    case TRANSMIT_POWER_LIMIT_TLV:
        offset = dissect_transmit_power_limit(tvb, pinfo, tree, offset);
        break;

    case CHANNEL_SELECTION_RESPONSE_TLV:
        offset = dissect_channel_selection_response(tvb, pinfo, tree, offset);
        break;

    case OPERATING_CHANNEL_REPORT_TLV:
        offset = dissect_operating_channel_report(tvb, pinfo, tree, offset);
        break;

    case CLIENT_INFO_TLV:
        offset = dissect_client_info(tvb, pinfo, tree, offset);
        break;

    case CLIENT_CAPABILITY_REPORT_TLV:
        offset = dissect_client_capability_report(tvb, pinfo, tree, offset, tlv_len);
        break;

    case CLIENT_ASSOCIATION_EVENT_TLV:
        offset = dissect_client_association_event(tvb, pinfo, tree, offset);
        break;

    case AP_METRIC_QUERY_TLV:
        offset = dissect_ap_metric_query(tvb, pinfo, tree, offset, tlv_len);
        break;

    case AP_METRICS_TLV:
        offset = dissect_ap_metrics(tvb, pinfo, tree, offset, tlv_len);
        break;

    case STA_MAC_ADDRESS_TYPE_TLV:
        offset = dissect_sta_mac_address_type(tvb, pinfo, tree, offset, tlv_len);
        break;

    case ASSOCIATED_STA_LINK_METRICS_TLV:
        offset = dissect_associated_sta_link_metrics(tvb, pinfo, tree, offset,
                                                     tlv_len);
        break;

    case UNASSOCIATED_STA_LINK_METRICS_QUERY_TLV:
        offset = dissect_unassociated_sta_link_metrics_query(tvb, pinfo, tree,
                                                        offset, tlv_len);
        break;

    case UNASSOCIATED_STA_LINK_METRICS_RESPONSE_TLV:
        offset = dissect_unassociated_sta_link_metric_response(tvb, pinfo, tree,
                                                        offset, tlv_len);
        break;

    case BEACON_METRICS_QUERY_TLV:
        offset = dissect_beacon_metrics_query(tvb, pinfo, tree, offset, tlv_len);
        break;

    case BEACON_METRICS_RESPONSE_TLV:
        offset = dissect_beacon_metrics_response(tvb, pinfo, tree, offset, tlv_len);
        break;

    case STEERING_REQUEST_TLV:
        offset = dissect_steering_request(tvb, pinfo, tree, offset, tlv_len);
        break;

    case STEERING_BTM_REPORT_TLV:
        offset = dissect_steering_btm_report(tvb, pinfo, tree, offset, tlv_len);
        break;

    case CLIENT_ASSOCIATION_CONTROL_REQUEST_TLV:
        offset = dissect_client_association_control_request(tvb, pinfo, tree, offset);
        break;

    case BACKHAUL_STEERING_REQUEST_TLV:
        offset = dissect_backhaul_steering_request(tvb, pinfo, tree, offset);
        break;

    case BACKHAUL_STEERING_RESPONSE_TLV:
        offset = dissect_backhaul_steering_response(tvb, pinfo, tree, offset);
        break;

    case HIGHER_LAYER_DATA_TLV:
        offset = dissect_higher_layer_data(tvb, pinfo, tree, offset, tlv_len);
        break;

    case AP_CAPABILITY_TLV:
        offset = dissect_ap_capability(tvb, pinfo, tree, offset);
        break;

    case ASSOCIATED_STA_TRAFFIC_STATS_TLV:
        offset = dissect_associated_sta_traffic_stats(tvb, pinfo, tree, offset, tlv_len);
        break;

    case ERROR_CODE_TLV:
        offset = dissect_error_code(tvb, pinfo, tree, offset, tlv_len);
        break;

    case CHANNEL_SCAN_REPORTING_POLICY_TLV:
        offset = dissect_channel_scan_reporting_policy(tvb, pinfo, tree,
                                                       offset, tlv_len);
        break;

    case CHANNEL_SCAN_CAPABILITIES_TLV:
        offset = dissect_channel_scan_capabilities(tvb, pinfo, tree, offset,
                                                   tlv_len);
        break;

    case CHANNEL_SCAN_REQUEST_TLV:
        offset = dissect_channel_scan_request(tvb, pinfo, tree, offset,
                                              tlv_len);
        break;

    case CHANNEL_SCAN_RESULT_TLV:
        offset = dissect_channel_scan_result(tvb, pinfo, tree, offset, tlv_len);
        break;

    case TIMESTAMP_TLV:
        offset = dissect_timestamp(tvb, pinfo, tree, offset, tlv_len);
        break;

    case IEEE1905_LAYER_SECURITY_CAPABILITY_TLV:
        offset = dissect_1905_layer_security_capability(tvb, pinfo, tree,
                                                        offset, tlv_len);
        break;

    case AP_WF6_CAPABILITIES_TLV:
        offset = dissect_ap_wf6_capabilities(tvb, pinfo, tree, offset, tlv_len);
        break;

    case MIC_TLV:
        offset = dissect_mic(tvb, pinfo, tree, offset, tlv_len);
        break;

    case ENCRYPTED_TLV:
        offset = dissect_encrypted(tvb, pinfo, tree, offset, tlv_len);
        break;

    case CAC_REQUEST_TLV:
        offset = dissect_cac_request(tvb, pinfo, tree, offset, tlv_len);
        break;

    case CAC_TERMINATION_TLV:
        offset = dissect_cac_termination(tvb, pinfo, tree, offset, tlv_len);
        break;

    case CAC_COMPLETION_REPORT_TLV:
        offset = dissect_cac_completion_report(tvb, pinfo, tree, offset,
                                               tlv_len);
        break;

    case ASSOCIATED_WF6_STA_STATUS_REPORT_TLV:
        offset = dissect_associated_wf6_sta_status_report(tvb, pinfo, tree,
                                                          offset, tlv_len);
        break;

    case CAC_STATUS_REPORT_TLV:
        offset = dissect_cac_status_report(tvb, pinfo, tree, offset, tlv_len);
        break;

    case CAC_CAPABILITIES_TLV:
        offset = dissect_cac_capabilities(tvb, pinfo, tree, offset, tlv_len);
        break;

    case MULTI_AP_PROFILE_TLV:
        offset = dissect_multi_ap_version(tvb, pinfo, tree, offset, tlv_len);
        break;

    case PROFILE_2_AP_CAPABILITY_TLV:
        offset = dissect_r2_ap_capability(tvb, pinfo, tree, offset, tlv_len);
        break;

    case DEFAULT_802_1Q_SETTINGS_TLV:
        offset = dissect_default_802_1q_settings(tvb, pinfo, tree, offset,
                                                 tlv_len);
        break;

    case TRAFFIC_SEPARATION_POLICY_TLV:
        offset = dissect_traffic_separation_policy(tvb, pinfo, tree, offset,
                                                   tlv_len);
        break;

    case BSS_CONFIGURATION_REPORT_TLV:
        offset = dissect_bss_configuration_report(tvb, pinfo, tree, offset,
                                                  tlv_len);
        break;

    case BSSID_TLV:
        offset = dissect_bssid(tvb, pinfo, tree, offset, tlv_len);
        break;

    case SERVICE_PRIORITIZATION_RULE_TLV:
        offset = dissect_service_prioritization_rule(tvb, pinfo, tree, offset,
                                                     tlv_len);
        break;

    case DSCP_MAPPING_TABLE_TLV:
        offset = dissect_dscp_mapping_table(tvb, pinfo, tree, offset, tlv_len);
        break;

    case PROFILE_2_ERROR_CODE_ERROR_TLV:
        offset = dissect_r2_error_code(tvb, pinfo, tree, offset, tlv_len);
        break;

    case AP_RADIO_ADVANCED_CAPABILITIES_TLV:
        offset = dissect_ap_radio_advanced_capabilities(tvb, pinfo, tree,
                                                        offset, tlv_len);
        break;

    case ASSOCIATION_STATUS_NOTIFICATION_TLV:
        offset = dissect_association_status_notification(tvb, pinfo, tree,
                                                         offset, tlv_len);
        break;

    case SOURCE_INFO_TLV:
        offset = dissect_source_info(tvb, pinfo, tree, offset, tlv_len);
        break;

    case TUNNELED_MESSAGE_TYPE_TLV:
        offset = dissect_tunneled_message_type(tvb, pinfo, tree, offset,
                                                tlv_len);
        break;

    case TUNNELED_TLV:
        offset = dissect_tunneled(tvb, pinfo, tree, offset, tlv_len);
        break;

    case PROFILE_2_STEERING_REQUEST_TLV:
        offset = dissect_r2_steering_request(tvb, pinfo, tree, offset, tlv_len);
        break;

    case UNSUCCESSFUL_ASSOCIATION_POLICY_TLV:
        offset = dissect_unsuccessful_association_policy(tvb, pinfo, tree,
                                                        offset, tlv_len);
        break;

    case METRIC_COLLECTION_INTERVAL_TLV:
        offset = dissect_metric_collection_interval(tvb, pinfo, tree, offset,
                                                    tlv_len);
        break;

    case RADIO_METRICS_TLV:
        offset = dissect_radio_metrics(tvb, pinfo, tree, offset, tlv_len);
        break;

    case AP_EXTENDED_METRICS_TLV:
        offset = dissect_ap_extended_metrics(tvb, pinfo, tree, offset, tlv_len);
        break;

    case ASSOCIATED_STA_EXTENDED_LINK_METRICS_TLV:
        offset = dissect_associated_sta_extended_link_metrics(tvb, pinfo, tree,
                                                              offset, tlv_len);
        break;

    case STATUS_CODE_TLV:
        offset = dissect_status_code(tvb, pinfo, tree, offset,
                                                tlv_len);
        break;

    case REASON_CODE_TLV:
        offset = dissect_disassociation_reason_code(tvb, pinfo, tree, offset,
                                                    tlv_len);
        break;

    case BACKHAUL_STA_RADIO_CAPABILITIES_TLV:
        offset = dissect_backhaul_sta_radio_capabilities(tvb, pinfo, tree,
                                                        offset, tlv_len);
        break;

    case AKM_SUITE_CAPABILITIES_TLV:
        offset = dissect_akm_suite_capabilities(tvb, pinfo, tree, offset,
                                                tlv_len);
        break;

    case IEEE1905_ENCAP_DPP_TLV:
        offset = dissect_1905_encap_dpp(tvb, pinfo, tree, offset, tlv_len);
        break;

    case IEEE1905_ENCAP_EAPOL_TLV:
        offset = dissect_1905_encap_eapol(tvb, pinfo, tree, offset, tlv_len);
        break;

    case DPP_BOOTSTRAPPING_URI_NOTIFICATION_TLV:
        offset = dissect_dpp_bootstrapping_uri_notification(tvb, pinfo, tree,
                                                            offset, tlv_len);
        break;

    case DPP_CCE_INDICATION_TLV:
        offset = dissect_dpp_cce_indication(tvb, pinfo, tree, offset, tlv_len);
        break;

    case DPP_CHIRP_VALUE_TLV:
        offset = dissect_dpp_chirp_value(tvb, pinfo, tree, offset, tlv_len);
        break;

    case DEVICE_INVENTORY_TLV:
        offset = dissect_device_inventory(tvb, pinfo, tree, offset, tlv_len);
        break;

    case PACKET_FILTERING_POLICY_TLV:
        offset = dissect_packet_filtering_policy(tvb, pinfo, tree, offset,
                                                 tlv_len);
        break;

    case AGENT_LIST_TLV:
        offset = dissect_agent_list(tvb, pinfo, tree, offset, tlv_len);
        break;

    case LOOP_PREVENTION_MECHANISM_SETTING_TLV:
        offset = dissect_loop_prevention_mechanism_setting(tvb, pinfo, tree,
                                                           offset, tlv_len);
        break;

    case LOOP_DETECTION_SEQUENCE_NUMBER_TLV:
        offset = dissect_loop_detection_sequence_number(tvb, pinfo, tree,
                                                        offset, tlv_len);
        break;

    case GROUP_INTEGRITY_KEY_TLV:
        offset = dissect_group_integrity_key(tvb, pinfo, tree, offset, tlv_len);
        break;

    case CAC_STATUS_REQUEST_TLV:
        offset = dissect_cac_status_request(tvb, pinfo, tree, offset, tlv_len);
        break;

    case BSS_CONFIGURATION_REQUEST_TLV:
        offset = dissect_bss_configuration_request(tvb, pinfo, tree, offset,
                                                   tlv_len);
        break;

    case BSS_CONFIGURATION_RESPONSE_TLV:
        offset = dissect_bss_configuration_response(tvb, pinfo, tree, offset,
                                                    tlv_len);
        break;

    case DPP_MESSAGE_TLV:
        offset = dissect_dpp_message(tvb, pinfo, tree, offset, tlv_len);
        break;

    default:
        proto_tree_add_item(tree, hf_ieee1905_tlv_data, tvb, offset, tlv_len, ENC_NA);
        offset += tlv_len;
    }

  return offset;
}

static int * const tlv_len_headers[] = {
    &hf_ieee1905_tlv_len_reserved,
    &hf_ieee1905_tlv_len_length,
    NULL
};

#ifndef min
#define min(a, b) ((a < b) ? a : b)
#endif

static int
dissect_ieee1905_tlvs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gboolean eom_seen = 0;
    guint offset = 0;

    while (!eom_seen) {
        guint8 tlv_type;
        guint16 tlv_len;
        proto_item *tlv_tree;

        tlv_type = tvb_get_guint8(tvb, offset);
        eom_seen = (tlv_type == EOM_TLV);
        /*
        * We can only deal with the reported length remaining ATM so take the
        * min of the TLV len and the reported len.
        */
        tlv_len = min(tvb_get_ntohs(tvb, offset + 1),
                    tvb_reported_length_remaining(tvb, offset));

        tlv_tree = proto_tree_add_subtree(tree, tvb, offset, tlv_len + 3,
                                          ett_tlv, NULL, val_to_str_ext(tlv_type,
                                                &ieee1905_tlv_types_vals_ext,
                                                "Unknown: %02x"));

        proto_tree_add_item(tlv_tree, hf_ieee1905_tlv_types, tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_bitmask(tlv_tree, tvb, offset, hf_ieee1905_tlv_len,
                             ett_ieee1905_tlv_len, tlv_len_headers, ENC_BIG_ENDIAN);
        offset += 2;

        if (tlv_len)
            offset = dissect_ieee1905_tlv_data(tvb, pinfo, tlv_tree, offset, tlv_type, tlv_len);
    }
    return offset;
}

static const fragment_items ieee1905_fragment_items = {
    /* Fragment subtrees */
    &ett_ieee1905_fragment,
    &ett_ieee1905_fragments,
    /* Fragment fields */
    &hf_ieee1905_fragments,
    &hf_ieee1905_fragment,
    &hf_ieee1905_fragment_overlap,
    &hf_ieee1905_fragment_overlap_conflicts,
    &hf_ieee1905_fragment_multiple_tails,
    &hf_ieee1905_fragment_too_long_fragment,
    &hf_ieee1905_fragment_error,
    &hf_ieee1905_fragment_count,
    &hf_ieee1905_fragment_reassembled_in,
    &hf_ieee1905_fragment_reassembled_length,
    NULL,
    "IEEE1905 Fragments"
};

typedef struct {
    address src;
    address dst;
    guint32 vlan_id; /* Take the VLAN ID into account */
    guint8 frag_id;
} ieee1905_fragment_key;

static guint
ieee1905_fragment_hash(gconstpointer k)
{
    guint hash_val;
    const ieee1905_fragment_key *key = (const ieee1905_fragment_key *)k;

    if (!key || !key->src.data || !key->dst.data) {
        return 0;
    }

    const guint8 src_len = key->src.len;
    const guint8 dst_len = key->dst.len;
    const guint8 hash_buf_len = src_len + dst_len + sizeof(guint8) + sizeof(guint32);
    guint8* hash_buf = (guint8*)wmem_alloc(wmem_packet_scope(), hash_buf_len);

    memcpy(hash_buf, key->src.data, src_len);
    memcpy(&hash_buf[src_len], key->dst.data, dst_len);
    hash_buf[src_len + dst_len] = key->frag_id;
    memcpy(&hash_buf[src_len + dst_len + sizeof(guint8)], &key->vlan_id, sizeof(guint32));
    hash_val = wmem_strong_hash((const guint8 *)hash_buf, hash_buf_len);
    return hash_val;
}

static gboolean
ieee1905_fragment_equal(gconstpointer k1, gconstpointer k2)
{
    const ieee1905_fragment_key *key1 =
                        (const ieee1905_fragment_key *)k1;
    const ieee1905_fragment_key *key2 =
                        (const ieee1905_fragment_key *)k2;

    if (!key1 || !key2) {
        return FALSE;
    }

    return (key1->frag_id == key2->frag_id &&
            key1->vlan_id == key2->vlan_id &&
            addresses_equal(&key1->src, &key2->src) &&
            addresses_equal(&key1->src, &key2->src));
}

static gpointer
ieee1905_fragment_temporary_key(const packet_info *pinfo, const guint32 id,
                                const void *data _U_)
{
    ieee1905_fragment_key *key;

    if (pinfo->src.data == NULL || pinfo->dst.data == NULL) {
        return NULL;
    }

    key = g_slice_new(ieee1905_fragment_key);

    key->frag_id = id & 0xFF;
    copy_address_shallow(&key->src, &pinfo->src);
    copy_address_shallow(&key->dst, &pinfo->dst);
    key->vlan_id = pinfo->vlan_id;

    return (gpointer)key;
}

static gpointer
ieee1905_fragment_persistent_key(const packet_info *pinfo, const guint id,
                                 const void *data _U_)
{
    if (pinfo->src.data == NULL || pinfo->dst.data == NULL) {
        return NULL;
    }

    ieee1905_fragment_key *key = g_slice_new(ieee1905_fragment_key);

    key->frag_id = id & 0xFF;
    copy_address(&key->src, &pinfo->src);
    copy_address(&key->dst, &pinfo->dst);
    key->vlan_id = pinfo->vlan_id;

    return (gpointer)key;
}

static void
ieee1905_fragment_free_temporary_key(gpointer ptr)
{
    ieee1905_fragment_key *key = (ieee1905_fragment_key *)ptr;

    g_slice_free(ieee1905_fragment_key, key);
}

static void
ieee1905_fragment_free_persistent_key(gpointer ptr)
{
    ieee1905_fragment_key *key = (ieee1905_fragment_key *)ptr;

    if (key) {
        free_address(&key->src);
        free_address(&key->dst);
        g_slice_free(ieee1905_fragment_key, key);
    }
}

static reassembly_table g_ieee1905_reassembly_table;

static reassembly_table_functions ieee1905_reassembly_table_functions = {
    ieee1905_fragment_hash,
    ieee1905_fragment_equal,
    ieee1905_fragment_temporary_key,
    ieee1905_fragment_persistent_key,
    ieee1905_fragment_free_temporary_key,
    ieee1905_fragment_free_persistent_key,
};

#define LAST_IEEE1905_FRAGMENT 0x80

static int
dissect_ieee1905(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_tree *ieee1905_tree;
    guint16    message_type;
    guint      offset = 0, next_offset = 0;
    static int * const flag_headers[] = {
        &hf_ieee1905_last_fragment,
        &hf_ieee1905_relay_indicator,
        NULL
    };
    guint16 msg_id = tvb_get_ntohs(tvb, 4);
    guint8 frag_id = tvb_get_guint8(tvb, 6);
    guint8 flags = tvb_get_guint8(tvb, 7);
    tvbuff_t *next_tvb = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ieee1905");

    col_clear(pinfo->cinfo, COL_INFO);

    message_type = tvb_get_ntohs(tvb, 2);

    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str_ext(message_type, &ieee1905_message_type_vals_ext,
                        "Unknown: %u"));

    ti = proto_tree_add_item(tree, proto_ieee1905, tvb, 0, -1, ENC_NA);

    ieee1905_tree = proto_item_add_subtree(ti, ett_ieee1905);

    proto_tree_add_item(ieee1905_tree, hf_ieee1905_message_version, tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(ieee1905_tree, hf_ieee1905_message_reserved, tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(ieee1905_tree, hf_ieee1905_message_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ieee1905_tree, hf_ieee1905_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ieee1905_tree, hf_ieee1905_fragment_id, tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_bitmask(ieee1905_tree, tvb, offset, hf_ieee1905_flags,
                           ett_ieee1905_flags, flag_headers, ENC_NA);
    offset++;

    /*
     * Now figure out if it is a fragment and do reassembly. If we have a
     * fragment but not the whole lot, just dissect it as data, otherwise
     * dissect it.
     */
    if ((flags & LAST_IEEE1905_FRAGMENT) && frag_id == 0) {
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        next_offset = dissect_ieee1905_tlvs(next_tvb, pinfo, ieee1905_tree);
    } else {
        gboolean save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;
        fragment_head *frag_head = NULL;
        guint remaining_length = tvb_reported_length_remaining(tvb, offset);

        pinfo->fragmented = save_fragmented;
        frag_head = fragment_add_seq_check(&g_ieee1905_reassembly_table, tvb,
                                           offset, pinfo,
                                           msg_id, NULL, frag_id,
                                           remaining_length,
                                           (flags & LAST_IEEE1905_FRAGMENT) == 0);

        next_tvb = process_reassembled_data(tvb, offset, pinfo,
                                            "Reassembled Message",
                                            frag_head,
                                            &ieee1905_fragment_items,
                                            NULL, ieee1905_tree);

        if (next_tvb) { /* Reassembled */
            next_offset = dissect_ieee1905_tlvs(next_tvb, pinfo, ieee1905_tree);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            " (Message ID: %u, Fragment ID: %u, VLAN ID: %u)",
                            msg_id, frag_id, pinfo->vlan_id);
            next_tvb = NULL;
            proto_tree_add_item(ieee1905_tree, hf_ieee1905_fragment_data, tvb,
                                offset,
                                tvb_reported_length_remaining(tvb, offset) - 1,
                                ENC_NA);
        }
    }

    if (next_tvb && tvb_reported_length_remaining(next_tvb, next_offset)) {
        proto_item *pi = NULL;

        /* THis shouldn't happen ... */
        pi = proto_tree_add_item(ieee1905_tree, hf_ieee1905_data, next_tvb,
                                 next_offset, -1, ENC_NA);
        expert_add_info(pinfo, pi, &ei_ieee1905_extraneous_data_after_eom);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_ieee1905(void)
{
    static hf_register_info hf[] = {
        { &hf_ieee1905_fragment_data,
          { "Fragment Data", "ieee1905.fragment.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_message_version,
          { "Message version", "ieee1905.message_version",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_message_reserved,
          { "Message reserved", "ieee1905.message_reserved",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_message_type,
          { "Message type", "ieee1905.message_type",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &ieee1905_message_type_vals_ext, 0, NULL, HFILL }},

        { &hf_ieee1905_message_id,
          { "Message id", "ieee1905.message_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_fragment_id,
          { "Fragment id", "ieee1905.fragment_id",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_flags,
          { "Flags", "ieee1905.flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_last_fragment,
          { "Last fragment", "ieee1905.last_fragment",
            FT_BOOLEAN, 8, TFS(&tfs_last_fragment), 0x80, NULL, HFILL }},

        { &hf_ieee1905_relay_indicator,
          { "Relay indicator", "ieee1905.relay_indicator",
            FT_BOOLEAN, 8, TFS(&tfs_relay_indicator), 0x40, NULL, HFILL }},

        { &hf_ieee1905_tlv_types,
          { "TLV type", "ieee1905.tlv_type",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ieee1905_tlv_types_vals_ext, 0, NULL, HFILL }},

        { &hf_ieee1905_tlv_len,
          { "TLV length", "ieee1905.tlv_length",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_tlv_len_reserved,
          { "TLV length reserved", "ieee1905.tlv_length.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xC000, NULL, HFILL }},

        { &hf_ieee1905_tlv_len_length,
          { "TLV length length", "ieee1905.tlv_length.length",
            FT_UINT16, BASE_DEC, NULL, 0x3FFF, NULL, HFILL }},

        { &hf_ieee1905_tlv_data,
          { "TLV data", "ieee1905.tlv_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_al_mac_address_type,
          { "1905 AL MAC address type", "ieee1905.1905_al_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_mac_address_type,
          { "MAC address type", "ieee1905.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_link_metric_query_type,
          { "Link metric query type", "ieee1905.link_metric_query_type",
            FT_UINT8, BASE_DEC, VALS(ieee1905_link_metric_query_type_vals),
            0, NULL, HFILL }},

        { &hf_ieee1905_link_metrics_requested,
          { "Link metrics requested", "ieee1905.link_metrics_requested",
            FT_UINT8, BASE_DEC, VALS(ieee1905_link_metrics_requested_vals),
            0, NULL, HFILL }},

        { &hf_ieee1905_responder_al_mac_addr,
          { "Responder MAC address", "ieee1905.responder_al_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_neighbor_al_mac_addr,
          { "Neighbor MAC address", "ieee1905.neighbor_al_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_receiving_al_mac_addr,
          { "Receiving AL MAC address", "ieee1905.receiving_al_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bridge_flag,
          { "IEEE 802.1 bridge flag", "ieee1905.bridgeFlag",
            FT_UINT8, BASE_DEC, VALS(ieee1905_bridge_flag_vals), 0, NULL, HFILL }},

        { &hf_ieee1905_packet_errors,
          { "Packet errors", "ieee1905.packetErrors",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_transmitted_packets,
          { "Transmitted packets", "ieee1905.transmittedPackets",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_mac_throughput_capacity,
          { "MAC throughput capacity", "ieee1905.macThroughputCapacity",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_link_availability,
          { "Link availability", "ieee1905.linkAvailability",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_phy_rate,
          { "Phy rate", "ieee1905.phyRate",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_packets_received,
          { "Packets received", "ieee1905.packets_received",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_rssi,
          { "RSSI", "ieee1905.rssi",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_local_interface_count,
          { "Local interface count", "ieee1905.dev_info.local_int_cnt",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_media_type,
          { "Media type", "ieee1905.dev_info.media_type",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_media_type_high,
          { "Media type bits 15 to 8", "ieee1905.media_type.bits_15_to_8",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_media_type_low,
          { "Media type bits 7 to 0", "ieee1905.media_type.bits_7_to_0",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_media_spec_info_len,
          { "Special info length", "ieee1905.dev_info.spec_info_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_media_spec_info,
          { "Special info", "ieee1905.dev_info.spec_info",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bridging_tuples_cnt,
          { "Bridging tuples count", "ieee1905.bridging_info.tuples_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bridging_mac_address_cnt,
          { "Bridging MAC address count", "ieee1905.bridging_info.mac_addr_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bridging_mac_address,
          { "Bridging MAC address", "ieee1905.bridging_info.mac_address",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_local_interface_mac,
          { "Local interface MAC address", "ieee1905.local_intf.mac_address",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_non_1905_neighbor_mac,
          { "Non 1905 neighbor MAC address", "ieee1905.non_1905_neighbor.mac_address",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_neighbor_flags,
          { "IEEE1905 neighbor flags", "ieee1905.neighbor_flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bridges_flag,
          { "IEEE1905 bridges", "ieee1905.bridges",
            FT_BOOLEAN, 8, TFS(&tfs_bridges_flag), 0x80, NULL, HFILL }},

        { &hf_ieee1905_link_metric_result_code,
          { "IEEE1905 link metric result code", "ieee1905.link_metric.result_code",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_vendor_specific_oui,
          { "Vendor specific OUI", "ieee1905.vendor_specific.oui",
            FT_UINT24, BASE_OUI, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_vendor_specific_info,
          { "Vendor specific information", "ieee1905.vendor_specific.info",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_searched_role,
          { "Searched role", "ieee1905.searched_role",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_supported_role,
          { "Supported role", "ieee1905.supported_role",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_auto_config_freq_band,
          { "Auto config frequency band", "ieee1905.auto_config.freq_band",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_supported_freq_band,
          { "Supported frequency band", "ieee1905.supported.freq_band",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_event_notification_media_types,
          { "Media types", "ieee1905.event_notif.media_types",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_sender_al_id,
          { "Sender AL ID", "ieee1905.sender.al_id",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_push_button_event_msg_id,
          { "Push button event message ID", "ieee1905.sender.msg_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_sender_joining_interface,
          { "Joining MAC address of sender", "ieee1905.sender.joining_intf",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_new_device_interface,
          { "New device MAC address", "ieee1905.new_device.intf",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_device_al_mac,
          { "1905 device AL MAC address", "ieee1905.device_al_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_local_intf_oui,
          { "Local interface OUI", "ieee1905.local_intf.oui",
            FT_UINT24, BASE_OUI, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_local_intf_variant,
          { "Local interface variant index", "ieee1905.local_intf.variant",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_local_intf_variant_name,
          { "Local interface variant name", "ieee1905.local_intf.variant_name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_local_intf_url_count,
          { "Local interface URL octet count", "ieee1905.local_intf.url_byte_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_local_intf_spec_count,
          { "Local interface media specific count", "ieee1905.local_intf.media_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_local_intf_url,
          { "Local interface XML description URL", "ieee1905.local_intf.url",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_local_intf_spec,
          { "Local interface media specific info", "ieee1905.local_intf.spec_info",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dev_id_friendly_name,
          { "Device Id Friendly name", "ieee1905.device_id.friendly_name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dev_id_manuf_name,
          { "Device Id Manufacturer name", "ieee1905.device_id.manuf_name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dev_id_manuf_model,
          { "Device Id Manufacturer model", "ieee1905.device_id.manuf_model",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_control_url,
          { "Device control URL", "ieee1905.device.control_url",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ipv4_type_count,
          { "Count of IPv4 entries", "ieee1905.ipv4_type.count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_mac_address,
          { "MAC address", "ieee1905.ipv4_type.mac_address",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ipv4_addr_count,
          { "IPv4 address count", "ieee1905.ipv4_type.addr_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_addr_type,
          { "IPv4 address type", "ieee1905.ipv4_type.addr_type",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ipv4_addr,
          { "IPv4 address", "ieee1905.ipv4_type.ipv4_addr",
            FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dhcp_server,
          { "DHCP server", "ieee1905.ipv4_type.dhcp_server",
            FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ipv6_type_count,
          { "Count of IPv6 entries", "ieee1905.ipv6_type.count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ipv6_linklocal,
          { "Link local address", "ieee1905.ipv6_type.link_local",
            FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ipv6_mac_address,
          { "MAC address", "ieee1905.ipv6_type.mac_address",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ipv6_addr_count,
          { "IPv6 address count", "ieee1905.ipv6_type.addr_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ipv6_addr_type,
          { "IPv6 address type", "ieee1905.ipv6_type.addr_type",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ipv6_addr,
          { "IPv6 address", "ieee1905.ipv6_type.ipv6_addr",
            FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ipv6_dhcp_server,
          { "DHCP server", "ieee1905.ipv6_type.dhcp_server",
            FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_generic_phy_media_types,
          { "Generic Phy media type count", "ieee1905.button_push.phy_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_profile_version,
          { "1905 profile version type", "ieee1905.profile.version",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_power_off_intf_count,
          { "Powered off interface count", "ieee1905.power_off.intf_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_power_change_intf_count,
          { "Power change local interface count", "ieee1905.power_chg.intf_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_power_change_mac_addr,
          { "Power change interface MAc addr", "ieee1905.power_chg.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_power_change_state,
          { "Power change requested state", "ieee1905.power_chg.state",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_power_status_intf_count,
          { "Power status local interface count", "ieee1905.power_sts.intf_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_power_status_mac_addr,
          { "Power status interface MAc addr", "ieee1905.power_sts.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_power_status_state,
          { "Power change status", "ieee1905.power_sts.state",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_l2_neighbor_intf_count,
          { "L2 neighbor interface count", "ieee1905.l2_neighbor.intf_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_l2_local_intf_mac_addr,
          { "L2 neighbor local interface MAC addr", "ieee1905.l2_neighbor.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_l2_neighbor_dev_count,
          { "L2 neighbor device count", "ieee1905.l2_neighbor.dev_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_l2_neighbor_mac_addr,
          { "L2 neighbor interface MAC address", "ieee1905.l2_neighbor.neighbor_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_l2_behind_mac_addr_count,
          { "L2 neighbor behind MAC addr count", "ieee1905.l2_neighbor.neighbor_behind_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_l2_behind_mac_addr,
          { "L2 neighbor behind MAC addr", "ieee1905.l2_neighbor.neighbor_behind_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_supported_service_count,
          { "Supported service count", "ieee1905.supported_service.service_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_supported_service,
          { "Supported service", "ieee1905.supported_service.service",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_searched_service_count,
          { "Searched service count", "ieee1905.searched_service.service_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_searched_service,
          { "Searched service", "ieee1905.searched_service.service",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_radio_identifier,
          { "AP radio identifier", "ieee1905.ap_radio_identifier",
           FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_operatonal_bss_radio_count,
          { "AP operational BSS radio count", "ieee1905.ap_bss_radio_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_operational_intf_count,
          { "AP operational interface count", "ieee1905.ap_bss_intf_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_local_intf_mac_addr,
          { "AP operational local interface MAC addr", "ieee1905.ap_bss_local_intf_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_local_intf_ssid_len,
          { "AP operational BSS local interface SSID len", "ieee1905.ap_bss_local_intf_ssid_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_local_intf_ssid,
          { "AP operational BSS local interface SSID", "ieee1905.ap_bss_local_intf_ssid",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_capabilities_flags,
          { "AP capabilities flags", "ieee1905.ap_capability_flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_rpt_unsuccessful_associations,
          { "Report Unsuccessful Associations", "ieee1905.rpt_unsuccessful_assoc",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_sta_metrics_oper_flag,
          { "STA link metric reporting operational channels", "ieee1905.link_metric_oper",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80, NULL, HFILL }},

        { &hf_ieee1905_unassoc_sta_metrics_non_oper_flag,
          { "STA link metric reporting non-operational channels", "ieee1905.link_metric_non_oper",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40, NULL, HFILL }},

        { &hf_ieee1905_agent_init_steering,
          { "Agent-initiated RCPI-based Steering", "ieee1905.agent_init_steering",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20, NULL, HFILL }},

        { &hf_ieee1905_rpt_unsuccessful_assoc_report,
          { "Unsuccessful Association Attempts", "ieee1905.report_unsuccessful_associations",
            FT_BOOLEAN, 8, TFS(&tfs_ieee1905_report_unsuccessful_association_attempt_flag), 0x80, NULL, HFILL }},

        { &hf_ieee1905_higher_layer_protocol,
          { "Higher layer protocol", "ieee1905.higher_layer_proto",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_higher_layer_data,
          { "Higher layer data", "ieee1905.higher_layer_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_backhaul_station_mac,
          { "Associated backhaul station MAC address", "ieee1905.assoc.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_backhaul_target_bssid,
          { "Target BSS BSSID", "ieee1905.assoc.target_bssid",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_backhaul_steering_status,
          { "Status code", "ieee1905.assoc.status",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_backhaul_operating_class,
          { "Backhaul operating class", "ieee1905.assoc.operating_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_backhaul_channel_number,
          { "Backhaul beacon channel number", "ieee1905.assoc.channel_num",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_client_assoc_bssid,
          { "Target BSSID", "ieee1905.assoc_ctrl.bssid",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_association_control,
          { "Association control", "ieee1905.assoc_ctrl.control",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_association_control_validity,
          { "Request validity period", "ieee1905.assoc_ctrl.validity",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_client_assoc_sta_count,
          { "STA control list count", "ieee1905.assoc_ctrl.sta_list_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_client_assoc_mac_addr,
          { "Target STA MAC address", "ieee1905.assoc_ctrl.target_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_btm_reporter_bssid,
          { "BTM report source BSSID", "ieee1905.btm_report.source_bssid",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_btm_sta_mac_addr,
          { "BTM report target MAC address", "ieee1905.btm_report.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_btm_report_status,
          { "BTM status code", "ieee1905.btm_report.status",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_btm_report_bssid,
          { "BTM target BSSID", "ieee1905.btm_report.target_bssid",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_source_bss_bssid,
          { "Source BSS BSSID", "ieee1905.steering_req.source_bssid",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_request_flags,
          { "Steering request flags", "ieee1905.steering_req.flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_req_op_window,
          { "Steering opportunity window", "ieee1905.steering_req.window",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_request_mode_flag,
          { "Mode", "ieee1905.steering_req.mode",
            FT_BOOLEAN, 8, TFS(&tfs_ieee1905_steering_request_mode_flag), 0x80, NULL, HFILL }},

        { &hf_ieee1905_btm_disassoc_imminent_flag,
          { "BTM disassociation imminent", "ieee1905.steering_req.disassoc_imminent",
            FT_BOOLEAN, 8, TFS(&tfs_ieee1905_btm_disassoc_imminent_flag), 0x40, NULL, HFILL }},

        { &hf_ieee1905_btm_abridged_flag,
          { "BTM abridged", "ieee1905.steering_req.btm_abridged",
            FT_BOOLEAN, 8, TFS(&tfs_ieee1905_btm_abridged_flag), 0x20, NULL, HFILL }},

        { &hf_ieee1905_steering_req_reserved,
          { "Reserved", "ieee1905.steering_req.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }},

        { &hf_ieee1905_steering_btm_disass_timer,
          { "BTM disassociation timer", "ieee1905.steering_req.disass_timer",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_req_sta_count,
          { "STA list count", "ieee1905.steering_req.sta_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_req_target_bssid_count,
          { "Target BSSID list count", "ieee1905.steering_req.bssid_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_req_sta_mac,
          { "Target MAC address", "ieee1905.steering_req.target_mac",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_req_target_bssid,
          { "Target BSSID", "ieee1905.steering_req.target_bssid",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_req_oper_class,
          { "Target BSS operating class", "ieee1905.steering_req.oper_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_req_target_channel,
          { "Target BSS channel number", "ieee1905.steering_req.target_channel",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_client_bssid,
          { "Client BSSID", "ieee1905.client_info.bssid",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_client_mac_addr,
          { "Client MAC address", "ieee1905.client_info.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_client_capability_result,
          { "Result code", "ieee1905.client_capability.result",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_client_capability_frame,
          { "(Re)Association frame body", "ieee1905.client_capability.frame",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_association_flag,
          { "Association event", "ieee1905.assoc_event.assoc_event",
            FT_BOOLEAN, 8, TFS(&tfs_ieee1905_association_event_flag),
            0x80, NULL, HFILL }},

        { &hf_ieee1905_association_client_mac_addr,
          { "Client mac address", "ieee1905.assoc_event.client_mac",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_association_agent_bssid,
          { "Multi-AP agent BSSID", "ieee1905.assoc_event.agent_bssid",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_association_event_flags,
          { "Association event flags", "ieee1905.assoc_event.flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_radio_max_bss,
          { "Maximum BSS support", "ieee1905.radio_basic_cap.max_bss",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_radio_classes,
          { "Operating class count", "ieee1905.radio_basic.op_classes",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_radio_class,
          { "Operating class", "ieee1905.radio_basic.op_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_radio_eirp,
          { "Maximum transmit power EIRP", "ieee1905.radio_basic.max_power",
            FT_INT8, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_radio_non_op_count,
          { "Number of non-operable channels", "ieee1905.radio_basic.non_op_channels",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_radio_basic_non_op_channel,
          { "Statically non-operable channel", "ieee1905.radio_basic.non_op_channel",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_max_supported_tx_streams,
          { "Maximum supported Tx spatial streams", "ieee1905.ap_ht.max_tx_streams",
            FT_UINT8, BASE_HEX, VALS(max_supported_tx_streams_vals), 0xC0, NULL, HFILL}},

        { &hf_ieee1905_max_supported_rx_streams,
          { "Maximum supported Rx spatial streams", "ieee1905.ap_ht.max_rx_streams",
            FT_UINT8, BASE_HEX, VALS(max_supported_rx_streams_vals), 0x30, NULL, HFILL}},

        { &hf_ieee1905_short_gi_20mhz_flag,
          { "Short GI support for 20 MHz", "ieee1905.ap_ht.short_gi_20mhz",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08, NULL, HFILL}},

        { &hf_ieee1905_short_gi_40mhz_flag,
          { "Short GI support for 40 MHz", "ieee1905.ap_ht.short_gi_40mhz",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04, NULL, HFILL}},

        { &hf_ieee1905_ht_support_40mhz_flag,
          { "HT support for 40MHz", "ieee1905.ap_ht.ht_support_40mhz",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL}},

        { &hf_ieee1905_ap_ht_capabilities_radio_id,
          { "Radio unique ID", "ieee1905.ap_ht.radio_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ht_cap_flags,
          { "Capabilities", "ieee1905.ap_ht.caps",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_vht_max_supported_tx_streams,
          { "Maximum supported Tx spatial streams", "ieee1905.ap_vht.max_tx_streams",
            FT_UINT16, BASE_HEX, VALS(vht_he_max_supported_tx_streams_vals), 0xE000, NULL, HFILL}},

        { &hf_ieee1905_vht_max_supported_rx_streams,
          { "Maximum supported Rx spatial streams", "ieee1905.ap_vht.max_rx_streams",
            FT_UINT16, BASE_HEX, VALS(vht_he_max_supported_rx_streams_vals), 0x1C00, NULL, HFILL}},

        { &hf_ieee1905_short_gi_80mhz_flag,
          { "Short GI support for 80 MHz", "ieee1905.ap_vht.short_gi_80mhz",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0200, NULL, HFILL}},

        { &hf_ieee1905_short_gi_160mhz_flag,
          { "Short GI support for 160 and 80+80 MHz", "ieee1905.ap_vht.short_gi_160mhz",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0100, NULL, HFILL}},

        { &hf_ieee1905_vht_support_80plus_mhz_flag,
          { "VHT support for 80+80 MHz", "ieee1905.ap_vht.vht_80plus_mhz",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x80, NULL, HFILL}},

        { &hf_ieee1905_vht_support_160_mhz_flag,
          { "VHT support for 160 MHz", "ieee1905.ap_vht.vht_160mhz",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x40, NULL, HFILL}},

        { &hf_ieee1905_su_beamformer_capable_flag,
          { "SU beamformer capable", "ieee1905.ap_vht.su_beamformer",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x20, NULL, HFILL}},

        { &hf_ieee1905_mu_beamformer_capable_flag,
          { "MU beamformer capable", "ieee1905.ap_vht.mu_beamformer",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL}},

        { &hf_ieee1905_ap_vht_capabilities_radio_id,
          { "Radio unique ID", "ieee1905.ap_vht.radio_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_vht_cap_flags,
          { "Capabilities", "ieee1905.ap_vht.caps",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_vht_supported_vht_tx_mcs,
          { "Supported VHY Tx MCS", "ieee1905.vht.supported_tx_mcs",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_vht_supported_vht_rx_mcs,
          { "Supported VHY Rx MCS", "ieee1905.vht.supported_rx_mcs",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_clients_bss_count,
          { "Included BSS count", "ieee1905.assoc_client.bss_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_bssid,
          { "Associated BSS", "ieee1905.assoc_client.bss",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bss_client_count,
          { "Associated client count", "ieee1905.assoc_client.client_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bss_client_mac,
          { "Associated client MAC address", "ieee1905.assoc_client.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bss_client_last_assoc,
          { "Time since last association", "ieee1905.assoc_client.time_since",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_pref_preference,
          { "Preference", "ieee1905.channel_pref.pref",
            FT_UINT8, BASE_HEX, VALS(channel_preference_prefs_vals), 0xF0, NULL, HFILL}},
        { &hf_ieee1905_channel_pref_reason,
          { "Reason code", "ieee1905.channel_pref.reason",
            FT_UINT8, BASE_HEX, VALS(channel_preference_reason_vals), 0x0F, NULL, HFILL}},

        { &hf_ieee1905_channel_preference_radio_id,
          { "Radio unique ID", "ieee1905.channel_pref.radio_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_preference_class_count,
          { "Operating class count", "ieee1905.channel_prefs.class_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_pref_class,
          { "Operating class", "ieee1905.channel_prefs.class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_pref_channel_count,
          { "Channel list count", "ieee1905.channel_prefs.channel_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_pref_channel,
          { "Channel number", "ieee1905.channel_prefs.channel_no",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_prefs_flags,
          { "Channel preference flags", "ieee1905.channel_prefs.flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_trans_power_limit_radio_id,
          { "Radio unique ID", "ieee1905.transmit_power.radio_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_trans_power_limit_eirp,
          { "Transmit power limit EIRP per 20MHz", "ieee1905.transmit_power.eirp",
            FT_INT8, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_select_resp_radio_id,
          { "Radio unique ID", "ieee1905.channel_select.radio_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_radio_metrics_radio_id,
          { "Radio unique ID", "ieee1905.radio_metrics.radio_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_select_resp_code,
          { "Response coce", "ieee1905.channel_select.response_code",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_op_channel_report_radio_id,
          { "Radio unique ID", "ieee1905.operating_channel.radio_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_op_channel_report_classes,
          { "Currently operating classes", "ieee1905.operating_channel.classes",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_op_channel_class,
          { "Operating class", "ieee1905.operating_channel.op_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_op_channel_number,
          { "Operating channel number", "ieee1905.operating_channel.chan_num",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_op_channel_eirp,
          { "Current transmit power EIRP", "ieee1905.operating_channel.eirp",
            FT_INT8, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_he_cap_radio_id,
          { "Radio unique ID", "ieee1905.ap_he_capability.radio_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_he_cap_mcs_length,
          { "Supported HE MCS length", "ieee1905.ap_he_capability.he_mcs_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_he_cap_tx_mcs_le_80_mhz,
          { "Supported Tx HE-MCS <= 80 MHz",
            "ieee1905.ap_he_capability.supported_tx_he_mcs_le_80mhz",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_he_tx_mcs_map_1ss,
          { "Max Tx HE-MCS for 1 SS",
            "ieee1905.ap_he_capability.max_tx_he_mcs_1_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_1_ss_vals),
            0xC000, NULL, HFILL }},

        { &hf_ieee1905_ap_he_tx_mcs_map_2ss,
          { "Max Tx HE-MCS for 2 SS",
            "ieee1905.ap_he_capability.max_tx_he_mcs_2_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_2_ss_vals),
            0x3000, NULL, HFILL }},

        { &hf_ieee1905_ap_he_tx_mcs_map_3ss,
          { "Max Tx HE-MCS for 3 SS",
            "ieee1905.ap_he_capability.max_tx_he_mcs_3_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_3_ss_vals),
            0x0C00, NULL, HFILL }},

        { &hf_ieee1905_ap_he_tx_mcs_map_4ss,
          { "Max Tx HE-MCS for 4 SS",
            "ieee1905.ap_he_capability.max_tx_he_mcs_4_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_4_ss_vals),
            0x0300, NULL, HFILL }},

        { &hf_ieee1905_ap_he_tx_mcs_map_5ss,
          { "Max Tx HE-MCS for 5 SS",
            "ieee1905.ap_he_capability.max_tx_he_mcs_5_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_5_ss_vals),
            0x00C0, NULL, HFILL }},

        { &hf_ieee1905_ap_he_tx_mcs_map_6ss,
          { "Max Tx HE-MCS for 6 SS",
            "ieee1905.ap_he_capability.max_tx_he_mcs_6_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_6_ss_vals),
            0x0030, NULL, HFILL }},

        { &hf_ieee1905_ap_he_tx_mcs_map_7ss,
          { "Max Tx HE-MCS for 7 SS",
            "ieee1905.ap_he_capability.max_tx_he_mcs_7_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_7_ss_vals),
            0x000C, NULL, HFILL }},

        { &hf_ieee1905_ap_he_tx_mcs_map_8ss,
          { "Max Tx HE-MCS for 8 SS",
            "ieee1905.ap_he_capability.max_tx_he_mcs_8_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_8_ss_vals),
            0x0003, NULL, HFILL }},

        { &hf_ieee1905_ap_he_cap_rx_mcs_le_80_mhz,
          { "Supported Rx HE-MCS <= 80 MHz",
            "ieee1905.ap_he_capability.supported_rx_he_mcs_le_80mhz",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_he_rx_mcs_map_1ss,
          { "Max Rx HE-MCS for 1 SS",
            "ieee1905.ap_he_capability.max_rx_he_mcs_1_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_1_ss_vals),
            0xC000, NULL, HFILL }},

        { &hf_ieee1905_ap_he_rx_mcs_map_2ss,
          { "Max Rx HE-MCS for 2 SS",
            "ieee1905.ap_he_capability.max_rx_he_mcs_2_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_2_ss_vals),
            0x3000, NULL, HFILL }},

        { &hf_ieee1905_ap_he_rx_mcs_map_3ss,
          { "Max Rx HE-MCS for 3 SS",
            "ieee1905.ap_he_capability.max_rx_he_mcs_3_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_3_ss_vals),
            0x0C00, NULL, HFILL }},

        { &hf_ieee1905_ap_he_rx_mcs_map_4ss,
          { "Max Rx HE-MCS for 4 SS",
            "ieee1905.ap_he_capability.max_rx_he_mcs_4_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_4_ss_vals),
            0x0300, NULL, HFILL }},

        { &hf_ieee1905_ap_he_rx_mcs_map_5ss,
          { "Max Rx HE-MCS for 5 SS",
            "ieee1905.ap_he_capability.max_rx_he_mcs_5_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_5_ss_vals),
            0x00C0, NULL, HFILL }},

        { &hf_ieee1905_ap_he_rx_mcs_map_6ss,
          { "Max Rx HE-MCS for 6 SS",
            "ieee1905.ap_he_capability.max_rx_he_mcs_6_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_6_ss_vals),
            0x0030, NULL, HFILL }},

        { &hf_ieee1905_ap_he_rx_mcs_map_7ss,
          { "Max Rx HE-MCS for 7 SS",
            "ieee1905.ap_he_capability.max_rx_he_mcs_7_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_7_ss_vals),
            0x000C, NULL, HFILL }},

        { &hf_ieee1905_ap_he_rx_mcs_map_8ss,
          { "Max Rx HE-MCS for 8 SS",
            "ieee1905.ap_he_capability.max_rx_he_mcs_8_ss",
            FT_UINT16, BASE_DEC, VALS(max_he_mcs_8_ss_vals),
            0x0003, NULL, HFILL }},

        { &hf_ieee1905_ap_he_cap_tx_mcs_160_mhz,
          { "Supported Tx HE-MCS 160 MHz",
            "ieee1905.ap_he_capability.supported_tx_he_mcs_160mhz",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_he_cap_rx_mcs_160_mhz,
          { "Supported Rx HE-MCS 160 MHz",
            "ieee1905.ap_he_capability.supported_rx_he_mcs_160mhz",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_he_cap_tx_mcs_80p80_mhz,
          { "Supported Tx HE-MCS 80+80 MHz",
            "ieee1905.ap_he_capability.supported_tx_he_mcs_80p80mhz",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_he_cap_rx_mcs_80p80_mhz,
          { "Supported Rx HE-MCS 80+80 MHz",
            "ieee1905.ap_he_capability.supported_rx_he_mcs_80p80mhz",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_metrics_mac_count,
          {"MAC Addresses for this channel",
           "ieee1905.unassoc_sta_link_metrics.mac_count",
           FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_link_metrics_query_mac,
          { "STA MAC address", "ieee1905.unassoc_sta_link_metrics.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_metrics_reporting_interval,
          { "AP metrics reporting interval", "ieee1905.sta_metric_policy.ap_interval",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_metric_reporting_policy_radio_id,
          { "Radio ID", "ieee1905.metric_reporing_policy.radio_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_metric_reporting_radio_count,
          { "Radio count", "ieee1905.sta_metric_policy.radio_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_metric_rcpi_threshold,
          { "RCPI reporting threshold", "ieee1905.sta_metric_policy.rcpi_threshold",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(rcpi_threshold_custom),
            0, NULL, HFILL }},

        { &hf_ieee1905_metric_reporting_rcpi_hysteresis,
          {"STA Metrics Reporting RCPI Hysteresis Margin Override",
            "ieee1905.sta_metric_policy.rcpi_hysteresis_margin_override",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(rcpi_hysteresis_custom),
            0, NULL, HFILL }},

        { &hf_ieee1905_metrics_policy_flags,
          {"STA Metrics Reporting Policy Flags",
            "ieee1905.sta_metrics_policy_flags",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_traffic_stats_inclusion,
          { "Associated STA Traffic Stats Inclusion Policy",
             "ieee1905.sta_metrics_policy_flags.sta_traffic_stats_inclusion",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_link_metrics_inclusion,
          { "Associated STA Link Metrics Inclusion Policy",
             "ieee1905.sta_metrics_policy_flags.sta_link_metrics_inclusion",
          FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},

        { &hf_ieee1905_assoc_wf6_status_policy_inclusion,
          { "Associated Wi-Fi6 STA Status Inclusion Policy",
            "ieee1905.sta_metrics_policy_flags.wf6_sta_status_inclusion",
            FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},

        { &hf_ieee1905_reporting_policy_flags_reserved,
          { "Reserved", "ieee1905.sta_metrics_policy_flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }},

        { &hf_ieee1905_metrics_channel_util_threshold,
          { "Utilization Reporting threshold", "ieee1905.sta_metric_policy.utilization_threshold",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_metric_query_bssid_cnt,
          { "BSSID Count", "ieee1905.ap_metrics_query.bssid_cnt",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_metric_query_bssid,
          { "Query BSSID", "ieee1905.ap_metrics_query.bssid",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_sta_mac_address_type,
          { "MAC address", "ieee1905.sta_mac_addr_type.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_mac_addr,
          { "MAC address", "ieee1905.assoc_sta_link_metrics.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_bssid_count,
          { "Number of BSSIDs for STA", "ieee1905.assoc_sta_link_metrics.bssid_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_link_metrics_bssid,
          { "STA BSSID", "ieee1905.assoc_sta_link_metrics.bssid",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_link_metrics_time_delta,
          { "Measurement time delta", "ieee1905.assoc_sta_link_metrics.time_delta",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_link_metrics_dwn_rate,
          { "Downlink data rate", "ieee1905.assoc_sta_link_metrics.down_rate",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_link_metrics_up_rate,
          { "Uplink data rate", "ieee1905.assoc_sta_link_metrics.up_rate",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_link_metrics_rcpi,
          { "Measured uplink RCPI for STA", "ieee1905.assoc_sta_link_metrics.rcpi",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_wf6_sta_mac_addr,
          { "MAC address", "ieee1905.assoc_wf6_sta_status_report.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_wf6_sta_tid_count,
          { "Number of Wi-Fi 6 TIDs",
            "ieee1905.assoc_wf6_sta_status_report.tid_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_wf6_sta_tid,
          { "TID", "ieee1905.assoc_wf6_sta_status_report.tid",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_wf6_sta_queue_size,
          { "Queue Size", "ieee1905.assoc_wf6_sta_status_report.queue_size",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_ext_link_metrics_mac_addr,
          { "Associated STA MAC Address",
            "ieee1905.assoc_sta_extended_link_metrics.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_ext_link_metrics_count,
          { "BSSID count", "ieee1905.assoc_sta_extended_link_metrics.count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_extended_metrics_bssid,
          { "BSSID", "ieee1905.assoc_sta_extended_link_metrics.bssid",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_extended_metrics_lddlr,
          { "Last Data Downlink Rate",
            "ieee1905.assoc_sta_extended_link_metrics.lddlr",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_extended_metrics_ldulr,
          { "Last Data Uplink Rate",
            "ieee1905.assoc_sta_extended_link_metrics.ldulr",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_extended_metrics_ur,
          { "Utilization Receive",
            "ieee1905.assoc_sta_extended_link_metrics.ur",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_extended_metrics_tr,
          { "Utilization Transmit",
            "ieee1905.assoc_sta_extended_link_metrics.ut",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_sta_link_metrics_class,
          { "Operating class", "ieee1905.unassoc_sta_link_metrics.operaring_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_sta_link_channel_count,
          { "Channel count", "ieee1905.unassoc_sta_link_metrics.channel_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_metrics_channel,
          { "Channel number", "ieee1905.unassoc_sta_link_metrics.channel",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_he_max_supported_tx_streams,
          { "Maximum supported Tx spatial streams", "ieee1905.he_cap.max_tx_streams",
            FT_UINT16, BASE_HEX, VALS(vht_he_max_supported_tx_streams_vals), 0xE000, NULL, HFILL}},

        { &hf_ieee1905_he_max_supported_rx_streams,
          { "Maximum supported Rx spatial streams", "ieee1905.he_cap.max_rx_streams",
            FT_UINT16, BASE_HEX, VALS(vht_he_max_supported_rx_streams_vals), 0x1C00, NULL, HFILL}},

        { &hf_ieee1905_he_support_80plus_mhz_flag,
          { "HE support for 80+80 MHz", "ieee1905.ap_he.he_80plus_mhz",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported),
            0x0200, NULL, HFILL}},

        { &hf_ieee1905_he_support_160mhz_flag,
          { "HE support for 160 MHz", "ieee1905.ap_he.he_160_mhz",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0100, NULL, HFILL}},

        { &hf_ieee1905_he_su_beamformer_capable_flag,
          { "SU beanformer capable", "ieee1905.ap_he.su_beamformer",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0080, NULL, HFILL}},

        { &hf_ieee1905_he_mu_beamformer_capable_flag,
          { "MU beamformer capable", "ieee1905.ap_he.mu_beamformer",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0040, NULL, HFILL}},

        { &hf_ieee1905_ul_mu_mimo_capable_flag,
          { "UL MU-MIMO capable", "ieee1905.ap_he.ul_mu_mimo",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0020, NULL, HFILL}},

        { &hf_ieee1905_ul_mu_mimo_ofdma_capable_flag,
          { "UL MU-MIMO OFDMA capable", "ieee1905.ap_he.he_ul_mu_mimo_ofdma",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0010, NULL, HFILL}},

        { &hf_ieee1905_dl_mu_mimo_ofdma_capable_flag,
          { "DL MU-MIMO OFDMA capable", "ieee1905.ap_he.he_dl_mu_mimo_ofdma",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0008, NULL, HFILL}},

        { &hf_ieee1905_ul_ofdma_capable,
          { "UL OFDMA capable", "ieee1905.ap_he.he_ul_ofdma",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0004, NULL, HFILL}},

        { &hf_ieee1905_dl_ofdma_capable,
          { "DL OFDMA capable", "ieee1905.ap_he.he_dl_ofdma",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0002, NULL, HFILL}},

        { &hf_ieee1905_he_cap_flags,
          { "Capabilities", "ieee1905.ap_he.caps",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_policy_local_disallowed_count,
          { "Local steering disallowed STA count", "ieee1905.steering_policy.local_disallow_sta",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_disallowed_mac_addr,
          { "Local steering disallowed MAC address", "ieee1905.steering_policy.local_disallow_mac",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_btm_steering_disallowed_count,
          { "BTM steering disallowed count", "ieee1905.steering_policy.btm_disall_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_btm_steering_disallowed_mac_addr,
          { "Local steering disallowed MAC address", "ieee1905.steering_policy.local_disallow_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_policy_radio_count,
          { "Steering policy radio count", "ieee1905.steering_policy.radio_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_policy_radio_id,
          { "Radio unique ID", "ieee1905.steering_policy.radio_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_policy_policy,
          { "Steering policy", "ieee1905.steering_policy.policy",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_policy_util,
          { "Channel utilization threshold", "ieee1905.steering_policy.utilization_threshold",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_policy_rcpi_threshold,
          { "RCPI steering threshold", "ieee1905.steering_policy.rcpi_threshold",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_radio_restriction_radio_id,
          { "Radio unique ID", "ieee1905.radio_restriction.radio_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_radio_restriction_op_class_count,
          { "Restricted operating classes", "ieee1905.radio_restriction.classes",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_radio_restriction_op_class,
          { "Restricted operating class", "ieee1905.radio_restriction.class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_radio_restriction_chan_count,
          { "Channel count", "ieee1905.radio_restriction.channel_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_radio_restriction_channel,
          { "Restricted channel", "ieee1905.radio_restriction.channel",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_radio_restriction_min_separation,
          { "Minimum separation", "ieee1905.radio_restriction.min_sep",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_include_estimated_spi_ac_eq_be,
          { "Include Estimated Service Parameters Information for AC=BE",
             "ieee1905.ap_metrics.include_ac_eq_be_params",
           FT_BOOLEAN, 8, TFS(&tfs_included_not_included), 0x80, NULL, HFILL }},

        { &hf_ieee1905_include_estimated_spi_ac_eq_bk,
          { "Include Estimated Service Parameters Information for AC=BK",
             "ieee1905.ap_metrics.include_ac_eq_bk_params",
           FT_BOOLEAN, 8, TFS(&tfs_included_not_included), 0x40, NULL, HFILL }},

        { &hf_ieee1905_include_estimated_spi_ac_eq_vo,
          { "Include Estimated Service Parameters Information for AC=VO",
             "ieee1905.ap_metrics.include_ac_eq_vo_params",
           FT_BOOLEAN, 8, TFS(&tfs_included_not_included), 0x20, NULL, HFILL }},

        { &hf_ieee1905_include_estimated_spi_ac_eq_vi,
          { "Include Estimated Service Parameters Information for AC=VI",
             "ieee1905.ap_metrics.include_ac_eq_vi_params",
           FT_BOOLEAN, 8, TFS(&tfs_included_not_included), 0x10, NULL, HFILL }},

        { &hf_ieee1905_ap_metrics_agent_bssid,
          { "Multi-AP agent BSSID", "ieee1905.ap_metrics.bssid",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_metrics_channel_utilization,
          { "Channel utilization", "ieee1905.ap_metrics.channel_util",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_metrics_sta_count,
          { "BSS STA count", "ieee1905.ap_metrics.sta_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_metrics_flags,
          { "Estimated Service Parameters Flags", "ieee1905.ap_metrics.flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_metrics_service_params_be,
          { "Estimated service parameters AC=BE", "ieee1905.ap_metrics.est_param_be",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_metrics_service_params_bk,
          { "Estimated service parameters AC=BK", "ieee1905.ap_metrics.est_param_bk",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_metrics_service_params_vo,
          { "Estimated service parameters AC=VO", "ieee1905.ap_metrics.est_param_vo",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_metrics_service_params_vi,
          { "Estimated service parameters AC=VI", "ieee1905.ap_metrics.est_param_vi",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_sta_link_metric_op_class,
          { "Operating class", "ieee1905.unassoc_sta_link_metrics.op_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_sta_link_metric_sta_count,
          { "STA count", "ieee1905.unassoc_sta_link_metrics.sta_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_link_metric_mac_addr,
          { "STA MAC address", "ieee1905.unassoc_sta_link_metrics.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_link_metric_channel,
          { "Channel number", "ieee1905.unassoc_sta_link_metrics.channel",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_link_metric_delta,
          { "Time delta (ms)", "ieee1905.unassoc_sta_link_metrics.delta",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_query_mac_addr,
          { "Associated STA MAC address", "ieee1905.beacon_metrics.assoc_sta_mac",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_link_metric_uplink_rcpi,
          { "Uplink RCPI", "ieee1905.unassoc_sta_link_metrics.rcpi",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_query_op_class,
          { "Operating class", "ieee1905.beacon_metrics.op_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_query_channel,
          { "Channel number", "ieee1905.beacon_metrics.channel_number",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_query_bssid,
          { "BSSID", "ieee1905.beacon_metrics.bssid",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_query_detail,
          { "Reporting detail", "ieee1905.beacon_metrics.detail",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_query_ssid_len,
          { "SSID length", "ieee1905.beacon_metrics.ssid_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_query_ssid,
          { "SSID", "ieee1905.beacon_metrics.ssid",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_channel_count,
          { "Channel reports number", "ieee1905.beacon_metrics.report_number",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_report_len,
          { "Channel report length", "ieee1905.beacon_metrics.report_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_report_op_class,
          { "Channel report operating class", "ieee1905.beacon_metrics.op_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_report_channel_id,
          { "Channel number", "ieee1905.beacon_metrics.channel_number",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_measurement_report,
          { "Measurement Report", "ieee1905.measurement_report",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_response_mac_addr,
          { "STA MAC address", "ieee1905.beacon_metrics.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_response_reserved,
          { "Reserved", "ieee1905.beacon_metrics.reserved",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_response_meas_num,
          { "Number of Measurements", "ieee1905.beacon_metrics.number_of_measurements",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_traffic_stats_mac_addr,
          { "Associated STA MAC address", "ieee1905.assoc_sta_traffic_stats.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_traffic_stats_bytes_sent,
          { "Bytes Sent", "ieee1905.assoc_sta_traffic_stats.bytes_sent",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_traffic_stats_bytes_rcvd,
          { "Bytes Received", "ieee1905.assoc_sta_traffic_stats.bytes_rcvd",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_traffic_stats_packets_sent,
          { "Packets Sent", "ieee1905.assoc_sta_traffic_stats.packets_sent",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_traffic_stats_packets_rcvd,
          { "Packets Received", "ieee1905.assoc_sta_traffic_stats.packets_rcvd",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_traffic_stats_tx_pkt_errs,
          { "Tx Packet Errors", "ieee1905.assoc_sta_traffic_stats.tx_pkt_errs",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_traffic_stats_rx_pkt_errs,
          { "Rx Packet Errors", "ieee1905.assoc_sta_traffic_stats.rx_packet_errs",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_assoc_sta_traffic_stats_retrans_count,
          { "Retransmission Count", "ieee1905.assoc_sta_traffic_stats.retrans_count",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_error_code_value,
          { "Reason code", "ieee1905.error_code.reason",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_error_code_mac_addr,
          { "MAC address of error-code STA", "ieee1905.error_code.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_rep_policy,
          { "Reporting Policy", "ieee1905.channel_scan_reporting_policy",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_pol_report,
          { "Report Independent Channel Scans",
            "ieee1905.channel_scan_reporting_policy.report_independent_channel_scans",
            FT_BOOLEAN, 8, TFS(&report_independent_scans_tfs), 0x01, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_pol_reserved,
          { "Reserved", "ieee1905.channel_scan_reporting_policy.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFE, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_capabilities_radio_num,
          { "Number of radios", "ieee1905.channel_scan_capabilities.num_radios",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_capa_radio_id,
          { "Radio Unique ID", "ieee1905.channel_scan_capabilities.radio_id",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_capa_flags,
          { "Flags", "ieee1905.channel_scan_capabilities.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_capa_flags_on_boot_only,
          { "On boot only", "ieee1905.channel_scan_capabilities.flags.on_boot_only",
            FT_BOOLEAN, 8, TFS(&channel_scan_capa_flags_on_boot_only_tfs),
            0x80, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_capa_flags_scan_impact,
          { "Scan Impact", "ieee1905.channel_scan_capabilities.flags.scan_impact",
            FT_UINT8, BASE_HEX, VALS(channel_scan_capa_flags_impact_vals), 0x60,
            NULL, HFILL }},

        { &hf_ieee1905_channel_scan_capa_flags_reserved,
          { "Reserved", "ieee1905.channel_scan_capabilities.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_capa_min_scan_interval,
          { "Minimum Scan Interval", "ieee1905.channel_scan_capabilities.min_scan_interval",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_seconds,
            0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_capa_class_num,
          { "Number of Operating Classes",
            "ieee1905.channel_scan_capabilities.num_operating_classes",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_capa_oper_class,
          { "Operating Class", "ieee1905.channel_scan_capabilities.operating_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_capa_oper_class_chan_cnt,
          { "Number of Channels", "ieee1905.channel_scan_capabilities.operating_class.num_channels",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_capa_channel,
          { "Channel", "ieee1905.channel_scan_capabilities.operating_class.channel",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_request_flags,
          { "Flags", "ieee1905.channel_scan_request.flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_request_flags_fresh_scan,
          { "Perform Fresh Scan", "ieee1905.channel_scan_request.flags.perform_fresh_scan",
            FT_BOOLEAN, 8, TFS(&perform_fresh_scan_tfs), 0x80, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_request_flags_reserved,
          { "Reserved", "ieee1905.channel_scan_request.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_request_radio_num,
          { "Number of Radios", "ieee1905.channel_scan_request.number_radios",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_request_radio_id,
          { "Radio Unique ID", "ieee1905.channel_scan_request.radio_id",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_request_class_num,
          { "Number of Operating Classes",
            "ieee1905.channel_scan_request.num_operating_classes",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_request_oper_class,
          { "Operating Class", "ieee1905.channel_scan_request.operating_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_request_oper_class_chan_cnt,
          { "Number of Channels", "ieee1905.channel_scan_request.operating_class.num_channels",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_request_channel,
          { "Channel", "ieee1905.channel_scan_request.channel",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_radio_id,
          { "Radio Unique ID", "ieee1905.channel_scan_result.radio_id",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_oper_class,
          { "Operating Class", "ieee1905.channel_scan_result.operating_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_channel,
          { "Channel", "ieee1905.channel_scan_result.channel",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_status,
          { "Status", "ieee1905.channel_scan_result.status",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(channel_scan_result_status_rvals),
            0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_timestamp_len,
          { "Timestamp Length", "ieee1905.channel_scan_result.timestamp_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_timestamp_string,
          { "Timestamp", "ieee1905.channel_scan_result.timestamp",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_utilization,
          { "Utilization", "ieee1905.channel_scan_result.utilization",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_noise,
          { "Noise", "ieee1905.channel_scan_result.noise",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_radio_metrics_noise,
          { "Noise", "ieee1905.radio_metrics.noise",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_radio_metrics_transmit,
          { "Transmit", "ieee1905.radio_metrics.transmit",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_radio_metrics_receive_self,
          { "ReceiveSelf", "ieee1905.radio_metrics.receive_self",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_radio_metrics_receive_other,
          { "ReceiveOther", "ieee1905.radio_metrics.receive_other",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_extended_metrics_bssid,
          { "BSSID", "ieee1905.ap_extended_metrics.bssid",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_extended_metrics_unicast_sent,
          { "UnicastBytesSent",
            "ieee1905.ap_extended_metrics.unicast_bytes_sent",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_extended_metrics_unicast_rcvd,
          { "UnicastBytesReceived",
            "ieee1905.ap_extended_metrics.unicast_bytes_received",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_extended_metrics_multicast_sent,
          { "MulticastBytesSent",
            "ieee1905.ap_extended_metrics.multicast_bytes_sent",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_extended_metrics_multicast_rcvd,
          { "MulticastBytesReceived",
            "ieee1905.ap_extended_metrics.multicast_bytes_received",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_extended_metrics_bcast_sent,
          { "BroadcastBytesSent",
            "ieee1905.ap_extended_metrics.Broadcast_bytes_sent",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_extended_metrics_bcast_rcvd,
          { "BroadcastBytesReceived",
            "ieee1905.ap_extended_metrics.broadcast_bytes_received",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_neigh_num,
          { "Number of Neighbors", "ieee1905.channel_scan_result.number_of_neighbors",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_bssid,
          { "BSSID", "ieee1905.channel_scan_result.bssid",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_ssid_len,
          { "SSID Length", "ieee1905.channel_scan_result.ssid_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_ssid,
          { "SSID", "ieee1905.channel_scan_result.ssid",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_sig_level,
          { "Signal Strength", "ieee1905.channel_scan_result.signal_strength",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_bw_len,
          { "Channel BW Length", "ieee1905.channel_scan_result.channel_bw_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_bw,
          { "Channel BW", "ieee1905.channel_scan_result.channel_bw",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_neigh_flags,
          { "Neighbor Flags", "ieee1905.channel_scan_result.neighbor_flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_load_element_present,
          { "Utilization Present", "ieee1905.channel_scan_result.neighbor_flags.load_element_present",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_util,
          { "Channel Utilization", "ieee1905.channel_scan_result.channel_util",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_sta_count,
          { "Station Count", "ieee1905.channel_scan_result.station_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_neigh_reserved,
          { "Reserved", "ieee1905.channel_scan_result.neighbor_flags.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_scan_duration,
          { "Scan Duration", "ieee1905.channel_scan_result.scan_duration",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_flags,
          { "Flags", "ieee1905.channel_scan_result.flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_scan_type,
          { "Scan Type", "ieee1905.channel_scan_result.flags.scan_type",
            FT_BOOLEAN, 8, TFS(&channel_scan_result_type_tfs), 0x80, NULL, HFILL }},

        { &hf_ieee1905_channel_scan_result_scan_flags_reserved,
          { "Reserved", "ieee1905.channel_scan_result.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL }},

        { &hf_ieee1905_timestamp_length,
          { "Timestamp Length", "ieee1905.timestamp.length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_timestamp_string,
          { "Timestamp", "ieee1905.timestamp.timestamp",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_1905_layer_sec_capa_onboarding,
          { "Onboarding Protocols Supported", "ieee1905.1905_layer_security_capability.onboarding_protocols_supported",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(onboarding_protocol_supported_rvals),
            0, NULL, HFILL }},

        { &hf_ieee1905_1905_layer_sec_capa_mic_sup,
          { "Message Integrity Algorithms Supported",
            "ieee1905.1905_layer_security_capability.message_integrity_algorithms_supported",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(message_integrity_algorithms_sup_rvals),
            0, NULL, HFILL }},

        { &hf_ieee1905_1905_layer_sec_capa_enc_alg_sup,
          { "Message Encryption Algorithms Supported",
            "ieee1905.1905_layer_security_capability.message_encryption_algorithms_supported",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(message_encryption_algorithms_sup_rvals),
            0, NULL, HFILL }},

        { &hf_ieee1905_ap_wf6_capa_radio_id,
          { "Radio ID", "ieee1905.ap_wifi_6_capabilities.radio_id",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_role_count,
          { "Role Count", "ieee1905.ap_wifi_6_capabilities.role_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_agent_role_flags,
          { "Role Flags", "ieee1905.ap_wifi_6_capabilities.role_flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_capa_agents_role,
          { "Agent's Role", "ieee1905.ap_wifi_6_capabilities.agents_role",
            FT_UINT8, BASE_HEX, VALS(ap_wf6_agent_role_vals),
            0xC0, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_capa_he_160_support,
          { "Support for HE 160 MHz",
            "ieee1905.ap_wifi_6_capabilities.support_for_he_160",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x20, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_capa_he_80p80_support,
          { "Support for HE 80+80 MHz",
            "ieee1905.ap_wifi_6_capabilities.support_for_he_80_p_80",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x10, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_capa_reserved,
          { "Reserved", "ieee1905.ap_wifi_6_capabilities.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_he_supported_flags,
          { "HE Support flags",
            "ieee1905.ap_wifi_6_capabilities.he_support_flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_su_beamformer,
          { "SU Beamformer", "ieee1905.ap_wifi_6_capabilities.su_beamformer",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x80, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_su_beamformee,
          { "SU Beamformee", "ieee1905.ap_wifi_6_capabilities.su_beamformee",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x40, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_mu_beamformer_status,
          { "MU Beamformer Status",
            "ieee1905.ap_wifi_6_capabilities.mu_beamformer_status",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x20, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_beamformee_sts_le_80mhz,
          { "Beamformee STS <= 80MHz",
            "ieee1905.ap_wifi_6_capabilities.beamformee_sts_le_80mhz",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x10, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_beamformee_sts_gt_80mhz,
          { "Beamformee STS > 80MHz",
            "ieee1905.ap_wifi_6_capabilities.beamformee_sts_gt_80mhz",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x08, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_ul_mu_mimo,
          { "UL MU MIMO", "ieee1905.ap_wifi_6_capabilities.us_mu_mimo",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x04, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_ul_ofdma,
          { "UL OFDMA", "ieee1905.ap_wifi_6_capabilities.ul_ofdma",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x02, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_dl_ofdma,
          { "DL OFDMA", "ieee1905.ap_wifi_6_capabilities.dl_ofdma",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x01, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_mimo_max_flags,
          { "MIMO Max Users flags",
            "ieee1905.ap_wifi_6_capabilities.mimo_max_users_flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_max_ap_dl_mu_mimo_tx,
          { "Max AP DL MU-MIMO TX",
            "ieee1905.ap_wifi_6_capabilities.max_ap_dl_mu_mimo_tx",
            FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_max_ap_ul_mu_mimi_rx,
          { "Max AP UL MU-MIMO RX",
            "ieee1905.ap_wifi_6_capabilities.max_ap_ul_mu_mimo_rx",
            FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_dl_ofdma_max_tx,
          { "Max users per DL OFDMA TX in AP role",
            "ieee1905.ap_wifi_6_capabilities.ap_max_users_per_dl_ofdma_tx",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_ul_ofdma_max_rx,
          { "Max users per UL OFDMA RX in AP role",
            "ieee1905.ap_wifi_6_capabilities.ap_max_users_per_ul_ofdma_rx",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_gen_flags,
          { "General flags", "ieee1905.ap_wifi_6_capabilities.general_flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_gen_rts,
          { "RTS", "ieee1905.ap_wifi_6_capabilities.general_flags.rts",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x80, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_gen_mu_rts,
          { "MU RTS", "ieee1905.ap_wifi_6_capabilities.general_flags.mu_rts",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x40, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_gen_multi_bssid,
          { "Multi-BSSID",
            "ieee1905.ap_wifi_6_capabilities.general_flags.multi_bssid",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x20, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_gen_mu_edca,
          { "MU EDCA", "ieee1905.ap_wifi_6_capabilities.general_flags.mu_edca",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x10, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_gen_twt_requester,
          { "TWT Requester",
            "ieee1905.ap_wifi_6_capabilities.general_flags.twt_requester",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x08, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_gen_twt_responder,
          { "TWT Responder",
            "ieee1905.ap_wifi_6_capabilities.general_flags.twt_responder",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x04, NULL, HFILL}},

        { &hf_ieee1905_ap_wf6_gen_reserved,
          { "Reserved",
            "ieee1905.ap_wifi_6_capabilities.general_flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }},

        { &hf_ieee1905_agent_list_bytes,
          { "Agent List", "ieee1905.agent_list.agent_list_data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_loop_prevention_mech_setting,
          {"Loop Prevention Mechanism Setting",
           "ieee1905.loop_prevention_mechanism_setting.setting",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_loop_prevention_mechanism,
          { "Loop Prevention Mechanism",
           "ieee1905.loop_prevention_mechanism_setting.loop_prevention_mech",
           FT_UINT8, BASE_HEX, VALS(loop_prev_mech_vals), 0xC0, NULL, HFILL }},

        { &hf_ieee1905_loop_prevention_preferred_backhaul_intf,
          { "Preferred Backhaul Interface",
           "ieee1905.loop_prevention_mechanism_setting.preferred_backhaul_intf",
           FT_UINT8, BASE_HEX, VALS(pref_backhaul_intf_vals), 0x30,
           NULL, HFILL }},

        { &hf_ieee1905_loop_detection_sequence_number,
          { "Loop Detection Sequence Number",
            "ieee1905.loop_detection_sequence_number.sequence_number",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_loop_prevention_reserved,
          { "Reserved",
           "ieee1905.loop_prevention_mechanism_setting.reserved",
           FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }},

        { &hf_ieee1905_group_integrity_key_id,
          { "Group Integrity Key ID",
            "ieee1905.group_integrity_key.group_integrity_key_id",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_group_integrity_key_len,
          { "Group Integrity Key ID Length",
            "ieee1905.group_integrity_key.group_integrity_key_id_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_group_integrity_key_bytes,
          { "Group Integrity Key",
            "ieee1905.group_integrity_key.group_integrity_key",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_group_integrity_key_mic_alg,
          { "MIC Algorithm", "ieee1905.group_integrity_key.mic_algorithm",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(group_integrity_key_mic_alg_rvals),
            0, NULL, HFILL }},

        { &hf_ieee1905_mic_group_temporal_key_id,
          { "Group Temporal Key ID", "ieee1905.mic.group_temporal_key_id",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_1905_gtk_key_id,
          { "MIC Version", "ieee1905.mic.group_temporal_key_id.mic_version",
            FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},

        { &hf_ieee1905_mic_version,
          { "MIC Version", "ieee1905.mic.group_temporal_key_id.mic_version",
            FT_UINT8, BASE_HEX, VALS(mic_version_vals), 0x30, NULL, HFILL }},

        { &hf_ieee1905_mic_reserved,
          { "Reserved", "ieee1905.mic.group_temporal_key_id.reserved",
             FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }},

        { &hf_ieee1905_mic_integrity_transmission_counter,
          { "Integrity Transmission Counter",
            "ieee1905.mic.integrity_transmission_counter",
            FT_UINT48, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_mic_source_la_mac_id,
          {"Source LA MAC ID", "ieee1905.mic.source_la_max_id",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_mic_length,
          { "MIC Length", "ieee1905.mic.mic_length",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_mic_bytes,
          { "MIC", "ieee1905.mic.mic_bytes",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_encrypted_enc_transmission_count,
          { "Encryption Transmission Counter",
            "ieee1905.encrypted.encryption_transmission_counter",
            FT_UINT48, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_encrypted_dest_al_mac_addr,
          { "Destination 1905 AL MAC Address",
            "ieee1905.encrypted.destination_1905_al_mac",
            FT_ETHER, ENC_NA, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_encrypted_source_la_mac_id,
          { "Source AL MAC", "ieee1905.encrypted.source_al_mac",
            FT_ETHER, ENC_NA, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_encrypted_enc_output_field_len,
          { "AES-SIV Encrypted Output Length",
            "ieee1905.encrypted.aes_siv_encrypted_output_length",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_encrypted_enc_output_field,
          { "AES-SIV Encryption Output",
            "ieee1905.encrypted.aes_siv_encryption_output",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_cac_request_radio_count,
          { "Number of Radios", "ieee1905.cac_request.number_of_radios",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_cac_request_radio_id,
          { "Radio ID", "ieee1905.cac_request.radio_id",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_cac_request_op_class,
          { "Operating class", "ieee1905.cac_request.operating_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_cac_request_channel,
          { "Channel", "ieee1905.cac_request.channel",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_cac_request_flags,
          { "Request flags", "ieee1905.cac_request.flags",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_cac_request_method,
          { "CAC Method", "ieee1905.cac_request.flags.cac_method",
            FT_UINT8, BASE_DEC, VALS(cac_request_method_vals),
            0xE0, NULL, HFILL }},

        { &hf_ieee1905_cac_request_completion_action,
          { "Successful Completion Action",
            "ieee1905.cac_request.flags.successful_completion_action",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(cac_completion_action_vals), 0x18, NULL, HFILL }},

        { &hf_ieee1905_cac_request_completion_unsuccess,
          { "Unsuccessful Completion Action",
            "ieee1905.cac_request.flags.unsuccessful_completion_action",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(cac_completion_action_vals), 0x06, NULL, HFILL }},

        { &hf_ieee1905_cac_request_reserved,
          { "Reserved", "ieee1905.cac_request.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL }},

        { &hf_ieee1905_cac_termination_radio_count,
          { "Number of Radios", "ieee1905.cac_termination.number_of_radios",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_terminate_radio_id,
          { "Radio ID", "ieee1905.cac_termination.radio_id",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_terminate_op_class,
          { "Operating class", "ieee1905.cac_termination.operating_class",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_terminate_channel,
          { "Channel", "ieee1905.cac_termination.channel",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_terminate_action,
          { "CAC Termination Action", "ieee1905.cac_termination.action",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(cac_completion_action_vals), 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_completion_rep_radio_count,
          { "Number of radios",
            "ieee1905.cac_completion_report.number_of_radios",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_cac_completion_radio_id,
          { "Radio ID", "ieee1905.cac_completion_report.radio_id",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_cac_completion_op_class,
          { "Operating class", "ieee1905.cac_completion_report.operating_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_cac_completion_channel,
          { "Channel", "ieee1905.cac_completion_report.channel",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_cac_completion_status,
          { "CAC Completion Status",
            "ieee1905.cac_completion_report.cac_completion_status",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(cac_completion_status_rvals), 0, NULL, HFILL }},

        { &hf_ieee1905_cac_completion_radar_count,
          { "Radar detected count",
            "ieee1905.cac_completion_report.radar_detected_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_cac_comp_radar_op_class,
          { "Operating class",
            "ieee1905.cac_completion_report.radar.operating_class",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_comp_radar_channel,
          { "Channel", "ieee1905.cac_completion_report.radar.channel",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_status_rpt_active_chan,
          { "Available Channel Count",
            "ieee1905.cac_status_report.available_channel_count",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_status_rpt_avail_op_class,
          { "Operating Class",
            "ieee1905.cac_status_report.available_channel.operating_class",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_status_rpt_avail_channel,
          { "Channel",
            "ieee1905.cac_status_report.available_channel.channel",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_status_rpt_avail_minutes,
          { "Minutes since CAC completed",
            "ieee1905.cac_status_report.available_channel.minutes_since",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_status_rpt_non_occ_cnt,
          { "Non-occupied Channel Count",
            "ieee1905.cac_status_report.non_occupied_channel_count",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_status_rpt_non_occ_op_class,
          { "Operating Class",
            "ieee1905.cac_status_report.non_occupied_channel.operating_class",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_status_rpt_non_occ_channel,
          { "Channel",
            "ieee1905.cac_status_report.non_occupied_channel.channel",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_status_rpt_non_occ_seconds,
          { "Seconds remaining",
            "ieee1905.cac_status_report.non_occupied_channel.second_remaining",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_status_rpt_active_cac_cnt,
          { "Active CAC Channel Count",
            "ieee1905.cac_status_report.active_cac_channel_count",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_status_rpt_active_cac_op_class,
          { "Operating Class",
            "ieee1905.cac_status_report.active_cac.operating_class",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_status_rpt_active_cac_channel,
          { "Channel",
            "ieee1905.cac_status_report.active_cac.channel",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_status_rpt_active_cac_seconds,
          { "Seconds remaining",
            "ieee1905.cac_status_report.active_cac.seconds_remaining",
            FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_capa_country_code,
          { "Country Code", "ieee1905.cac_capabilities.country_code",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_capa_radio_cnt,
          { "Number of radios", "ieee1905.cac_capabilities.number_of_radios",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_capabilities_radio_id,
          { "Radio ID", "ieee1905.cac_capabilities.radio_id",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_capabilities_types_num,
          { "Number of types", "ieee1905.cac_capabilities.number_of_types",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_capabilities_cac_mode,
          { "CAC mode supported",
            "ieee1905.cac_capabilities.cac_mode_supported",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(cac_mode_supported_rvals), 0, NULL, HFILL }},

        { &hf_ieee1905_cac_capabilities_cac_seconds,
          { "Seconds required to complete CAC",
            "ieee1905.cac_capabilities.seconds_required_to_complete_cac",
            FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_capabilities_op_class_num,
          { "Operating Class number",
            "ieee1905.cac_capabilities.operating_class_number",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_capabilities_op_class,
          { "Operating Class", "ieee1905.cac_capabilities.operating_class",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_capabilities_channel_cnt,
          { "Number of channels",
            "ieee1905.cac_capabilities.number_of_channels",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_cac_capabillity_channel,
          { "Channel", "ieee1905.cac_capabilities.channel",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_multi_ap_version,
          { "Multi-AP Profile", "ieee1905.multi_ap_version",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(multi_ap_version_rvals), 0x0, NULL, HFILL }},

        { &hf_ieee1905_max_total_serv_prio_rules,
          { "Max Total Number Service Prioritization Rules",
            "ieee1905.r2_ap_capabilities.max_total_service_prio_rules",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_r2_ap_capa_reserved,
          { "Reserved", "ieee1905.r2_ap_capabilities.reserved",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_r2_ap_capa_flags,
          { "Flags", "ieee1905.r2_ap_capabilities.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_byte_counter_units,
          { "Byte Counter Units", "ieee1905.r2_ap_capabilities.byte_counter_units",
            FT_UINT8, BASE_DEC, VALS(byte_counter_units_vals), 0xC0, NULL, HFILL}},

        { &hf_ieee1905_basic_service_prio_flag,
          { "Basic Service Prioritization", "ieee1905.r2_ap_capabilities.basic_service_prioritization",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20, NULL, HFILL }},

        { &hf_ieee1905_enhanced_service_prio_flag,
          { "Enhanced Service Prioritization", "ieee1905.r2_ap_capabilities.enhanced_service_prioritization" ,
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10, NULL, HFILL }},

        { &hf_ieee1905_r2_ap_capa_flags_reserved,
          { "Reserved", "ieee1905.r2_ap_capabilities.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }},

        { &hf_ieee1905_max_vid_count,
          { "Max Total Number of VIDs", "ieee1905.r2_ap_capabilities.max_total_number_of_vids",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_default_802_1q_settings_primary_vlan,
          { "Primary VLAN ID", "ieee1905.service_prioritization_rule.primary_vlan_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_default_802_1q_settings_flags,
          { "Flags", "ieee1905.service_prioritization_rule.flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_default_802_1q_settings_default_pcp,
          { "Primary PCP", "ieee1905.service_prioritization_rule.flags.primary_pcp",
            FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }},

        { &hf_ieee1905_default_802_1q_settings_reserved,
          { "Reserved", "ieee1905.service_prioritization_rule.fkags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }},

        { &hf_ieee1905_ap_radio_advanced_capa_radio_id,
          { "Radio Unique ID", "ieee1905.ap_advanced_capabilities.radio_id",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_radio_advanced_capa_flags,
          { "AP Radio Advanced Capabilities Flags",
            "ieee1905.ap_advanced_capabilities.flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_traffic_separation_policy_num_ssids,
          { "Number of SSIDs", "ieee1905.traffic_separation_policy.num_ssids",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_traffic_separation_policy_ssid_len,
          { "SSID Length", "ieee1905.traffic_separation_policy.ssid_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_traffic_separation_policy_ssid,
          { "SSID", "ieee1905.traffic_separation_policy.ssid",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_traffic_separation_policy_vlanid,
          { "VLAN ID", "ieee1905.traffic_separation_policy.vlan_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bss_config_report_radio_count,
          { "Radio Count", "ieee1905.bss_config_report.radio_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bss_config_report_radio_id,
          { "Radio ID", "ieee1905.bss_config_report.radio_id",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bss_config_report_flags,
          { "Report Flags", "ieee1905.bss_config_report.report_flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bss_config_report_backhaul_bss,
          { "Backhaul BSS", "ieee1905.bss_config_report.backhaul_bss",
            FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x80, NULL, HFILL }},

        { &hf_ieee1905_bss_config_report_fronthaul_bss,
          { "Fronthaul BSS", "ieee1905.bss_config_report.fronthaul_bss",
            FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x40, NULL, HFILL }},

        { &hf_ieee1905_bss_config_report_r1_disallowed_status,
          { "R1 Disallowed Status",
            "ieee1905.bss_config_report.r1_disallowed_status",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_disallowed), 0x20, NULL, HFILL }},

        { &hf_ieee1905_bss_config_report_r2_disallowed_status,
          { "R2 Disallowed Status",
            "ieee1905.bss_config_report.r2_disallowed_status",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_disallowed), 0x10, NULL, HFILL }},

        { &hf_ieee1905_bss_config_report_multiple_bssid_set,
          { "Multiple BSSID Set",
            "ieee1905.bss_config_report.multiple_bssid_set",
            FT_BOOLEAN, 8, TFS(&tfs_transmitted_non_transmitted),
            0x08, NULL, HFILL }},

        { &hf_ieee1905_bss_config_report_transmitted_bssid,
          { "Transmitted BSSID",
            "ieee1905.bss_config_report.transmitted_bssid",
            FT_BOOLEAN, 8, TFS(&tfs_transmitted_non_transmitted),
            0x04, NULL, HFILL }},

        { &hf_ieee1905_bss_config_report_reserved,
          { "Reserved", "ieee1905.bss_config_report.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }},

        { &hf_ieee1905_bss_config_report_res,
          { "Reserved", "ieee1905.bss_config_report.reserved",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bss_config_report_bss_cnt,
          { "BSS Count", "ieee1905.bss_config_report.bss_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hs_ieee1902_bss_config_report_mac,
          { "Local Interface MAC addr",
            "ieee1905.bss_config_report.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1902_bss_config_report_ssid_len,
          { "SSID Length", "ieee1905.bss_config_report.ssid_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bss_config_report_ssid,
          { "SSID", "ieee1905.bss_config_report.ssid",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_packet_filtering_policy_bssid_num,
          { "Number of BSSIDs", "ieee1905.packet_filtering_policy.num_bssids",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_packet_filtering_policy_bssid,
          { "BSSID", "ieee1905.packet_filtering_policy.bssid",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_packet_filtering_policy_mac_count,
          { "Number of Permitted Destination MAC Addresses",
            "ieee1905.packet_filtering_policy.num_permitted_mac_addr",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_packet_filtering_policy_mac_addr,
          { "Permitted Destination MAC Address",
            "ieee1905.packet_filtering_policy.permitted_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_bssid_tlv_bssid,
          { "BSSID", "ieee1905.bssid",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_id,
          { "Rule Identifier", "ieee1905.service_prio_rule.id",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_flags,
          { "Flags", "ieee1905.service_prio_rule.flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_add_remove_filter_bit,
          { "Add-Remove Filter", "ieee1905.service_prio_rule.flags.add_remove",
            FT_BOOLEAN, 8, TFS(&tfs_add_remove), 0x80, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_flags_reserved,
          { "Reserved", "ieee1905.service_prio_rule.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL }},


        { &hf_ieee1905_service_prio_rule_precedence,
          { "Rule Precedence", "ieee1905.service_prio_rule.precedence",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_output,
          { "Rule Output", "ieee1905.service_prio_rule.output",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_service_prio_match_flags,
          { "Match flags", "ieee1905.service_prio_rule.match_flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_match_always,
          { "Match Always", "ieee1905.service_prio_rule.match.match_always",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_match_reserved,
          { "Reserved", "ieee1905.service_prio_rule.match.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_match_up_in_qos,
          { "Match Up in 802.11 QoS Control",
            "ieee1905.service_prio_rule.match.match_up_802_11_qos",
            FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_match_up_control_match,
          { "UP in 802.11 QoS Control Match Sense Flag",
            "ieee1905.service_prio_rule.match.up_in_802_11_qos_control",
            FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_match_source_mac,
          { "Match Source MAC Address",
            "ieee1905.service_prio_rule.match.match_source_mac",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_match_source_mac_sense,
          { "Source MAC Address Match Sense",
            "ieee1905.service_prio_rule.match.source_mac_address_match_sense",
            FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_match_dest_mac,
          { "Match Destination MAC address",
            "ieee1905.service_prio_rule.match.match_destination_mac",
            FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_match_dest_mac_sense,
          { "Destination MAC Address Match Sense",
            "ieee1905.service_prio_rule.match.destination_mac_address_match_sense",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_up_control,
          { "UP in 802.11 QoS Control",
            "ieee1905.service_prio_rule.up_in_802_11_qos_control",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_source_mac,
          { "Source MAC Address", "ieee1905.service_prio_rule.source_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_service_prio_rule_dest_mac,
          { "Destination MAC Address", "ieee1905.service_prio_rule.destination_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dscp_mapping_table_val,
          { "PCP Value", "ieee1905.dscp_mapping_table.pcp_value",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_r2_error_reason_code,
          { "Reason Code", "ieee1905.profile_2_error.reason_code",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(r2_error_code_rvals),
            0, NULL, HFILL }},

        { &hf_ieee1905_r2_error_bssid,
          { "BSSID", "ieee1905.profile_2_error.bssid",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_radio_advance_capa_backhaul_bss_traffic_sep,
          { "Traffic Separation on combined fronthaul and R1-only backhaul",
            "ieee1905.ap_advanced_capabilities.traffic_sep_on_combined_fronthaul_and_r1_only_backhaul",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x80, NULL, HFILL }},

        { &hf_ieee1905_ap_radio_advance_capa_combined_r1_r2_backhaul,
          { "Traffic Separation on combined R1 and R2 and above backhaul",
            "ieee1905.ap_advanced_capabilities.traffic_sep_on_combined_r1_and_r2_and_backhaul",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported),
            0x40, NULL, HFILL }},

        { &hf_ieee1905_ap_radio_advance_capa_reserved,
          { "Reserved", "ieee1905.ap_advanced_capabilities.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }},

        { &hf_ieee1905_assoc_status_notif_num_bssid,
          { "Number of BSSIDs",
            "ieee1905.association_status_notification.num_bssids",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_assoc_status_notif_bssid,
          { "BSSID of operated BSS",
            "ieee1905.associated_status_notification.bssid_of_operated_bss",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_assoc_status_notif_status,
          { "Status", "ieee1905.associated_status_notification.status",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(assoc_status_notif_status_rvals), 0x0, NULL, HFILL }},

        { &hf_ieee1905_source_info_mac_addr,
          { "Tunneled Source MAC Address",
            "ieee1905.source_info.tunneled_source_mac_address",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_tunneled_message_type,
          { "Tunneled protocol payload type",
            "ieee1905.tunneled_message_type.tunneled_payload_type",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
            RVALS(tunneled_message_type_rvals), 0x0, NULL, HFILL }},

        { &hf_ieee1905_tunneled_data,
          { "Tunneled protocol payload",
            "ieee1905.tunneled.tunneled_protocol_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_status_code_status,
          { "Status Code", "ieee1905.status_code.status_code",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &ieee80211_status_code_ext, 0,
            NULL, HFILL }},

        { &hf_ieee1905_disassociation_reason_code,
          { "Reason Code", "ieee1905.disassociation_reason_code.reason_code",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &ieee80211_reason_code_ext, 0,
            NULL, HFILL }},

        { &hf_ieee1905_backhaul_sta_radio_id,
          { "Radio ID", "ieee1905.backhaul_sta_radio_capabilities.radio_id",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_backhaul_sta_radio_capabilities,
          { "Flags", "ieee1905.backhaul_sta_radio_capabilities.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_backhaul_sta_radio_capa_mac_included,
          { "MAC address included",
            "ieee1905.backhaul_sta_radio_capabilities.mac_address_included",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},

        { &hf_ieee1905_backhaul_sta_radio_capa_reserved,
          { "Reserved", "ieee1905.backhaul_sta_radio_capabilities.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL }},

        { &hf_ieee1905_backhaul_sta_addr,
          { "Backhaul STA MAC address",
            "ieee1905.backhaul_sta_radio_capabilities.backhaul_sta_mac_address",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_akm_backhaul_suite_oui,
          { "Backhaul Suite OUI",
            "ieee1905.akm_suite_capabilities.backhaul.backhaul_akm_suite_oui",
            FT_UINT24, BASE_OUI, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_akm_backhaul_suite_type,
          { "Backhaul AKM Suite type",
            "ieee1905.akm_suite_capabilities.backhaul_akm_suite_type",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_backhaul_akm_suite_capa_count,
          { "Backhaul AKM Suite count",
            "ieee1905.akm_suite_capabilities.backhaul_akm_suite_count",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_akm_fronthaul_suite_oui,
          { "Fronthaul Suite OUI",
            "ieee1905.akm_suite_capabilities.backhaul.fronthaul_akm_suite_oui",
            FT_UINT24, BASE_OUI, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_akm_fronthaul_suite_type,
          { "Fronthaul AKM Suite type",
            "ieee1905.akm_suite_capabilities.fronthaul_akm_suite_type",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_fronthaul_akm_suite_capa_count,
          { "Fronthaul AKM Suite count",
            "ieee1905.akm_suite_capabilities.fronthaul_akm_suite_count",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_encap_dpp_flags,
          { "Flags", "ieee1905.1905_encap_dpp.flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dpp_encap_enrollee_mac_present,
          { "Enrollee Mac Address Present",
            "ieee1905.1905_encap_dpp.flags.enrollee_mac_address_present",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},

        { &hf_ieee1905_dpp_encap_reserved,
          { "Reserved",
            "ieee1905.1905_encap_dpp.flags.reserved",
            FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},

        { &hf_ieee1905_dpp_encap_frame_type_flag,
          { "DPP Frame Indicator",
            "ieee1905.1905_encap_dpp.flags.dpp_frame_indicator",
            FT_BOOLEAN, 8, TFS(&tfs_dpp_frame_indicator), 0x20, NULL, HFILL }},

        { &hf_ieee1905_dpp_encap_reserved2,
          { "Reserved", "ieee1905.1905_encap_dpp.flags.reserved2",
            FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }},

        { &hf_ieee1905_encap_dpp_sta_mac,
          { "Destination STA MAC address",
            "ieee1905.1905_encap_dpp.destination_sta_mac_address",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_dpp_encap_frame_type,
          { "Frame Type", "ieee1905.1905_encap_dpp.frame_type",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_dpp_encap_frame_length,
          { "Frame Length", "ieee1905.1905_encap_dpp.frame_length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_dpp_encap_dpp_oui,
          { "OUI", "ieee1905.1905_encap_dpp.oui",
            FT_UINT24, BASE_OUI, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dpp_encap_category,
          { "Category", "ieee1905.1905_encap_dpp.category",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dpp_encap_public_action,
          { "Public Action", "ieee1905.1905_encap_dpp.public_action",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ff_pa_action_codes_ext, 0,
            NULL, HFILL }},

        { &hf_ieee1905_dpp_encap_dpp_subtype,
          { "WFA Subtype", "ieee1905.1905_encap_dpp.subtype",
            FT_UINT8, BASE_DEC, VALS(wfa_subtype_vals), 0,
            NULL, HFILL }},

        { &hf_ieee1905_dpp_bootstrapping_uri_radio_id,
          { "Radio ID", "ieee1905.dpp_bootstrapping_uri_notification.radio_id",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_dpp_bootstrapping_uri_local_mac_addr,
          { "MAC Address of Local Interface",
            "ieee1905.dpp_bootstrapping_uri_notification.mac_addr_local_intf",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_dpp_bootstrapping_uri_bsta_mac_addr,
          { "MAC Address of bSTA",
            "ieee1905.dpp_bootstrapping_uri_notification.mac_addr_bsta",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_dpp_bootstrapping_uri_received,
          { "DPP Bootstrapping URI",
            "ieee1905.dpp_bootstrapping_uri_notification.dpp_bootstrapping_uri",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dpp_advertise_cce_flag,
          { "Advertise CCE", "ieee1905.dpp_advertise_cce.flag",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }},

        { &hf_ieee1905_dpp_chirp_value_flags,
          { "Chirp Value Flags", "ieee1905.dpp_chirp_value.flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dpp_chirp_enrollee_mac_addr_present,
          { "Enrollee MAC Address Present",
            "ieee1905.dpp_chirp_value.flags.enrollee_mac_addr_present",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x80, NULL, HFILL }},

        { &hf_ieee1905_dpp_chirp_hash_validity,
          { "Hash Validity Bit", "ieee1905.dpp_chirp_value.flags.hash_validity_bit",
            FT_BOOLEAN, 8, TFS(&tfs_chirp_hash_validity_bit),
            0x40, NULL, HFILL }},

        { &hf_ieee1905_dpp_chirp_reserved,
          { "Reserved", "ieee1905.dpp_chirp_value.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }},

        { &hf_ieee1905_dpp_chirp_enrollee_mac_addr,
          { "Destination STA MAC Address",
            "ieee1905.dpp_chirp_value.dest_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_dpp_chirp_value_hash_length,
          { "Hash Length", "ieee1905.dpp_chirp_value.hash_length",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dpp_chirp_value_hash_value,
          { "Hash Value", "ieee1905.dpp_chirp_value.hash_value",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dev_inventory_lsn,
          { "Serial Number Length", "ieee1905.device_inventory.lsn",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dev_inventory_serial,
          { "Serial Number", "ieee1905.device_inventory.serial_number",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dev_inventory_lsv,
          { "Software Version Length", "ieee1905.device_inventory.lsv",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dev_inventory_sw_vers,
          { "Software Version", "ieee1905.device_inventory.software_version",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dev_inventory_lee,
          { "Execution Env Length", "ieee1905.device_inventory.lee",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dev_inventory_exec_env,
          { "Execution Env", "ieee1905.device_inventory.execution_env",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dev_inventory_num_radios,
          { "Number of Radios", "ieee1905.device_inventory.number_of_radios",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dev_inventory_radio_id,
          { "Radio ID", "ieee1905.device_inventory.radio_id",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dev_inventory_lcv,
          { "Chipset Vendor Length", "ieee1905.device_inventory.lcv",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_dev_inventory_chp_ven,
          { "Chipset Vendor", "ieee1905.device_inventory.chipset_vendor",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_r2_steering_req_src_bssid,
          { "Src BSSID", "ieee1905.r2_steering_request.src_bssid",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_r2_steering_req_flags,
          { "Flags", "ieee1905.r2_steering_request.flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_r2_steering_request_mode_flag,
          { "Request Mode", "ieee1905.r2_steering_request.flags.request_mode",
            FT_BOOLEAN, 8, TFS(&tfs_ieee1905_steering_request_mode_flag),
            0x80, NULL, HFILL }},

        { &hf_ieee1905_r2_btm_disassoc_imminent_flag,
          { "BTM Disassociation Imminent",
            "ieee1905.r2_steering_request.flags.btm_disassociation_imminent",
            FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},

        { &hf_ieee1905_r2_btm_abridged_flag,
          { "BTM Abridged", "ieee1905.r2_steering_request.flags.btm_abridged",
            FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},

        { &hf_ieee1905_r2_steering_req_reserved,
          { "Reserved", "ieee1905.r2_steering_request.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }},

        { &hf_ieee1905_r2_steering_op_window,
          { "Steering Opportunity window",
            "ieee1905.r2_steering_request.steering_opportunity_window",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_r2_steering_btm_dissasoc_tmr,
          { "BTM Disassociation Timer",
            "ieee1905.r2_steering_request.btm_disassociation_timer",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_r2_steering_sta_count,
          { "STA List Count", "ieee1905.r2_steering_request.sta_list_count",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_r2_steering_sta_mac,
          { "AMB capable STA MAC",
            "ieee1905.r2_steering_request.amb_capable_sta_mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_r2_steering_target_count,
          { "Target BSSID Count",
            "ieee1905.r2_steering_request.target_bssid_count",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_r2_steering_target_bssid,
          { "Target BSSID", "ieee1905.r2_steering_request.target_bssid",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_r2_steering_target_op_class,
          { "Target Operating Class",
            "ieee1905.r2_steering_request.target_operating_class",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_r2_steering_target_channel,
          { "Target Channel",
            "ieee1905.r2_steering_request.target_channel",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_r2_steering_reason,
          { "Reason code", "ieee1905.r2_steering_request.reason_code",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_metric_collection_interval,
          { "Collection Interval", "ieee1905.metric_collection_interval.interval",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_max_reporting_rate,
          { "Maximum Reporting Rate", "ieee1905.unsuccessful_assoc.max_report_rate",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_bss_configuration_request,
          { "Configuration Request Object",
            "ieee1905.bss_configuration_request.configuration_request_object",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_bss_configuration_response,
          { "Configuration Response Object",
            "ieee1905.bss_configuration_response.configuration_response_object",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_dpp_message_category,
          { "Category", "ieee1905.dpp_message.category",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }},

        { &hf_ieee1905_dpp_message_public_action,
          { "Public Action", "ieee1905.dpp_message.public_action",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ff_pa_action_codes_ext, 0,
            NULL, HFILL }},

        { &hf_ieee1905_extra_tlv_data,
          { "Extraneous TLV data", "ieee1905.extra_tlv_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_data,
          { "Extraneous message data", "ieee1905.data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_ieee1905_fragments,
          { "IEEE1905 Message Fragments", "ieee1905.fragments",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_fragment,
          { "IEEE1905 Message Fragment", "ieee1905.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_fragment_overlap,
          { "IEEE1905 Message Fragment Overlap", "ieee1905.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_fragment_overlap_conflicts,
          { "IEEE1905 Message Fragment Overlap Conflict",
            "ieee1905.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_fragment_multiple_tails,
          { "IEEE1905 Message has multiple tail fragments",
            "ieee1905.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_fragment_too_long_fragment,
          { "IEEE1905 Message Fragment too long",
            "ieee1905.fragment.too_long",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_fragment_error,
          { "IEEE1905 Message defragmentation error",
            "ieee1905.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_fragment_count,
          { "IEEE1905 Message Fragment count", "ieee1905.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_fragment_reassembled_in,
          { "Reassembled in", "ieee1905.fragment.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee1905_fragment_reassembled_length,
          { "IEEE1905 Message length", "ieee1905.fragment.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    };

    static gint *ett[] = {
        &ett_ieee1905,
        &ett_ieee1905_flags,
        &ett_ieee1905_tlv_len,
        &ett_tlv,
        &ett_device_information_list,
        &ett_device_information_tree,
        &ett_media_type,
        &ett_bridging_tuples_list,
        &ett_bridging_mac_list,
        &ett_non_1905_neighbor_list,
        &ett_1905_neighbor_list,
        &ett_ieee1905_neighbor_flags,
        &ett_media_type_list,
        &ett_media_item,
        &ett_local_interface_list,
        &ett_local_interface_info,
        &ett_ipv4_list,
        &ett_ipv4_info,
        &ett_ipv4_type_addr_list,
        &ett_ipv4_addr_info,
        &ett_ipv6_list,
        &ett_ipv6_info,
        &ett_ipv6_type_addr_list,
        &ett_ipv6_addr_info,
        &ett_push_button_phy_list,
        &ett_push_button_phy_info,
        &ett_power_off_info,
        &ett_power_change_list,
        &ett_power_change_info,
        &ett_power_status_list,
        &ett_power_status_info,
        &ett_l2_local_intf_list,
        &ett_l2_neighbor_device_info,
        &ett_l2_neighbor_dev_list,
        &ett_l2_neighbor_dev_tree,
        &ett_supported_service_list,
        &ett_searched_service_list,
        &ett_ap_operational_bss_list,
        &ett_ap_operational_bss_tree,
        &ett_ap_operational_bss_intf,
        &ett_ap_operational_bss_intf_list,
        &ett_ap_operational_bss_intf_tree,
        &ett_ieee1905_capabilities_flags,
        &ett_ieee1905_unsuccessful_associations,
        &ett_assoc_control_list,
        &ett_ieee1905_steering_request_flags,
        &ett_ieee1905_association_event_flags,
        &ett_radio_basic_class_list,
        &ett_ap_radio_basic_cap_class_tree,
        &ett_radio_basic_non_op_list,
        &ett_ht_cap_flags,
        &ett_vht_cap_flags,
        &ett_assoc_clients_bss_list,
        &ett_assoc_client_bss_tree,
        &ett_assoc_client_list,
        &ett_assoc_client_tree,
        &ett_channel_preference_class_list,
        &ett_ap_channel_preference_class_tree,
        &ett_channel_pref_channel_list,
        &ett_ieee1905_channel_prefs_flags,
        &ett_op_channel_report_class_tree,
        &ett_op_channel_report_class_list,
        &ett_sta_link_metrics_query_channel_list,
        &ett_sta_link_link_mac_addr_list,
        &ett_metric_reporting_policy_list,
        &ett_metric_reporting_policy_tree,
        &ett_metric_policy_flags,
        &ett_ap_metric_query_bssid_list,
        &ett_ieee1905_ap_metrics_flags,
        &ett_sta_list_metrics_bss_list,
        &ett_sta_list_metrics_bss_tree,
        &ett_sta_wf6_status_report_tid_list,
        &ett_sta_wf6_status_report_tid_tree,
        &ett_sta_extended_link_metrics_list,
        &ett_sta_extended_link_metrics_tree,
        &ett_ap_he_mcs_set,
        &ett_ap_he_cap_flags,
        &ett_ieee1905_ap_he_tx_mcs_set,
        &ett_ieee1905_ap_he_rx_mcs_set,
        &ett_steering_policy_disallowed_list,
        &ett_btm_steering_policy_disallowed_list,
        &ett_btm_steering_radio_list,
        &ett_radio_restriction_op_class_list,
        &ett_radio_restriction_op_class_tree,
        &ett_radio_restriction_channel_list,
        &ett_radio_restriction_channel_tree,
        &ett_unassoc_sta_link_metric_list,
        &ett_unassoc_sta_link_metric_tree,
        &ett_beacon_metrics_query_list,
        &ett_beacon_metrics_query_tree,
        &ett_beacon_metrics_query_channel_list,
        &ett_beacon_report_subelement_list,
        &ett_beacon_report_sub_element_tree,
        &ett_beacon_metrics_response_report_list,
        &ett_beacon_metrics_response_report_tree,
        &ett_ieee1905_beacon_reported_flags,
        &ett_channel_scan_rep_policy,
        &ett_channel_scan_capa_radio_list,
        &ett_channel_scan_capa_radio,
        &ett_channel_scan_capa_flags,
        &ett_channel_scan_capa_class_list,
        &ett_channel_scan_capa_class,
        &ett_channel_scan_capa_channels,
        &ett_channel_scan_request_flags,
        &ett_channel_scan_request_radio_list,
        &ett_channel_scan_request_radio,
        &ett_channel_scan_request_class_list,
        &ett_channel_scan_request_class,
        &ett_channel_scan_request_channels,
        &ett_channel_scan_result_neigh_list,
        &ett_channel_scan_result_neigh_flags,
        &ett_ap_wf6_role_list,
        &ett_ap_wf6_role_tree,
        &ett_ap_wf6_agent_role_flags,
        &ett_ap_wf6_supported_flags,
        &ett_ap_wf6_mimo_max_flags,
        &ett_ap_wf6_gen_flags,
        &ett_channel_scan_result_neigh,
        &ett_channel_scan_result_flags,
        &ett_cac_request_flags,
        &ett_cac_request_radio_list,
        &ett_cac_request_radio,
        &ett_cac_terminate_radio_list,
        &ett_cac_terminate_radio,
        &ett_cac_completion_radio_list,
        &ett_cac_completion_radio,
        &ett_cac_completion_radar_list,
        &ett_cac_completion_radar,
        &ett_cac_status_rpt_avail_list,
        &ett_cac_status_rpt_avail_chan,
        &ett_cac_status_rpt_non_occupy_list,
        &ett_cac_status_rpt_unocc_chan,
        &ett_cac_status_rpt_active_cac_list,
        &ett_cac_status_rpt_active_cac_tree,
        &ett_cac_capabilities_radio_list,
        &ett_cac_capabilities_radio_tree,
        &ett_cac_capabilities_type_list,
        &ett_cac_capabilities_type_tree,
        &ett_cac_capabilities_class_list,
        &ett_cac_capabilities_class_tree,
        &ett_cac_capabilities_channel_list,
        &ett_cac_capabilities_channel,
        &ett_r2_ap_capa_flags,
        &ett_edge_interface_list,
        &ett_radio_advanced_capa_flags,
        &ett_ap_operational_backhaul_bss_tree,
        &ett_ap_operational_backhaul_bss_intf_list,
        &ett_default_802_1q_settings_flags,
        &ett_traffic_separation_ssid_list,
        &ett_traffic_separation_ssid,
        &ett_bss_config_report_list,
        &ett_bss_config_report_tree,
        &ett_bss_config_report_bss_list,
        &ett_bss_config_report_bss_tree,
        &ett_bss_config_report_flags,
        &ett_packet_filtering_policy_bssid_list,
        &ett_packet_filtering_policy_bssid,
        &ett_packet_filtering_policy_mac_tree,
        &ett_ethernet_config_policy_list,
        &ett_ethernet_config_policy,
        &ett_ethernet_config_policy_flags,
        &ett_ieee1905_service_prio_rule_flags,
        &ett_ieee1905_service_prio_rule_match_flags,
        &ett_backhaul_sta_radio_capa_flags,
        &ett_assoc_status_notif_bssid_list,
        &ett_assoc_status_notif_bssid_tree,
        &ett_akm_suite_list,
        &ett_akm_suite,
        &ett_backhaul_akm_suite_list,
        &ett_backhaul_akm_suite,
        &ett_fronthaul_akm_suite_list,
        &ett_fronthaul_akm_suite,
        &ett_1905_encap_dpp_flags,
        &ett_1905_encap_dpp_classes,
        &ett_1905_encap_dpp_op_class_tree,
        &ett_1905_encap_dpp_channel_list,
        &ett_ieee1905_dpp_chirp,
        &ett_device_inventory_radio_list,
        &ett_device_inventory_radio_tree,
        &ett_r2_steering_sta_list,
        &ett_r2_steering_target_list,
        &ett_r2_steering_target,
        &ett_loop_prevention_mech,
        &ett_mic_group_temporal_key,
        &ett_ieee1905_fragment,
        &ett_ieee1905_fragments,
    };

    static ei_register_info ei[] = {
        { &ei_ieee1905_malformed_tlv,
          { "ieee1905.tlv.too_short", PI_PROTOCOL, PI_WARN,
            "TLV is too short", EXPFILL }},

        { &ei_ieee1905_extraneous_data_after_eom,
          { "ieee1905.tlv.extraneous_data", PI_PROTOCOL, PI_WARN,
            "Extraneous data after EOM TLV", EXPFILL }},

        { &ei_ieee1905_extraneous_tlv_data,
          { "ieee1905.tlv.extra_data", PI_PROTOCOL, PI_WARN,
             "TLV has extra data or an incorrect length", EXPFILL }},

        { &ei_ieee1905_deprecated_tlv,
          { "ieee1905.tlv.deprecated_tvl", PI_PROTOCOL, PI_WARN,
            "TLV is deprecated", EXPFILL }},
    };

    expert_module_t *expert_ieee1905 = NULL;

    proto_ieee1905 = proto_register_protocol("IEEE 1905.1a",
            "ieee1905", "ieee1905");

    proto_register_field_array(proto_ieee1905, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_ieee1905 = expert_register_protocol(proto_ieee1905);
    expert_register_field_array(expert_ieee1905, ei, array_length(ei));

    reassembly_table_register(&g_ieee1905_reassembly_table,
                              &ieee1905_reassembly_table_functions);
}

void
proto_reg_handoff_ieee1905(void)
{
    static dissector_handle_t ieee1905_handle;

    ieee1905_handle = create_dissector_handle(dissect_ieee1905,
                proto_ieee1905);

    dissector_add_uint("ethertype", ETHERTYPE_IEEE_1905, ieee1905_handle);

    eapol_handle = find_dissector("eapol");
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
