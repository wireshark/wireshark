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
#include <epan/expert.h>
#include "packet-wps.h"

void proto_reg_handoff_ieee1905(void);
void proto_register_ieee1905(void);

static int proto_ieee1905 = -1;
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
static int hf_ieee1905_unassoc_sta_metrics_oper_flag = -1;
static int hf_ieee1905_unassoc_sta_metrics_non_oper_flag = -1;
static int hf_ieee1905_agent_init_steering = -1;
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
static int hf_ieee1905_channel_select_resp_code = -1;
static int hf_ieee1905_op_channel_report_radio_id = -1;
static int hf_ieee1905_op_channel_report_classes = -1;
static int hf_ieee1905_op_channel_class = -1;
static int hf_ieee1905_op_channel_number = -1;
static int hf_ieee1905_op_channel_eirp = -1;
static int hf_ieee1905_ap_he_cap_radio_id = -1;
static int hf_ieee1905_ap_he_cap_mcs_count = -1;
static int hf_ieee1905_unassoc_link_metrics_query_mac = -1;
static int hf_ieee1905_unassoc_sta_link_metrics_class = -1;
static int hf_ieee1905_ap_metrics_reporting_interval = -1;
static int hf_ieee1905_metric_reporting_policy_radio_id = -1;
static int hf_ieee1905_metric_reporting_radio_count = -1;
static int hf_ieee1905_metrics_rssi_threshold = -1;
static int hf_ieee1905_metric_reporting_rssi_hysteresis = -1;
static int hf_ieee1905_metrics_policy_flags = -1;
static int hf_ieee1905_metrics_channel_util_threshold = -1;
static int hf_ieee1905_assoc_sta_traffic_stats_inclusion = -1;
static int hf_ieee1905_assoc_sta_link_metrics_inclusion = -1;
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
static int hf_ieee1905_assoc_sta_link_metrics_rssi = -1;
static int hf_ieee1905_unassoc_sta_link_channel_count = -1;
static int hf_ieee1905_unassoc_metrics_channel = -1;
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
static int hf_ieee1905_steering_policy_rssi_threshold = -1;
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
static int hf_ieee1905_unassoc_link_metric_uplink_rssi = -1;
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
static int hf_ieee1905_phy_type_flag = -1;
static int hf_ieee1905_reported_frame_type_flag = -1;
static int hf_ieee1905_beacon_report_op_class = -1;
static int hf_ieee1905_beacon_report_channel_no = -1;
static int hf_ieee1905_beacon_report_meas_start_time = -1;
static int hf_ieee1905_beacon_report_meas_duration = -1;
static int hf_ieee1905_beacon_reported_frame_flags = -1;
static int hf_ieee1905_beacon_report_rcpi = -1;
static int hf_ieee1905_beacon_report_rsni = -1;
static int hf_ieee1905_beacon_report_bssid = -1;
static int hf_ieee1905_beacon_report_ant_id = -1;
static int hf_ieee1905_beacon_report_tsf = -1;
static int hf_ieee1905_beacon_report_sub_elt = -1;
static int hf_ieee1905_beacon_report_sub_elt_len = -1;
static int hf_ieee1905_beacon_report_sub_elt_body = -1;
static int hf_ieee1905_beacon_metrics_response_mac_addr = -1;
static int hf_ieee1905_beacon_metrics_response_status = -1;
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

static gint ett_ieee1905 = -1;
static gint ett_ieee1905_flags = -1;
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
static gint ett_he_mcs_list = -1;
static gint ett_he_cap_flags = -1;
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

static expert_field ei_ieee1905_malformed_tlv = EI_INIT;
static expert_field ei_ieee1905_extraneous_data_after_eom = EI_INIT;
static expert_field ei_ieee1905_extraneous_tlv_data = EI_INIT;

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
  { IEEE1905_PUSH_BUTTON_JOIN_NOTIFICATION_MESSAGE,  "1905 push button join notificaton" },
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
  { ASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE, "Associated STA Link Metrics Resonse" },
  { UNASSOCIATED_STA_LINK_METRICS_QUERY_MESSAGE, "Unassociated STA Link Metrics Query" },
  { UNASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE, "Unassociated STA Link Metrics Resonse" },
  { BEACON_METRICS_QUERY_MESSAGE,                "Beacon Metrics Query" },
  { BEACON_METRICS_REPONSE_METRICS,              "Beacon Metrics Response" },
  { COMBINED_INFRASTRUCTURE_METRICS_MESSAGE,     "Combined Infrastructure Metrics" },
  { CLIENT_STEERING_REQUEST_MESSAGE,             "Client Steering Request" },
  { CLIENT_STEERING_BTM_REPORT_MESSAGE,          "Client Steering BTM Report" },
  { CLIENT_ASSOCIATION_CONTROL_REQUEST_MESSAGE,  "Client Association Control Request" },
  { STEERING_COMPLETED_MESSAGE,                  "Steering Completed" },
  { HIGHER_LAYER_DATA_MESSAGE,                   "Higher Layer Data" },
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
#define UNASSOCIATED_STA_LINK_METRICS_QUERY_TLV    0x97
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
  { DEVICE_IDENTIFICATION_TYPE_TLV,          "Device identificaton type" },
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
  { ASSOCIATED_STA_LINK_METRICS_TLV,         "Associated STA link metrics" },
  { UNASSOCIATED_STA_LINK_METRICS_QUERY_TLV,       "Unassociated STA link metrics query" },
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
  { 0x2, "Intra-network 802.11 OBSS interfernece management" },
  { 0x3, "External network 802.11 OBSS interference management" },
  { 0x4, "Reduced coverage (e.g. due to limited transmit power" },
  { 0x5, "Reduced throughput (e.g. due to limited channel bandwidth..." },
  { 0x6, "In-device interference within AP" },
  { 0x7, "Operation disallowed due to radar detection on a DFS channel" },
  { 0x8, "Operation would prevent backhaul operatoon uding shared radio" },
  { 0x9, "Immediate operation possible on a DFS channel" },
  { 0xA, "DFS channel state unknown" },
  { 0, NULL }
};

static const value_string ieee1905_channel_select_resp_code_vals[] = {
  { 0x00, "Accept" },
  { 0x01, "Declined because request violates current preferences" },
  { 0x02, "Declined because request violates most recently reported preferencs" },
  { 0x02, "Declined because request would prevent operation of a current backhaul link" },
  { 0, NULL }
};

static const value_string ieee1905_steering_policy_vals[] = {
  { 0x0, "Agent initiated steering disallowed" },
  { 0x1, "Agent initiated RSSI-based steering mandated" },
  { 0x2, "Agent initiated RSSI-based steering allowed" },
  { 0, NULL}
};

static const value_string beacon_metrics_status_vals[] = {
  { 0x00, "Success - Beacon report received from STA" },
  { 0x40, "Failure - STA supports but no beacon report received" },
  { 0x80, "Failure - STA does not support beacon reports" },
  { 0xC0, "Failure - unspecified" },
  { 0, NULL }
};

static const value_string condensed_phy_type_vals[] = {
  { 0, "phy_type_any" },
  { 1, "phy_type_fhss" },
  { 2, "phy_type_dsss" },
  { 3, "phy_type_irbaseband" },
  { 4, "phy_type_ofdm" },
  { 5, "phy_type_hrdsss" },
  { 6, "phy_type_erp" },
  { 7, "phy_type_ht" },
  { 8, "phy_type_vht" },
  { 0, NULL }
};

static const value_string reported_frame_type_vals[] = {
  { 0, "Beacon or Probe Response frame" },
  { 1, "Measurement Pilot frame" },
  { 0, NULL }
};

static const value_string beacon_report_sub_element_vals[] = {
  { 1, "Reported Frame Body" },
  { 163, "Wite Bandwidth Channel Switch" },
  { 221, "Vendor Specific" },
  { 0, NULL }
};

static const value_string ieee1905_error_code_vals[] = {
  { 0x01, "STA associated with a BSS operatted by the Agent" },
  { 0x02, "STA not associated with any BSS operated by the Agent" },
  { 0x03, "Client capability report undecified failure" },
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
        proto_tree *tree, guint offset, guint16 len)
{
    guint count = 0;
    guint media_type_offset = 0;
    proto_item *pi = NULL;
    proto_tree *dev_tree = NULL;

    while (len > 0) {
        guint8 spec_info_len = 0;

        dev_tree = proto_tree_add_subtree_format(tree, tvb, offset, 8,
                                ett_device_information_tree,
                                &pi, "Local interface %u device info",
                                count);

        proto_tree_add_item(dev_tree, hf_ieee1905_mac_address_type, tvb,
                            offset, 6, ENC_NA);
        offset += 6;
        len -= 6;

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

        len -= (offset - media_type_offset);

        count++;
    }

    return offset;
}

/*
 * Dissect device bridging capabilities
 */
static int
dissect_device_bridging_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
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
    len--;

    while (len > 0) {
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
        len--;

        while (mac_addresses) {
           proto_tree_add_item(bridging_list,
                               hf_ieee1905_bridging_mac_address, tvb,
                               offset, 6, ENC_NA);
           len -= 6;
           offset += 6;
           mac_addresses--;

        }

        proto_item_set_len(mpi, offset - bl_start);
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

    proto_tree_add_item(tree, hf_ieee1905_local_interface_mac, tvb,
                        offset, 6, ENC_NA);

    len -= 6;
    offset += 6;

    start = offset;
    neighbor_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                                ett_non_1905_neighbor_list,
                                &pi, "Non IEEE1905 neighbor devices");

    while (len > 0) {

        proto_tree_add_item(neighbor_list, hf_ieee1905_non_1905_neighbor_mac,
                        tvb, offset, 6, ENC_NA);

        len -= 6;
        offset += 6;

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
    static const int *flags[] = {
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
                        offset, 2, ENC_LITTLE_ENDIAN);
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
                            tvb, offset, 32, ENC_UTF_8|ENC_NA);
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
                            offset, url_field_count, ENC_ASCII|ENC_NA);
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
                        offset, 64, ENC_UTF_8|ENC_NA);
    offset += 64;

    proto_tree_add_item(tree, hf_ieee1905_dev_id_manuf_name, tvb,
                        offset, 64, ENC_UTF_8|ENC_NA);
    offset += 64;

    proto_tree_add_item(tree, hf_ieee1905_dev_id_manuf_model, tvb,
                        offset, 64, ENC_UTF_8|ENC_NA);
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
                        len, ENC_ASCII|ENC_NA);
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

        proto_tree_add_item(ipv6_tree, hf_ieee1905_mac_address, tvb,
                            offset, 6, ENC_NA);
        offset += 6;

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
                            offset, 2, ENC_LITTLE_ENDIAN);
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
                                tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
                                tvb, offset, ssid_len, ENC_ASCII|ENC_NA);
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
    static const int *capabilities[] = {
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
    static const int *capabilities[] = {
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
    static const int *capabilities[] = {
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
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ieee1905_ap_vht_supported_vht_rx_mcs,
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask(tree, tvb, offset, hf_ieee1905_vht_cap_flags,
                           ett_vht_cap_flags, capabilities, ENC_NA);
    offset += 2;

    return offset;
}

/*
 * Dissect an AP HE Capabilities TLV
 */
static int
dissect_ap_he_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset)
{
    guint8 he_mcs_count = 0, he_mcs_index = 0;
    proto_tree *he_mcs_list = NULL;
    static const int *he_capabilities[] = {
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

    proto_tree_add_item(tree, hf_ieee1905_ap_he_cap_radio_id, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    he_mcs_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_ap_he_cap_mcs_count, tvb,
                        offset, 1, ENC_NA);
    offset++;

    he_mcs_list = proto_tree_add_subtree(tree, tvb, offset, he_mcs_count * 2,
                        ett_he_mcs_list, NULL,
                        "HE MCS list");
    while (he_mcs_index < he_mcs_count) {
        proto_tree_add_bitmask(he_mcs_list, tvb, offset, hf_ieee1905_he_cap_flags,
                           ett_he_cap_flags, he_capabilities, ENC_NA);
        offset += 2;

        he_mcs_index++;
    }

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
                                hf_ieee1905_steering_policy_rssi_threshold,
                                tvb, offset, 1, ENC_NA);
            offset++;

            radio_index++;
        }

    }

    return offset;
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
    static const int *ieee1905_reporting_policy_flags[] = {
        &hf_ieee1905_assoc_sta_traffic_stats_inclusion,
        &hf_ieee1905_assoc_sta_link_metrics_inclusion,
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

        proto_tree_add_item(radio_tree, hf_ieee1905_metrics_rssi_threshold, tvb,
                            offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(radio_tree, hf_ieee1905_metric_reporting_rssi_hysteresis,
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
    static const int *preference[] = {
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

        if (channel_count == 0)
            continue;

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

        proto_tree_add_item(sta_tree, hf_ieee1905_unassoc_link_metric_uplink_rssi,
                            tvb, offset, 1, ENC_NA);
        offset++;

        sta_index++;
    }

    return offset;
}

/*
 * Dissect a Steering request TLV
 */
static int
dissect_steering_request(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    guint8 mode = 0;
    guint8 steering_count = 0;
    static const int *steering_flags[] = {
      &hf_ieee1905_steering_request_mode_flag,
      &hf_ieee1905_btm_disassoc_imminent_flag,
      &hf_ieee1905_btm_abridged_flag,
      NULL,
    };
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

    /* If Request Mode is 1, this field is not present. */
    if (!(mode & 0x80)) {
        proto_tree_add_item(tree, hf_ieee1905_steering_req_op_window,
                            tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    proto_tree_add_item(tree, hf_ieee1905_steering_btm_disass_timer,
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
                        tvb, offset, ssid_len, ENC_ASCII|ENC_NA);
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
 * Dissect a beacon report
 */
static gint16
dissect_beacon_report(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    guint16 start_len = len;
    guint16 start_offset = 0;
    proto_tree *sub_element_list = NULL;
    proto_item *pi = NULL;
    static const int *reported_frame_info_flags[] = {
      &hf_ieee1905_phy_type_flag,
      &hf_ieee1905_reported_frame_type_flag,
      NULL,
    };


    proto_tree_add_item(tree, hf_ieee1905_beacon_report_op_class, tvb,
                        offset, 1, ENC_NA);
    offset++; len--;

    if (len == 0) return start_len; /* We should add an error report */

    proto_tree_add_item(tree, hf_ieee1905_beacon_report_channel_no, tvb,
                        offset, 1, ENC_NA);
    offset++; len--;

    /*
     * In case the next item is truncated ... this is sub optimal. We should
     * add an error node if it is too short.
     */
    if (len < 8) return start_len;

    proto_tree_add_item(tree, hf_ieee1905_beacon_report_meas_start_time, tvb,
                        offset, 8, ENC_BIG_ENDIAN);
    offset += 8; len -= 8;

    if (len < 2) return start_len;

    proto_tree_add_item(tree, hf_ieee1905_beacon_report_meas_duration, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2; len -= 2;

    if (len == 0) return start_len;

    proto_tree_add_bitmask(tree, tvb, offset,
                           hf_ieee1905_beacon_reported_frame_flags,
                           ett_ieee1905_beacon_reported_flags,
                           reported_frame_info_flags, ENC_NA);
    offset++; len--;

    if (len == 0) return start_len;

    proto_tree_add_item(tree, hf_ieee1905_beacon_report_rcpi, tvb,
                        offset, 1, ENC_NA);
    offset++; len--;

    if (len == 0) return start_len;

    proto_tree_add_item(tree, hf_ieee1905_beacon_report_rsni, tvb,
                        offset, 1, ENC_NA);
    offset++; len--;

    if (len < 6) return start_len;

    proto_tree_add_item(tree, hf_ieee1905_beacon_report_bssid, tvb,
                        offset, 6, ENC_NA);
    offset += 6; len -= 6;

    if (len == 0) return start_len;

    proto_tree_add_item(tree, hf_ieee1905_beacon_report_ant_id, tvb,
                        offset, 1, ENC_NA);
    offset++; len--;

    if (len < 4) return start_len;

    proto_tree_add_item(tree, hf_ieee1905_beacon_report_tsf, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
    offset += 4; len -= 4;

    if (len < 2) return start_len;

    sub_element_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                            ett_beacon_report_subelement_list, &pi,
                            "Sub-element list");
    start_offset = offset;

    while (len >= 2) {
        proto_tree *sub_elt_tree = NULL;
        proto_item *lpi = NULL;
        guint8 sub_elt_len = 0;
        guint8 sub_element = tvb_get_guint8(tvb, offset);

        sub_elt_tree = proto_tree_add_subtree_format(sub_element_list, tvb,
                                offset, -1,
                                ett_beacon_report_sub_element_tree,
                                &lpi, "%s", val_to_str(sub_element,
                                                beacon_report_sub_element_vals,
                                                "Reserved"));
        proto_tree_add_item(sub_elt_tree, hf_ieee1905_beacon_report_sub_elt,
                            tvb, offset, 1, ENC_NA);
        offset++; len--;

        sub_elt_len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(sub_elt_tree, hf_ieee1905_beacon_report_sub_elt_len,
                            tvb, offset, 1, ENC_NA);
        offset++; len--;

        /* Just insert the raw bytes for the moment */
        if (len > 0) {
            guint8 insert_len = len > sub_elt_len ? sub_elt_len : len;

            proto_tree_add_item(sub_elt_tree, hf_ieee1905_beacon_report_sub_elt_body,
                                tvb, offset, insert_len, ENC_NA);
            offset += insert_len; len -= insert_len;

            proto_item_set_len(lpi, insert_len + 2);
        }

    }

    proto_item_set_len(pi, offset - start_offset);

    if (len > 0) len--;  /* There can only be one byte left over */

    return start_len - len;
}

/*
 * Dissect a Beacon Metrics Response TLV
 */
static int
dissect_beacon_metrics_response(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len _U_)
{
    guint8 response = 0, report_index = 0;
    proto_item *pi = NULL;
    proto_tree *report_list = NULL;
    guint saved_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_beacon_metrics_response_mac_addr,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    response = tvb_get_guint8(tvb, offset);
    pi = proto_tree_add_item(tree, hf_ieee1905_beacon_metrics_response_status,
                        tvb, offset, 1, ENC_NA);
    proto_item_append_text(pi, ", %s",
                        val_to_str(response,
                           beacon_metrics_status_vals,
                           "Reserved"));
    offset++;

    len -= 7;

    /* Now, the report(s) ... */
    report_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                            ett_beacon_metrics_response_report_list, &pi,
                            "Measurement report list");
    saved_offset = offset;

    while (len > 0) {
        guint16 amount = 0;
        proto_tree *report_tree = NULL;
        proto_item *lpi = NULL;

        report_tree = proto_tree_add_subtree_format(report_list, tvb,
                                offset, -1,
                                ett_beacon_metrics_response_report_tree,
                                &lpi, "Beacon report %u", report_index);

        amount = dissect_beacon_report(tvb, pinfo, report_tree, offset, len);

        proto_item_set_len(pi, amount);

        len -= amount;
        offset += amount;
        report_index++;
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
    static const int *association_flags[] = {
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
    static const int *flags[] = {
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
        proto_tree *tree, guint offset, guint16 len)
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

        proto_tree_add_item(bss_tree, hf_ieee1905_assoc_sta_link_metrics_rssi,
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
 * Dissect an Unassociated STA Link Metrics Query TLV
 */
static int
dissect_unassociated_sta_link_metrics_query(tvbuff_t *tvb,
        packet_info *pinfo _U_, proto_tree *tree, guint offset, guint16 len)
{
    guint8 channel_count = 0;
    proto_tree *channel_list = NULL;
    proto_tree *sta_mac_list = NULL;
    proto_item *pi = NULL;
    guint saved_offset = 0;

    proto_tree_add_item(tree, hf_ieee1905_unassoc_sta_link_metrics_class,
                        tvb, offset, 1, ENC_NA);
    offset++;
    len--;

    channel_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ieee1905_unassoc_sta_link_channel_count,
                        tvb, offset, 1, ENC_NA);
    offset++;
    len--;

    if (channel_count > 0) {
        channel_list = proto_tree_add_subtree(tree, tvb, offset, channel_count,
                            ett_sta_link_metrics_query_channel_list, NULL,
                            "Channel list");

        while (channel_count > 0) {
            proto_tree_add_item(channel_list,
                            hf_ieee1905_unassoc_metrics_channel,
                            tvb, offset, 1, ENC_NA);
            offset++;
            channel_count--;
            len--;
        }
    }

    if (len < 6)  /* Could generate an error if < 6 but > 0 */
        return offset;

    /* Since no count of STA MAC addresses, use len. Must be at least one. */
    sta_mac_list = proto_tree_add_subtree(tree, tvb, offset, -1,
                            ett_sta_link_link_mac_addr_list, &pi,
                            "MAC address list");
    saved_offset = offset;

    while (len >= 6) {
        proto_tree_add_item(sta_mac_list, hf_ieee1905_unassoc_link_metrics_query_mac,
                            tvb, offset, 6, ENC_NA);
        offset += 6;
        len -= 6;
    }

    proto_item_set_len(pi, offset - saved_offset);

    return offset;
}

/*
 * Dissect a Device Information Type TLV
 */
static int
dissect_device_information_type(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, guint offset, guint16 len)
{
    proto_item *pi = NULL;
    proto_tree *sub_tree = NULL;

    proto_tree_add_item(tree, hf_ieee1905_al_mac_address_type, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(tree, hf_ieee1905_local_interface_count, tvb,
                        offset, 1, ENC_NA);
    offset++;

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
                            ett_device_information_list,
                            &pi, "Local interface list");

    offset = dissect_local_interface_list(tvb, pinfo, sub_tree,
                            offset, len - (6 + 1));

    proto_item_set_len(pi, offset - (6 + 1));

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
 * Dissect an Associated STA Traffic Stats TLV
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

    default:
        proto_tree_add_item(tree, hf_ieee1905_tlv_data, tvb, offset, tlv_len, ENC_NA);
        offset += tlv_len;
    }

  return offset;
}

static int
dissect_ieee1905(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_tree *ieee1905_tree;
    guint16    message_type;
    guint       offset = 0;
    static const int *flags[] = {
      &hf_ieee1905_last_fragment,
      &hf_ieee1905_relay_indicator,
      NULL
    };
    gboolean eom_seen = 0;

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
                           ett_ieee1905_flags, flags, ENC_NA);
    offset++;

    /*
     * Handle the TLVs ... There must be at least one TLV.
     */
    while (!eom_seen) {
      guint8 tlv_type;
      guint16 tlv_len;
      proto_item *tlv_tree;

      tlv_type = tvb_get_guint8(tvb, offset);
      eom_seen = (tlv_type == EOM_TLV);
      tlv_len = tvb_get_ntohs(tvb, offset + 1);

      tlv_tree = proto_tree_add_subtree(ieee1905_tree, tvb, offset, tlv_len + 3,
                                        ett_tlv, NULL, val_to_str_ext(tlv_type,
                                                &ieee1905_tlv_types_vals_ext,
                                                "Unknown: %u"));

      proto_tree_add_item(tlv_tree, hf_ieee1905_tlv_types, tvb, offset, 1, ENC_NA);
      offset++;

      proto_tree_add_item(tlv_tree, hf_ieee1905_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      if (tlv_len)
        offset = dissect_ieee1905_tlv_data(tvb, pinfo, tlv_tree, offset, tlv_type, tlv_len);
    }

    if (tvb_reported_length_remaining(tvb, offset)) {
      proto_item *pi = NULL;

      /* THis shouldn't happen ... */
      pi = proto_tree_add_item(ieee1905_tree, hf_ieee1905_data, tvb, offset, -1, ENC_NA);
      expert_add_info(pinfo, pi, &ei_ieee1905_extraneous_data_after_eom);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_ieee1905(void)
{
    static hf_register_info hf[] = {
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
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ieee1905_tlv_types_vals_ext, 0, NULL, HFILL }},

        { &hf_ieee1905_tlv_len,
          { "TLV length", "ieee1905.tlv_length",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

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
          { "Responder MAC address", "ieee1905.responder_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_neighbor_al_mac_addr,
          { "Neighbor MAC address", "ieee1905.responder_mac_addr",
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
          { "MAC througput capacity", "ieee1905.macThroughputCapacity",
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

        { &hf_ieee1905_ipv6_addr_count,
          { "IPv4 address count", "ieee1905.ipv6_type.addr_count",
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
          { "L2 neighbor interfae count", "ieee1905.l2_neighbor.intf_count",
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
          { "AP operational BSS local interfase SSID", "ieee1905.ap_bss_local_intf_ssid",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_capabilities_flags,
          { "AP capabilities flags", "ieee1905.ap_capability_flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_sta_metrics_oper_flag,
          { "STA link metric reporting operational channels", "ieee1905.link_metric_oper",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80, NULL, HFILL }},

        { &hf_ieee1905_unassoc_sta_metrics_non_oper_flag,
          { "STA link metric reporting non-operational channels", "ieee1905.link_metric_non_oper",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40, NULL, HFILL }},

        { &hf_ieee1905_agent_init_steering,
          { "Agent-initiated RSSI-based Steering", "ieee1905.agent_init_steering",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20, NULL, HFILL }},

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
            FT_BOOLEAN, 8, TFS(&tfs_ieee1905_association_event_flag), 0x20, NULL, HFILL }},

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
          { "Short GI support for 160 and 80+80 MHz", "ieee1905.ap_ht.short_gi_160mhz",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0100, NULL, HFILL}},

        { &hf_ieee1905_vht_support_80plus_mhz_flag,
          { "VHT support for 80+80 MHz", "ieee1905.ap_ht.vht_80plus_mhz",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x80, NULL, HFILL}},

        { &hf_ieee1905_vht_support_160_mhz_flag,
          { "VHT support for 160 MHz", "ieee1905.ap_ht.vht_160mhz",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x40, NULL, HFILL}},

        { &hf_ieee1905_su_beamformer_capable_flag,
          { "SU beamformer capable", "ieee1905.ap_ht.su_beamformer",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x20, NULL, HFILL}},

        { &hf_ieee1905_mu_beamformer_capable_flag,
          { "MU beamformer capable", "ieee1905.ap_ht.mu_beamformer",
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

        { &hf_ieee1905_ap_he_cap_mcs_count,
          { "Supported HE MCS count", "ieee1905.ap_he_capability.he_mcs_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_unassoc_link_metrics_query_mac,
          { "STA MAC address", "ieee1905.unassoc_sta_link_metrics.mac_addr",
            FT_ETHER, FT_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_ap_metrics_reporting_interval,
          { "AP metrics reporting interval", "ieee1905.sta_metric_policy.ap_interval",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_metric_reporting_policy_radio_id,
          { "Radio ID", "ieee1905.metric_reporing_policy.radio_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_metric_reporting_radio_count,
          { "Radio count", "ieee1905.sta_metric_policy.radio_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_metrics_rssi_threshold,
          { "RSSI reporting threshold", "ieee1905.sta_metric_policy.rssi_threshold",
            FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_metric_reporting_rssi_hysteresis,
          {"STA Metrics Reporting RSSI Hysteresis Margin Override",
            "ieee1905.sta_metric_policy.rssi_hysteresis_margin_override",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

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

        { &hf_ieee1905_reporting_policy_flags_reserved,
          { "Reserved", "ieee1905.sta_metrics_policy_flags.reserved",
          FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL }},

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

        { &hf_ieee1905_assoc_sta_link_metrics_rssi,
          { "Measured uplink RSSI for STA", "ieee1905.assoc_sta_link_metrics.rssi",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

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
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x20, NULL, HFILL}},

        { &hf_ieee1905_he_support_160mhz_flag,
          { "HE support for 160 MHz", "ieee1905.ap_he.he_160_mhz",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL}},

        { &hf_ieee1905_he_su_beamformer_capable_flag,
          { "SU beanformer capable", "ieee1905.ap_he.su_beamformer",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL}},

        { &hf_ieee1905_he_mu_beamformer_capable_flag,
          { "MU beamformer capable", "ieee1905.ap_he.mu_beamformer",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL}},

        { &hf_ieee1905_ul_mu_mimo_capable_flag,
          { "UL MU-MIMO capable", "ieee1905.ap_he.ul_mu_mimo",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL}},

        { &hf_ieee1905_ul_mu_mimo_ofdma_capable_flag,
          { "UL MU-MIMO OFDMA capable", "ieee1905.ap_he.he_ul_mu_mimo_ofdma",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL}},

        { &hf_ieee1905_dl_mu_mimo_ofdma_capable_flag,
          { "DL MU-MIMO OFDMA capable", "ieee1905.ap_he.he_dl_mu_mimo_ofdma",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL}},

        { &hf_ieee1905_ul_ofdma_capable,
          { "UL OFDMA capable", "ieee1905.ap_he.he_ul_ofdma",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL}},

        { &hf_ieee1905_dl_ofdma_capable,
          { "DL OFDMA capable", "ieee1905.ap_he.he_dl_ofdma",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL}},

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
          { "Local steering disallowed MAC address", "ieee1905.steering_policy.local_disalow_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_policy_radio_count,
          { "Steering policy radio count", "ieee1905.steering_policy.radio_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_policy_radio_id,
          { "Radio unique ID", "ieee1905.steering_policy.radio_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_policy_policy,
          { "Steering policy", "ieee1905.steering_polocy.policy",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_policy_util,
          { "Channel utilization threshold", "ieee1905.steering_policy.utilization_threshold",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_steering_policy_rssi_threshold,
          { "RSSI steering threshold", "ieee1905.steering_policy.rssi_threshold",
            FT_INT8, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0, NULL, HFILL }},

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

        { &hf_ieee1905_unassoc_link_metric_uplink_rssi,
          { "Uplink RSSI", "ieee1905.unassoc_sta_link_metrics.rssi",
            FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL }},

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

        { &hf_ieee1905_phy_type_flag,
          { "Condensed PHY type", "ieee1905.beacon_report.phy_type",
            FT_UINT8, BASE_HEX, VALS(condensed_phy_type_vals), 0xFE, NULL, HFILL }},

        { &hf_ieee1905_reported_frame_type_flag,
          { "Reportted frame type", "ieee1905.beacon_report.rep_frame_type",
            FT_UINT8, BASE_HEX, VALS(reported_frame_type_vals), 0x01, NULL, HFILL }},

        { &hf_ieee1905_beacon_report_op_class,
          { "Operating class", "ieee1905.beacon_report.op_class",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_report_channel_no,
          { "Channel number", "ieee1905.beacon_report.channel_no",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_report_meas_start_time,
          { "Measurement start time", "ieee1905.beacon_report.start_time",
            FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_report_meas_duration,
          { "Measurement duration", "ieee1905.beacon_report.meas_duration",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_reported_frame_flags,
          { "Reported frame information", "ieee1905.beacon_report.rfi",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_report_rcpi,
          { "RCPI", "ieee1905.beacon_report.rcpi",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_report_rsni,
          { "RSNI", "ieee1905.beacon_report.rsni",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_report_bssid,
          { "BSSID", "ieee1905.beacon_report.bssid",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_report_ant_id,
          { "Antenna ID", "ieee1905.beacon_report.antenna_id",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_report_tsf,
          { "Parent TSF", "ieee1905.beacon_report.parent_tsf",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_report_sub_elt,
          { "Sub-element ID", "ieee1905.beacon_report.sub_elt_id",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_report_sub_elt_len,
          { "Sub-element length", "ieee1905.beacon_report.sub_elt_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_report_sub_elt_body,
          { "Sub-element body", "ieee1905.beacon_report.sub_elt_body",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_response_mac_addr,
          { "STA MAC address", "ieee1905.beacon_metrics.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_beacon_metrics_response_status,
          { "Response status", "ieee1905.beacon_metrics.status",
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

        { &hf_ieee1905_extra_tlv_data,
          { "Extraneous TLV data", "ieee1905.extra_tlv_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_ieee1905_data,
          { "Extraneous message data", "ieee1905.data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_ieee1905,
        &ett_ieee1905_flags,
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
        &ett_he_mcs_list,
        &ett_he_cap_flags,
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
           "TLV has extra data", EXPFILL }},
    };

    expert_module_t *expert_ieee1905 = NULL;

    proto_ieee1905 = proto_register_protocol("IEEE 1905.1a",
            "ieee1905", "ieee1905");

    proto_register_field_array(proto_ieee1905, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_ieee1905 = expert_register_protocol(proto_ieee1905);
    expert_register_field_array(expert_ieee1905, ei, array_length(ei));
}

void
proto_reg_handoff_ieee1905(void)
{
    static dissector_handle_t ieee1905_handle;

    ieee1905_handle = create_dissector_handle(dissect_ieee1905,
                proto_ieee1905);

    dissector_add_uint("ethertype", ETHERTYPE_IEEE_1905, ieee1905_handle);
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
