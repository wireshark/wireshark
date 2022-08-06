/* packet-capwap.c
 * Routines for CAPWAP dissection (RFC 5415 / RFC 5416)
 * Copyright 2009, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/sminmpec.h>
#include <epan/addr_resolv.h>

#include "packet-ieee80211.h"

void proto_register_capwap_control(void);
void proto_reg_handoff_capwap(void);

#define UDP_PORT_CAPWAP_CONTROL 5246
#define UDP_PORT_CAPWAP_DATA 5247

static range_t *global_capwap_data_udp_ports = NULL;
static gboolean global_capwap_draft_8_cisco = FALSE;
static gboolean global_capwap_reassemble = TRUE;
static gboolean global_capwap_swap_frame_control = TRUE;

static reassembly_table capwap_reassembly_table;

/* TODO LIST !
* add decryption of DLTS Message
* add support of all Messages Element Type
*/

static int proto_capwap_control = -1;
static int proto_capwap_data = -1;

static int hf_capwap_preamble = -1;
static int hf_capwap_preamble_version = -1;
static int hf_capwap_preamble_type = -1;
static int hf_capwap_preamble_reserved = -1;

static int hf_capwap_header = -1;
static int hf_capwap_header_hlen = -1;
static int hf_capwap_header_rid = -1;
static int hf_capwap_header_wbid = -1;

static int hf_capwap_header_flags = -1;
static int hf_capwap_header_flags_t = -1;
static int hf_capwap_header_flags_f = -1;
static int hf_capwap_header_flags_l = -1;
static int hf_capwap_header_flags_w = -1;
static int hf_capwap_header_flags_m = -1;
static int hf_capwap_header_flags_k = -1;
static int hf_capwap_header_flags_r = -1;

static int hf_capwap_header_fragment_id = -1;
static int hf_capwap_header_fragment_offset = -1;
static int hf_capwap_header_reserved = -1;

static int hf_capwap_header_mac_length = -1;
static int hf_capwap_header_mac_eui48 = -1;
static int hf_capwap_header_mac_eui64 = -1;
static int hf_capwap_header_mac_data = -1;

static int hf_capwap_header_wireless_length = -1;
static int hf_capwap_header_wireless_data = -1;

static int hf_capwap_header_wireless_data_ieee80211_fi = -1;
static int hf_capwap_header_wireless_data_ieee80211_fi_rssi = -1;
static int hf_capwap_header_wireless_data_ieee80211_fi_snr = -1;
static int hf_capwap_header_wireless_data_ieee80211_fi_data_rate = -1;
static int hf_capwap_header_wireless_data_ieee80211_dest_wlan = -1;
static int hf_capwap_header_wireless_data_ieee80211_dw_wlan_id_bitmap = -1;
static int hf_capwap_header_wireless_data_ieee80211_dw_reserved = -1;
static int hf_capwap_header_padding = -1;

static int hf_capwap_control_header = -1;
static int hf_capwap_control_header_msg_type = -1;
static int hf_capwap_control_header_msg_type_enterprise_nbr = -1;
static int hf_capwap_control_header_msg_type_enterprise_specific = -1;
static int hf_capwap_control_header_seq_number = -1;
static int hf_capwap_control_header_flags = -1;
static int hf_capwap_control_header_msg_element_length = -1;

static int hf_capwap_message_element = -1;
static int hf_capwap_msg_element = -1;
static int hf_capwap_msg_element_type = -1;
static int hf_capwap_msg_element_length = -1;
static int hf_capwap_msg_element_value = -1;

static int hf_capwap_msg_element_type_ac_descriptor_stations = -1;
static int hf_capwap_msg_element_type_ac_descriptor_limit = -1;
static int hf_capwap_msg_element_type_ac_descriptor_active_wtp = -1;
static int hf_capwap_msg_element_type_ac_descriptor_max_wtp = -1;
/* AC Descriptor Security Flags... */
static int hf_capwap_msg_element_type_ac_descriptor_security = -1;
static int hf_capwap_msg_element_type_ac_descriptor_security_s = -1;
static int hf_capwap_msg_element_type_ac_descriptor_security_x = -1;
static int hf_capwap_msg_element_type_ac_descriptor_security_r = -1;
static int hf_capwap_msg_element_type_ac_descriptor_rmac_field = -1;
static int hf_capwap_msg_element_type_ac_descriptor_reserved = -1;
/* AC Descriptor DTLS Policy Flags... */
static int hf_capwap_msg_element_type_ac_descriptor_dtls_policy = -1;
static int hf_capwap_msg_element_type_ac_descriptor_dtls_policy_d = -1;
static int hf_capwap_msg_element_type_ac_descriptor_dtls_policy_c = -1;
static int hf_capwap_msg_element_type_ac_descriptor_dtls_policy_r = -1;

static int hf_capwap_msg_element_type_ac_information = -1;
static int hf_capwap_msg_element_type_ac_information_vendor = -1;
static int hf_capwap_msg_element_type_ac_information_type = -1;
static int hf_capwap_msg_element_type_ac_information_length = -1;
static int hf_capwap_msg_element_type_ac_information_value = -1;
static int hf_capwap_msg_element_type_ac_information_hardware_version = -1;
static int hf_capwap_msg_element_type_ac_information_software_version = -1;

static int hf_capwap_msg_element_type_ac_name = -1;
static int hf_capwap_msg_element_type_ac_name_with_priority = -1;

static int hf_capwap_msg_element_type_ac_timestamp = -1;

static int hf_capwap_msg_element_type_add_station_radio_id = -1;
static int hf_capwap_msg_element_type_add_station_length = -1;
static int hf_capwap_msg_element_type_add_station_mac_eui48 = -1;
static int hf_capwap_msg_element_type_add_station_mac_eui64 = -1;
static int hf_capwap_msg_element_type_add_station_mac_data = -1;
static int hf_capwap_msg_element_type_add_station_vlan_name = -1;

static int hf_capwap_msg_element_type_ac_ipv4_list = -1;
static int hf_capwap_msg_element_type_ac_ipv6_list = -1;

static int hf_capwap_msg_element_type_capwap_control_ipv4 = -1;
static int hf_capwap_msg_element_type_capwap_control_ipv6 = -1;
static int hf_capwap_msg_element_type_capwap_control_wtp_count = -1;

static int hf_capwap_msg_element_type_capwap_timers_discovery = -1;
static int hf_capwap_msg_element_type_capwap_timers_echo_request = -1;

static int hf_capwap_msg_element_type_decryption_error_report_period_radio_id = -1;
static int hf_capwap_msg_element_type_decryption_error_report_period_interval = -1;

static int hf_capwap_msg_element_type_delete_station_radio_id = -1;
static int hf_capwap_msg_element_type_delete_station_length = -1;
static int hf_capwap_msg_element_type_delete_station_mac_eui48 = -1;
static int hf_capwap_msg_element_type_delete_station_mac_eui64 = -1;
static int hf_capwap_msg_element_type_delete_station_mac_data = -1;

static int hf_capwap_msg_element_type_discovery_type = -1;

static int hf_capwap_msg_element_type_location_data = -1;

static int hf_capwap_msg_element_type_maximum_message_length = -1;

static int hf_capwap_msg_element_type_capwap_local_ipv4_address = -1;

static int hf_capwap_msg_element_type_idle_timeout = -1;
static int hf_capwap_msg_element_type_radio_admin_id = -1;
static int hf_capwap_msg_element_type_radio_admin_state = -1;

static int hf_capwap_msg_element_type_radio_op_state_radio_id = -1;
static int hf_capwap_msg_element_type_radio_op_state_radio_state = -1;
static int hf_capwap_msg_element_type_radio_op_state_radio_cause = -1;
static int hf_capwap_msg_element_type_result_code = -1;

static int hf_capwap_msg_element_type_session_id = -1;

static int hf_capwap_msg_element_type_statistics_timer = -1;

static int hf_capwap_msg_element_type_vsp_vendor_identifier = -1;
static int hf_capwap_msg_element_type_vsp_vendor_element_id = -1;
static int hf_capwap_msg_element_type_vsp_vendor_data = -1;

static int hf_capwap_msg_element_type_wtp_board_data = -1;
static int hf_capwap_msg_element_type_wtp_board_data_vendor = -1;
static int hf_capwap_msg_element_type_wtp_board_data_type = -1;
static int hf_capwap_msg_element_type_wtp_board_data_length = -1;
static int hf_capwap_msg_element_type_wtp_board_data_value = -1;
static int hf_capwap_msg_element_type_wtp_board_data_wtp_model_number  = -1;
static int hf_capwap_msg_element_type_wtp_board_data_wtp_serial_number  = -1;
static int hf_capwap_msg_element_type_wtp_board_data_wtp_board_id  = -1;
static int hf_capwap_msg_element_type_wtp_board_data_wtp_board_revision  = -1;
static int hf_capwap_msg_element_type_wtp_board_data_base_mac_address  = -1;

static int hf_capwap_msg_element_type_wtp_descriptor_max_radios = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_radio_in_use = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_number_encrypt = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_encrypt = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_encrypt_reserved = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_encrypt_wbid = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_encrypt_capabilities = -1;

static int hf_capwap_msg_element_type_wtp_descriptor = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_vendor = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_type = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_length = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_value = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_hardware_version = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_active_software_version = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_boot_version = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_other_software_version = -1;

static int hf_capwap_msg_element_type_wtp_fallback = -1;
static int hf_capwap_msg_element_type_wtp_frame_tunnel_mode = -1;
static int hf_capwap_msg_element_type_wtp_frame_tunnel_mode_n = -1;
static int hf_capwap_msg_element_type_wtp_frame_tunnel_mode_e = -1;
static int hf_capwap_msg_element_type_wtp_frame_tunnel_mode_l = -1;
static int hf_capwap_msg_element_type_wtp_frame_tunnel_mode_r = -1;

static int hf_capwap_msg_element_type_wtp_mac_type = -1;

static int hf_capwap_msg_element_type_wtp_name = -1;

static int hf_capwap_msg_element_type_wtp_reboot_statistics_reboot_count = -1;
static int hf_capwap_msg_element_type_wtp_reboot_statistics_ac_initiated_count = -1;
static int hf_capwap_msg_element_type_wtp_reboot_statistics_link_failure_count = -1;
static int hf_capwap_msg_element_type_wtp_reboot_statistics_sw_failure_count = -1;
static int hf_capwap_msg_element_type_wtp_reboot_statistics_hw_failure_count = -1;
static int hf_capwap_msg_element_type_wtp_reboot_statistics_other_failure_count = -1;
static int hf_capwap_msg_element_type_wtp_reboot_statistics_unknown_failure_count = -1;
static int hf_capwap_msg_element_type_wtp_reboot_statistics_last_failure_type = -1;

static int hf_capwap_msg_element_type_capwap_local_ipv6_address = -1;

static int hf_capwap_msg_element_type_capwap_transport_protocol = -1;

static int hf_capwap_msg_element_type_mtu_discovery_padding = -1;

static int hf_capwap_msg_element_type_ecn_support = -1;

static int hf_capwap_msg_element_type_ieee80211_add_wlan_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_wlan_id = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_e = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_i = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_c = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_f = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_p = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_s = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_b = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_a = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_m = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_q = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_t = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_d = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_v = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_o = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_k = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_capability_l = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_key_index = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_key_status = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_key_length = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_key = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_group_tsc = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_qos = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_auth_type = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_mac_mode = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_tunnel_mode = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_suppress_ssid = -1;
static int hf_capwap_msg_element_type_ieee80211_add_wlan_ssid = -1;

static int hf_capwap_msg_element_type_ieee80211_antenna_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_antenna_diversity = -1;
static int hf_capwap_msg_element_type_ieee80211_antenna_combiner = -1;
static int hf_capwap_msg_element_type_ieee80211_antenna_count = -1;
static int hf_capwap_msg_element_type_ieee80211_antenna_selection = -1;

static int hf_capwap_msg_element_type_ieee80211_assigned_wtp_bssid_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_assigned_wtp_bssid_wlan_id = -1;
static int hf_capwap_msg_element_type_ieee80211_assigned_wtp_bssid_bssid = -1;

static int hf_capwap_msg_element_type_ieee80211_delete_wlan_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_delete_wlan_wlan_id = -1;

static int hf_capwap_msg_element_type_ieee80211_direct_sequence_control_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_direct_sequence_control_reserved = -1;
static int hf_capwap_msg_element_type_ieee80211_direct_sequence_control_current_channel = -1;
static int hf_capwap_msg_element_type_ieee80211_direct_sequence_control_current_cca = -1;
static int hf_capwap_msg_element_type_ieee80211_direct_sequence_control_energy_detect_threshold = -1;

static int hf_capwap_msg_element_type_ieee80211_ie_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_ie_wlan_id = -1;
static int hf_capwap_msg_element_type_ieee80211_ie_flags = -1;
static int hf_capwap_msg_element_type_ieee80211_ie_flags_b = -1;
static int hf_capwap_msg_element_type_ieee80211_ie_flags_p = -1;
static int hf_capwap_msg_element_type_ieee80211_ie_flags_rsv = -1;

static int hf_capwap_msg_element_type_ieee80211_mac_operation_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_mac_operation_reserved = -1;
static int hf_capwap_msg_element_type_ieee80211_mac_operation_rts_threshold = -1;
static int hf_capwap_msg_element_type_ieee80211_mac_operation_short_retry = -1;
static int hf_capwap_msg_element_type_ieee80211_mac_operation_long_retry = -1;
static int hf_capwap_msg_element_type_ieee80211_mac_operation_fragmentation_threshold = -1;
static int hf_capwap_msg_element_type_ieee80211_mac_operation_tx_msdu_lifetime = -1;
static int hf_capwap_msg_element_type_ieee80211_mac_operation_rx_msdu_lifetime = -1;

static int hf_capwap_msg_element_type_ieee80211_mic_countermeasures_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_mic_countermeasures_wlan_id = -1;
static int hf_capwap_msg_element_type_ieee80211_mic_countermeasures_mac_address = -1;

static int hf_capwap_msg_element_type_ieee80211_ofdm_control_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_ofdm_control_reserved = -1;
static int hf_capwap_msg_element_type_ieee80211_ofdm_control_current_channel = -1;
static int hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support = -1;
static int hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit0 = -1;
static int hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit1 = -1;
static int hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit2 = -1;
static int hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit3 = -1;
static int hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit4 = -1;
static int hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit5 = -1;
static int hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit6 = -1;
static int hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit7 = -1;
static int hf_capwap_msg_element_type_ieee80211_ofdm_control_ti_threshold = -1;

static int hf_capwap_msg_element_type_ieee80211_multi_domain_capability_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_multi_domain_capability_reserved = -1;
static int hf_capwap_msg_element_type_ieee80211_multi_domain_capability_first_channel = -1;
static int hf_capwap_msg_element_type_ieee80211_multi_domain_capability_number_of_channels = -1;
static int hf_capwap_msg_element_type_ieee80211_multi_domain_capability_max_tx_power_level = -1;

static int hf_capwap_msg_element_type_ieee80211_rate_set_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_rate_set_rate_set = -1;

static int hf_capwap_msg_element_type_ieee80211_station_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_station_association_id = -1;
static int hf_capwap_msg_element_type_ieee80211_station_flags = -1;
static int hf_capwap_msg_element_type_ieee80211_station_mac_address = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_e = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_i = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_c = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_f = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_p = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_s = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_b = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_a = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_m = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_q = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_t = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_d = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_v = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_o = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_k = -1;
static int hf_capwap_msg_element_type_ieee80211_station_capabilities_l = -1;
static int hf_capwap_msg_element_type_ieee80211_station_wlan_id = -1;
static int hf_capwap_msg_element_type_ieee80211_station_supported_rates = -1;

static int hf_capwap_msg_element_type_ieee80211_station_session_key_mac = -1;
static int hf_capwap_msg_element_type_ieee80211_station_session_key_flags = -1;
static int hf_capwap_msg_element_type_ieee80211_station_session_key_flags_a = -1;
static int hf_capwap_msg_element_type_ieee80211_station_session_key_flags_c = -1;
static int hf_capwap_msg_element_type_ieee80211_station_session_key_pairwire_tsc = -1;
static int hf_capwap_msg_element_type_ieee80211_station_session_key_pairwire_rsc = -1;
static int hf_capwap_msg_element_type_ieee80211_station_session_key_key = -1;

static int hf_capwap_msg_element_type_ieee80211_supported_rates_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_supported_rates_rate = -1;

static int hf_capwap_msg_element_type_ieee80211_tx_power_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_tx_power_reserved = -1;
static int hf_capwap_msg_element_type_ieee80211_tx_power_current_tx_power  = -1;

static int hf_capwap_msg_element_type_ieee80211_tx_power_level_radio_id  = -1;
static int hf_capwap_msg_element_type_ieee80211_tx_power_level_num_levels  = -1;
static int hf_capwap_msg_element_type_ieee80211_tx_power_level_power_level = -1;

static int hf_capwap_msg_element_type_ieee80211_update_wlan_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_wlan_id = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_e = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_i = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_c = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_f = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_p = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_s = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_b = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_a = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_m = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_q = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_t = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_d = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_v = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_o = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_k = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_capability_l = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_key_index = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_key_status = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_key_length = -1;
static int hf_capwap_msg_element_type_ieee80211_update_wlan_key = -1;

static int hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_short_preamble = -1;
static int hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_num_of_bssids = -1;
static int hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_dtim_period = -1;
static int hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_bssid = -1;
static int hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_beacon_period = -1;
static int hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_country_string = -1;

static int hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_id = -1;
static int hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_reserved = -1;
static int hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_n = -1;
static int hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_g = -1;
static int hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_a = -1;
static int hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_b = -1;

static int hf_capwap_msg_element_type_ieee80211_supported_mac_profiles_numbers = -1;
static int hf_capwap_msg_element_type_ieee80211_supported_mac_profiles_profile = -1;
static int hf_capwap_msg_element_type_ieee80211_mac_profile = -1;

static int hf_capwap_data_keep_alive = -1;
static int hf_capwap_data_keep_alive_length = -1;

static int hf_capwap_fortinet_element_id = -1;
static int hf_capwap_fortinet_value = -1;
static int hf_capwap_fortinet_ap_scan_rid = -1;
static int hf_capwap_fortinet_ap_scan_bgscan_intv = -1;
static int hf_capwap_fortinet_ap_scan_bgscan_idle = -1;
static int hf_capwap_fortinet_ap_scan_bgscan_rpt_intv = -1;
static int hf_capwap_fortinet_ap_scan_fgscan_rpt_intv = -1;
static int hf_capwap_fortinet_passive_rid = -1;
static int hf_capwap_fortinet_passive = -1;
static int hf_capwap_fortinet_daemon_rst = -1;
static int hf_capwap_fortinet_mac_rid = -1;
static int hf_capwap_fortinet_mac_wid = -1;
static int hf_capwap_fortinet_mac_len = -1;
static int hf_capwap_fortinet_mac = -1;
static int hf_capwap_fortinet_wtp_allow_sn = -1;
static int hf_capwap_fortinet_wtp_allow_allow = -1;
static int hf_capwap_fortinet_wbh_sta_rid = -1;
static int hf_capwap_fortinet_wbh_sta_len = -1;
static int hf_capwap_fortinet_wbh_sta_mac = -1;
static int hf_capwap_fortinet_wbh_sta_bssid = -1;
static int hf_capwap_fortinet_wbh_sta_mhc = -1;
static int hf_capwap_fortinet_htcap_rid = -1;
static int hf_capwap_fortinet_htcap_mcs = -1;
static int hf_capwap_fortinet_htcap_gi = -1;
static int hf_capwap_fortinet_htcap_bw = -1;
static int hf_capwap_fortinet_mvap_sn_length = -1;
static int hf_capwap_fortinet_mvap_sn = -1;
static int hf_capwap_fortinet_mvap_unknown = -1;
static int hf_capwap_fortinet_mvap_age = -1;
static int hf_capwap_fortinet_mvap_period = -1;
static int hf_capwap_fortinet_mvap_vfid = -1;
static int hf_capwap_fortinet_mode_rid = -1;
static int hf_capwap_fortinet_mode = -1;
static int hf_capwap_fortinet_coext_rid = -1;
static int hf_capwap_fortinet_coext = -1;
static int hf_capwap_fortinet_amsdu_rid = -1;
static int hf_capwap_fortinet_amsdu = -1;
static int hf_capwap_fortinet_ps_opt_rid = -1;
static int hf_capwap_fortinet_ps_opt = -1;
static int hf_capwap_fortinet_pure_rid = -1;
static int hf_capwap_fortinet_pure = -1;
static int hf_capwap_fortinet_ebptag_ebp = -1;
static int hf_capwap_fortinet_ebptag_tag = -1;
static int hf_capwap_fortinet_telnet_enable = -1;
static int hf_capwap_fortinet_admin_passwd = -1;
static int hf_capwap_fortinet_regcode = -1;
static int hf_capwap_fortinet_countrycode_rid = -1;
static int hf_capwap_fortinet_countrycode_code = -1;
static int hf_capwap_fortinet_countrycode_string = -1;
static int hf_capwap_fortinet_sta_scan_rid = -1;
static int hf_capwap_fortinet_sta_scan = -1;
static int hf_capwap_fortinet_fho_rid = -1;
static int hf_capwap_fortinet_fho = -1;
static int hf_capwap_fortinet_apho_rid = -1;
static int hf_capwap_fortinet_apho = -1;
static int hf_capwap_fortinet_sta_locate_rid = -1;
static int hf_capwap_fortinet_sta_locate_enable = -1;
static int hf_capwap_fortinet_sta_locate_interval = -1;
static int hf_capwap_fortinet_sa_rid = -1;
static int hf_capwap_fortinet_sa_enable = -1;
static int hf_capwap_fortinet_sa_ssid = -1;
static int hf_capwap_fortinet_darrp_cfg_rid = -1;
static int hf_capwap_fortinet_darrp_cfg_enable = -1;
static int hf_capwap_fortinet_darrp_cfg_interval = -1;
static int hf_capwap_fortinet_ap_suppress_list_ver = -1;
static int hf_capwap_fortinet_ap_suppress_list_op = -1;
static int hf_capwap_fortinet_ap_suppress_list_rid = -1;
static int hf_capwap_fortinet_ap_suppress_list_len = -1;
static int hf_capwap_fortinet_wds_rid = -1;
static int hf_capwap_fortinet_wds_wid = -1;
static int hf_capwap_fortinet_wds_enable = -1;
static int hf_capwap_fortinet_vap_vlan_tag_rid = -1;
static int hf_capwap_fortinet_vap_vlan_tag_wid = -1;
static int hf_capwap_fortinet_vap_vlan_tag = -1;
static int hf_capwap_fortinet_vap_bitmap_rid = -1;
static int hf_capwap_fortinet_vap_bitmap = -1;
static int hf_capwap_fortinet_mcast_rate_rid = -1;
static int hf_capwap_fortinet_mcast_rate_wid = -1;
static int hf_capwap_fortinet_mcast_rate = -1;
static int hf_capwap_fortinet_cfg_rid = -1;
static int hf_capwap_fortinet_cfg_wid = -1;
static int hf_capwap_fortinet_cfg_ip = -1;
static int hf_capwap_fortinet_cfg_mask = -1;
static int hf_capwap_fortinet_split_tun_cfg_enable_local_subnet = -1;
static int hf_capwap_fortinet_split_tun_cfg_cnt = -1;
static int hf_capwap_fortinet_mgmt_vlan_id = -1;
static int hf_capwap_fortinet_vap_psk_passwd_rid = -1;
static int hf_capwap_fortinet_vap_psk_passwd_wid = -1;
static int hf_capwap_fortinet_vap_psk_passwd_key = -1;
static int hf_capwap_fortinet_mesh_eth_bridge_enable = -1;
static int hf_capwap_fortinet_mesh_eth_bridge_type = -1;
static int hf_capwap_fortinet_wtp_cap = -1;
static int hf_capwap_fortinet_txpwr_rid = -1;
static int hf_capwap_fortinet_txpwr = -1;
static int hf_capwap_fortinet_wids_enable_rid = -1;
static int hf_capwap_fortinet_wids_enable = -1;
static int hf_capwap_fortinet_unknown_rid = -1;
static int hf_capwap_fortinet_unknown_wid = -1;
static int hf_capwap_fortinet_unknown = -1;

static int hf_capwap_cisco_element_id = -1;
static int hf_capwap_cisco_value = -1;
static int hf_capwap_cisco_mwar_addr = -1;
static int hf_capwap_cisco_rad_name = -1;
static int hf_capwap_cisco_mwar_type = -1;
static int hf_capwap_cisco_mwar_hardware = -1;
static int hf_capwap_cisco_mwar_software = -1;
static int hf_capwap_cisco_mwar_active_ms = -1;
static int hf_capwap_cisco_mwar_supported_ms = -1;
static int hf_capwap_cisco_mwar_active_rad = -1;
static int hf_capwap_cisco_mwar_supported_rad = -1;
static int hf_capwap_cisco_ap_mode_and_type_mode = -1;
static int hf_capwap_cisco_ap_mode_and_type_type = -1;
static int hf_capwap_cisco_ap_static_ip_addr = -1;
static int hf_capwap_cisco_ap_static_ip_netmask = -1;
static int hf_capwap_cisco_ap_static_ip_gateway = -1;
static int hf_capwap_cisco_ap_static_ip_type = -1;
static int hf_capwap_cisco_ap_static_ip_reserved = -1;
static int hf_capwap_cisco_ap_uptime_current = -1;
static int hf_capwap_cisco_ap_uptime_last = -1;
static int hf_capwap_cisco_ap_group_name = -1;
static int hf_capwap_cisco_ap_led_state = -1;
static int hf_capwap_cisco_ap_timesync = -1;
static int hf_capwap_cisco_ap_timesync_type = -1;
static int hf_capwap_cisco_board_data_options_ant_type = -1;
static int hf_capwap_cisco_board_data_options_flex_connect = -1;
static int hf_capwap_cisco_board_data_options_ap_type = -1;
static int hf_capwap_cisco_board_data_options_join_priority = -1;
static int hf_capwap_cisco_unknown = -1;

static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;

static dissector_handle_t dtls_handle;
static dissector_handle_t ieee8023_handle;
static dissector_handle_t ieee80211_handle;
static dissector_handle_t ieee80211_bsfc_handle;

static gint ett_capwap = -1;
static gint ett_capwap_control = -1;
static gint ett_capwap_data = -1;
static gint ett_capwap_preamble = -1;
static gint ett_capwap_header = -1;
static gint ett_capwap_header_flags = -1;
static gint ett_capwap_control_header = -1;
static gint ett_capwap_control_header_msg = -1;
static gint ett_capwap_data_keep_alive = -1;
static gint ett_capwap_message_element = -1;
static gint ett_capwap_data_message_bindings_ieee80211 = -1;
static gint ett_capwap_encryption_capabilities = -1;
static gint ett_capwap_encryption_capability = -1;
static gint ett_capwap_ac_information = -1;
static gint ett_capwap_wtp_descriptor = -1;
static gint ett_capwap_board_data = -1;
static gint ett_capwap_message_element_type = -1;
static gint ett_capwap_ac_descriptor_security_flags = -1;
static gint ett_capwap_ac_descriptor_dtls_flags = -1;
static gint ett_capwap_wtp_frame_tunnel_mode = -1;
static gint ett_capwap_ieee80211_add_wlan_capability = -1;
static gint ett_capwap_ieee80211_ie_flags = -1;
static gint ett_capwap_ieee80211_update_wlan_capability = -1;
static gint ett_capwap_ieee80211_station_capabilities = -1;
static gint ett_capwap_ieee80211_ofdm_control_band_support = -1;

static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static expert_field ei_capwap_header_length_bad = EI_INIT;
static expert_field ei_capwap_data_keep_alive_length = EI_INIT;
static expert_field ei_capwap_msg_element_length = EI_INIT;
static expert_field ei_capwap_message_element_type = EI_INIT;
static expert_field ei_capwap_fortinet_mac_len = EI_INIT;
static expert_field ei_capwap_message_element_fortinet_type = EI_INIT;
static expert_field ei_capwap_message_element_cisco_type = EI_INIT;

static int * const ieee80211_ofdm_control_band_support_flags[] = {
    &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit0,
    &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit1,
    &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit2,
    &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit3,
    &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit4,
    &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit5,
    &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit6,
    &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit7,
    NULL
};

static int * const ieee80211_ie_flags[] = {
    &hf_capwap_msg_element_type_ieee80211_ie_flags_b,
    &hf_capwap_msg_element_type_ieee80211_ie_flags_p,
    &hf_capwap_msg_element_type_ieee80211_ie_flags_rsv,
    NULL
};

static int * const capwap_ac_descriptor_security_flags[] = {
    &hf_capwap_msg_element_type_ac_descriptor_security_r,
    &hf_capwap_msg_element_type_ac_descriptor_security_s,
    &hf_capwap_msg_element_type_ac_descriptor_security_x,
    NULL
};

static int * const capwap_ac_descriptor_dtls_flags[] = {
    &hf_capwap_msg_element_type_ac_descriptor_dtls_policy_r,
    &hf_capwap_msg_element_type_ac_descriptor_dtls_policy_d,
    &hf_capwap_msg_element_type_ac_descriptor_dtls_policy_c,
    NULL
};

static int * const capwap_wtp_frame_tunnel_mode_flags[] = {
    &hf_capwap_msg_element_type_wtp_frame_tunnel_mode_n,
    &hf_capwap_msg_element_type_wtp_frame_tunnel_mode_e,
    &hf_capwap_msg_element_type_wtp_frame_tunnel_mode_l,
    &hf_capwap_msg_element_type_wtp_frame_tunnel_mode_r,
    NULL
};

static int * const ieee80211_add_wlan_capability_flags[] = {
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_e,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_i,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_c,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_f,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_p,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_s,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_b,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_a,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_m,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_q,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_t,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_d,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_v,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_o,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_k,
    &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_l,
    NULL
};

static int * const ieee80211_station_capabilities_flags[] ={
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_e,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_i,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_c,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_f,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_p,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_s,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_b,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_a,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_m,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_q,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_t,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_d,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_v,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_o,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_k,
    &hf_capwap_msg_element_type_ieee80211_station_capabilities_l,
    NULL
};

static int * const ieee80211_update_wlan_capability_flags[] = {
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_e,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_i,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_c,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_f,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_p,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_s,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_b,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_a,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_m,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_q,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_t,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_d,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_v,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_o,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_k,
    &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_l,
    NULL
};

/* ************************************************************************* */
/*                  Fragment items                                           */
/* ************************************************************************* */

static const fragment_items capwap_frag_items = {
    /* Fragment subtrees */
    &ett_msg_fragment,
    &ett_msg_fragments,
    /* Fragment fields */
    &hf_msg_fragments,
    &hf_msg_fragment,
    &hf_msg_fragment_overlap,
    &hf_msg_fragment_overlap_conflicts,
    &hf_msg_fragment_multiple_tails,
    &hf_msg_fragment_too_long_fragment,
    &hf_msg_fragment_error,
    &hf_msg_fragment_count,
    /* Reassembled in field */
    &hf_msg_reassembled_in,
    /* Reassembled length field */
    &hf_msg_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Message fragments"
};

/* ************************************************************************* */
/*                  Header Type                                              */
/* ************************************************************************* */
static const value_string type_header_vals[] = {
    { 0, "CAPWAP Header" },
    { 1, "CAPWAP DTLS Header" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                   Wireless Binding IDentifier (WBID)                      */
/* ************************************************************************* */
static const value_string type_wbid[] = {
    { 0, "Reserved" },
    { 1, "IEEE 802.11" },
    { 2, "IEEE 802.16" }, /* From old RFC Draft... */
    { 3, "EPCGlobal" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                 flag Type Transported (payload)                           */
/* ************************************************************************* */
static const true_false_string flag_type_t = {
    "Native frame format (see Wireless Binding ID field)",
    "IEEE 802.3 frame"
};
/* ************************************************************************* */
/*                 flag Type Fragment                                        */
/* ************************************************************************* */
static const true_false_string flag_type_f = {
    "Fragmented",
    "Don't Fragment"
};
/* ************************************************************************* */
/*                 flag Type Last Fragment                                   */
/* ************************************************************************* */
static const true_false_string flag_type_l = {
    "This is the last fragment",
    "More fragments follow"
 };
/* ************************************************************************* */
/*                 flag Type Wireless                                        */
/* ************************************************************************* */
static const true_false_string flag_type_w = {
    "Wireless Specific Information is present",
    "No Wireless Specific Information"
 };
/* ************************************************************************* */
/*                 flag Type Radio Mac                                       */
/* ************************************************************************* */
static const true_false_string flag_type_m = {
    "Radio MAC Address is present",
    "No Radio MAC Address"
 };
/* ************************************************************************* */
/*                 flag Type Keep Alive                                      */
/* ************************************************************************* */
static const true_false_string flag_type_k = {
    "Keep-Alive Packet",
    "No Keep-Alive"
 };
/* ************************************************************************* */
/*                  Message Type Value                                       */
/* ************************************************************************* */
static const value_string message_type[] = {
    { 1, "Discovery Request" },
    { 2, "Discovery Response" },
    { 3, "Join Request" },
    { 4, "Join Response" },
    { 5, "Configuration Status Request" },
    { 6, "Configuration Status Response" },
    { 7, "Configuration Update Request" },
    { 8, "Configuration Update Response" },
    { 9, "WTP Event Request" },
    { 10, "WTP Event Response" },
    { 11, "Change State Request" },
    { 12, "Change State Response" },
    { 13, "Echo Request" },
    { 14, "Echo Response" },
    { 15, "Image Data Request" },
    { 16, "Image Data Response" },
    { 17, "Reset Request" },
    { 18, "Reset Response" },
    { 19, "Primary Discovery Request" },
    { 20, "Primary Discovery Response" },
    { 21, "Data Transfer Request" },
    { 22, "Data Transfer Response" },
    { 23, "Clear Configuration Request" },
    { 24, "Clear Configuration Response" },
    { 25, "Station Configuration Request" },
    { 26, "Station Configuration Response" },
    /* RFC5416 : Section 3 : IEEE 802.11 Specific CAPWAP Control Messages */
    { 3398913, "IEEE 802.11 WLAN Configuration Request" },
    { 3398914, "IEEE 802.11 WLAN Configuration Response" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                      Message Element Type                                 */
/* ************************************************************************* */
#define TYPE_AC_DESCRIPTOR                        1
#define TYPE_AC_IPV4_LIST                         2
#define TYPE_AC_IPV6_LIST                         3
#define TYPE_AC_NAME                              4
#define TYPE_AC_NAME_W_PRIORITY                   5
#define TYPE_AC_TIMESTAMP                         6
#define TYPE_ADD_MAC_ACL_ENTRY                    7
#define TYPE_ADD_STATION                          8
#define TYPE_RESERVED_9                           9
#define TYPE_CAPWAP_CONTROL_IPV4_ADDRESS          10
#define TYPE_CAPWAP_CONTROL_IPV6_ADDRESS          11
#define TYPE_CAPWAP_TIMERS                        12
#define TYPE_DATA_TRANSFER_DATA                   13
#define TYPE_DATA_TRANSFER_MODE                   14
#define TYPE_DESCRYPTION_ERROR_REPORT             15
#define TYPE_DECRYPTION_ERROR_REPORT_PERIOD       16
#define TYPE_DELETE_MAC_ENTRY                     17
#define TYPE_DELETE_STATION                       18
#define TYPE_RESERVED_19                          19
#define TYPE_DISCOVERY_TYPE                       20
#define TYPE_DUPLICATE_IPV4_ADDRESS               21
#define TYPE_DUPLICATE_IPV6_ADDRESS               22
#define TYPE_IDLE_TIMEOUT                         23
#define TYPE_IMAGE_DATA                           24
#define TYPE_IMAGE_IDENTIFIER                     25
#define TYPE_IMAGE_INFORMATION                    26
#define TYPE_INITIATE_DOWNLOAD                    27
#define TYPE_LOCATION_DATA                        28
#define TYPE_MAXIMUM_MESSAGE_LENGTH               29
#define TYPE_CAPWAP_LOCAL_IPV4_ADDRESS            30
#define TYPE_RADIO_ADMINISTRATIVE_STATE           31
#define TYPE_RADIO_OPERATIONAL_STATE              32
#define TYPE_RESULT_CODE                          33
#define TYPE_RETURNED_MESSAGE_ELEMENT             34
#define TYPE_SESSION_ID                           35
#define TYPE_STATISTICS_TIMER                     36
#define TYPE_VENDOR_SPECIFIC_PAYLOAD              37
#define TYPE_WTP_BOARD_DATA                       38
#define TYPE_WTP_DESCRIPTOR                       39
#define TYPE_WTP_FALLBACK                         40
#define TYPE_WTP_FRAME_TUNNEL_MODE                41
#define TYPE_RESERVED_42                          42
#define TYPE_RESERVED_43                          43
#define TYPE_WTP_MAC_TYPE                         44
#define TYPE_WTP_NAME                             45
#define TYPE_RESERVED_46                          46
#define TYPE_WTP_RADIO_STATISTICS                 47
#define TYPE_WTP_REBOOT_STATISTICS                48
#define TYPE_WTP_STATIC_IP_ADDRESS_INFORMATION    49
#define TYPE_CAPWAP_LOCAL_IPV6_ADDRESS            50
#define TYPE_CAPWAP_TRANSPORT_PROTOCOL            51
#define TYPE_MTU_DISCOVERY_PADDING                52
#define TYPE_ECN_SUPPORT                          53

#define IEEE80211_ADD_WLAN                        1024
#define IEEE80211_ANTENNA                         1025
#define IEEE80211_ASSIGNED_WTP_BSSID              1026
#define IEEE80211_DELETE_WLAN                     1027
#define IEEE80211_DIRECT_SEQUENCE_CONTROL         1028
#define IEEE80211_INFORMATION_ELEMENT             1029
#define IEEE80211_MAC_OPERATION                   1030
#define IEEE80211_MIC_COUNTERMEASURES             1031
#define IEEE80211_MULTI_DOMAIN_CAPABILITY         1032
#define IEEE80211_OFDM_CONTROL                    1033
#define IEEE80211_RATE_SET                        1034
#define IEEE80211_RSNA_ERROR_REPORT_FROM_STATION  1035
#define IEEE80211_STATION                         1036
#define IEEE80211_STATION_QOS_PROFILE             1037
#define IEEE80211_STATION_SESSION_KEY             1038
#define IEEE80211_STATISTICS                      1039
#define IEEE80211_SUPPORTED_RATES                 1040
#define IEEE80211_TX_POWER                        1041
#define IEEE80211_TX_POWER_LEVEL                  1042
#define IEEE80211_UPDATE_STATION_QOS              1043
#define IEEE80211_UPDATE_WLAN                     1044
#define IEEE80211_WTP_QUALITY_OF_SERVICE          1045
#define IEEE80211_WTP_RADIO_CONFIGURATION         1046
#define IEEE80211_WTP_RADIO_FAIL_ALARM_INDICATION 1047
#define IEEE80211_WTP_RADIO_INFORMATION           1048
#define IEEE80211_SUPPORTED_MAC_PROFILES          1060
#define IEEE80211_MAC_PROFILE                     1061
/* ************************************************************************* */
/*                      Message Element Type Value                           */
/* ************************************************************************* */
static const value_string message_element_type_vals[] = {
    { TYPE_AC_DESCRIPTOR, "AC Descriptor" },
    { TYPE_AC_IPV4_LIST, "AC IPv4 List" },
    { TYPE_AC_IPV6_LIST, "AC IPv6 List" },
    { TYPE_AC_NAME, "AC Name" },
    { TYPE_AC_NAME_W_PRIORITY, "AC Name With Priority" },
    { TYPE_AC_TIMESTAMP, "AC Timestamp" },
    { TYPE_ADD_MAC_ACL_ENTRY, "Add MAC ACL Entry" },
    { TYPE_ADD_STATION, "Add Station" },
    { TYPE_RESERVED_9, "Reserved" },
    { TYPE_CAPWAP_CONTROL_IPV4_ADDRESS, "CAPWAP Control IPv4 Address" },
    { TYPE_CAPWAP_CONTROL_IPV6_ADDRESS, "CAPWAP Control IPv6 Address" },
    { TYPE_CAPWAP_TIMERS, "CAPWAP Timers" },
    { TYPE_DATA_TRANSFER_DATA, "Data Transfer Data" },
    { TYPE_DATA_TRANSFER_MODE, "Data Transfer Mode" },
    { TYPE_DESCRYPTION_ERROR_REPORT, "Decryption Error Report" },
    { TYPE_DECRYPTION_ERROR_REPORT_PERIOD, "Decryption Error Report Period" },
    { TYPE_DELETE_MAC_ENTRY, "Delete MAC ACL Entry" },
    { TYPE_DELETE_STATION, "Delete Station" },
    { TYPE_RESERVED_19, "Reserved" },
    { TYPE_DISCOVERY_TYPE, "Discovery Type" },
    { TYPE_DUPLICATE_IPV4_ADDRESS, "Duplicate IPv4 Address" },
    { TYPE_DUPLICATE_IPV6_ADDRESS, "Duplicate IPv6 Address" },
    { TYPE_IDLE_TIMEOUT, "Idle Timeout" },
    { TYPE_IMAGE_DATA, "Image Data" },
    { TYPE_IMAGE_IDENTIFIER, "Image Identifier" },
    { TYPE_IMAGE_INFORMATION, "Image Information" },
    { TYPE_INITIATE_DOWNLOAD, "Initiate Download" },
    { TYPE_LOCATION_DATA, "Location Data" },
    { TYPE_MAXIMUM_MESSAGE_LENGTH, "Maximum Message Length" },
    { TYPE_CAPWAP_LOCAL_IPV4_ADDRESS, "CAPWAP Local IPv4 Address" },
    { TYPE_RADIO_ADMINISTRATIVE_STATE, "Radio Administrative State " },
    { TYPE_RADIO_OPERATIONAL_STATE, "Radio Operational State" },
    { TYPE_RESULT_CODE, "Result Code" },
    { TYPE_RETURNED_MESSAGE_ELEMENT, "Returned Message Element" },
    { TYPE_SESSION_ID, "Session ID" },
    { TYPE_STATISTICS_TIMER, "Statistics Timer" },
    { TYPE_VENDOR_SPECIFIC_PAYLOAD, "Vendor Specific Payload" },
    { TYPE_WTP_BOARD_DATA, "WTP Board Data" },
    { TYPE_WTP_DESCRIPTOR, "WTP Descriptor" },
    { TYPE_WTP_FALLBACK, "WTP Fallback " },
    { TYPE_WTP_FRAME_TUNNEL_MODE, "WTP Frame Tunnel Mode " },
    { TYPE_RESERVED_42, "Reserved" },
    { TYPE_RESERVED_43, "Reserved" },
    { TYPE_WTP_MAC_TYPE, "WTP MAC Type" },
    { TYPE_WTP_NAME, "WTP Name" },
    { TYPE_RESERVED_46, "Unused/Reserved" },
    { TYPE_WTP_RADIO_STATISTICS, "WTP Radio Statistics" },
    { TYPE_WTP_REBOOT_STATISTICS, "WTP Reboot Statistics" },
    { TYPE_WTP_STATIC_IP_ADDRESS_INFORMATION, "WTP Static IP Address Information" },
    { TYPE_CAPWAP_LOCAL_IPV6_ADDRESS, "CAPWAP Local IPv6 Address" },
    { TYPE_CAPWAP_TRANSPORT_PROTOCOL, "CAPWAP Transport Protocol" },
    { TYPE_MTU_DISCOVERY_PADDING, "MTU Discovery Padding" },
    { TYPE_ECN_SUPPORT, "ECN Support" },

    { IEEE80211_ADD_WLAN, "IEEE 802.11 Add WLAN" },
    { IEEE80211_ANTENNA, "IEEE 802.11 Antenna" },
    { IEEE80211_ASSIGNED_WTP_BSSID, "IEEE 802.11 Assigned WTP BSSID" },
    { IEEE80211_DELETE_WLAN, "IEEE 802.11 Delete WLAN" },
    { IEEE80211_DIRECT_SEQUENCE_CONTROL, "IEEE 802.11 Direct Sequence Control" },
    { IEEE80211_INFORMATION_ELEMENT, "IEEE 802.11 Information Element" },
    { IEEE80211_MAC_OPERATION, "IEEE 802.11 MAC Operation" },
    { IEEE80211_MIC_COUNTERMEASURES, "IEEE 802.11 MIC Countermeasures" },
    { IEEE80211_MULTI_DOMAIN_CAPABILITY, "IEEE 802.11 Multi-Domain Capability" },
    { IEEE80211_OFDM_CONTROL, "IEEE 802.11 OFDM Control" },
    { IEEE80211_RATE_SET, "IEEE 802.11 Rate Set" },
    { IEEE80211_RSNA_ERROR_REPORT_FROM_STATION, "IEEE 802.11 RSNA Error Report From Station" },
    { IEEE80211_STATION, "IEEE 802.11 Station" },
    { IEEE80211_STATION_QOS_PROFILE, "IEEE 802.11 Station QoS Profile" },
    { IEEE80211_STATION_SESSION_KEY, "IEEE 802.11 Station Session Key" },
    { IEEE80211_STATISTICS, "IEEE 802.11 Statistics" },
    { IEEE80211_SUPPORTED_RATES, "IEEE 802.11 Supported Rates" },
    { IEEE80211_TX_POWER, "IEEE 802.11 Tx Power" },
    { IEEE80211_TX_POWER_LEVEL, "IEEE 802.11 Tx Power Level" },
    { IEEE80211_UPDATE_STATION_QOS, "IEEE 802.11 Update Station QoS" },
    { IEEE80211_UPDATE_WLAN, "IEEE 802.11 Update WLAN" },
    { IEEE80211_WTP_QUALITY_OF_SERVICE, "IEEE 802.11 WTP Quality of Service" },
    { IEEE80211_WTP_RADIO_CONFIGURATION, "IEEE 802.11 WTP Radio Configuration" },
    { IEEE80211_WTP_RADIO_FAIL_ALARM_INDICATION, "IEEE 802.11 WTP Radio Fail Alarm Indication" },
    { IEEE80211_WTP_RADIO_INFORMATION, "IEEE 802.11 WTP Radio Information" },
    { IEEE80211_SUPPORTED_MAC_PROFILES, "IEEE 802.11 Supported MAC Profiles" },
    { IEEE80211_MAC_PROFILE, "IEEE 802.11 MAC Profile" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                      Discovery Type                                       */
/* ************************************************************************* */
static const value_string discovery_type_vals[] = {
    { 0, "Unknown" },
    { 1, "Static Configuration" },
    { 2, "DHCP" },
    { 3, "DNS" },
    { 4, "AC Referral" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                      Radio Administrative State                           */
/* ************************************************************************* */
static const value_string radio_admin_state_vals[] = {
    { 1, "Enabled" },
    { 2, "Disabled" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                      Radio Operational State                              */
/* ************************************************************************* */
static const value_string radio_op_state_vals[] = {
    { 0, "Reserved" },
    { 1, "Enabled" },
    { 2, "Disabled" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                      Radio Operational Cause                              */
/* ************************************************************************* */
static const value_string radio_op_cause_vals[] = {
    { 0, "Normal" },
    { 1, "Radio Failure" },
    { 2, "Software Failure" },
    { 3, "Administratively Set" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                      Result Code                                          */
/* ************************************************************************* */
static const value_string result_code_vals[] = {
    { 0 , "Success" },
    { 1 , "Failure (AC List Message Element MUST Be Present)" },
    { 2 , "Success (NAT Detected)" },
    { 3 , "Join Failure (Unspecified)" },
    { 4 , "Join Failure (Resource Depletion)" },
    { 5 , "Join Failure (Unknown Source)" },
    { 6 , "Join Failure (Incorrect Data)" },
    { 7 , "Join Failure (Session ID Already in Use)" },
    { 8 , "Join Failure (WTP Hardware Not Supported)" },
    { 9 , "Join Failure (Binding Not Supported)" },
    { 10, "Reset Failure (Unable to Reset)" },
    { 11, "Reset Failure (Firmware Write Error)" },
    { 12, "Configuration Failure (Unable to Apply Requested Configuration - Service Provided Anyhow)" },
    { 13, "Configuration Failure (Unable to Apply Requested Configuration - Service Not Provided)" },
    { 14, "Image Data Error (Invalid Checksum)" },
    { 15, "Image Data Error (Invalid Data Length)" },
    { 16, "Image Data Error (Other Error)" },
    { 17, "Image Data Error (Image Already Present)" },
    { 18, "Message Unexpected (Invalid in Current State)" },
    { 19, "Message Unexpected (Unrecognized Request)" },
    { 20, "Failure - Missing Mandatory Message Element" },
    { 21, "Failure - Unrecognized Message Element" },
    { 22, "Data Transfer Error (No Information to Transfer)" },
    { 0 ,     NULL     }
};
/* ************************************************************************* */
/*                      Radio MAC Address Field                              */
/* ************************************************************************* */
static const value_string rmac_field_vals[] = {
    { 0, "Reserved" },
    { 1, "Supported" },
    { 2, "Not Supported" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                      Board Data Type Value                                */
/* ************************************************************************* */
#define BOARD_DATA_WTP_MODEL_NUMBER 0
#define BOARD_DATA_WTP_SERIAL_NUMBER 1
#define BOARD_DATA_BOARD_ID 2
#define BOARD_DATA_BOARD_REVISION 3
#define BOARD_DATA_BASE_MAC_ADDRESS 4

static const value_string board_data_type_vals[] = {
    { BOARD_DATA_WTP_MODEL_NUMBER, "WTP Model Number" },
    { BOARD_DATA_WTP_SERIAL_NUMBER, "WTP Serial Number" },
    { BOARD_DATA_BOARD_ID, "Board ID" },
    { BOARD_DATA_BOARD_REVISION, "Board Revision" },
    { BOARD_DATA_BASE_MAC_ADDRESS, "Base MAC Address" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                      Descriptor WTP Type Value                            */
/* ************************************************************************* */
#define WTP_DESCRIPTOR_HARDWARE_VERSION 0
#define WTP_DESCRIPTOR_ACTIVE_SOFTWARE_VERSION 1
#define WTP_DESCRIPTOR_BOOT_VERSION 2
#define WTP_DESCRIPTOR_OTHER_SOFTWARE_VERSION 3

static const value_string wtp_descriptor_type_vals[] = {
    { WTP_DESCRIPTOR_HARDWARE_VERSION, "WTP Hardware Version" },
    { WTP_DESCRIPTOR_ACTIVE_SOFTWARE_VERSION, "WTP Active Software Version" },
    { WTP_DESCRIPTOR_BOOT_VERSION, "WTP Boot Version" },
    { WTP_DESCRIPTOR_OTHER_SOFTWARE_VERSION, "WTP Other Software Version" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                      AC Information Type Value                            */
/* ************************************************************************* */
#define AC_INFORMATION_HARDWARE_VERSION 4
#define AC_INFORMATION_SOFTWARE_VERSION 5

static const value_string ac_information_type_vals[] = {
    { AC_INFORMATION_HARDWARE_VERSION, "AC Hardware Version" },
    { AC_INFORMATION_SOFTWARE_VERSION, "AC Software Version" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                      WTP MAC Type                                         */
/* ************************************************************************* */
static const value_string wtp_mac_vals[] = {
    { 0, "Local MAC" },
    { 1, "Split MAC" },
    { 2, "Both (Local and Split MAC)" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                      WTP Fallback                                         */
/* ************************************************************************* */
static const value_string wtp_fallback_vals[] = {
    { 0, "Reserved" },
    { 1, "Enabled" },
    { 2, "Disabled" },
    { 0,     NULL     }
};
/* ************************************************************************* */
/*                     Last Failure Type                                     */
/* ************************************************************************* */
static const value_string last_failure_type_vals[] = {
    { 0, "Not Supported" },
    { 1, "AC Initiated" },
    { 2, "Link Failure" },
    { 3, "Software Failure" },
    { 4, "Hardware Failure" },
    { 5, "Other Failure" },
    { 255, "Unknown (e.g., WTP doesn't keep track of info)" },
    { 0,     NULL     }
};

/* ************************************************************************* */
/*                     CAPWAP Transport Protocol                             */
/* ************************************************************************* */
static const value_string capwap_transport_protocol_vals[] = {
    { 1, "UDP-Lite" },
    { 2, "UDP" },
    { 0,     NULL     }
};

/* ************************************************************************* */
/*                     ECN Support                                           */
/* ************************************************************************* */
static const value_string ecn_support_vals[] = {
    { 0, "Limited ECN Support" },
    { 1, "Full and Limited ECN Support" },
    { 0,     NULL     }
};

/* ************************************************************************* */
/*                     Add/Update WLAN : Key Status                          */
/* ************************************************************************* */
static const value_string ieee80211_wlan_key_status_vals[] = {
    { 0, "SN Information Element means that the WLAN uses per-station encryption keys" },
    { 1, "static WEP Key" },
    { 2, "Rekeying the GTK with the STA's in the BSS" },
    { 3, "Rekeying the GTK and broadcast" },
    { 0,     NULL     }
};

/* ************************************************************************* */
/*                     Add WLAN : QoS                                        */
/* ************************************************************************* */
static const value_string ieee80211_add_wlan_qos_vals[] = {
    { 0, "Best Effort" },
    { 1, "Video" },
    { 2, "Voice" },
    { 3, "Background" },
    { 0,     NULL     }
};

/* ************************************************************************* */
/*                     Add WLAN : Auth Type                                  */
/* ************************************************************************* */
static const value_string ieee80211_add_wlan_auth_type_vals[] = {
    { 0, "Open System" },
    { 1, "WEP Shared Key" },
    { 0,     NULL     }
};

/* ************************************************************************* */
/*                     Add WLAN : MAC Mode                                   */
/* ************************************************************************* */
static const value_string ieee80211_add_wlan_mac_mode_vals[] = {
    { 0, "Local MAC" },
    { 1, "Split MAC" },
    { 0,     NULL     }
};

/* ************************************************************************* */
/*                     Add WLAN : Tunnel Mode                                */
/* ************************************************************************* */
static const value_string ieee80211_add_wlan_tunnel_mode_vals[] = {
    { 0, "Local Bridging" },
    { 1, "802.3 Tunnel" },
    { 2, "802.11 Tunnel" },
    { 0,     NULL     }
};

/* ************************************************************************* */
/*                     IEE8011 Antenna                                       */
/* ************************************************************************* */
static const value_string ieee80211_antenna_diversity_vals[] = {
    { 0, "Disabled" },
    { 1, "Enabled" },
    { 0, NULL }
};

static const value_string ieee80211_antenna_combiner_vals[] = {
    { 1, "Sectorized (Left)" },
    { 2, "Sectorized (Right)" },
    { 3, "Omni" },
    { 4, "Multiple Input/Multiple Output (MIMO)" },
    { 0, NULL }
};

static const value_string ieee80211_antenna_selection_vals[] = {
    { 1, "Internal Antenna" },
    { 2, "External Antenna" },
    { 0, NULL }
};
/* ************************************************************************* */
/*                     IEE8011 MAC Profile                                   */
/* ************************************************************************* */
static const value_string ieee80211_mac_profile_vals[] = {
    { 0, "Split MAC with WTP encryption" },
    { 1, "Split MAC with AC encryption" },
    { 0,     NULL     }
};

static void
dissect_capwap_data_message_bindings_ieee80211(tvbuff_t *tvb, proto_tree *data_message_binding_tree, guint offset, packet_info *pinfo)
{
    proto_item *data_message_binding_item, *ti;
    proto_tree *sub_data_message_binding_tree;

    if (value_is_in_range(global_capwap_data_udp_ports, pinfo->destport))
    {
        guint16 data_rate;
        /* (WTP -> AC) IEEE 802.11 Frame Info */
        data_message_binding_item = proto_tree_add_item(data_message_binding_tree, hf_capwap_header_wireless_data_ieee80211_fi, tvb, offset, 4, ENC_NA);
        sub_data_message_binding_tree = proto_item_add_subtree(data_message_binding_item, ett_capwap_data_message_bindings_ieee80211);

        proto_tree_add_item(sub_data_message_binding_tree, hf_capwap_header_wireless_data_ieee80211_fi_rssi, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(sub_data_message_binding_tree, hf_capwap_header_wireless_data_ieee80211_fi_snr, tvb, offset+1, 1, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(sub_data_message_binding_tree, hf_capwap_header_wireless_data_ieee80211_fi_data_rate, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        data_rate = tvb_get_ntohs(tvb, offset+2);
        proto_item_append_text(ti, " (%.1f Mb/s)", ((float)data_rate / 10));
    }
    else
    {
        /* (AC -> WTP) IEEE 802.11 Destination Wlans */
        data_message_binding_item = proto_tree_add_item(data_message_binding_tree, hf_capwap_header_wireless_data_ieee80211_dest_wlan,tvb, offset, 4, ENC_NA);
        sub_data_message_binding_tree = proto_item_add_subtree(data_message_binding_item, ett_capwap_data_message_bindings_ieee80211);

        proto_tree_add_item(sub_data_message_binding_tree, hf_capwap_header_wireless_data_ieee80211_dw_wlan_id_bitmap, tvb, offset, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(sub_data_message_binding_tree, hf_capwap_header_wireless_data_ieee80211_dw_reserved, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    }
}

static void
dissect_capwap_encryption_capabilities(tvbuff_t *tvb, proto_tree *encryption_capabilities_tree, guint offset)
{
    proto_item *encryption_capabilities_item;
    proto_tree *sub_encryption_capabilities_tree;

    encryption_capabilities_item = proto_tree_add_item(encryption_capabilities_tree, hf_capwap_msg_element_type_wtp_descriptor_encrypt, tvb, offset, 3, ENC_NA);
    sub_encryption_capabilities_tree = proto_item_add_subtree(encryption_capabilities_item, ett_capwap_encryption_capability);

    proto_tree_add_item(sub_encryption_capabilities_tree, hf_capwap_msg_element_type_wtp_descriptor_encrypt_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item (sub_encryption_capabilities_tree, hf_capwap_msg_element_type_wtp_descriptor_encrypt_wbid, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(encryption_capabilities_item, ": (WBID %d)",tvb_get_guint8(tvb, offset) & 0x1F);


    proto_tree_add_item(sub_encryption_capabilities_tree, hf_capwap_msg_element_type_wtp_descriptor_encrypt_capabilities, tvb, offset+1, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(encryption_capabilities_item, " %d",tvb_get_ntohs(tvb, offset+1));

}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_ac_information(tvbuff_t *tvb, proto_tree *ac_information_type_tree, guint offset)
{
    guint optlen,ac_information_type = 0;
    proto_item *ac_information_type_item;
    proto_tree *sub_ac_information_type_tree;

    ac_information_type = tvb_get_ntohs(tvb, offset+4);
    optlen = tvb_get_ntohs(tvb, offset+6);
    ac_information_type_item = proto_tree_add_item(ac_information_type_tree, hf_capwap_msg_element_type_ac_information, tvb, offset, 4+2+2+optlen, ENC_NA );

    proto_item_append_text(ac_information_type_item,": (t=%d,l=%d) %s", ac_information_type, optlen, val_to_str(ac_information_type,ac_information_type_vals,"Unknown AC Information Type (%02d)") );

    sub_ac_information_type_tree = proto_item_add_subtree(ac_information_type_item, ett_capwap_ac_information);

    proto_tree_add_item(sub_ac_information_type_tree, hf_capwap_msg_element_type_ac_information_vendor, tvb, offset, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(sub_ac_information_type_tree, hf_capwap_msg_element_type_ac_information_type, tvb, offset+4, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(sub_ac_information_type_tree, hf_capwap_msg_element_type_ac_information_length, tvb, offset+6, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(sub_ac_information_type_tree, hf_capwap_msg_element_type_ac_information_value, tvb, offset+8, optlen, ENC_NA);

    switch (ac_information_type) {
    case AC_INFORMATION_HARDWARE_VERSION:
        proto_tree_add_item(sub_ac_information_type_tree, hf_capwap_msg_element_type_ac_information_hardware_version, tvb, offset+8, optlen, ENC_ASCII);
        break;

    case AC_INFORMATION_SOFTWARE_VERSION:
        proto_tree_add_item(sub_ac_information_type_tree, hf_capwap_msg_element_type_ac_information_software_version, tvb, offset+8, optlen, ENC_ASCII);
        break;

    default:
        /* No Default Action */
        break;
    }
    return 4+2+2+optlen;
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_wtp_descriptor(tvbuff_t *tvb, proto_tree *wtp_descriptor_type_tree, guint offset)
{
    guint optlen,wtp_descriptor_type = 0;
    proto_item *wtp_descriptor_type_item;
    proto_tree *sub_wtp_descriptor_type_tree;

    wtp_descriptor_type = tvb_get_ntohs(tvb, offset+4);
    optlen = tvb_get_ntohs(tvb, offset+6);
    wtp_descriptor_type_item = proto_tree_add_item(wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor, tvb, offset, 4+2+2+optlen, ENC_NA);

    proto_item_append_text(wtp_descriptor_type_item, ": (t=%d,l=%d) %s", wtp_descriptor_type, optlen, val_to_str(wtp_descriptor_type,wtp_descriptor_type_vals,"Unknown WTP Descriptor Type (%02d)") );

    sub_wtp_descriptor_type_tree = proto_item_add_subtree(wtp_descriptor_type_item, ett_capwap_wtp_descriptor);

    proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_vendor, tvb, offset, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_type, tvb, offset+4, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_length, tvb, offset+6, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_value, tvb, offset+8, optlen, ENC_NA);

    switch (wtp_descriptor_type) {
    case WTP_DESCRIPTOR_HARDWARE_VERSION:
        proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_hardware_version, tvb, offset+8, optlen, ENC_ASCII);
        break;

    case WTP_DESCRIPTOR_ACTIVE_SOFTWARE_VERSION:
        proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_active_software_version, tvb, offset+8, optlen, ENC_ASCII);
        break;

    case WTP_DESCRIPTOR_BOOT_VERSION:
        proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_boot_version, tvb, offset+8, optlen, ENC_ASCII);
        break;

    case WTP_DESCRIPTOR_OTHER_SOFTWARE_VERSION:
        proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_other_software_version, tvb, offset+8, optlen, ENC_ASCII);
        break;

    default:
        /* No Default Action */
        break;
    }

    return 4+2+2+optlen;
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_board_data(tvbuff_t *tvb, proto_tree *board_data_type_tree, guint offset)
{
    guint optlen,board_data_type = 0;
    proto_item *board_data_type_item;
    proto_tree *sub_board_data_type_tree;

    board_data_type = tvb_get_ntohs(tvb, offset);
    optlen = tvb_get_ntohs(tvb, offset+2);
    board_data_type_item = proto_tree_add_item(board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data, tvb, offset, 2+2+optlen, ENC_NA );

    proto_item_append_text(board_data_type_item, ": (t=%d,l=%d) %s", board_data_type, optlen, val_to_str(board_data_type,board_data_type_vals,"Unknown Board Data Type (%02d)") );

    sub_board_data_type_tree = proto_item_add_subtree(board_data_type_item, ett_capwap_board_data);

    proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_type, tvb, offset, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_value, tvb, offset+4, optlen, ENC_NA);
    switch (board_data_type) {
    case BOARD_DATA_WTP_MODEL_NUMBER:
        proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_wtp_model_number, tvb, offset+4, optlen, ENC_ASCII);
        break;

    case BOARD_DATA_WTP_SERIAL_NUMBER:
        proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_wtp_serial_number, tvb, offset+4, optlen, ENC_ASCII);
        break;

    case BOARD_DATA_BOARD_ID:
        proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_wtp_board_id, tvb, offset+4, optlen, ENC_ASCII);
        break;

    case BOARD_DATA_BOARD_REVISION:
        proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_wtp_board_revision, tvb, offset+4, optlen, ENC_ASCII);
        break;

    case BOARD_DATA_BASE_MAC_ADDRESS:
        proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_base_mac_address, tvb, offset+4, 6, ENC_NA);
        break;

    default:
        /* No Default Action */
        break;
    }

    return 2+2+optlen;
}

/* From FortiAP/WiFI 5.2.0


*/
#define VSP_FORTINET_AP_SCAN 16
#define VSP_FORTINET_PASSIVE 24
#define VSP_FORTINET_DAEMON_RST 32
#define VSP_FORTINET_MAC 33
#define VSP_FORTINET_WTP_ALLOW 34
#define VSP_FORTINET_WBH_STA 36
#define VSP_FORTINET_HTCAP 49
#define VSP_FORTINET_MGMT_VAP 50 /* MVAP */
#define VSP_FORTINET_MODE 51
#define VSP_FORTINET_COEXT 52
#define VSP_FORTINET_AMSDU 53
#define VSP_FORTINET_PS_OPT 54
#define VSP_FORTINET_PURE 55
#define VSP_FORTINET_EBP_TAG 56 /* ?? */
#define VSP_FORTINET_TELNET_ENABLE 81
#define VSP_FORTINET_ADMIN_PASSWD 82
#define VSP_FORTINET_REGCODE 83
#define VSP_FORTINET_COUNTRYCODE 84
#define VSP_FORTINET_STA_SCAN 99
#define VSP_FORTINET_FHO 103
#define VSP_FORTINET_APHO 104
#define VSP_FORTINET_STA_LOCATE 106
#define VSP_FORTINET_SPECTRUM_ANALYSIS 108
#define VSP_FORTINET_DARRP_CFG 112
#define VSP_FORTINET_AP_SUPPRESS_LIST 128
#define VSP_FORTINET_WDS 145
#define VSP_FORTINET_VAP_VLAN_TAG 147
#define VSP_FORTINET_VAP_BITMAP 148
#define VSP_FORTINET_MCAST_RATE 149
#define VSP_FORTINET_CFG 150
#define VSP_FORTINET_SPLIT_TUN_CFG 151
#define VSP_FORTINET_MGMT_VLAN_TAG 161
#define VSP_FORTINET_VAP_PSK_PASSWD 167
#define VSP_FORTINET_MESH_ETH_BRIDGE_ENABLE 176
#define VSP_FORTINET_MESH_ETH_BRIDGE_TYPE 177
#define VSP_FORTINET_WTP_CAP 192
#define VSP_FORTINET_TXPWR 193
#define VSP_FORTINET_WIDS_ENABLE 209

static const value_string fortinet_element_id_vals[] = {
    { VSP_FORTINET_AP_SCAN, "AP Scan" },
    { VSP_FORTINET_DAEMON_RST, "Daemon Reset" },
    { VSP_FORTINET_MAC, "MAC" },
    { VSP_FORTINET_PASSIVE, "Passive" },
    { VSP_FORTINET_WTP_ALLOW, "WTP Allow" },
    { VSP_FORTINET_WBH_STA, "Mesh WBH STA" },
    { VSP_FORTINET_HTCAP, "HT Capabilities" },
    { VSP_FORTINET_MGMT_VAP, "Management VAP" },
    { VSP_FORTINET_MODE, "Mode" },
    { VSP_FORTINET_COEXT, "Coext" },
    { VSP_FORTINET_AMSDU, "AMSDU" },
    { VSP_FORTINET_PS_OPT, "PS OPT" },
    { VSP_FORTINET_PURE, "Pure" },
    { VSP_FORTINET_EBP_TAG, "EBP Tag" },
    { VSP_FORTINET_TELNET_ENABLE, "Telnet Enable" },
    { VSP_FORTINET_ADMIN_PASSWD, "Admin Password" },
    { VSP_FORTINET_REGCODE, "Reg Code" },
    { VSP_FORTINET_COUNTRYCODE, "Country Code" },
    { VSP_FORTINET_STA_SCAN, "STA Scan" },
    { VSP_FORTINET_FHO, "FHO" },
    { VSP_FORTINET_APHO, "APHO" },
    { VSP_FORTINET_STA_LOCATE, "STA Locate" },
    { VSP_FORTINET_SPECTRUM_ANALYSIS, "Spectrum Analysis" },
    { VSP_FORTINET_DARRP_CFG, "DARRP Configuration" },
    { VSP_FORTINET_AP_SUPPRESS_LIST, "AP Suppress List" },
    { VSP_FORTINET_WDS, "WDS" },
    { VSP_FORTINET_VAP_VLAN_TAG, "VAP Vlan" },
    { VSP_FORTINET_VAP_BITMAP, "VAP Bitmap" },
    { VSP_FORTINET_MCAST_RATE, "Multicast Rate" },
    { VSP_FORTINET_CFG, "Configuration" },
    { VSP_FORTINET_SPLIT_TUN_CFG, "Split Tunnel Configuration" },
    { VSP_FORTINET_MGMT_VLAN_TAG, "Management Vlan" },
    { VSP_FORTINET_VAP_PSK_PASSWD, "VAP PSK Password" },
    { VSP_FORTINET_MESH_ETH_BRIDGE_ENABLE, "Mesh Eth Bridge Enable" },
    { VSP_FORTINET_MESH_ETH_BRIDGE_TYPE, "Mesh Eth Bridge Type" },
    { VSP_FORTINET_WTP_CAP, "WTP Capabilities" },
    { VSP_FORTINET_TXPWR, "Tx Power" },
    { VSP_FORTINET_WIDS_ENABLE, "WIDS Enable" },
    { 0,     NULL     }
};


static int
dissect_capwap_message_element_vendor_fortinet_type(tvbuff_t *tvb, proto_tree *sub_msg_element_type_tree, guint offset, packet_info *pinfo, guint optlen,  proto_item *msg_element_type_item)
{
    guint element_id, i;

    proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_element_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    element_id = tvb_get_ntohs(tvb, offset);
    proto_item_append_text(msg_element_type_item, ": Fortinet %s", val_to_str(element_id, fortinet_element_id_vals,"Unknown Vendor Specific Element Type (%02d)") );
    offset += 2;

    /* Remove length and element id to optlen */
    optlen -= 6;
    proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_value, tvb, offset, optlen, ENC_NA);

    switch(element_id){
        case VSP_FORTINET_AP_SCAN: /* 16 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_ap_scan_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_ap_scan_bgscan_intv, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_ap_scan_bgscan_idle, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_ap_scan_bgscan_rpt_intv, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_ap_scan_fgscan_rpt_intv, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        break;
        case VSP_FORTINET_PASSIVE: /* 24 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_passive_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_passive, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_DAEMON_RST: /* 32 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_daemon_rst, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_MAC:{ /* 33 */
            guint mac_length;
            proto_item *ti;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mac_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mac_wid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            ti =proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mac_len, tvb, offset, 1, ENC_BIG_ENDIAN);
            mac_length = tvb_get_guint8(tvb, offset);
            offset += 1;
            if(mac_length %6 != 0)
            {
                expert_add_info(pinfo, ti, &ei_capwap_fortinet_mac_len );
                break;
            }
            for(i = 0; i < mac_length/6; i++){
                proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mac, tvb, offset, 6, ENC_NA);
                offset += 6;
            }
            }
        break;
        case VSP_FORTINET_WTP_ALLOW: /* 34 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_wtp_allow_sn, tvb, offset, optlen-1, ENC_ASCII);
            offset += optlen - 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_wtp_allow_allow, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_WBH_STA:{ /* 36 */
            guint mac_length;
            proto_item *ti;

            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_wbh_sta_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            ti = proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_wbh_sta_len, tvb, offset, 1, ENC_BIG_ENDIAN);
            mac_length = tvb_get_guint8(tvb, offset);
            offset += 1;
            if(mac_length %6 != 0)
            {
                expert_add_info(pinfo, ti, &ei_capwap_fortinet_mac_len );
                break;
            }
            for(i = 0; i < mac_length/6; i++){
                proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_wbh_sta_mac, tvb, offset, 6, ENC_NA);
                offset += 6;
            }
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_wbh_sta_bssid, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_wbh_sta_mhc, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            }
        break;
        case VSP_FORTINET_HTCAP: /* 49 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_htcap_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_htcap_mcs, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_htcap_gi, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_htcap_bw, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_MGMT_VAP:{ /* 50 */
            guint16 sn_length;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mvap_sn_length, tvb, offset, 2, ENC_NA);
            sn_length = tvb_get_ntohs(tvb, offset);
            offset += 2;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mvap_sn, tvb, offset, sn_length, ENC_ASCII);
            offset += sn_length;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mvap_unknown, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mvap_unknown, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mvap_age, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mvap_period, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mvap_vfid, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        break;
        }
        case VSP_FORTINET_MODE: /* 51 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mode_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_COEXT: /* 52 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_coext_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_coext, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_AMSDU: /* 53 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_amsdu_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_amsdu, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_PS_OPT: /* 54 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_ps_opt_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_ps_opt, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_PURE: /* 55 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_pure_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_pure, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_EBP_TAG: /* 56 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_ebptag_ebp, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_ebptag_tag, tvb, offset, 6, ENC_NA);
            offset += 6;
        break;
        case VSP_FORTINET_TELNET_ENABLE: /* 81 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_telnet_enable, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        break;
        case VSP_FORTINET_ADMIN_PASSWD: /* 82 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_admin_passwd, tvb, offset, optlen, ENC_ASCII);
            offset += optlen;
        break;
        case VSP_FORTINET_REGCODE: /* 83 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_regcode, tvb, offset, 3, ENC_ASCII);
            offset += 3;
        break;
        case VSP_FORTINET_COUNTRYCODE: /* 84 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_countrycode_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_countrycode_code, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_countrycode_string, tvb, offset, 3, ENC_ASCII);
            offset += 3;
        break;
        case VSP_FORTINET_STA_SCAN: /* 99 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_sta_scan_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_sta_scan, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        break;
        case VSP_FORTINET_FHO: /* 103 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_fho_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_fho, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_APHO: /* 104 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_apho_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_apho, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_STA_LOCATE: /* 106 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_sta_locate_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_sta_locate_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_sta_locate_interval, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        break;
        case VSP_FORTINET_SPECTRUM_ANALYSIS: /* 108 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_sa_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            optlen -= 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_sa_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            optlen -= 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_sa_ssid, tvb, offset, optlen, ENC_ASCII);
            offset += optlen;
        break;
        case VSP_FORTINET_DARRP_CFG: /* 112 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_darrp_cfg_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_darrp_cfg_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_darrp_cfg_interval, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_AP_SUPPRESS_LIST: /* 128 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_ap_suppress_list_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_ap_suppress_list_op, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_ap_suppress_list_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_ap_suppress_list_len, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_WDS: /* 145 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_wds_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_wds_wid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_wds_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_VAP_VLAN_TAG: /* 147 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_vap_vlan_tag_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_vap_vlan_tag_wid, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_vap_vlan_tag, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        break;
        case VSP_FORTINET_VAP_BITMAP: /* 148 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_vap_bitmap_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_vap_bitmap, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        break;
        case VSP_FORTINET_MCAST_RATE: /* 149 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mcast_rate_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mcast_rate_wid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mcast_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        break;
        case VSP_FORTINET_CFG: /* 150 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_cfg_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_cfg_wid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_cfg_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_cfg_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        break;
        case VSP_FORTINET_SPLIT_TUN_CFG: /* 151 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_split_tun_cfg_enable_local_subnet, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_split_tun_cfg_cnt, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_MGMT_VLAN_TAG: /* 161 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mgmt_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        break;
        case VSP_FORTINET_VAP_PSK_PASSWD: /* 167 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_vap_psk_passwd_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            optlen -= 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_vap_psk_passwd_wid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            optlen -= 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_vap_psk_passwd_key, tvb, offset, optlen, ENC_ASCII);
            offset += optlen;
        break;
        case VSP_FORTINET_MESH_ETH_BRIDGE_ENABLE: /* 176 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mesh_eth_bridge_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_FORTINET_MESH_ETH_BRIDGE_TYPE: /* 177 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_mesh_eth_bridge_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        break;
        case VSP_FORTINET_WTP_CAP: /* 192 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_wtp_cap, tvb, offset, optlen, ENC_NA);
            offset += optlen;
        break;
        case VSP_FORTINET_TXPWR: /* 193 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_txpwr_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_txpwr, tvb, offset, 2, ENC_NA);
            offset += 2;
        break;
        case VSP_FORTINET_WIDS_ENABLE: /* 209 */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_wids_enable_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_wids_enable, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        break;
        case 146: /* VAP (ak Virtual AP) stuff, there is Radio ID and Wlan ID to start... */
        case 152:
        case 153:
        case 163:
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_unknown_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            optlen -= 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_unknown_wid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            optlen -= 1;
            expert_add_info_format(pinfo, msg_element_type_item, &ei_capwap_message_element_fortinet_type,
                                 "Dissector for CAPWAP Vendor Specific (Fortinet) Message Element"
                                 " (%d) type not implemented (VAP Stuff..)", element_id);
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_unknown, tvb, offset, optlen, ENC_NA);
            offset += optlen;
        break;

        case 65: /* Radio stuff, there is Radio ID  to start... */
        case 170:
        case 171:
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_unknown_rid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            optlen -= 1;
            expert_add_info_format(pinfo, msg_element_type_item, &ei_capwap_message_element_fortinet_type,
                                 "Dissector for CAPWAP Vendor Specific (Fortinet) Message Element"
                                 " (%d) type not implemented (VAP Stuff..)", element_id);
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_unknown, tvb, offset, optlen, ENC_NA);
            offset += optlen;
        break;
        default:
            expert_add_info_format(pinfo, msg_element_type_item, &ei_capwap_message_element_fortinet_type,
                                 "Dissector for CAPWAP Vendor Specific (Fortinet) Message Element"
                                 " (%d) type not implemented", element_id);
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_fortinet_unknown, tvb, offset, optlen, ENC_NA);
            offset += optlen;
        break;
    }

    return offset;
}

/* From Cisco WLC with help of actube  (http://www.github.com/7u83/actube */

/* Copy and rename (CW_ => VSP_ for actube/capwap/capwap_cisco.h (revision g387cc5da) */
#define VSP_CISCO_AP_NAME 5
#define VSP_CISCO_MWAR 6
#define VSP_CISCO_AP_TIMESYNC 151

#define VSP_CISCO_MWAR_ADDR                 2
#define VSP_CISCO_RAD                       3
#define VSP_CISCO_RAD_SLOT                  4
#define VSP_CISCO_RAD_NAME                  5
#define VSP_CISCO_MWAR                      6
#define VSP_CISCO_ADD_WLAN                  7
#define VSP_CISCO_WTP_RADIO_CFG             8

#define VSP_CISCO_MULTI_DOMAIN_CAPAB        10
#define VSP_CISCO_MAC_OPERATION             11

#define VSP_CISCO_TX_POWER                  12
#define VSP_CISCO_TX_POWER_LEVELS           13
#define VSP_CISCO_DIRECT_SEQUENCE_CONTROL   14
#define VSP_CISCO_SUPPORTED_RATES           16

#define VSP_CISCO_80211_DELETE_WLAN         28

#define VSP_CISCO_MWAR_NAME                 31

#define VSP_CISCO_LOCATION_DATA             35
#define VSP_CISCO_STATISTICS_TIMER          37

#define VSP_CISCO_ANTENNA_PAYLOAD           41

#define VSP_CISCO_CERTIFICATE               44
#define VSP_CISCO_WTP_BOARD_DATA            50
#define VSP_CISCO_AP_MODE_AND_TYPE          54
#define VSP_CISCO_AP_QOS                    57
#define VSP_CISCO_AC_IPV4_LIST              59

#define VSP_CISCO_AP_STATIC_IP_ADDR         83
#define VSP_CISCO_SIG_PAYLOAD               84
#define VSP_CISCO_SIG_TOGGLE                87

#define VSP_CISCO_AC_NAME_WITH_INDEX        91
#define VSP_CISCO_SPAM_DOMAIN_SECRET        96

#define VSP_CISCO_SPAM_VENDOR_SPECIFIC      104

#define VSP_CISCO_AP_UPTIME                 108

#define VSP_CISCO_AP_GROUP_NAME             123

#define VSP_CISCO_AP_LED_STATE_CONFIG       125
#define VSP_CISCO_AP_REGULATORY_DOMAIN      126
#define VSP_CISCO_AP_MODEL                  127
#define VSP_CISCO_AP_RESET_BUTTON_STATE     128

#define VSP_CISCO_LWAPP_CHANNEL_POWER       134
#define VSP_CISCO_AP_PRE_STD_SWITCH_CONFIG  137
#define VSP_CISCO_AP_POWER_INJECTOR_CONFIG  138

#define VSP_CISCO_AP_MINIOS_VERSION         149
#define VSP_CISCO_AP_TIMESYNC               151
#define VSP_CISCO_AP_DOMAIN                 169
#define VSP_CISCO_AP_DNS                    170

#define VSP_CISCO_AP_BACKUP_SOFTWARE_VERSION 183
#define VSP_CISCO_BOARD_DATA_OPTIONS        207
#define VSP_CISCO_MWAR_TYPE                 208
#define VSP_CISCO_80211_ASSOC_LIMIT         213
#define VSP_CISCO_TLV_PAYLOAD               215
#define VSP_CISCO_AP_LOG_FACILITY           224
#define VSP_CISCO_AP_RETRANSMIT_PARAM       240
#define VSP_CISCO_AP_VENUE_SETTINGS         249


static const value_string cisco_element_id_vals[] = {
    { VSP_CISCO_MWAR_ADDR, "MWAR Address" },
    { VSP_CISCO_RAD, "RAD" },
    { VSP_CISCO_RAD_SLOT, "RAD Slot" },
    { VSP_CISCO_RAD_NAME, "RAD (AP) Name" },
    { VSP_CISCO_MWAR, "MWAR" },
    { VSP_CISCO_ADD_WLAN, "Add WLAN" },
    { VSP_CISCO_WTP_RADIO_CFG, "WTP Radio Configuration" },

    { VSP_CISCO_MULTI_DOMAIN_CAPAB, "Multi Domain Capability" },
    { VSP_CISCO_MAC_OPERATION, "MAC Operation" },

    { VSP_CISCO_TX_POWER, "TX Power" },
    { VSP_CISCO_TX_POWER_LEVELS, "TX Power Levels" },
    { VSP_CISCO_DIRECT_SEQUENCE_CONTROL, "Direct Sequence Control" },
    { VSP_CISCO_SUPPORTED_RATES, "Supported Rates" },

    { VSP_CISCO_80211_DELETE_WLAN, "802.11 Delete WLAN" },

    { VSP_CISCO_MWAR_NAME, "MWAR NAME" },

    { VSP_CISCO_LOCATION_DATA, "Location Data" },
    { VSP_CISCO_STATISTICS_TIMER, "Statistics Timer" },

    { VSP_CISCO_ANTENNA_PAYLOAD, "Antenna Payload" },

    { VSP_CISCO_CERTIFICATE, "Certificate" },
    { VSP_CISCO_WTP_BOARD_DATA, "WTP Board Data" },
    { VSP_CISCO_AP_MODE_AND_TYPE, "AP Mode and Type" },

    { VSP_CISCO_AP_QOS, "AP QoS"},
    { VSP_CISCO_AC_IPV4_LIST, "AC IPv4 List" },

    { VSP_CISCO_AP_STATIC_IP_ADDR, "AP Static IP Addr" },
    { VSP_CISCO_SIG_PAYLOAD, "SIG Payload" },
    { VSP_CISCO_SIG_TOGGLE, "SIG Toggle" },

    { VSP_CISCO_AC_NAME_WITH_INDEX, "AC Name with Index" },
    { VSP_CISCO_SPAM_DOMAIN_SECRET, "SPAM Domain Secret" },

    { VSP_CISCO_SPAM_VENDOR_SPECIFIC, "SPAM Vendor Specific" },

    { VSP_CISCO_AP_UPTIME, "AP Uptime" },

    { VSP_CISCO_AP_GROUP_NAME, "AP Group Name" },
    { VSP_CISCO_AP_MODEL, "AP Model" },
    { VSP_CISCO_AP_RESET_BUTTON_STATE, "AP reset button state" },

    { VSP_CISCO_AP_LED_STATE_CONFIG, "AP Led State Config" },
    { VSP_CISCO_AP_REGULATORY_DOMAIN, "AP Regulatory domain" },

    { VSP_CISCO_LWAPP_CHANNEL_POWER, "LWAPP Channel Power" },
    { VSP_CISCO_AP_PRE_STD_SWITCH_CONFIG, "AP Pre STD Switch Config" },
    { VSP_CISCO_AP_POWER_INJECTOR_CONFIG, "AP Power Injector config" },

    { VSP_CISCO_AP_MINIOS_VERSION, "AP MinIOS Version" },
    { VSP_CISCO_AP_TIMESYNC, "AP Time Sync" },
    { VSP_CISCO_AP_DOMAIN, "AP Domain" },
    { VSP_CISCO_AP_DNS, "AP DNS" },

    { VSP_CISCO_AP_BACKUP_SOFTWARE_VERSION, "AP Backup software version" },
    { VSP_CISCO_BOARD_DATA_OPTIONS, "Board Data Options" },
    { VSP_CISCO_MWAR_TYPE, "MWAR Type" },
    { VSP_CISCO_80211_ASSOC_LIMIT, "802.11 Assoc Limit" },
    { VSP_CISCO_TLV_PAYLOAD, "TLV Payload" },
    { VSP_CISCO_AP_LOG_FACILITY, "AP Log Facility" },

    { VSP_CISCO_AP_RETRANSMIT_PARAM, "AP Retransmit Param" },
    { VSP_CISCO_AP_VENUE_SETTINGS, "AP Venue Settings" },
    { 0,     NULL     }
};

static const value_string cisco_ap_mode_and_type_mode_vals[] = {
    { 0, "Split MAC / Local Mode" },
    { 1, "Monitor" },
    { 2, "Local MAC / FlexConnect" },
    { 3, "Rogue Detector" },
    { 4, "Sniffer" },
    { 0,     NULL     }
};


static int
dissect_capwap_message_element_vendor_cisco_type(tvbuff_t *tvb, proto_tree *sub_msg_element_type_tree, guint offset, packet_info *pinfo, guint optlen,  proto_item *msg_element_type_item)
{
    guint element_id;

    proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_element_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    element_id = tvb_get_ntohs(tvb, offset);
    proto_item_append_text(msg_element_type_item, ": Cisco %s", val_to_str(element_id, cisco_element_id_vals,"Unknown Vendor Specific Element Type (%02d)") );
    offset += 2;

    /* Remove length and element id to optlen */
    optlen -= 6;
    proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_value, tvb, offset, optlen, ENC_NA);

    switch(element_id){
        case VSP_CISCO_MWAR_ADDR: /* MWAR Address (2) */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_mwar_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_mwar_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        break;
        case VSP_CISCO_RAD_NAME: /* RAD (AP) Name (5) */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_rad_name, tvb, offset, optlen, ENC_ASCII);
            offset += optlen;
        break;
        case VSP_CISCO_MWAR: /* MWAR (6) */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_mwar_type, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_mwar_hardware, tvb, offset, 4, ENC_ASCII);
            offset += 4;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_mwar_software, tvb, offset, 4, ENC_ASCII);
            offset += 4;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_mwar_active_ms, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_mwar_supported_ms, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_mwar_active_rad, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_mwar_supported_rad, tvb, offset, 2, ENC_NA);
            offset += 2;
        break;
        case VSP_CISCO_AP_MODE_AND_TYPE: /* AP_MODE_AND_TYPE (54) */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_ap_mode_and_type_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_ap_mode_and_type_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        break;
        case VSP_CISCO_AP_STATIC_IP_ADDR: /* AP_MODE_AND_TYPE (83) */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_ap_static_ip_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_ap_static_ip_netmask, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_ap_static_ip_gateway, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_ap_static_ip_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_ap_static_ip_reserved, tvb, offset, 4, ENC_NA);
            offset += 4;
        break;
        case VSP_CISCO_AP_UPTIME: /* AP Uptime (108) */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_ap_uptime_current, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_ap_uptime_last, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        break;
        case VSP_CISCO_AP_GROUP_NAME: /* AP Group Name (123) */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_ap_group_name, tvb, offset, optlen, ENC_ASCII);
            offset += optlen;
        break;
        case VSP_CISCO_AP_LED_STATE_CONFIG: /* AP Led State (125) */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_ap_led_state, tvb, offset, 2, ENC_NA);
            offset += 2;
        break;
        case VSP_CISCO_AP_TIMESYNC: /* AP Timesync (151) */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_ap_timesync, tvb, offset, 4, ENC_NA);
            offset += 4;

            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_ap_timesync_type, tvb, offset, 1, ENC_NA);
            offset += 1;
        break;
        case VSP_CISCO_BOARD_DATA_OPTIONS: /* Board Data Options (207) */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_board_data_options_ant_type, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_board_data_options_flex_connect, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_board_data_options_ap_type, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_board_data_options_join_priority, tvb, offset, 1, ENC_NA);
            offset += 1;
        break;

        case VSP_CISCO_MWAR_TYPE: /* MWAR_TYPE (208) */
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_mwar_type, tvb, offset, 1, ENC_NA);
            offset += 1;
        break;
        default:
            expert_add_info_format(pinfo, msg_element_type_item, &ei_capwap_message_element_cisco_type,
                                 "Dissector for CAPWAP Vendor Specific (Cisco) Message Element"
                                 " (%d) type not implemented", element_id);
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_cisco_unknown, tvb, offset, optlen, ENC_NA);
            offset += optlen;
        break;
    }

    return offset;
}
/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_message_element_type(tvbuff_t *tvb, proto_tree *msg_element_type_tree, guint offset, packet_info *pinfo)
{
    guint optlen, offset_end, number_encrypt, i, msg_element_type = 0;
    proto_item *msg_element_type_item, *msg_element_type_item_flag, *ti_len, *ti_type;
    proto_tree *sub_msg_element_type_tree, *sub_msg_element_type_flag_tree;

    msg_element_type = tvb_get_ntohs(tvb, offset);
    optlen = tvb_get_ntohs(tvb, offset+2);
    msg_element_type_item = proto_tree_add_item(msg_element_type_tree, hf_capwap_msg_element, tvb, offset, 2+2+optlen, ENC_NA );

    proto_item_append_text(msg_element_type_item, ": (t=%d,l=%d) %s", msg_element_type, optlen, val_to_str(msg_element_type,message_element_type_vals,"Unknown Message Element Type (%02d)") );

    sub_msg_element_type_tree = proto_item_add_subtree(msg_element_type_item, ett_capwap_message_element_type);

    ti_type = proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type, tvb, offset, 2, ENC_BIG_ENDIAN);

    ti_len = proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_value, tvb, offset+4, optlen, ENC_NA);

    switch (msg_element_type) {
    case TYPE_AC_DESCRIPTOR: /* AC Descriptor (1) */
        if (optlen < 12) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "AC Descriptor length %u wrong, must be >= 12", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_stations, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_limit, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_active_wtp, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_max_wtp, tvb, offset+10, 2, ENC_BIG_ENDIAN);

        /* AC Descriptor Security Flags... */
        proto_tree_add_bitmask_with_flags(sub_msg_element_type_tree, tvb, offset+12,
hf_capwap_msg_element_type_ac_descriptor_security, ett_capwap_ac_descriptor_security_flags, capwap_ac_descriptor_security_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);

        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_rmac_field, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_reserved, tvb, offset+14, 1, ENC_BIG_ENDIAN);

        /* AC Descriptor DTLS Flags... */
        proto_tree_add_bitmask_with_flags(sub_msg_element_type_tree, tvb, offset+15,
hf_capwap_msg_element_type_ac_descriptor_dtls_policy, ett_capwap_ac_descriptor_dtls_flags,  capwap_ac_descriptor_dtls_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);

        offset_end = offset + optlen -4;
        offset += 4 + 12;
        while (offset < offset_end) {
            offset += dissect_capwap_ac_information(tvb, sub_msg_element_type_tree, offset);
        }
        break;

    case TYPE_AC_IPV4_LIST: /* AC IPv4 List (2) */
        if (optlen < 4) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "AC IPv4 List length %u wrong, must be >= 4", optlen);
        break;
        }
        offset += 4;

        if (optlen%4 == 0)
        {
            for (i = 0; i < optlen/4; i++)
            {
                proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_ipv4_list, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }

        }
        break;
    case TYPE_AC_IPV6_LIST: /* AC IPv6 List (3) */
        if (optlen < 16) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "AC IPv6 List length %u wrong, must be >= 4", optlen);
        break;
        }
        offset += 4;

        if (optlen%16 == 0)
        {
            for (i = 0; i < optlen/16; i++)
            {
                proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_ipv6_list, tvb, offset, 16, ENC_NA);
                offset += 16;
            }

        }
        break;
    case TYPE_AC_NAME: /* AC Name (4) */
        if (optlen < 1) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "AC Name length %u wrong, must be >= 1", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_name, tvb, offset+4, optlen, ENC_ASCII);
        break;

    case TYPE_AC_NAME_W_PRIORITY: /* AC Name With Priority (5) */
        if (optlen < 2) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "AC Name with Priority length %u wrong, must be >= 2", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_name_with_priority, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_name, tvb, offset+5, optlen-1, ENC_ASCII);
        break;

    case TYPE_AC_TIMESTAMP: /* AC Timestamp (6) */
        if (optlen != 4) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "AC Timestamp length %u wrong, must be = 4", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_timestamp, tvb, offset + 4, 4, ENC_TIME_SECS_NTP|ENC_BIG_ENDIAN);
        break;

    case TYPE_ADD_STATION:{ /* Add Station (8) */
        guint8 maclength;
        if (optlen < 8) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "Add Station length %u wrong, must be >= 8", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_add_station_radio_id, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_add_station_length, tvb, offset + 5, 1, ENC_BIG_ENDIAN);
        maclength = tvb_get_guint8(tvb, offset+5);
        switch(maclength){
            case 6:
                proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_add_station_mac_eui48, tvb, offset+6, maclength, ENC_NA);
            break;
            case 8:
                proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_add_station_mac_eui64, tvb, offset+6, maclength, ENC_BIG_ENDIAN);
            break;
            default:
                proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_add_station_mac_data, tvb, offset+6, maclength, ENC_NA);
            break;
        }

        if(optlen -(2 + maclength)) {
                proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_add_station_vlan_name, tvb, offset+6+maclength, optlen -(2 + maclength), ENC_ASCII);
        }
        }
        break;

    case TYPE_CAPWAP_CONTROL_IPV4_ADDRESS: /* CAPWAP Control IPv4 Address (10) */
        if (optlen != 6) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "CAPWAP Control IPv4 Address length %u wrong, must be = 6", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_capwap_control_ipv4, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_capwap_control_wtp_count, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        break;

    case TYPE_CAPWAP_CONTROL_IPV6_ADDRESS: /* CAPWAP Control IPv6 Address (11) */
        if (optlen != 18) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "CAPWAP Control IPv6 Address length %u wrong, must be = 18", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_capwap_control_ipv6, tvb, offset+4, 16, ENC_NA);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_capwap_control_wtp_count, tvb, offset+20, 2, ENC_BIG_ENDIAN);
        break;

    case TYPE_CAPWAP_TIMERS: /* CAPWAP Timers (12) */
        if (optlen != 2) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "CAPWAP Timers length %u wrong, must be = 2", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_capwap_timers_discovery, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_capwap_timers_echo_request, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        break;

    case TYPE_DECRYPTION_ERROR_REPORT_PERIOD: /* Decryption Error Report Period (16) */
        if (optlen != 3) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "Decryption Error Report Period length %u wrong, must be = 3", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_decryption_error_report_period_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree,hf_capwap_msg_element_type_decryption_error_report_period_interval, tvb, offset+5, 2, ENC_BIG_ENDIAN);
        break;

    case TYPE_DELETE_STATION:{ /* Delete Station (18) */
        guint8 maclength;
        if (optlen < 8) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "Delete Station length %u wrong, must be >= 8", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_delete_station_radio_id, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_delete_station_length, tvb, offset + 5, 1, ENC_BIG_ENDIAN);
        maclength = tvb_get_guint8(tvb, offset+5);
        switch(maclength){
            case 6:
                proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_delete_station_mac_eui48, tvb, offset+6, maclength, ENC_NA);
            break;
            case 8:
                proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_delete_station_mac_eui64, tvb, offset+6, maclength, ENC_BIG_ENDIAN);
            break;
            default:
                proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_delete_station_mac_data, tvb, offset+6, maclength, ENC_NA);
            break;
        }

        }
        break;

    case TYPE_DISCOVERY_TYPE: /* Discovery Type (20) */
        if (optlen != 1) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "Discovery Type length %u wrong, must be = 1", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_discovery_type, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        break;
    case TYPE_IDLE_TIMEOUT: /* Idle Timeout (23) */
        if (optlen != 4) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "Idle Timeout length %u wrong, must be = 4", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_idle_timeout, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        break;

    case TYPE_LOCATION_DATA: /* Location Data (28) */
        if (optlen < 1) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "Location Data length %u wrong, must be >= 1", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_location_data, tvb, offset+4, optlen, ENC_ASCII);
        break;

    case TYPE_MAXIMUM_MESSAGE_LENGTH: /* Maximum Message Length (29) */
        if (optlen != 2) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "Maximum Message length %u wrong, must be = 2", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_maximum_message_length, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        break;

    case TYPE_CAPWAP_LOCAL_IPV4_ADDRESS: /* CAPWAP Local IPv4 Address (30) */
        if (optlen != 4) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "CAPWAP Local IPv4 Address length %u wrong, must be = 4", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_capwap_local_ipv4_address, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        break;


    case TYPE_RADIO_ADMINISTRATIVE_STATE: /* Radio Administrative State (31) */
        if (optlen != 2) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "Radio Administrative State length %u wrong, must be = 2", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_radio_admin_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_radio_admin_state, tvb, offset+5, 1, ENC_BIG_ENDIAN);

        break;

    case TYPE_RADIO_OPERATIONAL_STATE: /* Radio Operational State (32) */
        if (optlen != 3) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "Radio Operational State length %u wrong, must be = 3", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_radio_op_state_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_radio_op_state_radio_state, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_radio_op_state_radio_cause, tvb, offset+6, 1, ENC_BIG_ENDIAN);
        break;

    case TYPE_RESULT_CODE: /* Result Code (33) */
        if (optlen != 4) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "Result Code length %u wrong, must be = 4", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_result_code, tvb, offset+4, 4, ENC_BIG_ENDIAN);

        break;

    case TYPE_SESSION_ID: /* Session ID (35) */
        if (optlen != 16) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "Session ID length %u wrong, must be = 16", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_session_id, tvb, offset+4, 16, ENC_NA);
        break;

    case TYPE_STATISTICS_TIMER: /* Statistics Timer (36) */
        if (optlen != 2) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "Statistics Timer length %u wrong, must be = 2", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_statistics_timer, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        break;

    case TYPE_VENDOR_SPECIFIC_PAYLOAD:{ /* Vendor Specific Payload (37) */
        guint32 vendor_id;
        if (optlen < 7) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "Vendor Specific Payload length %u wrong, must be >= 7", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_vsp_vendor_identifier, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        vendor_id = tvb_get_ntohl(tvb, offset+4);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_vsp_vendor_element_id, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_vsp_vendor_data, tvb, offset+10, optlen-6, ENC_NA);
        switch(vendor_id){
            case VENDOR_FORTINET:
                dissect_capwap_message_element_vendor_fortinet_type(tvb, sub_msg_element_type_tree, offset+8, pinfo, optlen, msg_element_type_item);
            break;
            case VENDOR_CISCO_WIFI:
                dissect_capwap_message_element_vendor_cisco_type(tvb, sub_msg_element_type_tree, offset+8, pinfo, optlen, msg_element_type_item);
            break;
            default:
                /* No default... */
            break;
        }
        }
        break;

    case TYPE_WTP_BOARD_DATA: /* WTP Board Data (38) */
        if (optlen < 14) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "WTP Board Data length %u wrong, must be >= 14", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_board_data_vendor, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        offset += 8;
        offset_end = offset + optlen -4;
        while (offset < offset_end) {
            offset += dissect_capwap_board_data(tvb, sub_msg_element_type_tree, offset);
        }
        break;

    case TYPE_WTP_DESCRIPTOR: /* WTP Descriptor (39) */
        if (optlen < 33) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "WTP Descriptor length %u wrong, must be >= 33", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_descriptor_max_radios, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_descriptor_radio_in_use, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        if (global_capwap_draft_8_cisco == 0)
        {
            number_encrypt = tvb_get_guint8(tvb,offset+6);
            msg_element_type_item_flag = proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_descriptor_number_encrypt, tvb, offset+6, 1, ENC_BIG_ENDIAN);
            sub_msg_element_type_flag_tree = proto_item_add_subtree(msg_element_type_item_flag, ett_capwap_encryption_capabilities);
            for (i=0; i < number_encrypt; i++) {
                dissect_capwap_encryption_capabilities(tvb, sub_msg_element_type_flag_tree, offset+4+3+i*3);
            }
            offset_end = offset + optlen -4;
            offset += 4 + 3 + number_encrypt * 3;
        }
        else
        {
            /*in Draft 8, there is only one "encryption_capabilities*/
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_descriptor_encrypt_capabilities, tvb, offset+6, 2, ENC_BIG_ENDIAN);
            offset_end = offset + optlen -4;
            offset += 6 + 2;
        }
        while (offset < offset_end) {
            offset += dissect_capwap_wtp_descriptor(tvb, sub_msg_element_type_tree, offset);
        }
        break;

    case TYPE_WTP_FALLBACK: /* WTP Fallback (40) */
        if (optlen != 1) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "WTP Fallback length %u wrong, must be = 1", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_fallback, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        break;

    case TYPE_WTP_FRAME_TUNNEL_MODE: /* WTP Frame Tunnel Mode (41) */
        if (optlen != 1) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "WTP Frame Tunnel Mode length %u wrong, must be = 1", optlen);
        break;
        }

        proto_tree_add_bitmask_with_flags(sub_msg_element_type_tree, tvb, offset+4,
hf_capwap_msg_element_type_wtp_frame_tunnel_mode, ett_capwap_wtp_frame_tunnel_mode, capwap_wtp_frame_tunnel_mode_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        break;
    case TYPE_WTP_MAC_TYPE: /* WTP MAC Type (44) */
        if (optlen != 1) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "WTP MAC Type length %u wrong, must be = 1", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_mac_type, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        break;

    case TYPE_WTP_NAME: /* WTP Name (45) */
        if (optlen < 1) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "WTP Name length %u wrong, must be >= 1", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_name, tvb, offset+4, optlen, ENC_ASCII);
        break;

    case TYPE_WTP_REBOOT_STATISTICS: /* WTP Reboot Statistics (48) */
        if (optlen != 15) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "WTP Reboot Statistics length %u wrong, must be = 15", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_reboot_statistics_reboot_count, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_reboot_statistics_ac_initiated_count, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_reboot_statistics_link_failure_count, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_reboot_statistics_sw_failure_count, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_reboot_statistics_hw_failure_count, tvb, offset+12, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_reboot_statistics_other_failure_count, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_reboot_statistics_unknown_failure_count, tvb, offset+16, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_reboot_statistics_last_failure_type, tvb, offset+18, 1, ENC_BIG_ENDIAN);
        break;

    case TYPE_CAPWAP_LOCAL_IPV6_ADDRESS: /* CAPWAP Local IPv6 Address (50) */
        if (optlen != 16) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "CAPWAP Local IPv6 Address length %u wrong, must be = 16", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_capwap_local_ipv6_address, tvb, offset+4, 16, ENC_NA);
        break;

    case TYPE_CAPWAP_TRANSPORT_PROTOCOL: /* CAPWAP Transport Protocol (51) */
        if (optlen != 1) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "CAPWAP Transport Protocol length %u wrong, must be = 1", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_capwap_transport_protocol, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        break;

    case TYPE_MTU_DISCOVERY_PADDING: /* MTU Discovery Padding (52) */
        if (optlen < 1) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "MTU Discovery Padding length %u wrong, must be >= 1", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_mtu_discovery_padding, tvb, offset+4, optlen, ENC_NA);
        break;


    case TYPE_ECN_SUPPORT: /* ECN Support (53) */
        if (optlen != 1) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "ECN Support length %u wrong, must be = 1", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ecn_support, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        break;

    case IEEE80211_ADD_WLAN:{ /* ieee80211 Add WLAN (1024) */
        guint16 key_length;
        if (optlen < 20) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Add Wlan length %u wrong, must be >= 20", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_add_wlan_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_add_wlan_wlan_id, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask_with_flags(sub_msg_element_type_tree, tvb, offset+6,
hf_capwap_msg_element_type_ieee80211_add_wlan_capability, ett_capwap_ieee80211_add_wlan_capability, ieee80211_add_wlan_capability_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_add_wlan_key_index, tvb, offset+8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_add_wlan_key_status, tvb, offset+9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_add_wlan_key_length, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        key_length = tvb_get_ntohs(tvb, offset+10);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_add_wlan_key, tvb, offset+12, key_length, ENC_NA);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_add_wlan_group_tsc, tvb, offset+key_length+12, 6, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_add_wlan_qos, tvb, offset+key_length+18, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_add_wlan_auth_type, tvb, offset+key_length+19, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_add_wlan_mac_mode, tvb, offset+key_length+20, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_add_wlan_tunnel_mode, tvb, offset+key_length+21, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_add_wlan_suppress_ssid, tvb, offset+key_length+22, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_add_wlan_ssid, tvb, offset+key_length+23, optlen-(key_length+23-4), ENC_ASCII);
        }
        break;

    case IEEE80211_ANTENNA:{ /* ieee80211 Antenna (1025) */
        guint8 antenna_count, antenna = 0;
        if (optlen < 5) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Antenna length %u wrong, must be >= 5", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_antenna_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_antenna_diversity, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_antenna_combiner, tvb, offset+6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_antenna_count, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        antenna_count = tvb_get_guint8(tvb, offset+7);
        while(antenna < antenna_count){
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_antenna_selection, tvb, offset+8+antenna, 1, ENC_BIG_ENDIAN);
            antenna += 1;
        }
    }
    break;

    case IEEE80211_ASSIGNED_WTP_BSSID: /* ieee80211 Assigned WTP BSSID (1026) */
        if (optlen != 8) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Assigned WTP BSSID length %u wrong, must be = 8", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_assigned_wtp_bssid_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_assigned_wtp_bssid_wlan_id, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_assigned_wtp_bssid_bssid, tvb, offset+6, 6, ENC_NA);
        break;

    case IEEE80211_DELETE_WLAN: /* ieee80211 Delete WLAN (1027) */
        if (optlen != 2) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Delete Wlan length %u wrong, must be = 2", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_delete_wlan_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_delete_wlan_wlan_id, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        break;

    case IEEE80211_DIRECT_SEQUENCE_CONTROL: /* ieee80211 Direct Sequence Control (1028) */
        if (optlen != 8) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Direct Sequence Control length %u wrong, must be = 8", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_direct_sequence_control_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_direct_sequence_control_reserved, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_direct_sequence_control_current_channel, tvb, offset+6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_direct_sequence_control_current_cca, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_direct_sequence_control_energy_detect_threshold, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        break;

    case IEEE80211_INFORMATION_ELEMENT: /* ieee80211 Information Element (1029) */
        if (optlen < 4) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Information Element length %u wrong, must be >= 4", optlen);
        break;
        }
        offset += 4;
        offset_end = offset + optlen;

        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_ie_radio_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_ie_wlan_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_bitmask_with_flags(sub_msg_element_type_tree, tvb, offset,
hf_capwap_msg_element_type_ieee80211_ie_flags, ett_capwap_ieee80211_ie_flags, ieee80211_ie_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        offset += 1;

        while (offset < offset_end) {
            offset += add_tagged_field(pinfo, sub_msg_element_type_tree, tvb, offset, 0, NULL, 0, NULL);
        }

        break;

    case IEEE80211_MAC_OPERATION: /* ieee80211 MAC Operation (1030) */
        if (optlen != 16) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 MAC Operation length %u wrong, must be = 16", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_mac_operation_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_mac_operation_reserved, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_mac_operation_rts_threshold, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_mac_operation_short_retry, tvb, offset+8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_mac_operation_long_retry, tvb, offset+9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_mac_operation_fragmentation_threshold, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_mac_operation_tx_msdu_lifetime, tvb, offset+12, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_mac_operation_rx_msdu_lifetime, tvb, offset+16, 4, ENC_BIG_ENDIAN);
        break;

    case IEEE80211_MIC_COUNTERMEASURES: /* ieee80211 MIC Countermeasures (1031) */
        if (optlen != 8) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 MIC Countermeasures length %u wrong, must be = 8", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_mic_countermeasures_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_mic_countermeasures_wlan_id, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_mic_countermeasures_mac_address, tvb, offset+6, 6, ENC_NA);
        break;

    case IEEE80211_MULTI_DOMAIN_CAPABILITY: /* ieee80211 Multi-Domain Capability (1032) */
        if (optlen != 8) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Multi-Domain Capability length %u wrong, must be = 8", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_multi_domain_capability_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_multi_domain_capability_reserved, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_multi_domain_capability_first_channel, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_multi_domain_capability_number_of_channels, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_multi_domain_capability_max_tx_power_level, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        break;

    case IEEE80211_OFDM_CONTROL: /* ieee80211 OFDM Control (1033) */
        if (optlen != 8) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 OFDM Control length %u wrong, must be = 8", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_ofdm_control_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_ofdm_control_reserved, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_ofdm_control_current_channel, tvb, offset+6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask_with_flags(sub_msg_element_type_tree, tvb, offset+7, hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support, ett_capwap_ieee80211_ofdm_control_band_support, ieee80211_ofdm_control_band_support_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);

        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_ofdm_control_ti_threshold, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        break;

    case IEEE80211_RATE_SET: /* ieee80211 Rate Set (1034) */
        if (optlen < 3) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Rate Set length %u wrong, must be >= 3", optlen);
        break;
        }
        offset += 4;
        offset_end = offset + optlen;

        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_rate_set_radio_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        while (offset < offset_end) {
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_rate_set_rate_set, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }


        break;
    case IEEE80211_STATION: /* ieee80211 Station (1036) */
        if (optlen < 14) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Station length %u wrong, must be >= 14", optlen);
        break;
        }
        offset_end = offset + 4 + optlen;
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_station_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_station_association_id, tvb, offset+5, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_station_flags, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_station_mac_address, tvb, offset+8, 6, ENC_NA);
        proto_tree_add_bitmask_with_flags(sub_msg_element_type_tree, tvb, offset+14,
hf_capwap_msg_element_type_ieee80211_station_capabilities, ett_capwap_ieee80211_station_capabilities, ieee80211_station_capabilities_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_station_wlan_id, tvb, offset+16, 1, ENC_BIG_ENDIAN);

        offset += 17;
        while (offset < offset_end) {
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_station_supported_rates, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }

        break;

    case IEEE80211_STATION_SESSION_KEY: /* ieee80211 Station Session Key (1038) */
        if (optlen < 25) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Station Session Key length %u wrong, must be >= 25", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_station_session_key_mac, tvb, offset+4, 6, ENC_NA);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_station_session_key_flags, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_station_session_key_flags_a, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_station_session_key_flags_c, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_station_session_key_pairwire_tsc, tvb, offset+12, 6, ENC_NA);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_station_session_key_pairwire_rsc, tvb, offset+18, 6, ENC_NA);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_station_session_key_key, tvb, offset+24, optlen-24, ENC_NA);
        break;

    case IEEE80211_SUPPORTED_RATES: /* ieee80211 Supported Rates (1040) */
        if (optlen < 3) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Supported Rates length %u wrong, must be >= 3", optlen);
        break;
        }
        offset += 4;
        offset_end = offset + optlen;

        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_supported_rates_radio_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        while (offset < offset_end) {
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_supported_rates_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }
        break;

    case IEEE80211_TX_POWER: /* ieee80211 Tx Power (1041) */
        if (optlen != 4) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Tx Power length %u wrong, must be = 4", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_tx_power_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_tx_power_reserved, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_tx_power_current_tx_power, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        break;

    case IEEE80211_TX_POWER_LEVEL:{ /* ieee80211 Tx Power Level (1042) */
        guint8 num_levels, level = 0;
        if (optlen < 3) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Antenna length %u wrong, must be >= 3", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_tx_power_level_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_tx_power_level_num_levels, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        num_levels = tvb_get_guint8(tvb, offset+5);
        while(level < num_levels){
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_tx_power_level_power_level, tvb, offset+6+(level*2), 2, ENC_BIG_ENDIAN);
            level += 1;
        }
        }
        break;

    case IEEE80211_UPDATE_WLAN:{ /* ieee80211 Update WLAN (1044) */
        guint16 key_length;
        if (optlen < 8) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Update Wlan length %u wrong, must be >= 8", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_update_wlan_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_update_wlan_wlan_id, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask_with_flags(sub_msg_element_type_tree, tvb, offset+6,
hf_capwap_msg_element_type_ieee80211_update_wlan_capability, ett_capwap_ieee80211_update_wlan_capability, ieee80211_update_wlan_capability_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_update_wlan_key_index, tvb, offset+8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_update_wlan_key_status, tvb, offset+9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_update_wlan_key_length, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        key_length = tvb_get_ntohs(tvb, offset+10);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_update_wlan_key, tvb, offset+12, key_length, ENC_NA);
        }
        break;

    case IEEE80211_WTP_RADIO_CONFIGURATION: /* ieee80211 WTP Radio Configuration (1046) */
        if (optlen != 16) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 WTP Radio Configuration length %u wrong, must be = 16", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_short_preamble, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_num_of_bssids, tvb, offset+6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_dtim_period, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_bssid, tvb, offset+8, 6, ENC_NA);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_beacon_period, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_country_string, tvb, offset+16, 4, ENC_ASCII);
        break;

    case IEEE80211_WTP_RADIO_INFORMATION: /* ieee80211 WTP Radio Information (1048) */
        if (optlen != 5) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 WTP Radio Information length %u wrong, must be = 5", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_id, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_reserved, tvb, offset+5, 3, ENC_NA);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_n, tvb, offset+8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_g, tvb, offset+8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_a, tvb, offset+8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_b, tvb, offset+8, 1, ENC_BIG_ENDIAN);
        break;



    case IEEE80211_SUPPORTED_MAC_PROFILES:{ /* ieee80211 Supported MAC Profiles (1060) */
        guint8 num_profiles;
        if (optlen < 2) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 Supported MAC Profiles length %u wrong, must be >= 2", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_supported_mac_profiles_numbers, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        num_profiles = tvb_get_guint8(tvb ,offset);
        while(num_profiles){
            proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_supported_mac_profiles_profile, tvb, offset+5, 1, ENC_BIG_ENDIAN);
            offset += 1;
            num_profiles--;
        }
        }
        break;

    case IEEE80211_MAC_PROFILE: /* ieee80211 MAC Profile (1061) */
        if (optlen != 1) {
            expert_add_info_format(pinfo, ti_len, &ei_capwap_msg_element_length,
                           "IEEE80211 MAC Profile length %u wrong, must be = 1", optlen);
        break;
        }
        proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ieee80211_mac_profile, tvb, offset+4, 1, ENC_BIG_ENDIAN);

        break;

    default:
      expert_add_info_format(pinfo, ti_type, &ei_capwap_message_element_type,
                             "Dissector for CAPWAP Message Element"
                             " (%s) type not implemented, Contact"
                             " Wireshark developers if you want this supported",
                             val_to_str(msg_element_type, message_element_type_vals, "(%d)"));
        break;
    }

    return 2+2+optlen;
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_message_element(tvbuff_t *tvb, proto_tree *capwap_control_tree, guint offset, packet_info *pinfo)
{
    guint plen = 0, offset_end;
    proto_item *ti;
    proto_tree *capwap_message_element_tree;

    ti = proto_tree_add_item(capwap_control_tree, hf_capwap_message_element, tvb, offset, tvb_reported_length(tvb) - offset, ENC_NA);
    capwap_message_element_tree = proto_item_add_subtree(ti, ett_capwap_message_element);

    offset_end = tvb_reported_length(tvb);

    while (offset+plen < offset_end) {
        plen += dissect_capwap_message_element_type(tvb, capwap_message_element_tree, offset+plen, pinfo);
    }

    return plen;
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_data_keep_alive(tvbuff_t *tvb, packet_info *pinfo, proto_tree *capwap_data_tree, guint offset)
{
    guint16 len;
    guint plen = 0, offset_end;
    proto_item *ti;
    proto_tree *capwap_data_keep_alive_tree;

    ti = proto_tree_add_item(capwap_data_tree, hf_capwap_data_keep_alive, tvb, offset, tvb_reported_length(tvb), ENC_NA);
    capwap_data_keep_alive_tree = proto_item_add_subtree(ti, ett_capwap_data_keep_alive);

    ti = proto_tree_add_item(capwap_data_keep_alive_tree, hf_capwap_data_keep_alive_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    len = tvb_get_ntohs(tvb, offset);
    if (len != tvb_reported_length(tvb))
        expert_add_info(pinfo, ti, &ei_capwap_data_keep_alive_length);

    plen += 2;

    offset_end = tvb_reported_length(tvb);

    while (offset+plen < offset_end) {
        plen += dissect_capwap_message_element_type(tvb, capwap_data_keep_alive_tree, offset+plen, pinfo);
    }

    return plen;
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_control_header(tvbuff_t *tvb, proto_tree *capwap_control_tree, guint offset, packet_info *pinfo)
{
    guint plen = 0;
    proto_item *ti, *ti_flag;
    proto_tree *capwap_control_header_tree;
    proto_tree *capwap_control_msg_type_tree;

    ti = proto_tree_add_item(capwap_control_tree, hf_capwap_control_header, tvb, offset, 8, ENC_NA);
    capwap_control_header_tree = proto_item_add_subtree(ti, ett_capwap_control_header);

    /* Message Type 32 bits */
    ti_flag = proto_tree_add_item(capwap_control_header_tree, hf_capwap_control_header_msg_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    capwap_control_msg_type_tree = proto_item_add_subtree(ti_flag, ett_capwap_control_header_msg);

    proto_tree_add_item(capwap_control_msg_type_tree, hf_capwap_control_header_msg_type_enterprise_nbr, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(capwap_control_msg_type_tree, hf_capwap_control_header_msg_type_enterprise_specific, tvb, offset, 4, ENC_BIG_ENDIAN);

    col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",val_to_str(tvb_get_ntohl(tvb, offset),message_type,"Unknown Message Type (0x%x)"));

    plen += 4;
    /* Sequence 8 bits */
    proto_tree_add_item(capwap_control_header_tree, hf_capwap_control_header_seq_number, tvb, offset+plen, 1, ENC_BIG_ENDIAN);
    plen += 1;

    /* Message Element Length 16 bits */
    proto_tree_add_item(capwap_control_header_tree, hf_capwap_control_header_msg_element_length, tvb, offset+plen, 2, ENC_BIG_ENDIAN);
    plen += 2;
    /* Flags 8 bits */
    proto_tree_add_item(capwap_control_header_tree, hf_capwap_control_header_flags, tvb, offset+plen, 1, ENC_BIG_ENDIAN);
    plen += 1;
    return plen;
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_header(tvbuff_t *tvb, proto_tree *capwap_control_tree, guint offset, packet_info *pinfo, guint8 *payload_type, guint8 *payload_wbid, gboolean *fragment_is, gboolean *fragment_more, guint32 *fragment_id, guint32 *fragment_offset)
{
    guint plen = 0, hlen = 0;
    proto_item *ti, *ti_flag, *ti_len;
    proto_tree *capwap_header_tree;
    proto_tree *capwap_header_flags_tree;
    guint flags = 0;
    guint8 maclength, wirelesslength;
    guint align = 0;

    /* RFC 5415  HLEN:  A 5-bit field containing the length of the CAPWAP transport header in 4-byte words */
    /* As we display the preamble separately reduce the length by 1 */
    hlen = tvb_get_bits8(tvb, (offset+plen)*8, 5)*4-1;
    ti = proto_tree_add_item(capwap_control_tree, hf_capwap_header, tvb, offset+plen, hlen, ENC_NA);
    capwap_header_tree = proto_item_add_subtree(ti, ett_capwap_header);

    /* Header Length : 5 Bits */
    ti_len = proto_tree_add_item(capwap_header_tree, hf_capwap_header_hlen, tvb, offset+plen, 3, ENC_BIG_ENDIAN);
    proto_item_append_text(ti_len, " (%d)",hlen+1);
    /* Radio ID : 5 Bits */
    proto_tree_add_item(capwap_header_tree, hf_capwap_header_rid, tvb, offset+plen, 3, ENC_BIG_ENDIAN);

    /* Wireless Binding ID : 5 Bits */
    proto_tree_add_item(capwap_header_tree, hf_capwap_header_wbid, tvb, offset+plen, 3, ENC_BIG_ENDIAN);

    /* WBid of Payload (for CAPWAP Data Packet) */
    *payload_wbid = tvb_get_bits8(tvb, (offset+plen)*8+10, 5);

    /* Flags : 9 Bits */
    flags = tvb_get_bits16(tvb, (offset+plen)*8+15, 9, ENC_BIG_ENDIAN);
    ti_flag = proto_tree_add_item(capwap_header_tree, hf_capwap_header_flags, tvb, offset+plen, 3, ENC_BIG_ENDIAN);
    capwap_header_flags_tree = proto_item_add_subtree(ti_flag, ett_capwap_header_flags);

    proto_tree_add_item(capwap_header_flags_tree, hf_capwap_header_flags_t, tvb, offset+plen, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(capwap_header_flags_tree, hf_capwap_header_flags_f, tvb, offset+plen, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(capwap_header_flags_tree, hf_capwap_header_flags_l, tvb, offset+plen, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(capwap_header_flags_tree, hf_capwap_header_flags_w, tvb, offset+plen, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(capwap_header_flags_tree, hf_capwap_header_flags_m, tvb, offset+plen, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(capwap_header_flags_tree, hf_capwap_header_flags_k, tvb, offset+plen, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(capwap_header_flags_tree, hf_capwap_header_flags_r, tvb, offset+plen, 3, ENC_BIG_ENDIAN);

    /* Fragment ??*/
    *fragment_is = ((flags & 0x80) == 0x80) ? TRUE : FALSE;
    *fragment_more = ((flags &0x40) == 0x40) ? FALSE : TRUE;

    /* Type of Payload (for CAPWAP Data Packet), use 0xff for Keep-Alive */
    if (flags &0x08 /* data channel Keep-Alive packet */) {
        col_append_str(pinfo->cinfo, COL_INFO, " Keep-Alive");
        *payload_type = 0xff;
    } else
        *payload_type = tvb_get_bits8(tvb, (offset+plen)*8+15,1);

    plen += 3;

    /* Fragment ID : 16 Bits */
    proto_tree_add_item(capwap_header_tree, hf_capwap_header_fragment_id, tvb, offset+plen, 2, ENC_BIG_ENDIAN);
    *fragment_id = (guint32)tvb_get_ntohs(tvb, offset+plen);
    plen += 2;

    /* Fragment offset : 13 Bits */
    proto_tree_add_item(capwap_header_tree, hf_capwap_header_fragment_offset, tvb, offset+plen, 2, ENC_BIG_ENDIAN);
    *fragment_offset = 8 * (guint32)tvb_get_bits16(tvb, (offset+plen)*8, 13, ENC_BIG_ENDIAN);

    /* Reserved 3 Bits */
    proto_tree_add_item(capwap_header_tree, hf_capwap_header_reserved, tvb, offset+plen+1, 1, ENC_BIG_ENDIAN);
    plen += 2;
    /* Optionnal Headers */
    if (flags & 0x10 /* Radio MAC address */) {
        maclength=tvb_get_guint8(tvb, offset+plen);
        proto_tree_add_item(capwap_header_tree, hf_capwap_header_mac_length, tvb, offset+plen, 1, ENC_BIG_ENDIAN);
        plen += 1;
        if (maclength == 6) {
            proto_tree_add_item(capwap_header_tree, hf_capwap_header_mac_eui48, tvb, offset+plen, maclength, ENC_NA);

        } else if (maclength == 8) {
            proto_tree_add_item(capwap_header_tree, hf_capwap_header_mac_eui64, tvb, offset+plen, maclength, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(capwap_header_tree, hf_capwap_header_mac_data, tvb, offset+plen, maclength, ENC_NA);
        }
        plen += maclength;
        /* 4 Bytes Alignment ? */
        align = 4-((offset+plen)%4);
        if (align != 4)
        {
            proto_tree_add_item(capwap_header_tree, hf_capwap_header_padding, tvb, offset+plen, align, ENC_NA);
            plen += align;
        }
    }
    if (flags & 0x20 /* Wireless specific information */) {
        wirelesslength=tvb_get_guint8(tvb, offset+plen);

        /* in Draft 8, the WBid is add in Wireless Specific Information*/
        if (global_capwap_draft_8_cisco == 1)
        {
            plen += 1;
            wirelesslength = 4;
        }
        proto_tree_add_item(capwap_header_tree, hf_capwap_header_wireless_length, tvb, offset+plen, 1, ENC_BIG_ENDIAN);
        plen += 1;
        proto_tree_add_item(capwap_header_tree, hf_capwap_header_wireless_data, tvb, offset+plen, wirelesslength, ENC_NA);

        /* Optional Wireless Specific Information for ieee80211 (wbid = 1) Section 4 of RFC5416 */
        if (*payload_wbid == 1)
        {
            dissect_capwap_data_message_bindings_ieee80211(tvb, capwap_header_tree, offset+plen, pinfo);
        }

        plen += wirelesslength;
        /* 4 Bytes Alignment ? */
        align = 4-((offset+plen)%4);
        if (align != 4)
        {
            proto_tree_add_item(capwap_header_tree, hf_capwap_header_padding, tvb, offset+plen, align, ENC_NA);
            plen += align;
        }
    }
    if ((plen != hlen) && global_capwap_draft_8_cisco == 0)
    {
        expert_add_info_format(pinfo, ti_len, &ei_capwap_header_length_bad, "Wrong calculate length (%d) =! header length (%d) ! (May be try to use Cisco Wireless Controller Support Preference ?)", plen, hlen);
    }
    return hlen;
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_preamble(tvbuff_t *tvb, proto_tree *capwap_control_tree, guint offset, guint8 *type_header)
{
    guint plen = 0;
    proto_item *ti;
    proto_tree *capwap_preamble_tree;

    ti = proto_tree_add_item(capwap_control_tree, hf_capwap_preamble, tvb, offset+plen, -1, ENC_NA);
    capwap_preamble_tree = proto_item_add_subtree(ti, ett_capwap_preamble);

    proto_tree_add_item(capwap_preamble_tree, hf_capwap_preamble_version, tvb, offset+plen, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(capwap_preamble_tree, hf_capwap_preamble_type, tvb, offset+plen, 1, ENC_BIG_ENDIAN);
    *type_header = tvb_get_guint8(tvb, offset+plen) & 0x0F;
    plen++;
    /* DTLS Header ? */
    if (*type_header == 1) {
        proto_tree_add_item(capwap_preamble_tree, hf_capwap_preamble_reserved, tvb, offset+plen, 3, ENC_BIG_ENDIAN);
        plen +=3;
    }
    proto_item_set_len(ti, plen);
    return plen;
}

/* Code to actually dissect the packets */
static int
dissect_capwap_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *capwap_control_tree;
    guint offset = 0;
    tvbuff_t *next_tvb = NULL;
    guint8 type_header;
    guint8 payload_type;
    guint8 payload_wbid;
    gboolean fragment_is;
    gboolean fragment_more;
    guint32 fragment_id;
    guint32 fragment_offset;
    fragment_head *frag_msg = NULL;
    gboolean save_fragmented;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAPWAP-Control");
    col_set_str(pinfo->cinfo, COL_INFO, "CAPWAP-Control");

    ti = proto_tree_add_item(tree, proto_capwap_control, tvb, 0, -1, ENC_NA);
    capwap_control_tree = proto_item_add_subtree(ti, ett_capwap_control);

    /* CAPWAP Preamble */
    offset += dissect_capwap_preamble(tvb, capwap_control_tree, offset, &type_header);

    if (type_header == 1) {
        next_tvb = tvb_new_subset_remaining (tvb, offset);
        call_dissector(dtls_handle, next_tvb, pinfo, tree);
        return offset;
    }

    /* CAPWAP Header */
    offset += dissect_capwap_header(tvb, capwap_control_tree, offset, pinfo, &payload_type, &payload_wbid, &fragment_is, &fragment_more, &fragment_id, &fragment_offset );

    /* CAPWAP Reassemble */
    save_fragmented = pinfo->fragmented;

    if (global_capwap_reassemble && fragment_is)
    {
        const int len_rem = tvb_reported_length_remaining(tvb, offset);
        if (len_rem <= 0)
            return offset;

        pinfo->fragmented = TRUE;

        frag_msg = fragment_add_check(&capwap_reassembly_table,
                                      tvb, offset, pinfo, fragment_id, NULL,
                                      fragment_offset,
                                      len_rem,
                                      fragment_more);

        next_tvb = process_reassembled_data(tvb, offset, pinfo,
                                            "Reassembled CAPWAP", frag_msg,
                                            &capwap_frag_items, NULL, tree);

        if (next_tvb == NULL)
        { /* make a new subset */
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_data_dissector(next_tvb, pinfo, tree);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Fragment ID: %u, Fragment Offset: %u)", fragment_id, fragment_offset);
        }
        else
        {
            /* CAPWAP Control Header */
            offset = dissect_capwap_control_header(next_tvb, capwap_control_tree, 0, pinfo);

            /* CAPWAP Message Element */
            offset += dissect_capwap_message_element(next_tvb, capwap_control_tree, offset, pinfo);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Reassembled, Fragment ID: %u)", fragment_id);
        }
    }
    else
    {
        /* CAPWAP Control Header */
        offset += dissect_capwap_control_header(tvb, capwap_control_tree, offset, pinfo);

        /* CAPWAP Message Element */
        offset += dissect_capwap_message_element(tvb, capwap_control_tree, offset, pinfo);
    }
    pinfo->fragmented = save_fragmented;
    return offset;
}

static int
dissect_capwap_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *capwap_data_tree;
    guint offset = 0;
    tvbuff_t *next_tvb;
    guint8 type_header;
    guint8 payload_type;
    guint8 payload_wbid;
    gboolean fragment_is;
    gboolean fragment_more;
    guint32 fragment_id;
    guint32 fragment_offset;
    fragment_head *frag_msg = NULL;
    gboolean save_fragmented;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAPWAP-Data");
    col_set_str(pinfo->cinfo, COL_INFO, "CAPWAP-Data");

    ti = proto_tree_add_item(tree, proto_capwap_data, tvb, 0, -1, ENC_NA);
    capwap_data_tree = proto_item_add_subtree(ti, ett_capwap_data);

    /* CAPWAP Preamble */
    offset += dissect_capwap_preamble(tvb, capwap_data_tree, offset, &type_header);

    if (type_header == 1) {
        next_tvb = tvb_new_subset_remaining (tvb, offset);
        call_dissector(dtls_handle, next_tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }

    /* CAPWAP Header */
    offset += dissect_capwap_header(tvb, capwap_data_tree, offset, pinfo, &payload_type, &payload_wbid, &fragment_is, &fragment_more, &fragment_id, &fragment_offset);

    /* CAPWAP Reassemble */
    save_fragmented = pinfo->fragmented;

    if (global_capwap_reassemble && fragment_is)
    {
        gint len_rem = tvb_reported_length_remaining(tvb, offset);
        if (len_rem <= 0)
            return offset;

        pinfo->fragmented = TRUE;

        frag_msg = fragment_add_check(&capwap_reassembly_table,
                                      tvb, offset, pinfo, fragment_id, NULL,
                                      fragment_offset,
                                      len_rem,
                                      fragment_more);

        next_tvb = process_reassembled_data(tvb, offset, pinfo,
                                            "Reassembled CAPWAP", frag_msg,
                                            &capwap_frag_items, NULL, tree);

        if (next_tvb == NULL)
        { /* make a new subset */
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_data_dissector(next_tvb, pinfo, tree);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Fragment ID: %u, Fragment Offset: %u)", fragment_id, fragment_offset);
            return tvb_captured_length(tvb);
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Reassembled, Fragment ID: %u)", fragment_id);
        }
    }
    else
    {
        next_tvb = tvb_new_subset_remaining (tvb, offset);
    }

    /* CAPWAP Data Payload */
    if (payload_type == 0) {
        /* IEEE 802.3 Frame */
        call_dissector(ieee8023_handle, next_tvb, pinfo, tree);
    }
    else if (payload_type == 0xff) {
        /* CAPWAP Keep-Alive Payload */
        dissect_capwap_data_keep_alive(next_tvb, pinfo, capwap_data_tree, 0);
    }
    else
    {
        switch (payload_wbid) {
        case 0: /* Reserved - Cisco seems to use this instead of 1 */
            /* It seems that just calling ieee80211_handle is not
             * quite enough to get this right, so call data dissector
             * for now:
             */
            call_data_dissector(next_tvb, pinfo, tree);
            break;
        case 1: /* IEEE 802.11 */
            call_dissector(global_capwap_swap_frame_control ? ieee80211_bsfc_handle : ieee80211_handle, next_tvb, pinfo, tree);
            break;
        default: /* Unknown Data */
            call_data_dissector(next_tvb, pinfo, tree);
            break;
        }
    }
    pinfo->fragmented = save_fragmented;
    return tvb_captured_length(tvb);
}

static void
apply_capwap_prefs(void)
{
  global_capwap_data_udp_ports = prefs_get_range_value("capwap.data", "udp.port");
}

void
proto_register_capwap_control(void)
{
    module_t *capwap_module;

    static hf_register_info hf[] = {
        /* Preamble */
        { &hf_capwap_preamble,
            { "Preamble", "capwap.preamble",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_preamble_version,
            { "Version", "capwap.preamble.version",
              FT_UINT8, BASE_DEC, NULL, 0xF0,
              "Version of CAPWAP", HFILL }
        },
        { &hf_capwap_preamble_type,
            { "Type", "capwap.preamble.type",
              FT_UINT8, BASE_DEC, VALS(type_header_vals), 0x0F,
              "Type of Payload", HFILL }
        },
        { &hf_capwap_preamble_reserved,
            { "Reserved", "capwap.preamble.reserved",
              FT_UINT24, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        /* CAPWAP Header */
        { &hf_capwap_header,
            { "Header", "capwap.header",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_hlen,
            { "Header Length", "capwap.header.length",
              FT_UINT24, BASE_DEC, NULL, 0xF80000,
              "Length of the CAPWAP transport header in 4-byte words (similar to IP header length)", HFILL }
        },
        { &hf_capwap_header_rid,
            { "Radio ID", "capwap.header.rid",
              FT_UINT24, BASE_DEC, NULL, 0x07C000,
              NULL, HFILL }
        },
        { &hf_capwap_header_wbid,
            { "Wireless Binding ID", "capwap.header.wbid",
              FT_UINT24, BASE_DEC, VALS(type_wbid), 0x003E00,
              NULL, HFILL }
        },
        { &hf_capwap_header_flags,
            { "Header Flags", "capwap.header.flags",
              FT_UINT24, BASE_HEX, NULL, 0x0001FF,
              NULL, HFILL }
        },
        { &hf_capwap_header_flags_t,
            { "Payload Type", "capwap.header.flags.t",
              FT_BOOLEAN, 24, TFS(&flag_type_t), 0x000100,
              NULL, HFILL }
        },
        { &hf_capwap_header_flags_f,
            { "Fragment", "capwap.header.flags.f",
              FT_BOOLEAN, 24, TFS(&flag_type_f), 0x000080,
              NULL, HFILL }
        },
        { &hf_capwap_header_flags_l,
            { "Last Fragment", "capwap.header.flags.l",
              FT_BOOLEAN, 24, TFS(&flag_type_l), 0x000040,
              NULL, HFILL }
        },
        { &hf_capwap_header_flags_w,
        { "Wireless header", "capwap.header.flags.w",
            FT_BOOLEAN, 24, TFS(&flag_type_w), 0x000020,
            NULL, HFILL }
        },
        { &hf_capwap_header_flags_m,
            { "Radio MAC header", "capwap.header.flags.m",
              FT_BOOLEAN, 24, TFS(&flag_type_m), 0x000010,
              NULL, HFILL }
        },
        { &hf_capwap_header_flags_k,
            { "Keep-Alive", "capwap.header.flags.k",
              FT_BOOLEAN, 24, TFS(&flag_type_k), 0x000008,
              NULL, HFILL }
        },
        { &hf_capwap_header_flags_r,
            { "Reserved", "capwap.header.flags.r",
              FT_UINT24, BASE_HEX, 0x0, 0x000007,
              NULL, HFILL }
        },
        { &hf_capwap_header_fragment_id,
            { "Fragment ID", "capwap.header.fragment.id",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_fragment_offset,
            { "Fragment Offset", "capwap.header.fragment.offset",
              FT_UINT16, BASE_DEC, NULL, 0xFFF8,
              NULL, HFILL }
        },
        { &hf_capwap_header_reserved,
            { "Reserved", "capwap.header.fragment.reserved",
              FT_UINT16, BASE_DEC, NULL, 0x0007,
              NULL, HFILL }
        },
        { &hf_capwap_header_mac_length,
            { "MAC length", "capwap.header.mac.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_mac_eui48,
            { "MAC address", "capwap.header.mac.eui48",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_mac_eui64,
            { "MAC address", "capwap.header.mac.eui64",
              FT_EUI64, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_mac_data,
            { "MAC address", "capwap.header.mac.data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_wireless_length,
            { "Wireless length", "capwap.header.wireless.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_wireless_data,
            { "Wireless data", "capwap.header.wireless.data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_wireless_data_ieee80211_fi,
            { "Wireless data ieee80211 Frame Info", "capwap.header.wireless.data.ieee80211.fi",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_wireless_data_ieee80211_fi_rssi,
            { "Wireless data ieee80211 RSSI (dBm)", "capwap.header.wireless.data.ieee80211.fi.rssi",
              FT_INT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_wireless_data_ieee80211_fi_snr,
            { "Wireless data ieee80211 SNR (dB)", "capwap.header.wireless.data.ieee80211.fi.snr",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_wireless_data_ieee80211_fi_data_rate,
            { "Wireless data ieee80211 Data Rate (Mbps)", "capwap.header.wireless.data.ieee80211.fi.data_rate",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_wireless_data_ieee80211_dest_wlan,
            { "Wireless data ieee80211 Destination WLANs", "capwap.header.wireless.data.ieee80211.dw",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
            },
        { &hf_capwap_header_wireless_data_ieee80211_dw_wlan_id_bitmap,
            { "Wireless data ieee80211 Destination Wlan Id bitmap",
            "capwap.header.wireless.data.ieee80211.dw.wlan_id_bitmap",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_wireless_data_ieee80211_dw_reserved,
            { "Wireless data ieee80211 Destination Wlan reserved", "capwap.header.wireless.data.ieee80211.dw.reserved",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_header_padding,
            { "Padding for 4 Byte Alignment", "capwap.header.padding",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        /* CAPWAP Control Header Message */

        { &hf_capwap_control_header,
            { "Control Header", "capwap.control.header",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_control_header_msg_type,
            { "Message Type", "capwap.control.header.message_type",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_control_header_msg_type_enterprise_nbr,
            { "Message Type (Enterprise Number)", "capwap.control.header.message_type.enterprise_number",
              FT_UINT24, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_control_header_msg_type_enterprise_specific,
            { "Message Type (Enterprise Specific)", "capwap.control.header.message_type.enterprise_specific",
              FT_UINT32, BASE_DEC, VALS(message_type), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_control_header_seq_number,
            { "Sequence Number", "capwap.control.header.sequence_number",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_control_header_msg_element_length,
            { "Message Element Length", "capwap.control.header.message_element_length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_control_header_flags,
            { "Flags", "capwap.control.header.flags",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        /* CAPWAP Protocol Message Elements */

        { &hf_capwap_message_element,
            { "Message Element", "capwap.message_element",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element,
            { "Type", "capwap.message_element",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type,
            { "Type", "capwap.message_element.type",
              FT_UINT16, BASE_DEC, VALS(message_element_type_vals), 0x0,
              "CAPWAP Message Element type", HFILL }
        },
        { &hf_capwap_msg_element_length,
            { "Length", "capwap.message_element.length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "CAPWAP Message Element length", HFILL }
        },
        { &hf_capwap_msg_element_value,
            { "Value", "capwap.message_element.value",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "CAPWAP Message Element value", HFILL }
        },

        /* CAPWAP Protocol Message Element Type */

        /* AC Descriptor */
        { &hf_capwap_msg_element_type_ac_descriptor_stations,
            { "Stations", "capwap.control.message_element.ac_descriptor.stations",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_descriptor_limit,
            { "Limit Stations", "capwap.control.message_element.ac_descriptor.limit",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_descriptor_active_wtp,
            { "Active WTPs", "capwap.control.message_element.ac_descriptor.active_wtp",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_descriptor_max_wtp,
            { "Max WTPs", "capwap.control.message_element.ac_descriptor.max_wtp",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        /* AC Descriptor Security Flags... */
        { &hf_capwap_msg_element_type_ac_descriptor_security,
            { "Security Flags", "capwap.control.message_element.ac_descriptor.security",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_descriptor_security_s,
            { "AC supports the pre-shared", "capwap.control.message_element.ac_descriptor.security.s",
              FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_descriptor_security_x,
            { "AC supports X.509 Certificate", "capwap.control.message_element.ac_descriptor.security.x",
              FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_descriptor_security_r,
            { "Reserved", "capwap.control.message_element.ac_descriptor.security.r",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0xF9,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_ac_descriptor_rmac_field,
            { "R-MAC Field", "capwap.control.message_element.ac_descriptor.rmac_field",
              FT_UINT8, BASE_DEC, VALS(rmac_field_vals), 0x0,
              NULL, HFILL }
            },
        { &hf_capwap_msg_element_type_ac_descriptor_reserved,
            { "Reserved", "capwap.control.message_element.ac_descriptor.reserved",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        /* AC Descriptor DTLS Policy Flags... */
        { &hf_capwap_msg_element_type_ac_descriptor_dtls_policy,
            { "DTLS Policy Flags", "capwap.control.message_element.ac_descriptor.dtls_policy",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_descriptor_dtls_policy_d,
            { "DTLS-Enabled Data Channel Supported", "capwap.control.message_element.ac_descriptor.dtls_policy.d",
              FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_descriptor_dtls_policy_c,
            { "Clear Text Data Channel Supported", "capwap.control.message_element.ac_descriptor.dtls_policy.c",
              FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_descriptor_dtls_policy_r,
            { "Reserved", "capwap.control.message_element.ac_descriptor.dtls_policy.r",
              FT_UINT8, BASE_HEX, 0x0, 0xF9,
              "Must be zero", HFILL }
        },

        { &hf_capwap_msg_element_type_ac_information,
            { "AC Information", "capwap.control.message_element.ac_information",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_ac_information_vendor,
            { "AC Information Vendor", "capwap.control.message_element.ac_information.vendor",
              FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_information_type,
            { "AC Information Type", "capwap.control.message_element.ac_information.type",
              FT_UINT16, BASE_DEC, VALS(ac_information_type_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_information_length,
            { "AC Information Length", "capwap.control.message_element.ac_information.length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_ac_information_value,
            { "AC Information Value", "capwap.control.message_element.ac_information.value",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_information_hardware_version,
            { "AC Hardware Version", "capwap.control.message_element.ac_information.hardware_version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_information_software_version,
            { "AC Software Version", "capwap.control.message_element.ac_information.software_version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_ipv4_list,
            { "AC IPv4 List", "capwap.control.message_element.message_element.ac_ipv4_list",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_ipv6_list,
            { "AC IPv6 List", "capwap.control.message_element.message_element.ac_ipv6_list",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        /* CAPWAP Control IPvX Address*/
        { &hf_capwap_msg_element_type_capwap_control_ipv4,
            { "CAPWAP Control IP Address", "capwap.control.message_element.message_element.capwap_control_ipv4",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_capwap_control_ipv6,
            { "CAPWAP Control IP Address", "capwap.control.message_element.message_element.capwap_control_ipv6",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_capwap_control_wtp_count,
            { "CAPWAP Control WTP Count", "capwap.control.message_element.capwap_control_wtp_count",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_capwap_timers_discovery,
            { "CAPWAP Timers Discovery (Sec)", "capwap.control.message_element.capwap_timers_discovery",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_capwap_timers_echo_request,
            { "CAPWAP Timers Echo Request (Sec)", "capwap.control.message_element.capwap_timers_echo_request",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_decryption_error_report_period_radio_id,
            { "Decryption Error Report Period Radio ID", "capwap.control.message_element.decryption_error_report_period.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_decryption_error_report_period_interval,
            { "Decryption Error Report Period Interval (Sec)", "capwap.control.message_element.decryption_error_report_period.interval",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_delete_station_radio_id,
            { "Radio ID", "capwap.control.message_element.delete_station.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Representing the radio, whose value is between one (1) and 31", HFILL }
        },
        { &hf_capwap_msg_element_type_delete_station_length,
            { "Mac Length", "capwap.control.message_element.delete_station.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "The length of the MAC Address field", HFILL }
        },
        { &hf_capwap_msg_element_type_delete_station_mac_eui48,
            { "MAC address", "capwap.control.message_element.delete_station.mac.eui48",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_delete_station_mac_eui64,
            { "MAC address", "capwap.control.message_element.delete_station.mac.eui64",
              FT_EUI64, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_delete_station_mac_data,
            { "MAC address", "capwap.control.message_element.delete_station.mac.data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_name,
            { "AC Name", "capwap.control.message_element.ac_name",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ac_name_with_priority,
            { "AC Name Priority", "capwap.control.message_element.ac_name_with_priority",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_ac_timestamp,
            { "AC Timestamp", "capwap.control.message_element.ac_timestamp",
              FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_add_station_radio_id,
            { "Radio ID", "capwap.control.message_element.add_station.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Representing the radio, whose value is between one (1) and 31", HFILL }
        },
        { &hf_capwap_msg_element_type_add_station_length,
            { "Mac Length", "capwap.control.message_element.add_station.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "The length of the MAC Address field", HFILL }
        },
        { &hf_capwap_msg_element_type_add_station_mac_eui48,
            { "MAC address", "capwap.control.message_element.add_station.mac.eui48",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_add_station_mac_eui64,
            { "MAC address", "capwap.control.message_element.add_station.mac.eui64",
              FT_EUI64, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_add_station_mac_data,
            { "MAC address", "capwap.control.message_element.add_station.mac.data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_add_station_vlan_name,
            { "Vlan Name", "capwap.control.message_element.add_station.vlan_name",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Containing the VLAN Name on which the WTP is to locally bridge user data", HFILL }
        },

        { &hf_capwap_msg_element_type_discovery_type,
            { "Discovery Type", "capwap.control.message_element.discovery_type",
              FT_UINT8, BASE_DEC, VALS(discovery_type_vals), 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_idle_timeout,
            { "Idle Timeout (Sec)", "capwap.control.message_element.idle_timeout",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_location_data,
            { "Location Data", "capwap.control.message_element.location_data",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_maximum_message_length,
            { "Maximum Message Length", "capwap.control.message_element.maximum_message_length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_capwap_local_ipv4_address,
            { "CAPWAP Local IPv4 Address", "capwap.control.message_element.capwap_local_ipv4_address",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              "The IP address of the sender", HFILL }
        },


        { &hf_capwap_msg_element_type_radio_admin_id,
            { "Radio Administrative ID", "capwap.control.message_element.radio_admin.id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_radio_admin_state,
            { "Radio Administrative State", "capwap.control.message_element.radio_admin.state",
              FT_UINT8, BASE_DEC, VALS(radio_admin_state_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_radio_op_state_radio_id,
            { "Radio Operational ID", "capwap.control.message_element.radio_op_state.radio_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_radio_op_state_radio_state,
            { "Radio Operational State", "capwap.control.message_element.radio_op_state.radio_state",
              FT_UINT8, BASE_DEC, VALS(radio_op_state_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_radio_op_state_radio_cause,
            { "Radio Operational Cause", "capwap.control.message_element.radio_op_state.radio_cause",
               FT_UINT8, BASE_DEC, VALS(radio_op_cause_vals), 0x0,
               NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_result_code,
            { "Result Code", "capwap.control.message_element.result_code",
              FT_UINT32, BASE_DEC, VALS(result_code_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_session_id,
            { "Session ID", "capwap.control.message_element.session_id",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_statistics_timer,
            { "Statistics Timer (Sec)", "capwap.control.message_element.statistics_timer",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_vsp_vendor_identifier,
            { "Vendor Identifier", "capwap.control.message_element.vsp.vendor_identifier",
              FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_vsp_vendor_element_id,
            { "Vendor Element ID", "capwap.control.message_element.vsp.vendor_element_id",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_vsp_vendor_data,
            { "Vendor Data", "capwap.control.message_element.vsp.vendor_data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_wtp_board_data,
            { "WTP Board Data", "capwap.control.message_element.wtp_board_data",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_board_data_vendor,
            { "WTP Board Data Vendor", "capwap.control.message_element.wtp_board_data.vendor",
               FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0x0,
               NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_board_data_type,
            { "Board Data Type", "capwap.control.message_element.wtp_board_data.type",
              FT_UINT16, BASE_DEC, VALS(board_data_type_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_board_data_length,
            { "Board Data Length", "capwap.control.message_element.wtp_board_data.length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_board_data_value,
            { "Board Data Value", "capwap.control.message_element.wtp_board_data.value",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_wtp_board_data_wtp_model_number,
            { "WTP Model Number", "capwap.control.message_element.wtp_board_data.wtp_model_number",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_board_data_wtp_serial_number,
            { "WTP Serial Number", "capwap.control.message_element.wtp_board_data.wtp_serial_number",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_board_data_wtp_board_id,
            { "WTP Board ID", "capwap.control.message_element.wtp_board_data.wtp_board_id",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_board_data_wtp_board_revision,
            { "WTP Board Revision", "capwap.control.message_element.wtp_board_data.wtp_board_revision",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_board_data_base_mac_address,
            { "Base Mac Address", "capwap.control.message_element.wtp_board_data.base_mac_address",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_wtp_descriptor_max_radios,
            { "Max Radios", "capwap.control.message_element.wtp_descriptor.max_radios",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_radio_in_use,
            { "Radio in use", "capwap.control.message_element.wtp_descriptor.radio_in_use",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_number_encrypt,
            { "Encryption Capabilities (Number)", "capwap.control.message_element.wtp_descriptor.number_encrypt",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_encrypt,
            { "Encryption Capabilities", "capwap.control.message_element.wtp_descriptor.encrypt",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_encrypt_reserved,
            { "Reserved (Encrypt)", "capwap.control.message_element.wtp_descriptor.encrypt_reserved",
              FT_UINT8, BASE_DEC, NULL, 0xE0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_encrypt_wbid,
            { "Encrypt WBID", "capwap.control.message_element.wtp_descriptor.encrypt_wbid",
              FT_UINT8, BASE_DEC, VALS(type_wbid), 0x1F,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_encrypt_capabilities,
            { "Encryption Capabilities", "capwap.control.message_element.wtp_descriptor.encrypt_capabilities",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_wtp_descriptor,
            { "WTP Descriptor", "capwap.control.message_element.wtp_descriptor",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_vendor,
            { "WTP Descriptor Vendor", "capwap.control.message_element.wtp_descriptor.vendor",
              FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_type,
            { "Descriptor Type", "capwap.control.message_element.wtp_descriptor.type",
              FT_UINT16, BASE_DEC, VALS(wtp_descriptor_type_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_length,
            { "Descriptor Length", "capwap.control.message_element.wtp_descriptor.length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_value,
            { "Descriptor Value", "capwap.control.message_element.wtp_descriptor.value",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_hardware_version,
            { "WTP Hardware Version", "capwap.control.message_element.wtp_descriptor.hardware_version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_active_software_version,
            { "WTP Active Software Version", "capwap.control.message_element.wtp_descriptor.active_software_version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_boot_version,
            { "WTP Boot Version", "capwap.control.message_element.wtp_descriptor.boot_version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_descriptor_other_software_version,
            { "WTP Other Software Version", "capwap.control.message_element.wtp_descriptor.other_software_version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_fallback,
            { "WTP Fallback", "capwap.control.message_element.wtp_fallback",
              FT_UINT8, BASE_DEC, VALS(wtp_fallback_vals), 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_wtp_frame_tunnel_mode,
            { "WTP Frame Tunnel Mode", "capwap.control.message_element.wtp_frame_tunnel_mode",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_frame_tunnel_mode_n,
            { "Native Frame Tunnel Mode", "capwap.control.message_element.wtp_frame_tunnel_mode.n",
              FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x08,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_frame_tunnel_mode_e,
            { "802.3 Frame Tunnel Mode", "capwap.control.message_element.wtp_frame_tunnel_mode.e",
              FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_frame_tunnel_mode_l,
            { "Local Bridging", "capwap.control.message_element.wtp_frame_tunnel_mode.l",
              FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_frame_tunnel_mode_r,
            { "Reserved", "capwap.control.message_element.wtp_frame_tunnel_mode.r",
              FT_UINT8, BASE_HEX, 0x0, 0xF1,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_wtp_mac_type,
            { "WTP MAC Type", "capwap.control.message_element.wtp_mac_type",
              FT_UINT8, BASE_DEC, VALS(wtp_mac_vals), 0x0,
              "The MAC mode of operation supported by the WTP", HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_name,
            { "WTP Name", "capwap.control.message_element.wtp_name",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_reboot_statistics_reboot_count,
            { "Reboot  Count", "capwap.control.message_element.wtp_reboot_statistics.reboot_count",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "The number of reboots that have occurred due to a WTP crash", HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_reboot_statistics_ac_initiated_count,
            { "AC Initiated Count", "capwap.control.message_element.wtp_reboot_statistics.ac_initiated_count",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "The number of reboots that have occurred at the request of a CAPWAP protocol message", HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_reboot_statistics_link_failure_count,
            { "Link Failure Count", "capwap.control.message_element.wtp_reboot_statistics.link_failure_count",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "The number of times that a CAPWAP protocol connection with an AC has failed due to link failure", HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_reboot_statistics_sw_failure_count,
            { "SW Failure Count", "capwap.control.message_element.wtp_reboot_statistics.sw_failure_count",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "The number of times that a CAPWAP protocol connection with an AC has failed due to software-related reasons", HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_reboot_statistics_hw_failure_count,
            { "HW Failure Count", "capwap.control.message_element.wtp_reboot_statistics.hw_failure_count",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "The number of times that a CAPWAP protocol connection with an AC has failed due to hardware-related reasons", HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_reboot_statistics_other_failure_count,
            { "Other Failure Count", "capwap.control.message_element.wtp_reboot_statistics.other_failure_count",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "The number of times that a CAPWAP protocol connection with an AC has failed due to known reasons, other than AC initiated, link, SW or HW failure", HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_reboot_statistics_unknown_failure_count,
            { "Unknown Failure Count", "capwap.control.message_element.wtp_reboot_statistics.unknown_failure_count",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "The number of times that a CAPWAP protocol connection with an AC has failed for unknown reasons", HFILL }
        },
        { &hf_capwap_msg_element_type_wtp_reboot_statistics_last_failure_type,
            { "Last Failure Type", "capwap.control.message_element.wtp_reboot_statistics.last_failure_type",
              FT_UINT8, BASE_DEC, VALS(last_failure_type_vals), 0x0,
              "The failure type of the most recent WTP failure", HFILL }
        },

        { &hf_capwap_msg_element_type_capwap_local_ipv6_address,
            { "CAPWAP Local IPv6 Address", "capwap.control.message_element.capwap_local_ipv6_address",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              "The IP address of the sender", HFILL }
        },

        { &hf_capwap_msg_element_type_capwap_transport_protocol,
            { "CAPWAP Transport Protocol", "capwap.control.message_element.capwap_transport_protocol",
              FT_UINT8, BASE_DEC, VALS(capwap_transport_protocol_vals), 0x0,
              "The transport to use for the CAPWAP Data channel", HFILL }
        },

        { &hf_capwap_msg_element_type_mtu_discovery_padding,
            { "MTU Discovery Padding", "capwap.control.message_element.mtu_discovery_padding",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "A variable-length pad, filled with the value 0xFF", HFILL }
        },

        { &hf_capwap_msg_element_type_ecn_support,
            { "ECN Support", "capwap.control.message_element.ecn_support",
              FT_UINT8, BASE_DEC, VALS(ecn_support_vals), 0x0,
              "The sender's support for ECN, as defined in [RFC3168]", HFILL }
        },


        /* Message element type IEEE80211 : RFC 5416 Section 6 */
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_add_wlan.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_wlan_id,
            { "WLAN ID", "capwap.control.message_element.ieee80211_add_wlan.wlan_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability,
            { "Capability", "capwap.control.message_element.ieee80211_add_wlan.capability",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_e,
            { "ESS", "capwap.control.message_element.ieee80211_add_wlan.capability.e",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_i,
            { "IBSS", "capwap.control.message_element.ieee80211_add_wlan.capability.i",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x4000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_c,
            { "CF-Pollable", "capwap.control.message_element.ieee80211_add_wlan.capability.c",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x2000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_f,
            { "CF-Poll Request", "capwap.control.message_element.ieee80211_add_wlan.capability.f",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x1000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_p,
            { "Privacy", "capwap.control.message_element.ieee80211_add_wlan.capability.p",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0800,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_s,
            { "Short Preamble", "capwap.control.message_element.ieee80211_add_wlan.capability.s",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0400,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_b,
            { "PBCC", "capwap.control.message_element.ieee80211_add_wlan.capability.b",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0200,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_a,
            { "Channel Agility", "capwap.control.message_element.ieee80211_add_wlan.capability.a",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_m,
            { "Spectrum Management", "capwap.control.message_element.ieee80211_add_wlan.capability.m",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_q,
            { "QoS", "capwap.control.message_element.ieee80211_add_wlan.capability.q",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0040,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_t,
            { "Short Slot Time", "capwap.control.message_element.ieee80211_add_wlan.capability.t",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0020,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_d,
            { "APSD", "capwap.control.message_element.ieee80211_add_wlan.capability.d",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0010,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_v,
            { "Reserved", "capwap.control.message_element.ieee80211_add_wlan.capability.v",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0008,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_o,
            { "DSSS-OFDM", "capwap.control.message_element.ieee80211_add_wlan.capability.o",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0004,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_k,
            { "Delayed Block ACK", "capwap.control.message_element.ieee80211_add_wlan.capability.k",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0002,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_capability_l,
            { "Immediate Block ACK", "capwap.control.message_element.ieee80211_add_wlan.capability.l",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0001,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_key_index,
            { "Key-Index", "capwap.control.message_element.ieee80211_add_wlan.key_index",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_key_status,
            { "Key Status", "capwap.control.message_element.ieee80211_add_wlan.key_status",
              FT_UINT8, BASE_DEC, VALS(ieee80211_wlan_key_status_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_key_length,
            { "Key Length", "capwap.control.message_element.ieee80211_add_wlan.key_length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_key,
            { "Key", "capwap.control.message_element.ieee80211_add_wlan.key",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_group_tsc,
            { "Group TSC", "capwap.control.message_element.ieee80211_add_wlan.group_tsc",
              FT_UINT64, BASE_DEC, NULL, 0x00FFFFFF,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_qos,
            { "QoS", "capwap.control.message_element.ieee80211_add_wlan.qos",
              FT_UINT8, BASE_DEC, VALS(ieee80211_add_wlan_qos_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_auth_type,
            { "Auth Type", "capwap.control.message_element.ieee80211_add_wlan.auth_type",
              FT_UINT8, BASE_DEC, VALS(ieee80211_add_wlan_auth_type_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_mac_mode,
            { "MAC Mode", "capwap.control.message_element.ieee80211_add_wlan.mac_mode",
              FT_UINT8, BASE_DEC, VALS(ieee80211_add_wlan_mac_mode_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_tunnel_mode,
            { "Tunnel Mode", "capwap.control.message_element.ieee80211_add_wlan.tunnel_mode",
              FT_UINT8, BASE_DEC, VALS(ieee80211_add_wlan_tunnel_mode_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_suppress_ssid,
            { "Suppress SSID", "capwap.control.message_element.ieee80211_add_wlan.suppress_ssid",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_add_wlan_ssid,
            { "SSID", "capwap.control.message_element.ieee80211_add_wlan.ssid",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_antenna_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_antenna.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_antenna_diversity,
            { "Diversity", "capwap.control.message_element.ieee80211_antenna.diversity",
              FT_UINT8, BASE_DEC, VALS(ieee80211_antenna_diversity_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_antenna_combiner,
            { "Combiner", "capwap.control.message_element.ieee80211_antenna.combiner",
              FT_UINT8, BASE_DEC, VALS(ieee80211_antenna_combiner_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_antenna_count,
            { "Antenna Count", "capwap.control.message_element.ieee80211_antenna.count",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_antenna_selection,
            { "Selection", "capwap.control.message_element.ieee80211_antenna.selection",
              FT_UINT8, BASE_DEC, VALS(ieee80211_antenna_selection_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_assigned_wtp_bssid_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_assigned_wtp_bssid.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_assigned_wtp_bssid_wlan_id,
            { "WLAN ID", "capwap.control.message_element.ieee80211_assigned_wtp_bssid.wlan_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_assigned_wtp_bssid_bssid,
            { "BSSID", "capwap.control.message_element.ieee80211_assigned_wtp_bssid.bssid",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_delete_wlan_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_delete_wlan.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_delete_wlan_wlan_id,
            { "WLAN ID", "capwap.control.message_element.ieee80211_delete_wlan.wlan_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_direct_sequence_control_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_direct_sequence_control.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_direct_sequence_control_reserved,
            { "Reserved", "capwap.control.message_element.ieee80211_direct_sequence_control.reserved",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_direct_sequence_control_current_channel,
            { "Current Channel", "capwap.control.message_element.ieee80211_direct_sequence_control.current_channel",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_direct_sequence_control_current_cca,
            { "Current CCA", "capwap.control.message_element.ieee80211_direct_sequence_control.current_cca",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_direct_sequence_control_energy_detect_threshold,
            { "Energy Detect Threshold", "capwap.control.message_element.ieee80211_direct_sequence_control.energy_detect_threshold",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ie_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_ie.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ie_wlan_id,
            { "WLAN ID", "capwap.control.message_element.ieee80211_ie.wlan_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ie_flags,
            { "Flags", "capwap.control.message_element.ieee80211_ie.flags",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ie_flags_b,
            { "Include IE in Beacons", "capwap.control.message_element.ieee80211_ie.flags.b",
              FT_BOOLEAN, 8, NULL, 0x80,
              "When set, the WTP is to include the Information Element in IEEE 802.11 Beacons associated with the WLAN", HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ie_flags_p,
            { "Include IE in  Probe Responses", "capwap.control.message_element.ieee80211_ie.flags.p",
              FT_BOOLEAN, 8, NULL, 0x40,
              "When set, the WTP is to include the Information Element in Probe Responses associated with the WLAN", HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ie_flags_rsv,
            { "Reserved", "capwap.control.message_element.ieee80211_ie.flags.rsv",
              FT_UINT8, BASE_HEX, NULL, 0x3F,
              "Must be Zero", HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_mac_operation_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_mac_operation.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_mac_operation_reserved,
            { "Reserved", "capwap.control.message_element.ieee80211_mac_operation.reserved",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_mac_operation_rts_threshold,
            { "RTS Threshold", "capwap.control.message_element.ieee80211_mac_operation.rts_threshold",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_mac_operation_short_retry,
            { "Short Retry", "capwap.control.message_element.ieee80211_mac_operation.short_retry",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_mac_operation_long_retry,
            { "Long Retry", "capwap.control.message_element.ieee80211_mac_operation.long_retry",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_mac_operation_fragmentation_threshold,
            { "Fragmentation Threshold", "capwap.control.message_element.ieee80211_mac_operation.fragmentation_threshold",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_mac_operation_tx_msdu_lifetime,
            { "Tx MDSU Lifetime", "capwap.control.message_element.ieee80211_mac_operation.tx_msdu_lifetime",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_mac_operation_rx_msdu_lifetime,
            { "Rx MDSU Lifetime", "capwap.control.message_element.ieee80211_mac_operation.rx_msdu_lifetime",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_mic_countermeasures_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_mic_countermeasures.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_mic_countermeasures_wlan_id,
            { "WLAN ID", "capwap.control.message_element.ieee80211_mic_countermeasures.wlan_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_mic_countermeasures_mac_address,
            { "MAC Address", "capwap.control.message_element.ieee80211_mic_countermeasures.mac_address",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_multi_domain_capability_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_multi_domain_capability.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_multi_domain_capability_reserved,
            { "Reserved", "capwap.control.message_element.ieee80211_multi_domain_capability.reserved",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_multi_domain_capability_first_channel,
            { "First Channel", "capwap.control.message_element.ieee80211_multi_domain_capability.first_channel",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_multi_domain_capability_number_of_channels,
            { "Number of  Channels", "capwap.control.message_element.ieee80211_multi_domain_capability.number_of_channels",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_multi_domain_capability_max_tx_power_level,
            { "Max TX Power Level", "capwap.control.message_element.ieee80211_multi_domain_capability.max_tx_power_level",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_ieee80211_ofdm_control_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_ofdm_control.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ofdm_control_reserved,
            { "Reserved", "capwap.control.message_element.ieee80211_ofdm_control.reserved",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ofdm_control_current_channel,
            { "Current Channel", "capwap.control.message_element.ieee80211_ofdm_control.current_channel",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support,
            { "Band Support", "capwap.control.message_element.ieee80211_ofdm_control.band_support",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit0,
            { "Operating in the 5.15-5.25 GHz band", "capwap.control.message_element.ieee80211_ofdm_control.band_support.bit0",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit1,
            { "Operating in the 5.25-5.35 GHz band", "capwap.control.message_element.ieee80211_ofdm_control.band_support.bit1",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit2,
            { "Operating in the 5.725-5.825 GHz band", "capwap.control.message_element.ieee80211_ofdm_control.band_support.bit2",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit3,
            { "Operating in the 5.47-5.725 GHz band", "capwap.control.message_element.ieee80211_ofdm_control.band_support.bit3",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit4,
            { "Operating in the lower Japanese 5.25 GHz band", "capwap.control.message_element.ieee80211_ofdm_control.band_support.bit4",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit5,
            { "Operating in the l5.03-5.091 GHz band", "capwap.control.message_element.ieee80211_ofdm_control.band_support.bit5",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit6,
            { "Operating in the l5.03-5.091 GHz band", "capwap.control.message_element.ieee80211_ofdm_control.band_support.bit5",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ofdm_control_band_support_bit7,
            { "Reserved", "capwap.control.message_element.ieee80211_ofdm_control.band_support.bit7",
              FT_UINT8, BASE_HEX, NULL, 0x80,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_ofdm_control_ti_threshold,
            { "TI Threshold", "capwap.control.message_element.ieee80211_mofdm_control.ti_threshold",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_ieee80211_rate_set_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_rate_set.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_rate_set_rate_set,
            { "Rate Set", "capwap.control.message_element.ieee80211_rate_set.rate_set",
              FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ieee80211_supported_rates_vals_ext, 0x0,
              "In Mbit/sec, (B) for Basic Rates", HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_station.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_association_id,
            { "Association ID", "capwap.control.message_element.ieee80211_station.association_id",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_flags,
            { "Flags", "capwap.control.message_element.ieee80211_station.flags",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_mac_address,
            { "MAC Address", "capwap.control.message_element.ieee80211_station.mac_address",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities,
            { "Capabilities", "capwap.control.message_element.ieee80211_station.capabilities",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_e,
            { "ESS", "capwap.control.message_element.ieee80211_station.capabilities.e",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_i,
            { "IBSS", "capwap.control.message_element.ieee80211_station.capabilities.i",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x4000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_c,
            { "CF-Pollable", "capwap.control.message_element.ieee80211_station.capabilities.c",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x2000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_f,
            { "CF-Poll Request", "capwap.control.message_element.ieee80211_station.capabilities.f",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x1000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_p,
            { "Privacy", "capwap.control.message_element.ieee80211_station.capabilities.p",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0800,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_s,
            { "Short Preamble", "capwap.control.message_element.ieee80211_station.capabilities.s",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0400,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_b,
            { "PBCC", "capwap.control.message_element.ieee80211_station.capabilities.b",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0200,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_a,
            { "Channel Agility", "capwap.control.message_element.ieee80211_station.capabilities.a",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_m,
            { "Spectrum Management", "capwap.control.message_element.ieee80211_station.capabilities.m",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_q,
            { "QoS", "capwap.control.message_element.ieee80211_station.capabilities.q",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0040,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_t,
            { "Short Slot Time", "capwap.control.message_element.ieee80211_station.capabilities.t",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0020,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_d,
            { "APSD", "capwap.control.message_element.ieee80211_station.capabilities.d",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0010,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_v,
            { "Reserved", "capwap.control.message_element.ieee80211_station.capabilities.v",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0008,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_o,
            { "DSSS-OFDM", "capwap.control.message_element.ieee80211_station.capabilities.o",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0004,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_k,
            { "Delayed Block ACK", "capwap.control.message_element.ieee80211_station.capabilities.k",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0002,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_capabilities_l,
            { "Immediate Block ACK", "capwap.control.message_element.ieee80211_station.capabilities.l",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0001,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_wlan_id,
            { "WLAN ID", "capwap.control.message_element.ieee80211_station.wlan_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_supported_rates,
            { "Supported Rates", "capwap.control.message_element.ieee80211_station.supported_rates",
              FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ieee80211_supported_rates_vals_ext, 0x0,
              "In Mbit/sec, (B) for Basic Rates", HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_session_key_mac,
            { "Mac Address", "capwap.control.message_element.ieee80211_station_session_key.mac",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              "The station's MAC Address", HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_session_key_flags,
            { "Flags", "capwap.control.message_element.ieee80211_station_session_key.flags",
              FT_UINT16, BASE_DEC, NULL, 0x3FFF,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_session_key_flags_a,
            { "Flag A", "capwap.control.message_element.ieee80211_station_session_key.flags_a",
              FT_BOOLEAN, 16, NULL, 0x2000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_session_key_flags_c,
            { "Flag C", "capwap.control.message_element.ieee80211_station_session_key.flags_c",
              FT_BOOLEAN, 16, NULL, 0x1000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_session_key_pairwire_tsc,
            { "Pairwise TSC", "capwap.control.message_element.ieee80211_station_session_key.pairwire_tsc",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Transmit Sequence Counter (TSC)", HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_session_key_pairwire_rsc,
            { "Pairwise RSC", "capwap.control.message_element.ieee80211_station_session_key.pairwire_rsc",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Receive Sequence Counter (TSC)", HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_station_session_key_key,
            { "Key", "capwap.control.message_element.ieee80211_station_session_key.key",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_supported_rates_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_supported_rates.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_supported_rates_rate,
            { "Rates", "capwap.control.message_element.ieee80211_supported_rates.rate",
              FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ieee80211_supported_rates_vals_ext, 0x0,
              "In Mbit/sec, (B) for Basic Rates", HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_tx_power_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_tx_power.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_tx_power_reserved,
            { "Reserved", "capwap.control.message_element.ieee80211_tx_power.reserved",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_tx_power_current_tx_power,
            { "Current Tx Power", "capwap.control.message_element.ieee80211_tx_power.current_tx_power",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_tx_power_level_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_tx_power_level.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_tx_power_level_num_levels,
            { "Num Levels", "capwap.control.message_element.ieee80211_tx_power_level.num_levels",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_tx_power_level_power_level,
            { "Power Level", "capwap.control.message_element.ieee80211_tx_power_level.power_level",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_update_wlan.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_wlan_id,
            { "WLAN ID", "capwap.control.message_element.ieee80211_update_wlan.wlan_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability,
            { "Capability", "capwap.control.message_element.ieee80211_update_wlan.capability",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_e,
            { "ESS", "capwap.control.message_element.ieee80211_update_wlan.capability.e",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_i,
            { "IBSS", "capwap.control.message_element.ieee80211_update_wlan.capability.i",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x4000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_c,
            { "CF-Pollable", "capwap.control.message_element.ieee80211_update_wlan.capability.c",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x2000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_f,
            { "CF-Poll Request", "capwap.control.message_element.ieee80211_update_wlan.capability.f",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x1000,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_p,
            { "Privacy", "capwap.control.message_element.ieee80211_update_wlan.capability.p",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0800,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_s,
            { "Short Preamble", "capwap.control.message_element.ieee80211_update_wlan.capability.s",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0400,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_b,
            { "PBCC", "capwap.control.message_element.ieee80211_update_wlan.capability.b",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0200,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_a,
            { "Channel Agility", "capwap.control.message_element.ieee80211_update_wlan.capability.a",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_m,
            { "Spectrum Management", "capwap.control.message_element.ieee80211_update_wlan.capability.m",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_q,
            { "QoS", "capwap.control.message_element.ieee80211_update_wlan.capability.q",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0040,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_t,
            { "Short Slot Time", "capwap.control.message_element.ieee80211_update_wlan.capability.t",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0020,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_d,
            { "APSD", "capwap.control.message_element.ieee80211_update_wlan.capability.d",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0010,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_v,
            { "Reserved", "capwap.control.message_element.ieee80211_update_wlan.capability.v",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0008,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_o,
            { "DSSS-OFDM", "capwap.control.message_element.ieee80211_update_wlan.capability.o",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0004,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_k,
            { "Delayed Block ACK", "capwap.control.message_element.ieee80211_update_wlan.capability.k",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0002,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_capability_l,
            { "Immediate Block ACK", "capwap.control.message_element.ieee80211_update_wlan.capability.l",
              FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0001,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_key_index,
            { "Key-Index", "capwap.control.message_element.ieee80211_update_wlan.key_index",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_key_status,
            { "Key Status", "capwap.control.message_element.ieee80211_update_wlan.key_status",
              FT_UINT8, BASE_DEC, VALS(ieee80211_wlan_key_status_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_key_length,
            { "Key Length", "capwap.control.message_element.ieee80211_update_wlan.key_length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_update_wlan_key,
            { "Key", "capwap.control.message_element.ieee80211_update_wlan.key",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_wtp_radio_info.cfg_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_short_preamble,
            { "Short Preamble", "capwap.control.message_element.ieee80211_wtp_radio_info.short_preamble",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_num_of_bssids,
            { "Num of BSSIDs", "capwap.control.message_element.ieee80211_wtp_radio_info.num_of_bssids",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_dtim_period,
            { "DTIM Period", "capwap.control.message_element.ieee80211_wtp_radio_info.dtim_period",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_bssid,
            { "BSSID", "capwap.control.message_element.ieee80211_wtp_radio_info.bssid",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_beacon_period,
            { "Beacon Period", "capwap.control.message_element.ieee80211_wtp_radio_info.beacon_period",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_wtp_radio_cfg_country_string,
            { "Country String", "capwap.control.message_element.ieee80211_wtp_radio_info.country_string",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_id,
            { "Radio ID", "capwap.control.message_element.ieee80211_wtp_radio_info.radio_id",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_reserved,
            { "Radio Type Reserved", "capwap.control.message_element.ieee80211_wtp_info_radio.radio_type_reserved",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_n,
            { "Radio Type 802.11n", "capwap.control.message_element.ieee80211_wtp_info_radio.radio_type_n",
              FT_BOOLEAN, 4, TFS(&tfs_true_false), 0x8,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_g,
            { "Radio Type 802.11g", "capwap.control.message_element.ieee80211_wtp_info_radio.radio_type_g",
              FT_BOOLEAN, 4, TFS(&tfs_true_false), 0x4,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_a,
            { "Radio Type 802.11a", "capwap.control.message_element.ieee80211_wtp_info_radio.radio_type_a",
              FT_BOOLEAN, 4, TFS(&tfs_true_false), 0x2,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_wtp_radio_info_radio_type_b,
            { "Radio Type 802.11b", "capwap.control.message_element.ieee80211_wtp_info_radio.radio_type_b",
              FT_BOOLEAN, 4, TFS(&tfs_true_false), 0x1,
              NULL, HFILL }
        },

        { &hf_capwap_msg_element_type_ieee80211_supported_mac_profiles_numbers,
            { "Numbers Profiles", "capwap.control.message_element.ieee80211_supported_mac_profiles.numbers",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_supported_mac_profiles_profile,
            { "Profile", "capwap.control.message_element.ieee80211_supported_mac_profiles.profile",
              FT_UINT8, BASE_DEC, VALS(ieee80211_mac_profile_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_msg_element_type_ieee80211_mac_profile,
            { "Profile", "capwap.control.message_element.ieee80211_mac_profile",
              FT_UINT8, BASE_DEC, VALS(ieee80211_mac_profile_vals), 0x0,
              NULL, HFILL }
        },

        /* Data Channel Keep-Alive entries */
        { &hf_capwap_data_keep_alive,
            { "Keep-Alive", "capwap.keep_alive",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_data_keep_alive_length,
            { "Message Element Length", "capwap.keep_alive.length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        /* Fortinet Vendor Specific*/

        { &hf_capwap_fortinet_element_id,
            { "Fortinet Element ID", "capwap.control.fortinet.element_id",
              FT_UINT16, BASE_DEC, VALS(fortinet_element_id_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_value,
            { "Fortinet Value", "capwap.control.fortinet.value",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_ap_scan_rid,
            { "Radio ID", "capwap.control.fortinet.ap_scan.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_ap_scan_bgscan_intv,
            { "bg scan interval", "capwap.control.fortinet.ap_scan.bgpscan.interval",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_ap_scan_bgscan_idle,
            { "bg scan idle", "capwap.control.fortinet.ap_scan.bgpscan.idle",
              FT_UINT24, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_ap_scan_bgscan_rpt_intv,
            { "bg scan rpt interval", "capwap.control.fortinet.ap_scan.bgscan.rpt_interval",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_ap_scan_fgscan_rpt_intv,
            { "fg scan rpt interval", "capwap.control.fortinet.ap_scan.fgscan.rpt_interval",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_passive_rid,
            { "Radio ID", "capwap.control.fortinet.passive.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_passive,
            { "Passive", "capwap.control.fortinet.passive",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_daemon_rst,
            { "Daemon RST", "capwap.control.fortinet.daemon_rst",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mac_rid,
            { "Radio ID", "capwap.control.fortinet.mac.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mac_wid,
            { "WLAN ID", "capwap.control.fortinet.mac.wid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mac_len,
            { "Length", "capwap.control.fortinet.mac.len",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mac,
            { "MAC", "capwap.control.fortinet.mac",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_wtp_allow_sn,
            { "Serial Number", "capwap.control.fortinet.wtp_allow.sn",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "WTP Serial Number", HFILL }
        },
        { &hf_capwap_fortinet_wtp_allow_allow,
            { "Allowed", "capwap.control.fortinet.wtp_allow.allowed",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_wbh_sta_rid,
            { "Radio ID", "capwap.control.fortinet.wbh_sta.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_wbh_sta_len,
            { "Length", "capwap.control.fortinet.wbh_sta.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_wbh_sta_mac,
            { "STA MAC", "capwap.control.fortinet.wbh_sta.mac",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_wbh_sta_bssid,
            { "BSSID", "capwap.control.fortinet.wbh_sta.bssid",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_wbh_sta_mhc,
            { "MHC", "capwap.control.fortinet.wbh_sta.mhc",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_htcap_rid,
            { "Radio ID", "capwap.control.fortinet.htcap.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_htcap_mcs,
            { "MCS", "capwap.control.fortinet.htcap.mcs",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_htcap_gi,
            { "HT Short GI", "capwap.control.fortinet.htcap.mcs.gi",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_htcap_bw,
            { "Bandwidth", "capwap.control.fortinet.htcap.mcs.bw",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "20 or 40Mhz Mode", HFILL }
        },
        { &hf_capwap_fortinet_mvap_sn_length,
            { "SN Length", "capwap.control.fortinet.mvap.sn.length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mvap_sn,
            { "SN", "capwap.control.fortinet.mvap.sn",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mvap_unknown,
            { "Unknown", "capwap.control.fortinet.mvap.unknown",
              FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mvap_age,
            { "Age", "capwap.control.fortinet.mvap.age",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mvap_period,
            { "Period", "capwap.control.fortinet.mvap.period",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mvap_vfid,
            { "Vfid", "capwap.control.fortinet.mvap.vfid",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mode_rid,
            { "Radio ID", "capwap.control.fortinet.mode.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mode,
            { "Mode", "capwap.control.fortinet.mode",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_coext_rid,
            { "Radio ID", "capwap.control.fortinet.coext.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_coext,
            { "Coext", "capwap.control.fortinet.coext",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_amsdu_rid,
            { "Radio ID", "capwap.control.fortinet.amsdu.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_amsdu,
            { "AMSDU", "capwap.control.fortinet.amsdu",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_ps_opt_rid,
            { "Radio ID", "capwap.control.fortinet.ps_opt.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_ps_opt,
            { "PS OPT", "capwap.control.fortinet.ps_opt",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_pure_rid,
            { "Radio ID", "capwap.control.fortinet.pure.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_pure,
            { "Pure", "capwap.control.fortinet.pure",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_ebptag_ebp,
            { "EBP", "capwap.control.fortinet.ebptag.ebp",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_ebptag_tag,
            { "Tag", "capwap.control.fortinet.ebptag.tag",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_telnet_enable,
            { "Telnet Enable", "capwap.control.fortinet.telnet_enable",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_admin_passwd,
            { "Admin Password", "capwap.control.fortinet.admin_password",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_regcode,
            { "Reg Code", "capwap.control.fortinet.reg_code",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_countrycode_rid,
            { "Radio ID", "capwap.control.fortinet.countrycode.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_countrycode_code,
            { "Country Code", "capwap.control.fortinet.countrycode.code",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_countrycode_string,
            { "Country Code", "capwap.control.fortinet.countrycode.string",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_sta_scan_rid,
            { "Radio ID", "capwap.control.fortinet.sta_scan.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_sta_scan,
            { "STA Scan", "capwap.control.fortinet.sta_scan",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_fho_rid,
            { "Radio ID", "capwap.control.fortinet.fho.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_fho,
            { "FHO", "capwap.control.fortinet.fho",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_apho_rid,
            { "Radio ID", "capwap.control.fortinet.fho.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_apho,
            { "APHO", "capwap.control.fortinet.apho",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_sta_locate_rid,
            { "Radio ID", "capwap.control.fortinet.sta_locate.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_sta_locate_enable,
            { "Locate Enable", "capwap.control.fortinet.sta_locate.enable",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_sta_locate_interval,
            { "Locate Interval", "capwap.control.fortinet.sta_locate.interval",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_sa_rid,
            { "Radio ID", "capwap.control.fortinet.spectrum_analysis.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_sa_enable,
            { "Spectrum Analysis Enable", "capwap.control.fortinet.spectrum_analysis.enable",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_sa_ssid,
            { "SSID", "capwap.control.fortinet.spectrum_analysis.ssid",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_darrp_cfg_rid,
            { "Radio ID", "capwap.control.fortinet.darrp_cfg.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_darrp_cfg_enable,
            { "DARRP CFG Enable", "capwap.control.fortinet.darrp_cfg.enable",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_darrp_cfg_interval,
            { "DARRP CFG Interval", "capwap.control.fortinet.darrp_cfg.interval",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_ap_suppress_list_ver,
            { "Ver", "capwap.control.fortinet.ap_suppress_list.ver",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_ap_suppress_list_op,
            { "Op", "capwap.control.fortinet.ap_suppress_list.op",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Operation ?", HFILL }
        },
        { &hf_capwap_fortinet_ap_suppress_list_rid,
            { "Radio ID", "capwap.control.fortinet.ap_suppress_list.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_ap_suppress_list_len,
            { "Length", "capwap.control.fortinet.ap_suppress_list.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_wds_rid,
            { "Radio ID", "capwap.control.fortinet.wds.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_wds_wid,
            { "WLAN ID", "capwap.control.fortinet.wds.wid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_wds_enable,
            { "WDS Enable", "capwap.control.fortinet.wds.enable",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_vap_vlan_tag_rid,
            { "Radio ID", "capwap.control.fortinet.vap_vlan_tag.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_vap_vlan_tag_wid,
            { "WLAN ID", "capwap.control.fortinet.vap_vlan_tag.wid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_vap_vlan_tag,
            { "Vlan ID", "capwap.control.fortinet.vap_vlan_tag",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_vap_bitmap_rid,
            { "Radio ID", "capwap.control.fortinet.bitmap.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_vap_bitmap,
            { "Bitmap", "capwap.control.fortinet.vap_bitmap",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mcast_rate_rid,
            { "Radio ID", "capwap.control.fortinet.mcast_rate.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mcast_rate_wid,
            { "WLAN ID", "capwap.control.fortinet.mcast_rate.wid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mcast_rate,
            { "Multicast Rate", "capwap.control.fortinet.mcast_rate",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_cfg_rid,
            { "Radio ID", "capwap.control.fortinet.cfg.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_cfg_wid,
            { "WLAN ID", "capwap.control.fortinet.cfg.wid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_cfg_ip,
            { "IP", "capwap.control.fortinet.cfg.ip",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_cfg_mask,
            { "Mask", "capwap.control.fortinet.cfg.mask",
              FT_IPv4, BASE_NETMASK, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_split_tun_cfg_enable_local_subnet,
            { "Enable Local Subnet", "capwap.control.fortinet.split_tun_cfg.enable_local_subnet",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_split_tun_cfg_cnt,
            { "CNT", "capwap.control.fortinet.split_tun_cfg.cnt",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mgmt_vlan_id,
            { "Vlan ID", "capwap.control.fortinet.mgmt_vlan.id",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_vap_psk_passwd_rid,
            { "Radio ID", "capwap.control.fortinet.vap_psk_passwd.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_vap_psk_passwd_wid,
            { "WLAN ID", "capwap.control.fortinet.vap_psk_passwd.wid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_vap_psk_passwd_key,
            { "Key", "capwap.control.fortinet.vap_psk_passwd.key",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mesh_eth_bridge_enable,
            { "Mesh Eth Bridge Enable", "capwap.control.fortinet.mesh_eth_bridge.enable",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_mesh_eth_bridge_type,
            { "Mesh Eth Bridge Type", "capwap.control.fortinet.mesh_eth_bridge.type",
              FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_wtp_cap,
            { "WTP CAP", "capwap.control.fortinet.wtp_cap",
              FT_BYTES, SEP_SPACE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_txpwr_rid,
            { "Radio ID", "capwap.control.fortinet.tx_power.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_txpwr,
            { "TX Power", "capwap.control.fortinet.tx_power",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "In Percentage", HFILL }
        },
        { &hf_capwap_fortinet_wids_enable_rid,
            { "Radio ID", "capwap.control.fortinet.wids_enable.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_wids_enable,
            { "WIDS Enable", "capwap.control.fortinet.wids_enable.enable",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_unknown_rid,
            { "Radio ID", "capwap.control.fortinet.unknown.rid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_unknown_wid,
            { "WLAN ID", "capwap.control.fortinet.unknown.wid",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_fortinet_unknown,
            { "Unknown Data", "capwap.control.fortinet.unknown",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },


        /* Cisco Vendor Specific*/

        { &hf_capwap_cisco_element_id,
            { "Cisco Element ID", "capwap.control.cisco.element_id",
              FT_UINT16, BASE_DEC, VALS(cisco_element_id_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_value,
            { "Cisco Value", "capwap.control.cisco.value",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_mwar_addr,
            { "Address", "capwap.control.cisco.mwar.address",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_rad_name,
            { "RAD (AP) Name", "capwap.control.cisco.rad_name",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_mwar_type,
            { "Type", "capwap.control.cisco.mwar.type",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_mwar_hardware,
            { "Hardware version", "capwap.control.cisco.mwar.hardware",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_mwar_software,
            { "Software version", "capwap.control.cisco.mwar.software",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_mwar_active_ms,
            { "Active MS", "capwap.control.cisco.mwar.active_ms",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_mwar_supported_ms,
            { "Supported MS", "capwap.control.cisco.mwar.supported_ms",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_mwar_active_rad,
            { "Active RAD", "capwap.control.cisco.mwar.active_rad",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_mwar_supported_rad,
            { "Supported RAD", "capwap.control.cisco.mwar.supported_rad",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_ap_mode_and_type_mode,
            { "Mode", "capwap.control.cisco.ap_mode_and_type.mode",
              FT_UINT8, BASE_DEC, VALS(cisco_ap_mode_and_type_mode_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_ap_mode_and_type_type,
            { "Type", "capwap.control.cisco.ap_mode_and_type.type",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_ap_static_ip_addr,
            { "IP Address", "capwap.control.cisco.ap_static_ip.addr",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_ap_static_ip_netmask,
            { "Netmask", "capwap.control.cisco.ap_static_ip.netmask",
              FT_IPv4, BASE_NETMASK, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_ap_static_ip_gateway,
            { "Gateway", "capwap.control.cisco.ap_static_ip.gateway",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_ap_static_ip_type,
            { "Type", "capwap.control.cisco.ap_static_ip.type",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_ap_static_ip_reserved,
            { "Reserved", "capwap.control.cisco.ap_static_ip.reserved",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_ap_uptime_current,
            { "AP Uptime Current", "capwap.control.cisco.ap_uptime.current",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_ap_uptime_last,
            { "AP Uptime Last", "capwap.control.cisco.ap_uptime.last",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_ap_group_name,
            { "AP Group Name", "capwap.control.cisco.ap_group_name",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_ap_led_state,
            { "Led State", "capwap.control.cisco.ap_led_state",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_ap_timesync,
            { "AP TimeSync", "capwap.control.cisco.ap_timesync",
              FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_ap_timesync_type,
            { "Type (?)", "capwap.control.cisco.ap_timesync.type",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_board_data_options_ant_type,
            { "Antenna Type", "capwap.control.cisco.board_data_options.ant_type",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_board_data_options_flex_connect,
            { "Flex Connect", "capwap.control.cisco.board_data_options.flex_connect",
              FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_board_data_options_ap_type,
            { "AP Type", "capwap.control.cisco.board_data_options.ap_type",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_board_data_options_join_priority,
            { "Join Priority", "capwap.control.cisco.board_data_options.join_priority",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_capwap_cisco_unknown,
            { "Unknown Data", "capwap.control.cisco.unknown",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        /* Fragment entries */
        { &hf_msg_fragments,
            { "Message fragments", "capwap.fragments",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_msg_fragment,
            { "Message fragment", "capwap.fragment",
              FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_msg_fragment_overlap,
            { "Message fragment overlap", "capwap.fragment.overlap",
              FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_msg_fragment_overlap_conflicts,
            { "Message fragment overlapping with conflicting data", "capwap.fragment.overlap.conflicts",
              FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_msg_fragment_multiple_tails,
            { "Message has multiple tail fragments", "capwap.fragment.multiple_tails",
              FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_msg_fragment_too_long_fragment,
            { "Message fragment too long", "capwap.fragment.too_long_fragment",
              FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_msg_fragment_error,
            { "Message defragmentation error", "capwap.fragment.error",
              FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_msg_fragment_count,
            { "Message fragment count", "capwap.fragment.count",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_msg_reassembled_in,
            { "Reassembled in", "capwap.reassembled.in",
              FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_msg_reassembled_length,
            { "Reassembled CAPWAP length", "capwap.reassembled.length",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_capwap,
        &ett_capwap_control,
        &ett_capwap_data,
        &ett_capwap_preamble,
        &ett_capwap_header,
        &ett_capwap_header_flags,
        &ett_capwap_control_header,
        &ett_capwap_control_header_msg,
        &ett_capwap_data_keep_alive,
        &ett_capwap_message_element,
        &ett_capwap_data_message_bindings_ieee80211,
        &ett_capwap_encryption_capabilities,
        &ett_capwap_encryption_capability,
        &ett_capwap_ac_information,
        &ett_capwap_wtp_descriptor,
        &ett_capwap_board_data,
        &ett_capwap_message_element_type,
        &ett_capwap_ac_descriptor_security_flags,
        &ett_capwap_ac_descriptor_dtls_flags,
        &ett_capwap_wtp_frame_tunnel_mode,
        &ett_capwap_ieee80211_add_wlan_capability,
        &ett_capwap_ieee80211_ie_flags,
        &ett_capwap_ieee80211_update_wlan_capability,
        &ett_capwap_ieee80211_station_capabilities,
        &ett_capwap_ieee80211_ofdm_control_band_support,
        &ett_msg_fragment,
        &ett_msg_fragments
    };

    static ei_register_info ei[] = {
        { &ei_capwap_header_length_bad, { "capwap.header.length.bad", PI_MALFORMED, PI_WARN, "Wrong calculate length =! header length", EXPFILL }},
        { &ei_capwap_data_keep_alive_length, { "capwap.keep_alive.length.bad", PI_MALFORMED, PI_WARN, "Invalid Keep Alive length", EXPFILL }},
        { &ei_capwap_msg_element_length, { "capwap.message_element.length.bad", PI_MALFORMED, PI_ERROR, "Bad Message Element length", EXPFILL }},
        { &ei_capwap_message_element_type, { "capwap.message_element.type.undecoded", PI_UNDECODED, PI_NOTE, "Dissector for CAPWAP message element Type not implemented, Contact Wireshark developers if you want this supported", EXPFILL }},
        { &ei_capwap_fortinet_mac_len, { "capwap.control.fortinet.mac.length.bad", PI_MALFORMED, PI_ERROR, "Bad length: Should be a multiple of 6", EXPFILL }},
        { &ei_capwap_message_element_fortinet_type, { "capwap.message_element.type.fortinet.undecoded", PI_UNDECODED, PI_NOTE, "Dissector for CAPWAP message element Fortinet Type not implemented", EXPFILL }},
        { &ei_capwap_message_element_cisco_type, { "capwap.message_element.type.fortinet.undecoded", PI_UNDECODED, PI_NOTE, "Dissector for CAPWAP message element Cisco Type not implemented", EXPFILL }}
    };

    expert_module_t* expert_capwap;

    proto_capwap_control = proto_register_protocol("Control And Provisioning of Wireless Access Points - Control", "CAPWAP-CONTROL", "capwap");
    proto_capwap_data = proto_register_protocol("Control And Provisioning of Wireless Access Points - Data", "CAPWAP-DATA", "capwap.data");

    proto_register_field_array(proto_capwap_control, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));

    expert_capwap = expert_register_protocol(proto_capwap_control);
    expert_register_field_array(expert_capwap, ei, array_length(ei));

    reassembly_table_register(&capwap_reassembly_table,
                          &addresses_reassembly_table_functions);

    capwap_module = prefs_register_protocol(proto_capwap_control, NULL);
    /* Need to create a placeholder for "port" preferences so there is a callback */
    prefs_register_protocol(proto_capwap_data, apply_capwap_prefs);

    prefs_register_bool_preference(capwap_module, "draft_8_cisco", "Cisco Wireless Controller Support",
        "Enable support of Cisco Wireless Controller (based on old 8 draft revision).",
        &global_capwap_draft_8_cisco);

    prefs_register_bool_preference(capwap_module, "reassemble", "Reassemble fragmented CAPWAP packets",
        "Reassemble fragmented CAPWAP packets.",
        &global_capwap_reassemble);

    prefs_register_bool_preference(capwap_module, "swap_fc", "Swap Frame Control",
        "Swap frame control bytes (needed for some APs).",
        &global_capwap_swap_frame_control);

}

void
proto_reg_handoff_capwap(void)
{
    dissector_handle_t capwap_control_handle, capwap_data_handle;

    capwap_control_handle = create_dissector_handle(dissect_capwap_control, proto_capwap_control);
    capwap_data_handle    = create_dissector_handle(dissect_capwap_data, proto_capwap_data);
    dtls_handle           = find_dissector_add_dependency("dtls", proto_capwap_control);
    find_dissector_add_dependency("dtls", proto_capwap_data);
    ieee8023_handle       = find_dissector_add_dependency("eth_withoutfcs", proto_capwap_data);
    ieee80211_handle      = find_dissector_add_dependency("wlan_withoutfcs", proto_capwap_data);
    ieee80211_bsfc_handle = find_dissector_add_dependency("wlan_bsfc", proto_capwap_data);

    dissector_add_uint_with_preference("udp.port", UDP_PORT_CAPWAP_CONTROL, capwap_control_handle);
    dissector_add_uint_with_preference("udp.port", UDP_PORT_CAPWAP_DATA, capwap_data_handle);
    apply_capwap_prefs();
}
/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
